//! Native harness for the archive viewer's core: prints the same numbers the web
//! UI shows, and doubles as the throughput benchmark and a reference decompressor.

use archive_viewer_core::analysis::Analysis;
use archive_viewer_core::decode::{Compression, RecordDecoder};
use std::io::{Read, Write};

/// Retain everything by default; the point of the CLI is to check totals.
const DEFAULT_BUDGET: u64 = 8 * 1024 * 1024 * 1024;

fn usage() -> ! {
    eprintln!(
        "usage: archive-viewer-cli <command> <archive.bin[.zst]>...

commands:
  stats   decode the archives and print totals, a breakdown and throughput
  dump    write the decompressed record stream of one archive to stdout"
    );
    std::process::exit(2)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| usage());
    let paths: Vec<String> = args.collect();
    if paths.is_empty() {
        usage();
    }
    match command.as_str() {
        "stats" => stats(&paths),
        "dump" => dump(&paths[0]),
        _ => usage(),
    }
}

fn read_chunks(path: &str, mut feed: impl FnMut(&[u8])) {
    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("cannot open {path}: {e}");
        std::process::exit(1)
    });
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf).expect("read archive");
        if n == 0 {
            break;
        }
        feed(&buf[..n]);
    }
}

fn stats(paths: &[String]) {
    let budget = std::env::var("ARCHIVE_VIEWER_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BUDGET);
    let mut analysis = Analysis::new(budget);

    let start = std::time::Instant::now();
    for path in paths {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        analysis.begin_file(path.clone(), size);
        read_chunks(path, |chunk| {
            if let Err(e) = analysis.push(chunk) {
                eprintln!("error in {path}: {e}");
            }
        });
        analysis.end_file();
    }
    let elapsed = start.elapsed().as_secs_f64();

    for file in &analysis.files {
        println!("file              {}", file.name);
        println!("  compression     {}", file.compression.unwrap_or("?"));
        println!(
            "  created         {}",
            file.created.map_or("?".into(), |c| c.to_string())
        );
        println!("  low_data        {:?}", file.low_data);
        println!("  compressed      {} bytes", file.compressed_bytes);
        println!(
            "  decompressed    {} bytes ({:.2}x)",
            file.decompressed_bytes,
            file.decompressed_bytes as f64 / file.compressed_bytes.max(1) as f64
        );
        println!("  events          {}", file.events);
        println!("  decode errors   {}", file.decode_errors);
        println!(
            "  truncated       {} (incomplete frame {}, {} trailing bytes)",
            file.truncated, file.incomplete_frame, file.trailing_bytes
        );
        if let Some(error) = &file.error {
            println!("  ERROR           {error}");
        }
    }

    let total_out: u64 = analysis.files.iter().map(|f| f.decompressed_bytes).sum();
    println!();
    println!("events            {}", analysis.total_events);
    println!("decode errors     {}", analysis.decode_errors);
    println!("distinct kinds    {}", analysis.kinds.len());
    println!("peers             {}", analysis.peers.len());
    println!(
        "time range        {:?} .. {:?} ({:.1}s)",
        analysis.first_timestamp,
        analysis.last_timestamp,
        analysis.duration_ms() as f64 / 1000.0
    );
    println!(
        "timeline          {} bins of {} ms",
        analysis.histogram.bins(),
        analysis.histogram.bin_ms()
    );
    println!(
        "retained          {} events, {:.1} MB{}",
        analysis.store.len(),
        analysis.store.bytes_used() as f64 / 1e6,
        if analysis.store.is_full() {
            " (budget reached)"
        } else {
            ""
        }
    );
    println!(
        "raw data dropped  {} events, {} bytes (transaction and block payloads)",
        analysis.stripped_events, analysis.stripped_bytes
    );
    println!("elapsed           {elapsed:.3}s");
    println!(
        "throughput        {:.1} MB/s decompressed",
        total_out as f64 / 1e6 / elapsed
    );

    println!("\nbreakdown");
    let mut kinds: Vec<_> = analysis
        .kinds
        .iter()
        .map(|(id, info)| (analysis.counts.get(id as usize).copied().unwrap_or(0), info))
        .collect();
    kinds.sort_by_key(|(count, _)| std::cmp::Reverse(*count));
    for (count, info) in kinds {
        println!(
            "  {:>12}  {:>6.2}%  {}.{}.{}",
            count,
            count as f64 * 100.0 / analysis.total_events.max(1) as f64,
            info.category().as_str(),
            info.group.as_str(),
            info.name
        );
    }
}

fn dump(path: &str) {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let hint = Some(if path.ends_with(".zst") {
        Compression::Zstd
    } else {
        Compression::None
    });
    let mut decoder = RecordDecoder::new(hint);
    {
        let mut sink = |_i: u64, bytes: &[u8]| {
            // Re-emit the framing so the output matches the decompressed stream.
            let mut prefix = Vec::new();
            prost::encoding::encode_varint(bytes.len() as u64, &mut prefix);
            out.write_all(&prefix).expect("write stdout");
            out.write_all(bytes).expect("write stdout");
        };
        read_chunks(path, |chunk| {
            decoder.push(chunk, &mut sink).expect("decode");
        });
        decoder.finish(&mut sink).expect("finish");
    }
    out.flush().expect("flush stdout");
}
