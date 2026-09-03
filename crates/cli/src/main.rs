//! Native harness for the archive decoder: prints the same numbers the web UI
//! shows, and doubles as the throughput benchmark and a reference decompressor.

use archive_viewer_core::decode::{Compression, RecordDecoder};
use std::io::{Read, Write};

fn usage() -> ! {
    eprintln!(
        "usage: archive-viewer-cli <command> <archive.bin[.zst]>

commands:
  stats   decode the archive and print totals and throughput
  dump    write the decompressed record stream to stdout"
    );
    std::process::exit(2)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (command, path) = match (args.next(), args.next()) {
        (Some(c), Some(p)) => (c, p),
        _ => usage(),
    };
    match command.as_str() {
        "stats" => stats(&path),
        "dump" => dump(&path),
        _ => usage(),
    }
}

/// The extension is only a hint; the decoder sniffs the zstd magic itself.
fn hint(path: &str) -> Option<Compression> {
    Some(if path.ends_with(".zst") {
        Compression::Zstd
    } else {
        Compression::None
    })
}

fn read_archive<S: archive_viewer_core::decode::RecordSink>(
    path: &str,
    sink: &mut S,
) -> (RecordDecoder, archive_viewer_core::decode::Completion) {
    let mut file = std::fs::File::open(path).unwrap_or_else(|e| {
        eprintln!("cannot open {path}: {e}");
        std::process::exit(1)
    });
    let mut decoder = RecordDecoder::new(hint(path));
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf).expect("read archive");
        if n == 0 {
            break;
        }
        if let Err(e) = decoder.push(&buf[..n], sink) {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    let completion = decoder.finish(sink).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1)
    });
    (decoder, completion)
}

fn stats(path: &str) {
    let mut records = 0u64;
    let mut record_bytes = 0u64;
    let mut largest = 0usize;
    let start = std::time::Instant::now();
    let (decoder, completion) = {
        let mut sink = |_i: u64, bytes: &[u8]| {
            records += 1;
            record_bytes += bytes.len() as u64;
            largest = largest.max(bytes.len());
        };
        read_archive(path, &mut sink)
    };
    let elapsed = start.elapsed().as_secs_f64();
    let (cin, out) = (decoder.compressed_bytes(), decoder.decompressed_bytes());

    println!("compression       {:?}", decoder.compression());
    println!("compressed        {cin} bytes");
    println!(
        "decompressed      {out} bytes ({:.2}x)",
        out as f64 / cin.max(1) as f64
    );
    println!("records           {records}");
    println!(
        "  mean size       {:.1} bytes",
        record_bytes as f64 / records.max(1) as f64
    );
    println!("  largest         {largest} bytes");
    println!("truncated         {}", completion.truncated);
    println!("  incomplete frame  {}", completion.incomplete_frame);
    println!("  trailing bytes    {}", completion.trailing_bytes);
    println!("elapsed           {elapsed:.3}s");
    println!(
        "throughput        {:.1} MB/s decompressed, {:.1} MB/s of input",
        out as f64 / 1e6 / elapsed,
        cin as f64 / 1e6 / elapsed
    );
}

fn dump(path: &str) {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    {
        let mut sink = |_i: u64, bytes: &[u8]| {
            // Re-emit the framing so the output matches the decompressed stream.
            let mut prefix = Vec::new();
            prost::encoding::encode_varint(bytes.len() as u64, &mut prefix);
            out.write_all(&prefix).expect("write stdout");
            out.write_all(bytes).expect("write stdout");
        };
        read_archive(path, &mut sink);
    }
    out.flush().expect("flush stdout");
}
