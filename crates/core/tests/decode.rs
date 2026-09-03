mod support;

use archive_viewer_core::decode::{Compression, DecodeError, RecordDecoder};
use archive_viewer_core::proto::{event::Event, header::ArchiveHeader};
use prost::Message;
use support::*;

/// Decode a whole archive in fixed-size chunks, returning the records and how
/// the stream ended.
fn decode_in_chunks(
    bytes: &[u8],
    chunk: usize,
    hint: Option<Compression>,
) -> (Vec<Vec<u8>>, archive_viewer_core::decode::Completion) {
    let mut records = Vec::new();
    let mut decoder = RecordDecoder::new(hint);
    {
        let mut sink = |_i: u64, r: &[u8]| records.push(r.to_vec());
        for part in bytes.chunks(chunk.max(1)) {
            decoder.push(part, &mut sink).expect("push");
        }
        let completion = decoder.finish(&mut sink).expect("finish");
        (records, completion)
    }
}

fn sample_events() -> Vec<Event> {
    let mut events = Vec::new();
    for i in 0..200u64 {
        events.push(message_event(
            1_700_000_000_000 + i,
            i % 17,
            "inv",
            i % 2 == 0,
            100 + i,
        ));
        if i % 25 == 0 {
            events.push(connection_event(1_700_000_000_000 + i, i % 17));
        }
    }
    // Force two- and three-byte varint length prefixes.
    events.push(big_event(1_700_000_001_000, 200));
    events.push(big_event(1_700_000_002_000, 40_000));
    events
}

#[test]
fn roundtrips_a_complete_archive() {
    let header = header(1_700_000_000, Some(false));
    let events = sample_events();
    let archive = compress(&record_stream(&header, &events), 3);

    let (records, completion) = decode_in_chunks(&archive, 64 * 1024, Some(Compression::Zstd));

    assert!(
        !completion.truncated,
        "a finalised archive must not look truncated"
    );
    assert_eq!(completion.trailing_bytes, 0);
    assert_eq!(records.len(), events.len() + 1, "header plus every event");

    let decoded_header = ArchiveHeader::decode(records[0].as_slice()).expect("header decodes");
    assert_eq!(decoded_header, header);

    for (raw, expected) in records[1..].iter().zip(&events) {
        assert_eq!(
            &Event::decode(raw.as_slice()).expect("event decodes"),
            expected
        );
    }
}

/// Records must be reassembled correctly no matter where chunk boundaries fall,
/// including in the middle of a varint length prefix.
#[test]
fn survives_every_chunk_boundary() {
    let header = header(1_700_000_000, None);
    let events = vec![
        message_event(1, 1, "ping", true, 32),
        big_event(2, 200), // two-byte length prefix
        message_event(3, 2, "pong", false, 32),
    ];
    let stream = record_stream(&header, &events);
    let archive = compress(&stream, 3);
    let expected = events.len() + 1;

    // Uncompressed: exercise a split at literally every byte offset.
    for chunk in 1..=stream.len() {
        let (records, completion) = decode_in_chunks(&stream, chunk, Some(Compression::None));
        assert_eq!(records.len(), expected, "uncompressed, chunk size {chunk}");
        assert!(!completion.truncated, "uncompressed, chunk size {chunk}");
    }

    // Compressed: a handful of awkward sizes, including below the zstd magic.
    for chunk in [1, 2, 3, 7, 64, 1000, archive.len()] {
        let (records, completion) = decode_in_chunks(&archive, chunk, Some(Compression::Zstd));
        assert_eq!(records.len(), expected, "compressed, chunk size {chunk}");
        assert!(!completion.truncated, "compressed, chunk size {chunk}");
    }
}

/// The important one: an archive that is still being written ends mid-frame.
/// Every record before the cut must still come out, and truncation is reported
/// rather than raised as an error.
///
/// The fixture has to span several zstd blocks: a block holds up to 128 KiB and a
/// partial one is not decodable even in principle, so cutting inside the first
/// block could only ever yield nothing.
#[test]
fn recovers_records_from_a_truncated_frame() {
    let header = header(1_700_000_000, Some(true));
    let events: Vec<_> = (0..8_000u64)
        .map(|i| message_event(1_700_000_000_000 + i, i % 64, "inv", i % 2 == 0, 100 + i))
        .collect();
    let archive = compress(&record_stream(&header, &events), 3);
    let full = decode_in_chunks(&archive, 64 * 1024, Some(Compression::Zstd))
        .0
        .len();
    assert_eq!(full, events.len() + 1);

    // Cut most of the way through, as a live archive would be.
    let cut = archive.len() * 3 / 4;
    let (records, completion) =
        decode_in_chunks(&archive[..cut], 64 * 1024, Some(Compression::Zstd));

    assert!(completion.truncated);
    assert!(
        completion.incomplete_frame,
        "the frame has no terminating block"
    );
    assert!(
        records.len() > 1,
        "must recover the records decoded before the cut, got {}",
        records.len()
    );
    assert!(
        records.len() < full,
        "a truncated archive cannot yield every record"
    );

    // Whatever came out must be intact, not partially decoded garbage.
    ArchiveHeader::decode(records[0].as_slice()).expect("header decodes");
    for (raw, expected) in records[1..].iter().zip(&events) {
        assert_eq!(
            &Event::decode(raw.as_slice()).expect("event decodes"),
            expected
        );
    }
}

/// Cutting inside the very first zstd block yields no records at all. That is
/// the format's limit, not a bug, and it must still be reported as truncation
/// rather than raised as an error.
#[test]
fn truncating_inside_the_first_block_yields_nothing_but_does_not_error() {
    let header = header(1, None);
    let events = sample_events();
    let archive = compress(&record_stream(&header, &events), 3);

    let (records, completion) = decode_in_chunks(&archive[..32], 8, Some(Compression::Zstd));

    assert!(records.is_empty());
    assert!(completion.truncated);
    assert!(completion.incomplete_frame);
}

#[test]
fn truncating_mid_record_reports_the_trailing_bytes() {
    let header = header(1, None);
    let events = vec![message_event(1, 1, "ping", true, 32), big_event(2, 300)];
    let mut stream = record_stream(&header, &events);
    stream.truncate(stream.len() - 100); // slice into the middle of the last record

    let (records, completion) = decode_in_chunks(&stream, 16, Some(Compression::None));

    assert_eq!(records.len(), 2, "header and the one complete event");
    assert!(completion.truncated);
    assert!(
        !completion.incomplete_frame,
        "uncompressed streams have no frame"
    );
    assert!(completion.trailing_bytes > 0);
}

#[test]
fn reads_uncompressed_archives() {
    let header = header(42, None);
    let events = sample_events();
    let stream = record_stream(&header, &events);

    let (records, completion) = decode_in_chunks(&stream, 4096, Some(Compression::None));

    assert!(!completion.truncated);
    assert_eq!(records.len(), events.len() + 1);
}

/// The zstd magic wins over the filename, so a renamed or extensionless archive
/// still opens. Upstream's reader goes by extension alone and has a TODO for this.
#[test]
fn sniffs_compression_rather_than_trusting_the_hint() {
    let header = header(1, None);
    let events = vec![message_event(1, 1, "ping", true, 32)];

    let compressed = compress(&record_stream(&header, &events), 3);
    let (records, _) = decode_in_chunks(&compressed, 7, Some(Compression::None));
    assert_eq!(records.len(), 2, "zstd data behind a plain .bin name");

    let plain = record_stream(&header, &events);
    let (records, _) = decode_in_chunks(&plain, 7, Some(Compression::Zstd));
    assert_eq!(records.len(), 2, "plain data behind a .zst name");
}

#[test]
fn rejects_an_implausible_record_length() {
    // A varint for 1 GiB, well past the record size limit.
    let mut bytes = Vec::new();
    prost::encoding::encode_varint(1 << 30, &mut bytes);
    bytes.extend_from_slice(&[0u8; 32]);

    let mut decoder = RecordDecoder::new(Some(Compression::None));
    let mut sink = |_i: u64, _r: &[u8]| panic!("no record should be emitted");
    let err = decoder
        .push(&bytes, &mut sink)
        .expect_err("must be rejected");

    assert!(
        matches!(err, DecodeError::RecordTooLarge { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_a_malformed_length_prefix() {
    let mut decoder = RecordDecoder::new(Some(Compression::None));
    let mut sink = |_i: u64, _r: &[u8]| panic!("no record should be emitted");
    let err = decoder
        .push(&[0xFF; 16], &mut sink)
        .expect_err("must be rejected");

    assert_eq!(err, DecodeError::MalformedVarint);
}

#[test]
fn an_empty_file_is_not_an_error() {
    let mut decoder = RecordDecoder::new(None);
    let mut sink = |_i: u64, _r: &[u8]| panic!("no record should be emitted");
    let completion = decoder.finish(&mut sink).expect("finish");
    assert!(!completion.truncated);
}

#[test]
fn reports_byte_counters() {
    let header = header(1, None);
    let events = sample_events();
    let stream = record_stream(&header, &events);
    let archive = compress(&stream, 3);

    let mut decoder = RecordDecoder::new(Some(Compression::Zstd));
    let mut count = 0u64;
    {
        let mut sink = |_i: u64, _r: &[u8]| count += 1;
        decoder.push(&archive, &mut sink).expect("push");
        decoder.finish(&mut sink).expect("finish");
    }

    assert_eq!(decoder.compressed_bytes(), archive.len() as u64);
    assert_eq!(decoder.decompressed_bytes(), stream.len() as u64);
    assert_eq!(decoder.records(), count);
    assert_eq!(decoder.compression(), Some(Compression::Zstd));
}

/// Runs against a genuine archive when one is available, e.g.
/// `PEER_OBSERVER_ARCHIVE=/path/to/archive.bin.zst cargo test -- --ignored`.
#[test]
fn real_archive() {
    let Ok(path) = std::env::var("PEER_OBSERVER_ARCHIVE") else {
        eprintln!("skipping: set PEER_OBSERVER_ARCHIVE to a real archive to run this");
        return;
    };
    let bytes = std::fs::read(&path).expect("read archive");
    let hint = path.ends_with(".zst").then_some(Compression::Zstd);

    let mut decoder = RecordDecoder::new(hint);
    let mut records = 0u64;
    let mut header = None;
    {
        let mut sink = |i: u64, raw: &[u8]| {
            if i == 0 {
                header = Some(ArchiveHeader::decode(raw).expect("header decodes"));
            } else {
                let event = Event::decode(raw).expect("event decodes");
                assert!(event.timestamp > 0, "every event carries a timestamp");
                assert!(
                    event.peer_observer_event.is_some(),
                    "every event has a oneof arm"
                );
            }
            records += 1;
        };
        for chunk in bytes.chunks(64 * 1024) {
            decoder.push(chunk, &mut sink).expect("push");
        }
        decoder.finish(&mut sink).expect("finish");
    }

    assert!(records > 1, "expected records in {path}");
    assert!(header.expect("archive has a header").created > 0);
}
