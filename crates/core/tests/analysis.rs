mod support;

use archive_viewer_core::analysis::Analysis;
use archive_viewer_core::kind::{Category, Group};
use archive_viewer_core::store::NO_PEER;
use support::*;

const BIG_BUDGET: u64 = 64 * 1024 * 1024;

fn feed(analysis: &mut Analysis, name: &str, bytes: &[u8]) {
    analysis.begin_file(name.to_string(), bytes.len() as u64);
    for chunk in bytes.chunks(4096) {
        analysis.push(chunk).expect("push");
    }
    analysis.end_file();
}

fn count_of(analysis: &Analysis, group: Group, name: &str) -> u64 {
    analysis
        .kinds
        .iter()
        .find(|(_, info)| info.group == group && info.name == name)
        .map(|(id, _)| analysis.counts[id as usize])
        .unwrap_or(0)
}

#[test]
fn aggregates_a_whole_archive() {
    let header = header(1_700_000_000, Some(false));
    let mut events = Vec::new();
    for i in 0..300u64 {
        events.push(message_event(
            1_700_000_000_000 + i * 10,
            i % 20,
            "inv",
            i % 2 == 0,
            40,
        ));
    }
    for i in 0..15u64 {
        events.push(connection_event(1_700_000_000_000 + i * 100, i));
    }
    let archive = compress(&record_stream(&header, &events), 3);

    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(&mut analysis, "test.bin.zst", &archive);

    assert_eq!(analysis.total_events, events.len() as u64);
    assert_eq!(analysis.decode_errors, 0);
    assert_eq!(count_of(&analysis, Group::EbpfMessage, "inv"), 300);
    assert_eq!(count_of(&analysis, Group::EbpfConnection, "inbound"), 15);

    // Every event is accounted for exactly once across all kinds.
    assert_eq!(analysis.counts.iter().sum::<u64>(), analysis.total_events);
    assert_eq!(analysis.histogram.total(), analysis.total_events);

    assert_eq!(analysis.first_timestamp, Some(1_700_000_000_000));
    assert_eq!(analysis.last_timestamp, Some(1_700_000_000_000 + 299 * 10));
    assert_eq!(analysis.duration_ms(), 2_990);

    // The header record is read but is not an event.
    let file = &analysis.files[0];
    assert_eq!(file.created, Some(1_700_000_000));
    assert_eq!(file.low_data, Some(false));
    assert_eq!(file.events, events.len() as u64);
    assert_eq!(file.compression, Some("zstd"));
    assert!(!file.truncated);
    assert!(file.error.is_none());
}

#[test]
fn attributes_events_to_peers() {
    let header = header(1, None);
    let events = vec![
        message_event(100, 1, "version", true, 100),
        message_event(200, 1, "verack", false, 24),
        message_event(300, 2, "inv", true, 61),
        connection_event(400, 1),
    ];
    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(&mut analysis, "a.bin", &record_stream(&header, &events));

    assert_eq!(analysis.peers.len(), 2);
    let peer = analysis.peers.get(1).expect("peer 1");
    assert_eq!((peer.messages_in, peer.messages_out), (1, 1));
    assert_eq!((peer.bytes_in, peer.bytes_out), (100, 24));
    assert_eq!(peer.lifecycle.len(), 1);
    assert_eq!(analysis.peers.get(2).unwrap().messages_in, 1);

    // The store's dense peer index resolves back to the right peer id.
    let row = analysis.store.row(0).expect("first event retained");
    assert_ne!(row.peer, NO_PEER);
    assert_eq!(analysis.peers.peer_id_at(row.peer), Some(1));
    assert_eq!(row.inbound(), Some(true));
    assert_eq!(row.size, 100);

    // A connection event has a peer but no direction.
    let conn_row = analysis.store.row(3).unwrap();
    assert_eq!(analysis.peers.peer_id_at(conn_row.peer), Some(1));
    assert_eq!(conn_row.inbound(), None);
}

/// The central promise of the memory budget: aggregates still cover every
/// event, only retention stops.
#[test]
fn aggregation_continues_after_the_retention_budget_is_spent() {
    let header = header(1, None);
    let events: Vec<_> = (0..4_000u64)
        .map(|i| message_event(1_000 + i, i % 50, "inv", i % 2 == 0, 40))
        .collect();
    let stream = record_stream(&header, &events);

    // Room for only a fraction of the events.
    let mut analysis = Analysis::new(16 * 1024);
    feed(&mut analysis, "a.bin", &stream);

    assert!(analysis.store.is_full(), "budget must have been reached");
    assert!(
        analysis.store.len() < events.len(),
        "retention must have stopped early"
    );
    assert!(
        !analysis.store.is_empty(),
        "some events must have been retained"
    );

    // ...but the aggregates are complete.
    assert_eq!(analysis.total_events, events.len() as u64);
    assert_eq!(
        count_of(&analysis, Group::EbpfMessage, "inv"),
        events.len() as u64
    );
    assert_eq!(analysis.histogram.total(), events.len() as u64);
    assert_eq!(analysis.peers.len(), 50);
    let messages: u64 = analysis
        .peers
        .iter()
        .map(|p| p.messages_in + p.messages_out)
        .sum();
    assert_eq!(messages, events.len() as u64);
}

/// Rotated files are dropped in together and must read as one archive.
#[test]
fn merges_several_rotated_files() {
    let first = compress(
        &record_stream(
            &header(100, Some(false)),
            &[message_event(1_000, 1, "inv", true, 40)],
        ),
        3,
    );
    let second = compress(
        &record_stream(
            &header(200, Some(true)),
            &[
                message_event(2_000, 2, "tx", false, 300),
                message_event(3_000, 1, "inv", true, 40),
            ],
        ),
        3,
    );

    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(&mut analysis, "archive.1.bin.zst", &first);
    feed(&mut analysis, "archive.2.bin.zst", &second);

    assert_eq!(analysis.files.len(), 2);
    assert_eq!(analysis.files[0].events, 1);
    assert_eq!(analysis.files[1].events, 2);
    assert_eq!(analysis.files[0].low_data, Some(false));
    assert_eq!(analysis.files[1].low_data, Some(true));

    assert_eq!(analysis.total_events, 3);
    assert_eq!(count_of(&analysis, Group::EbpfMessage, "inv"), 2);
    assert_eq!(analysis.first_timestamp, Some(1_000));
    assert_eq!(analysis.last_timestamp, Some(3_000));
    // Peer 1 appears in both files and must be one peer, not two.
    assert_eq!(analysis.peers.len(), 2);
    assert_eq!(analysis.peers.get(1).unwrap().messages_in, 2);
}

/// One unreadable record must be counted and skipped, not abandon the archive.
#[test]
fn a_corrupt_record_does_not_abort_the_archive() {
    let mut stream = framed(&header(1, None));
    stream.extend_from_slice(&framed(&message_event(100, 1, "inv", true, 40)));
    // A record whose framing is valid but whose contents are not protobuf: tag
    // byte for field 1 with no value after it. (A zero-length record would NOT
    // do -- prost does not enforce proto2 `required`, so it decodes as an empty
    // Event.)
    stream.push(0x01);
    stream.push(0x08);
    stream.extend_from_slice(&framed(&message_event(200, 1, "tx", false, 300)));

    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(&mut analysis, "a.bin", &stream);

    assert_eq!(analysis.decode_errors, 1);
    assert_eq!(analysis.files[0].decode_errors, 1);
    assert_eq!(
        analysis.total_events, 2,
        "the events on both sides are still read"
    );
    assert_eq!(count_of(&analysis, Group::EbpfMessage, "tx"), 1);
}

#[test]
fn reports_truncation_per_file() {
    let header = header(1_700_000_000, None);
    let events: Vec<_> = (0..8_000u64)
        .map(|i| message_event(1_700_000_000_000 + i, i % 64, "inv", true, 40))
        .collect();
    let archive = compress(&record_stream(&header, &events), 3);

    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(
        &mut analysis,
        "live.bin.zst",
        &archive[..archive.len() * 3 / 4],
    );

    assert!(analysis.truncated());
    assert!(analysis.files[0].incomplete_frame);
    assert!(
        analysis.files[0].error.is_none(),
        "truncation is not an error"
    );
    assert!(analysis.total_events > 0);
    assert!(analysis.total_events < events.len() as u64);
}

/// Dropping something that is not an archive must fail cleanly, on that file only.
#[test]
fn a_file_that_is_not_an_archive_is_reported_as_an_error() {
    let mut analysis = Analysis::new(BIG_BUDGET);
    analysis.begin_file("holiday.png".to_string(), 8);
    let _ = analysis.push(&[0xFF; 64]);
    analysis.end_file();

    assert!(analysis.files[0].error.is_some());
    assert_eq!(analysis.total_events, 0);

    // A good file afterwards still loads.
    let good = compress(
        &record_stream(&header(1, None), &[message_event(1, 1, "inv", true, 40)]),
        3,
    );
    feed(&mut analysis, "good.bin.zst", &good);
    assert_eq!(analysis.total_events, 1);
    assert!(analysis.files[1].error.is_none());
}

#[test]
fn classifies_every_category() {
    use archive_viewer_core::kind::GROUPS;
    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(
        &mut analysis,
        "a.bin",
        &record_stream(
            &header(1, None),
            &[message_event(1, 1, "inv", true, 40), connection_event(2, 1)],
        ),
    );

    let categories: Vec<Category> = analysis
        .kinds
        .iter()
        .map(|(_, info)| info.category())
        .collect();
    assert!(categories.iter().all(|c| *c == Category::Ebpf));
    // Group -> category mapping is total.
    for group in GROUPS {
        let _ = group.category();
    }
}

/// prost does not enforce proto2 `required` fields, so an event with no oneof
/// arm decodes cleanly. It has to be classified rather than silently dropped,
/// otherwise an archive from a newer peer-observer would under-report.
#[test]
fn an_event_with_no_arm_is_counted_as_unknown() {
    use archive_viewer_core::kind::UNKNOWN;

    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(
        &mut analysis,
        "a.bin",
        &record_stream(
            &header(1, None),
            &[
                message_event(1, 1, "inv", true, 40),
                event_without_an_arm(2),
            ],
        ),
    );

    assert_eq!(
        analysis.decode_errors, 0,
        "it decodes, it is just unrecognised"
    );
    assert_eq!(analysis.total_events, 2);
    assert_eq!(count_of(&analysis, Group::EbpfMessage, UNKNOWN), 1);
    assert_eq!(analysis.counts.iter().sum::<u64>(), analysis.total_events);
}

/// Raw transaction data is most of a full-data archive. It must not be retained
/// — but every aggregate must still be computed from the complete event.
#[test]
fn raw_transaction_data_is_dropped_from_retained_events() {
    let header = header(1, None);
    let events = vec![
        transaction_event(100, 1, 250_000),
        message_event(200, 1, "inv", true, 40),
        transaction_event(300, 2, 250_000),
    ];
    let stream = record_stream(&header, &events);

    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(&mut analysis, "a.bin", &stream);

    assert_eq!(analysis.total_events, 3, "every event is counted");
    assert_eq!(analysis.peers.len(), 2);
    assert_eq!(analysis.stripped_events, 2);
    assert!(
        analysis.stripped_bytes >= 500_000,
        "got {}",
        analysis.stripped_bytes
    );

    // All three are retained, but the transactions no longer carry their bytes.
    assert_eq!(analysis.store.len(), 3);
    assert!(
        analysis.store.bytes_used() < 10_000,
        "retained {} bytes for a 500 kB payload",
        analysis.store.bytes_used()
    );

    // The retained copy still decodes, and still identifies the transaction.
    use archive_viewer_core::proto::{
        bitcoin_primitives::Transaction,
        ebpf_extractor::{ebpf::EbpfEvent, message::message_event::Msg},
        event::{event::PeerObserverEvent, Event},
    };
    use prost::Message;
    let raw = analysis.store.bytes(0).expect("retained");
    let decoded = Event::decode(raw).expect("stripped event still decodes");
    let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &decoded.peer_observer_event else {
        panic!("wrong arm")
    };
    let Some(EbpfEvent::Message(message)) = &ebpf.ebpf_event else {
        panic!("wrong arm")
    };
    assert_eq!(message.meta.peer_id, 1, "metadata survives");
    let Some(Msg::Tx(tx)) = &message.msg else {
        panic!("wrong msg")
    };
    let Transaction { txid, wtxid, raw } = &tx.tx;
    assert_eq!(txid.len(), 32, "txid kept");
    assert_eq!(wtxid.len(), 32, "wtxid kept");
    assert_eq!(*raw, None, "raw transaction dropped");
}

/// Stripping must not disturb events that carry no raw data.
#[test]
fn events_without_raw_data_are_retained_verbatim() {
    let events = vec![message_event(100, 1, "inv", true, 40)];
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BIG_BUDGET);
    feed(&mut analysis, "a.bin", &stream);

    assert_eq!(analysis.stripped_events, 0);
    assert_eq!(analysis.stripped_bytes, 0);
    let expected = framed(&events[0]);
    // `framed` includes the length prefix; the store holds the message only.
    assert_eq!(analysis.store.bytes(0).unwrap().len(), expected.len() - 1);
}
