mod support;

use archive_viewer_core::analysis::Analysis;
use archive_viewer_core::view::{self, Filter, QueryCache};
use serde_json::{json, Value};
use support::*;

const BUDGET: u64 = 64 * 1024 * 1024;

fn loaded() -> Analysis {
    let mut events = Vec::new();
    for i in 0..100u64 {
        events.push(message_event(1_000 + i * 10, i % 5, "inv", i % 2 == 0, 40));
    }
    for i in 0..10u64 {
        events.push(connection_event(1_000 + i * 100, i % 5));
    }
    let stream = record_stream(&header(1_700_000_000, Some(false)), &events);

    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("test.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();
    analysis
}

#[test]
fn summary_reports_totals_and_a_sorted_breakdown() {
    let analysis = loaded();
    let summary = view::summary(&analysis);

    assert_eq!(summary["totals"]["events"], 110);
    assert_eq!(summary["totals"]["peers"], 5);
    assert_eq!(summary["files"][0]["lowData"], false);
    assert_eq!(summary["files"][0]["compression"], "none");

    let breakdown = summary["breakdown"].as_array().expect("breakdown array");
    assert_eq!(breakdown[0]["kind"], "inv", "sorted by count, descending");
    assert_eq!(breakdown[0]["count"], 100);
    let total: u64 = breakdown.iter().map(|b| b["count"].as_u64().unwrap()).sum();
    assert_eq!(total, 110);

    let shares: f64 = breakdown.iter().map(|b| b["share"].as_f64().unwrap()).sum();
    assert!(
        (shares - 100.0).abs() < 1e-6,
        "shares add up to 100%, got {shares}"
    );
}

#[test]
fn timeline_downsamples_without_losing_events() {
    let analysis = loaded();
    let timeline = view::timeline(&analysis, 8);

    let count = timeline["count"].as_u64().unwrap() as usize;
    assert!(
        count <= 8,
        "downsampled to at most the requested bins, got {count}"
    );

    let series = timeline["series"].as_array().unwrap();
    assert_eq!(series.len(), 8, "one series per group");
    assert_eq!(timeline["names"].as_array().unwrap().len(), 8);
    let total: u64 = series
        .iter()
        .flat_map(|s| s.as_array().unwrap())
        .map(|v| v.as_u64().unwrap())
        .sum();
    assert_eq!(total, 110, "downsampling preserves every event");
    assert!(timeline["binMs"].as_u64().unwrap() >= 1);
}

#[test]
fn timeline_of_an_empty_analysis_is_well_formed() {
    let analysis = Analysis::new(BUDGET);
    let timeline = view::timeline(&analysis, 100);

    assert_eq!(timeline["count"], 0);
    assert_eq!(timeline["names"].as_array().unwrap().len(), 8);
}

#[test]
fn peers_sort_and_page() {
    let analysis = loaded();

    let page = view::peers(&analysis, "events", true, 0, 3);
    assert_eq!(page["total"], 5);
    let rows = page["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let counts: Vec<u64> = rows.iter().map(|r| r["events"].as_u64().unwrap()).collect();
    assert!(
        counts.windows(2).all(|w| w[0] >= w[1]),
        "descending: {counts:?}"
    );

    // Paging continues where the first page stopped.
    let second = view::peers(&analysis, "events", true, 3, 3);
    assert_eq!(second["rows"].as_array().unwrap().len(), 2);
    assert_eq!(second["offset"], 3);
}

#[test]
fn peer_detail_lists_commands_and_lifecycle() {
    let analysis = loaded();
    let detail = view::peer_detail(&analysis, 0);

    assert_eq!(detail["found"], true);
    assert_eq!(detail["peerId"], 0);
    assert_eq!(detail["connType"], "inbound");
    let commands = detail["commands"].as_array().unwrap();
    assert_eq!(commands[0]["command"], "inv");
    assert!(commands[0]["total"].as_u64().unwrap() > 0);
    assert_eq!(detail["lifecycle"].as_array().unwrap().len(), 2);

    let missing = view::peer_detail(&analysis, 9_999);
    assert_eq!(missing["found"], false);
}

#[test]
fn an_unfiltered_query_pages_through_every_event() {
    let analysis = loaded();
    let mut cache = QueryCache::new();
    let filter = Filter::default();

    let first = view::query(&analysis, &mut cache, &filter, 0, 10);
    assert_eq!(first["total"], 110);
    assert_eq!(first["rows"].as_array().unwrap().len(), 10);
    assert_eq!(first["rows"][0]["index"], 0);

    let last = view::query(&analysis, &mut cache, &filter, 105, 10);
    assert_eq!(
        last["rows"].as_array().unwrap().len(),
        5,
        "clamped at the end"
    );
}

#[test]
fn filters_by_group_peer_time_and_text() {
    let analysis = loaded();
    let mut cache = QueryCache::new();

    let by_group = Filter {
        groups: vec!["connection".into()],
        ..Default::default()
    };
    assert_eq!(
        view::query(&analysis, &mut cache, &by_group, 0, 5)["total"],
        10
    );

    let by_peer = Filter {
        peer_ids: vec![0],
        ..Default::default()
    };
    let peer_result = view::query(&analysis, &mut cache, &by_peer, 0, 100);
    assert_eq!(
        peer_result["total"], 22,
        "20 messages and 2 connection events"
    );
    for row in peer_result["rows"].as_array().unwrap() {
        assert_eq!(row["peerId"], 0);
    }

    let by_time = Filter {
        time_from: Some(1_000),
        time_to: Some(1_090),
        ..Default::default()
    };
    let timed = view::query(&analysis, &mut cache, &by_time, 0, 100);
    for row in timed["rows"].as_array().unwrap() {
        let ts = row["timestamp"].as_u64().unwrap();
        assert!((1_000..=1_090).contains(&ts));
    }

    let by_text = Filter {
        text: "inv".into(),
        ..Default::default()
    };
    assert_eq!(
        view::query(&analysis, &mut cache, &by_text, 0, 5)["total"],
        100
    );

    // Text also matches the peer address.
    let by_addr = Filter {
        text: "10.0.0.1:".into(),
        ..Default::default()
    };
    assert!(
        view::query(&analysis, &mut cache, &by_addr, 0, 5)["total"]
            .as_u64()
            .unwrap()
            > 0
    );
}

/// Combining filters must narrow, not widen.
#[test]
fn filters_combine_conjunctively() {
    let analysis = loaded();
    let mut cache = QueryCache::new();
    let filter = Filter {
        groups: vec!["message".into()],
        peer_ids: vec![1],
        ..Default::default()
    };

    let result = view::query(&analysis, &mut cache, &filter, 0, 100);
    for row in result["rows"].as_array().unwrap() {
        assert_eq!(row["group"], "message");
        assert_eq!(row["peerId"], 1);
    }
    assert_eq!(result["total"], 20);
}

/// The cache must not serve stale results when the filter changes or more
/// events arrive.
#[test]
fn the_query_cache_invalidates_correctly() {
    let mut analysis = loaded();
    let mut cache = QueryCache::new();

    let connections = Filter {
        groups: vec!["connection".into()],
        ..Default::default()
    };
    assert_eq!(
        view::query(&analysis, &mut cache, &connections, 0, 5)["total"],
        10
    );

    let messages = Filter {
        groups: vec!["message".into()],
        ..Default::default()
    };
    assert_eq!(
        view::query(&analysis, &mut cache, &messages, 0, 5)["total"],
        100
    );

    // Same filter again, from cache.
    assert_eq!(
        view::query(&analysis, &mut cache, &messages, 0, 5)["total"],
        100
    );

    // More events arrive: the cached total must be recomputed.
    let more = record_stream(
        &header(1, None),
        &[message_event(9_000, 1, "inv", true, 40)],
    );
    analysis.begin_file("second.bin".to_string(), more.len() as u64);
    analysis.push(&more).expect("push");
    analysis.end_file();
    assert_eq!(
        view::query(&analysis, &mut cache, &messages, 0, 5)["total"],
        101
    );
}

#[test]
fn a_filter_deserialises_from_the_ui_json() {
    let filter: Filter = serde_json::from_str(
        r#"{"groups":["message"],"peerIds":[7],"timeFrom":10,"timeTo":20,"text":"inv","kinds":[1,2]}"#,
    )
    .expect("filter parses");

    assert_eq!(filter.groups, vec!["message".to_string()]);
    assert_eq!(filter.peer_ids, vec![7]);
    assert_eq!(filter.time_from, Some(10));
    assert_eq!(filter.time_to, Some(20));
    assert_eq!(filter.kinds, vec![1, 2]);

    // An empty object means "no constraint", not "match nothing".
    let empty: Filter = serde_json::from_str("{}").expect("empty filter parses");
    assert_eq!(empty, Filter::default());
}

#[test]
fn a_group_timeline_breaks_the_group_down_by_kind() {
    let analysis = loaded();
    let breakdown = view::timeline_group(&analysis, "connection", 8);

    assert_eq!(breakdown["group"], "connection");
    let names = breakdown["names"].as_array().unwrap();
    assert_eq!(names.len(), 1, "the fixture only has inbound connections");
    assert_eq!(names[0], "inbound");

    let plotted: u64 = breakdown["series"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s.as_array().unwrap())
        .map(|v| v.as_u64().unwrap())
        .sum();
    assert_eq!(plotted, 10, "every connection event is plotted");
}

/// A group with more kinds than the palette can carry folds the tail into one
/// bucket rather than dropping it.
#[test]
fn a_group_timeline_folds_excess_kinds_into_other() {
    let mut events = Vec::new();
    for i in 0..40u64 {
        // 20 distinct commands, with decreasing frequency.
        let command = format!("cmd{:02}", i % 20);
        for _ in 0..(20 - (i % 20)) {
            events.push(message_event(1_000 + i, 1, &command, true, 10));
        }
    }
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("a.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let breakdown = view::timeline_group(&analysis, "message", 16);
    let names: Vec<String> = breakdown["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert_eq!(names.len(), 9, "eight kinds plus one 'other' bucket");
    assert!(
        names.last().unwrap().starts_with("other ("),
        "got {names:?}"
    );

    let plotted: u64 = breakdown["series"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s.as_array().unwrap())
        .map(|v| v.as_u64().unwrap())
        .sum();
    assert_eq!(plotted, events.len() as u64, "folding loses nothing");
}

#[test]
fn groups_present_lists_only_groups_with_events_busiest_first() {
    let analysis = loaded();
    assert_eq!(
        view::groups_present(&analysis),
        vec!["message", "connection"]
    );
    assert!(view::groups_present(&Analysis::new(BUDGET)).is_empty());
}

/// A bare kind name like `rejected` or `closed` is meaningless on its own, so
/// non-message kinds carry their group in the event table.
#[test]
fn event_labels_qualify_ambiguous_kinds() {
    let analysis = loaded();
    let mut cache = QueryCache::new();

    let messages = view::query(
        &analysis,
        &mut cache,
        &Filter {
            groups: vec!["message".into()],
            ..Default::default()
        },
        0,
        1,
    );
    assert_eq!(messages["rows"][0]["label"], "inv", "commands stand alone");

    let connections = view::query(
        &analysis,
        &mut cache,
        &Filter {
            groups: vec!["connection".into()],
            ..Default::default()
        },
        0,
        1,
    );
    assert_eq!(connections["rows"][0]["label"], "connection inbound");
}

/// `time_established` is a UNIX epoch timestamp in seconds, not a duration.
/// Reporting it as one would show a connection as having lived for decades.
#[test]
fn lifecycle_events_report_a_real_connection_lifetime() {
    use archive_viewer_core::proto::{
        bitcoin_primitives::ConnType,
        ebpf_extractor::{
            self,
            connection::{
                connection_event::Event as ConnEvent, ClosedConnection, Connection, ConnectionEvent,
            },
        },
        event::{event, Event},
    };

    let established_secs = 1_700_000_000u64;
    let closed_ms = established_secs * 1000 + 4_500; // 4.5 s later
    let event = Event {
        timestamp: closed_ms,
        peer_observer_event: Some(event::PeerObserverEvent::EbpfExtractor(
            ebpf_extractor::Ebpf {
                ebpf_event: Some(ebpf_extractor::ebpf::EbpfEvent::Connection(
                    ConnectionEvent {
                        event: Some(ConnEvent::Closed(ClosedConnection {
                            conn: Connection {
                                peer_id: 1,
                                addr: "10.0.0.1:8333".into(),
                                conn_type: ConnType::Inbound as i32,
                                network: 1,
                            },
                            time_established: established_secs,
                        })),
                    },
                )),
            },
        )),
    };

    let stream = record_stream(&header(1, None), &[event]);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("a.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let detail = view::peer_detail(&analysis, 1);
    let entry = &detail["lifecycle"][0];
    assert_eq!(entry["kind"], "closed");
    assert_eq!(
        entry["lifetimeMs"], 4_500,
        "lifetime, not the raw timestamp"
    );
    assert_eq!(entry["establishedAt"], established_secs * 1000);
}

#[test]
fn the_sequence_view_ties_requests_to_their_replies() {
    // One peer's transaction relay round trip, plus a ping that is answered
    // and a stray unsolicited addrv2 that is not.
    let events = vec![
        message_event(1_000, 3, "inv", true, 37),
        message_event(1_050, 3, "getdata", false, 37),
        message_event(1_200, 3, "tx", true, 250),
        message_event(1_260, 3, "tx", true, 190),
        message_event(1_300, 3, "addrv2", true, 60),
        message_event(1_400, 3, "ping", false, 32),
        message_event(1_512, 3, "pong", true, 32),
    ];
    let stream = record_stream(&header(1_700_000_000, Some(false)), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("test.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let mut cache = QueryCache::new();
    let page = view::sequence(&analysis, &mut cache, &Filter::default(), 0, 100);

    // The rows are exactly what `query` returns.
    let rows = page["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 7);
    assert_eq!(rows[0]["kind"], "inv");

    let ties: Vec<(u64, u64, u64)> = page["ties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["request"].as_u64().unwrap(),
                t["reply"].as_u64().unwrap(),
                t["elapsedMs"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        ties,
        vec![(0, 1, 50), (1, 2, 150), (1, 3, 210), (5, 6, 112)],
        "inv -> getdata -> two tx, and ping -> pong; the addrv2 is untied"
    );
}

#[test]
fn sequence_ties_are_positions_within_the_page() {
    let analysis = loaded();
    let mut cache = QueryCache::new();
    // `loaded()` alternates inbound and outbound `inv`, so an outbound inv is
    // never answered by a getdata -- what matters here is that a second page
    // numbers its ties from zero rather than from the offset.
    let page = view::sequence(&analysis, &mut cache, &Filter::default(), 50, 10);
    assert_eq!(page["offset"], 50);
    assert_eq!(page["rows"].as_array().unwrap().len(), 10);
    for tie in page["ties"].as_array().unwrap() {
        assert!(tie["reply"].as_u64().unwrap() < 10);
        assert!(tie["request"].as_u64().unwrap() < tie["reply"].as_u64().unwrap());
    }
}

/// A short transaction-relay conversation: two peers race to announce two
/// transactions, and both deliver one of them.
fn relay_archive() -> Analysis {
    let events = vec![
        // Peer 3 announces tx A first; peer 4 is 250 ms behind.
        inv_event(1_000, 3, &[0xA1]),
        inv_event(1_250, 4, &[0xA1]),
        // Peer 4 gets tx B in first.
        inv_event(1_400, 4, &[0xB2]),
        inv_event(1_900, 3, &[0xB2]),
        // We ask peer 3 for A and it delivers.
        message_event(2_000, 3, "getdata", false, 37),
        tx_event(2_100, 3, 0xA1, 400),
        // Peer 4 sends A too: bytes we already had.
        tx_event(2_500, 4, 0xA1, 400),
        // A ping that is answered, and one that never is.
        message_event(3_000, 3, "ping", false, 32),
        message_event(3_120, 3, "pong", true, 32),
        message_event(4_000, 4, "ping", false, 32),
        // The archive has to outlast the ping window, or that last ping is
        // still in flight when the stream ends rather than unanswered.
        message_event(4_000 + 21 * 60 * 1_000, 3, "feefilter", false, 32),
    ];
    let stream = record_stream(&header(1_700_000_000, Some(false)), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("relay.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();
    analysis
}

#[test]
fn relay_reports_the_announcement_race_and_what_duplicates_cost() {
    let analysis = relay_archive();
    let relay = view::relay(&analysis, "first", true, 10);

    assert_eq!(relay["items"], 2, "two transactions");
    assert_eq!(relay["announcements"], 4);
    assert_eq!(relay["lateAnnouncements"], 2);
    assert_eq!(relay["deliveries"], 2);
    assert_eq!(relay["duplicateDeliveries"], 1);
    assert_eq!(relay["duplicateBytes"], 400);
    assert_eq!(relay["duplicateFactor"], 2.0);
    assert_eq!(relay["capped"], false);

    // Each peer won one race, so both have a 50% win ratio.
    let rows = relay["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row["first"], 1);
        assert_eq!(row["late"], 1);
        assert_eq!(row["winRatio"], 0.5);
        assert!(row["addr"].is_string(), "the scorecard names the peer");
    }

    // Only peer 4 sent a transaction we already had.
    let by_id = |id: u64| rows.iter().find(|r| r["peerId"] == id).unwrap();
    assert_eq!(by_id(3)["duplicateBytes"], 0);
    assert_eq!(by_id(4)["duplicateBytes"], 400);
    assert_eq!(by_id(4)["duplicate"], 1);
}

#[test]
fn the_relay_scorecard_sorts_by_the_column_asked_for() {
    let analysis = relay_archive();
    let by_duplicates = view::relay(&analysis, "duplicateBytes", true, 10);
    assert_eq!(by_duplicates["rows"][0]["peerId"], 4);

    let ascending = view::relay(&analysis, "duplicateBytes", false, 10);
    assert_eq!(ascending["rows"][0]["peerId"], 3);

    // A limit truncates the listing but not the totals.
    let one = view::relay(&analysis, "first", true, 1);
    assert_eq!(one["rows"].as_array().unwrap().len(), 1);
    assert_eq!(one["peers"], 2);
}

#[test]
fn exchanges_report_what_each_request_kind_got_back() {
    let analysis = relay_archive();
    let rows = view::exchanges(&analysis);
    let rows = rows["rows"].as_array().unwrap();
    let find = |name: &str| rows.iter().find(|r| r["request"] == name);

    let ping = find("ping").expect("pings were sent");
    assert_eq!(ping["opened"], 2);
    assert_eq!(ping["answered"], 1);
    assert_eq!(ping["unanswered"], 1, "peer 4 never answered");
    assert_eq!(ping["undetermined"], 0);
    assert_eq!(ping["optional"], false);
    assert_eq!(ping["peerLatency"]["count"], 1);
    assert_eq!(ping["peerLatency"]["maxMs"], 120);

    // An announcement is never counted as a failure to answer.
    let inv = find("inv").expect("invs were sent");
    assert_eq!(inv["optional"], true);
    assert_eq!(inv["unanswered"], 0);

    // Every reported exchange names the commands that answer it.
    for row in rows {
        assert!(!row["replies"].as_array().unwrap().is_empty());
        assert!(row["opened"].as_u64().unwrap() > 0);
    }
}

#[test]
fn peer_detail_carries_the_relay_record() {
    let analysis = relay_archive();

    // Reply times and unanswered counts are archive-wide, not per peer: see
    // `exchanges_report_what_each_request_kind_got_back`. What is per peer is
    // the relay scorecard, because who announced first is a fact about a peer.
    let three = view::peer_detail(&analysis, 3);
    assert!(three["replies"].is_null(), "no per-peer reply distribution");
    assert!(three["unanswered"].is_null());
    assert_eq!(three["relay"]["first"], 1);
    assert_eq!(three["relay"]["late"], 1);

    // A peer that never relayed anything says so rather than inventing zeroes.
    let events = vec![message_event(1_000, 9, "addrv2", true, 60)];
    let stream = record_stream(&header(1, None), &events);
    let mut quiet = Analysis::new(BUDGET);
    quiet.begin_file("q.bin".to_string(), stream.len() as u64);
    quiet.push(&stream).expect("push");
    quiet.end_file();
    assert!(view::peer_detail(&quiet, 9)["relay"].is_null());
}

#[test]
fn silence_says_nothing_when_the_reply_was_never_captured() {
    // What an archive captured with a message filter looks like: `version` was
    // recorded, `verack` was not. Every handshake then appears unanswered, and
    // reporting that as peers failing to answer would be plainly wrong.
    let mut events = Vec::new();
    for i in 0..20u64 {
        events.push(message_event(1_000 + i * 10, i, "version", false, 102));
    }
    // Long enough after for the handshake window to have passed.
    events.push(message_event(
        1_000 + 5 * 60 * 1_000,
        99,
        "addrv2",
        true,
        60,
    ));
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("filtered.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let page = view::exchanges(&analysis);
    let version = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["request"] == "version")
        .expect("versions were sent");
    assert_eq!(version["opened"], 20);
    assert!(
        version["unanswered"].as_u64().unwrap() > 0,
        "they do look unanswered"
    );
    assert_eq!(
        version["repliesCaptured"], false,
        "but no verack appears anywhere in the archive"
    );
    assert_eq!(page["unansweredMeaningful"], false);

    // The same archive with veracks in it is trustworthy again.
    events.insert(1, message_event(1_005, 0, "verack", true, 24));
    let stream = record_stream(&header(1, None), &events);
    let mut answered = Analysis::new(BUDGET);
    answered.begin_file("full.bin".to_string(), stream.len() as u64);
    answered.push(&stream).expect("push");
    answered.end_file();
    let page = view::exchanges(&answered);
    let version = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["request"] == "version")
        .unwrap();
    assert_eq!(version["repliesCaptured"], true);
    assert_eq!(page["unansweredMeaningful"], true);
}

#[test]
fn reply_times_are_reported_per_request_kind_across_every_peer() {
    let analysis = relay_archive();
    let page = view::exchanges(&analysis);
    let rows = page["rows"].as_array().unwrap();
    let ping = rows.iter().find(|r| r["request"] == "ping").unwrap();

    // One distribution per request kind, not per peer: a single number per peer
    // would fold a ping round trip together with a `getaddr` that Core answers
    // on a thirty-second timer.
    assert_eq!(ping["peerLatency"]["count"], 1);
    assert_eq!(ping["peerLatency"]["p50Ms"], 120);
    assert_eq!(ping["ourLatency"]["count"], 0, "nobody pinged this node");

    // The bucket edges travel with the counts, so the page never has to know
    // how the histogram is laid out.
    let latency = &ping["peerLatency"];
    let edges = latency["edges"].as_array().unwrap();
    assert_eq!(edges.len(), latency["buckets"].as_array().unwrap().len());
    assert_eq!(edges[0]["lowMs"], 0);
    assert!(
        edges.last().unwrap()["highMs"].is_null(),
        "the last bucket is open-ended"
    );

    // Both directions are measured: this node answered peer 3's getdata-driven
    // transaction requests, and its own getdata was answered by the peer.
    let getdata = rows.iter().find(|r| r["request"] == "getdata").unwrap();
    assert!(getdata["peerLatency"]["count"].as_u64().unwrap() > 0);
}

#[test]
fn unanswered_requests_say_which_side_stayed_silent() {
    // This node asks peer 3 and is ignored; peer 4 asks this node and is
    // ignored. Adding those together would hide both.
    let events = vec![
        message_event(1_000, 3, "getaddr", false, 24),
        message_event(1_100, 4, "getaddr", true, 24),
        message_event(1_000 + 10 * 60 * 1_000, 3, "feefilter", false, 32),
    ];
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("silent.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let page = view::exchanges(&analysis);
    let getaddr = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["request"] == "getaddr")
        .expect("getaddrs were sent");
    assert_eq!(getaddr["opened"], 2);
    assert_eq!(getaddr["unanswered"], 2);
    assert_eq!(getaddr["unansweredByPeers"], 1, "peer 3 ignored this node");
    assert_eq!(getaddr["unansweredByUs"], 1, "this node ignored peer 4");
}

/// Two peers with overlapping but distinct activity, and a connection event.
fn activity_archive() -> Analysis {
    let mut events = vec![connection_event(1_000, 1)];
    // Peer 1 talks throughout; peer 2 only in the second half.
    for i in 0..40u64 {
        events.push(message_event(1_000 + i * 100, 1, "inv", i % 2 == 0, 100));
    }
    for i in 0..10u64 {
        events.push(message_event(3_000 + i * 100, 2, "tx", true, 250));
    }
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("activity.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();
    analysis
}

#[test]
fn peer_activity_rasters_each_peer_into_columns() {
    let analysis = activity_archive();
    let page = view::peer_activity(&analysis, &Filter::default(), 10, 50, 0, "first", "count");

    assert_eq!(page["columns"], 10);
    assert_eq!(page["shown"], 2);
    assert_eq!(page["peers"], 2);
    assert_eq!(page["partial"], false);

    let rows = page["rows"].as_array().unwrap();
    // First-seen order: peer 1 connected first.
    assert_eq!(rows[0]["peerId"], 1);
    assert_eq!(rows[1]["peerId"], 2);

    // Every message lands in exactly one cell, and directions are separated.
    let sum = |v: &Value| -> u64 {
        v.as_array()
            .unwrap()
            .chunks(2)
            .map(|pair| pair[1].as_u64().unwrap())
            .sum()
    };
    assert_eq!(sum(&rows[0]["in"]), 20);
    assert_eq!(sum(&rows[0]["out"]), 20);
    assert_eq!(sum(&rows[1]["in"]), 10);
    assert_eq!(sum(&rows[1]["out"]), 0, "peer 2 only ever received");

    // Columns are pairs of (column, value) and stay inside the grid.
    for row in rows {
        for lane in ["in", "out"] {
            let flat = row[lane].as_array().unwrap();
            assert_eq!(flat.len() % 2, 0, "flat pairs");
            for pair in flat.chunks(2) {
                assert!(pair[0].as_u64().unwrap() < 10);
                assert!(pair[1].as_u64().unwrap() > 0, "empty cells are not sent");
            }
        }
    }

    // The connection event is a mark, not a dot.
    let marks = rows[0]["marks"].as_array().unwrap();
    assert_eq!(marks.len(), 1);
    assert_eq!(marks[0]["kind"], "inbound");
    assert_eq!(rows[0]["marksComplete"], true);
}

#[test]
fn peer_activity_weighs_by_bytes_when_asked() {
    let analysis = activity_archive();
    let by_bytes = view::peer_activity(&analysis, &Filter::default(), 10, 50, 0, "first", "bytes");
    assert_eq!(by_bytes["byBytes"], true);

    let rows = by_bytes["rows"].as_array().unwrap();
    let sum = |v: &Value| -> u64 {
        v.as_array()
            .unwrap()
            .chunks(2)
            .map(|pair| pair[1].as_u64().unwrap())
            .sum()
    };
    // Peer 2 received ten 250-byte transactions.
    assert_eq!(sum(&rows[1]["in"]), 2_500);
}

#[test]
fn peer_activity_filters_and_orders_its_rows() {
    let analysis = activity_archive();

    // Peer 2 was only seen for 900 ms, so a longer threshold drops it.
    let long = view::peer_activity(
        &analysis,
        &Filter::default(),
        10,
        50,
        2_000,
        "first",
        "count",
    );
    assert_eq!(long["shown"], 1);
    assert_eq!(long["rows"][0]["peerId"], 1);
    assert_eq!(long["peers"], 1, "the count reflects the threshold too");

    // Busiest first is a different order from first seen.
    let busiest = view::peer_activity(&analysis, &Filter::default(), 10, 50, 0, "events", "count");
    assert_eq!(busiest["rows"][0]["peerId"], 1);

    // A row cap truncates but still reports how many there were.
    let capped = view::peer_activity(&analysis, &Filter::default(), 10, 1, 0, "first", "count");
    assert_eq!(capped["shown"], 1);
    assert_eq!(capped["peers"], 2);

    // A brushed time range narrows the span rather than the peer list.
    let brushed = Filter {
        time_from: Some(3_000),
        time_to: Some(3_900),
        ..Default::default()
    };
    let window = view::peer_activity(&analysis, &brushed, 10, 50, 0, "first", "count");
    assert_eq!(window["startMs"], 3_000);
    assert_eq!(window["endMs"], 3_900);
    let rows = window["rows"].as_array().unwrap();
    let peer2 = rows.iter().find(|r| r["peerId"] == 2).unwrap();
    let total: u64 = peer2["in"]
        .as_array()
        .unwrap()
        .chunks(2)
        .map(|p| p[1].as_u64().unwrap())
        .sum();
    assert_eq!(total, 10, "every one of peer 2's messages is in the window");
}

#[test]
fn peer_activity_of_an_empty_analysis_is_well_formed() {
    let analysis = Analysis::new(BUDGET);
    let page = view::peer_activity(&analysis, &Filter::default(), 100, 50, 0, "first", "count");
    assert_eq!(page["shown"], 0);
    assert_eq!(page["rows"].as_array().unwrap().len(), 0);
    assert_eq!(page["max"], 0);
}

#[test]
fn a_peer_raster_gives_each_command_a_row_of_its_own() {
    // One peer, three commands, and a chart scoped to that peer's own lifetime
    // rather than the archive's.
    let mut events = vec![connection_event(1_000, 1)];
    for i in 0..20u64 {
        events.push(message_event(1_000 + i * 100, 1, "inv", true, 100));
    }
    for i in 0..10u64 {
        events.push(message_event(1_050 + i * 200, 1, "getdata", false, 60));
    }
    for i in 0..5u64 {
        events.push(message_event(1_500 + i * 300, 1, "tx", true, 250));
    }
    // Another peer's traffic, which must not appear on this one's chart.
    for i in 0..8u64 {
        events.push(message_event(3_000 + i * 100, 2, "ping", true, 32));
    }
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("raster.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let page = view::peer_raster(&analysis, 1, 40, 20);
    assert_eq!(page["found"], true);
    assert_eq!(page["startMs"], 1_000);
    assert_eq!(
        page["endMs"], 2_900,
        "the peer's last message, not the archive's"
    );
    assert_eq!(page["columns"], 40);
    assert_eq!(page["commands"], 3);

    // Busiest command first, and each direction on its own lane.
    let rows = page["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let sum = |v: &Value| -> u64 {
        v.as_array()
            .unwrap()
            .chunks(2)
            .map(|pair| pair[1].as_u64().unwrap())
            .sum()
    };
    for (row, kind, inbound, outbound) in [
        (&rows[0], "inv", 20, 0),
        (&rows[1], "getdata", 0, 10),
        (&rows[2], "tx", 5, 0),
    ] {
        assert_eq!(row["kind"], kind);
        assert_eq!(row["totalIn"], inbound);
        assert_eq!(row["totalOut"], outbound);
        assert_eq!(sum(&row["in"]), inbound, "{kind} inbound cells");
        assert_eq!(sum(&row["out"]), outbound, "{kind} outbound cells");
    }

    // Every column referenced is on the chart, and the peak is a real cell.
    let mut peak = 0;
    for row in rows {
        for lane in ["in", "out"] {
            for pair in row[lane].as_array().unwrap().chunks(2) {
                assert!(pair[0].as_u64().unwrap() < 40, "column on the chart");
                peak = peak.max(pair[1].as_u64().unwrap());
            }
        }
    }
    assert_eq!(page["max"], peak);

    // The connection event is a mark, not traffic.
    let marks = page["marks"].as_array().unwrap();
    assert_eq!(marks.len(), 1);
    assert_eq!(marks[0]["kind"], "inbound");
    assert!(marks[0]["col"].as_u64().unwrap() < 40);

    // Asking for fewer rows than there are commands drops the quietest, and
    // says how many there were.
    let capped = view::peer_raster(&analysis, 1, 40, 2);
    assert_eq!(capped["rows"].as_array().unwrap().len(), 2);
    assert_eq!(
        capped["commands"], 3,
        "the ones that did not fit are counted"
    );
    assert_eq!(capped["rows"][0]["kind"], "inv");
}

#[test]
fn a_peer_raster_survives_a_peer_seen_once() {
    // A peer with a single event has no duration to divide into columns.
    let events = vec![message_event(5_000, 42, "ping", true, 32)];
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("one.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let page = view::peer_raster(&analysis, 42, 100, 20);
    assert_eq!(page["found"], true);
    assert_eq!(page["rows"].as_array().unwrap().len(), 1);
    assert_eq!(page["rows"][0]["kind"], "ping");
    assert_eq!(page["rows"][0]["in"], json!([0, 1]));

    // A peer that is not in the archive is reported as such, not as empty data.
    let missing = view::peer_raster(&analysis, 999, 100, 20);
    assert_eq!(missing["found"], false);
    assert_eq!(missing["rows"].as_array().unwrap().len(), 0);
}

#[test]
fn connection_durations_split_by_type_and_by_how_they_ended() {
    use archive_viewer_core::proto::bitcoin_primitives::ConnType;

    // Three inbound connections Core evicted after a second or so, one that
    // closed after an hour, and an outbound that lasted two hours.
    let base = 1_700_000_000u64;
    let ms = |s: u64| s * 1_000;
    let events = vec![
        connection_end(ms(base + 1), 1, ConnType::Inbound, base, true),
        connection_end(ms(base + 2), 2, ConnType::Inbound, base, true),
        connection_end(ms(base + 4), 3, ConnType::Inbound, base, true),
        connection_end(ms(base + 3_600), 4, ConnType::Inbound, base, false),
        connection_end(
            ms(base + 7_200),
            5,
            ConnType::OutboundFullRelay,
            base,
            false,
        ),
    ];
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("conn.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let all = view::connection_durations(&analysis, "all");
    assert_eq!(all["connections"], 5);
    assert_eq!(all["any"], true);
    let rows = all["rows"].as_array().unwrap();
    let by = |name: &str| rows.iter().find(|r| r["connType"] == name).unwrap();

    let inbound = by("inbound");
    assert_eq!(inbound["durations"]["count"], 4);
    assert_eq!(inbound["evicted"], 3);
    assert_eq!(inbound["closed"], 1);
    assert_eq!(inbound["durations"]["minMs"], 1_000);
    assert_eq!(
        inbound["durations"]["maxMs"], 3_600_000,
        "an hour, in the wide buckets"
    );

    let outbound = by("outbound-full-relay");
    assert_eq!(outbound["durations"]["count"], 1);
    assert_eq!(outbound["durations"]["maxMs"], 7_200_000);

    // Filtering by ending picks out one population.
    let evicted = view::connection_durations(&analysis, "evicted");
    let rows = evicted["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "only inbound connections are evicted");
    assert_eq!(rows[0]["durations"]["count"], 3);
    assert_eq!(rows[0]["durations"]["maxMs"], 4_000);

    let closed = view::connection_durations(&analysis, "closed");
    assert_eq!(closed["connections"], 2);

    // A type this node never had is left out rather than drawn empty.
    assert!(rows.iter().all(|r| r["connType"] != "feeler"));
}

#[test]
fn connection_durations_ignore_events_that_cannot_give_a_lifetime() {
    use archive_viewer_core::proto::bitcoin_primitives::ConnType;

    // An opening connection has no establishment time, and a close that claims
    // to have been established in the future must not become a huge duration.
    let base = 1_700_000_000u64;
    let events = vec![
        connection_event(base * 1_000, 1),
        connection_end(base * 1_000, 2, ConnType::Inbound, base + 10_000, false),
    ];
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("odd.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let page = view::connection_durations(&analysis, "all");
    assert_eq!(page["connections"], 1, "only the close counts");
    assert_eq!(
        page["rows"][0]["durations"]["maxMs"], 0,
        "clamped, not wrapped"
    );

    // An archive with no connection events at all says so.
    let empty = Analysis::new(BUDGET);
    let none = view::connection_durations(&empty, "all");
    assert_eq!(none["any"], false);
    assert_eq!(none["rows"].as_array().unwrap().len(), 0);
}

#[test]
fn a_peer_is_named_by_its_version_message() {
    let events = vec![
        version_event(1_000, 1, "/Satoshi:29.0.0/", true),
        version_event(1_100, 2, "/Satoshi:28.1.0/", true),
        version_event(1_200, 3, "/Satoshi:29.0.0/", true),
        // Outbound version carries this node's own agent, not the peer's.
        version_event(1_300, 4, "/ThisNode:1.0/", false),
    ];
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("ua.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    let one = view::peer_detail(&analysis, 1);
    assert_eq!(one["userAgent"], "/Satoshi:29.0.0/");
    assert_eq!(one["userAgentFrom"], "version");
    assert!(
        view::peer_detail(&analysis, 4)["userAgent"].is_null(),
        "an outbound version says nothing about the peer"
    );

    // Interned once, counted per peer, commonest first.
    let agents = view::user_agents(&analysis, 10);
    assert_eq!(agents["distinct"], 2);
    assert_eq!(agents["named"], 3);
    assert_eq!(agents["unknown"], 1, "peer 4 never named itself");
    let rows = agents["rows"].as_array().unwrap();
    assert_eq!(rows[0]["userAgent"], "/Satoshi:29.0.0/");
    assert_eq!(rows[0]["peers"], 2);
    assert_eq!(rows[1]["peers"], 1);
}

#[test]
fn getpeerinfo_names_peers_the_version_messages_did_not() {
    // What an archive captured without the P2P message tracepoints looks like:
    // the peers are known from connection events, and only the RPC poll says
    // what they are.
    let events = vec![
        connection_event(1_000, 7),
        connection_event(1_010, 8),
        peer_infos_event(1_500, &[(7, "/Satoshi:27.0.0/"), (8, "/bcoin:2.2.0/")]),
        // A later poll repeating itself must not double-count or churn.
        peer_infos_event(2_500, &[(7, "/Satoshi:27.0.0/"), (8, "/bcoin:2.2.0/")]),
        // A peer this archive never otherwise saw is not invented from a poll.
        peer_infos_event(3_500, &[(99, "/Ghost:1.0/")]),
    ];
    let stream = record_stream(&header(1, None), &events);
    let mut analysis = Analysis::new(BUDGET);
    analysis.begin_file("rpc.bin".to_string(), stream.len() as u64);
    analysis.push(&stream).expect("push");
    analysis.end_file();

    assert_eq!(
        view::peer_detail(&analysis, 7)["userAgent"],
        "/Satoshi:27.0.0/"
    );
    assert_eq!(
        view::peer_detail(&analysis, 7)["userAgentFrom"],
        "getpeerinfo"
    );
    assert_eq!(
        view::peer_detail(&analysis, 8)["userAgent"],
        "/bcoin:2.2.0/"
    );
    assert_eq!(view::peer_detail(&analysis, 99)["found"], false);

    let agents = view::user_agents(&analysis, 10);
    assert_eq!(agents["distinct"], 2, "the ghost peer interned nothing");
    assert_eq!(agents["named"], 2);
    assert_eq!(agents["peers"], 2);
}

#[test]
fn a_version_message_wins_over_the_rpc_snapshot() {
    // Both sources present. The version message is what the peer put on the
    // wire, so it is the one reported, whichever arrives first.
    for version_first in [true, false] {
        let mut events = vec![connection_event(1_000, 5)];
        let version = version_event(2_000, 5, "/FromTheWire:1/", true);
        let poll = peer_infos_event(3_000, &[(5, "/FromTheRpc:1/")]);
        if version_first {
            events.push(version);
            events.push(poll);
        } else {
            events.push(poll);
            events.push(version);
        }
        let stream = record_stream(&header(1, None), &events);
        let mut analysis = Analysis::new(BUDGET);
        analysis.begin_file("both.bin".to_string(), stream.len() as u64);
        analysis.push(&stream).expect("push");
        analysis.end_file();

        let detail = view::peer_detail(&analysis, 5);
        assert_eq!(
            detail["userAgent"], "/FromTheWire:1/",
            "version_first={version_first}"
        );
        assert_eq!(detail["userAgentFrom"], "version");
    }
}
