mod support;

use archive_viewer_core::analysis::Analysis;
use archive_viewer_core::view::{self, Filter, QueryCache};
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
        peer_id: Some(0),
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
        peer_id: Some(1),
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
        r#"{"groups":["message"],"peerId":7,"timeFrom":10,"timeTo":20,"text":"inv","kinds":[1,2]}"#,
    )
    .expect("filter parses");

    assert_eq!(filter.groups, vec!["message".to_string()]);
    assert_eq!(filter.peer_id, Some(7));
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
