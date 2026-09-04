//! JSON views over an [`Analysis`], consumed by the web UI.
//!
//! Everything crossing the wasm boundary is JSON: the payloads are small (a page
//! of rows, a summary object) and it keeps the JavaScript side free of bindings.
//! Building them here rather than in the wasm crate keeps them natively testable.

use crate::analysis::Analysis;
use crate::asn;
use crate::exchange::{self, match_turns, Turn};
use crate::kind::{Group, GROUPS};
use crate::latency::{self, Latencies};
use crate::peers::{LifecycleKind, PeerStats};
use crate::proto::bitcoin_primitives::ConnType;
use crate::relay;
use crate::store::NO_PEER;
use serde::Deserialize;
use serde_json::{json, Value};

/// Totals, per-file detail and the category/group/kind breakdown.
pub fn summary(analysis: &Analysis) -> Value {
    let files: Vec<Value> = analysis
        .files
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "compression": f.compression,
                "created": f.created,
                "lowData": f.low_data,
                "declaredBytes": f.declared_bytes,
                "compressedBytes": f.compressed_bytes,
                "decompressedBytes": f.decompressed_bytes,
                "events": f.events,
                "decodeErrors": f.decode_errors,
                "truncated": f.truncated,
                "incompleteFrame": f.incomplete_frame,
                "trailingBytes": f.trailing_bytes,
                "error": f.error,
            })
        })
        .collect();

    let mut breakdown: Vec<Value> = analysis
        .kinds
        .iter()
        .map(|(id, info)| {
            let count = analysis.counts.get(id as usize).copied().unwrap_or(0);
            json!({
                "id": id,
                "category": info.category().as_str(),
                "group": info.group.as_str(),
                "kind": info.name,
                "label": info.label(),
                "count": count,
                "share": share(count, analysis.total_events),
            })
        })
        .collect();
    breakdown.sort_by_key(|entry| std::cmp::Reverse(entry["count"].as_u64().unwrap_or(0)));

    let compressed: u64 = analysis.files.iter().map(|f| f.compressed_bytes).sum();
    let decompressed: u64 = analysis.files.iter().map(|f| f.decompressed_bytes).sum();

    json!({
        "files": files,
        "totals": {
            "events": analysis.total_events,
            "decodeErrors": analysis.decode_errors,
            "peers": analysis.peers.len(),
            "kinds": analysis.kinds.len(),
            "firstTimestamp": analysis.first_timestamp,
            "lastTimestamp": analysis.last_timestamp,
            "durationMs": analysis.duration_ms(),
            "compressedBytes": compressed,
            "decompressedBytes": decompressed,
            "truncated": analysis.truncated(),
        },
        "retention": {
            "retained": analysis.store.len(),
            "bytesUsed": analysis.store.bytes_used(),
            "budgetBytes": analysis.store.budget_bytes(),
            "full": analysis.store.is_full(),
            "strippedEvents": analysis.stripped_events,
            "strippedBytes": analysis.stripped_bytes,
            "stoppedBecause": match analysis.store.stopped_because() {
                Some(crate::store::StoppedBecause::Budget) => Some("budget"),
                Some(crate::store::StoppedBecause::OutOfMemory) => Some("memory"),
                None => None,
            },
        },
        "breakdown": breakdown,
    })
}

/// Progress while a file is still loading.
pub fn progress(analysis: &Analysis) -> Value {
    json!({
        "events": analysis.total_events,
        "compressedBytes": analysis.files.iter().map(|f| f.compressed_bytes).sum::<u64>(),
        "decompressedBytes": analysis.files.iter().map(|f| f.decompressed_bytes).sum::<u64>(),
        "peers": analysis.peers.len(),
        "decodeErrors": analysis.decode_errors,
    })
}

/// Merge a set of per-kind series into one downsampled series per output slot.
///
/// The histogram keeps up to 4096 bins; a chart is a few hundred pixels wide, so
/// merging down avoids shipping data the UI cannot draw. Whole numbers of source
/// bins are merged so bin boundaries stay meaningful.
fn downsample(
    analysis: &Analysis,
    slots: &[Vec<u16>],
    max_bins: usize,
) -> (usize, u64, Vec<Vec<u64>>) {
    let histogram = &analysis.histogram;
    let bins = histogram.bins();
    if bins == 0 || max_bins == 0 {
        return (0, histogram.bin_ms(), vec![Vec::new(); slots.len()]);
    }
    let merge = bins.div_ceil(max_bins).max(1);
    let out_len = bins.div_ceil(merge);

    let mut series = vec![vec![0u64; out_len]; slots.len()];
    for (slot, kinds) in slots.iter().enumerate() {
        for kind in kinds {
            for (i, count) in histogram.series(*kind).iter().enumerate() {
                if *count > 0 {
                    series[slot][i / merge] += count;
                }
            }
        }
    }
    (out_len, histogram.bin_ms() * merge as u64, series)
}

fn timeline_value(
    analysis: &Analysis,
    names: Vec<String>,
    out: (usize, u64, Vec<Vec<u64>>),
) -> Value {
    let (count, bin_ms, series) = out;
    json!({
        "startMs": analysis.histogram.start_ms(),
        "binMs": bin_ms,
        "count": count,
        "series": series,
        "names": names,
    })
}

/// The whole archive over time, one series per event group.
pub fn timeline(analysis: &Analysis, max_bins: usize) -> Value {
    let slots: Vec<Vec<u16>> = GROUPS
        .iter()
        .map(|group| {
            analysis
                .kinds
                .iter()
                .filter(|(_, info)| info.group == *group)
                .map(|(id, _)| id)
                .collect()
        })
        .collect();
    let names = GROUPS.iter().map(|g| g.as_str().to_string()).collect();
    timeline_value(analysis, names, downsample(analysis, &slots, max_bins))
}

/// One group over time, broken down by kind — the connection event rate by type,
/// the message mix by command, and so on.
///
/// This covers every event in the archive, not just the retained ones, because
/// the histogram is kept per kind.
pub fn timeline_group(analysis: &Analysis, group: &str, max_bins: usize) -> Value {
    // Busiest kinds first, and capped: a categorical palette is only readable
    // for so many series, and `message` alone can have dozens of commands.
    const MAX_SERIES: usize = 8;

    let mut kinds: Vec<(u16, &str, u64)> = analysis
        .kinds
        .iter()
        .filter(|(_, info)| info.group.as_str() == group)
        .map(|(id, info)| {
            (
                id,
                info.name.as_str(),
                analysis.counts.get(id as usize).copied().unwrap_or(0),
            )
        })
        .filter(|(_, _, count)| *count > 0)
        .collect();
    kinds.sort_by_key(|(id, _, count)| (std::cmp::Reverse(*count), *id));

    let mut slots: Vec<Vec<u16>> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for (id, name, _) in kinds.iter().take(MAX_SERIES) {
        slots.push(vec![*id]);
        names.push((*name).to_string());
    }
    if kinds.len() > MAX_SERIES {
        // Everything past the cap folds into one bucket rather than being
        // dropped or given a made-up colour.
        slots.push(kinds[MAX_SERIES..].iter().map(|(id, _, _)| *id).collect());
        names.push(format!("other ({})", kinds.len() - MAX_SERIES));
    }

    let mut value = timeline_value(analysis, names, downsample(analysis, &slots, max_bins));
    if let Some(object) = value.as_object_mut() {
        object.insert("group".into(), json!(group));
    }
    value
}

/// Groups present in the archive, busiest first, for the breakdown selector.
pub fn groups_present(analysis: &Analysis) -> Vec<&'static str> {
    let mut totals: Vec<(&'static str, u64)> = GROUPS
        .iter()
        .map(|group| {
            let total: u64 = analysis
                .kinds
                .iter()
                .filter(|(_, info)| info.group == *group)
                .map(|(id, _)| analysis.counts.get(id as usize).copied().unwrap_or(0))
                .sum();
            (group.as_str(), total)
        })
        .filter(|(_, total)| *total > 0)
        .collect();
    totals.sort_by_key(|(_, total)| std::cmp::Reverse(*total));
    totals.into_iter().map(|(name, _)| name).collect()
}

/// How peer rows are ordered.
fn peer_sort_key(peer: &PeerStats, sort: &str) -> u64 {
    match sort {
        "firstSeen" => peer.first_seen,
        "lastSeen" => peer.last_seen,
        "duration" => peer.duration_ms(),
        "messagesIn" => peer.messages_in,
        "messagesOut" => peer.messages_out,
        "bytesIn" => peer.bytes_in,
        "bytesOut" => peer.bytes_out,
        "events" => peer.events(),
        _ => peer.peer_id,
    }
}

/// A page of the peer table.
pub fn peers(
    analysis: &Analysis,
    sort: &str,
    descending: bool,
    offset: usize,
    limit: usize,
) -> Value {
    let mut rows: Vec<&PeerStats> = analysis.peers.iter().collect();
    rows.sort_by(|a, b| {
        let ordering = peer_sort_key(a, sort).cmp(&peer_sort_key(b, sort));
        // Peer id as a tiebreak keeps paging stable for equal keys.
        let ordering = if descending {
            ordering.reverse()
        } else {
            ordering
        };
        ordering.then(a.peer_id.cmp(&b.peer_id))
    });

    let total = rows.len();
    let page: Vec<Value> = rows
        .iter()
        .skip(offset)
        .take(limit)
        .map(|p| peer_row(p))
        .collect();
    json!({ "total": total, "offset": offset, "rows": page })
}

fn peer_row(peer: &PeerStats) -> Value {
    json!({
        "peerId": peer.peer_id,
        "index": peer.index,
        "addr": peer.addr,
        "connType": peer.conn_type.map(conn_type_name),
        "network": peer.network.map(network_name),
        "firstSeen": peer.first_seen,
        "lastSeen": peer.last_seen,
        "durationMs": peer.duration_ms(),
        "messagesIn": peer.messages_in,
        "messagesOut": peer.messages_out,
        "bytesIn": peer.bytes_in,
        "bytesOut": peer.bytes_out,
        "events": peer.events(),
        "lifecycleEvents": peer.lifecycle_total,
    })
}

/// One peer in full: identity, per-command counts and connection lifecycle.
pub fn peer_detail(analysis: &Analysis, peer_id: u64) -> Value {
    let Some(peer) = analysis.peers.get(peer_id) else {
        return json!({ "found": false, "peerId": peer_id });
    };

    let mut commands: Vec<Value> = peer
        .commands
        .iter()
        .map(|(command, counts)| {
            json!({
                "command": analysis.kinds.get(*command).map(|k| k.name.as_str()).unwrap_or("?"),
                "inbound": counts.inbound,
                "outbound": counts.outbound,
                "inboundBytes": counts.inbound_bytes,
                "outboundBytes": counts.outbound_bytes,
                "total": counts.inbound + counts.outbound,
            })
        })
        .collect();
    commands.sort_by_key(|c| std::cmp::Reverse(c["total"].as_u64().unwrap_or(0)));

    let lifecycle: Vec<Value> = peer
        .lifecycle
        .iter()
        .map(|e| {
            json!({
                "timestamp": e.timestamp,
                "kind": e.kind.as_str(),
                // `time_established` is a UNIX epoch timestamp in *seconds*, not
                // a duration. What is actually interesting is how long the
                // connection lived, so derive that from the event's own
                // millisecond timestamp.
                "establishedAt": e.time_established.map(|s| s * 1000),
                "lifetimeMs": e.time_established
                    .map(|s| e.timestamp.saturating_sub(s * 1000)),
                "existingConnections": e.existing_connections,
                "message": e.message,
            })
        })
        .collect();

    let mut row = peer_row(peer);
    if let Some(object) = row.as_object_mut() {
        object.insert("found".into(), Value::Bool(true));
        object.insert("commands".into(), Value::Array(commands));
        object.insert("lifecycle".into(), Value::Array(lifecycle));
        object.insert("lifecycleTotal".into(), json!(peer.lifecycle_total));
        object.insert("lifecycleCap".into(), json!(crate::peers::LIFECYCLE_CAP));
        object.insert(
            "relay".into(),
            analysis
                .relay
                .peer(peer_id)
                .filter(|r| !r.is_empty())
                .map_or(Value::Null, |r| relay_row(analysis, peer_id, r)),
        );
    }
    row
}

/// Filter for the raw event table. Absent fields mean "no constraint".
#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct Filter {
    /// Kind ids to include.
    pub kinds: Vec<u16>,
    /// Group names to include, e.g. `message`, `connection`.
    pub groups: Vec<String>,
    /// Peers to include. Empty means every peer; several are allowed so a
    /// sequence diagram can show a conversation across more than one peer.
    pub peer_ids: Vec<u64>,
    pub time_from: Option<u64>,
    pub time_to: Option<u64>,
    /// Substring match against the kind name and the peer address.
    pub text: String,
}

impl Filter {
    fn is_unconstrained(&self) -> bool {
        self.kinds.is_empty()
            && self.groups.is_empty()
            && self.peer_ids.is_empty()
            && self.time_from.is_none()
            && self.time_to.is_none()
            && self.text.is_empty()
    }
}

/// Caches the indices matching the last filter, so paging through a virtualized
/// table does not rescan every event on every scroll.
#[derive(Debug, Default)]
pub struct QueryCache {
    filter: Option<Filter>,
    /// `None` when the filter matches everything, in which case index == row.
    matches: Option<Vec<u32>>,
    total: usize,
    /// Retained-event count the cache was built against, to spot staleness.
    built_at_len: usize,
}

impl QueryCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn refresh(&mut self, analysis: &Analysis, filter: &Filter) {
        let fresh =
            self.filter.as_ref() == Some(filter) && self.built_at_len == analysis.store.len();
        if fresh {
            return;
        }
        if filter.is_unconstrained() {
            self.matches = None;
            self.total = analysis.store.len();
        } else {
            let matches = scan(analysis, filter);
            self.total = matches.len();
            self.matches = Some(matches);
        }
        self.filter = Some(filter.clone());
        self.built_at_len = analysis.store.len();
    }
}

fn scan(analysis: &Analysis, filter: &Filter) -> Vec<u32> {
    let store = &analysis.store;
    let timestamps = store.timestamps();
    let kinds = store.kinds();
    let peer_column = store.peers();

    // Resolve the filter to dense ids once rather than per row.
    let peer_wanted: Option<Vec<u32>> = (!filter.peer_ids.is_empty()).then(|| {
        filter
            .peer_ids
            .iter()
            .map(|id| analysis.peers.get(*id).map_or(NO_PEER, |p| p.index))
            .collect()
    });
    let kind_allowed: Option<Vec<bool>> = (!filter.kinds.is_empty() || !filter.groups.is_empty())
        .then(|| {
            (0..analysis.kinds.len() as u16)
                .map(|id| {
                    let Some(info) = analysis.kinds.get(id) else {
                        return false;
                    };
                    let by_kind = filter.kinds.contains(&id);
                    let by_group = filter.groups.iter().any(|g| g == info.group.as_str());
                    by_kind || by_group
                })
                .collect()
        });
    let needle = filter.text.to_lowercase();

    (0..timestamps.len() as u32)
        .filter(|&i| {
            let row = i as usize;
            if let Some(from) = filter.time_from {
                if timestamps[row] < from {
                    return false;
                }
            }
            if let Some(to) = filter.time_to {
                if timestamps[row] > to {
                    return false;
                }
            }
            if let Some(wanted) = &peer_wanted {
                if !wanted.contains(&peer_column[row]) {
                    return false;
                }
            }
            if let Some(allowed) = &kind_allowed {
                if !allowed.get(kinds[row] as usize).copied().unwrap_or(false) {
                    return false;
                }
            }
            if !needle.is_empty() && !matches_text(analysis, row, &needle) {
                return false;
            }
            true
        })
        .collect()
}

fn matches_text(analysis: &Analysis, row: usize, needle: &str) -> bool {
    let kind = analysis.kinds.get(analysis.store.kinds()[row]);
    if let Some(info) = kind {
        if info.name.to_lowercase().contains(needle) {
            return true;
        }
    }
    let peer = analysis.store.peers()[row];
    if peer != NO_PEER {
        if let Some(stats) = analysis
            .peers
            .peer_id_at(peer)
            .and_then(|id| analysis.peers.get(id))
        {
            if let Some(addr) = &stats.addr {
                if addr.to_lowercase().contains(needle) {
                    return true;
                }
            }
        }
    }
    false
}

/// Serialise a latency distribution for the UI.
fn latencies(l: &Latencies) -> Value {
    json!({
        "count": l.count(),
        "minMs": l.min_ms(),
        "maxMs": l.max_ms(),
        "meanMs": l.mean_ms(),
        "p50Ms": l.percentile_ms(0.5),
        "p90Ms": l.percentile_ms(0.9),
        "p99Ms": l.percentile_ms(0.99),
        "buckets": l.buckets(),
        // Bucket edges travel with the counts so the page never has to know how
        // the buckets are laid out.
        "edges": (0..latency::BUCKETS)
            .map(|i| {
                let (low, high) = latency::bucket_range(i);
                json!({ "lowMs": low, "highMs": high })
            })
            .collect::<Vec<_>>(),
    })
}

/// One peer's line in the relay scorecard.
fn relay_row(analysis: &Analysis, peer_id: u64, record: &relay::PeerRelay) -> Value {
    let peer = analysis.peers.get(peer_id);
    json!({
        "peerId": peer_id,
        "addr": peer.and_then(|p| p.addr.clone()),
        "connType": peer.and_then(|p| p.conn_type).map(conn_type_name),
        "first": record.first,
        "late": record.late,
        "winRatio": record.win_ratio(),
        "lagP50Ms": record.lag.percentile_ms(0.5),
        "lagP90Ms": record.lag.percentile_ms(0.9),
        "delivered": record.delivered,
        "duplicate": record.duplicate,
        "duplicateBytes": record.duplicate_bytes,
        "heardToHeldP50Ms": record.heard_to_held.percentile_ms(0.5),
    })
}

/// A raster of per-peer activity over time: one row per peer, one column per
/// pixel, split by direction.
///
/// Built by scanning the retained events once, which is what makes it exact:
/// there is no per-peer-per-time aggregate kept during ingest, and adding one
/// would cost memory proportional to peers times bins for a view most archives
/// never open. The scan is linear over the columnar store and takes tens of
/// milliseconds on a few million events.
///
/// Only *retained* events are in the store, so on an archive that exhausted its
/// retention budget this covers the part that was kept. The caller is told, and
/// says so.
///
/// `weight` is `bytes` to accumulate wire bytes instead of message counts.
/// `sort` is `events` for the busiest peers first, anything else for
/// first-seen order, which is what makes connection churn legible.
#[allow(clippy::too_many_arguments)]
pub fn peer_activity(
    analysis: &Analysis,
    filter: &Filter,
    columns: usize,
    max_rows: usize,
    min_duration_ms: u64,
    sort: &str,
    weight: &str,
) -> Value {
    let columns = columns.clamp(1, 4096);
    let (start, end) = activity_span(analysis, filter);
    if end <= start {
        return json!({
            "columns": columns, "startMs": start, "endMs": end, "binMs": 0,
            "rows": [], "peers": 0, "shown": 0, "max": 0, "partial": false,
        });
    }
    let span = end - start;

    // Peers worth a row: seen inside the window, and connected long enough to
    // be worth one. A churn archive has hundreds of thousands of peers that
    // lived under a second, and a row each would be a solid block of noise.
    let mut candidates: Vec<&PeerStats> = analysis
        .peers
        .iter()
        .filter(|p| {
            p.duration_ms() >= min_duration_ms && p.last_seen >= start && p.first_seen <= end
        })
        .collect();
    let total_candidates = candidates.len();
    if sort == "events" {
        candidates.sort_by(|a, b| b.events().cmp(&a.events()).then(a.peer_id.cmp(&b.peer_id)));
    } else {
        candidates.sort_by(|a, b| {
            a.first_seen
                .cmp(&b.first_seen)
                .then(a.peer_id.cmp(&b.peer_id))
        });
    }
    candidates.truncate(max_rows);

    // Store peer index -> row. `usize::MAX` for peers with no row.
    let mut row_of = vec![usize::MAX; analysis.peers.len()];
    for (row, peer) in candidates.iter().enumerate() {
        if let Some(slot) = row_of.get_mut(peer.index as usize) {
            *slot = row;
        }
    }

    let by_bytes = weight == "bytes";
    let mut grid = vec![0u64; candidates.len() * columns * 2];
    let mut peak = 0u64;

    let timestamps = analysis.store.timestamps();
    let peers = analysis.store.peers();
    let flags = analysis.store.flags();
    let sizes = analysis.store.sizes();
    for i in 0..timestamps.len() {
        let peer = peers[i];
        if peer == NO_PEER {
            continue;
        }
        let Some(&row) = row_of.get(peer as usize) else {
            continue;
        };
        if row == usize::MAX {
            continue;
        }
        let timestamp = timestamps[i];
        if timestamp < start || timestamp > end {
            continue;
        }
        // Only directed messages have a lane; connection events are drawn from
        // the lifecycle marks instead.
        if flags[i] & crate::store::flags::HAS_DIRECTION == 0 {
            continue;
        }
        let lane = usize::from(flags[i] & crate::store::flags::INBOUND != 0);
        let column = (((timestamp - start) as u128 * columns as u128) / span as u128) as usize;
        let column = column.min(columns - 1);
        let slot = &mut grid[(row * columns + column) * 2 + lane];
        *slot += if by_bytes { u64::from(sizes[i]) } else { 1 };
        peak = peak.max(*slot);
    }

    let column_of = |timestamp: u64| -> Option<usize> {
        (timestamp >= start && timestamp <= end).then(|| {
            ((((timestamp - start) as u128 * columns as u128) / span as u128) as usize)
                .min(columns - 1)
        })
    };

    let rows: Vec<Value> = candidates
        .iter()
        .enumerate()
        .map(|(row, peer)| {
            // Sparse: a column with nothing in it is most of them for most
            // peers, and sending those would dominate the payload.
            let mut inbound = Vec::new();
            let mut outbound = Vec::new();
            for column in 0..columns {
                let base = (row * columns + column) * 2;
                if grid[base + 1] > 0 {
                    inbound.push(column as u64);
                    inbound.push(grid[base + 1]);
                }
                if grid[base] > 0 {
                    outbound.push(column as u64);
                    outbound.push(grid[base]);
                }
            }
            let marks: Vec<Value> = peer
                .lifecycle
                .iter()
                .filter_map(|e| {
                    column_of(e.timestamp).map(|column| {
                        json!({ "col": column, "kind": e.kind.as_str(), "timestamp": e.timestamp })
                    })
                })
                .collect();
            json!({
                "peerId": peer.peer_id,
                "addr": peer.addr,
                "connType": peer.conn_type.map(conn_type_name),
                "firstSeen": peer.first_seen,
                "lastSeen": peer.last_seen,
                "durationMs": peer.duration_ms(),
                "events": peer.events(),
                "messagesIn": peer.messages_in,
                "messagesOut": peer.messages_out,
                "in": inbound,
                "out": outbound,
                "marks": marks,
                // The lifecycle list is capped, so say when marks are missing.
                "marksComplete": peer.lifecycle_total as usize <= peer.lifecycle.len(),
            })
        })
        .collect();

    json!({
        "columns": columns,
        "startMs": start,
        "endMs": end,
        "binMs": span as f64 / columns as f64,
        "rows": rows,
        "peers": total_candidates,
        "shown": candidates.len(),
        "max": peak,
        "byBytes": by_bytes,
        // Retention stopped short, so this covers only what was kept.
        "partial": analysis.store.is_full(),
        "retained": analysis.store.len(),
        "totalEvents": analysis.total_events,
    })
}

/// The time window the activity chart covers.
fn activity_span(analysis: &Analysis, filter: &Filter) -> (u64, u64) {
    let start = filter
        .time_from
        .or(analysis.first_timestamp)
        .unwrap_or_default();
    let end = filter
        .time_to
        .or(analysis.last_timestamp)
        .unwrap_or_default();
    (start, end)
}

/// Transaction relay: who announced what first, and what the duplicates cost.
///
/// `sort` picks the column: `first`, `late`, `win`, `lag`, `delivered` or
/// `duplicateBytes`.
pub fn relay(analysis: &Analysis, sort: &str, descending: bool, limit: usize) -> Value {
    let relay = &analysis.relay;
    let mut rows: Vec<(u64, &relay::PeerRelay)> =
        relay.peers().filter(|(_, r)| !r.is_empty()).collect();
    rows.sort_by(|a, b| {
        let key = |r: &relay::PeerRelay| -> f64 {
            match sort {
                "late" => r.late as f64,
                "win" => r.win_ratio().unwrap_or(-1.0),
                "lag" => r.lag.percentile_ms(0.5).unwrap_or(0) as f64,
                "delivered" => r.delivered as f64,
                "duplicate" => r.duplicate as f64,
                "duplicateBytes" => r.duplicate_bytes as f64,
                _ => r.first as f64,
            }
        };
        let ordering = key(a.1)
            .partial_cmp(&key(b.1))
            .unwrap_or(std::cmp::Ordering::Equal)
            // Ties broken by peer id so paging is stable.
            .then(b.0.cmp(&a.0));
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    });

    let totals = relay.totals();
    let listed: Vec<Value> = rows
        .iter()
        .take(limit)
        .map(|(id, record)| relay_row(analysis, *id, record))
        .collect();

    json!({
        "peers": rows.len(),
        "rows": listed,
        "items": relay.items(),
        "announcements": relay.announcements,
        "lateAnnouncements": relay.late_announcements,
        "deliveries": relay.deliveries,
        "duplicateDeliveries": relay.duplicate_deliveries,
        "duplicateBytes": relay.duplicate_bytes,
        "duplicateFactor": relay.duplicate_factor(),
        "capped": relay.capped(),
        "untracked": relay.untracked,
        "maxItems": relay::MAX_ITEMS,
        "firstAnnouncers": totals.first,
        "lag": latencies(&relay.lag),
        "heardToHeld": latencies(&relay.heard_to_held),
    })
}

/// Whether any command that answers this exchange appears in the archive at all.
///
/// The archiver records which event types a run captured only as far as the
/// `low_data` flag; the message filter it used is not in the header. So an
/// archive holding `version` but no `verack` is indistinguishable from a node
/// whose every handshake failed -- except that every handshake failing is not a
/// thing that happens. Where a reply command never appears at all, silence says
/// nothing about the peers, and saying so beats reporting a number that is
/// certainly wrong.
fn replies_captured(analysis: &Analysis, index: usize) -> bool {
    exchange::reply_names(index).iter().any(|name| {
        analysis.kinds.iter().any(|(id, info)| {
            info.group == Group::EbpfMessage
                && info.name == *name
                && analysis.counts.get(id as usize).copied().unwrap_or(0) > 0
        })
    })
}

/// Whether unanswered counts mean anything for this archive.
///
/// False when some exchange produced unanswered requests but the archive never
/// captured the messages that would have answered them.
pub fn unanswered_is_meaningful(analysis: &Analysis) -> bool {
    !analysis
        .exchanges
        .iter()
        .enumerate()
        .any(|(index, stats)| stats.unanswered() > 0 && !replies_captured(analysis, index))
}

/// How each kind of request fared, and how long the answers took.
pub fn exchanges(analysis: &Analysis) -> Value {
    let rows: Vec<Value> = analysis
        .exchanges
        .iter()
        .enumerate()
        .filter(|(_, stats)| stats.opened > 0)
        .map(|(index, stats)| {
            json!({
                "request": exchange::request_name(index),
                "replies": exchange::reply_names(index),
                // An announcement is not a request: we act on a fraction of what
                // is announced to us, so its remainder is a choice, not a
                // failure, and it is never counted as unanswered.
                "optional": exchange::is_optional(index),
                "repliesCaptured": replies_captured(analysis, index),
                "opened": stats.opened,
                "answered": stats.answered,
                "unanswered": stats.unanswered(),
                "unansweredByPeers": stats.unanswered_by_peers,
                "unansweredByUs": stats.unanswered_by_us,
                "undetermined": stats.undetermined(),
                "peerLatency": latencies(&analysis.reply_latency[index]),
                "ourLatency": latencies(&analysis.our_reply_latency[index]),
            })
        })
        .collect();
    json!({ "rows": rows, "unansweredMeaningful": unanswered_is_meaningful(analysis) })
}

/// A page of the raw event table.
pub fn query(
    analysis: &Analysis,
    cache: &mut QueryCache,
    filter: &Filter,
    offset: usize,
    limit: usize,
) -> Value {
    cache.refresh(analysis, filter);
    let indices = page_indices(analysis, cache, offset, limit);
    let rows: Vec<Value> = indices
        .iter()
        .filter_map(|&i| event_row(analysis, i))
        .collect();
    json!({ "total": cache.total, "offset": offset, "rows": rows })
}

/// A page of the sequence diagram: the same rows [`query`] returns, plus the
/// request/reply ties among them.
///
/// Ties are positions within `rows`, so the caller can draw them without
/// looking anything up. They are matched only within the page: an exchange
/// whose request and reply fall either side of a page boundary is not
/// reported. See [`crate::exchange`] for what a tie does and does not prove.
pub fn sequence(
    analysis: &Analysis,
    cache: &mut QueryCache,
    filter: &Filter,
    offset: usize,
    limit: usize,
) -> Value {
    cache.refresh(analysis, filter);
    let indices = page_indices(analysis, cache, offset, limit);

    // Built in one pass, so that a row the store cannot produce drops out of
    // both lists at once and the tie positions stay aligned with the rows.
    let mut turns = Vec::with_capacity(indices.len());
    let mut rows = Vec::with_capacity(indices.len());
    for &index in &indices {
        let (Some(row), Some(value)) = (analysis.store.row(index), event_row(analysis, index))
        else {
            continue;
        };
        turns.push(Turn {
            peer: row.peer,
            command: analysis.kinds.get(row.kind).map_or("", |k| k.name.as_str()),
            inbound: row.inbound(),
            timestamp: row.timestamp,
        });
        rows.push(value);
    }

    let ties: Vec<Value> = match_turns(&turns)
        .into_iter()
        .map(|tie| {
            json!({
                "request": tie.request,
                "reply": tie.reply,
                "elapsedMs": tie.elapsed_ms,
            })
        })
        .collect();

    json!({ "total": cache.total, "offset": offset, "rows": rows, "ties": ties })
}

/// The store indices making up one page of a query.
fn page_indices(analysis: &Analysis, cache: &QueryCache, offset: usize, limit: usize) -> Vec<u32> {
    match &cache.matches {
        Some(matches) => matches.iter().skip(offset).take(limit).copied().collect(),
        None => (offset as u32..)
            .take(limit)
            .take_while(|i| (*i as usize) < analysis.store.len())
            .collect(),
    }
}

fn event_row(analysis: &Analysis, index: u32) -> Option<Value> {
    let row = analysis.store.row(index)?;
    let info = analysis.kinds.get(row.kind);
    let peer_id = (row.peer != NO_PEER)
        .then(|| analysis.peers.peer_id_at(row.peer))
        .flatten();
    let addr = peer_id
        .and_then(|id| analysis.peers.get(id))
        .and_then(|p| p.addr.clone());

    Some(json!({
        "index": index,
        "timestamp": row.timestamp,
        "kindId": row.kind,
        "category": info.map(|i| i.category().as_str()),
        "group": info.map(|i| i.group.as_str()),
        "kind": info.map(|i| i.name.clone()),
        "label": info.map(|i| i.label()),
        "peerId": peer_id,
        "addr": addr,
        "inbound": row.inbound(),
        "size": row.size,
    }))
}

fn share(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 * 100.0 / total as f64
    }
}

fn conn_type_name(value: i32) -> &'static str {
    match ConnType::try_from(value) {
        Ok(ConnType::Inbound) => "inbound",
        Ok(ConnType::OutboundFullRelay) => "outbound-full-relay",
        Ok(ConnType::BlockRelayOnly) => "block-relay-only",
        Ok(ConnType::Feeler) => "feeler",
        Ok(ConnType::Unknown) | Err(_) => "unknown",
    }
}

/// Bitcoin Core's `Network` enum, as carried by `Connection.network`.
fn network_name(value: u32) -> &'static str {
    match value {
        0 => "unroutable",
        1 => "ipv4",
        2 => "ipv6",
        3 => "onion",
        4 => "i2p",
        5 => "cjdns",
        6 => "internal",
        _ => "unknown",
    }
}

/// Values that JavaScript cannot hold exactly are emitted as strings rather than
/// silently rounded.
pub(crate) fn number(value: u64) -> Value {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    if value <= MAX_SAFE_INTEGER {
        json!(value)
    } else {
        json!(value.to_string())
    }
}

pub(crate) fn signed_number(value: i64) -> Value {
    const MAX_SAFE: i64 = 9_007_199_254_740_991;
    if (-MAX_SAFE..=MAX_SAFE).contains(&value) {
        json!(value)
    } else {
        json!(value.to_string())
    }
}

/// Networks (autonomous systems) the archive's peers belong to.
///
/// Requires an asmap file; without one the page says so rather than falling back
/// to a guess like grouping by /16, which would be wrong for anyone
/// multi-homing or announcing out of a larger allocation.
pub fn networks(
    analysis: &Analysis,
    asmap: Option<&asmap::Asmap>,
    offset: usize,
    limit: usize,
) -> Value {
    let Some(asmap) = asmap else {
        return json!({ "available": false, "total": 0, "rows": [] });
    };
    let groups = asn::group(analysis, asmap);
    let rows: Vec<Value> = groups
        .iter()
        .skip(offset)
        .take(limit)
        .map(|(network, stats)| network_row(*network, stats))
        .collect();

    json!({
        "available": true,
        "total": groups.len(),
        "offset": offset,
        "peersCovered": groups.iter().map(|(_, s)| s.peers).sum::<u64>(),
        "rows": rows,
    })
}

fn network_row(network: asn::Network, stats: &asn::NetworkStats) -> Value {
    // Deliberately no AS name here. The `asinfo` tables are ~4 MB embedded at
    // compile time, which would quadruple the wasm bundle for a label shown on
    // one screen, so naming lives in a separate module the page loads on demand.
    json!({
        "asn": network.asn(),
        "label": network.label(),
        "peers": stats.peers,
        "messagesIn": stats.messages_in,
        "messagesOut": stats.messages_out,
        "bytesIn": stats.bytes_in,
        "bytesOut": stats.bytes_out,
        "inbound": stats.count(LifecycleKind::Inbound),
        "outbound": stats.count(LifecycleKind::Outbound),
        "closed": stats.count(LifecycleKind::Closed),
        "evicted": stats.count(LifecycleKind::InboundEvicted),
        "misbehaving": stats.count(LifecycleKind::Misbehaving),
        "evictionRatio": stats.eviction_ratio(),
        "firstSeen": stats.first_seen,
        "lastSeen": stats.last_seen,
        "events": stats.events(),
    })
}

/// Peer ids belonging to one network, busiest first.
///
/// `asn` is `None` for the non-AS buckets, which `label` then distinguishes.
pub fn network_peers(
    analysis: &Analysis,
    asmap: Option<&asmap::Asmap>,
    asn_wanted: Option<u32>,
    label: &str,
    limit: usize,
) -> Value {
    let Some(asmap) = asmap else {
        return json!({ "rows": [] });
    };
    let wanted = match asn_wanted {
        Some(asn) => asn::Network::Asn(asn),
        None => match label {
            "unmapped IP" => asn::Network::UnmappedIp,
            "Tor / I2P / CJDNS" => asn::Network::Anonymising,
            _ => asn::Network::Unknown,
        },
    };

    let mut peers: Vec<&PeerStats> = analysis
        .peers
        .iter()
        .filter(|peer| asn::network_of(peer, asmap) == wanted)
        .collect();
    peers.sort_by_key(|p| std::cmp::Reverse(p.events()));

    json!({ "rows": peers.iter().take(limit).map(|p| peer_row(p)).collect::<Vec<_>>() })
}
