//! JSON views over an [`Analysis`], consumed by the web UI.
//!
//! Everything crossing the wasm boundary is JSON: the payloads are small (a page
//! of rows, a summary object) and it keeps the JavaScript side free of bindings.
//! Building them here rather than in the wasm crate keeps them natively testable.

use crate::analysis::Analysis;
use crate::kind::GROUPS;
use crate::peers::PeerStats;
use crate::proto::bitcoin_primitives::ConnType;
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

/// The timeline, downsampled to at most `max_bins` columns.
///
/// The histogram keeps up to 4096 bins; a chart is typically a few hundred
/// pixels wide, so merging down avoids shipping data the UI cannot draw.
pub fn timeline(analysis: &Analysis, max_bins: usize) -> Value {
    let histogram = &analysis.histogram;
    let bins = histogram.bins();
    if bins.is_empty() || max_bins == 0 {
        return json!({
            "startMs": 0, "binMs": histogram.bin_ms(), "count": 0,
            "groups": group_names(), "series": Vec::<Vec<u64>>::new(),
        });
    }

    // Merge whole numbers of source bins so bin boundaries stay meaningful.
    let merge = bins.len().div_ceil(max_bins).max(1);
    let out_len = bins.len().div_ceil(merge);
    let mut series = vec![vec![0u64; out_len]; GROUPS.len()];
    for (i, bin) in bins.iter().enumerate() {
        let target = i / merge;
        for (group, count) in bin.iter().enumerate() {
            series[group][target] += count;
        }
    }

    json!({
        "startMs": histogram.start_ms(),
        "binMs": histogram.bin_ms() * merge as u64,
        "count": out_len,
        "groups": group_names(),
        "series": series,
    })
}

fn group_names() -> Vec<&'static str> {
    GROUPS.iter().map(|g| g.as_str()).collect()
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
        "lifecycleEvents": peer.lifecycle.len(),
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
                "command": command,
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
                "kind": e.kind,
                "timeEstablished": e.time_established,
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
    pub peer_id: Option<u64>,
    pub time_from: Option<u64>,
    pub time_to: Option<u64>,
    /// Substring match against the kind name and the peer address.
    pub text: String,
}

impl Filter {
    fn is_unconstrained(&self) -> bool {
        self.kinds.is_empty()
            && self.groups.is_empty()
            && self.peer_id.is_none()
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
    let peer_index = filter
        .peer_id
        .map(|id| analysis.peers.get(id).map_or(NO_PEER, |p| p.index));
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
            if let Some(wanted) = peer_index {
                if peer_column[row] != wanted {
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

/// A page of the raw event table.
pub fn query(
    analysis: &Analysis,
    cache: &mut QueryCache,
    filter: &Filter,
    offset: usize,
    limit: usize,
) -> Value {
    cache.refresh(analysis, filter);
    let indices: Vec<u32> = match &cache.matches {
        Some(matches) => matches.iter().skip(offset).take(limit).copied().collect(),
        None => (offset as u32..)
            .take(limit)
            .take_while(|i| (*i as usize) < analysis.store.len())
            .collect(),
    };

    let rows: Vec<Value> = indices
        .iter()
        .filter_map(|&i| event_row(analysis, i))
        .collect();
    json!({ "total": cache.total, "offset": offset, "rows": rows })
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
