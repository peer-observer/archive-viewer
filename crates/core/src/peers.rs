//! Per-peer statistics, built from the eBPF message and connection events.
//!
//! A peer is identified by the `peer_id` Bitcoin Core assigns it. Note that ids
//! are only unique within one node run: an archive spanning a restart can reuse
//! them, and the UI says so.

use crate::latency::Latencies;
use crate::proto::ebpf_extractor::{
    connection::{connection_event::Event as ConnEvent, Connection, ConnectionEvent},
    message::MessageEvent,
};
use std::collections::HashMap;

/// Kind of connection lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleKind {
    Inbound,
    Outbound,
    Closed,
    InboundEvicted,
    Misbehaving,
}

impl LifecycleKind {
    /// Every kind, in a stable order, used to index the per-peer counters.
    pub const ALL: [LifecycleKind; 5] = [
        LifecycleKind::Inbound,
        LifecycleKind::Outbound,
        LifecycleKind::Closed,
        LifecycleKind::InboundEvicted,
        LifecycleKind::Misbehaving,
    ];

    pub fn index(self) -> usize {
        match self {
            LifecycleKind::Inbound => 0,
            LifecycleKind::Outbound => 1,
            LifecycleKind::Closed => 2,
            LifecycleKind::InboundEvicted => 3,
            LifecycleKind::Misbehaving => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleKind::Inbound => "inbound",
            LifecycleKind::Outbound => "outbound",
            LifecycleKind::Closed => "closed",
            LifecycleKind::InboundEvicted => "inbound_evicted",
            LifecycleKind::Misbehaving => "misbehaving",
        }
    }
}

/// Where a peer's user agent came from.
///
/// The `version` message is what the peer actually put on the wire; the RPC
/// snapshot is Bitcoin Core repeating it back later. They agree in practice,
/// but only one of them is first-hand, and an archive often has just one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAgentSource {
    Version,
    PeerInfo,
}

impl UserAgentSource {
    pub fn as_str(self) -> &'static str {
        match self {
            UserAgentSource::Version => "version",
            UserAgentSource::PeerInfo => "getpeerinfo",
        }
    }
}

/// How many lifecycle events to keep per peer.
///
/// The peer table is not covered by the event store's retention budget, so
/// anything unbounded in it is an allocation failure waiting to happen: an
/// archive of a churny node has millions of connection events, and a viewer that
/// kept them all would run the browser out of memory with no budget to blame.
/// Bitcoin Core assigns a fresh peer id per connection, so a peer id has one
/// lifecycle -- open, perhaps some misbehaviour, close. Eight is already
/// generous; `lifecycle_total` keeps the count honest when it is not.
pub const LIFECYCLE_CAP: usize = 8;

/// One entry in a peer's connection lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub timestamp: u64,
    pub kind: LifecycleKind,
    /// How long the connection had been established, for close and evict events.
    pub time_established: Option<u64>,
    /// Connection count at the time, for open events.
    pub existing_connections: Option<u64>,
    /// Description, for misbehaving events.
    pub message: Option<String>,
}

/// Messages seen for one P2P command, split by direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommandCounts {
    pub inbound: u64,
    pub outbound: u64,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub peer_id: u64,
    /// Dense index assigned in first-seen order, so the event store can refer
    /// to a peer in four bytes without truncating a 64-bit peer id.
    pub index: u32,
    /// Last address seen for this peer. `None` if only ever seen misbehaving.
    pub addr: Option<String>,
    /// Interned user agent, resolved with [`PeerTable::user_agent`]. Interned
    /// because a churning node sees the same few agent strings across hundreds
    /// of thousands of peers, and a `String` each would cost more than the rest
    /// of the peer table put together.
    pub user_agent: Option<u16>,
    pub user_agent_source: Option<UserAgentSource>,
    pub conn_type: Option<i32>,
    pub network: Option<u32>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub messages_in: u64,
    pub messages_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Per-command counts, keyed by the interned kind id of the command.
    ///
    /// A `HashMap<String, _>` per peer costs a hash table and a `String` per
    /// command; with the hundreds of thousands of peers a busy node produces
    /// that dominated the peer table. A short vector scanned linearly is both
    /// smaller and faster at this size (a peer sees a handful of commands).
    pub commands: Vec<(u16, CommandCounts)>,
    /// The most recent [`LIFECYCLE_CAP`] lifecycle events.
    pub lifecycle: Vec<LifecycleEvent>,
    /// How many lifecycle events actually occurred, including those dropped.
    pub lifecycle_total: u64,
    /// Exact count per lifecycle kind, indexed by [`LifecycleKind::index`].
    /// The list above is capped, so this is the only exact per-kind source.
    pub lifecycle_counts: [u32; 5],
}

impl PeerStats {
    fn new(peer_id: u64, index: u32, timestamp: u64) -> Self {
        PeerStats {
            peer_id,
            index,
            first_seen: timestamp,
            last_seen: timestamp,
            ..Default::default()
        }
    }

    fn touch(&mut self, timestamp: u64) {
        self.first_seen = self.first_seen.min(timestamp);
        self.last_seen = self.last_seen.max(timestamp);
    }

    /// Total events attributed to this peer.
    pub fn events(&self) -> u64 {
        self.messages_in + self.messages_out + self.lifecycle_total
    }

    /// How long the peer was observed for, in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }
}

/// How long connections lasted, by connection type and by how they ended.
///
/// Bitcoin Core reports the establishment time on the event that ends a
/// connection, so this is the node's own account of the lifetime rather than
/// the span of events this tool happened to see. Accumulated during ingest
/// because the per-peer lifecycle list is capped: on a churning node the list
/// would have thrown most of these away.
///
/// Kept split by how the connection ended as well as by type, because those are
/// different populations. An evicted inbound connection lived for as long as it
/// took the next one to arrive; one that closed normally lived as long as the
/// peer wanted it to, and averaging them together describes neither.
#[derive(Debug, Clone, Default)]
pub struct ConnectionDurations {
    closed: [Latencies; CONN_TYPES],
    evicted: [Latencies; CONN_TYPES],
}

/// Slots for `bitcoin_primitives.ConnType`, which is dense from zero.
pub const CONN_TYPES: usize = 5;

impl ConnectionDurations {
    fn add(&mut self, ended: &EndedConnection) {
        let slot = (ended.conn_type.clamp(0, CONN_TYPES as i32 - 1)) as usize;
        let side = if ended.evicted {
            &mut self.evicted
        } else {
            &mut self.closed
        };
        side[slot].add(ended.lifetime_ms);
    }

    /// Durations for one connection type, for connections that closed normally.
    pub fn closed(&self, conn_type: usize) -> &Latencies {
        &self.closed[conn_type.min(CONN_TYPES - 1)]
    }

    /// Durations for one connection type, for connections Core evicted.
    pub fn evicted(&self, conn_type: usize) -> &Latencies {
        &self.evicted[conn_type.min(CONN_TYPES - 1)]
    }

    /// Both, for one connection type.
    pub fn all(&self, conn_type: usize) -> Latencies {
        let mut both = self.closed(conn_type).clone();
        both.merge(self.evicted(conn_type));
        both
    }

    pub fn is_empty(&self) -> bool {
        (0..CONN_TYPES).all(|i| self.closed(i).is_empty() && self.evicted(i).is_empty())
    }
}

/// A connection that ended, as reported by the event that ended it.
#[derive(Debug, Clone, Copy)]
pub struct EndedConnection {
    /// `bitcoin_primitives.ConnType`.
    pub conn_type: i32,
    pub evicted: bool,
    pub lifetime_ms: u64,
}

/// Accumulates [`PeerStats`] across a whole archive.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: HashMap<u64, PeerStats>,
    /// Dense index -> peer id.
    by_index: Vec<u64>,
    durations: ConnectionDurations,
    user_agents: Vec<String>,
    user_agent_ids: HashMap<String, u16>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn get(&self, peer_id: u64) -> Option<&PeerStats> {
        self.peers.get(&peer_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerStats> {
        self.peers.values()
    }

    /// How long connections lasted, by type and by how they ended.
    pub fn durations(&self) -> &ConnectionDurations {
        &self.durations
    }

    /// Resolve an interned user agent.
    pub fn user_agent(&self, id: u16) -> Option<&str> {
        self.user_agents.get(id as usize).map(String::as_str)
    }

    /// Every user agent seen, with how many peers reported it, busiest first.
    pub fn user_agent_counts(&self) -> Vec<(&str, u64)> {
        let mut counts = vec![0u64; self.user_agents.len()];
        for peer in self.peers.values() {
            if let Some(id) = peer.user_agent {
                if let Some(slot) = counts.get_mut(id as usize) {
                    *slot += 1;
                }
            }
        }
        let mut out: Vec<(&str, u64)> = self
            .user_agents
            .iter()
            .map(String::as_str)
            .zip(counts)
            .filter(|(_, n)| *n > 0)
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        out
    }

    /// Note what a peer calls itself.
    ///
    /// The `version` message wins over the RPC snapshot: it is what the peer
    /// actually sent, and an archive holding both should report the first-hand
    /// one. Nothing else overwrites an agent already recorded, so the hundreds
    /// of `getpeerinfo` polls in a long archive cost one hash lookup each.
    pub fn record_user_agent(&mut self, peer_id: u64, agent: &str, source: UserAgentSource) {
        if agent.is_empty() {
            return;
        }
        // Only annotate peers already known from their own events: a poll
        // listing a peer this archive never otherwise saw must not invent one,
        // nor move an existing peer's first-seen time.
        let Some(peer) = self.peers.get(&peer_id) else {
            return;
        };
        let upgrading =
            source == UserAgentSource::Version && peer.user_agent_source != Some(source);
        if peer.user_agent.is_some() && !upgrading {
            return;
        }

        let id = match self.user_agent_ids.get(agent) {
            Some(id) => *id,
            None => {
                let Ok(id) = u16::try_from(self.user_agents.len()) else {
                    // More than 65,535 distinct agents is not a peer population,
                    // it is a garbage or adversarial archive. Stop interning
                    // rather than grow without bound.
                    return;
                };
                self.user_agents.push(agent.to_string());
                self.user_agent_ids.insert(agent.to_string(), id);
                id
            }
        };
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.user_agent = Some(id);
            peer.user_agent_source = Some(source);
        }
    }

    /// Peer id for a dense index.
    pub fn peer_id_at(&self, index: u32) -> Option<u64> {
        self.by_index.get(index as usize).copied()
    }

    fn entry(&mut self, peer_id: u64, timestamp: u64) -> &mut PeerStats {
        let by_index = &mut self.by_index;
        let peer = self.peers.entry(peer_id).or_insert_with(|| {
            let index = u32::try_from(by_index.len())
                .expect("an archive cannot contain more than u32::MAX distinct peers");
            by_index.push(peer_id);
            PeerStats::new(peer_id, index, timestamp)
        });
        peer.touch(timestamp);
        peer
    }

    /// Record a P2P message. `command` is the interned kind id of `meta.command`.
    pub fn record_message(&mut self, timestamp: u64, event: &MessageEvent, command: u16) {
        let meta = &event.meta;
        {
            // An inbound version carries the peer's agent; an outbound one
            // carries this node's, which is not what the peer page is about.
            use crate::proto::ebpf_extractor::message::message_event::Msg;
            if let (true, Some(Msg::Version(version))) = (meta.inbound, &event.msg) {
                self.entry(meta.peer_id, timestamp);
                let agent = version.user_agent.clone();
                self.record_user_agent(meta.peer_id, &agent, UserAgentSource::Version);
            }
        }
        let peer = self.entry(meta.peer_id, timestamp);
        if peer.addr.as_deref() != Some(meta.addr.as_str()) {
            peer.addr = Some(meta.addr.clone());
        }
        peer.conn_type = Some(meta.conn_type);

        let slot = match peer.commands.iter().position(|(id, _)| *id == command) {
            Some(i) => i,
            None => {
                peer.commands.push((command, CommandCounts::default()));
                peer.commands.len() - 1
            }
        };
        let counts = &mut peer.commands[slot].1;
        if meta.inbound {
            peer.messages_in += 1;
            peer.bytes_in += meta.size;
            counts.inbound += 1;
            counts.inbound_bytes += meta.size;
        } else {
            peer.messages_out += 1;
            peer.bytes_out += meta.size;
            counts.outbound += 1;
            counts.outbound_bytes += meta.size;
        }
    }

    /// Record a connection lifecycle event.
    pub fn record_connection(&mut self, timestamp: u64, event: &ConnectionEvent) {
        let Some(inner) = &event.event else { return };

        // `misbehaving` is the odd one out: it carries a bare peer id and a
        // description, with no address or connection type. It must not blank out
        // what we already know about the peer.
        let (peer_id, conn, kind, time_established, existing, message) = match inner {
            ConnEvent::Closed(c) => (
                c.conn.peer_id,
                Some(&c.conn),
                LifecycleKind::Closed,
                Some(c.time_established),
                None,
                None,
            ),
            ConnEvent::InboundEvicted(c) => (
                c.conn.peer_id,
                Some(&c.conn),
                LifecycleKind::InboundEvicted,
                Some(c.time_established),
                None,
                None,
            ),
            ConnEvent::Inbound(c) => (
                c.conn.peer_id,
                Some(&c.conn),
                LifecycleKind::Inbound,
                None,
                Some(c.existing_connections),
                None,
            ),
            ConnEvent::Outbound(c) => (
                c.conn.peer_id,
                Some(&c.conn),
                LifecycleKind::Outbound,
                None,
                Some(c.existing_connections),
                None,
            ),
            ConnEvent::Misbehaving(m) => (
                m.id,
                None,
                LifecycleKind::Misbehaving,
                None,
                None,
                Some(m.message.clone()),
            ),
        };

        let peer = self.entry(peer_id, timestamp);
        if let Some(conn) = conn {
            update_identity(peer, conn);
        }
        peer.lifecycle_total += 1;
        peer.lifecycle_counts[kind.index()] += 1;
        if peer.lifecycle.len() == LIFECYCLE_CAP {
            peer.lifecycle.remove(0);
        }
        peer.lifecycle.push(LifecycleEvent {
            timestamp,
            kind,
            time_established,
            existing_connections: existing,
            message,
        });

        // `time_established` is a UNIX timestamp in seconds, not a duration, so
        // the lifetime is the gap back to it from this event's own millisecond
        // clock. A connection that reports an establishment time in the future,
        // or none at all, contributes nothing rather than a wrong zero.
        let conn_type = conn.map_or(0, |c| c.conn_type);
        let ended = time_established
            .map(|seconds| timestamp.saturating_sub(seconds.saturating_mul(1_000)))
            .filter(|_| matches!(kind, LifecycleKind::Closed | LifecycleKind::InboundEvicted))
            .map(|lifetime_ms| EndedConnection {
                conn_type,
                evicted: kind == LifecycleKind::InboundEvicted,
                lifetime_ms,
            });
        if let Some(ended) = &ended {
            self.durations.add(ended);
        }
    }
}

fn update_identity(peer: &mut PeerStats, conn: &Connection) {
    peer.addr = Some(conn.addr.clone());
    peer.conn_type = Some(conn.conn_type);
    peer.network = Some(conn.network);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        bitcoin_primitives::ConnType,
        ebpf_extractor::{
            connection::MisbehavingConnection,
            message::{Metadata, Ping},
        },
    };

    fn message(peer_id: u64, command: &str, inbound: bool, size: u64) -> MessageEvent {
        use crate::proto::ebpf_extractor::message::message_event::Msg;
        MessageEvent {
            meta: Metadata {
                peer_id,
                addr: "10.0.0.1:8333".to_string(),
                conn_type: ConnType::Inbound as i32,
                command: command.to_string(),
                inbound,
                size,
            },
            msg: Some(Msg::Ping(Ping { value: 1 })),
        }
    }

    #[test]
    fn splits_messages_by_direction() {
        let mut peers = PeerTable::new();
        const INV: u16 = 0;
        const TX: u16 = 1;
        peers.record_message(100, &message(1, "inv", true, 40), INV);
        peers.record_message(200, &message(1, "inv", true, 60), INV);
        peers.record_message(300, &message(1, "tx", false, 250), TX);

        let peer = peers.get(1).expect("peer recorded");
        assert_eq!((peer.messages_in, peer.bytes_in), (2, 100));
        assert_eq!((peer.messages_out, peer.bytes_out), (1, 250));
        let counts = |id: u16| peer.commands.iter().find(|(k, _)| *k == id).unwrap().1;
        assert_eq!(counts(INV).inbound, 2);
        assert_eq!(counts(INV).inbound_bytes, 100);
        assert_eq!(counts(TX).outbound, 1);
        assert_eq!((peer.first_seen, peer.last_seen), (100, 300));
        assert_eq!(peer.duration_ms(), 200);
    }

    /// A misbehaving event carries no address, so it must not erase the address
    /// learned from the peer's other events.
    #[test]
    fn misbehaving_does_not_clobber_a_known_address() {
        let mut peers = PeerTable::new();
        peers.record_message(100, &message(7, "version", true, 100), 0);
        assert_eq!(peers.get(7).unwrap().addr.as_deref(), Some("10.0.0.1:8333"));

        peers.record_connection(
            200,
            &ConnectionEvent {
                event: Some(ConnEvent::Misbehaving(MisbehavingConnection {
                    id: 7,
                    message: "invalid header".to_string(),
                })),
            },
        );

        let peer = peers.get(7).unwrap();
        assert_eq!(
            peer.addr.as_deref(),
            Some("10.0.0.1:8333"),
            "address survives"
        );
        assert_eq!(peer.lifecycle.len(), 1);
        assert_eq!(peer.lifecycle[0].kind, LifecycleKind::Misbehaving);
        assert_eq!(peer.lifecycle[0].message.as_deref(), Some("invalid header"));
    }

    /// A peer only ever seen misbehaving has no address at all, and that has to
    /// be representable rather than faked as an empty string.
    #[test]
    fn a_peer_known_only_from_misbehaving_has_no_address() {
        let mut peers = PeerTable::new();
        peers.record_connection(
            10,
            &ConnectionEvent {
                event: Some(ConnEvent::Misbehaving(MisbehavingConnection {
                    id: 3,
                    message: "bad".to_string(),
                })),
            },
        );

        let peer = peers.get(3).expect("peer recorded");
        assert_eq!(peer.addr, None);
        assert_eq!(peer.conn_type, None);
    }

    /// The peer table sits outside the event store's retention budget, so an
    /// archive of a churny node must not be able to grow it without limit.
    #[test]
    fn the_lifecycle_list_is_capped_but_the_total_is_exact() {
        use crate::proto::ebpf_extractor::connection::MisbehavingConnection;
        let mut peers = PeerTable::new();
        let events = LIFECYCLE_CAP as u64 * 10;
        for i in 0..events {
            peers.record_connection(
                i,
                &ConnectionEvent {
                    event: Some(ConnEvent::Misbehaving(MisbehavingConnection {
                        id: 1,
                        message: format!("strike {i}"),
                    })),
                },
            );
        }

        let peer = peers.get(1).expect("peer recorded");
        assert_eq!(peer.lifecycle.len(), LIFECYCLE_CAP, "list is capped");
        assert_eq!(peer.lifecycle_total, events, "the count stays exact");
        assert_eq!(peer.events(), events, "totals use the real count");
        // The most recent events are the ones kept.
        assert_eq!(peer.lifecycle.last().unwrap().timestamp, events - 1);
        assert_eq!(peer.lifecycle[0].timestamp, events - LIFECYCLE_CAP as u64);
    }

    #[test]
    fn records_the_connection_lifecycle() {
        use crate::proto::ebpf_extractor::connection::{ClosedConnection, InboundConnection};
        let conn = Connection {
            peer_id: 5,
            addr: "192.0.2.1:8333".to_string(),
            conn_type: ConnType::Inbound as i32,
            network: 1,
        };
        let mut peers = PeerTable::new();
        peers.record_connection(
            10,
            &ConnectionEvent {
                event: Some(ConnEvent::Inbound(InboundConnection {
                    conn: conn.clone(),
                    existing_connections: 12,
                })),
            },
        );
        peers.record_connection(
            90,
            &ConnectionEvent {
                event: Some(ConnEvent::Closed(ClosedConnection {
                    conn,
                    time_established: 80,
                })),
            },
        );

        let peer = peers.get(5).unwrap();
        assert_eq!(peer.network, Some(1));
        assert_eq!(peer.lifecycle.len(), 2);
        assert_eq!(peer.lifecycle[0].existing_connections, Some(12));
        assert_eq!(peer.lifecycle[1].time_established, Some(80));
        assert_eq!(peer.events(), 2);
    }
}
