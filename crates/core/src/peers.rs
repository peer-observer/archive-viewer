//! Per-peer statistics, built from the eBPF message and connection events.
//!
//! A peer is identified by the `peer_id` Bitcoin Core assigns it. Note that ids
//! are only unique within one node run: an archive spanning a restart can reuse
//! them, and the UI says so.

use crate::proto::ebpf_extractor::{
    connection::{connection_event::Event as ConnEvent, Connection, ConnectionEvent},
    message::MessageEvent,
};
use std::collections::HashMap;

/// One entry in a peer's connection lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub timestamp: u64,
    /// `inbound`, `outbound`, `closed`, `inbound_evicted` or `misbehaving`.
    pub kind: &'static str,
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
    pub conn_type: Option<i32>,
    pub network: Option<u32>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub messages_in: u64,
    pub messages_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub commands: HashMap<String, CommandCounts>,
    pub lifecycle: Vec<LifecycleEvent>,
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
        self.messages_in + self.messages_out + self.lifecycle.len() as u64
    }

    /// How long the peer was observed for, in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }
}

/// Accumulates [`PeerStats`] across a whole archive.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: HashMap<u64, PeerStats>,
    /// Dense index -> peer id.
    by_index: Vec<u64>,
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

    /// Record a P2P message.
    pub fn record_message(&mut self, timestamp: u64, event: &MessageEvent) {
        let meta = &event.meta;
        let peer = self.entry(meta.peer_id, timestamp);
        peer.addr = Some(meta.addr.clone());
        peer.conn_type = Some(meta.conn_type);

        let counts = peer.commands.entry(meta.command.clone()).or_default();
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
                "closed",
                Some(c.time_established),
                None,
                None,
            ),
            ConnEvent::InboundEvicted(c) => (
                c.conn.peer_id,
                Some(&c.conn),
                "inbound_evicted",
                Some(c.time_established),
                None,
                None,
            ),
            ConnEvent::Inbound(c) => (
                c.conn.peer_id,
                Some(&c.conn),
                "inbound",
                None,
                Some(c.existing_connections),
                None,
            ),
            ConnEvent::Outbound(c) => (
                c.conn.peer_id,
                Some(&c.conn),
                "outbound",
                None,
                Some(c.existing_connections),
                None,
            ),
            ConnEvent::Misbehaving(m) => (
                m.id,
                None,
                "misbehaving",
                None,
                None,
                Some(m.message.clone()),
            ),
        };

        let peer = self.entry(peer_id, timestamp);
        if let Some(conn) = conn {
            update_identity(peer, conn);
        }
        peer.lifecycle.push(LifecycleEvent {
            timestamp,
            kind,
            time_established,
            existing_connections: existing,
            message,
        });
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
        peers.record_message(100, &message(1, "inv", true, 40));
        peers.record_message(200, &message(1, "inv", true, 60));
        peers.record_message(300, &message(1, "tx", false, 250));

        let peer = peers.get(1).expect("peer recorded");
        assert_eq!((peer.messages_in, peer.bytes_in), (2, 100));
        assert_eq!((peer.messages_out, peer.bytes_out), (1, 250));
        assert_eq!(peer.commands["inv"].inbound, 2);
        assert_eq!(peer.commands["inv"].inbound_bytes, 100);
        assert_eq!(peer.commands["tx"].outbound, 1);
        assert_eq!((peer.first_seen, peer.last_seen), (100, 300));
        assert_eq!(peer.duration_ms(), 200);
    }

    /// A misbehaving event carries no address, so it must not erase the address
    /// learned from the peer's other events.
    #[test]
    fn misbehaving_does_not_clobber_a_known_address() {
        let mut peers = PeerTable::new();
        peers.record_message(100, &message(7, "version", true, 100));
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
        assert_eq!(peer.lifecycle[0].kind, "misbehaving");
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
