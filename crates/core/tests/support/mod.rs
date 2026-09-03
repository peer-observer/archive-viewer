//! Helpers for building archive fixtures that match what `tools/archive` writes.
//!
//! Fixtures are synthesised rather than committed as captured data: a real
//! archive contains the peer addresses of whoever's node produced it, which has
//! no place in a public repo. The `real_archive` test covers genuine data by
//! pointing at a local file via `PEER_OBSERVER_ARCHIVE`.

// Shared by several test binaries; each uses a different subset.
#![allow(dead_code)]

use archive_viewer_core::proto::{
    bitcoin_primitives::ConnType,
    ebpf_extractor::{
        self,
        connection::{self, Connection, ConnectionEvent, InboundConnection},
        message::{message_event, MessageEvent, Metadata, Ping, Unknown},
    },
    event::{event, Event},
    header::ArchiveHeader,
};
use prost::Message;

/// Length-delimit a message exactly as prost's `encode_length_delimited_to_vec`
/// does in the archiver.
pub fn framed<M: Message>(msg: &M) -> Vec<u8> {
    msg.encode_length_delimited_to_vec()
}

pub fn header(created: u64, low_data: Option<bool>) -> ArchiveHeader {
    ArchiveHeader { created, low_data }
}

/// An `ebpf.message` event, the most common kind by far.
pub fn message_event(ts: u64, peer_id: u64, command: &str, inbound: bool, size: u64) -> Event {
    Event {
        timestamp: ts,
        peer_observer_event: Some(event::PeerObserverEvent::EbpfExtractor(
            ebpf_extractor::Ebpf {
                ebpf_event: Some(ebpf_extractor::ebpf::EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id,
                        addr: format!("10.0.0.{}:8333", peer_id % 251),
                        conn_type: ConnType::Inbound as i32,
                        command: command.to_string(),
                        inbound,
                        size,
                    },
                    msg: Some(message_event::Msg::Ping(Ping { value: ts })),
                })),
            },
        )),
    }
}

/// An `ebpf.connection` inbound-connection event.
pub fn connection_event(ts: u64, peer_id: u64) -> Event {
    Event {
        timestamp: ts,
        peer_observer_event: Some(event::PeerObserverEvent::EbpfExtractor(
            ebpf_extractor::Ebpf {
                ebpf_event: Some(ebpf_extractor::ebpf::EbpfEvent::Connection(
                    ConnectionEvent {
                        event: Some(connection::connection_event::Event::Inbound(
                            InboundConnection {
                                conn: Connection {
                                    peer_id,
                                    addr: format!("10.0.0.{}:8333", peer_id % 251),
                                    conn_type: ConnType::Inbound as i32,
                                    network: 1,
                                },
                                existing_connections: peer_id,
                            },
                        )),
                    },
                )),
            },
        )),
    }
}

/// An event carrying `payload_len` bytes, to exercise multi-byte varint length
/// prefixes (>127 needs two bytes, >16383 needs three).
pub fn big_event(ts: u64, payload_len: usize) -> Event {
    Event {
        timestamp: ts,
        peer_observer_event: Some(event::PeerObserverEvent::EbpfExtractor(
            ebpf_extractor::Ebpf {
                ebpf_event: Some(ebpf_extractor::ebpf::EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id: 7,
                        addr: "10.0.0.7:8333".to_string(),
                        conn_type: ConnType::OutboundFullRelay as i32,
                        command: "unknown".to_string(),
                        inbound: false,
                        size: payload_len as u64,
                    },
                    msg: Some(message_event::Msg::Unknown(Unknown {
                        command: "weird".to_string(),
                        payload: vec![0xAB; payload_len],
                    })),
                })),
            },
        )),
    }
}

/// The uncompressed record stream: one header followed by the events.
pub fn record_stream(header: &ArchiveHeader, events: &[Event]) -> Vec<u8> {
    let mut out = framed(header);
    for event in events {
        out.extend_from_slice(&framed(event));
    }
    out
}

/// A complete, properly terminated zstd archive.
pub fn compress(bytes: &[u8], level: i32) -> Vec<u8> {
    zstd::stream::encode_all(bytes, level).expect("zstd compress")
}

/// An event with a timestamp but no oneof arm set. prost does not enforce
/// proto2 `required`, so this decodes fine and must be classified, not dropped.
pub fn event_without_an_arm(ts: u64) -> Event {
    Event {
        timestamp: ts,
        peer_observer_event: None,
    }
}

/// A `tx` message carrying `raw_len` bytes of raw transaction data — the shape
/// that dominates a full-data archive.
pub fn transaction_event(ts: u64, peer_id: u64, raw_len: usize) -> Event {
    use archive_viewer_core::proto::{
        bitcoin_primitives::Transaction, ebpf_extractor::message::Tx,
    };
    Event {
        timestamp: ts,
        peer_observer_event: Some(event::PeerObserverEvent::EbpfExtractor(
            ebpf_extractor::Ebpf {
                ebpf_event: Some(ebpf_extractor::ebpf::EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id,
                        addr: format!("10.0.0.{}:8333", peer_id % 251),
                        conn_type: ConnType::Inbound as i32,
                        command: "tx".to_string(),
                        inbound: true,
                        size: raw_len as u64,
                    },
                    msg: Some(message_event::Msg::Tx(Tx {
                        tx: Transaction {
                            txid: vec![0x11; 32],
                            wtxid: vec![0x22; 32],
                            raw: Some(vec![0xAB; raw_len]),
                        },
                    })),
                })),
            },
        )),
    }
}

/// An inbound `inv` announcing transactions, by wtxid.
pub fn inv_event(ts: u64, peer_id: u64, hashes: &[u8]) -> Event {
    use archive_viewer_core::proto::{
        bitcoin_primitives::{inventory_item::Item, InventoryItem},
        ebpf_extractor::message::Inv,
    };
    let mut event = message_event(ts, peer_id, "inv", true, 37 * hashes.len() as u64);
    set_msg(
        &mut event,
        message_event::Msg::Inv(Inv {
            items: hashes
                .iter()
                .map(|seed| InventoryItem {
                    item: Some(Item::Wtx(vec![*seed; 32])),
                })
                .collect(),
        }),
    );
    event
}

/// An inbound `tx` delivering one transaction.
pub fn tx_event(ts: u64, peer_id: u64, seed: u8, size: u64) -> Event {
    use archive_viewer_core::proto::{
        bitcoin_primitives::Transaction, ebpf_extractor::message::Tx,
    };
    let mut event = message_event(ts, peer_id, "tx", true, size);
    set_msg(
        &mut event,
        message_event::Msg::Tx(Tx {
            tx: Transaction {
                txid: vec![seed; 32],
                wtxid: vec![seed; 32],
                raw: None,
            },
        }),
    );
    event
}

/// Replace the payload of a message event built by [`message_event`].
fn set_msg(event: &mut Event, msg: message_event::Msg) {
    if let Some(event::PeerObserverEvent::EbpfExtractor(ebpf)) = &mut event.peer_observer_event {
        if let Some(ebpf_extractor::ebpf::EbpfEvent::Message(message)) = &mut ebpf.ebpf_event {
            message.msg = Some(msg);
        }
    }
}
