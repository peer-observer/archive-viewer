//! Who told us about each transaction first, and what the losers cost us.
//!
//! This is the one question an archive can answer that a running node cannot be
//! asked after the fact: for every transaction, which peer announced it first,
//! how far behind everyone else was, and how many bytes went on receiving
//! something we already had. Aggregated per peer it is a relay scorecard --
//! "first to tell me" against "duplicate bytes contributed" -- which is the
//! evidence for whether a peer is earning its connection slot.
//!
//! # What is tracked, and what that costs
//!
//! One entry per distinct inventory hash, holding when it was first seen and
//! how often since. Announcements arrive by the thousand, so an entry is kept
//! deliberately small: a 64-bit prefix of the hash as the key, a millisecond
//! offset from the start of the archive rather than an absolute timestamp, and
//! saturating 16-bit counters. Past [`MAX_ITEMS`] no new hash is tracked, which
//! bounds the table; already-tracked hashes keep counting, so the numbers stay
//! meaningful for the part of the archive that was covered. [`Relay::capped`]
//! reports when that happened, and the views say so.
//!
//! # What it cannot see
//!
//! Bitcoin Core announces a transaction by wtxid to peers that negotiated
//! BIP339 and by txid to those that did not, and for a segwit transaction those
//! are different hashes. A race between one peer of each kind therefore looks
//! like two separate races. Nearly all modern peers use wtxid relay, so this is
//! rare in practice, but it is a real limit rather than a rounding error. A
//! delivered transaction carries both hashes, so a delivery is matched against
//! an announcement under either.

use crate::latency::Latencies;
use crate::proto::{
    bitcoin_primitives::{inventory_item::Item, InventoryItem},
    ebpf_extractor::message::{message_event::Msg, MessageEvent},
};
use std::collections::HashMap;

/// How many distinct inventory hashes to track.
///
/// At roughly twenty bytes an entry this caps the table near forty megabytes,
/// which is affordable next to the event store's own budget. A busy node
/// announces a few hundred thousand distinct transactions an hour, so this
/// covers many hours before it bites.
pub const MAX_ITEMS: usize = 2_000_000;

/// What is known about one announced or delivered inventory item.
#[derive(Debug, Clone, Copy)]
struct Item64 {
    /// Milliseconds after the first event in the archive.
    first_ms: u32,
    announcements: u16,
    deliveries: u16,
}

/// One peer's relay record.
#[derive(Debug, Clone, Default)]
pub struct PeerRelay {
    /// Times this peer was the first to announce something.
    pub first: u64,
    /// Times it announced something already announced by someone else.
    pub late: u64,
    /// How far behind it was on those, in milliseconds.
    pub lag: Latencies,
    /// Transactions delivered by this peer.
    pub delivered: u64,
    /// Deliveries of a transaction already delivered by someone.
    pub duplicate: u64,
    /// Bytes spent on those duplicates.
    pub duplicate_bytes: u64,
    /// From the first announcement by anyone to this peer's delivery.
    ///
    /// Not "how fast this peer answered": the clock starts when the network
    /// first told us, which is usually a different peer. It measures how long
    /// the node went between hearing about a transaction and holding it.
    pub heard_to_held: Latencies,
}

impl PeerRelay {
    /// Share of this peer's announcements that beat everyone else.
    pub fn win_ratio(&self) -> Option<f64> {
        let total = self.first + self.late;
        (total > 0).then(|| self.first as f64 / total as f64)
    }

    pub fn is_empty(&self) -> bool {
        self.first == 0 && self.late == 0 && self.delivered == 0
    }

    fn merge(&mut self, other: &PeerRelay) {
        self.first += other.first;
        self.late += other.late;
        self.lag.merge(&other.lag);
        self.delivered += other.delivered;
        self.duplicate += other.duplicate;
        self.duplicate_bytes += other.duplicate_bytes;
        self.heard_to_held.merge(&other.heard_to_held);
    }
}

/// Transaction relay across the whole archive.
#[derive(Debug, Default)]
pub struct Relay {
    items: HashMap<u64, Item64>,
    /// Anchor for the millisecond offsets stored per item.
    origin_ms: Option<u64>,
    /// Per peer id.
    peers: HashMap<u64, PeerRelay>,
    pub announcements: u64,
    pub deliveries: u64,
    pub duplicate_deliveries: u64,
    pub duplicate_bytes: u64,
    /// Announcements of an item someone had already announced.
    pub late_announcements: u64,
    /// Hashes not tracked because [`MAX_ITEMS`] was reached.
    pub untracked: u64,
    /// Every peer's lag, in one distribution.
    pub lag: Latencies,
    /// Every peer's hearing-to-holding time, in one distribution.
    pub heard_to_held: Latencies,
}

impl Relay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Distinct inventory hashes seen.
    pub fn items(&self) -> usize {
        self.items.len()
    }

    /// Whether tracking stopped short of the whole archive.
    pub fn capped(&self) -> bool {
        self.untracked > 0
    }

    pub fn peer(&self, peer_id: u64) -> Option<&PeerRelay> {
        self.peers.get(&peer_id)
    }

    pub fn peers(&self) -> impl Iterator<Item = (u64, &PeerRelay)> {
        self.peers.iter().map(|(id, relay)| (*id, relay))
    }

    /// Every peer's record folded into one.
    pub fn totals(&self) -> PeerRelay {
        let mut total = PeerRelay::default();
        for relay in self.peers.values() {
            total.merge(relay);
        }
        total
    }

    /// How many times a transaction was received for each time it was needed.
    ///
    /// One means every delivery was useful; two means half the transaction
    /// bytes coming in were bytes already held.
    pub fn duplicate_factor(&self) -> Option<f64> {
        let distinct = self.deliveries.checked_sub(self.duplicate_deliveries)?;
        (distinct > 0).then(|| self.deliveries as f64 / distinct as f64)
    }

    /// Record one P2P message. Only inbound messages say anything about relay:
    /// outbound ones are this node announcing, not a peer racing.
    pub fn record(&mut self, timestamp: u64, event: &MessageEvent) {
        if !event.meta.inbound {
            return;
        }
        match &event.msg {
            Some(Msg::Inv(inv)) => self.announce(timestamp, event.meta.peer_id, &inv.items),
            Some(Msg::Tx(tx)) => self.deliver(
                timestamp,
                event.meta.peer_id,
                &tx.tx.txid,
                &tx.tx.wtxid,
                event.meta.size,
            ),
            _ => {}
        }
    }

    /// Milliseconds since the archive's first event, saturating at the ~49 days
    /// a `u32` holds. An archive longer than that keeps working; items past the
    /// edge simply all look equally old.
    fn offset(&mut self, timestamp: u64) -> u32 {
        let origin = *self.origin_ms.get_or_insert(timestamp);
        u32::try_from(timestamp.saturating_sub(origin)).unwrap_or(u32::MAX)
    }

    fn announce(&mut self, timestamp: u64, peer_id: u64, items: &[InventoryItem]) {
        let now = self.offset(timestamp);
        for item in items {
            let Some(hash) = transaction_hash(item) else {
                continue;
            };
            self.announcements += 1;
            match self.items.get_mut(&hash) {
                Some(entry) => {
                    entry.announcements = entry.announcements.saturating_add(1);
                    let lag = u64::from(now.saturating_sub(entry.first_ms));
                    self.late_announcements += 1;
                    self.lag.add(lag);
                    let peer = self.peers.entry(peer_id).or_default();
                    peer.late += 1;
                    peer.lag.add(lag);
                }
                None => {
                    if self.items.len() >= MAX_ITEMS {
                        self.untracked += 1;
                        continue;
                    }
                    self.items.insert(
                        hash,
                        Item64 {
                            first_ms: now,
                            announcements: 1,
                            deliveries: 0,
                        },
                    );
                    self.peers.entry(peer_id).or_default().first += 1;
                }
            }
        }
    }

    fn deliver(&mut self, timestamp: u64, peer_id: u64, txid: &[u8], wtxid: &[u8], size: u64) {
        // An archive written with --low-data has no hashes to work with.
        let Some(by_txid) = prefix(txid) else {
            return;
        };
        let by_wtxid = prefix(wtxid);
        // The announcement may have come under either hash, depending on
        // whether that peer negotiated BIP339.
        let key = if self.items.contains_key(&by_txid) {
            by_txid
        } else {
            by_wtxid
                .filter(|k| self.items.contains_key(k))
                .unwrap_or(by_txid)
        };

        self.deliveries += 1;
        let now = self.offset(timestamp);
        match self.items.get_mut(&key) {
            Some(entry) => {
                let announced = entry.announcements > 0;
                let already = entry.deliveries > 0;
                entry.deliveries = entry.deliveries.saturating_add(1);
                let since_announced = u64::from(now.saturating_sub(entry.first_ms));
                let peer = self.peers.entry(peer_id).or_default();
                peer.delivered += 1;
                if already {
                    self.duplicate_deliveries += 1;
                    self.duplicate_bytes += size;
                    peer.duplicate += 1;
                    peer.duplicate_bytes += size;
                } else if announced {
                    // Only the first delivery measures the wait; a duplicate arriving
                    // later says nothing about how long the node went without it.
                    self.heard_to_held.add(since_announced);
                    peer.heard_to_held.add(since_announced);
                }
            }
            None => {
                if self.items.len() >= MAX_ITEMS {
                    self.untracked += 1;
                    return;
                }
                self.items.insert(
                    key,
                    Item64 {
                        first_ms: now,
                        announcements: 0,
                        deliveries: 1,
                    },
                );
                self.peers.entry(peer_id).or_default().delivered += 1;
            }
        }
    }
}

/// The 64-bit key for a hash, or `None` if there is no hash.
fn prefix(hash: &[u8]) -> Option<u64> {
    let head: [u8; 8] = hash.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(head))
}

/// The hash in an inventory item, if the item refers to a transaction.
///
/// Blocks and compact blocks are announced through the same message but are a
/// different question -- there are a few hundred a day, not a few hundred a
/// second -- so they are left out rather than diluting the transaction figures.
fn transaction_hash(item: &InventoryItem) -> Option<u64> {
    match item.item.as_ref()? {
        Item::Transaction(hash) | Item::Wtx(hash) | Item::WitnessTransaction(hash) => prefix(hash),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        bitcoin_primitives::{ConnType, Transaction},
        ebpf_extractor::message::{Inv, Metadata, Tx},
    };

    fn hash(seed: u8) -> Vec<u8> {
        let mut out = vec![seed; 32];
        out[8] = 0xAA; // beyond the 64-bit prefix, to prove it is not read
        out
    }

    fn meta(peer_id: u64, command: &str, inbound: bool, size: u64) -> Metadata {
        Metadata {
            peer_id,
            addr: format!("10.0.0.{peer_id}:8333"),
            conn_type: ConnType::Inbound as i32,
            command: command.to_string(),
            inbound,
            size,
        }
    }

    fn inv(peer_id: u64, inbound: bool, hashes: &[u8]) -> MessageEvent {
        MessageEvent {
            meta: meta(peer_id, "inv", inbound, 37 * hashes.len() as u64),
            msg: Some(Msg::Inv(Inv {
                items: hashes
                    .iter()
                    .map(|seed| InventoryItem {
                        item: Some(Item::Wtx(hash(*seed))),
                    })
                    .collect(),
            })),
        }
    }

    fn tx(peer_id: u64, seed: u8, size: u64) -> MessageEvent {
        MessageEvent {
            meta: meta(peer_id, "tx", true, size),
            msg: Some(Msg::Tx(Tx {
                tx: Transaction {
                    txid: hash(seed),
                    wtxid: hash(seed),
                    raw: None,
                },
            })),
        }
    }

    #[test]
    fn the_first_announcer_wins_and_the_rest_are_timed() {
        let mut relay = Relay::new();
        relay.record(1_000, &inv(7, true, &[1]));
        relay.record(1_250, &inv(8, true, &[1]));
        relay.record(1_900, &inv(9, true, &[1]));

        assert_eq!(relay.items(), 1, "one transaction, three announcements");
        assert_eq!(relay.announcements, 3);
        assert_eq!(relay.late_announcements, 2);

        assert_eq!(relay.peer(7).unwrap().first, 1);
        assert_eq!(relay.peer(7).unwrap().late, 0);
        assert_eq!(relay.peer(8).unwrap().lag.max_ms(), 250);
        assert_eq!(relay.peer(9).unwrap().lag.max_ms(), 900);
        assert_eq!(relay.peer(7).unwrap().win_ratio(), Some(1.0));
        assert_eq!(relay.peer(8).unwrap().win_ratio(), Some(0.0));
    }

    #[test]
    fn a_second_delivery_of_the_same_transaction_is_wasted_bandwidth() {
        let mut relay = Relay::new();
        relay.record(1_000, &inv(7, true, &[1]));
        relay.record(1_100, &tx(7, 1, 400));
        relay.record(1_500, &tx(8, 1, 400));

        assert_eq!(relay.deliveries, 2);
        assert_eq!(relay.duplicate_deliveries, 1);
        assert_eq!(relay.duplicate_bytes, 400);
        assert_eq!(relay.duplicate_factor(), Some(2.0));

        assert_eq!(relay.peer(7).unwrap().duplicate, 0);
        assert_eq!(relay.peer(8).unwrap().duplicate, 1);
        assert_eq!(relay.peer(8).unwrap().duplicate_bytes, 400);
        // Only the first delivery measures the wait.
        assert_eq!(relay.peer(7).unwrap().heard_to_held.max_ms(), 100);
        assert!(relay.peer(8).unwrap().heard_to_held.is_empty());
    }

    #[test]
    fn a_delivery_matches_an_announcement_under_either_hash() {
        let mut relay = Relay::new();
        // Announced by wtxid; the transaction carries a different txid.
        relay.record(1_000, &inv(7, true, &[1]));
        let mut delivery = tx(7, 1, 250);
        if let Some(Msg::Tx(t)) = &mut delivery.msg {
            t.tx.txid = hash(99);
        }
        relay.record(1_040, &delivery);

        assert_eq!(relay.items(), 1, "not a second, unrelated item");
        assert_eq!(relay.peer(7).unwrap().heard_to_held.max_ms(), 40);
    }

    #[test]
    fn outbound_messages_say_nothing_about_who_told_us_first() {
        let mut relay = Relay::new();
        relay.record(1_000, &inv(7, false, &[1, 2, 3]));
        assert_eq!(relay.announcements, 0);
        assert_eq!(relay.items(), 0);
    }

    #[test]
    fn block_announcements_are_left_out_of_the_transaction_figures() {
        let mut relay = Relay::new();
        let mut message = inv(7, true, &[1]);
        if let Some(Msg::Inv(i)) = &mut message.msg {
            i.items = vec![
                InventoryItem {
                    item: Some(Item::Block(hash(1))),
                },
                InventoryItem {
                    item: Some(Item::CompactBlock(hash(2))),
                },
                InventoryItem { item: None },
            ];
        }
        relay.record(1_000, &message);
        assert_eq!(relay.announcements, 0);
        assert_eq!(relay.items(), 0);
    }

    #[test]
    fn a_transaction_with_no_hashes_is_skipped_rather_than_miscounted() {
        // What a --low-data archive looks like.
        let mut relay = Relay::new();
        let mut message = tx(7, 1, 300);
        if let Some(Msg::Tx(t)) = &mut message.msg {
            t.tx.txid = Vec::new();
            t.tx.wtxid = Vec::new();
        }
        relay.record(1_000, &message);
        assert_eq!(relay.deliveries, 0);
        assert_eq!(relay.items(), 0);
    }

    #[test]
    fn totals_are_the_sum_of_every_peer() {
        let mut relay = Relay::new();
        relay.record(1_000, &inv(7, true, &[1, 2]));
        relay.record(1_100, &inv(8, true, &[1, 2]));
        relay.record(1_200, &tx(7, 1, 500));
        relay.record(1_300, &tx(8, 1, 500));

        let totals = relay.totals();
        assert_eq!(totals.first, 2, "peer 7 announced both first");
        assert_eq!(totals.late, 2);
        assert_eq!(totals.delivered, 2);
        assert_eq!(totals.duplicate, 1);
        assert_eq!(totals.duplicate_bytes, 500);
        assert_eq!(totals.lag.count(), relay.late_announcements);
    }
}
