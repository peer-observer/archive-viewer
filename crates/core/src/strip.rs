//! Dropping raw transaction and block data from retained events.
//!
//! Raw transaction data makes up most of a full-data archive — peer-observer's
//! own archiver says so, and offers `--low-data` to leave it out at capture
//! time. A `tx` message carries the whole serialized transaction, and a `block`
//! message every transaction in the block, so retaining events verbatim means
//! holding megabytes for a single event and running the browser out of memory.
//!
//! The viewer never needs those bytes: nothing it computes reads them, and the
//! inspector is more useful showing a txid than a wall of hex. So the retained
//! copy is stripped of exactly what `--low-data` strips — transactions keep
//! their txid and wtxid, blocks keep their header — while aggregation still runs
//! over the complete event.

use crate::proto::{
    bitcoin_primitives::Transaction,
    ebpf_extractor::{ebpf::EbpfEvent, message::message_event::Msg},
    event::{event::PeerObserverEvent, Event},
};

/// Remove raw transaction and block payloads from `event`, in place.
///
/// Returns the number of bytes dropped, or 0 if there was nothing to drop — in
/// which case the caller can retain the event's original encoding rather than
/// paying to re-encode it.
pub fn strip_raw_payloads(event: &mut Event) -> usize {
    let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = event.peer_observer_event.as_mut() else {
        return 0;
    };
    let Some(EbpfEvent::Message(message)) = ebpf.ebpf_event.as_mut() else {
        return 0;
    };
    let Some(msg) = message.msg.as_mut() else {
        return 0;
    };

    match msg {
        // Matches the set peer-observer's `--low-data` drops...
        Msg::Tx(tx) => take_raw(&mut tx.tx),
        Msg::Block(block) => {
            let dropped = block.transactions.iter().map(measure).sum();
            block.transactions.clear();
            block.transactions.shrink_to_fit();
            dropped
        }
        Msg::Blocktxn(blocktxn) => blocktxn.transactions.iter_mut().map(take_raw).sum(),
        Msg::Compactblock(compact) => compact
            .transactions
            .iter_mut()
            .map(|p| take_raw(&mut p.tx))
            .sum(),
        // ...plus the payload of an unrecognised message, which is raw wire
        // bytes of unbounded size that nothing here can interpret anyway. The
        // command name is kept, and that is what the event is classified by.
        Msg::Unknown(unknown) => {
            let dropped = unknown.payload.len();
            unknown.payload = Vec::new();
            dropped
        }
        _ => 0,
    }
}

fn take_raw(tx: &mut Transaction) -> usize {
    tx.raw.take().map_or(0, |raw| raw.len())
}

/// Encoded size of a transaction that is about to be dropped whole.
fn measure(tx: &Transaction) -> usize {
    tx.raw.as_ref().map_or(0, |raw| raw.len()) + tx.txid.len() + tx.wtxid.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        bitcoin_primitives::{BlockHeader, PrefilledTransaction},
        ebpf_extractor::{
            self,
            message::{Block, BlockTxn, CompactBlock, MessageEvent, Metadata, Ping, Tx, Unknown},
        },
    };
    use prost::Message;

    fn tx(raw: usize) -> Transaction {
        Transaction {
            txid: vec![1; 32],
            wtxid: vec![2; 32],
            raw: (raw > 0).then(|| vec![0xAB; raw]),
        }
    }

    fn header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_blockhash: vec![0; 32],
            merkle_root: vec![0; 32],
            time: 1,
            bits: 1,
            nonce: 1,
            hash: vec![9; 32],
        }
    }

    fn event(msg: Msg) -> Event {
        Event {
            timestamp: 1,
            peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(ebpf_extractor::Ebpf {
                ebpf_event: Some(EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id: 1,
                        addr: "10.0.0.1:8333".into(),
                        conn_type: 1,
                        command: "tx".into(),
                        inbound: true,
                        size: 1,
                    },
                    msg: Some(msg),
                })),
            })),
        }
    }

    /// The point of the exercise: a big event must shrink dramatically, and the
    /// identifying fields must survive.
    #[test]
    fn a_transaction_keeps_its_ids_and_loses_its_bytes() {
        let mut e = event(Msg::Tx(Tx { tx: tx(100_000) }));
        let before = e.encode_to_vec().len();

        let dropped = strip_raw_payloads(&mut e);

        assert_eq!(dropped, 100_000);
        let after = e.encode_to_vec().len();
        assert!(
            after < 200,
            "stripped event should be tiny, got {after} from {before}"
        );

        let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &e.peer_observer_event else {
            panic!()
        };
        let Some(EbpfEvent::Message(m)) = &ebpf.ebpf_event else {
            panic!()
        };
        let Some(Msg::Tx(t)) = &m.msg else { panic!() };
        assert_eq!(t.tx.txid, vec![1; 32], "txid kept");
        assert_eq!(t.tx.wtxid, vec![2; 32], "wtxid kept");
        assert_eq!(t.tx.raw, None, "raw dropped");
        // The metadata every view depends on is untouched.
        assert_eq!(m.meta.peer_id, 1);
        assert_eq!(m.meta.command, "tx");
    }

    #[test]
    fn a_block_keeps_its_header_and_drops_its_transactions() {
        let mut e = event(Msg::Block(Block {
            header: header(),
            transactions: (0..50).map(|_| tx(2_000)).collect(),
        }));

        let dropped = strip_raw_payloads(&mut e);
        assert!(dropped >= 50 * 2_000, "got {dropped}");

        let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &e.peer_observer_event else {
            panic!()
        };
        let Some(EbpfEvent::Message(m)) = &ebpf.ebpf_event else {
            panic!()
        };
        let Some(Msg::Block(b)) = &m.msg else {
            panic!()
        };
        assert!(b.transactions.is_empty());
        assert_eq!(
            b.header.hash,
            vec![9; 32],
            "header kept, block still identifiable"
        );
    }

    #[test]
    fn blocktxn_and_compactblock_transactions_keep_their_ids() {
        let mut e = event(Msg::Blocktxn(BlockTxn {
            block_hash: vec![7; 32],
            transactions: (0..10).map(|_| tx(5_000)).collect(),
        }));
        assert_eq!(strip_raw_payloads(&mut e), 50_000);

        let mut e = event(Msg::Compactblock(CompactBlock {
            header: header(),
            nonce: 1,
            short_ids: vec![vec![0; 6]; 100],
            transactions: (0..3)
                .map(|i| PrefilledTransaction {
                    diff_index: i,
                    tx: tx(4_000),
                })
                .collect(),
        }));
        assert_eq!(strip_raw_payloads(&mut e), 12_000);

        let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &e.peer_observer_event else {
            panic!()
        };
        let Some(EbpfEvent::Message(m)) = &ebpf.ebpf_event else {
            panic!()
        };
        let Some(Msg::Compactblock(c)) = &m.msg else {
            panic!()
        };
        assert_eq!(c.transactions.len(), 3, "prefilled entries survive");
        assert!(c.transactions.iter().all(|p| p.tx.raw.is_none()));
        assert_eq!(c.short_ids.len(), 100, "short ids are small and kept");
    }

    #[test]
    fn an_unknown_messages_payload_is_dropped_but_its_command_is_kept() {
        let mut e = event(Msg::Unknown(Unknown {
            command: "weird".into(),
            payload: vec![0xCD; 20_000],
        }));

        assert_eq!(strip_raw_payloads(&mut e), 20_000);
        let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &e.peer_observer_event else {
            panic!()
        };
        let Some(EbpfEvent::Message(m)) = &ebpf.ebpf_event else {
            panic!()
        };
        let Some(Msg::Unknown(u)) = &m.msg else {
            panic!()
        };
        assert_eq!(u.command, "weird");
        assert!(u.payload.is_empty());
    }

    /// Events with nothing heavy must report zero, so the caller can keep their
    /// original encoding instead of paying to re-encode.
    #[test]
    fn events_without_raw_data_are_left_alone() {
        let mut e = event(Msg::Ping(Ping { value: 7 }));
        let before = e.encode_to_vec();
        assert_eq!(strip_raw_payloads(&mut e), 0);
        assert_eq!(e.encode_to_vec(), before);

        // A transaction that never carried raw bytes is also a no-op.
        let mut e = event(Msg::Tx(Tx { tx: tx(0) }));
        assert_eq!(strip_raw_payloads(&mut e), 0);

        // Non-message events are not touched at all.
        let mut e = Event {
            timestamp: 1,
            peer_observer_event: None,
        };
        assert_eq!(strip_raw_payloads(&mut e), 0);
    }
}
