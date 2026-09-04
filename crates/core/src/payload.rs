//! What a P2P message carried, in one short line.
//!
//! The archive holds the decoded body of every message, not only its command
//! and size: an `inv` carries the txids it announced, an `addrv2` the addresses
//! it gossiped, a `headers` the headers themselves. None of that is read while
//! aggregating -- decoding two and a half million payloads to count events would
//! be an enormous cost for a number that does not need them -- so it is decoded
//! here, on demand, for the handful of rows a page of the sequence diagram
//! actually draws.
//!
//! Two things come out of it. A short line for the label, where the size does
//! not already say it -- `inv (145 bytes)` says nothing about whether that was
//! one transaction or forty, and `inv (4x wtx, 145 bytes)` does. And the hashes
//! the message names, so that a reply can be tied to the request that actually
//! asked for it rather than to whichever request came last.

use crate::analysis::Analysis;
use crate::proto::{
    bitcoin_primitives::{inventory_item::Item, InventoryItem},
    ebpf_extractor::{ebpf::EbpfEvent, message::message_event::Msg},
    event::{event::PeerObserverEvent, Event},
};
use prost::Message;

/// Commands with something to say beyond their size.
///
/// The list is exactly the arms [`describe`] handles.
pub fn has_detail(command: &str) -> bool {
    matches!(
        command,
        "inv"
            | "getdata"
            | "notfound"
            | "addr"
            | "addrv2"
            | "headers"
            | "cmpctblock"
            | "getblocktxn"
            | "blocktxn"
    )
}

fn describe(msg: &Msg) -> Option<String> {
    match msg {
        Msg::Inv(m) => Some(inventory(&m.items)),
        Msg::Getdata(m) => Some(inventory(&m.items)),
        Msg::Notfound(m) => Some(inventory(&m.items)),
        Msg::Addr(m) => Some(times(m.addresses.len(), "address")),
        Msg::Addrv2(m) => Some(times(m.addresses.len(), "address")),
        Msg::Headers(m) => Some(times(m.headers.len(), "header")),
        // A compact block is both numbers or neither: the short ids are what
        // the peer expects this node to already have, and the prefilled ones
        // are what it knew it would not -- the coinbase always, and whatever
        // else it guessed was missing.
        Msg::Compactblock(m) => Some(format!(
            "{}, {}",
            times(m.short_ids.len(), "short id"),
            times(m.transactions.len(), "prefilled"),
        )),
        Msg::Getblocktxn(m) => Some(times(m.tx_indexes.len(), "index")),
        Msg::Blocktxn(m) => Some(times(m.transactions.len(), "transaction")),
        _ => None,
    }
}

/// How many of a thing, the way the labels read: `4x wtx`, `10x address`.
///
/// Always the same shape, singular included, so a column of them lines up and
/// nothing has to carry a plural for every noun in the protocol.
fn times(n: usize, name: &str) -> String {
    format!("{n}x {name}")
}

/// The inventory types in one `inv`, `getdata` or `notfound`, counted.
///
/// Ordered by the type rather than by the count, so that the same message
/// always reads the same way and a column of them can be scanned. A mixed
/// message is rare -- Bitcoin Core batches by type -- but it is the case worth
/// seeing, since it is where a `getdata` asks for a block and a transaction in
/// one breath.
fn inventory(items: &[InventoryItem]) -> String {
    // Indices into `NAMES`, in the order they are reported.
    const NAMES: [&str; 8] = [
        "tx",
        "wtx",
        "witness tx",
        "block",
        "witness block",
        "cmpctblock",
        "unknown",
        "malformed",
    ];
    let mut counts = [0usize; NAMES.len()];
    for item in items {
        let slot = match &item.item {
            Some(Item::Transaction(_)) => 0,
            Some(Item::Wtx(_)) => 1,
            Some(Item::WitnessTransaction(_)) => 2,
            Some(Item::Block(_)) => 3,
            Some(Item::WitnessBlock(_)) => 4,
            Some(Item::CompactBlock(_)) => 5,
            Some(Item::Unknown(_)) => 6,
            // `error` is the extractor saying it could not read the item, and
            // an item with no arm at all is a schema this build predates.
            Some(Item::Error(_)) | None => 7,
        };
        counts[slot] += 1;
    }

    let parts: Vec<String> = counts
        .iter()
        .zip(NAMES)
        .filter(|(n, _)| **n > 0)
        .map(|(n, name)| times(*n, name))
        .collect();
    if parts.is_empty() {
        // A legitimate message: Core sends an empty `inv` for nothing, but an
        // empty `notfound` and an empty `getdata` both happen.
        return "empty".to_string();
    }
    parts.join(", ")
}

/// Commands that identify themselves on the wire, and can therefore have a
/// reply matched to them by what they name rather than by what came next.
///
/// `getheaders` is not among them: its locator is a walk back from the tip, not
/// the hashes of the headers that answer it, so there is nothing to compare.
pub fn has_keys(command: &str) -> bool {
    matches!(
        command,
        "inv"
            | "getdata"
            | "notfound"
            | "tx"
            | "block"
            | "merkleblock"
            | "cmpctblock"
            | "getblocktxn"
            | "blocktxn"
            | "ping"
            | "pong"
    )
}

/// Everything decoded from one retained message that anything outside this
/// module wants.
#[derive(Debug, Default, Clone)]
pub struct Carried {
    /// A short line for the label, where the size does not already say it.
    pub detail: Option<String>,
    /// What the message names: inventory hashes, a txid and wtxid, a block
    /// hash, a ping nonce. Sorted, so a reply can be looked up in a request's.
    pub keys: Vec<u64>,
}

/// Whether a command is worth decoding at all.
pub fn worth_decoding(command: &str) -> bool {
    has_detail(command) || has_keys(command)
}

/// Decode one retained message for its label and its identifying hashes.
///
/// `None` when the event was not retained, is not a P2P message, or is a
/// command with nothing to say either way. Callers should check
/// [`worth_decoding`] first, which costs a string comparison instead of a
/// protobuf decode.
pub fn carried(analysis: &Analysis, index: u32) -> Option<Carried> {
    let event = Event::decode(analysis.store.bytes(index)?).ok()?;
    let PeerObserverEvent::EbpfExtractor(ebpf) = event.peer_observer_event? else {
        return None;
    };
    let EbpfEvent::Message(message) = ebpf.ebpf_event? else {
        return None;
    };
    let msg = message.msg?;
    let mut keys = keys_of(&msg);
    keys.sort_unstable();
    keys.dedup();
    Some(Carried {
        detail: describe(&msg),
        keys,
    })
}

/// The leading eight bytes of a hash, as one number.
///
/// A hash is 32 bytes and comparing all of them would mean carrying them all;
/// eight is far more than enough to tell apart the few dozen things one peer
/// has in flight, which is the only comparison ever made.
fn prefix(hash: &[u8]) -> Option<u64> {
    hash.get(..8)
        .map(|head| u64::from_le_bytes(head.try_into().expect("eight bytes")))
}

fn item_key(item: &InventoryItem) -> Option<u64> {
    // The hash, whatever the type says it is. Bitcoin Core answers an `inv` of
    // `wtx` with a `getdata` for `witness tx`, copying the hash across, so
    // matching on the type as well as the hash would lose exactly the pairing
    // this is for.
    match item.item.as_ref()? {
        Item::Transaction(h)
        | Item::Block(h)
        | Item::Wtx(h)
        | Item::WitnessTransaction(h)
        | Item::WitnessBlock(h)
        | Item::CompactBlock(h) => prefix(h),
        Item::Unknown(u) => prefix(&u.hash),
        Item::Error(_) => None,
    }
}

fn keys_of(msg: &Msg) -> Vec<u64> {
    match msg {
        Msg::Inv(m) => m.items.iter().filter_map(item_key).collect(),
        Msg::Getdata(m) => m.items.iter().filter_map(item_key).collect(),
        Msg::Notfound(m) => m.items.iter().filter_map(item_key).collect(),
        // A transaction answers a request naming either of its hashes.
        Msg::Tx(m) => [prefix(&m.tx.txid), prefix(&m.tx.wtxid)]
            .into_iter()
            .flatten()
            .collect(),
        Msg::Block(m) => prefix(&m.header.hash).into_iter().collect(),
        Msg::Merkleblock(m) => prefix(&m.header.hash).into_iter().collect(),
        Msg::Compactblock(m) => prefix(&m.header.hash).into_iter().collect(),
        Msg::Getblocktxn(m) => prefix(&m.block_hash).into_iter().collect(),
        Msg::Blocktxn(m) => prefix(&m.block_hash).into_iter().collect(),
        // The one exact identifier in the protocol, and the reason a `pong` can
        // be tied to its `ping` with no guessing at all.
        Msg::Ping(m) => vec![m.value],
        Msg::Pong(m) => vec![m.value],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::bitcoin_primitives::UnknownItem;

    fn item(item: Item) -> InventoryItem {
        InventoryItem { item: Some(item) }
    }

    #[test]
    fn inventory_counts_by_type_in_a_fixed_order() {
        let items = vec![
            item(Item::Wtx(vec![1; 32])),
            item(Item::Block(vec![2; 32])),
            item(Item::Wtx(vec![3; 32])),
        ];
        assert_eq!(inventory(&items), "2x wtx, 1x block");

        // Order is the type's, not the count's: the same mix always reads the
        // same way whichever came first on the wire.
        let swapped = vec![
            item(Item::Block(vec![2; 32])),
            item(Item::Wtx(vec![1; 32])),
            item(Item::Wtx(vec![3; 32])),
        ];
        assert_eq!(inventory(&swapped), "2x wtx, 1x block");
    }

    #[test]
    fn an_inventory_item_the_extractor_could_not_read_is_still_counted() {
        let items = vec![
            item(Item::Error(true)),
            item(Item::Unknown(UnknownItem {
                inv_type: 99,
                hash: vec![0; 32],
            })),
            InventoryItem { item: None },
        ];
        assert_eq!(inventory(&items), "1x unknown, 2x malformed");
    }

    #[test]
    fn a_compact_block_reports_what_it_sent_and_what_it_expected() {
        use crate::proto::bitcoin_primitives::{BlockHeader, PrefilledTransaction, Transaction};
        use crate::proto::ebpf_extractor::message::CompactBlock;
        let prefilled = |index| PrefilledTransaction {
            diff_index: index,
            tx: Transaction::default(),
        };
        let block = CompactBlock {
            header: BlockHeader::default(),
            nonce: 7,
            short_ids: vec![vec![0; 6]; 2431],
            // The coinbase, which the peer can never have seen, and one more the
            // sender guessed at.
            transactions: vec![prefilled(0), prefilled(12)],
        };
        assert_eq!(
            describe(&Msg::Compactblock(block)),
            Some("2431x short id, 2x prefilled".to_string())
        );
    }
    #[test]
    fn an_empty_inventory_says_so_rather_than_nothing() {
        assert_eq!(inventory(&[]), "empty");
    }

    #[test]
    fn counts_read_the_same_shape_whatever_the_number() {
        assert_eq!(times(1, "address"), "1x address");
        assert_eq!(times(0, "address"), "0x address");
        assert_eq!(times(9, "address"), "9x address");
    }

    /// The gate and the match arms have to agree, or a command either pays for
    /// a decode that yields nothing or never gets the line it has.
    #[test]
    fn every_gated_command_actually_has_a_description() {
        use crate::proto::bitcoin_primitives::{Address, BlockHeader};
        use crate::proto::ebpf_extractor::message::{
            Addr, AddrV2, BlockTxn, CompactBlock, GetBlockTxn, GetData, Headers, Inv, NotFound,
        };
        let header = BlockHeader::default();
        let address = Address::default();
        for (command, msg) in [
            ("inv", Msg::Inv(Inv { items: vec![] })),
            ("getdata", Msg::Getdata(GetData { items: vec![] })),
            ("notfound", Msg::Notfound(NotFound { items: vec![] })),
            (
                "addr",
                Msg::Addr(Addr {
                    addresses: vec![address.clone()],
                }),
            ),
            (
                "addrv2",
                Msg::Addrv2(AddrV2 {
                    addresses: vec![address],
                }),
            ),
            (
                "headers",
                Msg::Headers(Headers {
                    headers: vec![header.clone()],
                }),
            ),
            (
                "cmpctblock",
                Msg::Compactblock(CompactBlock {
                    header,
                    nonce: 0,
                    short_ids: vec![vec![0; 6]],
                    transactions: vec![],
                }),
            ),
            (
                "getblocktxn",
                Msg::Getblocktxn(GetBlockTxn {
                    block_hash: vec![0; 32],
                    tx_indexes: vec![1, 2],
                }),
            ),
            (
                "blocktxn",
                Msg::Blocktxn(BlockTxn {
                    block_hash: vec![0; 32],
                    transactions: vec![],
                }),
            ),
        ] {
            assert!(has_detail(command), "{command} is not gated in");
            assert!(describe(&msg).is_some(), "{command} has no description");
        }
    }
}
