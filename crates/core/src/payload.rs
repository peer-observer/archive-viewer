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
//! Only messages whose *shape* is worth a word get one. `inv 1.2 kB` says
//! nothing about whether that was one transaction or forty; `inv 1.2 kB 40 wtx`
//! does. A `tx` message, on the other hand, is one transaction by definition,
//! and its size already says how big.

use crate::analysis::Analysis;
use crate::proto::{
    bitcoin_primitives::{inventory_item::Item, InventoryItem},
    ebpf_extractor::{ebpf::EbpfEvent, message::message_event::Msg},
    event::{event::PeerObserverEvent, Event},
};
use prost::Message;

/// Commands with something to say beyond their size.
///
/// Checked before decoding, so a page full of `tx` messages -- which is what a
/// relaying peer's page is -- costs nothing at all. The list is exactly the
/// arms [`describe`] handles.
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

/// Describe one retained message, or `None` if it was not retained, is not a
/// P2P message, or is one whose size already tells the whole story.
pub fn message_detail(analysis: &Analysis, index: u32) -> Option<String> {
    let event = Event::decode(analysis.store.bytes(index)?).ok()?;
    let PeerObserverEvent::EbpfExtractor(ebpf) = event.peer_observer_event? else {
        return None;
    };
    let EbpfEvent::Message(message) = ebpf.ebpf_event? else {
        return None;
    };
    describe(&message.msg?)
}

fn describe(msg: &Msg) -> Option<String> {
    match msg {
        Msg::Inv(m) => Some(inventory(&m.items)),
        Msg::Getdata(m) => Some(inventory(&m.items)),
        Msg::Notfound(m) => Some(inventory(&m.items)),
        Msg::Addr(m) => Some(count(m.addresses.len(), "address", "addresses")),
        Msg::Addrv2(m) => Some(count(m.addresses.len(), "address", "addresses")),
        Msg::Headers(m) => Some(count(m.headers.len(), "header", "headers")),
        Msg::Compactblock(m) => Some(count(m.short_ids.len(), "short id", "short ids")),
        Msg::Getblocktxn(m) => Some(count(m.tx_indexes.len(), "index", "indexes")),
        Msg::Blocktxn(m) => Some(count(m.transactions.len(), "transaction", "transactions")),
        _ => None,
    }
}

fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
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
        .map(|(n, name)| format!("{n} {name}"))
        .collect();
    if parts.is_empty() {
        // A legitimate message: Core sends an empty `inv` for nothing, but an
        // empty `notfound` and an empty `getdata` both happen.
        return "empty".to_string();
    }
    parts.join(", ")
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
        assert_eq!(inventory(&items), "2 wtx, 1 block");

        // Order is the type's, not the count's: the same mix always reads the
        // same way whichever came first on the wire.
        let swapped = vec![
            item(Item::Block(vec![2; 32])),
            item(Item::Wtx(vec![1; 32])),
            item(Item::Wtx(vec![3; 32])),
        ];
        assert_eq!(inventory(&swapped), "2 wtx, 1 block");
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
        assert_eq!(inventory(&items), "1 unknown, 2 malformed");
    }

    #[test]
    fn an_empty_inventory_says_so_rather_than_nothing() {
        assert_eq!(inventory(&[]), "empty");
    }

    #[test]
    fn counts_are_singular_where_there_is_one_of_them() {
        assert_eq!(count(1, "address", "addresses"), "1 address");
        assert_eq!(count(0, "address", "addresses"), "0 addresses");
        assert_eq!(count(9, "address", "addresses"), "9 addresses");
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
