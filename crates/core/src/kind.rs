//! The event taxonomy: every event is classified as category → group → kind.
//!
//! Kinds are interned to `u16` ids because they are not a closed set — an
//! `ebpf.message` event is classified by its `meta.command`, which is free text
//! for unrecognised P2P commands.

use crate::proto::{
    ebpf_extractor::{ebpf::EbpfEvent, Ebpf},
    event::{event::PeerObserverEvent, Event},
    ipc_extractor::{ipc::IpcEvent, Ipc},
    log_extractor::{log::LogEvent, Log},
    p2p_extractor::{p2p::P2pEvent, P2p},
    rpc_extractor::{rpc::RpcEvent, Rpc},
};
use std::collections::HashMap;

/// Top-level classification, matching the `Event` oneof arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Ebpf,
    Rpc,
    P2p,
    Log,
    Ipc,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Ebpf => "ebpf",
            Category::Rpc => "rpc",
            Category::P2p => "p2p",
            Category::Log => "log",
            Category::Ipc => "ipc",
        }
    }
}

/// Second level. The eBPF category splits four ways; the others have a single
/// group so that the timeline always has one series per group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    EbpfMessage,
    EbpfConnection,
    EbpfMempool,
    EbpfValidation,
    Rpc,
    P2p,
    Log,
    Ipc,
}

/// Every group, in display order. This is also the timeline's series order.
pub const GROUPS: [Group; 8] = [
    Group::EbpfMessage,
    Group::EbpfConnection,
    Group::EbpfMempool,
    Group::EbpfValidation,
    Group::Rpc,
    Group::P2p,
    Group::Log,
    Group::Ipc,
];

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Group::EbpfMessage => "message",
            Group::EbpfConnection => "connection",
            Group::EbpfMempool => "mempool",
            Group::EbpfValidation => "validation",
            Group::Rpc => "rpc",
            Group::P2p => "p2p",
            Group::Log => "log",
            Group::Ipc => "ipc",
        }
    }

    pub fn category(self) -> Category {
        match self {
            Group::EbpfMessage
            | Group::EbpfConnection
            | Group::EbpfMempool
            | Group::EbpfValidation => Category::Ebpf,
            Group::Rpc => Category::Rpc,
            Group::P2p => Category::P2p,
            Group::Log => Category::Log,
            Group::Ipc => Category::Ipc,
        }
    }

    /// Index into [`GROUPS`].
    pub fn index(self) -> usize {
        GROUPS
            .iter()
            .position(|g| *g == self)
            .expect("GROUPS covers every group")
    }
}

/// A distinct event kind, e.g. `ebpf` / `message` / `inv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindInfo {
    pub group: Group,
    pub name: String,
}

/// Interns kinds to dense `u16` ids so events can be stored compactly.
#[derive(Debug, Default)]
pub struct KindTable {
    kinds: Vec<KindInfo>,
    index: HashMap<(Group, String), u16>,
}

impl KindTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Id for a kind, interning it on first sight.
    pub fn intern(&mut self, group: Group, name: &str) -> u16 {
        if let Some(id) = self.index.get(&(group, name.to_string())) {
            return *id;
        }
        let id = u16::try_from(self.kinds.len())
            .expect("an archive cannot contain more than u16::MAX distinct event kinds");
        self.kinds.push(KindInfo {
            group,
            name: name.to_string(),
        });
        self.index.insert((group, name.to_string()), id);
        id
    }

    pub fn get(&self, id: u16) -> Option<&KindInfo> {
        self.kinds.get(id as usize)
    }

    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (u16, &KindInfo)> {
        self.kinds.iter().enumerate().map(|(i, k)| (i as u16, k))
    }
}

/// Classify an event. The returned name is borrowed from the event where
/// possible so that the common path allocates nothing.
pub fn classify(event: &Event) -> (Group, &str) {
    match &event.peer_observer_event {
        Some(PeerObserverEvent::EbpfExtractor(ebpf)) => classify_ebpf(ebpf),
        Some(PeerObserverEvent::RpcExtractor(rpc)) => (Group::Rpc, classify_rpc(rpc)),
        Some(PeerObserverEvent::P2pExtractor(p2p)) => (Group::P2p, classify_p2p(p2p)),
        Some(PeerObserverEvent::LogExtractor(log)) => (Group::Log, classify_log(log)),
        Some(PeerObserverEvent::IpcExtractor(ipc)) => (Group::Ipc, classify_ipc(ipc)),
        // An event with no oneof arm set: either an older writer or a newer
        // schema than this build knows about.
        None => (Group::EbpfMessage, UNKNOWN),
    }
}

/// Shown when an arm is present but this build does not recognise it, which
/// happens when an archive was written by a newer peer-observer.
pub const UNKNOWN: &str = "(unknown)";

fn classify_ebpf(ebpf: &Ebpf) -> (Group, &str) {
    match &ebpf.ebpf_event {
        // Classified by the wire command rather than the oneof arm, so that
        // unrecognised commands stay distinguishable instead of collapsing
        // into one "unknown" bucket.
        Some(EbpfEvent::Message(m)) => (Group::EbpfMessage, m.meta.command.as_str()),
        Some(EbpfEvent::Connection(c)) => {
            use crate::proto::ebpf_extractor::connection::connection_event::Event as C;
            let name = match &c.event {
                Some(C::Closed(_)) => "closed",
                Some(C::InboundEvicted(_)) => "inbound_evicted",
                Some(C::Inbound(_)) => "inbound",
                Some(C::Outbound(_)) => "outbound",
                Some(C::Misbehaving(_)) => "misbehaving",
                None => UNKNOWN,
            };
            (Group::EbpfConnection, name)
        }
        Some(EbpfEvent::Mempool(m)) => {
            use crate::proto::ebpf_extractor::mempool::mempool_event::Event as M;
            let name = match &m.event {
                Some(M::Added(_)) => "added",
                Some(M::Replaced(_)) => "replaced",
                Some(M::Removed(_)) => "removed",
                Some(M::Rejected(_)) => "rejected",
                None => UNKNOWN,
            };
            (Group::EbpfMempool, name)
        }
        Some(EbpfEvent::Validation(v)) => {
            use crate::proto::ebpf_extractor::validation::validation_event::Event as V;
            let name = match &v.event {
                Some(V::BlockConnected(_)) => "block_connected",
                None => UNKNOWN,
            };
            (Group::EbpfValidation, name)
        }
        None => (Group::EbpfMessage, UNKNOWN),
    }
}

fn classify_rpc(rpc: &Rpc) -> &'static str {
    match &rpc.rpc_event {
        Some(RpcEvent::PeerInfos(_)) => "peer_infos",
        Some(RpcEvent::MempoolInfo(_)) => "mempool_info",
        Some(RpcEvent::Uptime(_)) => "uptime",
        Some(RpcEvent::NetTotals(_)) => "net_totals",
        Some(RpcEvent::MemoryInfo(_)) => "memory_info",
        Some(RpcEvent::AddrmanInfo(_)) => "addrman_info",
        Some(RpcEvent::ChainTxStats(_)) => "chain_tx_stats",
        Some(RpcEvent::NetworkInfo(_)) => "network_info",
        Some(RpcEvent::BlockchainInfo(_)) => "blockchain_info",
        Some(RpcEvent::OrphanTxs(_)) => "orphan_txs",
        Some(RpcEvent::Addrman(_)) => "addrman",
        Some(RpcEvent::EstimateSmartFee(_)) => "estimate_smart_fee",
        None => UNKNOWN,
    }
}

fn classify_p2p(p2p: &P2p) -> &'static str {
    match &p2p.p2p_event {
        Some(P2pEvent::PingDuration(_)) => "ping_duration",
        Some(P2pEvent::AddressAnnouncement(_)) => "address_announcement",
        Some(P2pEvent::InventoryAnnouncement(_)) => "inventory_announcement",
        Some(P2pEvent::FeefilterAnnouncement(_)) => "feefilter_announcement",
        None => UNKNOWN,
    }
}

fn classify_log(log: &Log) -> &'static str {
    match &log.log_event {
        Some(LogEvent::UnknownLogMessage(_)) => "unknown_log_message",
        Some(LogEvent::BlockConnectedLog(_)) => "block_connected",
        Some(LogEvent::BlockCheckedLog(_)) => "block_checked",
        Some(LogEvent::SawNewHeaderLog(_)) => "saw_new_header",
        Some(LogEvent::CompactBlockReconstructedLog(_)) => "compact_block_reconstructed",
        None => UNKNOWN,
    }
}

fn classify_ipc(ipc: &Ipc) -> &'static str {
    match &ipc.ipc_event {
        Some(IpcEvent::BlockTip(_)) => "block_tip",
        None => UNKNOWN,
    }
}

impl KindInfo {
    pub fn category(&self) -> Category {
        self.group.category()
    }

    /// Display label for the event table.
    ///
    /// P2P message kinds are wire command names (`inv`, `version`) and stand on
    /// their own. Everywhere else the bare kind is ambiguous — `rejected`,
    /// `closed` and `block_connected` mean nothing without knowing whether they
    /// came from the mempool, a connection or validation — so the group is
    /// carried along.
    pub fn label(&self) -> String {
        match self.group {
            Group::EbpfMessage => self.name.clone(),
            group => format!("{} {}", group.as_str(), self.name),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_is_stable_and_dense() {
        let mut table = KindTable::new();
        let inv = table.intern(Group::EbpfMessage, "inv");
        let tx = table.intern(Group::EbpfMessage, "tx");

        assert_eq!(inv, 0);
        assert_eq!(tx, 1);
        assert_eq!(
            table.intern(Group::EbpfMessage, "inv"),
            inv,
            "re-interning is stable"
        );
        assert_eq!(table.len(), 2);
        assert_eq!(table.get(inv).unwrap().name, "inv");
    }

    /// The same name in two groups is two kinds: `ebpf.validation.block_connected`
    /// and `log.block_connected` are different events.
    #[test]
    fn the_same_name_in_two_groups_is_two_kinds() {
        let mut table = KindTable::new();
        let validation = table.intern(Group::EbpfValidation, "block_connected");
        let log = table.intern(Group::Log, "block_connected");

        assert_ne!(validation, log);
        assert_eq!(table.get(validation).unwrap().category(), Category::Ebpf);
        assert_eq!(table.get(log).unwrap().category(), Category::Log);
    }

    #[test]
    fn group_indices_match_the_groups_table() {
        for (i, group) in GROUPS.iter().enumerate() {
            assert_eq!(group.index(), i);
        }
    }
}
