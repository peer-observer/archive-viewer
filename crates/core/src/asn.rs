//! Grouping peers by autonomous system.
//!
//! A peer list is the wrong unit for spotting who is actually talking to your
//! node: one operator shows up as thousands of addresses. Bitcoin Core has the
//! same problem and solves it with asmap — an IP-to-ASN trie it uses to bucket
//! peers for eviction and address management. This applies the same mapping, so
//! the viewer groups peers the way Core reasons about them.
//!
//! The asmap file is supplied by the caller (the page fetches it) and is
//! optional: without it, peers are simply not grouped.

use crate::analysis::Analysis;
use crate::peers::{LifecycleKind, PeerStats};
use asmap::Asmap;
use std::collections::HashMap;
use std::net::IpAddr;

/// Which network a peer belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Network {
    /// Mapped to an autonomous system.
    Asn(u32),
    /// A routable IP address the asmap file does not cover.
    UnmappedIp,
    /// Not an IP address at all — Tor, I2P or CJDNS.
    Anonymising,
    /// The peer's address was never observed (only misbehaviour events).
    Unknown,
}

impl Network {
    pub fn asn(self) -> Option<u32> {
        match self {
            Network::Asn(asn) => Some(asn),
            _ => None,
        }
    }

    /// Label for a network with no autonomous system.
    pub fn label(self) -> &'static str {
        match self {
            Network::Asn(_) => "",
            Network::UnmappedIp => "unmapped IP",
            Network::Anonymising => "Tor / I2P / CJDNS",
            Network::Unknown => "address not seen",
        }
    }
}

/// Aggregated statistics for one network.
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    pub peers: u64,
    pub messages_in: u64,
    pub messages_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Exact counts per lifecycle kind, indexed by [`LifecycleKind::index`].
    pub lifecycle: [u64; 5],
    pub first_seen: u64,
    pub last_seen: u64,
}

impl NetworkStats {
    pub fn count(&self, kind: LifecycleKind) -> u64 {
        self.lifecycle[kind.index()]
    }

    /// Share of this network's inbound connections that Core chose to evict.
    ///
    /// A high ratio across many addresses in one AS is the signature of a
    /// connection flood: the connections are made and immediately thrown away.
    pub fn eviction_ratio(&self) -> Option<f64> {
        let inbound = self.count(LifecycleKind::Inbound);
        (inbound > 0).then(|| self.count(LifecycleKind::InboundEvicted) as f64 / inbound as f64)
    }

    fn absorb(&mut self, peer: &PeerStats) {
        self.peers += 1;
        self.messages_in += peer.messages_in;
        self.messages_out += peer.messages_out;
        self.bytes_in += peer.bytes_in;
        self.bytes_out += peer.bytes_out;
        for (slot, count) in self.lifecycle.iter_mut().zip(peer.lifecycle_counts) {
            *slot += count as u64;
        }
        self.first_seen = if self.first_seen == 0 {
            peer.first_seen
        } else {
            self.first_seen.min(peer.first_seen)
        };
        self.last_seen = self.last_seen.max(peer.last_seen);
    }

    /// Every event attributed to peers in this network.
    pub fn events(&self) -> u64 {
        self.messages_in + self.messages_out + self.lifecycle.iter().sum::<u64>()
    }
}

/// Extract the IP from a peer address.
///
/// Addresses arrive as Bitcoin Core formats them: `1.2.3.4:8333` for IPv4 and
/// `[2001:db8::1]:8333` for IPv6. Onion and I2P addresses are not IPs and are
/// reported as such rather than being forced into a bucket.
pub fn peer_ip(addr: &str) -> Option<IpAddr> {
    if let Some(rest) = addr.strip_prefix('[') {
        // [v6]:port, or a bare bracketed address.
        return rest.split(']').next()?.parse().ok();
    }
    // Strip a trailing :port, but only when the remainder still looks like IPv4;
    // a bare unbracketed IPv6 address has colons of its own.
    if let Some((host, port)) = addr.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(ip) = host.parse() {
                return Some(ip);
            }
        }
    }
    addr.parse().ok()
}

/// Which network a single peer belongs to.
pub fn network_of(peer: &PeerStats, asmap: &Asmap) -> Network {
    let Some(addr) = peer.addr.as_deref() else {
        return Network::Unknown;
    };
    let Some(ip) = peer_ip(addr) else {
        return Network::Anonymising;
    };
    match asmap.lookup(ip) {
        // asmap reports 0 for an address it does not cover.
        0 => Network::UnmappedIp,
        asn => Network::Asn(asn),
    }
}

/// Group every peer in the archive by network, busiest first.
pub fn group(analysis: &Analysis, asmap: &Asmap) -> Vec<(Network, NetworkStats)> {
    let mut groups: HashMap<Network, NetworkStats> = HashMap::new();
    for peer in analysis.peers.iter() {
        groups
            .entry(network_of(peer, asmap))
            .or_default()
            .absorb(peer);
    }
    let mut out: Vec<(Network, NetworkStats)> = groups.into_iter().collect();
    out.sort_by(|a, b| b.1.peers.cmp(&a.1.peers).then(a.0.cmp(&b.0)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_address_formats_bitcoin_core_emits() {
        assert_eq!(peer_ip("1.2.3.4:8333"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(
            peer_ip("[2602:f5c0:0:ace::72:158]:34081"),
            Some("2602:f5c0:0:ace::72:158".parse().unwrap())
        );
        assert_eq!(
            peer_ip("127.0.0.1:48682"),
            Some("127.0.0.1".parse().unwrap())
        );
        // Bare addresses, just in case.
        assert_eq!(peer_ip("8.8.8.8"), Some("8.8.8.8".parse().unwrap()));
        assert_eq!(peer_ip("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn non_ip_addresses_are_not_forced_into_a_bucket() {
        assert_eq!(peer_ip("explorernuoc63nb.onion:8333"), None);
        assert_eq!(peer_ip("gehtsi3qc5gxhq.b32.i2p:0"), None);
        assert_eq!(peer_ip(""), None);
    }

    #[test]
    fn eviction_ratio_needs_inbound_connections() {
        let mut stats = NetworkStats::default();
        assert_eq!(stats.eviction_ratio(), None);

        stats.lifecycle[LifecycleKind::Inbound.index()] = 100;
        stats.lifecycle[LifecycleKind::InboundEvicted.index()] = 97;
        assert_eq!(stats.eviction_ratio(), Some(0.97));
    }
}
