//! Pairing P2P requests with the replies they most likely caused.
//!
//! The archive records a message's command, direction, size and time. It does
//! not record the txids, block hashes, locators or ping nonces *inside* the
//! message, and those are exactly what would make this exact. So a tie here is
//! a likely pairing, not a proven one: the oldest unanswered request of a
//! matching kind, on the same peer, in the opposite direction, inside a window
//! sized to what Bitcoin Core actually does.
//!
//! That is reliable for the handshake, for pings and for the BIP157 filter
//! messages, which are only ever sent in answer to something. It can mislink
//! where a reply command is also sent unsolicited: `inv`, `headers`, `addr` and
//! `cmpctblock` are all announced without being asked for. Views built on this
//! must say so rather than presenting a tie as fact.

use crate::store::NO_PEER;
use std::collections::HashMap;

/// One message on the wire, as the sequence diagram sees it.
#[derive(Debug, Clone, Copy)]
pub struct Turn<'a> {
    /// Store peer index, or [`NO_PEER`].
    pub peer: u32,
    /// The wire command, e.g. `getdata`.
    pub command: &'a str,
    /// `None` for events that are not directed messages.
    pub inbound: Option<bool>,
    pub timestamp: u64,
}

/// A request and the reply it most likely caused, as positions in the slice
/// passed to [`match_turns`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tie {
    pub request: usize,
    pub reply: usize,
    pub elapsed_ms: u64,
}

struct Exchange {
    request: &'static str,
    replies: &'static [&'static str],
    /// Whether one request can be answered by more than one message.
    multi: bool,
    /// How long the request stays open before it is assumed unanswered.
    window_ms: u64,
}

const SECOND: u64 = 1_000;
const MINUTE: u64 = 60 * SECOND;

/// The exchanges worth drawing, by wire command.
///
/// Windows come from Bitcoin Core's own timeouts where it has one, and are
/// otherwise generous: a window that is too long costs a wrong tie on an idle
/// peer, while one that is too short silently drops a real exchange.
const EXCHANGES: &[Exchange] = &[
    // The handshake. Both sides send `version` and both answer with `verack`,
    // so the two halves have to be tracked separately -- see the direction in
    // the key below.
    Exchange {
        request: "version",
        replies: &["verack"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
    // Core pings every two minutes and disconnects after twenty without a pong.
    Exchange {
        request: "ping",
        replies: &["pong"],
        multi: false,
        window_ms: 20 * MINUTE,
    },
    // Core answers `getaddr` out of a cache on its next scheduled address send,
    // a Poisson timer averaging thirty seconds, and may split the answer across
    // several messages.
    Exchange {
        request: "getaddr",
        replies: &["addr", "addrv2"],
        multi: true,
        window_ms: 3 * MINUTE,
    },
    // Announcement, then the request for what was announced.
    Exchange {
        request: "inv",
        replies: &["getdata"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
    // ...and then the items themselves. Core's transaction request timeout is a
    // minute; a block download is given ten.
    Exchange {
        request: "getdata",
        replies: &["tx", "block", "merkleblock", "cmpctblock", "notfound"],
        multi: true,
        window_ms: 10 * MINUTE,
    },
    Exchange {
        request: "getheaders",
        replies: &["headers"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getblocks",
        replies: &["inv"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
    // BIP152: a compact block, the request for the transactions it was missing,
    // and those transactions.
    Exchange {
        request: "cmpctblock",
        replies: &["getblocktxn"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getblocktxn",
        replies: &["blocktxn", "notfound"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "mempool",
        replies: &["inv"],
        multi: true,
        window_ms: 2 * MINUTE,
    },
    // BIP157 compact block filters. These are never sent unsolicited, so these
    // three ties are as good as certain.
    Exchange {
        request: "getcfilters",
        replies: &["cfilter"],
        multi: true,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getcfheaders",
        replies: &["cfheaders"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getcfcheckpt",
        replies: &["cfcheckpt"],
        multi: false,
        window_ms: 2 * MINUTE,
    },
];

/// A request still waiting for its reply.
#[derive(Debug, Clone, Copy)]
struct Open {
    position: usize,
    timestamp: u64,
}

/// Which peer, which exchange, and which way the *request* went. Direction is
/// part of the key because both ends of a connection send `version` and `ping`,
/// and those two conversations must not be confused for one another.
type Key = (u32, usize, bool);

/// Tie up requests and replies in one window of the archive.
///
/// Turns must be in archive order. Only this window is considered, so an
/// exchange straddling the edge of the window is reported as neither a tie nor
/// an error -- it simply does not appear.
pub fn match_turns(turns: &[Turn<'_>]) -> Vec<Tie> {
    // At most one request per peer, exchange and direction is left open: once a
    // peer has sent a second `getdata`, the first one's items are on the wire
    // already, and keeping it open would let it absorb the second one's replies.
    // This also bounds the map by the number of lifelines on screen.
    let mut open: HashMap<Key, Open> = HashMap::new();
    let mut ties = Vec::new();

    for (position, turn) in turns.iter().enumerate() {
        let (Some(inbound), true) = (turn.inbound, turn.peer != NO_PEER) else {
            continue;
        };

        // Match as a reply before registering as a request: `getdata` both
        // answers an `inv` and asks for a `tx`, and must not answer itself.
        let mut best: Option<(Key, Open)> = None;
        for (index, exchange) in EXCHANGES.iter().enumerate() {
            if !exchange.replies.contains(&turn.command) {
                continue;
            }
            let key = (turn.peer, index, !inbound);
            let Some(request) = open.get(&key).copied() else {
                continue;
            };
            if turn.timestamp.saturating_sub(request.timestamp) > exchange.window_ms {
                continue;
            }
            // Oldest first, so pipelined requests are answered in order.
            if best.is_none_or(|(_, other)| request.timestamp < other.timestamp) {
                best = Some((key, request));
            }
        }
        if let Some((key, request)) = best {
            ties.push(Tie {
                request: request.position,
                reply: position,
                elapsed_ms: turn.timestamp.saturating_sub(request.timestamp),
            });
            if !EXCHANGES[key.1].multi {
                open.remove(&key);
            }
        }

        if let Some(index) = EXCHANGES.iter().position(|e| e.request == turn.command) {
            open.insert(
                (turn.peer, index, inbound),
                Open {
                    position,
                    timestamp: turn.timestamp,
                },
            );
        }
    }

    ties
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(peer, command, inbound, seconds)`.
    fn turns(rows: &[(u32, &'static str, bool, u64)]) -> Vec<Turn<'static>> {
        rows.iter()
            .map(|(peer, command, inbound, at)| Turn {
                peer: *peer,
                command,
                inbound: Some(*inbound),
                timestamp: at * SECOND,
            })
            .collect()
    }

    fn pairs(ties: &[Tie]) -> Vec<(usize, usize)> {
        ties.iter().map(|t| (t.request, t.reply)).collect()
    }

    #[test]
    fn ties_both_halves_of_the_handshake_separately() {
        // Peer connects: it sends version, we answer verack, and the same
        // exchange runs the other way. Keying on direction keeps the two apart.
        let rows = turns(&[
            (0, "version", true, 0),  // 0
            (0, "version", false, 0), // 1
            (0, "verack", false, 1),  // 2 answers 0
            (0, "verack", true, 1),   // 3 answers 1
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 2), (1, 3)]);
    }

    #[test]
    fn a_reply_only_ties_to_the_same_peer() {
        let rows = turns(&[
            (7, "ping", false, 0),
            (9, "pong", true, 1), // a different peer: not an answer
            (7, "pong", true, 2),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 2)]);
    }

    #[test]
    fn one_getdata_absorbs_every_transaction_it_asked_for() {
        let rows = turns(&[
            (0, "inv", true, 0),
            (0, "getdata", false, 1),
            (0, "tx", true, 2),
            (0, "tx", true, 3),
            (0, "tx", true, 4),
        ]);
        // inv -> getdata, then getdata -> each tx.
        assert_eq!(
            pairs(&match_turns(&rows)),
            vec![(0, 1), (1, 2), (1, 3), (1, 4)]
        );
    }

    #[test]
    fn a_single_reply_exchange_is_answered_once() {
        let rows = turns(&[
            (0, "ping", false, 0),
            (0, "pong", true, 1),
            (0, "pong", true, 2), // stray: the request is already answered
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 1)]);
    }

    #[test]
    fn a_request_stops_matching_once_its_window_has_passed() {
        let rows = turns(&[
            (0, "getheaders", false, 0),
            (0, "headers", true, 10 * 60), // ten minutes later
        ]);
        assert!(match_turns(&rows).is_empty());
    }

    #[test]
    fn unsolicited_announcements_are_left_untied() {
        // Gossip: an addrv2 nobody asked for, and an inv announcing a
        // transaction. Neither has a request open, so neither is tied.
        let rows = turns(&[(0, "addrv2", true, 0), (0, "inv", true, 1)]);
        assert!(match_turns(&rows).is_empty());
    }

    #[test]
    fn a_later_request_takes_over_from_an_unanswered_one() {
        let rows = turns(&[
            (0, "getdata", false, 0),
            (0, "getdata", false, 1),
            (0, "tx", true, 2),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(1, 2)]);
    }

    #[test]
    fn reports_how_long_the_reply_took() {
        let rows = turns(&[(0, "getaddr", false, 0), (0, "addrv2", true, 42)]);
        let ties = match_turns(&rows);
        assert_eq!(ties.len(), 1);
        assert_eq!(ties[0].elapsed_ms, 42 * SECOND);
    }

    #[test]
    fn follows_the_compact_block_round_trip() {
        let rows = turns(&[
            (0, "cmpctblock", true, 0),
            (0, "getblocktxn", false, 1),
            (0, "blocktxn", true, 2),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 1), (1, 2)]);
    }

    #[test]
    fn events_without_a_peer_or_a_direction_are_skipped() {
        let rows = vec![
            Turn {
                peer: NO_PEER,
                command: "ping",
                inbound: Some(false),
                timestamp: 0,
            },
            Turn {
                peer: 0,
                command: "inbound",
                inbound: None,
                timestamp: 1,
            },
            Turn {
                peer: NO_PEER,
                command: "pong",
                inbound: Some(true),
                timestamp: 2,
            },
        ];
        assert!(match_turns(&rows).is_empty());
    }
}
