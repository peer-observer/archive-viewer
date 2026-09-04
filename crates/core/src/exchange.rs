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
use std::hash::Hash;

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
    /// What the message names on the wire -- inventory hashes, a txid and
    /// wtxid, a block hash, a ping nonce -- sorted, or empty for a command that
    /// names nothing and for a caller that has not decoded the payload. See
    /// [`crate::payload::carried`].
    pub keys: &'a [u64],
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
    /// Whether silence is a normal outcome. An announcement is not a request:
    /// we ask for a fraction of what is announced to us, so an `inv` with no
    /// `getdata` after it means we already had the transaction, not that the
    /// peer failed to answer.
    optional: bool,
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
        optional: false,
        window_ms: 2 * MINUTE,
    },
    // Core pings every two minutes and disconnects after twenty without a pong.
    Exchange {
        request: "ping",
        replies: &["pong"],
        multi: false,
        optional: false,
        window_ms: 20 * MINUTE,
    },
    // Core answers `getaddr` out of a cache on its next scheduled address send,
    // a Poisson timer averaging thirty seconds, and may split the answer across
    // several messages.
    Exchange {
        request: "getaddr",
        replies: &["addr", "addrv2"],
        multi: true,
        optional: false,
        window_ms: 3 * MINUTE,
    },
    // Announcement, then the request for what was announced. Core holds a
    // transaction request back by a couple of seconds and sends getdata on a
    // timer, so the gap is short; a long window here would only tie a getdata to
    // an announcement that had nothing to do with it.
    Exchange {
        request: "inv",
        replies: &["getdata"],
        multi: false,
        optional: true,
        window_ms: 30 * SECOND,
    },
    // ...and then the items themselves. Core's transaction request timeout is a
    // minute; a block download is given ten.
    Exchange {
        request: "getdata",
        replies: &["tx", "block", "merkleblock", "cmpctblock", "notfound"],
        multi: true,
        optional: false,
        window_ms: 10 * MINUTE,
    },
    Exchange {
        request: "getheaders",
        replies: &["headers"],
        multi: false,
        optional: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getblocks",
        replies: &["inv"],
        multi: false,
        optional: false,
        window_ms: 2 * MINUTE,
    },
    // BIP152: a compact block, the request for the transactions it was missing,
    // and those transactions.
    Exchange {
        request: "cmpctblock",
        replies: &["getblocktxn"],
        multi: false,
        optional: true,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getblocktxn",
        replies: &["blocktxn", "notfound"],
        multi: false,
        optional: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "mempool",
        replies: &["inv"],
        multi: true,
        optional: false,
        window_ms: 2 * MINUTE,
    },
    // BIP157 compact block filters. These are never sent unsolicited, so these
    // three ties are as good as certain.
    Exchange {
        request: "getcfilters",
        replies: &["cfilter"],
        multi: true,
        optional: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getcfheaders",
        replies: &["cfheaders"],
        multi: false,
        optional: false,
        window_ms: 2 * MINUTE,
    },
    Exchange {
        request: "getcfcheckpt",
        replies: &["cfcheckpt"],
        multi: false,
        optional: false,
        window_ms: 2 * MINUTE,
    },
];

/// A request still waiting for its reply.
#[derive(Debug, Clone, Copy)]
struct Open {
    position: usize,
    timestamp: u64,
    replies: u32,
}

/// A request that was retired without ever being answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unanswered {
    /// Index into [`EXCHANGES`]; name it with [`request_name`].
    pub exchange: usize,
    pub position: usize,
    /// How long it had been open when it was given up on.
    pub age_ms: u64,
    /// Which way the request went. Silence only reflects on the peer when the
    /// request went out from this node.
    pub request_inbound: bool,
}

/// A request that was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answered {
    /// Index into [`EXCHANGES`].
    pub exchange: usize,
    pub request: usize,
    pub elapsed_ms: u64,
}

/// What observing one message did to the set of open requests.
#[derive(Debug, Clone, Copy, Default)]
pub struct Observed {
    /// The request this message answered: which exchange, the position it was
    /// recorded at, and how long the answer took.
    pub answered: Option<Answered>,
    /// Whether that was the first reply the request had received. A `getdata`
    /// answered by thirty transactions is one request answered, not thirty.
    pub first_reply: bool,
    /// A request this message displaced before it was ever answered.
    pub displaced: Option<Unanswered>,
    /// The exchange this message opened a request for, if it opened one.
    pub opened: Option<usize>,
}

/// How many requests may be open at once before new ones are ignored.
///
/// A backstop, not a working limit: [`Tracker::sweep`] keeps the real number
/// down to whatever is genuinely in flight. It exists so that an archive that
/// somehow defeats the sweep costs bounded memory instead of the tab.
pub const MAX_OPEN: usize = 500_000;

/// Matches replies to requests as messages stream past.
///
/// Generic over the peer key so the same matching serves both callers: the
/// sequence diagram keys on the store's peer index, whole-archive accumulation
/// keys on Bitcoin Core's peer id.
#[derive(Debug)]
pub struct Tracker<K> {
    /// Peer, exchange, and the direction the *request* went. Direction is part
    /// of the key because both ends of a connection send `version` and `ping`,
    /// and those two conversations must not be confused for one another.
    open: HashMap<(K, usize, bool), Open>,
    dropped: u64,
}

impl<K> Default for Tracker<K> {
    fn default() -> Self {
        Tracker {
            open: HashMap::new(),
            dropped: 0,
        }
    }
}

impl<K: Copy + Eq + Hash> Tracker<K> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_requests(&self) -> usize {
        self.open.len()
    }

    /// Requests never tracked because [`MAX_OPEN`] was reached.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Feed one directed message, in archive order.
    ///
    /// `position` is whatever the caller wants to remember a request by -- a row
    /// number for the diagram, an event index for the archive.
    pub fn observe(
        &mut self,
        peer: K,
        command: &str,
        inbound: bool,
        timestamp: u64,
        position: usize,
    ) -> Observed {
        let mut result = Observed::default();

        // Match as a reply before registering as a request: `getdata` both
        // answers an `inv` and asks for a `tx`, and must not answer itself.
        let mut best: Option<((K, usize, bool), Open)> = None;
        for (index, exchange) in EXCHANGES.iter().enumerate() {
            if !exchange.replies.contains(&command) {
                continue;
            }
            let key = (peer, index, !inbound);
            let Some(request) = self.open.get(&key).copied() else {
                continue;
            };
            if timestamp.saturating_sub(request.timestamp) > exchange.window_ms {
                continue;
            }
            // Oldest first, so pipelined requests are answered in order.
            if best.is_none_or(|(_, other)| request.timestamp < other.timestamp) {
                best = Some((key, request));
            }
        }
        if let Some((key, request)) = best {
            result.answered = Some(Answered {
                exchange: key.1,
                request: request.position,
                elapsed_ms: timestamp.saturating_sub(request.timestamp),
            });
            if EXCHANGES[key.1].multi {
                if let Some(slot) = self.open.get_mut(&key) {
                    result.first_reply = slot.replies == 0;
                    slot.replies += 1;
                }
            } else {
                // A single-reply request is closed by its answer, so every
                // answer it gets is the first one.
                result.first_reply = true;
                self.open.remove(&key);
            }
        }

        if let Some(index) = EXCHANGES.iter().position(|e| e.request == command) {
            if self.open.len() < MAX_OPEN {
                result.opened = Some(index);
                let previous = self.open.insert(
                    (peer, index, inbound),
                    Open {
                        position,
                        timestamp,
                        replies: 0,
                    },
                );
                // Once a peer has sent a second `getdata`, the first one's items
                // are on the wire already; keeping it open would let it absorb
                // the second one's replies. This also bounds the map by the
                // number of conversations actually in flight.
                // Displacement only proves silence where Bitcoin Core does not
                // pipeline. A second `getdata` says nothing about the first: its
                // transactions may still be on the wire, and judging the first
                // one here would report a timeout that never happened. Those are
                // left to the sweep, which waits out the whole window.
                let judged = !EXCHANGES[index].optional && !EXCHANGES[index].multi;
                let unanswered = previous.filter(|p| p.replies == 0 && judged);
                if let Some(previous) = unanswered {
                    result.displaced = Some(Unanswered {
                        exchange: index,
                        position: previous.position,
                        age_ms: timestamp.saturating_sub(previous.timestamp),
                        request_inbound: inbound,
                    });
                }
            } else {
                self.dropped += 1;
            }
        }

        result
    }

    /// Retire every request whose window has passed, reporting the ones that
    /// were never answered.
    ///
    /// Requests still inside their window stay open: at the end of an archive
    /// they are simply in flight, and calling those unanswered would report a
    /// timeout that never happened.
    pub fn sweep(&mut self, now: u64, mut retired: impl FnMut(K, Unanswered)) {
        self.open.retain(|key, request| {
            let age = now.saturating_sub(request.timestamp);
            if age <= EXCHANGES[key.1].window_ms {
                return true;
            }
            if request.replies == 0 && !EXCHANGES[key.1].optional {
                retired(
                    key.0,
                    Unanswered {
                        exchange: key.1,
                        position: request.position,
                        age_ms: age,
                        request_inbound: key.2,
                    },
                );
            }
            false
        });
    }
}

/// The command that opens exchange `index`, for reporting.
pub fn request_name(index: usize) -> &'static str {
    EXCHANGES.get(index).map_or("", |e| e.request)
}

/// How many exchanges there are, for callers keeping a count per exchange.
pub fn exchange_count() -> usize {
    EXCHANGES.len()
}

/// How many requests of one kind are followed at once while pairing a window.
///
/// This is the locality the pairing works within. Bitcoin Core will keep up to
/// a hundred `getdata` in flight with one peer, but a request whose reply has
/// not arrived within thirty-two further requests of the same kind is one whose
/// reply is not in this window either, and holding it open only gives a later
/// reply something wrong to match against.
const LOCAL_OPEN: usize = 32;

/// A request waiting for its replies.
#[derive(Debug, Clone)]
struct Pending {
    position: usize,
    timestamp: u64,
    /// What it asked for, sorted, with each item removed as it is delivered. A
    /// request whose items have all arrived is finished and stops matching.
    wanted: Vec<u64>,
    /// Whether it named anything at all. A `getaddr` names nothing, and must
    /// not be mistaken for a request whose items have all been delivered.
    keyed: bool,
    replies: u32,
}

/// Tie up requests and replies in one window of the archive.
///
/// Turns must be in archive order. Only this window is considered, so an
/// exchange straddling the edge of the window is reported as neither a tie nor
/// an error -- it simply does not appear.
///
/// Where both sides name hashes, that is what pairs them: a `tx` answers the
/// `getdata` that asked for that transaction, not whichever `getdata` was most
/// recent, and a `pong` answers the `ping` whose nonce it carries. Bitcoin Core
/// keeps several requests of a kind in flight at once and answers them out of
/// order, so this is the difference between a diagram that is right and one
/// that is merely plausible. Where neither side names anything -- `version` and
/// `verack`, `getaddr` and `addr` -- the oldest unanswered request in the window
/// is still the answer, as it always was.
///
/// A reply that names something no open request asked for is left untied rather
/// than being attached to the nearest candidate. Its request is outside the
/// window, and saying so is more use than a wrong line.
pub fn match_turns(turns: &[Turn<'_>]) -> Vec<Tie> {
    // Peer, exchange, and the direction the request went, as in `Tracker`.
    let mut open: HashMap<(u32, usize, bool), Vec<Pending>> = HashMap::new();
    let mut ties = Vec::new();

    for (position, turn) in turns.iter().enumerate() {
        let (Some(inbound), true) = (turn.inbound, turn.peer != NO_PEER) else {
            continue;
        };

        // Match as a reply before registering as a request: `getdata` both
        // answers an `inv` and asks for a `tx`, and must not answer itself.
        let mut best: Option<(usize, usize, bool)> = None; // exchange, slot, by hash
        for (index, exchange) in EXCHANGES.iter().enumerate() {
            if !exchange.replies.contains(&turn.command) {
                continue;
            }
            let key = (turn.peer, index, !inbound);
            let Some(pending) = open.get(&key) else {
                continue;
            };
            for (slot, request) in pending.iter().enumerate() {
                if turn.timestamp.saturating_sub(request.timestamp) > exchange.window_ms {
                    continue;
                }
                let hashed = request.keyed
                    && !turn.keys.is_empty()
                    && turn
                        .keys
                        .iter()
                        .any(|k| request.wanted.binary_search(k).is_ok());
                // A request that named things and has none left is done; a
                // reply that names something is only an answer to a request
                // that asked for it.
                if !hashed && request.keyed && !turn.keys.is_empty() {
                    continue;
                }
                if !hashed && request.keyed && request.wanted.is_empty() {
                    continue;
                }
                // A hash match beats a guess; among equals, the oldest, so that
                // pipelined requests are answered in order.
                let better = match best {
                    None => true,
                    Some((other, other_slot, other_hashed)) => {
                        let other_at = open[&(turn.peer, other, !inbound)][other_slot].timestamp;
                        (hashed, std::cmp::Reverse(request.timestamp))
                            > (other_hashed, std::cmp::Reverse(other_at))
                    }
                };
                if better {
                    best = Some((index, slot, hashed));
                }
            }
        }

        if let Some((index, slot, hashed)) = best {
            let key = (turn.peer, index, !inbound);
            let list = open.get_mut(&key).expect("the slot was just found");
            let request = &mut list[slot];
            ties.push(Tie {
                request: request.position,
                reply: position,
                elapsed_ms: turn.timestamp.saturating_sub(request.timestamp),
            });
            request.replies += 1;
            if hashed {
                request.wanted.retain(|k| !turn.keys.contains(k));
            }
            // A single-reply exchange is closed by its answer; a request that
            // named things is closed when the last of them has come back.
            if !EXCHANGES[index].multi || (request.keyed && request.wanted.is_empty()) {
                list.remove(slot);
            }
        }

        if let Some(index) = EXCHANGES.iter().position(|e| e.request == turn.command) {
            let list = open.entry((turn.peer, index, inbound)).or_default();
            // The locality bound: past this many, the oldest is forgotten.
            if list.len() >= LOCAL_OPEN {
                list.remove(0);
            }
            list.push(Pending {
                position,
                timestamp: turn.timestamp,
                wanted: turn.keys.to_vec(),
                keyed: !turn.keys.is_empty(),
                replies: 0,
            });
        }
    }
    ties
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(peer, command, inbound, seconds)`, naming nothing on the wire: these
    /// exercise the pairing that has only order and timing to go on.
    fn turns(rows: &[(u32, &'static str, bool, u64)]) -> Vec<Turn<'static>> {
        rows.iter()
            .map(|(peer, command, inbound, at)| Turn {
                peer: *peer,
                command,
                inbound: Some(*inbound),
                timestamp: at * SECOND,
                keys: &[],
            })
            .collect()
    }

    /// The same, with each message's hashes: `(peer, command, inbound, seconds,
    /// keys)`. Keys must be sorted, as [`crate::payload::carried`] returns them.
    fn keyed(rows: &[(u32, &'static str, bool, u64, &'static [u64])]) -> Vec<Turn<'static>> {
        rows.iter()
            .map(|(peer, command, inbound, at, keys)| Turn {
                peer: *peer,
                command,
                inbound: Some(*inbound),
                timestamp: at * SECOND,
                keys,
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
    fn pipelined_requests_are_answered_oldest_first() {
        // Two `getdata` in flight and one transaction back, with nothing to
        // tell them apart: Bitcoin Core answers in order, so the first asked is
        // the first answered.
        let rows = turns(&[
            (0, "getdata", false, 0),
            (0, "getdata", false, 1),
            (0, "tx", true, 2),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 2)]);
    }

    #[test]
    fn a_reply_goes_to_the_request_that_asked_for_it() {
        // The same two `getdata`, now naming what they want. The transaction
        // answers the one that asked for it, not the one that came first.
        let rows = keyed(&[
            (0, "getdata", false, 0, &[0xaa]),
            (0, "getdata", false, 1, &[0xbb]),
            (0, "tx", true, 2, &[0xbb]),
            (0, "tx", true, 3, &[0xaa]),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(1, 2), (0, 3)]);
    }

    #[test]
    fn a_request_stops_matching_once_all_its_items_have_come_back() {
        // A `getdata` for two transactions is answered by two, and the third
        // belongs to a request outside this window.
        let rows = keyed(&[
            (0, "getdata", false, 0, &[0xaa, 0xbb]),
            (0, "tx", true, 1, &[0xaa]),
            (0, "tx", true, 2, &[0xbb]),
            (0, "tx", true, 3, &[0xcc]),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 1), (0, 2)]);
    }

    #[test]
    fn a_reply_naming_something_nobody_asked_for_is_left_untied() {
        // Better an untied row than a line drawn to the wrong request: this
        // transaction answers a `getdata` from before the window began.
        let rows = keyed(&[
            (0, "getdata", false, 0, &[0xaa]),
            (0, "tx", true, 1, &[0x99]),
        ]);
        assert!(match_turns(&rows).is_empty());
    }

    #[test]
    fn a_pong_answers_the_ping_whose_nonce_it_carries() {
        // The one exact identifier in the protocol. Two pings in flight and the
        // answers arriving in the other order is a case ordering gets wrong and
        // the nonce gets right.
        let rows = keyed(&[
            (0, "ping", false, 0, &[0x1111]),
            (0, "ping", false, 1, &[0x2222]),
            (0, "pong", true, 2, &[0x2222]),
            (0, "pong", true, 3, &[0x1111]),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(1, 2), (0, 3)]);
    }

    #[test]
    fn an_inv_is_answered_by_the_getdata_that_takes_it_up() {
        // A node asks for a fraction of what it is told about, and the hashes
        // say which fraction. The second `inv` is announced and never fetched.
        let rows = keyed(&[
            (0, "inv", true, 0, &[0xaa, 0xbb]),
            (0, "inv", true, 1, &[0xcc]),
            (0, "getdata", false, 2, &[0xbb]),
        ]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 2)]);
    }

    #[test]
    fn a_request_that_names_nothing_still_pairs_by_order() {
        // `getaddr` names nothing and `addrv2` answers nothing in particular,
        // so these are paired the only way they can be.
        let rows = keyed(&[(0, "getaddr", false, 0, &[]), (0, "addrv2", true, 1, &[])]);
        assert_eq!(pairs(&match_turns(&rows)), vec![(0, 1)]);
    }

    #[test]
    fn only_so_many_requests_are_followed_at_once() {
        // The locality bound. Past `LOCAL_OPEN` requests of a kind, the oldest
        // is forgotten rather than kept around for a reply that is not coming.
        let mut rows: Vec<(u32, &'static str, bool, u64, &'static [u64])> = Vec::new();
        for i in 0..LOCAL_OPEN as u64 + 1 {
            rows.push((0, "getdata", false, i, &[]));
        }
        rows.push((0, "tx", true, 100, &[]));
        let ties = match_turns(&keyed(&rows));
        // The first request is gone, so the second is the oldest still open.
        assert_eq!(pairs(&ties), vec![(1, LOCAL_OPEN + 1)]);
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
                keys: &[],
            },
            Turn {
                peer: 0,
                command: "inbound",
                inbound: None,
                timestamp: 1,
                keys: &[],
            },
            Turn {
                peer: NO_PEER,
                command: "pong",
                inbound: Some(true),
                timestamp: 2,
                keys: &[],
            },
        ];
        assert!(match_turns(&rows).is_empty());
    }
}

#[cfg(test)]
mod tracker_tests {
    use super::*;

    fn exchange_of(name: &str) -> usize {
        EXCHANGES.iter().position(|e| e.request == name).unwrap()
    }

    #[test]
    fn a_displaced_request_is_reported_as_unanswered() {
        // `ping`: Core has at most one outstanding, so a second one proves the
        // first went unanswered.
        let mut tracker: Tracker<u32> = Tracker::new();
        let first = tracker.observe(1, "ping", false, 0, 0);
        assert!(first.displaced.is_none(), "nothing to displace yet");

        let second = tracker.observe(1, "ping", false, 5_000, 1);
        let displaced = second.displaced.expect("the first ping was never answered");
        assert_eq!(displaced.exchange, exchange_of("ping"));
        assert_eq!(displaced.position, 0);
        assert_eq!(displaced.age_ms, 5_000);
    }

    #[test]
    fn a_request_that_got_replies_is_not_reported_when_displaced() {
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "getdata", false, 0, 0);
        assert!(tracker.observe(1, "tx", true, 10, 1).answered.is_some());
        // A second getdata replaces the first, which did get what it asked for.
        assert!(tracker
            .observe(1, "getdata", false, 20, 2)
            .displaced
            .is_none());
    }

    #[test]
    fn sweeping_retires_requests_past_their_window_and_leaves_the_rest() {
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "getheaders", false, 0, 0); // two-minute window
        tracker.observe(2, "ping", false, 0, 1); // twenty-minute window

        let mut retired = Vec::new();
        tracker.sweep(5 * 60 * 1_000, |peer, u| retired.push((peer, u)));
        assert_eq!(retired.len(), 1, "only the getheaders has timed out");
        assert_eq!(retired[0].0, 1, "charged to the peer that was asked");
        assert_eq!(retired[0].1.exchange, exchange_of("getheaders"));
        assert_eq!(retired[0].1.age_ms, 5 * 60 * 1_000);
        assert!(!retired[0].1.request_inbound, "we asked, the peer did not");
        assert_eq!(tracker.open_requests(), 1, "the ping is still in flight");

        // An in-flight request is not a timeout, so sweeping at its own time
        // reports nothing.
        tracker.sweep(0, |_, _| panic!("nothing should retire"));
        assert_eq!(tracker.open_requests(), 1);
    }

    #[test]
    fn an_answered_request_never_retires_as_unanswered() {
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "ping", false, 0, 0);
        tracker.observe(1, "pong", true, 30, 1);
        assert_eq!(tracker.open_requests(), 0, "answering closes it");
        tracker.sweep(u64::MAX / 2, |_, _| panic!("nothing should retire"));
    }

    #[test]
    fn a_multi_request_that_was_answered_is_not_a_timeout() {
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "getdata", false, 0, 0);
        tracker.observe(1, "tx", true, 5, 1);
        // It stays open to absorb more transactions, but it did get an answer.
        assert_eq!(tracker.open_requests(), 1);
        tracker.sweep(u64::MAX / 2, |_, _| panic!("nothing should retire"));
        assert_eq!(tracker.open_requests(), 0, "swept, just not reported");
    }

    #[test]
    fn tracking_stops_rather_than_growing_without_bound() {
        let mut tracker: Tracker<u32> = Tracker::new();
        for peer in 0..(MAX_OPEN as u32 + 10) {
            tracker.observe(peer, "ping", false, 0, peer as usize);
        }
        assert_eq!(tracker.open_requests(), MAX_OPEN);
        assert_eq!(tracker.dropped(), 10);
    }
}

#[cfg(test)]
mod optional_tests {
    use super::*;

    #[test]
    fn an_ignored_announcement_is_not_a_failed_request() {
        // We hear about a transaction and do not ask for it, because we already
        // have it. That is the normal case, not a peer failing to answer.
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "inv", true, 0, 0);
        assert!(
            tracker
                .observe(1, "inv", true, 1_000, 1)
                .displaced
                .is_none(),
            "a superseded inv is not an unanswered request"
        );
        tracker.sweep(u64::MAX / 2, |_, u| {
            panic!("an announcement should never retire as unanswered: {u:?}")
        });

        // ...but an inv that *is* acted on still ties to its getdata.
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "inv", true, 0, 0);
        assert!(tracker
            .observe(1, "getdata", false, 500, 1)
            .answered
            .is_some());
    }

    #[test]
    fn a_real_request_still_reports_its_silence() {
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "getdata", false, 0, 0);
        let mut retired = Vec::new();
        tracker.sweep(30 * 60 * 1_000, |peer, u| retired.push((peer, u)));
        assert_eq!(retired.len(), 1);
        assert!(!retired[0].1.request_inbound);
    }
}

#[cfg(test)]
mod pipelining_tests {
    use super::*;

    #[test]
    fn a_displaced_getdata_is_not_called_a_timeout() {
        // Core keeps getdata in flight; the transactions the first one asked for
        // may still be on the wire when the second goes out.
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "getdata", false, 0, 0);
        assert!(
            tracker
                .observe(1, "getdata", false, 500, 1)
                .displaced
                .is_none(),
            "too early to know; the sweep decides this one"
        );

        // The sweep still catches it once the window really has passed.
        let mut retired = Vec::new();
        tracker.sweep(30 * 60 * 1_000, |peer, u| retired.push((peer, u)));
        assert_eq!(retired.len(), 1, "the surviving getdata timed out");
    }

    #[test]
    fn a_displaced_ping_is_a_timeout_because_core_sends_one_at_a_time() {
        let mut tracker: Tracker<u32> = Tracker::new();
        tracker.observe(1, "ping", false, 0, 0);
        assert!(tracker
            .observe(1, "ping", false, 500, 1)
            .displaced
            .is_some());
    }
}

/// The commands that answer exchange `index`, for reporting.
pub fn reply_names(index: usize) -> &'static [&'static str] {
    EXCHANGES.get(index).map_or(&[], |e| e.replies)
}

/// Whether silence is a normal outcome for exchange `index`.
pub fn is_optional(index: usize) -> bool {
    EXCHANGES.get(index).is_some_and(|e| e.optional)
}
