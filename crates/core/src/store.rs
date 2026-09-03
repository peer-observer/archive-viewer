//! Columnar retention of individual events, under a memory budget.
//!
//! Aggregates are computed over every event in an archive, but the raw event
//! table and the JSON inspector need the events themselves. Archives rotate at
//! 1 GiB *compressed* — roughly 8 GiB and ~90M events decompressed — which no
//! browser tab can hold, so retention stops at a budget while aggregation runs
//! on to the end of the file. The UI then says the raw table covers the first
//! *N* of *M* events rather than silently showing a partial picture.

/// Fixed per-event cost of the columns below. Used for budget accounting.
const BYTES_PER_EVENT: u64 = 8 + 2 + 4 + 1 + 4 + 8 + 4;

/// Marks an event that is not attributed to a peer.
pub const NO_PEER: u32 = u32::MAX;

/// Bit flags in the `flags` column.
pub mod flags {
    /// The event is an inbound P2P message.
    pub const INBOUND: u8 = 1 << 0;
    /// The event's direction is meaningful (i.e. it is a P2P message at all).
    pub const HAS_DIRECTION: u8 = 1 << 1;
}

/// One retained event, as returned to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventRow {
    pub index: u32,
    pub timestamp: u64,
    pub kind: u16,
    /// Dense peer index, or [`NO_PEER`].
    pub peer: u32,
    pub flags: u8,
    /// Wire size of the P2P message, where applicable.
    pub size: u32,
}

impl EventRow {
    pub fn inbound(&self) -> Option<bool> {
        (self.flags & flags::HAS_DIRECTION != 0).then_some(self.flags & flags::INBOUND != 0)
    }
}

/// Columnar event store with a byte budget.
#[derive(Debug)]
pub struct EventStore {
    timestamp: Vec<u64>,
    kind: Vec<u16>,
    peer: Vec<u32>,
    flags: Vec<u8>,
    size: Vec<u32>,
    /// Offset and length of each event's encoded bytes within `raw`.
    offset: Vec<u64>,
    length: Vec<u32>,
    raw: Vec<u8>,
    budget_bytes: u64,
    full: bool,
}

impl EventStore {
    pub fn new(budget_bytes: u64) -> Self {
        EventStore {
            timestamp: Vec::new(),
            kind: Vec::new(),
            peer: Vec::new(),
            flags: Vec::new(),
            size: Vec::new(),
            offset: Vec::new(),
            length: Vec::new(),
            raw: Vec::new(),
            budget_bytes,
            full: false,
        }
    }

    /// Number of retained events.
    pub fn len(&self) -> usize {
        self.timestamp.len()
    }

    pub fn is_empty(&self) -> bool {
        self.timestamp.is_empty()
    }

    /// Whether the budget has been reached and retention has stopped.
    pub fn is_full(&self) -> bool {
        self.full
    }

    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    /// Approximate bytes held.
    pub fn bytes_used(&self) -> u64 {
        self.raw.len() as u64 + self.len() as u64 * BYTES_PER_EVENT
    }

    /// Retain one event. Returns false once the budget is spent, after which the
    /// caller should keep aggregating but stop expecting retention.
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        timestamp: u64,
        kind: u16,
        peer: u32,
        flags: u8,
        size: u32,
        bytes: &[u8],
    ) -> bool {
        if self.full {
            return false;
        }
        if self.bytes_used() + bytes.len() as u64 + BYTES_PER_EVENT > self.budget_bytes {
            self.full = true;
            // Give back the capacity we over-reserved while growing.
            self.raw.shrink_to_fit();
            return false;
        }
        self.offset.push(self.raw.len() as u64);
        self.length.push(bytes.len() as u32);
        self.raw.extend_from_slice(bytes);
        self.timestamp.push(timestamp);
        self.kind.push(kind);
        self.peer.push(peer);
        self.flags.push(flags);
        self.size.push(size);
        true
    }

    pub fn row(&self, index: u32) -> Option<EventRow> {
        let i = index as usize;
        Some(EventRow {
            index,
            timestamp: *self.timestamp.get(i)?,
            kind: self.kind[i],
            peer: self.peer[i],
            flags: self.flags[i],
            size: self.size[i],
        })
    }

    /// The encoded protobuf bytes of a retained event.
    pub fn bytes(&self, index: u32) -> Option<&[u8]> {
        let i = index as usize;
        let offset = *self.offset.get(i)? as usize;
        let length = self.length[i] as usize;
        self.raw.get(offset..offset + length)
    }

    /// Columns, for filtering without building an [`EventRow`] per event.
    pub fn timestamps(&self) -> &[u64] {
        &self.timestamp
    }

    pub fn kinds(&self) -> &[u16] {
        &self.kind
    }

    pub fn peers(&self) -> &[u32] {
        &self.peer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_and_reads_back_events() {
        let mut store = EventStore::new(1 << 20);
        assert!(store.push(100, 1, 5, flags::HAS_DIRECTION | flags::INBOUND, 42, b"abc"));
        assert!(store.push(200, 2, NO_PEER, 0, 0, b"defgh"));

        assert_eq!(store.len(), 2);
        let row = store.row(0).unwrap();
        assert_eq!(
            (row.timestamp, row.kind, row.peer, row.size),
            (100, 1, 5, 42)
        );
        assert_eq!(row.inbound(), Some(true));
        assert_eq!(store.bytes(0), Some(&b"abc"[..]));
        assert_eq!(store.bytes(1), Some(&b"defgh"[..]));

        assert_eq!(
            store.row(1).unwrap().inbound(),
            None,
            "no direction for non-messages"
        );
        assert!(store.row(2).is_none());
        assert!(store.bytes(2).is_none());
    }

    /// Once the budget is spent retention stops, but what was already retained
    /// stays readable and correct.
    #[test]
    fn stops_retaining_at_the_budget() {
        let budget = 1024;
        let mut store = EventStore::new(budget);
        let payload = [0u8; 64];

        let mut retained = 0;
        for i in 0..100u64 {
            if store.push(i, 0, NO_PEER, 0, 0, &payload) {
                retained += 1;
            }
        }

        assert!(store.is_full());
        assert!(retained > 0, "some events fit");
        assert!(retained < 100, "not all events fit");
        assert_eq!(store.len(), retained);
        assert!(store.bytes_used() <= budget);
        // Everything retained is still intact.
        for i in 0..retained as u32 {
            assert_eq!(store.bytes(i), Some(&payload[..]));
        }
    }

    /// A budget too small for even one event must not panic or retain garbage.
    #[test]
    fn a_budget_of_zero_retains_nothing() {
        let mut store = EventStore::new(0);
        assert!(!store.push(1, 0, NO_PEER, 0, 0, b"x"));
        assert!(store.is_empty());
        assert!(store.is_full());
    }
}
