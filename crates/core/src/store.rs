//! Columnar retention of individual events, under a memory budget.
//!
//! Aggregates are computed over every event in an archive, but the raw event
//! table and the JSON inspector need the events themselves. Archives rotate at
//! 1 GiB *compressed* — roughly 8 GiB and ~90M events decompressed — which no
//! browser tab can hold, so retention stops at a budget while aggregation runs
//! on to the end of the file. The UI then says the raw table covers the first
//! *N* of *M* events rather than silently showing a partial picture.
//!
//! Two rules keep this from taking the whole module down on wasm32, where the
//! address space is 4 GiB and browsers in practice allow rather less:
//!
//! * Event bytes go into fixed-size chunks, never one growing buffer. A single
//!   `Vec` reaching a 1 GiB budget has to double through a ~1.5 GiB transient,
//!   which is enough to fail on its own.
//! * Every allocation is fallible. Running out of memory stops retention, the
//!   same as reaching the budget, instead of aborting the wasm module — which
//!   surfaces in the browser as `unreachable executed` followed by every later
//!   call failing with "recursive use of an object".

/// Fixed per-event cost of the columns below. Used for budget accounting.
const BYTES_PER_EVENT: u64 = 8 + 2 + 4 + 1 + 4 + 4 + 4 + 4;

/// Size of one raw-bytes chunk. Small enough to allocate reliably, large enough
/// that the per-chunk overhead is irrelevant.
const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// How many events' worth of column capacity to reserve at a time.
const COLUMN_GROWTH: usize = 64 * 1024;

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

/// Why retention stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoppedBecause {
    /// The configured budget was reached.
    Budget,
    /// An allocation failed first. On wasm32 this is the browser's memory cap.
    OutOfMemory,
}

/// Columnar event store with a byte budget.
#[derive(Debug)]
pub struct EventStore {
    timestamp: Vec<u64>,
    kind: Vec<u16>,
    peer: Vec<u32>,
    flags: Vec<u8>,
    size: Vec<u32>,
    /// Which chunk each event's bytes live in, and where.
    chunk: Vec<u32>,
    offset: Vec<u32>,
    length: Vec<u32>,
    chunks: Vec<Vec<u8>>,
    chunk_bytes: u64,
    budget_bytes: u64,
    stopped: Option<StoppedBecause>,
}

impl EventStore {
    pub fn new(budget_bytes: u64) -> Self {
        EventStore {
            timestamp: Vec::new(),
            kind: Vec::new(),
            peer: Vec::new(),
            flags: Vec::new(),
            size: Vec::new(),
            chunk: Vec::new(),
            offset: Vec::new(),
            length: Vec::new(),
            chunks: Vec::new(),
            chunk_bytes: 0,
            budget_bytes,
            stopped: None,
        }
    }

    /// Number of retained events.
    pub fn len(&self) -> usize {
        self.timestamp.len()
    }

    pub fn is_empty(&self) -> bool {
        self.timestamp.is_empty()
    }

    /// Whether retention has stopped.
    pub fn is_full(&self) -> bool {
        self.stopped.is_some()
    }

    pub fn stopped_because(&self) -> Option<StoppedBecause> {
        self.stopped
    }

    pub fn budget_bytes(&self) -> u64 {
        self.budget_bytes
    }

    /// Approximate bytes held.
    pub fn bytes_used(&self) -> u64 {
        self.chunk_bytes + self.len() as u64 * BYTES_PER_EVENT
    }

    /// Retain one event. Returns false once retention has stopped, after which
    /// the caller should keep aggregating but stop expecting retention.
    pub fn push(
        &mut self,
        timestamp: u64,
        kind: u16,
        peer: u32,
        flags: u8,
        size: u32,
        bytes: &[u8],
    ) -> bool {
        if self.stopped.is_some() {
            return false;
        }
        if self.bytes_used() + bytes.len() as u64 + BYTES_PER_EVENT > self.budget_bytes {
            self.stop(StoppedBecause::Budget);
            return false;
        }
        if !self.reserve_columns() || !self.reserve_chunk(bytes.len()) {
            self.stop(StoppedBecause::OutOfMemory);
            return false;
        }

        let chunk = self
            .chunks
            .last_mut()
            .expect("reserve_chunk left a usable chunk");
        let offset = chunk.len();
        chunk.extend_from_slice(bytes);
        self.chunk_bytes += bytes.len() as u64;

        self.chunk.push(self.chunks.len() as u32 - 1);
        self.offset.push(offset as u32);
        self.length.push(bytes.len() as u32);
        self.timestamp.push(timestamp);
        self.kind.push(kind);
        self.peer.push(peer);
        self.flags.push(flags);
        self.size.push(size);
        true
    }

    fn stop(&mut self, reason: StoppedBecause) {
        self.stopped = Some(reason);
        // Hand back capacity reserved ahead of the events that never arrived.
        self.timestamp.shrink_to_fit();
        self.kind.shrink_to_fit();
        self.peer.shrink_to_fit();
        self.flags.shrink_to_fit();
        self.size.shrink_to_fit();
        self.chunk.shrink_to_fit();
        self.offset.shrink_to_fit();
        self.length.shrink_to_fit();
        if let Some(last) = self.chunks.last_mut() {
            last.shrink_to_fit();
        }
    }

    /// Grow every column in step, fallibly.
    fn reserve_columns(&mut self) -> bool {
        if self.timestamp.len() < self.timestamp.capacity() {
            return true;
        }
        let n = COLUMN_GROWTH;
        self.timestamp.try_reserve(n).is_ok()
            && self.kind.try_reserve(n).is_ok()
            && self.peer.try_reserve(n).is_ok()
            && self.flags.try_reserve(n).is_ok()
            && self.size.try_reserve(n).is_ok()
            && self.chunk.try_reserve(n).is_ok()
            && self.offset.try_reserve(n).is_ok()
            && self.length.try_reserve(n).is_ok()
    }

    /// Ensure the last chunk has room for `needed` bytes, allocating a new one
    /// if not. An event larger than a chunk gets a chunk of its own.
    fn reserve_chunk(&mut self, needed: usize) -> bool {
        if let Some(last) = self.chunks.last() {
            if last.capacity() - last.len() >= needed {
                return true;
            }
        }
        let capacity = needed.max(CHUNK_BYTES);
        let mut chunk = Vec::new();
        if chunk.try_reserve_exact(capacity).is_err() {
            return false;
        }
        if self.chunks.try_reserve(1).is_err() {
            return false;
        }
        // The chunk being retired will take no more events; release its slack.
        if let Some(previous) = self.chunks.last_mut() {
            previous.shrink_to_fit();
        }
        self.chunks.push(chunk);
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
        let chunk = self.chunks.get(*self.chunk.get(i)? as usize)?;
        let offset = self.offset[i] as usize;
        chunk.get(offset..offset + self.length[i] as usize)
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

        assert_eq!(store.stopped_because(), Some(StoppedBecause::Budget));
        assert!(retained > 0, "some events fit");
        assert!(retained < 100, "not all events fit");
        assert_eq!(store.len(), retained);
        assert!(store.bytes_used() <= budget);
        for i in 0..retained as u32 {
            assert_eq!(store.bytes(i), Some(&payload[..]));
        }
    }

    /// Events must read back correctly across chunk boundaries, which is where
    /// the chunked layout could go wrong.
    #[test]
    fn events_span_many_chunks() {
        let mut store = EventStore::new(64 * 1024 * 1024);
        // Enough ~64 kB events to fill several 4 MiB chunks.
        let count = 300u32;
        for i in 0..count {
            let payload = vec![(i % 251) as u8; 64 * 1024];
            assert!(
                store.push(i as u64, 0, NO_PEER, 0, 0, &payload),
                "event {i}"
            );
        }

        assert!(store.chunks.len() > 4, "should have needed several chunks");
        assert_eq!(store.len(), count as usize);
        for i in 0..count {
            let bytes = store.bytes(i).expect("event retained");
            assert_eq!(bytes.len(), 64 * 1024);
            assert!(
                bytes.iter().all(|b| *b == (i % 251) as u8),
                "event {i} intact"
            );
        }
    }

    /// An event bigger than a chunk gets its own chunk rather than being refused.
    #[test]
    fn an_event_larger_than_a_chunk_still_fits() {
        let mut store = EventStore::new(64 * 1024 * 1024);
        let big = vec![0xAB; CHUNK_BYTES + 4096];
        assert!(store.push(1, 0, NO_PEER, 0, 0, &big));
        assert!(store.push(2, 0, NO_PEER, 0, 0, b"after"));

        assert_eq!(store.bytes(0).map(|b| b.len()), Some(CHUNK_BYTES + 4096));
        assert_eq!(store.bytes(1), Some(&b"after"[..]));
    }

    /// A budget too small for even one event must not panic or retain garbage.
    #[test]
    fn a_budget_of_zero_retains_nothing() {
        let mut store = EventStore::new(0);
        assert!(!store.push(1, 0, NO_PEER, 0, 0, b"x"));
        assert!(store.is_empty());
        assert!(store.is_full());
        assert_eq!(store.stopped_because(), Some(StoppedBecause::Budget));
    }

    /// The budget is honoured in chunk-sized steps, so a budget far larger than
    /// the data must never over-allocate up front.
    #[test]
    fn allocates_only_what_the_data_needs() {
        let mut store = EventStore::new(4 * 1024 * 1024 * 1024);
        store.push(1, 0, NO_PEER, 0, 0, b"tiny");

        assert_eq!(store.chunks.len(), 1);
        assert!(store.chunks[0].capacity() <= CHUNK_BYTES);
    }
}
