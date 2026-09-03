//! Ties decoding, classification, aggregation and retention together.
//!
//! One [`Analysis`] spans a whole session: several rotated archive files can be
//! fed into it in order and are reported as one continuous archive.

use crate::decode::{Completion, Compression, DecodeError, RecordDecoder, RecordSink};
use crate::histogram::Histogram;
use crate::kind::{classify, Group, KindTable};
use crate::peers::PeerTable;
use crate::proto::{
    ebpf_extractor::ebpf::EbpfEvent, event::event::PeerObserverEvent, event::Event,
    header::ArchiveHeader,
};
use crate::store::{flags, EventStore, NO_PEER};
use crate::strip::strip_raw_payloads;
use prost::Message;

/// What we know about one archive file in the session.
#[derive(Debug, Clone, Default)]
pub struct FileSummary {
    pub name: String,
    /// Size reported by the caller, if known.
    pub declared_bytes: u64,
    pub compressed_bytes: u64,
    pub decompressed_bytes: u64,
    /// `ArchiveHeader.created`, seconds since the epoch.
    pub created: Option<u64>,
    /// `ArchiveHeader.low_data`. Unset in archives written before the field existed.
    pub low_data: Option<bool>,
    pub events: u64,
    pub decode_errors: u64,
    pub compression: Option<&'static str>,
    pub truncated: bool,
    pub incomplete_frame: bool,
    pub trailing_bytes: usize,
    /// Set if the file failed outright, e.g. it is not an archive at all.
    pub error: Option<String>,
}

/// Everything accumulated across the session.
#[derive(Debug)]
pub struct Analysis {
    pub kinds: KindTable,
    /// Event counts indexed by kind id.
    pub counts: Vec<u64>,
    pub histogram: Histogram,
    pub peers: PeerTable,
    pub store: EventStore,
    pub files: Vec<FileSummary>,
    pub total_events: u64,
    pub decode_errors: u64,
    /// Events whose raw transaction or block data was dropped before retention.
    pub stripped_events: u64,
    /// Bytes of raw transaction and block data dropped before retention.
    pub stripped_bytes: u64,
    pub first_timestamp: Option<u64>,
    pub last_timestamp: Option<u64>,
    decoder: Option<RecordDecoder>,
    current_file: Option<usize>,
}

impl Analysis {
    pub fn new(budget_bytes: u64) -> Self {
        Analysis {
            kinds: KindTable::new(),
            counts: Vec::new(),
            histogram: Histogram::new(),
            peers: PeerTable::new(),
            store: EventStore::new(budget_bytes),
            files: Vec::new(),
            total_events: 0,
            decode_errors: 0,
            stripped_events: 0,
            stripped_bytes: 0,
            first_timestamp: None,
            last_timestamp: None,
            decoder: None,
            current_file: None,
        }
    }

    /// Start a new file. Any file already open is finished first.
    pub fn begin_file(&mut self, name: String, declared_bytes: u64) {
        if self.decoder.is_some() {
            let _ = self.end_file();
        }
        let hint = name.ends_with(".zst").then_some(Compression::Zstd);
        self.files.push(FileSummary {
            name,
            declared_bytes,
            ..Default::default()
        });
        self.current_file = Some(self.files.len() - 1);
        self.decoder = Some(RecordDecoder::new(hint));
    }

    /// Feed the next chunk of the current file.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), DecodeError> {
        let Some(mut decoder) = self.decoder.take() else {
            return Ok(());
        };
        let file = self.current_file.unwrap_or(0);
        let result = {
            let mut sink = Ingest {
                analysis: self,
                file,
            };
            decoder.push(chunk, &mut sink)
        };
        self.record_progress(&decoder, file);
        self.decoder = Some(decoder);
        if let Err(error) = &result {
            self.fail_current_file(error);
        }
        result
    }

    /// Finish the current file and report how its stream ended.
    pub fn end_file(&mut self) -> Option<Completion> {
        let mut decoder = self.decoder.take()?;
        let file = self.current_file.take().unwrap_or(0);
        let result = {
            let mut sink = Ingest {
                analysis: self,
                file,
            };
            decoder.finish(&mut sink)
        };
        self.record_progress(&decoder, file);

        match result {
            Ok(completion) => {
                if let Some(summary) = self.files.get_mut(file) {
                    summary.truncated = completion.truncated;
                    summary.incomplete_frame = completion.incomplete_frame;
                    summary.trailing_bytes = completion.trailing_bytes;
                }
                Some(completion)
            }
            Err(error) => {
                self.fail_current_file(&error);
                None
            }
        }
    }

    /// Whether any file in the session ended mid-stream.
    pub fn truncated(&self) -> bool {
        self.files.iter().any(|f| f.truncated)
    }

    /// Time span covered by the archive, in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        match (self.first_timestamp, self.last_timestamp) {
            (Some(first), Some(last)) => last.saturating_sub(first),
            _ => 0,
        }
    }

    fn record_progress(&mut self, decoder: &RecordDecoder, file: usize) {
        if let Some(summary) = self.files.get_mut(file) {
            summary.compressed_bytes = decoder.compressed_bytes();
            summary.decompressed_bytes = decoder.decompressed_bytes();
            summary.compression = decoder.compression().map(|c| match c {
                Compression::Zstd => "zstd",
                Compression::None => "none",
            });
        }
    }

    fn fail_current_file(&mut self, error: &DecodeError) {
        let file = self
            .current_file
            .unwrap_or(self.files.len().saturating_sub(1));
        if let Some(summary) = self.files.get_mut(file) {
            summary.error = Some(error.to_string());
        }
        // The stream cannot be resynchronised, so stop reading this file.
        self.decoder = None;
        self.current_file = None;
    }

    fn count_kind(&mut self, kind: u16) {
        let index = kind as usize;
        if self.counts.len() <= index {
            self.counts.resize(index + 1, 0);
        }
        self.counts[index] += 1;
    }
}

/// Borrows the aggregate state while the decoder emits records.
struct Ingest<'a> {
    analysis: &'a mut Analysis,
    file: usize,
}

impl RecordSink for Ingest<'_> {
    fn record(&mut self, index: u64, bytes: &[u8]) {
        // Record 0 of every file is the archive header, not an event.
        if index == 0 {
            match ArchiveHeader::decode(bytes) {
                Ok(header) => {
                    if let Some(summary) = self.analysis.files.get_mut(self.file) {
                        summary.created = Some(header.created);
                        summary.low_data = header.low_data;
                    }
                }
                Err(_) => self.note_decode_error(),
            }
            return;
        }

        let Ok(mut event) = Event::decode(bytes) else {
            // One unreadable record must not abandon the rest of the archive.
            self.note_decode_error();
            return;
        };
        self.ingest_event(&mut event, bytes);
    }
}

impl Ingest<'_> {
    fn note_decode_error(&mut self) {
        self.analysis.decode_errors += 1;
        if let Some(summary) = self.analysis.files.get_mut(self.file) {
            summary.decode_errors += 1;
        }
    }

    fn ingest_event(&mut self, event: &mut Event, bytes: &[u8]) {
        let timestamp = event.timestamp;
        let (group, name) = classify(event);
        let kind = self.analysis.kinds.intern(group, name);

        let analysis = &mut *self.analysis;
        analysis.total_events += 1;
        if let Some(summary) = analysis.files.get_mut(self.file) {
            summary.events += 1;
        }
        analysis.count_kind(kind);
        analysis.histogram.add(timestamp, kind);
        analysis.first_timestamp = Some(
            analysis
                .first_timestamp
                .map_or(timestamp, |t| t.min(timestamp)),
        );
        analysis.last_timestamp = Some(
            analysis
                .last_timestamp
                .map_or(timestamp, |t| t.max(timestamp)),
        );

        let (peer, event_flags, size) = self.attribute_to_peer(event, timestamp, kind);

        // Retain a copy without raw transaction and block data. Those bytes are
        // most of a full-data archive and nothing here reads them, so keeping
        // them would spend the retention budget -- and the browser's memory --
        // on payloads no view displays. Everything above saw the whole event.
        let dropped = strip_raw_payloads(event);
        let analysis = &mut *self.analysis;
        if dropped > 0 {
            analysis.stripped_events += 1;
            analysis.stripped_bytes += dropped as u64;
            let stripped = event.encode_to_vec();
            analysis
                .store
                .push(timestamp, kind, peer, event_flags, size, &stripped);
        } else {
            analysis
                .store
                .push(timestamp, kind, peer, event_flags, size, bytes);
        }
    }

    /// Update the peer table and return the columns describing this event's peer.
    fn attribute_to_peer(&mut self, event: &Event, timestamp: u64, kind: u16) -> (u32, u8, u32) {
        let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &event.peer_observer_event else {
            return (NO_PEER, 0, 0);
        };
        let peers = &mut self.analysis.peers;
        match &ebpf.ebpf_event {
            Some(EbpfEvent::Message(message)) => {
                peers.record_message(timestamp, message, kind);
                let meta = &message.meta;
                let mut event_flags = flags::HAS_DIRECTION;
                if meta.inbound {
                    event_flags |= flags::INBOUND;
                }
                let index = peers.get(meta.peer_id).map_or(NO_PEER, |p| p.index);
                (index, event_flags, meta.size.min(u32::MAX as u64) as u32)
            }
            Some(EbpfEvent::Connection(connection)) => {
                peers.record_connection(timestamp, connection);
                let peer_id = connection_peer_id(connection);
                let index = peer_id
                    .and_then(|id| peers.get(id))
                    .map_or(NO_PEER, |p| p.index);
                (index, 0, 0)
            }
            // Mempool and validation events carry no peer.
            _ => (NO_PEER, 0, 0),
        }
    }
}

fn connection_peer_id(
    event: &crate::proto::ebpf_extractor::connection::ConnectionEvent,
) -> Option<u64> {
    use crate::proto::ebpf_extractor::connection::connection_event::Event as C;
    Some(match event.event.as_ref()? {
        C::Closed(c) => c.conn.peer_id,
        C::InboundEvicted(c) => c.conn.peer_id,
        C::Inbound(c) => c.conn.peer_id,
        C::Outbound(c) => c.conn.peer_id,
        // Carries a bare peer id rather than a Connection.
        C::Misbehaving(m) => m.id,
    })
}

/// Group of a kind id, for callers that only have the id.
pub fn group_of(kinds: &KindTable, kind: u16) -> Option<Group> {
    kinds.get(kind).map(|k| k.group)
}
