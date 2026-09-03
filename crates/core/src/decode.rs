//! Push-based streaming decoder for peer-observer archive files.
//!
//! The browser hands us bytes as `ReadableStream` chunks, so this is driven by
//! [`RecordDecoder::push`] rather than by a `Read`. Each call decompresses what
//! it can, splits complete varint-length-delimited records out of the result and
//! hands them to a [`RecordSink`]; anything incomplete is carried over to the
//! next chunk.
//!
//! Truncation is a normal outcome, not an error: an archive that is still being
//! written ends mid-frame, and every record before the cut is perfectly good.

use ruzstd::decoding::FrameDecoder;

/// zstd frame magic (`28 b5 2f fd`).
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Refuse absurd record lengths rather than trying to allocate for them. The
/// largest record seen in practice is a block message at ~47 KB; this leaves
/// room for a maximum-size block and then some.
const MAX_RECORD_LEN: u64 = 64 * 1024 * 1024;

/// A zstd block can be up to 128 KiB and `decode_from_to` cannot make progress
/// without a whole one, so buffer at least that much (plus block and frame
/// header slack) before asking it to decode.
const MIN_DECODE_INPUT: usize = 128 * 1024 + 3 + 18;

/// Scratch buffer for draining decompressed bytes out of the zstd decoder.
const DECOMPRESS_CHUNK: usize = 256 * 1024;

/// Compact the scan buffer once this many consumed bytes have accumulated.
const COMPACT_THRESHOLD: usize = 1024 * 1024;

/// peer-observer archives are written by `zstd::Encoder::new`, which for higher
/// levels declares a 128 MiB window — above ruzstd's 100 MB default, which would
/// otherwise reject the file outright. Allow up to 512 MiB (windowLog 29).
/// Nothing is allocated up front; the decoder's ring buffer grows only as far as
/// the data actually produced.
const MAX_WINDOW_SIZE: u64 = 512 * 1024 * 1024;

/// Whether an archive's bytes are zstd-compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Zstd,
}

/// How a stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Completion {
    /// The stream ended mid-record or mid-frame. Expected for an archive that is
    /// still being written; every record reported before this point is valid.
    pub truncated: bool,
    /// Decompressed bytes left over that did not form a complete record.
    pub trailing_bytes: usize,
    /// The zstd frame had no terminating block (the writer never called
    /// `finish()`, e.g. because it is still running or was killed).
    pub incomplete_frame: bool,
}

/// Fatal decoding problems. Truncation is deliberately *not* one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The zstd stream itself is malformed.
    Zstd(String),
    /// A record length prefix was not a valid varint.
    MalformedVarint,
    /// A record claimed an implausible length, so the stream is not what we think.
    RecordTooLarge { len: u64 },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Zstd(msg) => write!(f, "zstd decoding failed: {msg}"),
            DecodeError::MalformedVarint => {
                write!(
                    f,
                    "malformed record length prefix; this is not a peer-observer archive"
                )
            }
            DecodeError::RecordTooLarge { len } => write!(
                f,
                "record claims to be {len} bytes, above the {MAX_RECORD_LEN} byte limit; \
                 this is probably not a peer-observer archive"
            ),
        }
    }
}

/// Receives each complete length-delimited record, in file order.
pub trait RecordSink {
    /// `index` is 0 for the `ArchiveHeader` and 1.. for `Event`s.
    fn record(&mut self, index: u64, bytes: &[u8]);
}

impl<F: FnMut(u64, &[u8])> RecordSink for F {
    fn record(&mut self, index: u64, bytes: &[u8]) {
        self(index, bytes)
    }
}

/// Streaming archive decoder. Feed it [`push`](Self::push), then
/// [`finish`](Self::finish).
pub struct RecordDecoder {
    compression: Option<Compression>,
    hint: Option<Compression>,
    zstd: Option<Box<FrameDecoder>>,
    /// Compressed bytes received but not yet consumed by the zstd decoder.
    cin: Vec<u8>,
    /// Decompressed bytes not yet split into complete records.
    out: Vec<u8>,
    /// How much of `out` has already been consumed.
    out_pos: usize,
    scratch: Vec<u8>,
    bytes_in: u64,
    bytes_out: u64,
    records: u64,
}

impl RecordDecoder {
    /// `hint` is used only when the stream is too short to sniff the zstd magic;
    /// pass what the file extension suggests, or `None`.
    pub fn new(hint: Option<Compression>) -> Self {
        RecordDecoder {
            compression: None,
            hint,
            zstd: None,
            cin: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            scratch: vec![0u8; DECOMPRESS_CHUNK],
            bytes_in: 0,
            bytes_out: 0,
            records: 0,
        }
    }

    /// Compressed (on-disk) bytes consumed so far.
    pub fn compressed_bytes(&self) -> u64 {
        self.bytes_in
    }

    /// Decompressed bytes produced so far.
    pub fn decompressed_bytes(&self) -> u64 {
        self.bytes_out
    }

    /// Records emitted so far, including the header record.
    pub fn records(&self) -> u64 {
        self.records
    }

    /// Detected compression, once enough bytes have arrived to tell.
    pub fn compression(&self) -> Option<Compression> {
        self.compression
    }

    /// Feed the next chunk of file bytes.
    pub fn push<S: RecordSink>(&mut self, chunk: &[u8], sink: &mut S) -> Result<(), DecodeError> {
        self.bytes_in += chunk.len() as u64;
        self.cin.extend_from_slice(chunk);
        self.pump(false, sink)
    }

    /// Signal end of file and report how the stream ended.
    pub fn finish<S: RecordSink>(&mut self, sink: &mut S) -> Result<Completion, DecodeError> {
        self.pump(true, sink)?;

        // Capture this *before* the terminator below makes the frame look finished.
        let incomplete_frame = match (self.compression, &self.zstd) {
            (Some(Compression::Zstd), Some(fd)) => !fd.is_finished(),
            // Compressed, but we never got enough bytes to start a frame at all.
            (Some(Compression::Zstd), None) => self.bytes_in > 0,
            _ => false,
        };

        if incomplete_frame && self.zstd.is_some() {
            self.flush_truncated_frame()?;
            self.scan(sink)?;
        }

        let trailing_bytes = self.out.len() - self.out_pos;
        Ok(Completion {
            truncated: incomplete_frame || trailing_bytes > 0,
            trailing_bytes,
            incomplete_frame,
        })
    }

    /// Recover the tail of a frame that has no terminating block.
    ///
    /// ruzstd retains `window_size` decompressed bytes for back-references and
    /// only releases them once the frame's last block arrives. A peer-observer
    /// archive declares a 128 MiB window, so for an archive that is still being
    /// written — the normal case for a live archive — that withholds *every*
    /// byte we decoded.
    ///
    /// The fix is to hand the decoder a synthetic final block. Any bytes left
    /// unconsumed in `cin` are a partial block, which zstd cannot decode even in
    /// principle, so they are dropped; that leaves the decoder exactly at a block
    /// boundary, where a raw, empty, last-block header (`01 00 00`) is valid. It
    /// adds no output of its own and simply flips the frame to finished, after
    /// which `read` drains everything.
    fn flush_truncated_frame(&mut self) -> Result<(), DecodeError> {
        const EMPTY_LAST_BLOCK: [u8; 3] = [0x01, 0x00, 0x00];
        self.cin.clear();
        self.cin.extend_from_slice(&EMPTY_LAST_BLOCK);
        self.decompress(true)
    }

    fn pump<S: RecordSink>(&mut self, finishing: bool, sink: &mut S) -> Result<(), DecodeError> {
        self.detect_compression(finishing);

        match self.compression {
            None => return Ok(()), // still sniffing
            Some(Compression::None) => {
                let n = self.cin.len();
                self.out.append(&mut self.cin);
                self.bytes_out += n as u64;
            }
            Some(Compression::Zstd) => self.decompress(finishing)?,
        }

        self.scan(sink)
    }

    fn detect_compression(&mut self, finishing: bool) {
        if self.compression.is_some() {
            return;
        }
        if self.cin.len() >= ZSTD_MAGIC.len() {
            // Sniff the magic rather than trusting the file extension, so a
            // renamed or extensionless archive still works.
            self.compression = Some(if self.cin[..ZSTD_MAGIC.len()] == ZSTD_MAGIC {
                Compression::Zstd
            } else {
                Compression::None
            });
        } else if finishing {
            self.compression = Some(self.hint.unwrap_or(Compression::None));
        }
    }

    fn decompress(&mut self, finishing: bool) -> Result<(), DecodeError> {
        // Without a full block there is nothing to gain from calling in, and the
        // frame header needs to be complete before the decoder can be started.
        if !finishing && self.cin.len() < MIN_DECODE_INPUT {
            return Ok(());
        }
        if self.zstd.is_none() {
            if self.cin.len() < 18 {
                return Ok(()); // not even a frame header yet; treated as truncation
            }
            let mut fd = Box::new(FrameDecoder::new());
            fd.set_max_window_size(MAX_WINDOW_SIZE);
            self.zstd = Some(fd);
        }
        let fd = self.zstd.as_mut().expect("just set");

        let mut consumed = 0usize;
        loop {
            let (read, written) = fd
                .decode_from_to(&self.cin[consumed..], &mut self.scratch)
                .map_err(|e| DecodeError::Zstd(e.to_string()))?;
            // Clamp: ruzstd reports 4 consumed bytes for a trailing content checksum
            // even when fewer than 4 are present.
            consumed = (consumed + read).min(self.cin.len());
            if written > 0 {
                self.out.extend_from_slice(&self.scratch[..written]);
                self.bytes_out += written as u64;
            }
            if read == 0 && written == 0 {
                break;
            }
        }
        self.cin.drain(..consumed);
        Ok(())
    }

    fn scan<S: RecordSink>(&mut self, sink: &mut S) -> Result<(), DecodeError> {
        loop {
            let rest = &self.out[self.out_pos..];
            let (len, varint_len) = match read_varint(rest) {
                Varint::Value(len, n) => (len, n),
                Varint::Incomplete => break,
                Varint::Invalid => return Err(DecodeError::MalformedVarint),
            };
            if len > MAX_RECORD_LEN {
                return Err(DecodeError::RecordTooLarge { len });
            }
            let start = varint_len;
            let end = start + len as usize;
            if rest.len() < end {
                break; // record not fully arrived yet
            }
            sink.record(self.records, &rest[start..end]);
            self.records += 1;
            self.out_pos += end;
        }

        if self.out_pos >= COMPACT_THRESHOLD {
            self.out.drain(..self.out_pos);
            self.out_pos = 0;
        }
        Ok(())
    }
}

enum Varint {
    Value(u64, usize),
    Incomplete,
    Invalid,
}

/// Reads a protobuf base-128 varint. This is the same framing prost's
/// `encode_length_delimited` writes: a bare length, with no field tag.
fn read_varint(buf: &[u8]) -> Varint {
    let mut value: u64 = 0;
    for (i, &byte) in buf.iter().take(10).enumerate() {
        // The 10th byte may only carry the single remaining bit of a u64.
        if i == 9 && byte > 1 {
            return Varint::Invalid;
        }
        value |= u64::from(byte & 0x7F) << (7 * i);
        if byte & 0x80 == 0 {
            return Varint::Value(value, i + 1);
        }
    }
    if buf.len() >= 10 {
        Varint::Invalid
    } else {
        Varint::Incomplete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for value in [0u64, 1, 127, 128, 300, 47_092, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            prost::encoding::encode_varint(value, &mut buf);
            match read_varint(&buf) {
                Varint::Value(got, n) => {
                    assert_eq!(got, value);
                    assert_eq!(n, buf.len());
                }
                _ => panic!("failed to read varint for {value}"),
            }
        }
    }

    #[test]
    fn varint_incomplete_is_not_an_error() {
        // 300 encodes as two bytes; the first alone must read as incomplete.
        assert!(matches!(read_varint(&[0xAC]), Varint::Incomplete));
        assert!(matches!(read_varint(&[]), Varint::Incomplete));
    }

    #[test]
    fn varint_overlong_is_invalid() {
        assert!(matches!(read_varint(&[0xFF; 11]), Varint::Invalid));
    }
}
