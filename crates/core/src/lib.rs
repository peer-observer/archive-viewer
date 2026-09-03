//! Decoding and aggregation of [peer-observer](https://github.com/peer-observer/peer-observer)
//! archive files.
//!
//! An archive file is a single zstd stream (or, with `--compression-level 0`,
//! raw bytes) containing varint-length-delimited protobuf messages: one
//! `header.ArchiveHeader` followed by `event.Event`s to EOF. There is no frame
//! checksum, no declared uncompressed size and only one zstd frame per file, so
//! decoding is strictly front-to-back.
//!
//! Everything here is `no_std`-agnostic pure Rust and compiles for both native
//! and `wasm32-unknown-unknown`.

pub mod analysis;
pub mod asn;
pub mod decode;
pub mod exchange;
pub mod histogram;
pub mod inspect;
pub mod kind;
pub mod peers;
pub mod proto;
pub mod store;
pub mod strip;
pub mod view;
