//! Protobuf types generated from the pinned `peer-observer` submodule.
//!
//! The module tree mirrors the proto package names, which is also how
//! peer-observer's own `shared::protobuf` is laid out. Note prost's renames:
//! the `event.Event` oneof enum is [`event::PeerObserverEvent`], proto
//! `message ebpf` becomes `ebpf_extractor::Ebpf`, and `GetCFCheckpt` becomes
//! `GetCfCheckpt`.

// prost's generated code is not written to our lint standards. Keep these
// suppressions confined to this module rather than the whole crate.
#![allow(clippy::module_inception)]
#![allow(clippy::doc_lazy_continuation)]

macro_rules! include_proto {
    ($file:literal) => {
        include!(concat!(env!("OUT_DIR"), "/", $file, ".rs"));
    };
}

/// `event.proto` — the top-level archived message.
pub mod event {
    include_proto!("event");
}

/// `archive/header.proto` — the first record of every archive file.
pub mod header {
    include_proto!("header");
}

/// `bitcoin_primitives.proto`
pub mod bitcoin_primitives {
    include_proto!("bitcoin_primitives");
}

/// `ebpf_extractor.proto` and its sub-packages.
pub mod ebpf_extractor {
    include_proto!("ebpf_extractor");

    pub mod message {
        include_proto!("ebpf_extractor.message");
    }
    pub mod connection {
        include_proto!("ebpf_extractor.connection");
    }
    pub mod mempool {
        include_proto!("ebpf_extractor.mempool");
    }
    pub mod validation {
        include_proto!("ebpf_extractor.validation");
    }
}

/// `rpc_extractor.proto`
pub mod rpc_extractor {
    include_proto!("rpc_extractor");
}

/// `p2p_extractor.proto`
pub mod p2p_extractor {
    include_proto!("p2p_extractor");
}

/// `log_extractor.proto`
pub mod log_extractor {
    include_proto!("log_extractor");
}

/// `ipc_extractor.proto`
pub mod ipc_extractor {
    include_proto!("ipc_extractor");
}

/// Serialized `FileDescriptorSet` for the whole schema, used by the
/// reflection-based JSON inspector.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.bin"));
