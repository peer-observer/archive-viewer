use std::path::PathBuf;

fn main() {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../peer-observer/protobuf")
        .canonicalize()
        .unwrap_or_else(|_| panic!("{}", MISSING_SUBMODULE));

    let event = proto_root.join("event.proto");
    let header = proto_root.join("archive/header.proto");
    if !event.exists() || !header.exists() {
        panic!("{}", MISSING_SUBMODULE);
    }

    println!("cargo:rerun-if-changed={}", proto_root.display());

    let descriptor_path = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"))
        .join("descriptor.bin");

    // Kept deliberately identical to peer-observer's own shared/build.rs, so the
    // generated types match upstream's exactly. The descriptor set is the one
    // addition: it backs the reflection-based JSON inspector.
    prost_build::Config::new()
        .compile_well_known_types()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(&[&event, &header], &[&proto_root])
        .expect("failed to compile peer-observer protobuf definitions");
}

const MISSING_SUBMODULE: &str = "\
the peer-observer submodule is missing or empty.

The protobuf schema is compiled from it. Fetch it with:

    git submodule update --init

(in CI: actions/checkout with `submodules: recursive`)";
