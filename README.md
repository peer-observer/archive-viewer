# peer-observer archive viewer

A standalone, static web page for inspecting
[peer-observer](https://github.com/peer-observer/peer-observer) archive files.
Drag a `.bin.zst` (or `.bin`) archive onto it and it decodes the whole thing in
your browser and shows what is inside.

Nothing is uploaded: decoding runs entirely in WebAssembly, client-side. There is
no server, no nodejs and no JavaScript framework.

## Status

Work in progress. See `docs/` and the repository history.

## Building

Everything is provided by the Nix dev shell:

```sh
nix develop
./build.sh          # builds the wasm bundle into web/pkg/
./build.sh --serve  # ...and serves web/ locally
```

The page has to be served over HTTP — ES modules and `WebAssembly` cannot be
fetched from a `file://` URL.

## Repository layout

| path | what it is |
|---|---|
| `crates/core` | decoding and aggregation; pure Rust, builds native and for wasm32 |
| `crates/wasm` | the `wasm-bindgen` boundary |
| `crates/cli` | native harness: `stats` and `dump`, also the throughput benchmark |
| `web/` | the page itself |
| `peer-observer/` | git submodule, pinned; the protobuf schema is compiled from it |

Clone with submodules, or the build will not find the `.proto` files:

```sh
git clone --recurse-submodules ...
# or, in an existing clone:
git submodule update --init
```

## The archive format

Written by peer-observer's `tools/archive`. Each file is a single zstd stream
(or raw bytes with `--compression-level 0`) containing varint-length-delimited
protobuf messages:

```
[varint len][ header.ArchiveHeader ]   <- exactly one, first
[varint len][ event.Event ]            <- repeated to EOF
...
```

There is no frame checksum, no declared uncompressed size and only one zstd frame
per file, so decoding is strictly front-to-back and progress can only be measured
in compressed bytes.

### Truncated archives are normal

A file that is still being written ends mid-frame. Every record before the cut is
valid, and the viewer reports truncation as information rather than an error.

This needs some care: `ruzstd` withholds the last `window_size` decompressed bytes
for back-references until the frame's final block arrives, and peer-observer
archives declare a 128 MiB window — which for any archive smaller than that is
*all* of it. The decoder therefore feeds the frame a synthetic empty final block
at EOF to release the tail. See `crates/core/src/decode.rs`.

The one thing genuinely unrecoverable is a partial zstd block at the very end
(up to 128 KiB), which is not decodable even in principle.

### Caveats when reading an archive

- Which event types an archive contains depends on the flags the producing
  archiver ran with (`--messages`, `--connections`, …), and those flags are *not*
  recorded in the file. An absent event type may simply have been filtered out.
- Peer ids are assigned by Bitcoin Core and are only unique within one node run,
  so an archive spanning a restart can reuse them.
