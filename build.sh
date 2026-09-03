#!/usr/bin/env bash
# Build the viewer's wasm bundles into web/pkg/, fetch the asmap data, and
# optionally serve the page.
#
# Run inside the dev shell:  nix develop --command ./build.sh
set -euo pipefail

cd "$(dirname "$0")"

CRATE=archive-viewer-wasm
WASM_NAME=archive_viewer_wasm
# The ASN name tables are a separate module: asinfo embeds ~4 MB at compile
# time, and the page loads it only when the networks view is opened.
ASINFO_CRATE=archive-viewer-asinfo
ASINFO_NAME=archive_viewer_asinfo

OUT_DIR=web/pkg
PROFILE=release
SERVE=0
FEATURES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serve) SERVE=1 ;;
    --debug) PROFILE=debug ;;
    --dev-panics) FEATURES+=(--features dev-panics) ;;
    -h|--help)
      echo "usage: ./build.sh [--serve] [--debug] [--dev-panics]"
      echo
      echo "env: ASMAP_FILE=path   use a local asmap instead of downloading"
      echo "     ASMAP_URL=url     download from somewhere else"
      echo "     ASMAP_REFRESH=1   re-fetch even if web/asmap.dat exists"
      exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

for tool in cargo wasm-bindgen; do
  command -v "$tool" >/dev/null || {
    echo "error: $tool not found. Run inside 'nix develop'." >&2
    exit 1
  }
done

# wasm-bindgen-cli refuses to process a module built by a different version of
# the wasm-bindgen crate, and the error it gives is not obvious. Check up front.
CLI_VERSION=$(wasm-bindgen --version | awk '{print $2}')
CRATE_VERSION=$(sed -n 's/^wasm-bindgen = "=\([0-9.]*\)".*/\1/p' crates/wasm/Cargo.toml)
if [[ -n "$CRATE_VERSION" && "$CLI_VERSION" != "$CRATE_VERSION" ]]; then
  cat >&2 <<EOF
error: wasm-bindgen version mismatch
  wasm-bindgen-cli:   $CLI_VERSION   (from flake.nix)
  wasm-bindgen crate: $CRATE_VERSION (from crates/wasm/Cargo.toml)

These must match exactly. Pin the crate to "=$CLI_VERSION", or update the
nixpkgs input in flake.nix so it provides $CRATE_VERSION.
EOF
  exit 1
fi

echo "==> cargo build ($PROFILE, wasm32-unknown-unknown)"
BUILD_FLAGS=(--target wasm32-unknown-unknown -p "$CRATE" -p "$ASINFO_CRATE")
[[ ${#FEATURES[@]} -gt 0 ]] && BUILD_FLAGS+=("${FEATURES[@]}")
[[ "$PROFILE" == release ]] && BUILD_FLAGS+=(--release)
cargo build "${BUILD_FLAGS[@]}"

echo "==> wasm-bindgen"
rm -rf "$OUT_DIR"
for name in "$WASM_NAME" "$ASINFO_NAME"; do
  wasm-bindgen --target web --no-typescript --out-dir "$OUT_DIR" \
    "target/wasm32-unknown-unknown/$PROFILE/$name.wasm"
done

BG="$OUT_DIR/${WASM_NAME}_bg.wasm"
ASINFO_BG="$OUT_DIR/${ASINFO_NAME}_bg.wasm"
if [[ "$PROFILE" == release ]] && command -v wasm-opt >/dev/null; then
  # -O3 for the viewer: it is parsing-throughput bound, not size bound.
  # -Oz for the name tables, which are inert data and only want to be small.
  echo "==> wasm-opt"
  wasm-opt -O3 --enable-bulk-memory --enable-nontrapping-float-to-int -o "$BG.opt" "$BG"
  mv "$BG.opt" "$BG"
  wasm-opt -Oz --enable-bulk-memory -o "$ASINFO_BG.opt" "$ASINFO_BG"
  mv "$ASINFO_BG.opt" "$ASINFO_BG"
fi

# The networks view needs Bitcoin Core's asmap trie. It is fetched rather than
# vendored: ~1.5 MB, updated independently of this tool, and everything else
# works without it.
ASMAP_URL="${ASMAP_URL:-https://raw.githubusercontent.com/bitcoin-core/asmap-data/main/latest_asmap.dat}"
ASMAP_DEST=web/asmap.dat
if [[ -n "${ASMAP_FILE:-}" ]]; then
  cp "$ASMAP_FILE" "$ASMAP_DEST"
  echo "==> asmap from $ASMAP_FILE"
elif [[ -f "$ASMAP_DEST" && -z "${ASMAP_REFRESH:-}" ]]; then
  echo "==> asmap already present ($(du -h "$ASMAP_DEST" | cut -f1))"
elif command -v curl >/dev/null && curl -sSfL -o "$ASMAP_DEST.tmp" "$ASMAP_URL"; then
  mv "$ASMAP_DEST.tmp" "$ASMAP_DEST"
  echo "==> asmap $(du -h "$ASMAP_DEST" | cut -f1)"
else
  rm -f "$ASMAP_DEST.tmp"
  echo "==> asmap could not be fetched; the networks view will be unavailable" >&2
fi

printf '==> viewer %s, asn names %s\n' \
  "$(du -h "$BG" | cut -f1)" "$(du -h "$ASINFO_BG" | cut -f1)"

if [[ "$SERVE" == 1 ]]; then
  command -v miniserve >/dev/null || {
    echo "error: miniserve not found. Run inside 'nix develop'." >&2
    exit 1
  }
  echo "==> serving web/ at http://127.0.0.1:8080"
  exec miniserve --index index.html --port 8080 web
fi
