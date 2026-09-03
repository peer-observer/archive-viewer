#!/usr/bin/env bash
# Build the wasm bundle into web/pkg/, and optionally serve the page.
#
# Run inside the dev shell:  nix develop --command ./build.sh
set -euo pipefail

cd "$(dirname "$0")"

CRATE=archive-viewer-wasm
WASM_NAME=archive_viewer_wasm
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
      sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
      echo
      echo "options: --serve  --debug  --dev-panics"
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
BUILD_FLAGS=(--target wasm32-unknown-unknown -p "$CRATE" "${FEATURES[@]+"${FEATURES[@]}"}")
[[ "$PROFILE" == release ]] && BUILD_FLAGS+=(--release)
cargo build "${BUILD_FLAGS[@]}"

echo "==> wasm-bindgen"
rm -rf "$OUT_DIR"
wasm-bindgen \
  --target web \
  --no-typescript \
  --out-dir "$OUT_DIR" \
  "target/wasm32-unknown-unknown/$PROFILE/$WASM_NAME.wasm"

BG="$OUT_DIR/${WASM_NAME}_bg.wasm"
if [[ "$PROFILE" == release ]] && command -v wasm-opt >/dev/null; then
  # -O3 rather than -Oz: this is a parsing-throughput bound app, not a
  # size-bound one, and the page is loaded from a local file or Pages.
  echo "==> wasm-opt -O3"
  wasm-opt -O3 --enable-bulk-memory --enable-nontrapping-float-to-int \
    -o "$BG.opt" "$BG"
  mv "$BG.opt" "$BG"
fi

printf '==> %s (%s)\n' "$BG" "$(du -h "$BG" | cut -f1)"

if [[ "$SERVE" == 1 ]]; then
  command -v miniserve >/dev/null || {
    echo "error: miniserve not found. Run inside 'nix develop'." >&2
    exit 1
  }
  echo "==> serving web/ at http://127.0.0.1:8080"
  exec miniserve --index index.html --port 8080 web
fi
