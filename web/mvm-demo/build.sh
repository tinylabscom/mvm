#!/usr/bin/env bash
# Build the browser wasm demo and stage it into the Astro site.
#
# This script is intended to run in CI or in the Linux builder VM, where
# wasm-pack and the wasm32-unknown-unknown target are available.  On macOS
# without the target, use the builder VM or skip the wasm build and rely on
# a previously-staged pkg/ directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEST_DIR="$ROOT_DIR/public/public/demo"

# Build the wasm-bindgen shim.
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack not found; please install it or run this in the builder VM"
  exit 1
fi
cd "$SCRIPT_DIR"
wasm-pack build --target web --out-dir pkg
wasm-opt -Oz pkg/mvm_demo_web_bg.wasm -o pkg/mvm_demo_web_bg.wasm

# Gzipped size budget for the demo wasm bundle.  The host-facing
# mvm-contract code is intentionally shared with the browser, so this is
# the price of portability; the budget keeps it honest.
BUDGET_BYTES=307200  # 300 KiB
GZIPPED_SIZE=$(gzip -c pkg/mvm_demo_web_bg.wasm | wc -c)
if [ "$GZIPPED_SIZE" -gt "$BUDGET_BYTES" ]; then
  echo "wasm bundle gzipped size $GZIPPED_SIZE bytes exceeds budget $BUDGET_BYTES bytes"
  exit 1
fi
echo "wasm bundle gzipped size: $GZIPPED_SIZE bytes (budget $BUDGET_BYTES bytes)"

# Build the curated WASI fixtures.
python3 "$SCRIPT_DIR/fixtures/build.py"

# Stage everything the Astro site serves at /demo/.
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR/fixtures"
cp "$SCRIPT_DIR/index.html" "$DEST_DIR/index.html"
cp "$SCRIPT_DIR/demo.js" "$DEST_DIR/demo.js"
cp "$SCRIPT_DIR/worker.js" "$DEST_DIR/worker.js"
cp "$SCRIPT_DIR/pkg"/* "$DEST_DIR/"
cp "$SCRIPT_DIR/fixtures/"*.opt.wasm "$DEST_DIR/fixtures/"

echo "Demo staged to $DEST_DIR"
