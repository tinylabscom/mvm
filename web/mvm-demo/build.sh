#!/usr/bin/env bash
# Build the browser wasm demo and stage assets into the Astro site.
#
# The HTML is served by public/src/pages/demo.astro (dev + production),
# so only the supporting assets are copied into public/public/demo/.
#
# This script is intended to run in CI or in the Linux builder VM, where
# wasm-pack and the wasm32 targets are available.  On macOS without the
# targets, use the builder VM or skip the wasm build and rely on a
# previously-staged pkg/ directory.
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

# Build the browser-tier microVM guest workload.
"$ROOT_DIR/web/mvm-demo-guest/build.sh"

# Plain size budget for the guest wasm (uncompressed). The guest grows as the
# simulated shell grows; pin a ceiling so additions are deliberate.
GUEST_WASM="$SCRIPT_DIR/guest/mvm-demo-guest.wasm"
GUEST_SIZE=$(wc -c < "$GUEST_WASM")
GUEST_BUDGET=200000  # 200 KiB
if [ "$GUEST_SIZE" -gt "$GUEST_BUDGET" ]; then
  echo "guest wasm size $GUEST_SIZE bytes exceeds budget $GUEST_BUDGET bytes"
  exit 1
fi
ls -la "$GUEST_WASM"

# Build the curated WASI fixtures.
python3 "$SCRIPT_DIR/fixtures/build.py"

# Stage assets only. index.html is served by public/src/pages/demo.astro.
# Remove only the wasm demo's own artifacts so a parallel weblinux staging
# under $DEST_DIR/weblinux/ is preserved.
rm -rf "$DEST_DIR/pkg" "$DEST_DIR/fixtures" "$DEST_DIR/guest" \
       "$DEST_DIR/demo.js" "$DEST_DIR/worker.js"
mkdir -p "$DEST_DIR/pkg"
mkdir -p "$DEST_DIR/fixtures"
mkdir -p "$DEST_DIR/guest"
cp "$SCRIPT_DIR/demo.js" "$DEST_DIR/demo.js"
cp "$SCRIPT_DIR/worker.js" "$DEST_DIR/worker.js"
cp "$SCRIPT_DIR/pkg"/* "$DEST_DIR/pkg/"
cp "$SCRIPT_DIR/fixtures/"*.opt.wasm "$DEST_DIR/fixtures/"
cp "$SCRIPT_DIR/guest/"*.wasm "$DEST_DIR/guest/"

echo "Demo assets staged to $DEST_DIR"
