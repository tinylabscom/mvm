#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${SCRIPT_DIR}/../mvm-demo/guest"

# Build the wasm32-wasip1 guest binary.
cd "$SCRIPT_DIR"
cargo build --target wasm32-wasip1 --release

# Optimize for size. Bulk-memory ops are emitted by the Rust wasm target.
mkdir -p "$DEST_DIR"
wasm-opt \
  -Oz \
  --enable-bulk-memory-opt \
  "$SCRIPT_DIR/target/wasm32-wasip1/release/mvm-demo-guest.wasm" \
  -o "$DEST_DIR/mvm-demo-guest.wasm"

echo "Built $DEST_DIR/mvm-demo-guest.wasm"
ls -lh "$DEST_DIR/mvm-demo-guest.wasm"
