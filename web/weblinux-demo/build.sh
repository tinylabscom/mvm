#!/usr/bin/env bash
# Stage the WebLinux demo assets into the Astro public directory.
#
# Usage:
#   ./build.sh <path-to-qemu-wasm-smoke-pack>
#
# The pack is produced by `nix build .#qemu-wasm-smoke-pack` (inside the
# project builder VM on macOS). This script copies the engine, preload data,
# firmware, and guest image next to the demo JS so Astro serves everything
# from /demo/weblinux/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEST_DIR="$ROOT_DIR/public/public/demo/weblinux"

PACK_DIR="${1:-}"
if [ -z "$PACK_DIR" ]; then
  echo "usage: $0 <path-to-qemu-wasm-smoke-pack>" >&2
  echo "Build the pack with: nix build .#qemu-wasm-smoke-pack" >&2
  exit 1
fi

if [ ! -d "$PACK_DIR" ]; then
  echo "pack directory not found: $PACK_DIR" >&2
  exit 1
fi

echo "Staging WebLinux demo to $DEST_DIR"
if [ -d "$DEST_DIR" ]; then
  chmod -R u+w "$DEST_DIR" || true
  rm -rf "$DEST_DIR"
fi
mkdir -p "$DEST_DIR"

# Copy the pack first, then overlay the demo source files so the demo's
# index.html, demo.js, and worker.js take precedence over any files that
# happen to share a name in the pack.
cp -R "$PACK_DIR/." "$DEST_DIR/"
chmod -R u+w "$DEST_DIR"
rm -f "$DEST_DIR/index.html"
cp "$SCRIPT_DIR/index.html" "$DEST_DIR/index.html"
cp "$SCRIPT_DIR/demo.js" "$DEST_DIR/demo.js"
cp "$SCRIPT_DIR/worker.js" "$DEST_DIR/worker.js"

# The standalone index.html is also kept in the destination so the demo can
# be served directly (e.g. with web/weblinux-demo/serve.py) without Astro.
# Astro's src/pages/demo/weblinux.astro renders the same HTML with COOP/COEP
# headers at the canonical /demo/weblinux route.

echo "WebLinux demo staged. Serve with Astro or web/weblinux-demo/serve.py."
