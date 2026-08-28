#!/usr/bin/env bash
# Build the qemu-wasm-smoke-pack in the builder VM and copy it back to macOS.
#
# Usage: ./scripts/build-qemu-wasm-smoke-pack.sh [output-dir]
#   output-dir: Where to place the built pack (default: ./qemu-wasm-smoke-pack)
#
# The pack is built inside the Linux builder VM (qemu-wasm requires x86_64 Linux)
# and copied back to the macOS host. The pack contains:
#   - qemu-system-x86_64.{js,wasm,worker.js}
#   - pack/ (firmware, kernel, rootfs)
#   - pack.data, pack.js (preloaded assets)
#   - index.html, xterm-pty.js
#
# Alternative: Download from GitHub releases
#   The pack is also published as part of boot-image releases:
#   gh release download boot-image/vX.Y.Z --pattern 'qemu-wasm-smoke-pack.tar.gz*'
#   Then extract and stage: tar -xzf qemu-wasm-smoke-pack.tar.gz

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/qemu-wasm-smoke-pack}"

# Builder VM name from limactl ls
BUILDER_VM="mvm-arm64"

# Check if builder VM exists
if ! limactl list | grep -q "^$BUILDER_VM "; then
  echo "ERROR: Builder VM '$BUILDER_VM' not found." >&2
  echo "Create it first with: limactl create --template=mvm-arm64" >&2
  exit 1
fi

# Check if builder VM is running
VM_STATUS=$(limactl list --json | jq -r --arg vm "$BUILDER_VM" 'select(.name == $vm) | .status')
if [ "$VM_STATUS" != "Running" ]; then
  echo "Booting builder VM '$BUILDER_VM'..."
  limactl start "$BUILDER_VM" &
  # Wait for VM to be ready
  for i in {1..30}; do
    sleep 10
    VM_STATUS=$(limactl list --json | jq -r --arg vm "$BUILDER_VM" 'select(.name == $vm) | .status')
    if [ "$VM_STATUS" == "Running" ]; then
      echo "Builder VM is ready"
      break
    fi
    echo "Waiting for builder VM... ($i/30) Status: $VM_STATUS"
  done
  if [ "$VM_STATUS" != "Running" ]; then
    echo "ERROR: Builder VM failed to start. Status: $VM_STATUS" >&2
    exit 1
  fi
fi

# Wait for SSH to be ready (VM is running but SSH may still be starting)
echo "Waiting for SSH to be ready..."
for i in {1..60}; do
  if limactl shell "$BUILDER_VM" -- echo "SSH ready" >/dev/null 2>&1; then
    echo "SSH is ready"
    break
  fi
  if [ $i -eq 60 ]; then
    echo "ERROR: SSH failed to become ready" >&2
    exit 1
  fi
  echo "Waiting for SSH... ($i/60)"
  sleep 5
done

echo "=== Building qemu-wasm-smoke-pack in builder VM ==="
echo "Output will be copied to: $OUTPUT_DIR"

# Run the nix build inside the builder VM
# We need to:
# 1. Copy the nix flake to the VM
# 2. Build the pack
# 3. Copy it back

# Create a temporary directory in the VM
VM_TMP_DIR="/tmp/qemu-wasm-build-$$"

# Copy the nix directory to the VM
echo "Copying nix directory to builder VM..."
limactl copy "$ROOT_DIR/nix" "$BUILDER_VM:$VM_TMP_DIR/nix"

# Copy the flake.lock if it exists
if [ -f "$ROOT_DIR/flake.lock" ]; then
  limactl copy "$ROOT_DIR/flake.lock" "$BUILDER_VM:$VM_TMP_DIR/flake.lock"
fi

# Run the build inside the VM
echo "Building qemu-wasm-smoke-pack in builder VM (this may take 10-30 minutes)..."
limactl shell "$BUILDER_VM" -- sh -c "
  set -euo pipefail
  cd $VM_TMP_DIR

  # Build the pack using nix
  nix build .#qemu-wasm-smoke-pack --print-build-logs

  # Copy the result to a known location
  cp -r result $VM_TMP_DIR/qemu-wasm-smoke-pack
  echo 'BUILD-SUCCESS'
"

# Check if build succeeded
limactl shell "$BUILDER_VM" -- sh -c "test -d $VM_TMP_DIR/qemu-wasm-smoke-pack" || {
  echo "ERROR: Build failed in builder VM" >&2
  limactl shell "$BUILDER_VM" -- sh -c "rm -rf $VM_TMP_DIR" || true
  exit 1
}

# Copy the built pack back to macOS
echo "Copying qemu-wasm-smoke-pack back to macOS..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
limactl copy "$BUILDER_VM:$VM_TMP_DIR/qemu-wasm-smoke-pack/." "$OUTPUT_DIR/"

# Clean up in VM
echo "Cleaning up builder VM..."
limactl shell "$BUILDER_VM" -- sh -c "rm -rf $VM_TMP_DIR"

echo ""
echo "=== Build complete! ==="
echo "Pack is ready at: $OUTPUT_DIR"
echo ""
echo "To stage it for the docs site, run:"
echo "  just demo-build-all $OUTPUT_DIR"
echo ""
echo "To verify the pack contents:"
ls -la "$OUTPUT_DIR"
