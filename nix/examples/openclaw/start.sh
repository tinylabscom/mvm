#!/usr/bin/env bash
# OpenClaw MicroVM - pre-built at Nix build time
set -euo pipefail

cd "$(dirname "$0")/../../.."

VM_NAME="${1:-oc}"
PORT="${2:-3000}"
SCRIPT_DIR="$(dirname "$0")"

echo "Starting OpenClaw MicroVM: $VM_NAME"
echo "  Port: $PORT"
echo ""

# Stop existing VM if running
if cargo run --quiet -- status 2>/dev/null | grep -q "  $VM_NAME "; then
    echo "Stopping existing VM '$VM_NAME'..."
    cargo run --quiet -- stop "$VM_NAME"
    sleep 2
fi

# Build template if not already built
if ! cargo run --quiet -- template list 2>/dev/null | grep -q "openclaw"; then
    echo "Building openclaw template..."
    cargo run --quiet -- template build openclaw
fi

# Run from template with config and secrets from host
cargo run -- run \
    --template openclaw \
    --name "$VM_NAME" \
    -v "$SCRIPT_DIR/config:/mnt/config" \
    -v "$SCRIPT_DIR/secrets:/mnt/secrets" \
    -p "$PORT:3000"

echo ""
echo "OpenClaw is starting (gateway takes ~5 min on first boot)."
echo ""
echo "  Forward port:  cargo run -- forward $VM_NAME $PORT:3000"
echo "  View logs:     cargo run -- logs $VM_NAME"
echo "  Check status:  cargo run -- status"
echo "  Stop:          cargo run -- stop $VM_NAME"
