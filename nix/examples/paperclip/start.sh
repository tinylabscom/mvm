#!/usr/bin/env bash
# Paperclip MicroVM — build template and run
set -euo pipefail

cd "$(dirname "$0")/../../.."    # cd to repo root

VM_NAME="${1:-paperclip}"
PORT="${2:-3100}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Paperclip MicroVM ==="
echo "  VM name : $VM_NAME"
echo "  Port    : $PORT"
echo ""

# Stop existing VM if running
if cargo run --quiet -- status 2>/dev/null | grep -q "  $VM_NAME "; then
    echo "Stopping existing VM '$VM_NAME'..."
    cargo run --quiet -- stop "$VM_NAME"
    sleep 2
fi

# Build template if not already built
if ! cargo run --quiet -- template list 2>/dev/null | grep -q "paperclip"; then
    echo "Building paperclip template..."
    cargo run --quiet -- template build paperclip
fi

# Run from template with config and secrets from host
echo "Starting VM..."
cargo run -- run \
    --template paperclip \
    --name "$VM_NAME" \
    -v "$SCRIPT_DIR/config:/mnt/config" \
    -v "$SCRIPT_DIR/secrets:/mnt/secrets" \
    -p "$PORT:3100"

echo ""
echo "=== Paperclip is starting ==="
echo ""
echo "  Forward port:  mvmctl forward $VM_NAME"
echo "  View logs:     mvmctl logs -f $VM_NAME"
echo "  Check status:  mvmctl status"
echo "  Stop:          mvmctl stop $VM_NAME"
echo ""
echo "  UI: http://localhost:$PORT (after forwarding)"
echo ""
