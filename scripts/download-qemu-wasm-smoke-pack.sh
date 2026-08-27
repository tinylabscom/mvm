#!/usr/bin/env bash
# Download the qemu-wasm-smoke-pack from GitHub releases.
#
# Usage: ./scripts/download-qemu-wasm-smoke-pack.sh [output-dir] [tag]
#   output-dir: Where to place the unpacked pack (default: ./qemu-wasm-smoke-pack)
#   tag:        The boot-image tag to download from (default: latest)
#
# NOTE: The qemu-wasm-smoke-pack is NOT currently published to GitHub releases.
# This script exists as a template but you'll need to build the pack using
# the just qemu-wasm-pack command which runs the build inside the Linux builder VM.
# See scripts/build-qemu-wasm-smoke-pack.sh for details.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/qemu-wasm-smoke-pack}"
TAG="${2:-}"

REPO="${GITHUB_REPOSITORY:-tinylabscom/mvm}"

echo "=== Downloading qemu-wasm-smoke-pack ==="
echo "Output directory: $OUTPUT_DIR"
echo "Repository: $REPO"
if [ -n "$TAG" ]; then
  echo "Tag: $TAG"
else
  echo "Tag: (latest)"
fi

# Check if gh is installed
if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: GitHub CLI (gh) not found. Install with: brew install gh" >&2
  exit 1
fi

# Login check
if ! gh auth status >/dev/null 2>&1; then
  echo "ERROR: Not logged in to GitHub. Run: gh auth login" >&2
  exit 1
fi

# Find the latest boot-image tag if not specified
if [ -z "$TAG" ]; then
  echo "Fetching latest boot-image tag..."
  TAG=$(gh release list --repo "$REPO" --limit 100 --json tagName --jq '
    [ .[].tagName
      | select(test("^boot-image/v[0-9]+\\.[0-9]+\\.[0-9]+$"))
      | {tag: ., v: (ltrimstr("boot-image/v") | split(".") | map(tonumber))} ]
    | sort_by(.v) | last | .tag // empty')

  if [ -z "$TAG" ]; then
    echo "ERROR: No boot-image/v* tag found" >&2
    exit 1
  fi
fi

echo "Using tag: $TAG"

# Check if the release exists
if ! gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  echo "ERROR: Tag '$TAG' not found in $REPO" >&2
  exit 1
fi

# Check if the pack asset exists
ASSETS=$(gh release view "$TAG" --repo "$REPO" --json assets --jq '.assets[].name')
if ! printf '%s\n' "$ASSETS" | grep -qxF 'qemu-wasm-smoke-pack.tar.gz'; then
  echo "ERROR: Tag '$TAG' does not contain qemu-wasm-smoke-pack.tar.gz" >&2
  echo "Available assets:"
  printf '%s\n' "$ASSETS"
  exit 1
fi

# Download the pack
DOWNLOAD_DIR=$(mktemp -d)
trap 'rm -rf "$DOWNLOAD_DIR"' EXIT

echo "Downloading qemu-wasm-smoke-pack from $TAG..."
gh release download "$TAG" --repo "$REPO" --pattern 'qemu-wasm-smoke-pack.tar.gz*' --dir "$DOWNLOAD_DIR"

# Verify checksum
if [ -f "$DOWNLOAD_DIR/qemu-wasm-smoke-pack.tar.gz.sha256" ]; then
  echo "Verifying checksum..."
  cd "$DOWNLOAD_DIR"
  sha256sum -c qemu-wasm-smoke-pack.tar.gz.sha256
  cd "$ROOT_DIR"
else
  echo "WARNING: No checksum file found, skipping verification"
fi

# Extract to output directory
echo "Extracting to $OUTPUT_DIR..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
tar -xzf "$DOWNLOAD_DIR/qemu-wasm-smoke-pack.tar.gz" -C "$OUTPUT_DIR"

echo ""
echo "=== Download complete! ==="
echo "Pack is ready at: $OUTPUT_DIR"
echo ""
echo "To stage it for the docs site, run:"
echo "  just demo-build-all $OUTPUT_DIR"
echo ""
echo "To verify the pack contents:"
ls -la "$OUTPUT_DIR"
