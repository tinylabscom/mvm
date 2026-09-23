#!/usr/bin/env bash
# Download the qemu-wasm-smoke-pack from GitHub releases.
#
# Usage: ./scripts/download-qemu-wasm-smoke-pack.sh [output-dir] [tag]
#   output-dir: Where to place the unpacked pack (default: ./qemu-wasm-smoke-pack)
#   tag:        The boot-image tag to download from (default: the tag pinned by
#               images.lock)
#
# The boot-image release train builds and publishes this pack. By default this
# downloads the exact release pinned by the checkout's image lock.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/qemu-wasm-smoke-pack}"
# Default to the locked pin rather than the newest published release: which
# bytes this pack is built from must be a property of the tree, not of whoever
# cut an image most recently.
LOCKED_TAG="$("$SCRIPT_DIR/locked-image-tag.sh")"
TAG="${2:-$LOCKED_TAG}"
if [ "$TAG" != "$LOCKED_TAG" ]; then
  echo "ERROR: requested image set '$TAG' is not the lock's '$LOCKED_TAG'" >&2
  exit 1
fi

REPO="$("$SCRIPT_DIR/locked-image-tag.sh" image_set repository)"
MANIFEST="$("$SCRIPT_DIR/locked-image-tag.sh" image_set manifest_asset)"
MANIFEST_SHA256="$("$SCRIPT_DIR/locked-image-tag.sh" image_set manifest_sha256)"
WORKFLOW="$("$SCRIPT_DIR/locked-image-tag.sh" image_set workflow)"
TAG_REF="$("$SCRIPT_DIR/locked-image-tag.sh" image_set tag_ref)"

echo "=== Downloading qemu-wasm-smoke-pack ==="
echo "Output directory: $OUTPUT_DIR"
echo "Repository: $REPO"
echo "Tag: $TAG"

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

DOWNLOAD_DIR=$(mktemp -d)
trap 'rm -rf "$DOWNLOAD_DIR"' EXIT

gh release download "$TAG" --repo "$REPO" --pattern "$MANIFEST*" --dir "$DOWNLOAD_DIR"
printf '%s  %s\n' "$MANIFEST_SHA256" "$DOWNLOAD_DIR/$MANIFEST" | sha256sum -c -
cosign verify-blob \
  --bundle "$DOWNLOAD_DIR/$MANIFEST.bundle" \
  --certificate-identity "https://github.com/$REPO/$WORKFLOW@$TAG_REF" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$DOWNLOAD_DIR/$MANIFEST"

# Compatibility is established before the member is requested.
jq -e '
  .compatibility.guest_agent_protocol.min <= 2 and
  .compatibility.guest_agent_protocol.max >= 2 and
  .compatibility.builder_cache_contract == 4
' "$DOWNLOAD_DIR/$MANIFEST" >/dev/null

echo "Downloading qemu-wasm-smoke-pack from $TAG..."
gh release download "$TAG" --repo "$REPO" --pattern 'qemu-wasm-smoke-pack.tar.gz' --dir "$DOWNLOAD_DIR"
jq -r '
  .members[] | select(.role == "qemu_wasm_smoke_pack") | .artifacts[] |
  select(.name == "qemu-wasm-smoke-pack.tar.gz") |
  "\(.sha256)  qemu-wasm-smoke-pack.tar.gz"
' "$DOWNLOAD_DIR/$MANIFEST" > "$DOWNLOAD_DIR/expected.txt"
test -s "$DOWNLOAD_DIR/expected.txt"
(cd "$DOWNLOAD_DIR" && sha256sum -c expected.txt)

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
