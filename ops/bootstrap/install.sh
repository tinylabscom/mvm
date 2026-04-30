#!/usr/bin/env bash
# mvm installer with SHA256 verification.
# Usage: ./mvm-install.sh [--version VERSION]
#
# NEVER run this via curl|bash in production.
# Download first, verify, then execute:
#   curl -LO https://github.com/auser/mvm/releases/download/vX.Y.Z/mvm-install.sh
#   curl -LO https://github.com/auser/mvm/releases/download/vX.Y.Z/checksums-sha256.txt
#   chmod +x mvm-install.sh && ./mvm-install.sh

set -euo pipefail

REPO="auser/mvm"
INSTALL_DIR="/usr/local/bin"
VERSION=""

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --help|-h) echo "Usage: $0 [--version VERSION]"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Detect architecture and map to Rust target triple
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux) TARGET="${ARCH}-unknown-linux-gnu" ;;
    darwin) TARGET="${ARCH}-apple-darwin" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Determine version
if [ -z "$VERSION" ]; then
    echo "Fetching latest version..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | cut -d'"' -f4)
    if [ -z "$VERSION" ]; then
        echo "ERROR: Failed to determine latest version"
        exit 1
    fi
fi
echo "Installing mvm ${VERSION} for ${TARGET}"

# Download archive and checksums
ARCHIVE_NAME="mvm-${TARGET}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ARCHIVE_NAME}..."
curl -fsSL -o "${TMPDIR}/${ARCHIVE_NAME}" "${BASE_URL}/${ARCHIVE_NAME}"

echo "Downloading checksums..."
curl -fsSL -o "${TMPDIR}/checksums-sha256.txt" "${BASE_URL}/checksums-sha256.txt"

# Verify SHA256 checksum
echo "Verifying SHA256 checksum..."
EXPECTED=$(grep "${ARCHIVE_NAME}" "${TMPDIR}/checksums-sha256.txt" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
    echo "ERROR: No checksum found for ${ARCHIVE_NAME} in checksums file"
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TMPDIR}/${ARCHIVE_NAME}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${TMPDIR}/${ARCHIVE_NAME}" | awk '{print $1}')
else
    echo "ERROR: No sha256sum or shasum found. Cannot verify binary."
    exit 1
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "ERROR: SHA256 checksum mismatch!"
    echo "  Expected: ${EXPECTED}"
    echo "  Actual:   ${ACTUAL}"
    echo "The downloaded archive may be corrupted or tampered with."
    exit 1
fi
echo "Checksum verified."

# Extract binary from archive
echo "Extracting..."
tar xzf "${TMPDIR}/${ARCHIVE_NAME}" -C "${TMPDIR}"

# The archive contains mvm-${TARGET}/mvm
EXTRACTED_BIN="${TMPDIR}/mvm-${TARGET}/mvm"
if [ ! -f "$EXTRACTED_BIN" ]; then
    echo "ERROR: Binary not found in archive at mvm-${TARGET}/mvm"
    exit 1
fi

# Install
chmod +x "$EXTRACTED_BIN"
if [ -w "$INSTALL_DIR" ]; then
    mv "$EXTRACTED_BIN" "${INSTALL_DIR}/mvm"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$EXTRACTED_BIN" "${INSTALL_DIR}/mvm"
fi

echo "mvm ${VERSION} installed to ${INSTALL_DIR}/mvm"

# Verify installation
if command -v mvm >/dev/null 2>&1; then
    mvm --version 2>/dev/null || true
fi
