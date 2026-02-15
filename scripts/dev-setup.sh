#!/usr/bin/env bash
set -euo pipefail

# scripts/dev-setup.sh — Install prerequisites for building mvm from source.
#
# Run this on a fresh host (or inside a Lima VM) before `cargo build`.
#
# Usage:
#   ./scripts/dev-setup.sh

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
else
    BOLD='' GREEN='' YELLOW='' RED='' RESET=''
fi

info()  { echo -e "${BOLD}${GREEN}==>${RESET} ${BOLD}$1${RESET}"; }
warn()  { echo -e "${BOLD}${YELLOW}warn:${RESET} $1" >&2; }
die()   { echo -e "${RED}error:${RESET} $1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

OS="$(uname -s)"
ARCH="$(uname -m)"

info "Detected: ${OS} ${ARCH}"

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------

install_linux_deps() {
    info "Installing system build dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y
        sudo apt-get install -y build-essential pkg-config libssl-dev lld clang curl nodejs npm protobuf-compiler
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config openssl-devel lld clang curl nodejs npm protobuf-compiler
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm base-devel openssl lld clang curl nodejs npm protobuf-compiler
    else
        die "No supported package manager found (apt/dnf/pacman). Install manually: gcc, pkg-config, libssl-dev, lld, clang, curl"
    fi
}

install_darwin_deps() {
    # Xcode CLI tools provide cc/ld; Homebrew for openssl if needed
    if ! xcode-select -p >/dev/null 2>&1; then
        info "Installing Xcode Command Line Tools..."
        xcode-select --install
        echo "  Re-run this script after Xcode CLI tools finish installing."
        exit 0
    fi

    if command -v brew >/dev/null 2>&1; then
        info "Ensuring openssl is available via Homebrew..."
        brew install openssl pkg-config 2>/dev/null || true
    else
        warn "Homebrew not found. If cargo build fails with OpenSSL errors, install Homebrew and run: brew install openssl pkg-config"
    fi
}

case "$OS" in
    Linux)  install_linux_deps ;;
    Darwin) install_darwin_deps ;;
    *)      die "Unsupported OS: $OS" ;;
esac

# ---------------------------------------------------------------------------
# Rust toolchain (via rustup)
# ---------------------------------------------------------------------------

if command -v rustup >/dev/null 2>&1; then
    info "rustup already installed: $(rustup --version 2>/dev/null)"
    info "Syncing toolchain from rust-toolchain.toml..."
    rustup show >/dev/null 2>&1 || true
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
    info "Installed: $(rustc --version)"
fi

# ---------------------------------------------------------------------------
# Cargo utilities
# ---------------------------------------------------------------------------
cargo install cargo-watch

# ---------------------------------------------------------------------------
# Pnpm
# ---------------------------------------------------------------------------
if command -v curl >/dev/null 2>&1; then
    info "Instaling pnpm..."
    curl -fsSL https://get.pnpm.io/install.sh | sh -
else
    info "Instaling pnpm..."
    wget -qO- https://get.pnpm.io/install.sh | sh -
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

info "Verifying toolchain..."

echo "  rustc:      $(rustc --version)"
echo "  cargo:      $(cargo --version)"
echo "  cc:         $(cc --version 2>&1 | head -1)"

if command -v lld >/dev/null 2>&1; then
    echo "  lld:        $(lld --version 2>&1 | head -1)"
elif command -v ld.lld >/dev/null 2>&1; then
    echo "  ld.lld:     $(ld.lld --version 2>&1 | head -1)"
else
    warn "lld not found on PATH. The .cargo/config.toml requires lld for Linux targets."
fi

if pkg-config --exists openssl 2>/dev/null; then
    echo "  openssl:    $(pkg-config --modversion openssl)"
else
    warn "pkg-config can't find openssl. cargo build may fail for reqwest/openssl-sys."
fi

echo ""
info "Ready! Run 'cargo build' to compile mvm."
