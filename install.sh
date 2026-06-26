#!/bin/sh
# mvmctl installer. Downloads the released binary for this platform from
# GitHub releases, verifies its sha256 (and cosign signature if cosign is
# present), installs it, and on macOS re-codesigns with the
# Hypervisor.framework entitlement.
#
# Env knobs:
#   MVM_VERSION            pin a release tag (e.g. v0.15.2); default: latest
#   MVM_INSTALL_DIR        install dir; default: ~/.local/bin
#   MVM_SKIP_HASH_VERIFY   set to 1 to skip checksum (emergency only)
#   MVM_SKIP_CODESIGN      set to 1 to skip macOS codesign
#   MVM_SKIP_PACK_PREFETCH set to 1 to skip bootstrap pack preloading
#   MVM_BOOTSTRAP_RUNTIME_PACK_SOURCE  local/HTTPS runtime pack archive to preload
#   MVM_BOOTSTRAP_BUILDER_PACK_SOURCE  local/HTTPS builder pack archive to preload
#   MVM_BOOTSTRAP_PACK_POLICY_HASH     required policy hash when pack sources are set
#   MVM_BOOTSTRAP_PACK_BACKEND         firecracker, libkrun, vz, qemu, or docker
#   MVM_BOOTSTRAP_PACK_CHANNELS        comma-separated allowed artifact channels
#   MVM_UPDATE_API_URL     override https://api.github.com (tests)
#   MVM_UPDATE_DOWNLOAD_URL override https://github.com (tests)
set -eu

REPO="tinylabscom/mvm"
API_BASE="${MVM_UPDATE_API_URL:-https://api.github.com}"
DL_BASE="${MVM_UPDATE_DOWNLOAD_URL:-https://github.com}"
INSTALL_DIR="${MVM_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '[mvm] %s\n' "$1"; }
warn() { printf '[mvm] WARN: %s\n' "$1" >&2; }
die() { printf '[mvm] ERROR: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

need curl
need tar

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin) case "$arch" in
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        # Intel mac is deferred — no x86_64-apple-darwin asset is published
        # yet (Intel-macOS CI runners unavailable). Apple Silicon only.
        x86_64) die "Intel macOS is not supported yet — Apple Silicon macs and Linux only" ;;
        *) die "unsupported macOS arch: $arch" ;;
      esac ;;
    Linux) case "$arch" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) die "unsupported Linux arch: $arch" ;;
      esac ;;
    *) die "unsupported OS: $os" ;;
  esac
}

resolve_version() {
  if [ -n "${MVM_VERSION:-}" ]; then
    echo "$MVM_VERSION"
    return
  fi
  curl -fsSL "$API_BASE/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' \
    | grep . || die "could not resolve latest release tag"
}

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    die "need shasum or sha256sum to verify the download"
  fi
}

TARGET="$(detect_target)"
VERSION="$(resolve_version)"
ARCHIVE="mvmctl-${TARGET}.tar.gz"
REL="$DL_BASE/$REPO/releases/download/$VERSION"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "Installing mvmctl $VERSION ($TARGET) to $INSTALL_DIR"

curl -fsSL "$REL/$ARCHIVE" -o "$TMP/$ARCHIVE" \
  || die "download failed: $REL/$ARCHIVE"

if [ "${MVM_SKIP_HASH_VERIFY:-}" = "1" ]; then
  warn "MVM_SKIP_HASH_VERIFY=1 — skipping checksum verification"
else
  curl -fsSL "$REL/checksums-sha256.txt" -o "$TMP/checksums.txt" \
    || die "could not download checksums-sha256.txt"
  want="$(grep " $ARCHIVE\$" "$TMP/checksums.txt" | awk '{print $1}' | head -n1)"
  [ -n "$want" ] || die "no checksum for $ARCHIVE in checksums-sha256.txt"
  got="$(sha256_of "$TMP/$ARCHIVE")"
  if [ "$want" != "$got" ]; then
    rm -f "$TMP/$ARCHIVE"
    die "checksum mismatch for $ARCHIVE (want $want, got $got)"
  fi
  say "Checksum verified."
fi

# Optional cosign provenance — non-fatal if cosign is absent.
if command -v cosign >/dev/null 2>&1; then
  if curl -fsSL "$REL/$ARCHIVE.bundle" -o "$TMP/$ARCHIVE.bundle" 2>/dev/null; then
    if cosign verify-blob \
        --bundle "$TMP/$ARCHIVE.bundle" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        --certificate-identity-regexp "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/.*" \
        "$TMP/$ARCHIVE" >/dev/null 2>&1; then
      say "Signature verified."
    else
      die "cosign signature verification failed for $ARCHIVE"
    fi
  else
    warn "no cosign bundle published for this release — skipping signature check"
  fi
else
  warn "cosign not installed — skipping signature verification"
fi

tar xzf "$TMP/$ARCHIVE" -C "$TMP"
SRC="$TMP/mvmctl-${TARGET}"
[ -f "$SRC/mvmctl" ] || die "archive missing mvmctl-${TARGET}/mvmctl"

mkdir -p "$INSTALL_DIR" 2>/dev/null || true
# `mkdir -p` on an existing dir returns 0 regardless of ownership, so it
# can't double as a writability probe — test -w directly, then sudo-mkdir
# only on the not-writable path (e.g. MVM_INSTALL_DIR=/usr/local/bin).
if [ -w "$INSTALL_DIR" ]; then
  SUDO=""
else
  warn "$INSTALL_DIR not writable — using sudo"
  SUDO="sudo"
  $SUDO mkdir -p "$INSTALL_DIR"
fi

$SUDO install -m 0755 "$SRC/mvmctl" "$INSTALL_DIR/mvmctl"
if [ -d "$SRC/resources" ]; then
  $SUDO rm -rf "$INSTALL_DIR/resources"
  $SUDO cp -R "$SRC/resources" "$INSTALL_DIR/resources"
fi

# macOS: Hypervisor.framework needs the entitlement. Best-effort —
# a re-sign failure warns but doesn't fail the install (the binary
# still runs for non-hypervisor uses; `codesign` can be re-run).
if [ "$(uname -s)" = "Darwin" ] && [ "${MVM_SKIP_CODESIGN:-}" != "1" ]; then
  ent="$INSTALL_DIR/resources/mvmctl.entitlements"
  if command -v codesign >/dev/null 2>&1 && [ -f "$ent" ]; then
    if $SUDO codesign --entitlements "$ent" -f -s - "$INSTALL_DIR/mvmctl" 2>/dev/null; then
      say "Codesigned with Hypervisor.framework entitlement."
    else
      warn "codesign failed — re-run: codesign --entitlements $ent -f -s - $INSTALL_DIR/mvmctl"
    fi
  fi
fi

say "Installed: $INSTALL_DIR/mvmctl"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "Add to PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

# Pre-fetch the builder VM image so the first `mvmctl dev up` is fast instead
# of paying a one-time download/build on the hot path. Opt out with
# MVM_SKIP_BUILDER_PREFETCH=1 (bandwidth-limited, headless, or CI installs).
# Non-fatal: a failure just defers the fetch to first `dev up`.
if [ "${MVM_SKIP_BUILDER_PREFETCH:-}" != "1" ]; then
  say "Pre-fetching the builder VM image so your first 'dev up' is instant (skip with MVM_SKIP_BUILDER_PREFETCH=1)..."
  if "$INSTALL_DIR/mvmctl" bootstrap; then
    say "Builder VM image ready."
  else
    warn "builder-image prefetch failed — 'mvmctl dev up' will fetch it on first run, or re-run 'mvmctl bootstrap'."
  fi
else
  say "Skipping builder-image prefetch — run 'mvmctl bootstrap' before your first 'dev up' for a fast start."
fi

say "Run 'mvmctl doctor' to check your host."
