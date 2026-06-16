#!/usr/bin/env bash
# Verify a published mvm release's asset set is complete and self-consistent:
# every binary target tarball has a SHA256 file that matches, a cosign
# signature bundle, and an entry in the combined checksums manifest; the
# signed SBOM is present. Fail-closed — any missing or mismatched asset is a
# nonzero exit. Run post-publish (release.yml `verify-release` job) against a
# directory of downloaded release assets, or locally against a staging dir.
#
# Usage:
#   verify-release-assets.sh --assets-dir DIR [--targets "t1 t2 ..."] [--cosign]
#
# --targets defaults to the release.yml build matrix. --cosign additionally
# runs `cosign verify-blob` against each bundle (needs cosign on PATH and the
# expected OIDC identity in COSIGN_IDENTITY / COSIGN_OIDC_ISSUER).
set -euo pipefail

ASSETS_DIR=""
# Keep in lockstep with the release.yml `build` matrix. x86_64-apple-darwin is
# deferred there (no Intel runner), so it is deliberately absent here too.
TARGETS="aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu"
DO_COSIGN=0
EXPECT_VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --assets-dir)     ASSETS_DIR="$2"; shift 2 ;;
    --targets)        TARGETS="$2"; shift 2 ;;
    --cosign)         DO_COSIGN=1; shift ;;
    # Assert the packaged binary reports this version. Only the target that
    # matches the host can be executed; cross-arch targets are skipped (their
    # `--version` is covered by the build-job smoke test before packaging).
    --expect-version) EXPECT_VERSION="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Which release target, if any, can run on this host?
host_target() {
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)          echo "x86_64-unknown-linux-gnu" ;;
    Linux/aarch64)         echo "aarch64-unknown-linux-gnu" ;;
    Darwin/arm64)          echo "aarch64-apple-darwin" ;;
    *)                     echo "" ;;
  esac
}
HOST_TARGET="$(host_target)"

[ -n "$ASSETS_DIR" ] || { echo "error: --assets-dir is required" >&2; exit 2; }
[ -d "$ASSETS_DIR" ] || { echo "error: assets dir not found: $ASSETS_DIR" >&2; exit 2; }

fail() { echo "::error::$*" >&2; FAILED=1; }
FAILED=0

# Prefer sha256sum (Linux), fall back to shasum -a 256 (macOS).
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

COMBINED="$ASSETS_DIR/checksums-sha256.txt"
[ -f "$COMBINED" ] || fail "combined checksums manifest missing: checksums-sha256.txt"

for target in $TARGETS; do
  tarball="$ASSETS_DIR/mvmctl-${target}.tar.gz"
  sha="$tarball.sha256"
  bundle="$tarball.bundle"

  [ -f "$tarball" ] || { fail "[$target] tarball missing: $(basename "$tarball")"; continue; }
  [ -f "$sha" ]     || fail "[$target] checksum file missing: $(basename "$sha")"
  [ -f "$bundle" ]  || fail "[$target] cosign signature bundle missing: $(basename "$bundle")"

  # The .sha256 file records the SHA over the tarball — recompute and compare.
  if [ -f "$sha" ]; then
    want=$(awk '{print $1}' "$sha")
    got=$(sha256_of "$tarball")
    [ "$want" = "$got" ] || fail "[$target] sha256 mismatch: recorded=$want actual=$got"
  fi

  # The combined manifest must cover this tarball (download-path integrity).
  if [ -f "$COMBINED" ]; then
    grep -q "mvmctl-${target}.tar.gz" "$COMBINED" \
      || fail "[$target] not listed in checksums-sha256.txt"
  fi

  if [ "$DO_COSIGN" = 1 ] && [ -f "$bundle" ]; then
    command -v cosign >/dev/null 2>&1 || { fail "--cosign given but cosign not on PATH"; continue; }
    cosign verify-blob --bundle "$bundle" \
      ${COSIGN_IDENTITY_REGEXP:+--certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP"} \
      ${COSIGN_IDENTITY:+--certificate-identity "$COSIGN_IDENTITY"} \
      ${COSIGN_OIDC_ISSUER:+--certificate-oidc-issuer "$COSIGN_OIDC_ISSUER"} \
      "$tarball" >/dev/null 2>&1 \
      || fail "[$target] cosign verify-blob failed"
  fi

  if [ -n "$EXPECT_VERSION" ] && [ "$target" = "$HOST_TARGET" ] && [ -f "$tarball" ]; then
    tmp=$(mktemp -d)
    if tar xzf "$tarball" -C "$tmp" 2>/dev/null; then
      bin="$tmp/mvmctl-${target}/mvmctl"
      if [ -x "$bin" ]; then
        ver=$("$bin" --version 2>/dev/null || true)
        case "$ver" in
          *"$EXPECT_VERSION"*) : ;;
          *) fail "[$target] --version mismatch: expected to contain '$EXPECT_VERSION', got '$ver'" ;;
        esac
      else
        fail "[$target] packaged mvmctl binary missing or not executable"
      fi
    else
      fail "[$target] tarball failed to extract"
    fi
    rm -rf "$tmp"
  fi
done

# The SBOM ships signed alongside the binaries on every release.
[ -f "$ASSETS_DIR/sbom.cdx.json" ]        || fail "SBOM missing: sbom.cdx.json"
[ -f "$ASSETS_DIR/sbom.cdx.json.bundle" ] || fail "SBOM signature bundle missing: sbom.cdx.json.bundle"

if [ "$FAILED" = 0 ]; then
  echo "ok: all $(echo "$TARGETS" | wc -w | tr -d ' ') target(s) have tarball + matching sha256 + signature bundle + manifest entry; SBOM signed."
else
  echo "release asset verification FAILED" >&2
  exit 1
fi
