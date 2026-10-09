#!/usr/bin/env bash
# Verify a published mvm release's asset set is complete and self-consistent:
# every binary target tarball has a SHA256 file that matches, a cosign
# signature bundle, and an entry in the combined checksums manifest; every
# Linux target has exactly one .deb and one .rpm held to the same three
# checks; the signed SBOM is present. Fail-closed — any missing or mismatched asset is a
# nonzero exit. Run post-publish (release.yml `verify-release` job) against a
# directory of downloaded release assets, or locally against a staging dir.
#
# Boot images are not part of a CLI release: they are members of the signed
# image set `crates/mvm-core/images.lock` pins, and every consumer verifies
# them against that root, so there is nothing image-shaped to check here.
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

# The installer and `mvmctl update` anchor on the combined checksum manifest:
# they hash the archive and compare against this file. That makes an unsigned manifest the weak link —
# whoever can swap an artifact can swap its recorded hash too, and the
# comparison still passes. So each manifest ships a cosign bundle beside it,
# and a release that skipped signing one is a packaging bug worth failing on
# here: the download would still succeed and still "verify", which is precisely
# the silent failure this catches.
require_signed_manifest() {
  manifest="$1"; label="$2"
  bundle="$manifest.bundle"
  # Every return is explicit: the script runs under `set -e`, so a bare `return`
  # after a failed test propagates that failure and aborts the whole run instead
  # of recording one problem and carrying on.
  [ -f "$bundle" ] || { fail "$label signature bundle missing: $(basename "$bundle")"; return 0; }
  [ "$DO_COSIGN" = 1 ] || return 0
  command -v cosign >/dev/null 2>&1 || { fail "--cosign given but cosign not on PATH"; return 0; }
  cosign verify-blob --bundle "$bundle" \
    ${COSIGN_IDENTITY_REGEXP:+--certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP"} \
    ${COSIGN_IDENTITY:+--certificate-identity "$COSIGN_IDENTITY"} \
    ${COSIGN_OIDC_ISSUER:+--certificate-oidc-issuer "$COSIGN_OIDC_ISSUER"} \
    "$manifest" >/dev/null 2>&1 \
    || fail "$label cosign verify-blob failed"
}

required_bins_for_target() {
  case "$1" in
    *apple-darwin)
      echo "mvmctl mvm-hvf-supervisor mvm-network-endpoint"
      ;;
    *)
      echo "mvmctl mvm-network-endpoint"
      ;;
  esac
}

# The distro package architectures for a target, or nothing for a target
# that has no packages.
package_arches() {
  case "$1" in
    x86_64-unknown-linux-gnu)  echo "amd64 x86_64" ;;
    aarch64-unknown-linux-gnu) echo "arm64 aarch64" ;;
    *)                         echo "" ;;
  esac
}

# One signed, listed, digest-matching asset: the checks a tarball gets, for a
# distro package.
check_signed_asset() {
  label="$1"; asset="$2"
  name="$(basename "$asset")"
  [ -f "$asset.bundle" ] || fail "$label cosign signature bundle missing: $name.bundle"
  if [ -f "$COMBINED" ]; then
    want=$(awk -v name="$name" '$2 == name || $2 == "*" name {print $1}' "$COMBINED")
    if [ -z "$want" ]; then
      fail "$label $name not listed in checksums-sha256.txt"
    else
      got=$(sha256_of "$asset")
      [ "$want" = "$got" ] || fail "$label $name sha256 mismatch against checksums-sha256.txt: recorded=$want actual=$got"
    fi
  fi
  if [ "$DO_COSIGN" = 1 ] && [ -f "$asset.bundle" ]; then
    command -v cosign >/dev/null 2>&1 || { fail "--cosign given but cosign not on PATH"; return 0; }
    cosign verify-blob --bundle "$asset.bundle" \
      ${COSIGN_IDENTITY_REGEXP:+--certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP"} \
      ${COSIGN_IDENTITY:+--certificate-identity "$COSIGN_IDENTITY"} \
      ${COSIGN_OIDC_ISSUER:+--certificate-oidc-issuer "$COSIGN_OIDC_ISSUER"} \
      "$asset" >/dev/null 2>&1 \
      || fail "$label $name cosign verify-blob failed"
  fi
  return 0
}

# Exactly one package of a format per architecture: none is a release that
# dropped it, two is one a user cannot pick between. The version is part of
# the name, so it is matched rather than derived.
check_distro_packages() {
  target="$1"
  arches="$(package_arches "$target")"
  [ -n "$arches" ] || return 0
  deb_arch="${arches% *}"; rpm_arch="${arches#* }"
  for pattern in "mvmctl_*_${deb_arch}.deb" "mvmctl-*.${rpm_arch}.rpm"; do
    found=()
    # shellcheck disable=SC2086  # $pattern is a glob, expanded on purpose.
    for candidate in "$ASSETS_DIR"/$pattern; do
      if [ -f "$candidate" ]; then found+=("$candidate"); fi
    done
    if [ "${#found[@]}" -ne 1 ]; then
      fail "[$target] expected one $pattern, found ${#found[@]}"
      continue
    fi
    check_signed_asset "[$target]" "${found[0]}"
  done
  return 0
}

COMBINED="$ASSETS_DIR/checksums-sha256.txt"
[ -f "$COMBINED" ] || fail "combined checksums manifest missing: checksums-sha256.txt"
require_signed_manifest "$COMBINED" "combined checksums manifest"

# The complete guest runtime is a CLI-train asset, not a boot image. Its
# standalone digest is also consumed before the signature by downloaded
# clients, so it must agree with both the archive and the combined manifest.
runtime_archives=()
for candidate in "$ASSETS_DIR"/mvm-guest-bins-v*.tar.gz; do
  if [ -f "$candidate" ]; then runtime_archives+=("$candidate"); fi
done
if [ "${#runtime_archives[@]}" -ne 1 ]; then
  fail "expected one complete guest-runtime archive, found ${#runtime_archives[@]}"
else
  runtime="${runtime_archives[0]}"
  runtime_name="$(basename "$runtime")"
  if [ -n "$EXPECT_VERSION" ] && [ "$runtime_name" != "mvm-guest-bins-v${EXPECT_VERSION#v}.tar.gz" ]; then
    fail "guest-runtime archive does not match release version $EXPECT_VERSION: $runtime_name"
  fi
  check_signed_asset "[guest-runtime]" "$runtime"
  if [ ! -f "$runtime.sha256" ]; then
    fail "guest-runtime checksum missing: $runtime_name.sha256"
  else
    want="$(awk -v name="$runtime_name" '$2 == name || $2 == "*" name {print $1}' "$runtime.sha256")"
    got="$(sha256_of "$runtime")"
    [ "$want" = "$got" ] || fail "guest-runtime standalone checksum mismatch: $runtime_name"
  fi
  require_signed_manifest "$runtime.sha256" "guest-runtime checksum"
fi

for target in $TARGETS; do
  tarball="$ASSETS_DIR/mvmctl-${target}.tar.gz"
  bundle="$tarball.bundle"

  [ -f "$tarball" ] || { fail "[$target] tarball missing: $(basename "$tarball")"; continue; }
  [ -f "$bundle" ]  || fail "[$target] cosign signature bundle missing: $(basename "$bundle")"

  # The signed combined manifest is the digest the installer and `mvmctl update`
  # compare against, so it is the one checked here. The release publishes no
  # per-archive `.sha256`; requiring one failed every release without guarding
  # anything a user downloads.
  if [ -f "$COMBINED" ]; then
    want=$(awk -v name="mvmctl-${target}.tar.gz" '$2 == name || $2 == "*" name {print $1}' "$COMBINED")
    if [ -z "$want" ]; then
      fail "[$target] not listed in checksums-sha256.txt"
    else
      got=$(sha256_of "$tarball")
      [ "$want" = "$got" ] || fail "[$target] sha256 mismatch against checksums-sha256.txt: recorded=$want actual=$got"
    fi
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

  if [ -f "$tarball" ]; then
    tmp=$(mktemp -d)
    if tar xzf "$tarball" -C "$tmp" 2>/dev/null; then
      package_dir="$tmp/mvmctl-${target}"
      if [ -d "$package_dir" ]; then
        [ -f "$package_dir/install.sh" ] \
          || fail "[$target] authenticated atomic updater installer missing: install.sh"
        for bin_name in $(required_bins_for_target "$target"); do
          [ -x "$package_dir/$bin_name" ] \
            || fail "[$target] required packaged binary missing or not executable: $bin_name"
        done
      else
        fail "[$target] archive missing top-level directory mvmctl-${target}"
      fi
      bin="$package_dir/mvmctl"
      if [ -n "$EXPECT_VERSION" ] && [ "$target" = "$HOST_TARGET" ] && [ -x "$bin" ]; then
        ver=$("$bin" --version 2>/dev/null || true)
        case "$ver" in
          *"$EXPECT_VERSION"*) : ;;
          *) fail "[$target] --version mismatch: expected to contain '$EXPECT_VERSION', got '$ver'" ;;
        esac
      fi
    else
      fail "[$target] tarball failed to extract"
    fi
    rm -rf "$tmp"
  fi

  check_distro_packages "$target"
done

# The SBOM ships signed alongside the binaries on every release.
[ -f "$ASSETS_DIR/sbom.cdx.json" ]        || fail "SBOM missing: sbom.cdx.json"
[ -f "$ASSETS_DIR/sbom.cdx.json.bundle" ] || fail "SBOM signature bundle missing: sbom.cdx.json.bundle"

if [ "$FAILED" = 0 ]; then
  echo "ok: all $(echo "$TARGETS" | wc -w | tr -d ' ') target(s) have tarball + matching sha256 + signature bundle + manifest entry, Linux targets one signed .deb and .rpm; guest runtime and SBOM signed."
else
  echo "release asset verification FAILED" >&2
  exit 1
fi
