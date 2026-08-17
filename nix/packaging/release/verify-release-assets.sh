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
# Keep in lockstep with the release.yml `builder-vm-image` matrix.
BUILDER_ARCHES="aarch64 x86_64"
KERNEL_ARCHES="aarch64 x86_64"
RUNTIME_ARCHES="aarch64 x86_64"
# Keep in lockstep with the release.yml `default-microvm` matrix.
BOOT_ARCHES="aarch64 x86_64"
DO_COSIGN=0
EXPECT_VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --assets-dir)     ASSETS_DIR="$2"; shift 2 ;;
    --targets)        TARGETS="$2"; shift 2 ;;
    --builder-arches) BUILDER_ARCHES="$2"; shift 2 ;;
    --kernel-arches)  KERNEL_ARCHES="$2"; shift 2 ;;
    --runtime-arches) RUNTIME_ARCHES="$2"; shift 2 ;;
    # Empty disables the boot-asset checks. Only for a host without
    # e2fsprogs, where /init cannot be read out of the rootfs at all.
    --boot-arches)    BOOT_ARCHES="$2"; shift 2 ;;
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

# Every downloader anchors on a checksum manifest: it hashes the artifact and
# compares against this file. That makes an unsigned manifest the weak link —
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

# Whether a rootfs can be exec'd by the kernel is asserted by one script, used
# both here (published artifact, re-downloaded) and by release.yml before the
# staged image is ever uploaded. It prints its own ::error:: diagnosis.
INIT_SHEBANG_CHECK="$(dirname "$0")/assert-init-shebang.sh"
assert_init_shebang() {
  "$INIT_SHEBANG_CHECK" "$1" "$2" >/dev/null || FAILED=1
  return 0
}

# The rootfs check above proves the guest has an exec'able /init. It says
# nothing about whether the kernel that would exec it can be loaded at all —
# and on x86_64 the published kernel was a bzImage, which Firecracker refuses
# before init ever runs. Two assets, two formats, two checks.
KERNEL_FORMAT_CHECK="$(dirname "$0")/assert-kernel-format.sh"
assert_kernel_format() {
  "$KERNEL_FORMAT_CHECK" "$1" "$2" "$3" >/dev/null || FAILED=1
  return 0
}

required_bins_for_target() {
  case "$1" in
    *apple-darwin)
      echo "mvmctl mvm-hvf-supervisor mvm-libkrun-supervisor mvm-network-endpoint"
      ;;
    *)
      echo "mvmctl mvm-network-endpoint"
      ;;
  esac
}

COMBINED="$ASSETS_DIR/checksums-sha256.txt"
[ -f "$COMBINED" ] || fail "combined checksums manifest missing: checksums-sha256.txt"
require_signed_manifest "$COMBINED" "combined checksums manifest"

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

  if [ -f "$tarball" ]; then
    tmp=$(mktemp -d)
    if tar xzf "$tarball" -C "$tmp" 2>/dev/null; then
      package_dir="$tmp/mvmctl-${target}"
      if [ -d "$package_dir" ]; then
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
done

# Slim workload-kernel release assets are consumed directly by
# `mvmctl build kernel build --source download`, and installed-binary
# cold-cache `--kernel-pin` now reuses that same verified fetch path. So a
# release is incomplete unless each declared kernel arch ships both the
# workload `vmlinux` asset and the matching per-arch checksums manifest entry.
for arch in $KERNEL_ARCHES; do
  workload_kernel="$ASSETS_DIR/vmlinux-${arch}-workload"
  kernel_checks="$ASSETS_DIR/kernel-${arch}-checksums-sha256.txt"

  [ -f "$workload_kernel" ] || { fail "[$arch] workload kernel missing: vmlinux-${arch}-workload"; continue; }
  [ -f "$kernel_checks" ] || { fail "[$arch] kernel checksums manifest missing: kernel-${arch}-checksums-sha256.txt"; continue; }
  require_signed_manifest "$kernel_checks" "[$arch] kernel checksums manifest"

  want=$(awk -v n="vmlinux-${arch}-workload" '$2 == n { print $1 }' "$kernel_checks" | head -1)
  if [ -z "$want" ]; then
    fail "[$arch] vmlinux-${arch}-workload not listed in kernel-${arch}-checksums-sha256.txt"
    continue
  fi
  got=$(sha256_of "$workload_kernel")
  [ "$want" = "$got" ] || fail "[$arch] workload kernel sha256 mismatch: recorded=$want actual=$got"
done

# The rootfs, kernel and metadata sidecar under `default-microvm-*` are the
# artifacts mvmctl actually boots, and nothing here used to open them: the
# runtime-pack loop below checks only the pack sidecars. v0.17.0 shipped a
# rootfs whose /init carries its `#!` at byte 1, and every checksum in this file
# still verified, because a faithful copy of a broken image is still faithful.
#
# Same COMPLETE-or-ABSENT contract as the packs, and for the same reason: the
# `release` job publishes under `!cancelled()`, so an image job that failed
# leaves these absent on purpose and that is not an error here. A partial set,
# or a rootfs whose /init the kernel cannot exec, is.
for arch in $BOOT_ARCHES; do
  boot_rootfs="default-microvm-rootfs-${arch}.ext4"
  boot_kernel="default-microvm-vmlinux-${arch}"
  boot_meta="default-microvm-meta-${arch}.json"
  boot_checks="$ASSETS_DIR/default-microvm-${arch}-checksums-sha256.txt"

  present=0
  for f in "$boot_rootfs" "$boot_kernel" "$boot_meta"; do
    [ -f "$ASSETS_DIR/$f" ] && present=$((present + 1))
  done

  if [ "$present" -eq 0 ]; then
    echo "note: [$arch] no default-microvm boot assets published (image job did not ship) — ok"
    continue
  fi
  if [ "$present" -ne 3 ]; then
    fail "[$arch] partial default-microvm boot assets: rootfs=$([ -f "$ASSETS_DIR/$boot_rootfs" ] && echo y || echo n) kernel=$([ -f "$ASSETS_DIR/$boot_kernel" ] && echo y || echo n) meta=$([ -f "$ASSETS_DIR/$boot_meta" ] && echo y || echo n)"
    continue
  fi

  [ -f "$boot_checks" ] || { fail "[$arch] default-microvm checksums manifest missing: default-microvm-${arch}-checksums-sha256.txt"; continue; }
  require_signed_manifest "$boot_checks" "[$arch] default-microvm checksums manifest"
  for f in "$boot_rootfs" "$boot_kernel" "$boot_meta"; do
    want=$(awk -v n="$f" '$2 == n { print $1 }' "$boot_checks" | head -1)
    if [ -z "$want" ]; then
      fail "[$arch] $f not listed in default-microvm-${arch}-checksums-sha256.txt"
      continue
    fi
    got=$(sha256_of "$ASSETS_DIR/$f")
    [ "$want" = "$got" ] || fail "[$arch] $f sha256 mismatch: recorded=$want actual=$got"
  done

  # The checksums above prove the bytes are the ones we published. These prove
  # the ones we published can boot: a loadable kernel, and a guest init it can
  # exec once it is running.
  assert_kernel_format "$ASSETS_DIR/$boot_kernel" "$arch" "$arch kernel"
  assert_init_shebang "$ASSETS_DIR/$boot_rootfs" "$arch"
done

# The SBOM ships signed alongside the binaries on every release.
[ -f "$ASSETS_DIR/sbom.cdx.json" ]        || fail "SBOM missing: sbom.cdx.json"
[ -f "$ASSETS_DIR/sbom.cdx.json.bundle" ] || fail "SBOM signature bundle missing: sbom.cdx.json.bundle"

# Attested builder packs are an accelerator, published best-effort: a signing
# outage skips them and the plain vmlinux/rootfs still ship. So a pack is valid
# either COMPLETE (manifest + cosign bundle + SBOM, each listed in and matching
# the per-arch builder checksums manifest) or entirely ABSENT — a partial pack
# is a packaging bug and fails closed, because an installed binary would fetch
# it, fail to verify, and silently fall back to the plain download.
for arch in $BUILDER_ARCHES; do
  bp_manifest="builder-vm-${arch}.pack-manifest.json"
  bp_bundle="builder-vm-${arch}.pack-manifest.json.bundle"
  bp_sbom="builder-vm-${arch}.sbom.txt"
  bp_checks="$ASSETS_DIR/builder-vm-${arch}-checksums-sha256.txt"

  present=0
  for f in "$bp_manifest" "$bp_bundle" "$bp_sbom"; do
    [ -f "$ASSETS_DIR/$f" ] && present=$((present + 1))
  done

  if [ "$present" -eq 0 ]; then
    echo "note: [$arch] no attested builder pack published (accelerator absent) — ok"
    continue
  fi
  if [ "$present" -ne 3 ]; then
    fail "[$arch] partial attested builder pack: manifest=$([ -f "$ASSETS_DIR/$bp_manifest" ] && echo y || echo n) bundle=$([ -f "$ASSETS_DIR/$bp_bundle" ] && echo y || echo n) sbom=$([ -f "$ASSETS_DIR/$bp_sbom" ] && echo y || echo n)"
    continue
  fi

  [ -f "$bp_checks" ] || { fail "[$arch] builder checksums manifest missing: builder-vm-${arch}-checksums-sha256.txt"; continue; }
  require_signed_manifest "$bp_checks" "[$arch] builder checksums manifest"
  for f in "$bp_manifest" "$bp_bundle" "$bp_sbom"; do
    want=$(awk -v n="$f" '$2 == n { print $1 }' "$bp_checks" | head -1)
    if [ -z "$want" ]; then
      fail "[$arch] $f not listed in builder-vm-${arch}-checksums-sha256.txt"
      continue
    fi
    got=$(sha256_of "$ASSETS_DIR/$f")
    [ "$want" = "$got" ] || fail "[$arch] $f sha256 mismatch: recorded=$want actual=$got"
  done
  [ "$FAILED" = 0 ] && echo "ok: [$arch] attested builder pack complete (manifest + bundle + SBOM, checksummed)."
done

# Attested runtime packs follow the identical accelerator contract as builder
# packs: COMPLETE (manifest + cosign bundle + SBOM, each listed in and matching
# the per-arch default-microvm checksums manifest) or entirely ABSENT. A partial
# runtime pack fails closed for the same reason — an installed binary would
# fetch it, fail to verify, and silently fall back to the plain download.
for arch in $RUNTIME_ARCHES; do
  rp_manifest="default-microvm-${arch}.pack-manifest.json"
  rp_bundle="default-microvm-${arch}.pack-manifest.json.bundle"
  rp_sbom="default-microvm-${arch}.sbom.txt"
  rp_checks="$ASSETS_DIR/default-microvm-${arch}-checksums-sha256.txt"

  present=0
  for f in "$rp_manifest" "$rp_bundle" "$rp_sbom"; do
    [ -f "$ASSETS_DIR/$f" ] && present=$((present + 1))
  done

  if [ "$present" -eq 0 ]; then
    echo "note: [$arch] no attested runtime pack published (accelerator absent) — ok"
    continue
  fi
  if [ "$present" -ne 3 ]; then
    fail "[$arch] partial attested runtime pack: manifest=$([ -f "$ASSETS_DIR/$rp_manifest" ] && echo y || echo n) bundle=$([ -f "$ASSETS_DIR/$rp_bundle" ] && echo y || echo n) sbom=$([ -f "$ASSETS_DIR/$rp_sbom" ] && echo y || echo n)"
    continue
  fi

  [ -f "$rp_checks" ] || { fail "[$arch] default-microvm checksums manifest missing: default-microvm-${arch}-checksums-sha256.txt"; continue; }
  require_signed_manifest "$rp_checks" "[$arch] default-microvm checksums manifest"
  for f in "$rp_manifest" "$rp_bundle" "$rp_sbom"; do
    want=$(awk -v n="$f" '$2 == n { print $1 }' "$rp_checks" | head -1)
    if [ -z "$want" ]; then
      fail "[$arch] $f not listed in default-microvm-${arch}-checksums-sha256.txt"
      continue
    fi
    got=$(sha256_of "$ASSETS_DIR/$f")
    [ "$want" = "$got" ] || fail "[$arch] $f sha256 mismatch: recorded=$want actual=$got"
  done
  [ "$FAILED" = 0 ] && echo "ok: [$arch] attested runtime pack complete (manifest + bundle + SBOM, checksummed)."
done

if [ "$FAILED" = 0 ]; then
  echo "ok: all $(echo "$TARGETS" | wc -w | tr -d ' ') target(s) have tarball + matching sha256 + signature bundle + manifest entry; SBOM signed."
else
  echo "release asset verification FAILED" >&2
  exit 1
fi
