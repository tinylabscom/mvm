#!/usr/bin/env bash
# Focused tests for the attested-builder-pack gate in verify-release-assets.sh:
# a published pack must be COMPLETE (manifest + bundle + SBOM, each listed in and
# matching the per-arch builder checksums) or entirely ABSENT — a partial or
# checksum-mismatched pack fails closed. Runs the real script (no --cosign, no
# --expect-version, so the OIDC/host-version checks are skipped) against
# fixtures built here. No network, no cosign.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/verify-release-assets.sh"
TARGETS="aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu"
BUILDER_ARCHES="aarch64 x86_64"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

bins_for() {
  case "$1" in
    *apple-darwin) echo "mvmctl mvm-bridge mvm-vz-supervisor mvm-hvf-supervisor mvm-libkrun-supervisor mvm-substitution-endpoint" ;;
    *)             echo "mvmctl mvm-bridge mvm-substitution-endpoint" ;;
  esac
}

# Build a fully-valid release-assets dir (all tarball/SBOM checks pass) with a
# COMPLETE attested pack for every builder arch. Echoes the dir path.
build_valid_fixture() {
  local dir; dir="$(mktemp -d)"
  : > "$dir/checksums-sha256.txt"
  for t in $TARGETS; do
    local pkg="$dir/mvmctl-$t"
    mkdir -p "$pkg"
    for b in $(bins_for "$t"); do printf '#!/bin/sh\n' > "$pkg/$b"; chmod +x "$pkg/$b"; done
    ( cd "$dir" && tar czf "mvmctl-$t.tar.gz" "mvmctl-$t" && rm -rf "mvmctl-$t" )
    sha256_of "$dir/mvmctl-$t.tar.gz" > "$dir/mvmctl-$t.tar.gz.sha256"
    printf 'bundle\n' > "$dir/mvmctl-$t.tar.gz.bundle"
    echo "$(sha256_of "$dir/mvmctl-$t.tar.gz")  mvmctl-$t.tar.gz" >> "$dir/checksums-sha256.txt"
  done
  printf '{"sbom":true}\n' > "$dir/sbom.cdx.json"
  printf 'bundle\n' > "$dir/sbom.cdx.json.bundle"
  for arch in $BUILDER_ARCHES; do
    printf '{"pack":"%s"}\n' "$arch" > "$dir/builder-vm-$arch.pack-manifest.json"
    printf 'sigstore-bundle\n'       > "$dir/builder-vm-$arch.pack-manifest.json.bundle"
    printf 'store-path-a\nstore-path-b\n' > "$dir/builder-vm-$arch.sbom.txt"
    : > "$dir/builder-vm-$arch-checksums-sha256.txt"
    for f in "builder-vm-$arch.pack-manifest.json" "builder-vm-$arch.pack-manifest.json.bundle" "builder-vm-$arch.sbom.txt"; do
      echo "$(sha256_of "$dir/$f")  $f" >> "$dir/builder-vm-$arch-checksums-sha256.txt"
    done
  done
  echo "$dir"
}

run() { bash "$SCRIPT" --assets-dir "$1" >/dev/null 2>&1; }  # returns the script's exit code

PASS=0; FAILN=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()  { FAILN=$((FAILN+1)); echo "  FAIL: $1" >&2; }

# 1. Complete packs → pass.
d="$(build_valid_fixture)"
if run "$d"; then ok "complete packs verify"; else bad "complete packs should verify"; fi
rm -rf "$d"

# 2. Partial pack (bundle missing) → fail closed.
d="$(build_valid_fixture)"
rm -f "$d/builder-vm-aarch64.pack-manifest.json.bundle"
if run "$d"; then bad "partial pack (missing bundle) must fail"; else ok "partial pack (missing bundle) fails closed"; fi
rm -rf "$d"

# 3. Absent pack (all three gone) → pass (accelerator absent).
d="$(build_valid_fixture)"
rm -f "$d/builder-vm-x86_64.pack-manifest.json" "$d/builder-vm-x86_64.pack-manifest.json.bundle" \
      "$d/builder-vm-x86_64.sbom.txt" "$d/builder-vm-x86_64-checksums-sha256.txt"
if run "$d"; then ok "absent pack is accepted"; else bad "absent pack should be accepted"; fi
rm -rf "$d"

# 4. Complete pack but checksum tampered → fail closed.
d="$(build_valid_fixture)"
printf 'tampered\n' > "$d/builder-vm-aarch64.pack-manifest.json"   # bytes no longer match recorded hash
if run "$d"; then bad "checksum-mismatched pack must fail"; else ok "checksum-mismatched pack fails closed"; fi
rm -rf "$d"

# 5. Complete pack but its file is not listed in the checksums manifest → fail.
d="$(build_valid_fixture)"
: > "$d/builder-vm-aarch64-checksums-sha256.txt"   # empty: nothing listed
if run "$d"; then bad "unlisted pack files must fail"; else ok "unlisted pack files fail closed"; fi
rm -rf "$d"

echo "verify-release-assets pack-gate: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ]
