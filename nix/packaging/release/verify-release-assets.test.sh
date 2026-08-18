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
KERNEL_ARCHES="aarch64 x86_64"
RUNTIME_ARCHES="aarch64 x86_64"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# The boot-asset gate reads /init out of the rootfs with debugfs, so a
# placeholder file cannot exercise it — these fixtures need a real ext4.
# `mkfs.ext4 -d` builds one from a directory with no root and no loop device.
# Absent that tooling (macOS), the boot checks are switched off via
# --boot-arches and their scenarios are skipped rather than faked green.
BOOT_TOOLS=0
if command -v mkfs.ext4 >/dev/null 2>&1 && command -v debugfs >/dev/null 2>&1; then
  BOOT_TOOLS=1
fi
BOOT_ARCHES="aarch64 x86_64"

# Write a kernel fixture at $1 carrying $2's real magic, because the boot-asset
# gate reads the format rather than trusting the file name — which is the whole
# point of it. `bad` writes a bzImage, the format that actually shipped.
make_kernel() {
  case "$2" in
    aarch64) # arm64 Image: "ARM\x64" at offset 56.
      { head -c 56 /dev/zero; printf 'ARMd'; head -c 4 /dev/zero; } > "$1" ;;
    x86_64)  # ELF magic at 0.
      { printf '\177ELF'; head -c 60 /dev/zero; } > "$1" ;;
    bad)     # bzImage: 0xAA55 boot signature at 510, "HdrS" at 514.
      { head -c 510 /dev/zero; printf '\125\252HdrS'; } > "$1" ;;
  esac
}

# Write an ext4 at $1 whose /init has $2 as its first line.
make_rootfs() {
  root="$(mktemp -d)"
  printf '%s\n# mvm /init fixture\nexit 0\n' "$2" > "$root/init"
  chmod 0500 "$root/init"
  mkfs.ext4 -F -q -d "$root" "$1" 2M >/dev/null 2>&1
  rm -rf "$root"
}

bins_for() {
  case "$1" in
    *apple-darwin) echo "mvmctl mvm-hvf-supervisor mvm-libkrun-supervisor mvm-network-endpoint" ;;
    *)             echo "mvmctl mvm-network-endpoint" ;;
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
  printf 'bundle\n' > "$dir/checksums-sha256.txt.bundle"
  for arch in $KERNEL_ARCHES; do
    printf 'kernel-%s-workload\n' "$arch" > "$dir/vmlinux-$arch-workload"
    : > "$dir/kernel-$arch-checksums-sha256.txt"
    echo "$(sha256_of "$dir/vmlinux-$arch-workload")  vmlinux-$arch-workload" >> "$dir/kernel-$arch-checksums-sha256.txt"
    printf 'bundle\n' > "$dir/kernel-$arch-checksums-sha256.txt.bundle"
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
    printf 'bundle\n' > "$dir/builder-vm-$arch-checksums-sha256.txt.bundle"
  done
  for arch in $RUNTIME_ARCHES; do
    printf '{"pack":"runtime-%s"}\n' "$arch" > "$dir/default-microvm-$arch.pack-manifest.json"
    printf 'sigstore-bundle\n'              > "$dir/default-microvm-$arch.pack-manifest.json.bundle"
    printf 'store-path-a\nstore-path-b\n'   > "$dir/default-microvm-$arch.sbom.txt"
    : > "$dir/default-microvm-$arch-checksums-sha256.txt"
    for f in "default-microvm-$arch.pack-manifest.json" "default-microvm-$arch.pack-manifest.json.bundle" "default-microvm-$arch.sbom.txt"; do
      echo "$(sha256_of "$dir/$f")  $f" >> "$dir/default-microvm-$arch-checksums-sha256.txt"
    done
    printf 'bundle\n' > "$dir/default-microvm-$arch-checksums-sha256.txt.bundle"
  done
  if [ "$BOOT_TOOLS" = 1 ]; then
    for arch in $BOOT_ARCHES; do
      make_rootfs "$dir/default-microvm-rootfs-$arch.ext4" '#!/bin/sh'
      make_kernel "$dir/default-microvm-vmlinux-$arch" "$arch"
      printf '{"meta":"%s"}\n' "$arch" > "$dir/default-microvm-meta-$arch.json"
      for f in "default-microvm-rootfs-$arch.ext4" "default-microvm-vmlinux-$arch" \
               "default-microvm-meta-$arch.json"; do
        echo "$(sha256_of "$dir/$f")  $f" >> "$dir/default-microvm-$arch-checksums-sha256.txt"
      done
    done
  fi
  echo "$dir"
}

# Returns the script's exit code.
run() {
  if [ "$BOOT_TOOLS" = 1 ]; then
    bash "$SCRIPT" --assets-dir "$1" >/dev/null 2>&1
  else
    bash "$SCRIPT" --assets-dir "$1" --boot-arches "" >/dev/null 2>&1
  fi
}

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

# 6. Partial runtime pack (bundle missing) → fail closed.
d="$(build_valid_fixture)"
rm -f "$d/default-microvm-aarch64.pack-manifest.json.bundle"
if run "$d"; then bad "partial runtime pack (missing bundle) must fail"; else ok "partial runtime pack (missing bundle) fails closed"; fi
rm -rf "$d"

# 7. Absent runtime pack (all three gone) → pass (accelerator absent).
# The per-arch manifest covers the boot assets too, and the job that writes it
# writes both, so "no manifest" only ever means "the whole image job shipped
# nothing" — drop the boot assets with it rather than fixture an impossible state.
d="$(build_valid_fixture)"
rm -f "$d/default-microvm-x86_64.pack-manifest.json" "$d/default-microvm-x86_64.pack-manifest.json.bundle" \
      "$d/default-microvm-x86_64.sbom.txt" "$d/default-microvm-x86_64-checksums-sha256.txt" \
      "$d/default-microvm-rootfs-x86_64.ext4" "$d/default-microvm-vmlinux-x86_64" \
      "$d/default-microvm-meta-x86_64.json"
if run "$d"; then ok "absent runtime pack is accepted"; else bad "absent runtime pack should be accepted"; fi
rm -rf "$d"

# 8. Complete runtime pack but checksum tampered → fail closed.
d="$(build_valid_fixture)"
printf 'tampered\n' > "$d/default-microvm-aarch64.pack-manifest.json"
if run "$d"; then bad "checksum-mismatched runtime pack must fail"; else ok "checksum-mismatched runtime pack fails closed"; fi
rm -rf "$d"

# 9. Missing kernel checksums manifest → fail closed.
d="$(build_valid_fixture)"
rm -f "$d/kernel-aarch64-checksums-sha256.txt"
if run "$d"; then bad "missing kernel checksums manifest must fail"; else ok "missing kernel checksums manifest fails closed"; fi
rm -rf "$d"

# 9b. A checksum manifest without its signature bundle → fail closed.
#
# The manifest is what every downloader anchors on, so an unsigned one lets
# whoever can swap an artifact swap its recorded digest too. Each of these
# deletes only the bundle, leaving a manifest that still parses and still
# matches its artifacts — the failure mode that is otherwise invisible until a
# release ships.
for manifest in checksums-sha256.txt kernel-aarch64-checksums-sha256.txt \
                builder-vm-aarch64-checksums-sha256.txt \
                default-microvm-aarch64-checksums-sha256.txt; do
  d="$(build_valid_fixture)"
  rm -f "$d/$manifest.bundle"
  if run "$d"; then bad "unsigned $manifest must fail"; else ok "unsigned $manifest fails closed"; fi
  rm -rf "$d"
done

# 10. Workload kernel present but absent from per-arch kernel manifest → fail.
d="$(build_valid_fixture)"
: > "$d/kernel-x86_64-checksums-sha256.txt"
if run "$d"; then bad "unlisted workload kernel must fail"; else ok "unlisted workload kernel fails closed"; fi
rm -rf "$d"

# 11. Workload kernel checksum mismatch → fail closed.
d="$(build_valid_fixture)"
printf 'tampered-kernel\n' > "$d/vmlinux-aarch64-workload"
if run "$d"; then bad "checksum-mismatched workload kernel must fail"; else ok "checksum-mismatched workload kernel fails closed"; fi
rm -rf "$d"

# 13-16. The boot-asset gate. These need a real ext4 (see make_rootfs), so they
# are skipped where e2fsprogs is absent — which is also where `run` switches the
# gate off, so the suite stays honest rather than reporting checks it never ran.
if [ "$BOOT_TOOLS" = 1 ]; then
  # 13. THE REGRESSION. A rootfs whose /init has its `#!` one column right of
  # byte 0 — byte-for-byte what v0.17.0 published. Every checksum still matches;
  # only reading /init catches it.
  d="$(build_valid_fixture)"
  make_rootfs "$d/default-microvm-rootfs-aarch64.ext4" ' #!/bin/sh'
  # Re-record the hash, so the image is a *faithful* copy of a broken build and
  # the checksum layer has nothing to say about it.
  grep -v ' default-microvm-rootfs-aarch64.ext4$' \
    "$d/default-microvm-aarch64-checksums-sha256.txt" > "$d/.checks.tmp"
  mv "$d/.checks.tmp" "$d/default-microvm-aarch64-checksums-sha256.txt"
  echo "$(sha256_of "$d/default-microvm-rootfs-aarch64.ext4")  default-microvm-rootfs-aarch64.ext4" \
    >> "$d/default-microvm-aarch64-checksums-sha256.txt"
  if run "$d"; then bad "a /init shebang off byte 0 must fail"; else ok "/init shebang off byte 0 fails closed"; fi
  rm -rf "$d"

  # 14. Partial boot assets (rootfs gone, kernel + meta still there) → fail.
  d="$(build_valid_fixture)"
  rm -f "$d/default-microvm-rootfs-aarch64.ext4"
  if run "$d"; then bad "partial boot assets must fail"; else ok "partial boot assets fail closed"; fi
  rm -rf "$d"

  # 15. Boot assets entirely absent → pass (image job did not ship; `release`
  # publishes the binary download regardless).
  d="$(build_valid_fixture)"
  rm -f "$d/default-microvm-rootfs-x86_64.ext4" "$d/default-microvm-vmlinux-x86_64" \
        "$d/default-microvm-meta-x86_64.json"
  if run "$d"; then ok "absent boot assets are accepted"; else bad "absent boot assets should be accepted"; fi
  rm -rf "$d"

  # 16. Rootfs bytes do not match the recorded hash → fail closed.
  d="$(build_valid_fixture)"
  printf 'tampered-rootfs\n' > "$d/default-microvm-rootfs-aarch64.ext4"
  if run "$d"; then bad "checksum-mismatched rootfs must fail"; else ok "checksum-mismatched rootfs fails closed"; fi
  rm -rf "$d"
  # 17. THE REGRESSION. A bzImage published under the name `vmlinux`.
  # Every checksum still matches — it is a faithful copy of the wrong format —
  # so only reading the magic catches it. Firecracker's x86_64 loader refuses
  # it before any guest code runs.
  d="$(build_valid_fixture)"
  make_kernel "$d/default-microvm-vmlinux-x86_64" bad
  grep -v ' default-microvm-vmlinux-x86_64$' \
    "$d/default-microvm-x86_64-checksums-sha256.txt" > "$d/.k.tmp"
  mv "$d/.k.tmp" "$d/default-microvm-x86_64-checksums-sha256.txt"
  echo "$(sha256_of "$d/default-microvm-vmlinux-x86_64")  default-microvm-vmlinux-x86_64" \
    >> "$d/default-microvm-x86_64-checksums-sha256.txt"
  if run "$d"; then bad "a bzImage named vmlinux must fail"; else ok "a bzImage named vmlinux fails closed"; fi
  rm -rf "$d"

else
  echo "  skip: boot-asset gate (mkfs.ext4/debugfs not on PATH)"
fi

# 12. Every binary the verifier REQUIRES must be one release.yml actually
# bundles. The fixtures above cannot catch a stale name: build_valid_fixture
# creates whatever bins_for names, so a required-but-unbuilt binary verifies
# green here and fails only at release time. Compare against the workflow.
RELEASE_YML="$HERE/../../../.github/workflows/release.yml"
# `release.yml` builds its list into a shell variable and then loops over it,
# so reading the `for` line yields the literal `${REQUIRED_HOSTBINS}` and every
# required bin looks like drift. Union the assignments instead — including the
# conditional one that appends the macOS supervisors — and drop the
# self-reference the append carries.
# shellcheck disable=SC2016  # the ${REQUIRED_HOSTBINS} below is a literal to
# strip out of the workflow's text, not a variable for this shell to expand.
shipped="mvmctl $(sed -n 's/^[[:space:]]*REQUIRED_HOSTBINS="\(.*\)"[[:space:]]*$/\1/p' "$RELEASE_YML" \
  | sed 's/\${REQUIRED_HOSTBINS}//g' | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')"
required="$(sed -n '/^required_bins_for_target()/,/^}/p' "$SCRIPT" \
  | sed -n 's/.*echo "\([^"]*\)".*/\1/p' | tr ' ' '\n' | sort -u)"
drift=""
for b in $required; do
  case " $shipped " in *" $b "*) ;; *) drift="$drift $b" ;; esac
done
if [ -n "$required" ] && [ -z "$drift" ]; then
  ok "every required bin is one release.yml ships"
else
  bad "verifier requires bin(s) release.yml never builds:${drift:- <none parsed>}"
fi

echo "verify-release-assets pack-gate: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ]
