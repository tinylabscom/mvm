#!/usr/bin/env bash
# Focused tests for verify-release-assets.sh: a release whose binary archives,
# distro packages, combined checksum manifest and SBOM are complete and signed
# verifies; one with a missing signature, a drifted digest, an unlisted
# archive or package, a missing or duplicated package, or a missing packaged
# binary fails closed. Runs the real script (no --cosign, no
# --expect-version, so the OIDC/host-version checks are skipped) against
# fixtures built here. No network, no cosign.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/verify-release-assets.sh"
TARGETS="aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

bins_for() {
  case "$1" in
    *apple-darwin) echo "mvmctl mvm-hvf-supervisor mvm-network-endpoint" ;;
    *)             echo "mvmctl mvm-network-endpoint" ;;
  esac
}

# Signed, listed distro packages for a Linux target, the way the release
# publishes them. Contents are placeholders: the verifier checks presence,
# signature bundle and manifest digest, not the payload.
add_packages() {
  local dir="$1" deb_arch="$2" rpm_arch="$3"
  for pkg in "mvmctl_0.0.0-1_${deb_arch}.deb" "mvmctl-0.0.0-1.${rpm_arch}.rpm"; do
    printf '%s\n' "$pkg" > "$dir/$pkg"
    printf 'bundle\n' > "$dir/$pkg.bundle"
    echo "$(sha256_of "$dir/$pkg")  $pkg" >> "$dir/checksums-sha256.txt"
  done
}

# Build a fully-valid release-assets dir (every tarball/package/manifest/SBOM
# check passes). Echoes the dir path.
build_valid_fixture() {
  local dir; dir="$(mktemp -d)"
  : > "$dir/checksums-sha256.txt"
  for t in $TARGETS; do
    local pkg="$dir/mvmctl-$t"
    mkdir -p "$pkg"
    for b in $(bins_for "$t"); do printf '#!/bin/sh\n' > "$pkg/$b"; chmod +x "$pkg/$b"; done
    ( cd "$dir" && tar czf "mvmctl-$t.tar.gz" "mvmctl-$t" && rm -rf "mvmctl-$t" )
    printf 'bundle\n' > "$dir/mvmctl-$t.tar.gz.bundle"
    echo "$(sha256_of "$dir/mvmctl-$t.tar.gz")  mvmctl-$t.tar.gz" >> "$dir/checksums-sha256.txt"
  done
  add_packages "$dir" amd64 x86_64
  add_packages "$dir" arm64 aarch64
  printf 'bundle\n' > "$dir/checksums-sha256.txt.bundle"
  printf '{"sbom":true}\n' > "$dir/sbom.cdx.json"
  printf 'bundle\n' > "$dir/sbom.cdx.json.bundle"
  echo "$dir"
}

# Returns the script's exit code.
run() {
  bash "$SCRIPT" --assets-dir "$1" >/dev/null 2>&1
}

PASS=0; FAILN=0
ok()   { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()  { FAILN=$((FAILN+1)); echo "  FAIL: $1" >&2; }

# 1. A complete release → pass.
d="$(build_valid_fixture)"
if run "$d"; then ok "complete release verifies"; else bad "complete release should verify"; fi
rm -rf "$d"

# 2. The combined checksum manifest without its signature bundle → fail closed.
# The installer anchors on that manifest, so an unsigned one lets whoever can
# swap an archive swap its recorded digest too. Only the bundle goes, leaving a
# manifest that still parses and still matches — the failure mode that is
# otherwise invisible until a release ships.
d="$(build_valid_fixture)"
rm -f "$d/checksums-sha256.txt.bundle"
if run "$d"; then bad "unsigned combined manifest must fail"; else ok "unsigned combined manifest fails closed"; fi
rm -rf "$d"

# 3. An archive whose bytes no longer match the signed manifest → fail closed.
d="$(build_valid_fixture)"
t=x86_64-unknown-linux-gnu
grep -v "mvmctl-$t.tar.gz" "$d/checksums-sha256.txt" > "$d/.c.tmp"
echo "0000000000000000000000000000000000000000000000000000000000000000  mvmctl-$t.tar.gz" >> "$d/.c.tmp"
mv "$d/.c.tmp" "$d/checksums-sha256.txt"
if run "$d"; then bad "a drifted archive digest must fail"; else ok "a drifted archive digest fails closed"; fi
rm -rf "$d"

# 4. An archive the combined manifest does not list → fail closed.
d="$(build_valid_fixture)"
grep -v 'mvmctl-aarch64-apple-darwin.tar.gz' "$d/checksums-sha256.txt" > "$d/.c.tmp"
mv "$d/.c.tmp" "$d/checksums-sha256.txt"
if run "$d"; then bad "an unlisted archive must fail"; else ok "an unlisted archive fails closed"; fi
rm -rf "$d"

# 5. An archive without its signature bundle → fail closed.
d="$(build_valid_fixture)"
rm -f "$d/mvmctl-aarch64-unknown-linux-gnu.tar.gz.bundle"
if run "$d"; then bad "an unsigned archive must fail"; else ok "an unsigned archive fails closed"; fi
rm -rf "$d"

# 6. An unsigned SBOM → fail closed.
d="$(build_valid_fixture)"
rm -f "$d/sbom.cdx.json.bundle"
if run "$d"; then bad "an unsigned SBOM must fail"; else ok "an unsigned SBOM fails closed"; fi
rm -rf "$d"

# 7. An archive missing a binary mvmctl spawns at run time → fail closed.
d="$(build_valid_fixture)"
t=x86_64-unknown-linux-gnu
( cd "$d" && tar xzf "mvmctl-$t.tar.gz" && rm -f "mvmctl-$t/mvm-network-endpoint" \
  && tar czf "mvmctl-$t.tar.gz" "mvmctl-$t" && rm -rf "mvmctl-$t" )
grep -v "mvmctl-$t.tar.gz" "$d/checksums-sha256.txt" > "$d/.c.tmp"
echo "$(sha256_of "$d/mvmctl-$t.tar.gz")  mvmctl-$t.tar.gz" >> "$d/.c.tmp"
mv "$d/.c.tmp" "$d/checksums-sha256.txt"
if run "$d"; then bad "an archive missing a required binary must fail"; else ok "an archive missing a required binary fails closed"; fi
rm -rf "$d"

# 8. A Linux target without its .deb → fail closed.
d="$(build_valid_fixture)"
rm -f "$d"/mvmctl_*_arm64.deb "$d"/mvmctl_*_arm64.deb.bundle
if run "$d"; then bad "a missing .deb must fail"; else ok "a missing .deb fails closed"; fi
rm -rf "$d"

# 9. A package without its signature bundle → fail closed.
d="$(build_valid_fixture)"
rm -f "$d"/mvmctl-*.x86_64.rpm.bundle
if run "$d"; then bad "an unsigned .rpm must fail"; else ok "an unsigned .rpm fails closed"; fi
rm -rf "$d"

# 10. A package the signed manifest does not list → fail closed.
d="$(build_valid_fixture)"
grep -v '_amd64.deb' "$d/checksums-sha256.txt" > "$d/.c.tmp"
mv "$d/.c.tmp" "$d/checksums-sha256.txt"
if run "$d"; then bad "an unlisted .deb must fail"; else ok "an unlisted .deb fails closed"; fi
rm -rf "$d"

# 11. Two packages for one architecture → fail closed: a user cannot tell
# which one the release meant.
d="$(build_valid_fixture)"
printf 'other\n' > "$d/mvmctl_0.0.1-1_amd64.deb"
printf 'bundle\n' > "$d/mvmctl_0.0.1-1_amd64.deb.bundle"
echo "$(sha256_of "$d/mvmctl_0.0.1-1_amd64.deb")  mvmctl_0.0.1-1_amd64.deb" >> "$d/checksums-sha256.txt"
if run "$d"; then bad "two .debs for one arch must fail"; else ok "two .debs for one arch fail closed"; fi
rm -rf "$d"

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

echo "verify-release-assets: $PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ]
