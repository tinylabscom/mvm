#!/usr/bin/env bash
# Hermetic test of the package-version mapping in build-distro-packages.sh:
# cargo-deb and cargo-generate-rpm are stubbed to record the version they get.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "${work}/bin"
cat > "${work}/bin/cargo" <<'S'
#!/usr/bin/env bash
sub="$1"; shift
out=""; ver=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out="$2"; shift ;;
    --deb-version) ver="$2"; shift ;;
    --set-metadata) ver="$(sed 's/version = "\(.*\)"/\1/' <<<"$2")-1"; shift ;;
  esac; shift
done
case "${sub}" in
  deb) : > "${out}/mvmctl_${ver}_amd64.deb"; echo "${out}/mvmctl_${ver}_amd64.deb" ;;
  generate-rpm) : > "${out}/mvmctl-${ver}.x86_64.rpm" ;;
esac
S
chmod +x "${work}/bin/cargo"

build() { # <version> <out-dir>; runs in the throwaway repo
  local v="$1" rt="${work}/mvm-guest-bins-v$1.tar.gz"
  echo rt > "${rt}"
  ( cd "${work}" && shasum -a 256 "$(basename "${rt}")" > "${rt}.sha256" )
  ( cd "${work}/repo" && PATH="${work}/bin:${PATH}" bash "${repo}/scripts/build-distro-packages.sh" \
      "${work}/t.tar.gz" x86_64-unknown-linux-gnu "$v" "$2" "${rt}" >/dev/null 2>&1 )
}

pkg="${work}/src/mvmctl-x86_64-unknown-linux-gnu"
mkdir -p "${pkg}/man" "${work}/repo"
: > "${pkg}/README.md"
: > "${pkg}/man/mvmctl.1"
printf '[package.metadata.deb]\n' > "${work}/repo/Cargo.toml"
( cd "${work}/repo" && git init -q && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m t )

for v in 0.27.0 0.27.0-rc.3; do
  # Rewrite the script the tarball carries so its reported version matches.
  printf '#!/bin/sh\necho "mvmctl %s"\n' "$v" > "${pkg}/mvmctl"; chmod +x "${pkg}/mvmctl"
  tar czf "${work}/t.tar.gz" -C "${work}/src" mvmctl-x86_64-unknown-linux-gnu
  build "$v" "${work}/out-$v" || fail "build of $v failed"
done

ls "${work}/out-0.27.0" | grep -qx 'mvmctl_0.27.0-1_amd64.deb' || fail "stable deb name changed"
ls "${work}/out-0.27.0" | grep -qx 'mvmctl-0.27.0-1.x86_64.rpm' || fail "stable rpm name changed"
ls "${work}/out-0.27.0-rc.3" | grep -qx 'mvmctl_0.27.0~rc.3-1_amd64.deb' || fail "rc deb not mapped"
ls "${work}/out-0.27.0-rc.3" | grep -qx 'mvmctl-0.27.0~rc.3-1.x86_64.rpm' || fail "rc rpm not mapped"

if command -v dpkg >/dev/null; then
  dpkg --compare-versions 0.27.0~rc.2 lt 0.27.0 || fail "dpkg: rc must sort before final"
  dpkg --compare-versions 0.27.0~rc.2 lt 0.27.0~rc.10 || fail "dpkg: rc.2 before rc.10"
fi
if command -v rpm >/dev/null; then
  [ "$(rpm --eval '%{lua:print(rpm.vercmp("0.27.0~rc.2","0.27.0"))}')" = -1 ] || fail "rpm: rc must sort before final"
fi

for bad in v0.27.0 "" 0.27 "0.27.0 x" "0.27.0-rc/1"; do
  if build "${bad}" "${work}/o" 2>/dev/null; then
    fail "version '${bad}' was accepted"
  fi
done
echo ok
