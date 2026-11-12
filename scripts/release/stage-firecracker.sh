#!/usr/bin/env bash
# Stage the pinned Firecracker into a release archive.
#
# Usage: scripts/release/stage-firecracker.sh [--base-url URL] <x86_64|aarch64> <dest-dir>
#
# Fetches the upstream release tarball named by `crates/mvm-core/firecracker.lock`,
# refuses it unless its digest is the locked one, extracts the `firecracker`
# binary with its LICENSE and NOTICE, refuses the binary unless its digest and
# size are the locked ones, and writes them to <dest-dir>. A release archive that
# carries this directory needs nothing from the network to boot its first guest,
# and its signature then covers the bytes the pin names.
#
# Upstream hosting is trusted for availability only. Every byte that reaches
# <dest-dir> was checked against the lock first, so where the tarball came from
# does not matter: --base-url (a directory URL, `file://` allowed) exists so the
# tests can serve a tarball they built.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
reader="$here/../locked-firecracker.sh"

fail() { echo "stage-firecracker: $*" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

size_of() { wc -c < "$1" | tr -d ' '; }

base_url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --base-url) [ $# -ge 2 ] || fail "--base-url needs a value"; base_url="$2"; shift 2 ;;
    --) shift; break ;;
    -*) fail "unknown option $1" ;;
    *) break ;;
  esac
done
[ $# -eq 2 ] || fail "usage: stage-firecracker.sh [--base-url URL] <x86_64|aarch64> <dest-dir>"
arch="$1"
dest="$2"
case "$arch" in
  x86_64|aarch64) ;;
  *) fail "architecture must be x86_64 or aarch64, not $arch" ;;
esac

repository="$("$reader" repository)"
version="$("$reader" version)"
tarball="$("$reader" tarball "$arch")"
tarball_sha256="$("$reader" tarball_sha256 "$arch")"
binary="$("$reader" binary "$arch")"
binary_sha256="$("$reader" binary_sha256 "$arch")"
binary_size="$("$reader" binary_size "$arch")"
member_dir="$(dirname "$binary")"

if [ -z "$base_url" ]; then
  base_url="https://github.com/${repository}/releases/download/${version}"
  protocols="=https"
else
  protocols="=https,file"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The tests set STAGE_FIRECRACKER_RETRIES=0 so a refusal is immediate.
curl --proto "$protocols" --tlsv1.2 -fsSL \
  --retry "${STAGE_FIRECRACKER_RETRIES:-6}" --retry-delay 5 --retry-all-errors --retry-max-time 180 \
  -o "$work/$tarball" "$base_url/$tarball" \
  || fail "could not download $base_url/$tarball"

got="$(sha256_of "$work/$tarball")"
[ "$got" = "$tarball_sha256" ] \
  || fail "$tarball is $got, but the lock pins $tarball_sha256; nothing was staged"

tar -xzf "$work/$tarball" -C "$work" "$binary" "$member_dir/LICENSE" "$member_dir/NOTICE" \
  || fail "$tarball does not contain $binary with its LICENSE and NOTICE"

extracted="$work/$binary"
[[ -f "$extracted" && ! -L "$extracted" ]] || fail "$binary is not a regular file"
got="$(sha256_of "$extracted")"
[ "$got" = "$binary_sha256" ] \
  || fail "$binary is $got, but the lock pins $binary_sha256; nothing was staged"
got="$(size_of "$extracted")"
[ "$got" = "$binary_size" ] \
  || fail "$binary is $got bytes, but the lock pins $binary_size; nothing was staged"
[ "$(head -c 4 "$extracted" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] \
  || fail "$binary is not an ELF executable"

mkdir -p "$dest"
install -m 0755 "$extracted" "$dest/firecracker"
install -m 0644 "$work/$member_dir/LICENSE" "$dest/LICENSE"
install -m 0644 "$work/$member_dir/NOTICE" "$dest/NOTICE"

echo "staged firecracker $version ($arch) in $dest: sha256=$binary_sha256 size=$binary_size"
