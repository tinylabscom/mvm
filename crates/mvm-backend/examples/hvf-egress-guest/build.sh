#!/usr/bin/env bash
# Build the HVF egress relay live-proof guest initramfs.
#
# Compiles the freestanding aarch64 init (raw syscalls, no libc) with zig and
# packs a newc cpio containing /init and an empty /proc mount point. The proof
# harness (examples/hvf-backend-egress) boots this as the guest initramfs.
#
# Output: $OUT/initramfs.cpio (default: /tmp/hvf-egress-guest/initramfs.cpio).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${OUT:-/tmp/hvf-egress-guest}"
mkdir -p "$out"

# Freestanding static aarch64 ELF; _start is the entry, no crt/libc.
zig cc -target aarch64-linux -nostdlib -static -Os -Wl,-e,_start \
    -o "$out/init" "$here/init.c"

# Pack a newc cpio with /init + an empty /proc for the procfs mount.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 0755 "$work"
install -m 0755 "$out/init" "$work/init"
mkdir -m 0755 "$work/proc"
( cd "$work" && find . | cpio -o -H newc ) > "$out/initramfs.cpio"

echo "built $out/initramfs.cpio"
