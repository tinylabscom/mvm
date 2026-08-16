#!/usr/bin/env bash
# Assert a default-microvm rootfs carries a /init the kernel can exec.
#
# The kernel exec()s /init directly, so `#!` must be the first two bytes of the
# file. Shift them by even one column and the boot dies with ENOEXEC before any
# userspace runs, leaving a kernel panic as the only symptom — which is what
# v0.17.0 published. Checksums cannot catch it: a faithful copy of a broken
# image is still faithful.
#
# Reads the bytes straight out of the unmounted ext4 with debugfs: no mount, no
# loop device, no root. Called twice — once on the staged image before it is
# uploaded (release.yml `default-microvm`), once on the published image after it
# is downloaded again (verify-release-assets.sh).
#
# Usage: assert-init-shebang.sh ROOTFS_EXT4 [LABEL]
set -euo pipefail

INIT_SHEBANG='#!/bin/sh'

rootfs="${1:-}"
[ -n "$rootfs" ] || { echo "usage: assert-init-shebang.sh ROOTFS_EXT4 [LABEL]" >&2; exit 2; }
label="${2:-$(basename "$rootfs")}"

[ -f "$rootfs" ] || { echo "::error::[$label] rootfs not found: $rootfs" >&2; exit 1; }
command -v debugfs >/dev/null 2>&1 || {
  echo "::error::[$label] debugfs (e2fsprogs) not on PATH — cannot read /init out of the rootfs" >&2
  exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! debugfs -R "dump /init $tmp/init" "$rootfs" >/dev/null 2>&1 || [ ! -s "$tmp/init" ]; then
  echo "::error::[$label] could not read /init out of $(basename "$rootfs")" >&2
  exit 1
fi

init_head=$(head -c "${#INIT_SHEBANG}" "$tmp/init")
if [ "$init_head" != "$INIT_SHEBANG" ]; then
  echo "::error::[$label] /init does not begin with '$INIT_SHEBANG' (got '$init_head') — the kernel panics with ENOEXEC before userspace" >&2
  exit 1
fi

echo "ok: [$label] /init begins with '$INIT_SHEBANG' at byte 0"
