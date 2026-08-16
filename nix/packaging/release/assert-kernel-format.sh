#!/usr/bin/env bash
# Assert a published kernel asset is in the format its loader accepts.
#
# The asset is named `vmlinux`, but that name has never carried a format. On
# aarch64 it is an arm64 `Image`, and that is correct — arm64 loaders take
# `Image`. On x86_64 Firecracker loads an uncompressed ELF and nothing else, so
# a bzImage published under this name dies in the loader with "Invalid Elf magic
# number": before init, before userspace, with nothing on the guest console.
# v0.17.0 shipped exactly that.
#
# Checksums cannot see this — a faithful copy of the wrong format still
# verifies. Only reading the first bytes does.
#
# Usage: assert-kernel-format.sh KERNEL_FILE ARCH [LABEL]
set -euo pipefail

kernel="${1:-}"
arch="${2:-}"
[ -n "$kernel" ] && [ -n "$arch" ] || {
  echo "usage: assert-kernel-format.sh KERNEL_FILE ARCH [LABEL]" >&2; exit 2; }
label="${3:-$(basename "$kernel")}"

[ -f "$kernel" ] || { echo "::error::[$label] kernel not found: $kernel" >&2; exit 1; }

magic0=$(od -An -tx1 -N4 "$kernel" | tr -d ' \n')
magic56=$(od -An -c -j56 -N4 "$kernel" | tr -d ' \n')

case "$arch" in
  aarch64|arm64)
    # Documentation/arm64/booting.rst: "ARM\x64" at offset 56.
    if [ "$magic56" != "ARMd" ]; then
      echo "::error::[$label] not an arm64 Image (magic@56='$magic56', want 'ARMd')" >&2
      exit 1
    fi
    echo "ok: [$label] arm64 Image (magic@56='ARMd')"
    ;;
  x86_64|amd64)
    if [ "$magic0" != "7f454c46" ]; then
      extra=""
      # 0xAA55 boot signature + "HdrS" is the x86 boot-protocol header, i.e.
      # the exact wrong-format case this exists to name.
      if [ "$(od -An -tx1 -j510 -N2 "$kernel" | tr -d ' \n')" = "55aa" ]; then
        extra=" It is a bzImage."
      fi
      echo "::error::[$label] not an ELF kernel (magic@0=0x$magic0, want 0x7f454c46).$extra" >&2
      echo "::error::[$label] Firecracker's x86_64 loader takes an uncompressed ELF vmlinux only; this boots nothing." >&2
      exit 1
    fi
    echo "ok: [$label] ELF kernel (magic@0=0x7f454c46)"
    ;;
  *)
    echo "::error::[$label] unknown arch '$arch' — refusing to guess a kernel format" >&2
    exit 1
    ;;
esac
