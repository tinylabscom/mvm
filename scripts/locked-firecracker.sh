#!/bin/sh
# Print a Firecracker pin from `crates/mvm-core/firecracker.lock`.
#
# Usage: scripts/locked-firecracker.sh repository|version
#        scripts/locked-firecracker.sh tarball|tarball_sha256|binary|binary_sha256|binary_size x86_64|aarch64
#
# The Rust side reads the same file through
# `mvm_core::firecracker_lock::firecracker_lock()`. This reader exists because
# the jobs that need a pin are not all Rust jobs, and resolving one string
# through cargo would cost them a full build. Reading the lock is not a second
# copy of the pin, and `xtask check-firecracker-pin` fails the build if this
# reader and the parsed lock disagree.

set -eu

field="${1:-version}"
arch="${2:-}"
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
lock="$root/crates/mvm-core/firecracker.lock"

if [ ! -f "$lock" ]; then
  echo "locked-firecracker: $lock does not exist" >&2
  exit 1
fi

case "$field" in
  repository|version)
    value=$(sed -n "s/^${field}[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$lock" | head -n 1)
    ;;
  tarball|tarball_sha256|binary|binary_sha256)
    case "$arch" in
      x86_64|aarch64) ;;
      *) echo "locked-firecracker: $field needs an architecture (x86_64 or aarch64)" >&2; exit 1 ;;
    esac
    value=$(sed -n "/^\\[${arch}\\]/,/^\\[/ s/^${field}[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$lock")
    ;;
  binary_size)
    case "$arch" in
      x86_64|aarch64) ;;
      *) echo "locked-firecracker: $field needs an architecture (x86_64 or aarch64)" >&2; exit 1 ;;
    esac
    value=$(sed -n "/^\\[${arch}\\]/,/^\\[/ s/^binary_size[[:space:]]*=[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$lock")
    ;;
  *)
    echo "locked-firecracker: unsupported field $field" >&2
    exit 1
    ;;
esac

if [ -z "$value" ]; then
  echo "locked-firecracker: $lock pins no $field${arch:+ for $arch}" >&2
  exit 1
fi

printf '%s\n' "$value"
