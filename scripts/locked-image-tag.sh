#!/bin/sh
# Print a release tag pinned by `crates/mvm-core/images.lock`.
#
# Usage: scripts/locked-image-tag.sh [image_set|boot_image|stage0_kernel] [field]
#
# The Rust side reads the same file through
# `mvm_core::image_set::image_train_lock()`, and `xtask release-boot-image tag`
# prints the boot-image tag from there. This reader exists because the jobs that
# need the tag are not all Rust jobs: `ci-full.yml`'s bounded no-KVM builder
# installs a prebuilt binary and carries no toolchain and no cargo cache, so
# resolving one string through cargo would cost it a full xtask build. Reading
# the lock is not a second copy of the pin, and `xtask check-image-lock` fails
# the build if this reader and the parsed lock disagree.

set -eu

section="${1:-image_set}"
field="${2:-release_tag}"
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
lock="$root/crates/mvm-core/images.lock"

if [ ! -f "$lock" ]; then
  echo "locked-image-tag: $lock does not exist" >&2
  exit 1
fi

case "$field" in
  repository)
    value=$(sed -n 's/^repository[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$lock" | head -n 1)
    ;;
  workflow|tag_ref)
    value=$(sed -n "/^\\[$section.signing_identity\\]/,/^\\[/ s/^$field[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$lock")
    ;;
  release_tag|manifest_asset|manifest_sha256)
    value=$(sed -n "/^\\[$section\\]/,/^\\[/ s/^$field[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$lock")
    ;;
  *)
    echo "locked-image-tag: unsupported field $field" >&2
    exit 1
    ;;
esac

if [ -z "$value" ]; then
  echo "locked-image-tag: images.lock pins no $field under [$section]" >&2
  exit 1
fi

printf '%s\n' "$value"
