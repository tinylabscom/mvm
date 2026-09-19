#!/bin/sh
# Print a release tag pinned by `crates/mvm-core/images.lock`.
#
# Usage: scripts/locked-image-tag.sh [boot_image|stage0_kernel]
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

section="${1:-boot_image}"
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
lock="$root/crates/mvm-core/images.lock"

if [ ! -f "$lock" ]; then
  echo "locked-image-tag: $lock does not exist" >&2
  exit 1
fi

tag=$(sed -n "/^\\[$section\\]/,/^\\[/ s/^release_tag[[:space:]]*=[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$lock")

if [ -z "$tag" ]; then
  echo "locked-image-tag: images.lock pins no release_tag under [$section]" >&2
  exit 1
fi

printf '%s\n' "$tag"
