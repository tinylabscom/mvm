#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A foreign CARGO_TARGET_DIR would let this build type-check against
# artifacts cargo recycled from another source tree (mtime-fresh, content-
# stale). Reclaim it before anything resolves the target dir.
# shellcheck source=scripts/cargo-target-dir-guard.sh
source "${workspace_root}/scripts/cargo-target-dir-guard.sh"
fast_toolchain="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' "${workspace_root}/rust-toolchain.toml")"
rustc_bin="$(rustup which --toolchain "${fast_toolchain}" rustc)"
cargo_bin="$(rustup which --toolchain "${fast_toolchain}" cargo)"
toolchain_bin="$(dirname "${cargo_bin}")"

PATH="${toolchain_bin}:${PATH}" \
RUSTUP_TOOLCHAIN="${fast_toolchain}" \
RUSTC="${rustc_bin}" \
  exec "${cargo_bin}" \
  --config "${workspace_root}/.cargo/fast.toml" \
  "$@"
