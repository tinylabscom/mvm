#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stable_toolchain="1.97.1"
rustc_bin="$(rustup which --toolchain "${stable_toolchain}" rustc)"
cargo_bin="$(rustup which --toolchain "${stable_toolchain}" cargo)"
toolchain_bin="$(dirname "${cargo_bin}")"
stable_target_root="${CARGO_TARGET_DIR:-${workspace_root}/target}/stable-${stable_toolchain}"

PATH="${toolchain_bin}:${PATH}" \
RUSTUP_TOOLCHAIN="${stable_toolchain}" \
RUSTC="${rustc_bin}" \
CARGO_TARGET_DIR="${stable_target_root}" \
  export PATH RUSTUP_TOOLCHAIN RUSTC CARGO_TARGET_DIR

if [[ "${1:-}" == "--direct" ]]; then
  shift
  exec "$@"
fi

exec "${cargo_bin}" "$@"
