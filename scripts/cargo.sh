#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Keep compilation isolated to this worktree.
# shellcheck source=scripts/cargo-target-dir-guard.sh
source "${workspace_root}/scripts/cargo-target-dir-guard.sh"
toolchain="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' "${workspace_root}/rust-toolchain.toml")"
rustc_bin="$(rustup which --toolchain "${toolchain}" rustc)"
cargo_bin="$(rustup which --toolchain "${toolchain}" cargo)"
toolchain_bin="$(dirname "${cargo_bin}")"

PATH="${toolchain_bin}:${PATH}" \
RUSTUP_TOOLCHAIN="${toolchain}" \
RUSTC="${rustc_bin}" \
  export PATH RUSTUP_TOOLCHAIN RUSTC

if [[ "${1:-}" == "--direct" ]]; then
  shift
  exec "$@"
fi

exec "${cargo_bin}" "$@"
