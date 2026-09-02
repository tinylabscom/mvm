#!/bin/sh
set -euo pipefail
export HOME=/out/home
export XDG_CACHE_HOME=/out/cache
export RUSTUP_HOME=/out/rustup
export CARGO_HOME=/out/cargo
export CARGO_TARGET_DIR=/out/target
export TMPDIR=/out/tmp
mkdir -p "$HOME" "$XDG_CACHE_HOME" "$RUSTUP_HOME" "$CARGO_HOME" "$CARGO_TARGET_DIR" "$TMPDIR"
cd /work
nix --extra-experimental-features 'nix-command flakes' shell nixpkgs#rustup nixpkgs#gcc nixpkgs#binutils nixpkgs#lld -c sh -c '
  rustup toolchain install 1.97.1 --profile minimal --component clippy
  rustup default 1.97.1
  cargo clippy -p mvm-vmm --all-targets -- -D warnings
'
