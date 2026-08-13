#!/bin/sh
set -euo pipefail
export HOME=/tmp
export RUSTUP_HOME=/tmp/rustup
export CARGO_HOME=/tmp/cargo
mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"
cd /work
nix --extra-experimental-features 'nix-command flakes' shell nixpkgs#rustup nixpkgs#gcc nixpkgs#binutils nixpkgs#lld -c sh -c '
  rustup toolchain install 1.96.0 --profile minimal --component clippy
  rustup default 1.96.0
  cargo clippy -p mvm-vmm --all-targets -- -D warnings
'
