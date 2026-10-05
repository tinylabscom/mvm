#!/bin/sh
set -eu

# Evaluates the root flake's dev shells; it builds nothing. Run it inside the
# project builder VM, or on a host that already has Nix: the merge-queue Nix
# flake check lane runs it on its runner.
workspace_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "${workspace_root}"

system="$(nix --extra-experimental-features 'nix-command flakes' eval --impure --raw --expr builtins.currentSystem)"

shell_inputs() {
  shell="$1"
  derivation="$(nix --extra-experimental-features 'nix-command flakes' eval --raw ".#devShells.${system}.${shell}.drvPath")"
  nix --extra-experimental-features 'nix-command flakes' derivation show "${derivation}"
}

default_inputs="$(shell_inputs default)"
full_inputs="$(shell_inputs full)"

# Match an input derivation by its store-path base name, so the check holds
# whether or not this Nix version's derivation JSON includes the store
# directory.
store_name='[0-9a-z]{32}'

if printf '%s\n' "${default_inputs}" | grep -Eq "${store_name}-([^\" /]+-)?(zig|cargo-zigbuild|clang)-[^\" ]+\\.drv"; then
  echo 'default devShell must not pull in Zig, cargo-zigbuild, or libclang' >&2
  exit 1
fi

for package in zig clang; do
  if ! printf '%s\n' "${full_inputs}" | grep -Eq "${store_name}-([^\" /]+-)?${package}-[^\" ]+\\.drv"; then
    echo "full devShell must include ${package}" >&2
    exit 1
  fi
done
