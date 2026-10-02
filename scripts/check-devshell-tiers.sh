#!/bin/sh
set -eu

# Run inside the project builder VM; Nix evaluation belongs there.
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

if printf '%s\n' "${default_inputs}" | grep -Eq '(/nix/store/[^" ]+-(zig|cargo-zigbuild|clang)-[^" ]+\.drv)'; then
  echo 'default devShell must not pull in Zig, cargo-zigbuild, or libclang' >&2
  exit 1
fi

for package in zig clang; do
  if ! printf '%s\n' "${full_inputs}" | grep -Eq "/nix/store/[^\" ]+-${package}-[^\" ]+\\.drv"; then
    echo "full devShell must include ${package}" >&2
    exit 1
  fi
done
