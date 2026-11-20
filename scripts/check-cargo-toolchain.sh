#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${workspace_root}"

require_text() {
  if ! grep -Fq -- "$2" "$1"; then
    echo "check-cargo-toolchain: $1 is missing: $2" >&2
    exit 1
  fi
}

require_recipe_text() {
  if ! grep -Fq -- "$1" Justfile just/*/mod.just; then
    echo "check-cargo-toolchain: recipe tree is missing: $1" >&2
    exit 1
  fi
}

toolchain="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)"
if [[ ! "$toolchain" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "check-cargo-toolchain: pin an exact stable Rust version" >&2
  exit 1
fi
if [[ -e .cargo/fast.toml ]] || grep -Eq 'codegen-backend|threads=8' .cargo/config.toml; then
  echo "check-cargo-toolchain: ordinary builds must use the standard LLVM configuration" >&2
  exit 1
fi
if grep -Fq 'rustc-codegen-cranelift' rust-toolchain.toml; then
  echo "check-cargo-toolchain: the workspace must not require Cranelift" >&2
  exit 1
fi

require_text rust-toolchain.toml '"wasm32-wasip1"'
require_text scripts/cargo.sh 'rust-toolchain.toml'
require_text scripts/cargo.sh "RUSTUP_TOOLCHAIN=\"\${toolchain}\""
require_text scripts/cargo.sh "if [[ \"\${1:-}\" == \"--direct\" ]]"
require_recipe_text './scripts/cargo.sh build --workspace'
require_recipe_text './scripts/cargo.sh nextest run --workspace'
require_recipe_text './scripts/cargo.sh clippy --workspace --all-targets -- -D warnings'
require_recipe_text './scripts/cargo.sh --direct cargo-zigbuild check --target {{ TARGET }} --workspace --all-targets'
require_text .githooks/pre-commit "./scripts/cargo.sh clippy \$pass -- -D warnings"
require_text .githooks/pre-commit 'sweep_args="--workspace"'
require_text .githooks/pre-commit "focus_args=\"\${pkg_args# } --all-targets\""
for workflow in ci ci-main bdd workspace-shard; do
  require_text ".github/workflows/${workflow}.yml" "toolchain: ${toolchain}"
done
for workflow in ci cache-warm; do
  require_text ".github/workflows/${workflow}.yml" "uses: dtolnay/rust-toolchain@"
  require_text ".github/workflows/${workflow}.yml" "toolchain: ${toolchain}"
done

# Check literal selections, not arbitrary shell evaluation or dynamic matrices.
python3 - "$toolchain" <<'PY'
from pathlib import Path
import re
import sys

pin = sys.argv[1]
nightly_jobs = {
    (".github/workflows/ci-main.yml", "test-ebpf-telemetry"): "nightly",
    (".github/workflows/security.yml", "fuzz"): "nightly-2026-06-11",
}
selectors = re.compile(
    r"""(?:^\s*(?:toolchain|RUSTUP_TOOLCHAIN):\s*|\bRUSTUP_TOOLCHAIN=|"""
    r"""\b(?:cargo|rustc)\s+\+|\brustup\s+(?:default|toolchain\s+install)\s+)"""
    r"""["']?([A-Za-z0-9][A-Za-z0-9_.-]*)"""
)
paths = set()
for extension in ("yml", "yaml"):
    paths.update(Path(".github/workflows").glob(f"*.{extension}"))
    paths.update(Path(".github/actions").rglob(f"action.{extension}"))
for path in sorted(paths):
    job = ""
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$", line)
        if match:
            job = match[1]
        for selection in selectors.finditer(line):
            selected = selection[1]
            if selected not in (pin, nightly_jobs.get((path.as_posix(), job))):
                sys.exit(
                    f"check-cargo-toolchain: {path}:{number} ({job}): "
                    f"compiler selection must use {pin}, found {selected}"
                )

# This gate owns the first-party recipe wiring; upstream libkrun is separate.
supplier = re.compile(r"(?m)^\s*(?:rustPlatform|rust)\s*=\s*\(?import\s+\./rust-platform\.nix\b")
consumer = re.compile(r"(?m)^\s*(?:rustPlatform|rust\.rustPlatform)\.buildRustPackage\b")
ambient = re.compile(r"\b(?:pkgs|staticPkgs)(?:\.[\w-]+)*\.rustPlatform\b")
checked = 0
for path in sorted(Path("nix/packages").glob("*.nix")):
    if not (path.name.startswith("mvm-") or path.name == "mvmctl.nix"):
        continue
    text = path.read_text()
    if "buildRustPackage" not in text:
        continue
    checked += 1
    if not supplier.search(text) or not consumer.search(text) or ambient.search(text):
        sys.exit(f"check-cargo-toolchain: {path}: first-party recipe must use the pinned Rust platform")
if checked < 10:
    sys.exit(f"check-cargo-toolchain: expected at least 10 first-party Rust recipes, checked {checked}")
PY

embedded_rust="$(sed -n 's/^rust = "\([^"]*\)"$/\1/p' Cargo.toml)"
if [[ "$embedded_rust" != "$toolchain" ]]; then
  echo "check-cargo-toolchain: embedded compiler must match ${toolchain}, found ${embedded_rust}" >&2
  exit 1
fi
require_text nix/packages/embedded-rust-toolchain.nix 'import ./rust-platform.nix'
require_text nix/packages/rust-platform.nix 'mvmSrc + "/rust-toolchain.toml"'
require_text nix/packages/rust-platform.nix 'mvmSrc + "/nix/flake.lock"'
require_text nix/packages/rust-platform.nix 'pkgs.buildPackages.extend'
require_text nix/packages/rust-platform.nix 'pkgs.makeRustPlatform'
require_text nix/packages/rust-platform.nix 'cargo = toolchain;'
require_text nix/packages/rust-platform.nix 'rustc = toolchain;'
require_text nix/packages/rust-platform.nix 'targets = [ target ];'
require_text flake.nix 'fromRustupToolchainFile ./rust-toolchain.toml'
require_text crates/mvm-build/src/guest_agent_build.rs 'pinned_rust_toolchain(&spec.workspace_root)'
require_text crates/mvm-build/src/guest_agent_build.rs '.env_remove("CARGO_ENCODED_RUSTFLAGS")'
require_text crates/mvm-conformance/tests/steps/cli.rs 'var_os("CARGO_BIN_EXE_mvmctl")'

# eBPF builds core for a target stable Rust does not ship.
floating_nightly="$(grep -Ec '^[[:space:]]*toolchain: nightly[[:space:]]*$' .github/workflows/ci-main.yml || true)"
[[ "$floating_nightly" == 1 ]]
if grep -Eq '^[[:space:]]*toolchain: nightly[[:space:]]*$' .github/workflows/cache-warm.yml; then
  echo "check-cargo-toolchain: workspace cache warming must use the stable pin" >&2
  exit 1
fi
require_text .github/workflows/ci-main.yml 'cargo +nightly install --locked --version 0.11.1'
require_text .github/workflows/ci-main.yml '--no-default-features --features llvm-23 bpf-linker'
require_text crates/mvm-hostd/ebpf/rust-toolchain.toml 'channel = "nightly"'

echo "check-cargo-toolchain: ordinary builds use Rust ${toolchain}; nightly tooling stays separate"
