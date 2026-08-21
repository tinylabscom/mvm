#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${workspace_root}"

require_text() {
  local file="$1"
  local text="$2"
  if ! grep -Fq -- "${text}" "${file}"; then
    echo "check-fast-cargo: ${file} is missing: ${text}" >&2
    exit 1
  fi
}

if ! grep -Eq '^channel = "nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}"$' rust-toolchain.toml; then
  echo "check-fast-cargo: rust-toolchain.toml must pin a dated nightly" >&2
  exit 1
fi
toolchain="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)"
embedded_rust="$(sed -n 's/^rust = "\([^"]*\)"$/\1/p' Cargo.toml)"

require_text rust-toolchain.toml '"rustc-codegen-cranelift"'
require_text rust-toolchain.toml '"wasm32-wasip1"'
require_text nix/packages/embedded-rust-toolchain.nix "version = \"${embedded_rust}\";"
require_text flake.nix 'fromRustupToolchainFile ./rust-toolchain.toml'
require_text flake.nix "echo \"Rust toolchain: \$(rustc --version)\""
if grep -Fq 'rustChannel' flake.nix; then
  echo "check-fast-cargo: flake.nix retains the removed rustChannel binding" >&2
  exit 1
fi
require_text .cargo/fast.toml 'rustflags = ["-Z", "threads=8"]'
require_text .cargo/fast.toml 'codegen-backend = "cranelift"'
if [[ "$(grep -Fc 'codegen-backend = "llvm"' .cargo/fast.toml)" -ne 2 ]]; then
  echo "check-fast-cargo: test and release profiles must explicitly retain LLVM" >&2
  exit 1
fi
require_text scripts/cargo-fast.sh '.cargo/fast.toml'
require_text scripts/cargo-fast.sh "RUSTUP_TOOLCHAIN=\"\${fast_toolchain}\""
require_text scripts/cargo-fast.sh "PATH=\"\${toolchain_bin}:\${PATH}\""
require_text Justfile './scripts/cargo-fast.sh build --workspace'
require_text Justfile './scripts/cargo-fast.sh nextest run --workspace'
require_text Justfile './scripts/cargo-stable.sh clippy --workspace --all-targets -- -D warnings'
require_text Justfile './scripts/cargo-stable.sh clippy --fix --allow-dirty --workspace --all-targets -- -D warnings'
require_text .githooks/pre-commit "./scripts/cargo-stable.sh clippy \$scope_args --all-targets -- -D warnings"
require_text .github/workflows/ci.yml './scripts/cargo-stable.sh clippy --all-targets -- -D warnings'
require_text .github/workflows/ci.yml 'uses: dtolnay/rust-toolchain@1.96.0'
require_text .github/workflows/ci-full.yml 'uses: dtolnay/rust-toolchain@1.96.0'
require_text .github/workflows/cache-warm.yml './scripts/cargo-stable.sh clippy --workspace --all-targets -- -D warnings'
require_text .github/workflows/cache-warm.yml 'uses: dtolnay/rust-toolchain@1.96.0'
require_text Justfile './scripts/cargo-stable.sh --direct cargo-zigbuild check --target {{ TARGET }} --workspace --all-targets'
require_text scripts/cargo-stable.sh 'stable_toolchain="1.96.0"'
require_text scripts/cargo-stable.sh "CARGO_TARGET_DIR=\"\${stable_target_root}\""
require_text scripts/cargo-stable.sh "if [[ \"\${1:-}\" == \"--direct\" ]]"
require_text crates/mvm-build/src/guest_agent_build.rs 'pinned_rust_toolchain(&spec.workspace_root)'
require_text crates/mvm-build/src/guest_agent_build.rs '.env_remove("CARGO_ENCODED_RUSTFLAGS")'
require_text .github/workflows/bdd.yml "toolchain: ${toolchain}"
require_text .github/workflows/bdd.yml 'components: rustc-codegen-cranelift'
require_text Justfile 'CARGO_BIN_EXE_mvmctl="${CARGO_TARGET_DIR:-target}/debug/mvmctl"'
require_text crates/mvm-conformance/tests/conformance.rs 'var_os("CARGO_BIN_EXE_mvmctl")'

if grep -Eq 'codegen-backend|threads=8' .cargo/config.toml; then
  echo "check-fast-cargo: nightly settings leaked into stable-compatible .cargo/config.toml" >&2
  exit 1
fi

echo "check-fast-cargo: nightly fast path is pinned, wired, and isolated"
