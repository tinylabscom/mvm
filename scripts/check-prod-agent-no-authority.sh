#!/usr/bin/env bash
# Production guest-agent authority contract.
#
# On the `mvm-guest-agent` binary built in its PRODUCTION configuration (no
# `dev-shell` feature), assert the workload agent links NONE of the host-only
# authority symbols. The workload microVM is the untrusted edge: it must not
# carry signing-key loading or plan-admission code, which live host-side.
#
#   canary: `handle_run_entrypoint` PRESENT — proves the symbol table is
#           populated, so the absence checks below are not vacuously true.
#   absent: `load_host_signing_key`, `host_signer`, `admit_for_run` — host-side
#           authority. None may appear in the agent's own crate symbols.
set -euo pipefail

PKG=mvm-guest
BIN=mvm-guest-agent

echo "::group::Build production agent (release, no dev-shell)"
CARGO_PROFILE_RELEASE_STRIP=false \
  cargo build --release --locked -p "$PKG" --bin "$BIN" --no-default-features
echo "::endgroup::"
prod_syms=$(nm "target/release/$BIN")

fail=0

if grep -q 'mvm_guest_agent.*handle_run_entrypoint' <<<"$prod_syms"; then
  echo "ok: handle_run_entrypoint present (symbol table populated)"
else
  echo "::error::handle_run_entrypoint ABSENT — symbol table stripped; absence checks would be vacuous." >&2
  fail=1
fi

# Check absence of each host-authority symbol with the appropriate prefix scope.
# `host_signer` is narrowed to `mvm_hostd` only: `mvm_core::protocol::host_signer`
# is a benign wire-type module, not the signing authority, so the broad alternation
# would false-positive on any binary that links mvm-core.
check_absent() {
  local sym="$1" prefix="$2"
  if grep -qE "${prefix}.*${sym}" <<<"$prod_syms"; then
    echo "::error::host authority symbol \`${sym}\` is PRESENT in the production agent." >&2
    grep -E "${prefix}.*${sym}" <<<"$prod_syms" >&2 || true
    fail=1
  else
    echo "ok: ${sym} absent from the production agent"
  fi
}

check_absent load_host_signing_key 'mvm_(guest_agent|core|hostd|backend|cli)'
check_absent admit_for_run         'mvm_(guest_agent|core|hostd|backend|cli)'
check_absent host_signer           'mvm_hostd'

if [ "$fail" -ne 0 ]; then
  echo "::error::Production guest-agent authority contract FAILED — see annotations above." >&2
  exit 1
fi
echo "All assertions passed: prod agent carries no host-authority symbols."
