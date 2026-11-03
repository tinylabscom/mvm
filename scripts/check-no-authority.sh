#!/usr/bin/env bash
# Host-authority contract for the binaries that run below the host.
#
#   check-no-authority.sh guest-agent   # the workload agent (untrusted edge)
#   check-no-authority.sh builderd      # the builder-VM control daemon
#
# Neither may link signing-key loading or plan-admission code: authority never
# reaches a daemon below the host (host > builder > workload).
#
#   canary: a symbol that must be PRESENT, proving the symbol table is
#           populated so the absence checks below are not vacuously true.
#   absent: `load_host_signing_key`, `admit_for_run`, `host_signer`.
set -euo pipefail

case "${1:-}" in
  guest-agent)
    PKG=mvm-agentd BIN=mvm-guest-agent LABEL="the production agent"
    CANARY='mvm_guest_agent.*handle_run_entrypoint'
    PREFIX='mvm_(guest_agent|core|hostd|backend|cli)'
    ;;
  builderd)
    PKG=mvm-builder-guest BIN=mvm-builderd LABEL="mvm-builderd"
    CANARY='mvm_builderd'
    PREFIX='mvm_(builderd|build|core|hostd|backend|cli)'
    ;;
  *)
    echo "usage: $0 guest-agent|builderd" >&2
    exit 2
    ;;
esac

echo "::group::Build ${BIN} (release)"
CARGO_PROFILE_RELEASE_STRIP=false \
  cargo build --release --locked -p "$PKG" --bin "$BIN"
echo "::endgroup::"
syms=$(nm "target/release/$BIN")

fail=0

if grep -q "$CANARY" <<<"$syms"; then
  echo "ok: ${BIN} symbols present (symbol table populated)"
else
  echo "::error::no ${BIN} canary symbol — table stripped; absence checks would be vacuous." >&2
  fail=1
fi

# `host_signer` is narrowed to `mvm_hostd` only: `mvm_core::protocol::host_signer`
# is a benign wire-type module, not the signing authority, so the broad alternation
# would false-positive on any binary that links mvm-core.
check_absent() {
  local sym="$1" prefix="$2"
  if grep -qE "${prefix}.*${sym}" <<<"$syms"; then
    echo "::error::host authority symbol \`${sym}\` is PRESENT in ${LABEL}." >&2
    grep -E "${prefix}.*${sym}" <<<"$syms" >&2 || true
    fail=1
  else
    echo "ok: ${sym} absent from ${LABEL}"
  fi
}

check_absent load_host_signing_key "$PREFIX"
check_absent admit_for_run         "$PREFIX"
check_absent host_signer           'mvm_hostd'

if [ "$fail" -ne 0 ]; then
  echo "::error::Host-authority contract FAILED for ${BIN} — see annotations above." >&2
  exit 1
fi
echo "All assertions passed: ${LABEL} carries no host-authority symbols."
