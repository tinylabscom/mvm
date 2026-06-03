#!/usr/bin/env bash
# ADR-002 §W4.3 (claim 4) + ADR-007 §W5 — production guest-agent symbol contract.
#
# On the `mvm-guest-agent` binary built in its PRODUCTION configuration (no
# `dev-shell` feature), assert:
#
#   1. `handle_run_entrypoint` is PRESENT — the constrained RunEntrypoint
#      handler ships (ADR-007 §W5). It is `#[inline(never)]` precisely so it
#      survives optimization. This also serves as a CANARY: if it's missing,
#      the symbol table was stripped and the absence check below would be
#      meaningless (vacuously true), so we fail instead of trusting it.
#   2. `do_exec` is ABSENT — the dev-only `sh -c` exec path did not leak into a
#      non-dev-shell build (claim 4 / W4.3). A compromised guest service must
#      not be able to reach an arbitrary-command handler.
#
# Then a POSITIVE CONTROL: built WITH `dev-shell`, `do_exec` MUST be detectable.
# This proves the detector works (so #2 can't silently pass against a renamed
# symbol) — if `do_exec` is ever renamed, this turns the lane red and points
# here, instead of letting the no-exec assertion rot into a no-op.
#
# `[profile.release] strip = true` in the root Cargo.toml would erase the
# symbol table, so each build overrides it with CARGO_PROFILE_RELEASE_STRIP=false
# — real release codegen, readable symbols.
set -euo pipefail

# Symbol greps are scoped to the agent's own crate (mvm_guest_agent.*<name>)
# on purpose: a bare `do_exec` also matches std::process::Command::do_exec,
# the libstd internal that exists in any binary that spawns a subprocess.

PKG=mvm-guest
BIN=mvm-guest-agent

echo "::group::Build production agent (release, no dev-shell)"
CARGO_PROFILE_RELEASE_STRIP=false \
  cargo build --release --locked -p "$PKG" --bin "$BIN" --no-default-features
echo "::endgroup::"
prod_syms=$(nm "target/release/$BIN")

fail=0

if grep -q 'mvm_guest_agent.*handle_run_entrypoint' <<<"$prod_syms"; then
  echo "ok: handle_run_entrypoint present (W5 handler ships; symbol table is populated)"
else
  echo "::error::ADR-007 §W5: handle_run_entrypoint is ABSENT from the production agent." >&2
  echo "Either the constrained RunEntrypoint handler was removed, or the symbol table" >&2
  echo "was stripped — which would make the do_exec absence check below vacuous. The" >&2
  echo "no-exec guarantee cannot be trusted until this is resolved." >&2
  fail=1
fi

if grep -q 'mvm_guest_agent.*do_exec' <<<"$prod_syms"; then
  echo "::error::claim 4 / ADR-002 §W4.3: do_exec is PRESENT in the production agent." >&2
  echo "The dev-only \`sh -c\` exec path leaked into a non-dev-shell build." >&2
  grep 'mvm_guest_agent.*do_exec' <<<"$prod_syms" >&2 || true
  fail=1
else
  echo "ok: do_exec absent from the production agent (claim 4 / W4.3)"
fi

echo "::group::Positive control — build WITH dev-shell; do_exec MUST be detectable"
CARGO_PROFILE_RELEASE_STRIP=false \
  cargo build --release --locked -p "$PKG" --bin "$BIN" \
    --no-default-features --features dev-shell \
    --target-dir target/claim4-poscontrol
echo "::endgroup::"
if grep -q 'mvm_guest_agent.*do_exec' <<<"$(nm "target/claim4-poscontrol/release/$BIN")"; then
  echo "ok: positive control — do_exec is detectable when dev-shell is enabled"
else
  echo "::error::Positive control FAILED: do_exec not found even WITH dev-shell on." >&2
  echo "The symbol was probably renamed. Update this script's grep so the production" >&2
  echo "absence assertion stays meaningful (otherwise it silently passes regardless)." >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "::error::Production guest-agent symbol contract FAILED — see annotations above." >&2
  exit 1
fi
echo "All assertions passed: prod agent ships handle_run_entrypoint and omits do_exec."
