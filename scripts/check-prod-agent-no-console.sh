#!/usr/bin/env bash
# Plan 165 WS-C (claim 15) — sealed-production interactivity contract.
#
# The agent-served PTY-over-vsock console (crates/mvm-guest/src/console.rs) is
# the SINGLE dev-only interactive path into a guest. On the `mvm-guest-agent`
# binary built in its PRODUCTION configuration (no `dev-shell` feature), assert:
#
#   1. `handle_run_entrypoint` is PRESENT — the constrained RunEntrypoint
#      handler ships (ADR-007 §W5). It is `#[inline(never)]` precisely so it
#      survives optimization. This also serves as a CANARY: if it's missing,
#      the symbol table was stripped and the absence check below would be
#      meaningless (vacuously true), so we fail instead of trusting it.
#   2. The console relay is ABSENT — `mvm_guest::console` is gated behind
#      `dev-shell`, so a sealed prod agent must not link `open_session` /
#      `run_console_relay` / `resize_active_session`. No interactive path can
#      reach a sealed workload (claim 15), mirroring the `do_exec` no-exec gate.
#
# Then a POSITIVE CONTROL: built WITH `dev-shell`, the console symbol MUST be
# detectable. This proves the detector works (so #2 can't silently pass against
# a renamed/inlined symbol) — if the gate or the symbol changes, this turns the
# lane red and points here, instead of letting the absence assertion rot.
#
# `[profile.release] strip = true` in the root Cargo.toml would erase the
# symbol table, so each build overrides it with CARGO_PROFILE_RELEASE_STRIP=false
# — real release codegen, readable symbols.
set -euo pipefail

# Symbol greps are scoped to the console module path (mvm_guest::console::<name>)
# so an unrelated `open_session` in a dependency can't mask a leak. NB: the
# console fns live in the mvm-guest *library*, so the mangled prefix is
# `mvm_guest..console..` — NOT `mvm_guest_agent..` (the binary crate) as in the
# sibling no-exec gate. Match ALL THREE relay entry points, not just one: gating
# the whole module keeps them absent together today, but the alternation means a
# future partial de-gating (e.g. moving `open_session` out while leaving the
# relay) still trips the absence assertion.

PKG=mvm-guest
BIN=mvm-guest-agent
CONSOLE_SYM='mvm_guest.*console.*(open_session|run_console_relay|resize_active_session)'

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
  echo "was stripped — which would make the console absence check below vacuous. The" >&2
  echo "no-interactivity guarantee cannot be trusted until this is resolved." >&2
  fail=1
fi

if grep -qE "$CONSOLE_SYM" <<<"$prod_syms"; then
  echo "::error::claim 15 / Plan 165 WS-C: console relay is PRESENT in the production agent." >&2
  echo "The dev-only PTY-over-vsock console leaked into a non-dev-shell build." >&2
  grep -E "$CONSOLE_SYM" <<<"$prod_syms" >&2 || true
  fail=1
else
  echo "ok: console relay absent from the production agent (claim 15)"
fi

echo "::group::Positive control — build WITH dev-shell; console relay MUST be detectable"
CARGO_PROFILE_RELEASE_STRIP=false \
  cargo build --release --locked -p "$PKG" --bin "$BIN" \
    --no-default-features --features dev-shell \
    --target-dir target/claim15-poscontrol
echo "::endgroup::"
if grep -qE "$CONSOLE_SYM" <<<"$(nm "target/claim15-poscontrol/release/$BIN")"; then
  echo "ok: positive control — console relay is detectable when dev-shell is enabled"
else
  echo "::error::Positive control FAILED: console relay not found even WITH dev-shell on." >&2
  echo "The symbol was probably renamed or inlined away. Update this script's grep so the" >&2
  echo "production absence assertion stays meaningful (otherwise it silently passes)." >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "::error::Production guest-agent console contract FAILED — see annotations above." >&2
  exit 1
fi
echo "All assertions passed: prod agent ships handle_run_entrypoint and omits the console relay."
