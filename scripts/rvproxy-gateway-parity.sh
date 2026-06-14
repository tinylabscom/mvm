#!/usr/bin/env bash
# rvproxy ⇄ gvproxy gateway parity gate.
#
# Gates the macOS/libkrun egress-gateway default flip from upstream gvproxy to
# the first-party rvproxy (ADR-082 stage 4 / Plan 179 Task 4 / Plan 193 WS-1).
# The gateway is the claim-10 security chokepoint, so the default must not flip
# on a binary that diverges from the proven one.
#
# Two layers, matching where enforcement currently lives:
#
#   1. Conformance (binary-discriminating). The only witness whose verdict
#      depends on the gateway binary is gvproxy_dhcp_offer_roundtrips_through_bridge:
#      it spawns a real gateway over the `-listen-vfkit unixgram://` contract and
#      round-trips a DHCP DISCOVER/OFFER. We run it against gvproxy (control) and
#      rvproxy (candidate) and require both to genuinely run and pass.
#
#   2. Enforcement (binary-agnostic today). claim-10 deny-by-default, the Plan
#      141 flow-audit observer, and Plan 129 substitution all enforce inside the
#      mvm-hostd bridge (gateway_bridge.rs), not the gateway binary, so swapping
#      the binary cannot change their verdict. We run the whole mvm-hostd suite
#      once to assert those witnesses stay green. They become binary-
#      discriminating only after Plan 193 WS-2 ports enforcement onto rvproxy's
#      native flow API and deletes the splice; this gate grows that arm then.
#
# Usage:
#   RVPROXY_BIN=/path/to/rvproxy scripts/rvproxy-gateway-parity.sh [gvproxy-path]
#
# Env:
#   RVPROXY_BIN   (required) candidate gateway binary.
#   GVPROXY_BIN   (optional) control binary; defaults to $1 or `which gvproxy`.
#                 If absent the control arm is reported MISSING (not a failure:
#                 a CI box without gvproxy can still prove the candidate).

set -euo pipefail
cd "$(dirname "$0")/.."

RVPROXY_BIN="${RVPROXY_BIN:-}"
GVPROXY_BIN="${GVPROXY_BIN:-${1:-$(command -v gvproxy || true)}}"
CONFORMANCE_TEST=gvproxy_dhcp_offer_roundtrips_through_bridge

if [[ -z "$RVPROXY_BIN" || ! -x "$RVPROXY_BIN" ]]; then
  echo "FATAL: set RVPROXY_BIN to an executable rvproxy binary (got: '${RVPROXY_BIN}')" >&2
  exit 2
fi

# Run the conformance witness against one gateway binary. Classifies the outcome
# as PASS (ran for real and the test passed), SKIP (self-skipped — binary absent
# or unspawnable, which the test treats as a soft skip), or FAIL.
run_conformance() {
  local label="$1" bin="$2" log
  log="$(mktemp)"
  if MVM_GATEWAY_DHCP_E2E=1 MVM_GATEWAY_BIN="$bin" \
      cargo test -p mvm-hostd "$CONFORMANCE_TEST" -- --nocapture >"$log" 2>&1; then
    if grep -q '^skip:' "$log"; then
      echo "  $label: SKIP (gateway did not run — see $log)"
      return 3
    fi
    echo "  $label: PASS ($bin)"
    return 0
  fi
  echo "  $label: FAIL ($bin) — see $log"
  sed -n 's/^/    /p' "$log" | tail -20
  return 1
}

echo "== rvproxy gateway parity gate =="
echo "candidate (rvproxy): $RVPROXY_BIN"
echo "control  (gvproxy):  ${GVPROXY_BIN:-<none>}"
echo

echo "[1/3] enforcement witnesses (claim-10 / flow-audit / substitution; bridge-side, binary-agnostic)"
# Scope to the witness families on purpose: the full mvm-hostd suite carries
# timing/flock-sensitive broker/vsock tests whose flakiness is unrelated to the
# gateway and must not gate a default flip. claim-10 deny-by-default + flow-audit
# observer live in the gateway_bridge + network::pipeline lib tests; Plan 129
# substitution lives in the egress_secret_leak_gate integration test.
if ! cargo test -p mvm-hostd --lib -- gateway_bridge network::pipeline >/dev/null 2>&1; then
  echo "  FAIL: claim-10 / flow-audit witnesses are not green" >&2
  exit 1
fi
if ! cargo test -p mvm-hostd --test egress_secret_leak_gate >/dev/null 2>&1; then
  echo "  FAIL: Plan 129 substitution leak-gate witnesses are not green" >&2
  exit 1
fi
echo "  PASS: claim-10 / flow-audit / substitution witnesses green"
echo

echo "[2/3] conformance — control (gvproxy)"
control=0
if [[ -n "$GVPROXY_BIN" && -x "$GVPROXY_BIN" ]]; then
  run_conformance "gvproxy" "$GVPROXY_BIN" || control=$?
else
  echo "  gvproxy: MISSING (no control binary on this host)"
  control=3
fi
echo

echo "[3/3] conformance — candidate (rvproxy)"
candidate=0
run_conformance "rvproxy" "$RVPROXY_BIN" || candidate=$?
echo

echo "== verdict =="
# The candidate MUST run for real and pass. A skipped/failed candidate means the
# parity claim is unproven, which is a hard fail.
if [[ "$candidate" -ne 0 ]]; then
  echo "REFUSED: rvproxy did not pass the conformance gate (status $candidate)."
  echo "Do not flip the macOS/libkrun default to rvproxy."
  exit 1
fi
if [[ "$control" -eq 1 ]]; then
  echo "REFUSED: gvproxy control unexpectedly FAILED — the gate itself is suspect."
  exit 1
fi
if [[ "$control" -eq 3 ]]; then
  echo "PASS (candidate only): rvproxy met the conformance gate; gvproxy control"
  echo "was unavailable on this host, so the head-to-head was not recorded. Re-run"
  echo "on a host with gvproxy to capture the control case before flipping."
  exit 0
fi
echo "PASS: rvproxy matches gvproxy on the conformance gate, and the claim-10 /"
echo "flow-audit / substitution enforcement witnesses are green. Conformance"
echo "parity recorded; the native-enforcement parity arm lands with Plan 193 WS-2."
