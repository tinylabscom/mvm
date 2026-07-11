#!/usr/bin/env bash
# Plan 213 SP4 — clean quiet-box capture for the instant-first-use numbers.
#
# `mvmctl ops bench first-use` boots real dev VMs and drives real in-guest
# builds, so its numbers can only come from a deliberate, uncontended host
# run — never from CI. This script is that opt-in entry point: it builds
# `mvmctl` with the live probes wired in (`--features mvm-cli/bench-first-use`
# — the root `mvmctl` package doesn't re-export the feature name directly),
# runs the bench, and writes dated evidence (JSON report + markdown summary)
# plus the two headline numbers:
#
#   - warm-vs-cold `dev up` (the instant-first-use win)
#   - in-guest `build_ms` p50/p99 (the cost SP3's closure-content/size
#     decision is weighing against)
#
# There is no pass/fail verdict here — the "instant" latency bar is TBD
# until this is run for the first time on a clean host.
#
# Usage:
#   MVM_SP4_LIVE=1 ./scripts/plan-213-sp4-baseline.sh
#   MVM_SP4_LIVE=1 ./scripts/plan-213-sp4-baseline.sh --runs 10
#   MVM_SP4_LIVE=1 ./scripts/plan-213-sp4-baseline.sh --flake ./my-flake
#   MVM_SP4_LIVE=1 ./scripts/plan-213-sp4-baseline.sh --out /tmp/my-evidence
#
# Flags (env var override in parens; flag wins):
#   --runs N     measured dev-up cold/warm pairs + in-guest builds (MVM_SP4_RUNS, default 5)
#   --flake P    flake built in-guest for each run (MVM_SP4_FLAKE, default examples/exit_code)
#   --out DIR    evidence dir, must be outside the repo (MVM_SP4_OUT_DIR, default /tmp/mvm-sp4-<timestamp>)
#
# Requires the opt-in env var MVM_SP4_LIVE=1 to actually run — this is a
# safety gate, not a prerequisite check: without it the script only prints
# usage and exits, touching nothing.
#
# Prerequisites (only needed once MVM_SP4_LIVE=1 is set):
#   - `mvmctl dev up` works on this host (builder-VM backend available:
#     libkrun on macOS 13-25 / HVF on macOS 26+ Apple Silicon / KVM on
#     Linux; gvproxy or passt installed per platform).
#   - A quiet, uncontended host — cold `dev up` numbers are meaningless
#     under contention from other builds, VMs, or heavy background load.
#   - `jq` on PATH (optional — falls back to python3 if absent).
#
# Output: JSON report + a dated markdown summary written under `--out`
# (never committed to the repo).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

RUNS="${MVM_SP4_RUNS:-5}"
FLAKE="${MVM_SP4_FLAKE:-examples/exit_code}"
OUT_DIR="${MVM_SP4_OUT_DIR:-/tmp/mvm-sp4-${STAMP}}"

usage() {
  sed -n '2,43p' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)  RUNS="$2"; shift 2 ;;
    --flake) FLAKE="$2"; shift 2 ;;
    --out)   OUT_DIR="$2"; shift 2 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${MVM_SP4_LIVE:-0}" != "1" ]]; then
  usage >&2
  echo >&2 "refusing: this boots real VMs on a clean host. Set MVM_SP4_LIVE=1 to run for real, on a quiet, uncontended host."
  exit 64
fi

command -v cargo >/dev/null || { echo "missing cargo on PATH" >&2; exit 1; }

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
case "${OUT_DIR}" in
  "${ROOT}"|"${ROOT}"/*)
    echo "refusing: --out must be outside the repository (got ${OUT_DIR})" >&2
    exit 65
    ;;
esac

TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
MVMCTL_BIN="${TARGET_DIR}/release/mvmctl"
REPORT_JSON="${OUT_DIR}/first-use-report.json"
SUMMARY_MD="${OUT_DIR}/plan-213-sp4-baseline-${STAMP}.md"

# The root `mvmctl` package doesn't expose `bench-first-use` directly (it
# lives on the `mvm-cli` dependency, `default-features = false` at the root)
# — the qualified `mvm-cli/bench-first-use` dependency-feature syntax turns
# it on without needing a root-level passthrough feature.
echo "plan-213-sp4-baseline: building mvmctl --features mvm-cli/bench-first-use ..." >&2
( cd "${ROOT}" && cargo build --release --bin mvmctl --features mvm-cli/bench-first-use )
[[ -x "${MVMCTL_BIN}" ]] || { echo "build did not produce ${MVMCTL_BIN}" >&2; exit 1; }

echo "plan-213-sp4-baseline: running ${RUNS} first-use runs against flake=${FLAKE} ..." >&2
"${MVMCTL_BIN}" ops bench first-use \
  --runs "${RUNS}" \
  --flake "${FLAKE}" \
  --json \
  --out "${REPORT_JSON}" \
  >"${OUT_DIR}/first-use-stdout.json"

if [[ ! -s "${REPORT_JSON}" ]]; then
  echo "warning: no report at ${REPORT_JSON} — falling back to captured stdout" >&2
  REPORT_JSON="${OUT_DIR}/first-use-stdout.json"
fi

# Pull the headline numbers out of the report. jq if present, else an
# embedded python3 dotted-path lookup (mirrors plan-89-baseline.sh's
# python3 percentile helper for hosts without jq).
json_field() {
  local field="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r "${field}" "${REPORT_JSON}"
  else
    python3 - "${REPORT_JSON}" "${field#.}" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
cur = data
for part in sys.argv[2].split("."):
    cur = cur[part]
print(cur)
PY
  fi
}

RUNS_ACTUAL="$(json_field '.runs')"
FLAKE_ACTUAL="$(json_field '.flake')"
DEV_UP_COLD_P50="$(json_field '.dev_up_cold.p50')"
DEV_UP_WARM_P50="$(json_field '.dev_up_warm.p50')"
BUILD_P50="$(json_field '.in_guest_build.p50')"
BUILD_P99="$(json_field '.in_guest_build.p99')"

DEV_UP_DELTA_MS="$(awk -v c="${DEV_UP_COLD_P50}" -v w="${DEV_UP_WARM_P50}" 'BEGIN{printf "%.2f", c-w}')"

OS="$(uname -s)"
ARCH="$(uname -m)"
STAMP_HUMAN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat >"${SUMMARY_MD}" <<EOF
# Plan 213 SP4 — first-use baseline (${STAMP_HUMAN})

Host: ${OS}/${ARCH}
Runs: ${RUNS_ACTUAL}
Flake: \`${FLAKE_ACTUAL}\`
mvmctl: \`$("${MVMCTL_BIN}" --version 2>/dev/null || echo unknown)\`
Report JSON: \`${REPORT_JSON}\`

## Headline numbers

| Metric | p50 (ms) | p99 (ms) |
|---|--:|--:|
| \`dev up\` cold | ${DEV_UP_COLD_P50} | — |
| \`dev up\` warm | ${DEV_UP_WARM_P50} | — |
| in-guest \`build_ms\` | ${BUILD_P50} | ${BUILD_P99} |

Cold − warm \`dev up\` p50 delta: ${DEV_UP_DELTA_MS} ms — this is the
instant-first-use win a warm dev image buys over a cold one.

These numbers feed the SP3 closure-content/size decision. There is no
pass/fail bar here — the "instant" latency bar is still TBD until this
script has been run for the first time on a clean, uncontended host.
EOF

echo "plan-213-sp4-baseline: wrote ${SUMMARY_MD}" >&2
echo "plan-213-sp4-baseline: dev up cold p50=${DEV_UP_COLD_P50}ms warm p50=${DEV_UP_WARM_P50}ms (delta ${DEV_UP_DELTA_MS}ms)" >&2
echo "plan-213-sp4-baseline: in-guest build_ms p50=${BUILD_P50}ms p99=${BUILD_P99}ms" >&2
echo "plan-213-sp4-baseline: these numbers feed the SP3 closure-content/size decision — no pass/fail threshold applies yet" >&2
