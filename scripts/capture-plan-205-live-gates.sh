#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${MVM_PLAN205_OUT_DIR:-/tmp/mvm-plan205-live-${STAMP}}"
RUNS="${MVM_PLAN205_RESTORE_RUNS:-5}"
OCI_IMAGE="${MVM_PLAN205_OCI_IMAGE:-docker.io/library/alpine:3.20}"
WARM_REUSE_MAX_MS="${MVM_PLAN205_WARM_REUSE_MAX_MS:-250}"
RESTORE_P50_MAX_MS="${MVM_PLAN205_RESTORE_P50_MAX_MS:-800}"
RESTORE_P95_MULTIPLIER="${MVM_PLAN205_RESTORE_P95_MULTIPLIER:-2}"

usage() {
  cat <<USAGE
Plan 205 live gate capture.

This script boots and manages real macOS Vz dev-builder state and runs an OCI
image. It is intentionally opt-in.

Required:
  MVM_PLAN205_LIVE=1 $0

Useful overrides:
  MVM_PLAN205_MVMCTL=/path/to/mvmctl       use an existing binary
  MVM_PLAN205_SKIP_BUILD=1                do not build target/release/mvmctl
  MVM_PLAN205_OUT_DIR=/tmp/path           evidence directory
  MVM_PLAN205_RESTORE_RUNS=5              parked restore timing samples
  MVM_PLAN205_OCI_IMAGE=ref               OCI image for run --image
  MVM_PLAN205_WARM_REUSE_MAX_MS=250       warm reuse latency budget
  MVM_PLAN205_RESTORE_P50_MAX_MS=800      restore p50 latency budget
  MVM_VZ_SUPERVISOR_PATH=/path/to/bin     use an existing Vz supervisor binary
  MVM_PLAN205_SKIP_SIGN=1                 skip macOS entitlement signing step
  MVM_PLAN205_USE_DEFAULT_STATE=1         use current MVM_DATA_DIR/MVM_CACHE_DIR
  MVM_PLAN205_DATA_DIR=/tmp/path          isolated data dir when not using default state
  MVM_PLAN205_CACHE_DIR=/tmp/path         isolated cache dir when not using default state
  MVM_PLAN205_ALLOW_UNSUPPORTED_HOST=1    bypass the Darwin arm64 macOS 26 guard

Evidence is written only under OUT_DIR. No screenshots or binary artifacts are
saved in the repository.
USAGE
}

if [[ "${MVM_PLAN205_LIVE:-0}" != "1" ]]; then
  usage >&2
  exit 64
fi

host_ok=1
if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  host_ok=0
fi
if command -v sw_vers >/dev/null 2>&1; then
  macos_version="$(sw_vers -productVersion)"
  macos_major="${macos_version%%.*}"
  if [[ "${macos_major}" -lt 26 ]]; then
    host_ok=0
  fi
else
  macos_version="unknown"
  host_ok=0
fi
if [[ "${host_ok}" != "1" && "${MVM_PLAN205_ALLOW_UNSUPPORTED_HOST:-0}" != "1" ]]; then
  echo "refusing: Plan 205 Vz live gate expects macOS 26+ on Apple Silicon" >&2
  echo "host: os=$(uname -s) arch=$(uname -m) macos=${macos_version}" >&2
  exit 65
fi

mkdir -p "${OUT_DIR}"
TIMINGS="${OUT_DIR}/timings.tsv"
SUMMARY="${OUT_DIR}/summary.json"
: > "${TIMINGS}"

if [[ "${MVM_PLAN205_USE_DEFAULT_STATE:-0}" != "1" ]]; then
  export MVM_DATA_DIR="${MVM_PLAN205_DATA_DIR:-${OUT_DIR}/data}"
  export MVM_CACHE_DIR="${MVM_PLAN205_CACHE_DIR:-${OUT_DIR}/cache}"
fi
export MVM_BUILDER_BACKEND="${MVM_BUILDER_BACKEND:-vz}"

if [[ -n "${MVM_PLAN205_MVMCTL:-}" ]]; then
  MVMCTL="${MVM_PLAN205_MVMCTL}"
else
  if [[ "${MVM_PLAN205_SKIP_BUILD:-0}" != "1" ]]; then
    cargo build --release --bin mvmctl --features builder-vm
  fi
  TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
  MVMCTL="${TARGET_DIR}/release/mvmctl"
fi

TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
if [[ -z "${MVM_VZ_SUPERVISOR_PATH:-}" && "${MVM_PLAN205_SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --release -p mvm-vm-host --bin mvm-vz-supervisor
  export MVM_VZ_SUPERVISOR_PATH="${TARGET_DIR}/release/mvm-vz-supervisor"
fi

if [[ ! -x "${MVMCTL}" ]]; then
  echo "refusing: mvmctl binary is not executable: ${MVMCTL}" >&2
  exit 66
fi
if [[ -n "${MVM_VZ_SUPERVISOR_PATH:-}" && ! -x "${MVM_VZ_SUPERVISOR_PATH}" ]]; then
  echo "refusing: MVM_VZ_SUPERVISOR_PATH is not executable: ${MVM_VZ_SUPERVISOR_PATH}" >&2
  exit 67
fi

# Runtime `mvmctl run --image` builds guest-agent binaries through code that
# currently resolves outputs under the workspace `target/` directory. Keep
# CARGO_TARGET_DIR for this script's prebuilds only; do not leak it into the
# runtime commands unless explicitly requested.
if [[ "${MVM_PLAN205_KEEP_CARGO_TARGET_DIR:-0}" != "1" ]]; then
  unset CARGO_TARGET_DIR
fi

CACHE_ROOT="${MVM_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/mvm}"
SNAPSHOT="${CACHE_ROOT}/builder-vm/vms/mvm-persistent-builder-vz-dev/state.vzsave"
SNAPSHOT_MACHINE_ID="${SNAPSHOT}.machine-id"

now_ns() {
  python3 -c 'import time; print(time.perf_counter_ns())'
}

run_timed() {
  local label="$1"
  shift
  local stdout="${OUT_DIR}/${label}.stdout"
  local stderr="${OUT_DIR}/${label}.stderr"
  local start end status duration_ms

  start="$(now_ns)"
  if "$@" >"${stdout}" 2>"${stderr}"; then
    status=0
  else
    status=$?
  fi
  end="$(now_ns)"
  duration_ms="$(((end - start) / 1000000))"
  printf '%s\t%s\t%s\t%s\t%s\n' "${label}" "${status}" "${duration_ms}" "${stdout}" "${stderr}" >> "${TIMINGS}"
  return "${status}"
}

assert_json_field() {
  local file="$1"
  local field="$2"
  local expected="$3"
  python3 - "$file" "$field" "$expected" <<'PY'
import json
import sys

path, field, expected = sys.argv[1:]
with open(path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)
actual = doc
for part in field.split("."):
    actual = actual[part]
if str(actual) != expected:
    raise SystemExit(f"{path}: expected {field}={expected!r}, got {actual!r}")
PY
}

json_field() {
  local file="$1"
  local field="$2"
  python3 - "$file" "$field" <<'PY'
import json
import sys

path, field = sys.argv[1:]
with open(path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)
actual = doc
for part in field.split("."):
    actual = actual[part]
print(actual)
PY
}

failures=0
record_failure() {
  local message="$1"
  echo "FAIL: ${message}" | tee -a "${OUT_DIR}/failures.log" >&2
  failures=$((failures + 1))
}

echo "Plan 205 live evidence: ${OUT_DIR}"
echo "mvmctl: ${MVMCTL}"
echo "state: MVM_DATA_DIR=${MVM_DATA_DIR:-default} MVM_CACHE_DIR=${MVM_CACHE_DIR:-default}"

if [[ "${MVM_PLAN205_SKIP_SIGN:-0}" != "1" ]]; then
  if ! run_timed sign "${MVMCTL}" env sign --json; then
    record_failure "entitlement signing failed"
  fi
fi

if ! run_timed clean env MVM_RESIDENCY=cold "${MVMCTL}" dev down --reset --json; then
  record_failure "initial cold reset failed"
fi

if ! run_timed warm_start env MVM_RESIDENCY=warm "${MVMCTL}" dev up --no-shell --json; then
  record_failure "warm dev up failed"
else
  assert_json_field "${OUT_DIR}/warm_start.stdout" "action" "up" || record_failure "warm_start did not return dev-up JSON"
fi

if ! run_timed warm_reuse env MVM_RESIDENCY=warm "${MVMCTL}" dev up --no-shell --json; then
  record_failure "warm reuse dev up failed"
else
  assert_json_field "${OUT_DIR}/warm_reuse.stdout" "outcome" "already-running" || record_failure "warm reuse did not hit already-running path"
fi

if ! run_timed warm_status env MVM_RESIDENCY=warm "${MVMCTL}" dev status --json; then
  record_failure "warm status failed"
else
  assert_json_field "${OUT_DIR}/warm_status.stdout" "state" "running" || record_failure "warm status did not report running"
fi

if ! run_timed warm_doctor env MVM_RESIDENCY=warm "${MVMCTL}" doctor --json; then
  record_failure "doctor failed against warm builder"
fi

if ! run_timed initial_park env MVM_RESIDENCY=parked "${MVMCTL}" dev park --json; then
  record_failure "initial explicit park failed"
else
  assert_json_field "${OUT_DIR}/initial_park.stdout" "outcome" "parked" || record_failure "initial park did not report parked"
fi
if [[ ! -f "${SNAPSHOT}" || ! -f "${SNAPSHOT_MACHINE_ID}" ]]; then
  record_failure "parked snapshot or machine-id sidecar missing under ${SNAPSHOT}"
fi

for i in $(seq 1 "${RUNS}"); do
  label="restore_${i}"
  if ! run_timed "${label}" env MVM_RESIDENCY=parked "${MVMCTL}" dev up --no-shell --json; then
    record_failure "${label} failed"
    continue
  fi
  assert_json_field "${OUT_DIR}/${label}.stdout" "outcome" "restored" || record_failure "${label} did not restore"

  if ! run_timed "restore_${i}_park" env MVM_RESIDENCY=parked "${MVMCTL}" dev park --json; then
    record_failure "park failed after ${label}"
  else
    park_outcome="$(json_field "${OUT_DIR}/restore_${i}_park.stdout" "outcome")"
    if [[ "${park_outcome}" == "parked" ]]; then
      :
    elif [[ "${park_outcome}" == "not-running" && -f "${SNAPSHOT}" && -f "${SNAPSHOT_MACHINE_ID}" ]]; then
      :
    else
      record_failure "park after ${label} reported ${park_outcome} without preserved snapshot"
    fi
  fi
done

if ! run_timed oci_run env MVM_RESIDENCY=warm "${MVMCTL}" run --image "${OCI_IMAGE}" --json -- /bin/true; then
  record_failure "OCI run --image failed for ${OCI_IMAGE}"
fi

if ! run_timed final_status env MVM_RESIDENCY=parked "${MVMCTL}" dev status --json; then
  record_failure "final parked status failed"
fi

python3 - "$TIMINGS" "$SUMMARY" "$WARM_REUSE_MAX_MS" "$RESTORE_P50_MAX_MS" "$RESTORE_P95_MULTIPLIER" "$failures" <<'PY'
import json
import math
import sys

timings, summary_path, warm_max, restore_p50_max, restore_p95_multiplier, failures = sys.argv[1:]
warm_max = int(warm_max)
restore_p50_max = int(restore_p50_max)
restore_p95_multiplier = int(restore_p95_multiplier)
failures = int(failures)
rows = []
with open(timings, "r", encoding="utf-8") as fh:
    for line in fh:
        label, status, duration_ms, stdout, stderr = line.rstrip("\n").split("\t")
        rows.append({
            "label": label,
            "status": int(status),
            "duration_ms": int(duration_ms),
            "stdout": stdout,
            "stderr": stderr,
        })

def percentile(values, pct):
    if not values:
        return None
    values = sorted(values)
    index = math.ceil((pct / 100) * len(values)) - 1
    return values[max(0, min(index, len(values) - 1))]

warm = next((row["duration_ms"] for row in rows if row["label"] == "warm_reuse"), None)
def json_outcome(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh).get("outcome")
    except (OSError, json.JSONDecodeError):
        return None

restores = [
    row["duration_ms"]
    for row in rows
    if row["label"].startswith("restore_")
    and row["label"].split("_")[-1].isdigit()
    and row["status"] == 0
    and json_outcome(row["stdout"]) == "restored"
]
p50 = percentile(restores, 50)
p95 = percentile(restores, 95)
budget_failures = []
if warm is not None and warm > warm_max:
    budget_failures.append(f"warm_reuse_ms {warm} > {warm_max}")
if p50 is not None and p50 > restore_p50_max:
    budget_failures.append(f"restore_p50_ms {p50} > {restore_p50_max}")
if p50 is not None and p95 is not None and p95 > (p50 * restore_p95_multiplier):
    budget_failures.append(f"restore_p95_ms {p95} > {restore_p95_multiplier}x p50 {p50}")

summary = {
    "schema_version": 1,
    "warm_reuse_ms": warm,
    "warm_reuse_budget_ms": warm_max,
    "restore_samples_ms": restores,
    "restore_p50_ms": p50,
    "restore_p50_budget_ms": restore_p50_max,
    "restore_p95_ms": p95,
    "restore_p95_multiplier": restore_p95_multiplier,
    "command_failures": failures,
    "budget_failures": budget_failures,
    "passed": failures == 0 and not budget_failures,
    "timings": rows,
}
with open(summary_path, "w", encoding="utf-8") as fh:
    json.dump(summary, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(json.dumps(summary, indent=2, sort_keys=True))
if not summary["passed"]:
    raise SystemExit(1)
PY
