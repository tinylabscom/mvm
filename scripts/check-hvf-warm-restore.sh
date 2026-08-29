#!/usr/bin/env bash
set -euo pipefail

# Live Apple Silicon HVF warm-claim acceptance matrix.
#
# This deliberately runs on the macOS host. A Linux builder cannot provide
# Hypervisor.framework, and a successful cold boot is not evidence of restore.
# The first invocation populates the compatible standby through the normal
# launch/replenish path; every measured invocation after that must be a real
# warm claim.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${MVM_HVF_WARM_OUT_DIR:-/tmp/mvm-hvf-warm-restore-${STAMP}}"
DATA_DIR="${MVM_HVF_WARM_DATA_DIR:-${OUT_DIR}/data}"
TARGET_DIR="${MVM_HVF_WARM_TARGET_DIR:-${CARGO_TARGET_DIR:-${ROOT}/target}}"
IMAGE_REF="${MVM_HVF_WARM_IMAGE:-alpine}"
RUNS="${MVM_HVF_WARM_RUNS:-1000}"
SKIP_BUILD="${MVM_HVF_WARM_SKIP_BUILD:-0}"
PROFILE="${MVM_HVF_WARM_PROFILE:-release}"

case "${PROFILE}" in
  debug) PROFILE_ARGS=() ;;
  release) PROFILE_ARGS=(--release) ;;
  *) echo "refusing: MVM_HVF_WARM_PROFILE must be debug or release" >&2; exit 64 ;;
esac

usage() {
  cat <<USAGE
Live Apple Silicon HVF warm-restore acceptance matrix.

Required host:
  macOS on Apple Silicon with Hypervisor.framework available.

The first run is a warm-pool bootstrap through the normal launch path. It may
be cold; it is not included in the measured matrix. Every following run must
report launch_mode=warm and warm_slo=ok.

Useful overrides:
  MVM_HVF_WARM_OUT_DIR=/tmp/path       evidence directory
  MVM_HVF_WARM_DATA_DIR=/tmp/path      isolated MVM_HOME
  MVM_HVF_WARM_TARGET_DIR=/tmp/path    isolated Cargo target directory
  MVM_HVF_WARM_SUBSTITUTION_ENDPOINT=/tmp/path
                                      substitution endpoint helper override
  MVM_HVF_WARM_HOST_AGENT=/tmp/path   resident host-agent override
  MVM_HVF_WARM_SIGNER_HELPER=/tmp/path resident signer-helper override
  MVM_HVF_WARM_IMAGE=alpine            compatible OCI image
  MVM_HVF_WARM_RUNS=1000               measured claims
  MVM_HVF_WARM_SKIP_BUILD=1            reuse existing binaries
  MVM_HVF_WARM_PROFILE=release         cargo profile and binary directory

Artifacts:
  summary.txt, bootstrap.stderr, claim-<n>.stderr, timings.csv, sorted-ms.txt
USAGE
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

case "${RUNS}" in
  ''|*[!0-9]*)
    echo "refusing: MVM_HVF_WARM_RUNS must be a positive integer" >&2
    exit 64
    ;;
esac
if (( RUNS < 1 )); then
  echo "refusing: MVM_HVF_WARM_RUNS must be at least 1" >&2
  exit 64
fi

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  usage >&2
  echo "refusing: this matrix requires macOS on Apple Silicon" >&2
  exit 64
fi
if ! command -v codesign >/dev/null 2>&1; then
  echo "refusing: codesign is required for the HVF supervisor entitlement" >&2
  exit 65
fi

mkdir -p "${OUT_DIR}" "${DATA_DIR}" "${TARGET_DIR}"
cd "${ROOT}"

MVMCTL_BIN="${MVM_HVF_WARM_MVMCTL:-${TARGET_DIR}/${PROFILE}/mvmctl}"
SUPERVISOR_BIN="${MVM_HVF_WARM_SUPERVISOR:-${TARGET_DIR}/${PROFILE}/mvm-hvf-supervisor}"
SUBSTITUTION_ENDPOINT_BIN="${MVM_HVF_WARM_SUBSTITUTION_ENDPOINT:-${TARGET_DIR}/${PROFILE}/mvm-network-endpoint}"
HOST_AGENT_BIN="${MVM_HVF_WARM_HOST_AGENT:-${TARGET_DIR}/${PROFILE}/mvm-host-agent}"
SIGNER_HELPER_BIN="${MVM_HVF_WARM_SIGNER_HELPER:-${TARGET_DIR}/${PROFILE}/mvm-signer-helper}"

if [[ "${SKIP_BUILD}" != "1" ]]; then
  CARGO_TARGET_DIR="${TARGET_DIR}" cargo build -p mvmctl --features hvf-live-validation,embed-host-bins "${PROFILE_ARGS[@]}"
  CARGO_TARGET_DIR="${TARGET_DIR}" cargo build -p mvm-hostd --bin mvm-hvf-supervisor \
    --features hvf-live-validation "${PROFILE_ARGS[@]}"
  CARGO_TARGET_DIR="${TARGET_DIR}" cargo build -p mvm-hostd --bin mvm-network-endpoint \
    --features hvf-live-validation "${PROFILE_ARGS[@]}"
  CARGO_TARGET_DIR="${TARGET_DIR}" cargo build -p mvm-hostd --bin mvm-host-agent \
    --bin mvm-signer-helper --features hvf-live-validation "${PROFILE_ARGS[@]}"
fi

if [[ ! -x "${MVMCTL_BIN}" ]]; then
  echo "refusing: mvmctl is not executable at ${MVMCTL_BIN}" >&2
  exit 66
fi
if [[ ! -x "${SUPERVISOR_BIN}" ]]; then
  echo "refusing: HVF supervisor is not executable at ${SUPERVISOR_BIN}" >&2
  exit 67
fi
if [[ ! -x "${SUBSTITUTION_ENDPOINT_BIN}" ]]; then
  echo "refusing: substitution endpoint is not executable at ${SUBSTITUTION_ENDPOINT_BIN}" >&2
  exit 67
fi
if [[ ! -x "${HOST_AGENT_BIN}" ]]; then
  echo "refusing: host agent is not executable at ${HOST_AGENT_BIN}" >&2
  exit 67
fi
if [[ ! -x "${SIGNER_HELPER_BIN}" ]]; then
  echo "refusing: signer helper is not executable at ${SIGNER_HELPER_BIN}" >&2
  exit 67
fi

# The supervisor self-signs on first execution. Trigger that once before the
# entitlement preflight so the preflight checks the exact binary the matrix
# will launch, including a freshly-built release binary.
if [[ "${PROFILE}" == "release" ]]; then
  printf '{}' | "${SUPERVISOR_BIN}" >/dev/null 2>&1 || true
fi

ENV_PREFIX=(
  env
  "MVM_HOME=${DATA_DIR}"
  "MVM_HVF_SUPERVISOR_PATH=${SUPERVISOR_BIN}"
  "MVM_SUBSTITUTION_ENDPOINT_PATH=${SUBSTITUTION_ENDPOINT_BIN}"
  "MVM_HOST_AGENT_PATH=${HOST_AGENT_BIN}"
  "MVM_SIGNER_HELPER_PATH=${SIGNER_HELPER_BIN}"
  "MVM_HVF_ENABLE_WARM_HANDOFF=${MVM_HVF_ENABLE_WARM_HANDOFF:-1}"
  "MVM_HVF_ENABLE_TRUSTED_SNAPSHOT=0"
  "MVM_RESIDENCY=warm"
  "MVM_PHASE_TIMING=1"
)
if [[ -n "${MVM_HVF_AGENT_DEBUG:-}" ]]; then
  ENV_PREFIX+=("MVM_HVF_AGENT_DEBUG=${MVM_HVF_AGENT_DEBUG}")
fi
run_launch() {
  local stderr_path="$1"
  local require_claim="${2:-0}"
  "${ENV_PREFIX[@]}" \
    "MVM_HVF_WARM_REQUIRE_CLAIM=${require_claim}" \
    "${MVMCTL_BIN}" machine run \
    --hypervisor hvf \
    --image "${IMAGE_REF}" \
    -- sh -c 'sleep 0.01 && test -r /etc/os-release && cat /etc/os-release >/dev/null && printf warm-continuity' \
    >"${OUT_DIR}/$(basename "${stderr_path}").stdout" \
    2>"${stderr_path}"
}

echo "==> bootstrap compatible HVF standby"
if ! run_launch "${OUT_DIR}/bootstrap.stderr"; then
  echo "HVF warm bootstrap failed; see ${OUT_DIR}/bootstrap.stderr" >&2
  if rg -q "standby pool|standby-pool|Unsupported|capability" "${OUT_DIR}/bootstrap.stderr"; then
    echo "the HVF warm capability is still disabled or the pool is unavailable" >&2
  fi
  exit 68
fi

entitlements="$(codesign -d --entitlements - --xml "${SUPERVISOR_BIN}" 2>&1 || true)"
if ! rg -q "com\.apple\.security\.hypervisor" <<<"${entitlements}"; then
  echo "refusing: HVF supervisor has no Hypervisor.framework entitlement" >&2
  exit 78
fi

bootstrap_line="$(rg '^\[mvm\] phase-timing:' "${OUT_DIR}/bootstrap.stderr" | tail -1 || true)"
if [[ -z "${bootstrap_line}" ]]; then
  echo "refusing: bootstrap emitted no phase-timing record" >&2
  exit 69
fi
echo "bootstrap=${bootstrap_line}" | tee "${OUT_DIR}/summary.txt"

TIMINGS="${OUT_DIR}/timings.csv"
printf 'iteration,launch_mode,warm_window_ms,warm_slo\n' >"${TIMINGS}"

for iteration in $(seq 1 "${RUNS}"); do
  stderr_path="${OUT_DIR}/claim-${iteration}.stderr"
  if ! run_launch "${stderr_path}" 1; then
    echo "claim ${iteration} failed; see ${stderr_path}" >&2
    exit 70
  fi
  line="$(rg '^\[mvm\] phase-timing:' "${stderr_path}" | tail -1 || true)"
  if [[ -z "${line}" ]]; then
    echo "claim ${iteration} emitted no phase-timing record" >&2
    exit 71
  fi
  mode="$(sed -nE 's/.*launch_mode=([^ ]+).*/\1/p' <<<"${line}")"
  window="$(sed -nE 's/.*dispatch_window=([^ ]+).*/\1/p' <<<"${line}")"
  window="${window%ms}"
  slo="$(sed -nE 's/.*warm_slo=([^ ]+).*/\1/p' <<<"${line}")"
  if [[ -z "${mode}" || -z "${window}" || -z "${slo}" ]]; then
    echo "claim ${iteration} has an unparseable phase-timing record: ${line}" >&2
    exit 72
  fi
  if ! rg -q "warm-continuity" "${OUT_DIR}/$(basename "${stderr_path}").stdout"; then
    echo "claim ${iteration} did not complete the post-restore guest continuity probe" >&2
    exit 77
  fi
  printf '%s,%s,%s,%s\n' "${iteration}" "${mode}" "${window}" "${slo}" >>"${TIMINGS}"
  if [[ "${mode}" != "warm" || "${slo}" != "ok" ]]; then
    echo "claim ${iteration} was not a successful warm claim: ${line}" >&2
    exit 73
  fi
  if awk -v value="${window}" 'BEGIN { exit !(value >= 300.0) }'; then
    echo "claim ${iteration} exceeded the strict 300ms ceiling: ${line}" >&2
    exit 74
  fi
done

WINDOWS="${OUT_DIR}/sorted-ms.txt"
awk -F, 'NR > 1 { print $3 }' "${TIMINGS}" | sort -n >"${WINDOWS}"
COUNT="$(wc -l <"${WINDOWS}" | tr -d ' ')"
P50_LINE="$(awk -v n="${COUNT}" 'NR == int((n * 50 + 99) / 100) { print; exit }' "${WINDOWS}")"
P95_LINE="$(awk -v n="${COUNT}" 'NR == int((n * 95 + 99) / 100) { print; exit }' "${WINDOWS}")"
P99_LINE="$(awk -v n="${COUNT}" 'NR == int((n * 99 + 99) / 100) { print; exit }' "${WINDOWS}")"
MAX_LINE="$(tail -1 "${WINDOWS}")"

{
  echo "host=$(uname -s)-$(uname -m)"
  echo "macos=$(sw_vers -productVersion)"
  echo "hypervisor_entitlement=present"
  echo "image=${IMAGE_REF}"
  echo "claims=${COUNT}"
  echo "warm_p50_ms=${P50_LINE}"
  echo "warm_p95_ms=${P95_LINE}"
  echo "warm_p99_ms=${P99_LINE}"
  echo "warm_max_ms=${MAX_LINE}"
  echo "hard_ceiling_ms=300"
  echo "result=PASS"
  echo "timings=${TIMINGS}"
} | tee -a "${OUT_DIR}/summary.txt"

if awk -v value="${P50_LINE}" 'BEGIN { exit !(value > 30.0) }'; then
  echo "warm p50 exceeded the 30ms aggregate target" >&2
  exit 75
fi
if awk -v value="${P99_LINE}" 'BEGIN { exit !(value > 50.0) }'; then
  echo "warm p99 exceeded the 50ms aggregate target" >&2
  exit 76
fi

echo "HVF warm-restore matrix: PASS"
