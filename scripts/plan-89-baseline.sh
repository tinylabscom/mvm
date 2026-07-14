#!/usr/bin/env bash
# Plan 89 W1 — cold-boot telemetry baseline harness.
#
# Runs N cold-boot `mvmctl build` invocations against a small flake,
# parses each run's `boot-timings.json` (written by `mvm-host-vm-init`
# at `<job_dir>/boot-timings.json`), and emits a markdown summary
# (default: `/tmp/plan-89-baseline.md`).
#
# Per the plan §Order of operations: if the median `job_start_ms`
# (boot fan-out — time from init anchor to first build instruction)
# is under ~500 ms on both macOS Apple Silicon and Linux KVM, the
# rest of Plan 89 is not worth shipping. Run this on both platforms
# and check the summary in.
#
# Why the default flake is the W1 fixture, not a real image build:
# `mvm-host-vm-init` writes boot-timings.json BEFORE exec'ing
# cmd.sh — so the boot fan-out we want to measure
# (init_start_ms → job_start_ms) is captured regardless of whether
# the inner `nix build` succeeds. The fixture flake at
# `tests/fixtures/plan-89-baseline/` deliberately throws at
# evaluation time: it has no inputs, no network fetch, no nixpkgs
# eval cost, and produces no artifacts. That isolates the
# measurement to the builder VM boot dance — the actual thing Plan
# 89 is debating amortizing. Point `--flake` at a real user flake
# if you want to measure end-to-end wall-clock instead.
#
# Usage:
#   ./scripts/plan-89-baseline.sh                       # 5 runs, fixture flake
#   ./scripts/plan-89-baseline.sh --runs 10
#   ./scripts/plan-89-baseline.sh --flake ./my-flake
#   ./scripts/plan-89-baseline.sh --out /tmp/baseline.md
#
# Prerequisites:
#   - `mvmctl dev up` works on this host (ur-seed installed and a
#     local dev image staged; libkrun on macOS or KVM on Linux;
#     gvproxy/passt installed per platform).
#   - `jq` on PATH.
#
# Output: `/tmp/plan-89-baseline.md` (default).

set -euo pipefail

RUNS=5
FLAKE="tests/fixtures/plan-89-baseline"
OUT="/tmp/plan-89-baseline.md"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)  RUNS="$2"; shift 2 ;;
    --flake) FLAKE="$2"; shift 2 ;;
    --out)   OUT="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

command -v jq >/dev/null || { echo "missing jq on PATH" >&2; exit 1; }
command -v mvmctl >/dev/null || { echo "missing mvmctl on PATH — run from repo root with 'cargo run --release -- ...' or install first" >&2; exit 1; }

JOBS_DIR="${HOME}/.cache/mvm/builder-vm/jobs"
TMPDIR_RUN="$(mktemp -d)"

OS="$(uname -s)"
ARCH="$(uname -m)"
HOSTID="${OS}/${ARCH}"

mkdir -p "$(dirname "${OUT}")"

echo "plan-89-baseline: ${RUNS} runs against flake=${FLAKE} on ${HOSTID}" >&2

# Phases we report. `nix_seeded_ms` (first-boot-only) and `job_end_ms`
# / `poweroff_start_ms` (post-build) are deliberately omitted — they
# are not part of boot fan-out per Plan 89 §Problem.
PHASES=(
  init_start_ms
  pseudofs_ready_ms
  nix_device_ready_ms
  nix_mounted_ms
  modules_ready_ms
  virtiofs_ready_ms
  network_ready_ms
  job_start_ms
)

# Snapshot existing job dirs so we can identify per-run dirs by
# "appeared since BEFORE" rather than relying on mtime sort, which
# breaks when the builder VM tears down a dir or several runs
# complete inside a single mtime second.
JOBS_BEFORE="$(mktemp)"
trap 'rm -rf "${TMPDIR_RUN}" "${JOBS_BEFORE}"' EXIT
ls -1 "${JOBS_DIR}" 2>/dev/null | sort >"${JOBS_BEFORE}" || true

for i in $(seq 1 "${RUNS}"); do
  echo "--- run ${i}/${RUNS} ---" >&2
  BEFORE="$(date +%s)"
  # We deliberately tolerate non-zero exit: with the W1 fixture flake
  # the inner `nix build` is expected to fail (throw at eval), and
  # boot-timings.json is written by builder-init BEFORE cmd.sh runs.
  # The only "real failure" we care about is missing timings.
  mvmctl build --flake "${FLAKE}" >"${TMPDIR_RUN}/run-${i}.out" 2>&1 || true
  AFTER="$(date +%s)"
  WALL=$(( AFTER - BEFORE ))
  # Find the job dir this run created: the only entry in JOBS_DIR
  # that wasn't there before the loop started.
  JOBS_NOW="$(mktemp)"
  ls -1 "${JOBS_DIR}" 2>/dev/null | sort >"${JOBS_NOW}" || true
  NEW_JOB_NAME="$(comm -13 "${JOBS_BEFORE}" "${JOBS_NOW}" | tail -1)"
  cp "${JOBS_NOW}" "${JOBS_BEFORE}"
  rm -f "${JOBS_NOW}"
  if [[ -z "${NEW_JOB_NAME}" ]]; then
    echo "run ${i}: no new job dir appeared under ${JOBS_DIR}" >&2
    echo "first 40 lines of build output:" >&2
    head -40 "${TMPDIR_RUN}/run-${i}.out" >&2
    exit 1
  fi
  JOB_DIR="${JOBS_DIR}/${NEW_JOB_NAME}"
  if [[ ! -f "${JOB_DIR}/boot-timings.json" ]]; then
    echo "run ${i}: ${JOB_DIR}/boot-timings.json missing — builder VM probably crashed before init wrote it" >&2
    echo "first 40 lines of build output:" >&2
    head -40 "${TMPDIR_RUN}/run-${i}.out" >&2
    exit 1
  fi
  cp "${JOB_DIR}/boot-timings.json" "${TMPDIR_RUN}/timings-${i}.json"
  echo "${WALL}" >"${TMPDIR_RUN}/wall-${i}.txt"
done

# Aggregate: for each phase, collect every run's value, compute
# min/median/max/p95 in milliseconds.
percentile() {
  local p="$1"; shift
  python3 - "$@" <<PY
import math, sys
xs = sorted(int(x) for x in sys.argv[1:] if x.isdigit())
if not xs:
    print("—")
else:
    k = (len(xs)-1) * float("${p}")
    f = math.floor(k); c = math.ceil(k)
    if f == c:
        print(xs[int(k)])
    else:
        d = xs[f] * (c-k) + xs[c] * (k-f)
        print(int(d))
PY
}

WALL_VALUES=()
for i in $(seq 1 "${RUNS}"); do
  WALL_VALUES+=("$(cat "${TMPDIR_RUN}/wall-${i}.txt")")
done
WALL_MEDIAN="$(percentile 0.5 "${WALL_VALUES[@]}")"

ROWS=""
for phase in "${PHASES[@]}"; do
  VALS=()
  for i in $(seq 1 "${RUNS}"); do
    V="$(jq -r --arg p "${phase}" '.[$p] // empty' "${TMPDIR_RUN}/timings-${i}.json")"
    [[ -n "${V}" && "${V}" != "null" ]] && VALS+=("${V}")
  done
  if [[ ${#VALS[@]} -eq 0 ]]; then
    ROWS+="| ${phase} | — | — | — | — | (no data) |"$'\n'
    continue
  fi
  MIN="$(percentile 0.0 "${VALS[@]}")"
  MED="$(percentile 0.5 "${VALS[@]}")"
  MAX="$(percentile 1.0 "${VALS[@]}")"
  P95="$(percentile 0.95 "${VALS[@]}")"
  ROWS+="| ${phase} | ${MIN} | ${MED} | ${P95} | ${MAX} | ${#VALS[@]}/${RUNS} runs |"$'\n'
done

JOB_START_MEDIAN="$(jq -r '.job_start_ms // empty' "${TMPDIR_RUN}/timings-1.json")"

# Verdict per the plan: median job_start_ms < 500 → stop.
JOB_START_VALS=()
for i in $(seq 1 "${RUNS}"); do
  V="$(jq -r '.job_start_ms // empty' "${TMPDIR_RUN}/timings-${i}.json")"
  [[ -n "${V}" && "${V}" != "null" ]] && JOB_START_VALS+=("${V}")
done
JOB_START_MEDIAN="$(percentile 0.5 "${JOB_START_VALS[@]}")"

if [[ "${JOB_START_MEDIAN}" == "—" ]]; then
  VERDICT="**inconclusive** — no \`job_start_ms\` recorded across runs."
elif (( JOB_START_MEDIAN < 500 )); then
  VERDICT="**STOP** — median \`job_start_ms\` is ${JOB_START_MEDIAN} ms, under the 500 ms threshold the plan calls out as the not-worth-shipping line."
else
  VERDICT="**proceed to W2** — median \`job_start_ms\` is ${JOB_START_MEDIAN} ms, above the 500 ms threshold; boot fan-out is a real lever."
fi

# Detect whether we appended a section for this host or are writing
# the file fresh.
SECTION_HEADER="## ${HOSTID} ($(date -u +%Y-%m-%dT%H:%M:%SZ))"

if [[ ! -f "${OUT}" ]]; then
  cat >"${OUT}" <<EOF
# Plan 89 W1 — cold-boot telemetry baseline

Generated by \`scripts/plan-89-baseline.sh\`. Run on each target
platform (macOS Apple Silicon and Linux KVM) and append the section
to this file. The headline number is the median \`job_start_ms\` —
the wall-clock from init anchor to the user's build script's first
instruction. Plan 89 §Order of operations gates the rest of the
plan on this number exceeding ~500 ms on both platforms.

EOF
fi

cat >>"${OUT}" <<EOF

${SECTION_HEADER}

- Flake: \`${FLAKE}\`
- Runs: ${RUNS}
- Median wall-clock per run: ${WALL_MEDIAN}s
- mvmctl: \`$(mvmctl --version 2>/dev/null || echo unknown)\`

### Per-phase distribution (ms since init anchor)

| Phase | min | median | p95 | max | coverage |
|---|--:|--:|--:|--:|---|
${ROWS}

### Verdict

${VERDICT}
EOF

echo "wrote ${OUT}" >&2
echo "headline: median job_start_ms = ${JOB_START_MEDIAN} ms on ${HOSTID}" >&2
