#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${MVM_HVF_DENSITY_OUT_DIR:-/tmp/mvm-hvf-density-${STAMP}}"
IMAGE_REF="${MVM_HVF_DENSITY_IMAGE:-docker.io/library/alpine:latest}"
WAVES_TEXT="${MVM_HVF_DENSITY_WAVES:-1 5 10 25}"
GUEST_SLEEP_SECONDS="${MVM_HVF_DENSITY_GUEST_SLEEP_SECONDS:-240}"
SETTLE_SECONDS="${MVM_HVF_DENSITY_SETTLE_SECONDS:-20}"
LAUNCH_SPACING_SECONDS="${MVM_HVF_DENSITY_LAUNCH_SPACING_SECONDS:-1}"
CLEANUP_GRACE_SECONDS="${MVM_HVF_DENSITY_CLEANUP_GRACE_SECONDS:-8}"
MEMORY="${MVM_HVF_DENSITY_MEMORY:-512M}"
CPUS="${MVM_HVF_DENSITY_CPUS:-2}"
SKIP_BUILD="${MVM_HVF_DENSITY_SKIP_BUILD:-0}"

usage() {
  cat <<USAGE
Measure current macOS HVF OCI VM density without changing runtime process shape.

Default waves: ${WAVES_TEXT}
Default image: ${IMAGE_REF}

Useful overrides:
  MVM_HVF_DENSITY_OUT_DIR=/tmp/path          artifact directory outside the repo
  MVM_HVF_DENSITY_WAVES="1 5 10 25 50 100"  wave sizes to run
  MVM_HVF_DENSITY_IMAGE=alpine              OCI image reference
  MVM_HVF_DENSITY_GUEST_SLEEP_SECONDS=240   in-guest sleep duration
  MVM_HVF_DENSITY_SETTLE_SECONDS=20         settle time before sampling
  MVM_HVF_DENSITY_MEMORY=512M               guest memory setting
  MVM_HVF_DENSITY_CPUS=2                    guest vCPU setting
  MVM_HVF_DENSITY_WORKLOAD_KERNEL=/path     seed isolated cache with this kernel
  MVM_HVF_DENSITY_SEED_HOST_KERNEL=0        do not auto-seed from ~/.cache/mvm
  MVM_HVF_DENSITY_SKIP_PREPULL=1            skip image pull before waves
  MVM_HVF_DENSITY_SKIP_BUILD=1              reuse existing binaries
  MVM_HVF_DENSITY_MVMCTL=/path/mvmctl       mvmctl binary override
  MVM_HVF_SUPERVISOR_PATH=/path/supervisor  supervisor binary override
  MVM_SUBSTITUTION_ENDPOINT_PATH=/path/bin  endpoint binary override
  MVM_HVF_DENSITY_ALLOW_BUSY_HOST=1         skip active build/runtime preflight
  MVM_HVF_DENSITY_ALLOW_UNSUPPORTED=1       bypass macOS arm64 host guard

Artifacts include command logs, VM names, launch failures, ps RSS snapshots,
vm_stat snapshots, and cleanup results. All generated state is isolated under
OUT_DIR unless an explicit override points elsewhere.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

host_ok=1
if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  host_ok=0
fi
if [[ "${MVM_HVF_DENSITY_ALLOW_UNSUPPORTED:-0}" != "1" && "${host_ok}" != "1" ]]; then
  usage >&2
  echo "refusing: HVF density measurement expects macOS on Apple Silicon" >&2
  exit 64
fi

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
case "${OUT_DIR}" in
  "${ROOT}"|"${ROOT}"/*)
    echo "refusing: artifact directory must be outside the repository: ${OUT_DIR}" >&2
    exit 65
    ;;
esac

DATA_DIR="${MVM_HVF_DENSITY_DATA_DIR:-${OUT_DIR}/mvm-data}"
CACHE_DIR="${DATA_DIR}/cache"
TARGET_DIR="${MVM_HVF_DENSITY_TARGET_DIR:-${OUT_DIR}/target}"
RUN_ID="plan237-${STAMP}"
SUMMARY="${OUT_DIR}/summary.tsv"
SEEDED_KERNEL_SOURCE="none"

read -r -a WAVES <<<"${WAVES_TEXT}"
if [[ "${#WAVES[@]}" -eq 0 ]]; then
  echo "refusing: no wave sizes configured" >&2
  exit 66
fi

MAX_WAVE=0
for wave in "${WAVES[@]}"; do
  if ! [[ "${wave}" =~ ^[0-9]+$ ]] || [[ "${wave}" -lt 1 ]]; then
    echo "refusing: invalid wave size ${wave}" >&2
    exit 70
  fi
  if [[ "${wave}" -gt "${MAX_WAVE}" ]]; then
    MAX_WAVE="${wave}"
  fi
done

mkdir -p "${DATA_DIR}" "${CACHE_DIR}" "${TARGET_DIR}"
DATA_DIR="$(cd "${DATA_DIR}" && pwd)"
CACHE_DIR="$(cd "${CACHE_DIR}" && pwd)"
TARGET_DIR="$(cd "${TARGET_DIR}" && pwd)"
for generated_dir in "${DATA_DIR}" "${CACHE_DIR}" "${TARGET_DIR}"; do
  case "${generated_dir}" in
    "${ROOT}"|"${ROOT}"/*)
      echo "refusing: generated state must be outside the repository: ${generated_dir}" >&2
      exit 65
      ;;
  esac
done

# macOS sockaddr_un paths are short; fail before the expensive prepull if the
# generated VM names would make the HVF agent socket impossible to bind.
longest_vm_name="${RUN_ID}-w${MAX_WAVE}-$(printf "%03d" "${MAX_WAVE}")"
longest_agent_socket="${DATA_DIR}/vms/${longest_vm_name}/hvf-agent.sock"
if [[ "${#longest_agent_socket}" -ge 104 ]]; then
  echo "refusing: HVF agent socket path would exceed macOS Unix socket length:" >&2
  echo "  ${longest_agent_socket}" >&2
  echo "choose a shorter MVM_HVF_DENSITY_OUT_DIR or MVM_HVF_DENSITY_DATA_DIR, for example /tmp/p237d" >&2
  exit 65
fi

busy_host_processes="${OUT_DIR}/busy-host-processes.txt"
capture_busy_host_processes() {
  ps axww -o pid=,ppid=,comm=,args= | awk '
    {
      args = $0
      if (args ~ /measure-hvf-density.sh/) next
      if (args ~ /awk /) next
      if (args ~ /(^|[[:space:]\/])(cargo|rustc|clang)([[:space:]]|$)/) {
        print
        found = 1
        next
      }
      if (args ~ /(mvm-hvf-supervisor|mvmctl|mvm-network-endpoint|mvm-host-agent)/) {
        print
        found = 1
        next
      }
    }
    END {
      exit found ? 0 : 1
    }
  '
}

if [[ "${MVM_HVF_DENSITY_ALLOW_BUSY_HOST:-0}" != "1" ]]; then
  if capture_busy_host_processes >"${busy_host_processes}"; then
    echo "refusing: active build or MVM runtime processes would contaminate the density baseline" >&2
    echo "see ${busy_host_processes}" >&2
    echo "wait for the host to become idle, or set MVM_HVF_DENSITY_ALLOW_BUSY_HOST=1 to bypass" >&2
    exit 72
  fi
  : >"${busy_host_processes}"
fi

run_env=(
  env
  "MVM_HOME=${DATA_DIR}"
  "CARGO_TARGET_DIR=${TARGET_DIR}"
)

host_kernel_arch() {
  case "$(uname -m)" in
    arm64) echo "aarch64" ;;
    x86_64) echo "x86_64" ;;
    *) uname -m ;;
  esac
}

seed_workload_kernel() {
  local arch
  local dest
  local seed
  arch="$(host_kernel_arch)"
  dest="${CACHE_DIR}/kernels/${arch}/workload/vmlinux"
  if [[ -f "${dest}" ]]; then
    SEEDED_KERNEL_SOURCE="already-present:${dest}"
    return
  fi

  seed="${MVM_HVF_DENSITY_WORKLOAD_KERNEL:-}"
  if [[ -z "${seed}" && "${MVM_HVF_DENSITY_SEED_HOST_KERNEL:-1}" != "0" ]]; then
    seed="${HOME}/.cache/mvm/kernels/${arch}/workload/vmlinux"
  fi
  if [[ -z "${seed}" || ! -f "${seed}" ]]; then
    return
  fi

  mkdir -p "$(dirname "${dest}")"
  cp "${seed}" "${dest}"
  SEEDED_KERNEL_SOURCE="${seed}"
}

cd "${ROOT}"

seed_workload_kernel

if [[ "${SKIP_BUILD}" != "1" ]]; then
  "${run_env[@]}" cargo build -p mvmctl --bin mvmctl
  "${run_env[@]}" cargo build -p mvm-hostd --bin mvm-network-endpoint
  "${run_env[@]}" cargo build -p mvm-hostd --bin mvm-hvf-supervisor
fi

MVMCTL_BIN="${MVM_HVF_DENSITY_MVMCTL:-${TARGET_DIR}/debug/mvmctl}"
SUPERVISOR_BIN="${MVM_HVF_SUPERVISOR_PATH:-${TARGET_DIR}/debug/mvm-hvf-supervisor}"
ENDPOINT_BIN="${MVM_SUBSTITUTION_ENDPOINT_PATH:-${TARGET_DIR}/debug/mvm-network-endpoint}"

if [[ ! -x "${MVMCTL_BIN}" ]]; then
  echo "refusing: mvmctl not executable at ${MVMCTL_BIN}" >&2
  exit 67
fi
if [[ ! -x "${SUPERVISOR_BIN}" ]]; then
  echo "refusing: mvm-hvf-supervisor not executable at ${SUPERVISOR_BIN}" >&2
  exit 68
fi
if [[ ! -x "${ENDPOINT_BIN}" ]]; then
  echo "refusing: mvm-network-endpoint not executable at ${ENDPOINT_BIN}" >&2
  exit 69
fi

run_env+=(
  "MVM_HVF_SUPERVISOR_PATH=${SUPERVISOR_BIN}"
  "MVM_SUBSTITUTION_ENDPOINT_PATH=${ENDPOINT_BIN}"
)

if [[ "${MVM_HVF_DENSITY_SKIP_PREPULL:-0}" != "1" ]]; then
  "${run_env[@]}" "${MVMCTL_BIN}" image pull "${IMAGE_REF}" \
    >"${OUT_DIR}/prepull.stdout" 2>"${OUT_DIR}/prepull.stderr"
fi

active_pids_file="${OUT_DIR}/active-pids.txt"
: >"${active_pids_file}"

cleanup_active_pids() {
  if [[ ! -f "${active_pids_file}" ]]; then
    return
  fi
  while read -r pid; do
    [[ -n "${pid}" ]] || continue
    kill "${pid}" 2>/dev/null || true
  done <"${active_pids_file}"
}
trap cleanup_active_pids INT TERM EXIT

capture_vm_stat() {
  local phase="$1"
  local dir="$2"
  if command -v vm_stat >/dev/null 2>&1; then
    vm_stat >"${dir}/vm_stat-${phase}.txt"
  else
    echo "vm_stat unavailable on this host" >"${dir}/vm_stat-${phase}.txt"
  fi
}

capture_processes() {
  local phase="$1"
  local dir="$2"
  local raw="${dir}/processes-${phase}.txt"
  local tsv="${dir}/rss-${phase}.tsv"
  ps axww -o pid=,rss=,comm=,args= >"${raw}"
  awk '
    BEGIN {
      print "component\tcount\trss_kib\trss_mib"
    }
    {
      pid = $1
      rss = $2
      comm = $3
      args = $0
      comp = ""
      if (args ~ /mvm-hvf-supervisor/) comp = "mvm-hvf-supervisor"
      else if (args ~ /mvm-network-endpoint/) comp = "mvm-network-endpoint"
      else if (args ~ /mvm-host-agent/) comp = "mvm-host-agent"
      else if (args ~ /mvm-signer-helper/) comp = "mvm-signer-helper"
      else if (args ~ /mvm-host-signer/) comp = "mvm-host-signer"
      else if (args ~ /mvm-audit-signer/) comp = "mvm-audit-signer"
      else if (args ~ /mvm-broker/) comp = "mvm-broker"
      else if (args ~ /mvmctl/) comp = "mvmctl"
      if (comp != "") {
        count[comp] += 1
        rss_kib[comp] += rss
      }
    }
    END {
      for (comp in count) {
        printf "%s\t%d\t%d\t%.1f\n", comp, count[comp], rss_kib[comp], rss_kib[comp] / 1024
      }
    }
  ' "${raw}" >>"${tsv}"
}

capture_matching_processes() {
  local phase="$1"
  local dir="$2"
  ps axww -o pid=,rss=,args= | awk -v pat="${RUN_ID}" '
    index($0, pat) > 0 && $0 !~ /awk -v pat/ && $0 !~ /measure-hvf-density.sh/ { print }
  ' >"${dir}/matching-${phase}.txt"
}

check_launches() {
  local dir="$1"
  shift
  : >"${dir}/launch-failures.tsv"
  for entry in "$@"; do
    local name="${entry%%:*}"
    local pid="${entry##*:}"
    if kill -0 "${pid}" 2>/dev/null; then
      continue
    fi
    local status=0
    set +e
    wait "${pid}"
    status=$?
    set -e
    printf "%s\t%s\t%d\n" "${name}" "${pid}" "${status}" >>"${dir}/launch-failures.tsv"
  done
}

cleanup_wave() {
  local dir="$1"
  shift
  local cleanup_log="${dir}/cleanup.txt"
  {
    echo "cleanup_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "guest_parent_count=$#"
  } >"${cleanup_log}"

  for pid in "$@"; do
    kill "${pid}" 2>/dev/null || true
  done
  sleep "${CLEANUP_GRACE_SECONDS}"
  for pid in "$@"; do
    if kill -0 "${pid}" 2>/dev/null; then
      echo "force_kill_pid=${pid}" >>"${cleanup_log}"
      kill -KILL "${pid}" 2>/dev/null || true
    fi
  done
  for pid in "$@"; do
    set +e
    wait "${pid}"
    status=$?
    set -e
    echo "wait_pid=${pid} status=${status}" >>"${cleanup_log}"
  done

  set +e
  "${run_env[@]}" "${MVMCTL_BIN}" machine stop --all --yes \
    >"${dir}/machine-stop.stdout" 2>"${dir}/machine-stop.stderr"
  stop_status=$?
  "${run_env[@]}" "${MVMCTL_BIN}" machine rm --all --yes \
    >"${dir}/machine-rm.stdout" 2>"${dir}/machine-rm.stderr"
  rm_status=$?
  set -e
  echo "machine_stop_status=${stop_status}" >>"${cleanup_log}"
  echo "machine_rm_status=${rm_status}" >>"${cleanup_log}"
  sleep 2
  capture_matching_processes "after-cleanup" "${dir}"
  remaining="$(wc -l <"${dir}/matching-after-cleanup.txt" | tr -d ' ')"
  echo "remaining_matching_processes=${remaining}" >>"${cleanup_log}"
  if [[ "${stop_status}" -ne 0 || "${rm_status}" -ne 0 || "${remaining}" -ne 0 ]]; then
    return 1
  fi
}

{
  echo -e "key\tvalue"
  echo -e "run_id\t${RUN_ID}"
  echo -e "out_dir\t${OUT_DIR}"
  echo -e "data_dir\t${DATA_DIR}"
  echo -e "cache_dir\t${CACHE_DIR}"
  echo -e "target_dir\t${TARGET_DIR}"
  echo -e "image\t${IMAGE_REF}"
  echo -e "waves\t${WAVES_TEXT}"
  echo -e "guest_sleep_seconds\t${GUEST_SLEEP_SECONDS}"
  echo -e "settle_seconds\t${SETTLE_SECONDS}"
  echo -e "memory\t${MEMORY}"
  echo -e "cpus\t${CPUS}"
  echo -e "seeded_kernel_source\t${SEEDED_KERNEL_SOURCE}"
  echo -e "mvmctl\t${MVMCTL_BIN}"
  echo -e "supervisor\t${SUPERVISOR_BIN}"
  echo -e "network_endpoint\t${ENDPOINT_BIN}"
} >"${SUMMARY}"

for wave in "${WAVES[@]}"; do
  wave_dir="${OUT_DIR}/wave-${wave}"
  mkdir -p "${wave_dir}"
  : >"${wave_dir}/launches.tsv"
  : >"${active_pids_file}"
  pids=()
  entries=()

  capture_vm_stat "before" "${wave_dir}"
  capture_processes "before" "${wave_dir}"

  for i in $(seq 1 "${wave}"); do
    name="${RUN_ID}-w${wave}-$(printf "%03d" "${i}")"
    stdout="${wave_dir}/${name}.stdout"
    stderr="${wave_dir}/${name}.stderr"
    printf "%s\n" "${name}" >>"${wave_dir}/vm-names.txt"
    "${run_env[@]}" "${MVMCTL_BIN}" machine run \
      --name "${name}" \
      --hypervisor hvf \
      --image "${IMAGE_REF}" \
      --memory "${MEMORY}" \
      --cpus "${CPUS}" \
      -- sleep "${GUEST_SLEEP_SECONDS}" \
      >"${stdout}" 2>"${stderr}" &
    pid=$!
    pids+=("${pid}")
    entries+=("${name}:${pid}")
    printf "%s\t%s\t%s\t%s\n" "${name}" "${pid}" "${stdout}" "${stderr}" \
      >>"${wave_dir}/launches.tsv"
    printf "%s\n" "${pid}" >>"${active_pids_file}"
    sleep "${LAUNCH_SPACING_SECONDS}"
  done

  sleep "${SETTLE_SECONDS}"
  check_launches "${wave_dir}" "${entries[@]}"
  capture_vm_stat "settled" "${wave_dir}"
  capture_processes "settled" "${wave_dir}"
  capture_matching_processes "settled" "${wave_dir}"

  cleanup_ok=0
  if cleanup_wave "${wave_dir}" "${pids[@]}"; then
    cleanup_ok=1
  fi
  : >"${active_pids_file}"
  capture_vm_stat "after-cleanup" "${wave_dir}"
  capture_processes "after-cleanup" "${wave_dir}"

  failures="$(wc -l <"${wave_dir}/launch-failures.tsv" | tr -d ' ')"
  echo -e "wave_${wave}_launch_failures\t${failures}" >>"${SUMMARY}"
  echo -e "wave_${wave}_cleanup_ok\t${cleanup_ok}" >>"${SUMMARY}"
  if [[ "${failures}" -ne 0 || "${cleanup_ok}" -ne 1 ]]; then
    echo "wave ${wave} failed; see ${wave_dir}" >&2
    exit 71
  fi
done

trap - INT TERM EXIT
echo "HVF density measurement complete: ${OUT_DIR}"
