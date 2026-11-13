#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKEND="${MVM_HVF_DENSITY_BACKEND:-hvf}"
OUT_DIR="${MVM_HVF_DENSITY_OUT_DIR:-/tmp/mvm-${BACKEND}-density-${STAMP}}"
IMAGE_REF="${MVM_HVF_DENSITY_IMAGE:-docker.io/library/alpine:latest}"
WAVES_TEXT="${MVM_HVF_DENSITY_WAVES:-1 5 10 25}"
GUEST_SLEEP_SECONDS="${MVM_HVF_DENSITY_GUEST_SLEEP_SECONDS:-240}"
SETTLE_SECONDS="${MVM_HVF_DENSITY_SETTLE_SECONDS:-20}"
IDLE_SAMPLE_SECONDS="${MVM_HVF_DENSITY_IDLE_SAMPLE_SECONDS:-10}"
LAUNCH_SPACING_SECONDS="${MVM_HVF_DENSITY_LAUNCH_SPACING_SECONDS:-1}"
CLEANUP_GRACE_SECONDS="${MVM_HVF_DENSITY_CLEANUP_GRACE_SECONDS:-8}"
MEMORY="${MVM_HVF_DENSITY_MEMORY:-512M}"
CPUS="${MVM_HVF_DENSITY_CPUS:-2}"
SKIP_BUILD="${MVM_HVF_DENSITY_SKIP_BUILD:-0}"
MAILBOX="${MVM_HVF_DENSITY_MAILBOX:-0}"

usage() {
  cat <<USAGE
Measure OCI VM density on macOS HVF or Linux/KVM Firecracker without changing runtime process shape.
Usage: $0 [-- GUEST_COMMAND [ARG ...]]
Without a command, guests run sleep ${GUEST_SLEEP_SECONDS}; use a real agent
command to measure working VMs. Do not put secrets in command arguments.

Default waves: ${WAVES_TEXT}
Default image: ${IMAGE_REF}

Useful overrides:
  MVM_HVF_DENSITY_OUT_DIR=/tmp/path          artifact directory outside the repo
  MVM_HVF_DENSITY_BACKEND=firecracker        Linux/KVM instead of macOS HVF
  MVM_HVF_DENSITY_WAVES="1 5 10 25 50 100"  wave sizes to run
  MVM_HVF_DENSITY_IMAGE=alpine              OCI image reference
  MVM_HVF_DENSITY_GUEST_SLEEP_SECONDS=240   in-guest sleep duration
  MVM_HVF_DENSITY_SETTLE_SECONDS=20         settle time before sampling
  MVM_HVF_DENSITY_IDLE_SAMPLE_SECONDS=10    Idle CPU and wakeup window; 0 skips it
  MVM_HVF_DENSITY_MEMORY=512M               guest memory setting
  MVM_HVF_DENSITY_CPUS=2                    guest vCPU setting
  MVM_HVF_DENSITY_MAILBOX=1                  grant one distinct mailbox per VM
  MVM_HVF_DENSITY_ACK_LARGE=1                explicitly permit waves over 100 VMs
  Large waves also require configured guest RAM to fit within 80% of host RAM.
  Linux requires /dev/kvm and MVM's shipped Firecracker; unpinned overrides are refused.
  MVM_HVF_DENSITY_WORKLOAD_KERNEL=/path     seed isolated cache with this kernel
  MVM_HVF_DENSITY_SEED_HOST_KERNEL=0        do not auto-seed from ~/.cache/mvm
  MVM_HVF_DENSITY_SKIP_PREPULL=1            skip image pull before waves
  MVM_HVF_DENSITY_SKIP_BUILD=1              reuse existing binaries
  MVM_HVF_DENSITY_MVMCTL=/path/mvmctl       mvmctl binary override
  MVM_HVF_SUPERVISOR_PATH=/path/supervisor  supervisor binary override
  MVM_SUBSTITUTION_ENDPOINT_PATH=/path/bin  endpoint binary override
  MVM_HVF_DENSITY_MAILBOX_BIN=/path/bin      mailbox binary override
  MVM_HVF_DENSITY_ALLOW_BUSY_HOST=1         skip active build/runtime preflight
  MVM_HVF_DENSITY_ALLOW_UNSUPPORTED=1       bypass native backend host guard

Artifacts include command logs, VM names, launch failures, ps RSS snapshots,
host memory snapshots, and cleanup results. All generated state is isolated under
OUT_DIR unless an explicit override points elsewhere.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

GUEST_COMMAND=(sleep "${GUEST_SLEEP_SECONDS}")
CUSTOM_WORKLOAD=0
if [[ "$#" -gt 0 ]]; then
  if [[ "$1" != "--" ]]; then
    usage >&2
    echo "refusing: expected -- followed by guest command arguments" >&2
    exit 64
  fi
  shift
  if [[ "$#" -eq 0 ]]; then
    echo "refusing: -- requires a guest command" >&2
    exit 64
  fi
  GUEST_COMMAND=("$@")
  CUSTOM_WORKLOAD=1
fi

host_ok=0
case "${BACKEND}" in
  hvf)
    if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
      host_ok=1
    fi
    ;;
  firecracker)
    if [[ "$(uname -s)" == "Linux" && -r /dev/kvm && -w /dev/kvm ]]; then
      host_ok=1
    fi
    ;;
  *)
    echo "refusing: backend must be hvf or firecracker, got ${BACKEND}" >&2
    exit 64
    ;;
esac
if [[ "${MVM_HVF_DENSITY_ALLOW_UNSUPPORTED:-0}" != "1" && "${host_ok}" != "1" ]]; then
  usage >&2
  echo "refusing: ${BACKEND} density measurement requires its native host and hypervisor" >&2
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
  if ! [[ "${wave}" =~ ^[0-9]+$ ]] || [[ "${#wave}" -gt 4 ]] \
    || [[ "${wave}" -lt 1 ]] || [[ "${wave}" -gt 1000 ]]; then
    echo "refusing: invalid wave size ${wave}" >&2
    exit 70
  fi
  if [[ "${wave}" -gt "${MAX_WAVE}" ]]; then
    MAX_WAVE="${wave}"
  fi
done

if [[ "${MAILBOX}" != "0" && "${MAILBOX}" != "1" ]]; then
  echo "refusing: MVM_HVF_DENSITY_MAILBOX must be 0 or 1" >&2
  exit 70
fi
if [[ "${MAX_WAVE}" -gt 100 && "${MVM_HVF_DENSITY_ACK_LARGE:-0}" != "1" ]]; then
  echo "refusing: ${MAX_WAVE} concurrent VMs require MVM_HVF_DENSITY_ACK_LARGE=1" >&2
  exit 70
fi
if ! [[ "${MEMORY}" =~ ^([0-9]+)(M|G)$ ]] || [[ "${#BASH_REMATCH[1]}" -gt 6 ]]; then
  echo "refusing: MVM_HVF_DENSITY_MEMORY must be a positive MiB/GiB size (e.g. 512M)" >&2
  exit 70
fi
memory_mib=$((10#${BASH_REMATCH[1]}))
if [[ "${BASH_REMATCH[2]}" == "G" ]]; then
  memory_mib=$((memory_mib * 1024))
fi
if [[ "${memory_mib}" -eq 0 ]]; then
  echo "refusing: guest memory must be nonzero" >&2
  exit 70
fi
if [[ "${BACKEND}" == "hvf" ]]; then
  host_bytes="$(sysctl -n hw.memsize 2>/dev/null)" || host_bytes=""
else
  host_kib="$(awk '$1 == "MemTotal:" { print $2; exit }' /proc/meminfo)" || host_kib=""
  host_bytes=$(( ${host_kib:-0} * 1024 ))
fi
if ! [[ "${host_bytes}" =~ ^[0-9]+$ ]] || [[ "${host_bytes}" -eq 0 ]]; then
  echo "refusing: cannot determine host RAM for density safety check" >&2
  exit 70
fi
host_memory_mib=$((host_bytes / 1024 / 1024))
requested_memory_mib=$((MAX_WAVE * memory_mib))
# shortcut: configured guest RAM plus 20% host reserve; upgrade to measured admission accounting.
if [[ "${requested_memory_mib}" -gt "$((host_memory_mib * 80 / 100))" ]]; then
  echo "refusing: ${MAX_WAVE} x ${MEMORY} exceeds 80% of host RAM (${host_memory_mib} MiB)" >&2
  exit 70
fi
for seconds in "${LAUNCH_SPACING_SECONDS}" "${SETTLE_SECONDS}" "${GUEST_SLEEP_SECONDS}" \
  "${IDLE_SAMPLE_SECONDS}"; do
  if ! [[ "${seconds}" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "refusing: spacing, settle, idle sample and guest sleep durations must be nonnegative numbers" >&2
    exit 70
  fi
done
if [[ "${CUSTOM_WORKLOAD}" == "0" ]] && awk \
  -v wave="${MAX_WAVE}" -v spacing="${LAUNCH_SPACING_SECONDS}" \
  -v settle="${SETTLE_SECONDS}" -v guest="${GUEST_SLEEP_SECONDS}" \
  -v idle="${IDLE_SAMPLE_SECONDS}" \
  'BEGIN { exit !(guest <= wave * spacing + settle + idle + 60) }'; then
  echo "refusing: guest sleep must outlast the launch wave, settling, idle sample and 60s boot margin" >&2
  exit 70
fi

if [[ -e "${DATA_DIR}" || -L "${DATA_DIR}" ]]; then
  echo "refusing: density data directory must be new, so cleanup cannot stop existing machines: ${DATA_DIR}" >&2
  exit 65
fi
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

if [[ "${BACKEND}" == "hvf" ]]; then
  # macOS sockaddr_un paths are short; fail before the expensive prepull.
  longest_vm_name="${RUN_ID}-w${MAX_WAVE}-$(printf "%03d" "${MAX_WAVE}")"
  longest_agent_socket="${DATA_DIR}/vms/${longest_vm_name}/hvf-agent.sock"
  if [[ "${#longest_agent_socket}" -ge 104 ]]; then
    echo "refusing: HVF agent socket path would exceed macOS Unix socket length:" >&2
    echo "  ${longest_agent_socket}" >&2
    echo "choose a shorter MVM_HVF_DENSITY_OUT_DIR or MVM_HVF_DENSITY_DATA_DIR, for example /tmp/p237d" >&2
    exit 65
  fi
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
      if (args ~ /(mvm-hvf-supervisor|firecracker|mvmctl|mvm-network-endpoint|mvm-mailbox|mvm-host-agent)/) {
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
  if [[ "${BACKEND}" == "hvf" ]]; then
    "${run_env[@]}" cargo build -p mvm-hostd --bin mvm-hvf-supervisor
  fi
  if [[ "${MAILBOX}" == "1" ]]; then
    "${run_env[@]}" cargo build -p mvm-hostd --bin mvm-mailbox
  fi
fi

MVMCTL_BIN="${MVM_HVF_DENSITY_MVMCTL:-${TARGET_DIR}/debug/mvmctl}"
SUPERVISOR_BIN="${MVM_HVF_SUPERVISOR_PATH:-${TARGET_DIR}/debug/mvm-hvf-supervisor}"
ENDPOINT_BIN="${MVM_SUBSTITUTION_ENDPOINT_PATH:-${TARGET_DIR}/debug/mvm-network-endpoint}"
MAILBOX_BIN="${MVM_HVF_DENSITY_MAILBOX_BIN:-${TARGET_DIR}/debug/mvm-mailbox}"

if [[ ! -x "${MVMCTL_BIN}" ]]; then
  echo "refusing: mvmctl not executable at ${MVMCTL_BIN}" >&2
  exit 67
fi
if [[ "${BACKEND}" == "hvf" && ! -x "${SUPERVISOR_BIN}" ]]; then
  echo "refusing: mvm-hvf-supervisor not executable at ${SUPERVISOR_BIN}" >&2
  exit 68
fi
if [[ "${BACKEND}" == "firecracker" && -n "${MVM_FIRECRACKER_BIN:-}" ]]; then
  echo "refusing: MVM_FIRECRACKER_BIN is an unpinned override; use MVM's shipped Firecracker" >&2
  exit 68
fi
if [[ ! -x "${ENDPOINT_BIN}" ]]; then
  echo "refusing: mvm-network-endpoint not executable at ${ENDPOINT_BIN}" >&2
  exit 69
fi
if [[ "${MAILBOX}" == "1" && ! -x "${MAILBOX_BIN}" ]]; then
  echo "refusing: mvm-mailbox not executable at ${MAILBOX_BIN}" >&2
  exit 69
fi

run_env+=(
  "MVM_SUBSTITUTION_ENDPOINT_PATH=${ENDPOINT_BIN}"
)
if [[ "${BACKEND}" == "hvf" ]]; then
  run_env+=("MVM_HVF_SUPERVISOR_PATH=${SUPERVISOR_BIN}")
fi
if [[ "${MAILBOX}" == "1" ]]; then
  run_env+=("MVM_MAILBOX_PATH=${MAILBOX_BIN}")
fi

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
  # Only this run could have populated the fresh MVM_HOME. An interrupted wave
  # must not leave its VMs resident after the parent launchers are stopped.
  if [[ -d "${DATA_DIR}/vms" ]]; then
    "${run_env[@]}" "${MVMCTL_BIN}" machine stop --all --yes \
      >"${OUT_DIR}/interrupted-stop.stdout" 2>"${OUT_DIR}/interrupted-stop.stderr" \
      || echo "warning: interrupted VM stop failed; inspect ${OUT_DIR}/interrupted-stop.stderr" >&2
    "${run_env[@]}" "${MVMCTL_BIN}" machine rm --all --yes \
      >"${OUT_DIR}/interrupted-rm.stdout" 2>"${OUT_DIR}/interrupted-rm.stderr" \
      || echo "warning: interrupted VM removal failed; inspect ${OUT_DIR}/interrupted-rm.stderr" >&2
  fi
}
trap cleanup_active_pids INT TERM EXIT

capture_host_memory() {
  local phase="$1"
  local dir="$2"
  if [[ "${BACKEND}" == "hvf" ]]; then
    vm_stat >"${dir}/host-memory-${phase}.txt"
  else
    cp /proc/meminfo "${dir}/host-memory-${phase}.txt"
  fi
}

capture_processes() {
  local phase="$1"
  local dir="$2"
  local raw="${dir}/processes-${phase}.txt"
  local tsv="${dir}/rss-${phase}.tsv"
  ps axww -o pid=,rss=,comm=,args= >"${raw}"
  awk -f "${ROOT}/scripts/density_rss.awk" "${raw}" >>"${tsv}"
}

capture_mailbox_threads() {
  local phase="$1"
  local dir="$2"
  local pids="${dir}/mailbox-pids-${phase}.txt"
  local result="${dir}/mailbox-threads-${phase}.tsv"
  ps axww -o pid=,comm= | awk '$2 ~ /mvm-mailbox$/ { print $1 }' >"${pids}"
  printf 'pid\tthreads\n' >"${result}"
  while read -r pid; do
    [[ -n "${pid}" ]] || continue
    local threads
    if [[ -r "/proc/${pid}/status" ]]; then
      # Linux ps -M adds a security-label column and prints one row per process.
      threads="$(awk '/^Threads:/ { n = $2 } END { print n+0 }' "/proc/${pid}/status" 2>/dev/null)"
    else
      threads="$(ps -M -p "${pid}" 2>/dev/null | awk 'NR > 1 { n++ } END { print n+0 }')"
    fi
    printf '%s\t%s\n' "${pid}" "${threads}" >>"${result}"
  done <"${pids}"
}

capture_idle() {
  local dir="$1"
  local wave="$2"
  if awk -v idle="${IDLE_SAMPLE_SECONDS}" 'BEGIN { exit !(idle == 0) }'; then
    printf 'wave_%s_idle_sampler\tnot_requested\n' "${wave}" >>"${SUMMARY}"
    return 0
  fi
  # A failed sample is recorded and never fails the wave it was observing.
  if ! python3 "${ROOT}/scripts/density_idle.py" "${dir}" "${wave}" "${IDLE_SAMPLE_SECONDS}" \
    >>"${SUMMARY}" 2>"${dir}/idle-sample.stderr"; then
    printf 'wave_%s_idle_sampler\tunavailable:sample_failed\n' "${wave}" >>"${SUMMARY}"
  fi
}

capture_storage() {
  local phase="$1"
  local dir="$2"
  # df sees filesystem pressure; du may double-count reflinked blocks.
  df -k "${DATA_DIR}" >"${dir}/filesystem-${phase}.txt"
  if [[ -d "${DATA_DIR}/vms" ]]; then
    du -sk "${DATA_DIR}/vms" >"${dir}/vm-state-blocks-${phase}.txt"
  else
    printf '0\t%s\n' "${DATA_DIR}/vms" >"${dir}/vm-state-blocks-${phase}.txt"
  fi
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
  echo -e "backend\t${BACKEND}"
  echo -e "waves\t${WAVES_TEXT}"
  echo -e "guest_sleep_seconds\t${GUEST_SLEEP_SECONDS}"
  echo -e "settle_seconds\t${SETTLE_SECONDS}"
  echo -e "idle_sample_seconds\t${IDLE_SAMPLE_SECONDS}"
  echo -e "memory\t${MEMORY}"
  echo -e "host_memory_mib\t${host_memory_mib}"
  echo -e "max_wave_guest_memory_mib\t${requested_memory_mib}"
  echo -e "cpus\t${CPUS}"
  echo -e "mailbox\t${MAILBOX}"
  echo -e "custom_workload\t${CUSTOM_WORKLOAD}"
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

  capture_host_memory "before" "${wave_dir}"
  capture_processes "before" "${wave_dir}"
  capture_mailbox_threads "before" "${wave_dir}"
  capture_storage "before" "${wave_dir}"

  for i in $(seq 1 "${wave}"); do
    name="${RUN_ID}-w${wave}-$(printf "%03d" "${i}")"
    stdout="${wave_dir}/${name}.stdout"
    stderr="${wave_dir}/${name}.stderr"
    receipt="${wave_dir}/${name}.receipt.json"
    mailbox_args=()
    if [[ "${MAILBOX}" == "1" ]]; then
      mailbox_id="$(printf '%s' "${name}" | shasum -a 256 | awk '{print $1}')"
      mailbox_args=(--mailbox "${mailbox_id}")
    fi
    printf "%s\n" "${name}" >>"${wave_dir}/vm-names.txt"
    launch_ns="$(python3 -c 'import time; print(time.time_ns())')"
    "${run_env[@]}" "${MVMCTL_BIN}" machine run \
      --name "${name}" \
      --hypervisor "${BACKEND}" \
      --image "${IMAGE_REF}" \
      --memory "${MEMORY}" \
      --cpus "${CPUS}" \
      --receipt "${receipt}" \
      "${mailbox_args[@]}" \
      -- "${GUEST_COMMAND[@]}" \
      >"${stdout}" 2>"${stderr}" &
    pid=$!
    pids+=("${pid}")
    entries+=("${name}:${pid}")
    printf "%s\t%s\t%s\t%s\t%s\n" "${name}" "${pid}" "${stdout}" "${stderr}" "${launch_ns}" \
      >>"${wave_dir}/launches.tsv"
    printf "%s\n" "${pid}" >>"${active_pids_file}"
    sleep "${LAUNCH_SPACING_SECONDS}"
  done

  sleep "${SETTLE_SECONDS}"
  check_launches "${wave_dir}" "${entries[@]}"
  capture_host_memory "settled" "${wave_dir}"
  capture_processes "settled" "${wave_dir}"
  capture_mailbox_threads "settled" "${wave_dir}"
  capture_storage "settled" "${wave_dir}"
  capture_matching_processes "settled" "${wave_dir}"
  capture_idle "${wave_dir}" "${wave}"
  read -r mailbox_count mailbox_rss_kib < <(
    awk -F '\t' '$1 == "mvm-mailbox" { count = $2; rss = $3 }
      END { print count+0, rss+0 }' "${wave_dir}/rss-settled.tsv"
  )
  mailbox_threads="$(awk -F '\t' 'NR > 1 { n += $2 } END { print n+0 }' \
    "${wave_dir}/mailbox-threads-settled.tsv")"
  vm_state_kib="$(awk 'NR == 1 { print $1 }' "${wave_dir}/vm-state-blocks-settled.txt")"
  available_before="$(awk 'NR == 2 { print $4 }' "${wave_dir}/filesystem-before.txt")"
  available_settled="$(awk 'NR == 2 { print $4 }' "${wave_dir}/filesystem-settled.txt")"
  {
    printf 'wave_%s_mailbox_processes\t%s\n' "${wave}" "${mailbox_count}"
    printf 'wave_%s_mailbox_rss_kib\t%s\n' "${wave}" "${mailbox_rss_kib}"
    printf 'wave_%s_mailbox_threads\t%s\n' "${wave}" "${mailbox_threads}"
    printf 'wave_%s_vm_state_du_kib\t%s\n' "${wave}" "${vm_state_kib}"
    printf 'wave_%s_fs_available_delta_kib\t%s\n' \
      "${wave}" "$((available_before - available_settled))"
  } >>"${SUMMARY}"

  cleanup_ok=0
  if cleanup_wave "${wave_dir}" "${pids[@]}"; then
    cleanup_ok=1
  fi
  : >"${active_pids_file}"
  capture_host_memory "after-cleanup" "${wave_dir}"
  capture_processes "after-cleanup" "${wave_dir}"
  capture_mailbox_threads "after-cleanup" "${wave_dir}"
  capture_storage "after-cleanup" "${wave_dir}"

  failures="$(wc -l <"${wave_dir}/launch-failures.tsv" | tr -d ' ')"
  echo -e "wave_${wave}_launch_failures\t${failures}" >>"${SUMMARY}"
  echo -e "wave_${wave}_cleanup_ok\t${cleanup_ok}" >>"${SUMMARY}"
  if [[ "${failures}" -ne 0 || "${cleanup_ok}" -ne 1 ]]; then
    echo "wave ${wave} failed; see ${wave_dir}" >&2
    exit 71
  fi
  python3 "${ROOT}/scripts/density_timings.py" "${wave_dir}" "${wave}" >>"${SUMMARY}"
  first_message_status="not_requested"
  if [[ "${MAILBOX}" == "1" ]]; then
    first_message_status="unavailable:no_public_receipt_probe"
  fi
  printf 'wave_%s_first_durable_message_p95_ms\t%s\n' \
    "${wave}" "${first_message_status}" >>"${SUMMARY}"
  printf 'wave_%s_first_durable_message_p99_ms\t%s\n' \
    "${wave}" "${first_message_status}" >>"${SUMMARY}"
done

trap - INT TERM EXIT
echo "HVF density measurement complete: ${OUT_DIR}"
