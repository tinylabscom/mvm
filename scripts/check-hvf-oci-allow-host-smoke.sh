#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${MVM_HVF_ALLOW_HOST_OUT_DIR:-/tmp/mvm-hvf-allow-host-smoke-${STAMP}}"
DATA_DIR="${MVM_HVF_ALLOW_HOST_DATA_DIR:-${OUT_DIR}/data}"
GUEST_OUT="${MVM_HVF_ALLOW_HOST_GUEST_OUT:-/tmp/hvf-egress-guest}"
ALLOW_HOST="${MVM_HVF_ALLOW_HOST_HOST:-google.com}"
IMAGE_REF="${MVM_HVF_ALLOW_HOST_IMAGE:-alpine}"
SKIP_BUILD="${MVM_HVF_ALLOW_HOST_SKIP_BUILD:-0}"
SKIP_RELAY_PROOF="${MVM_HVF_ALLOW_HOST_SKIP_RELAY_PROOF:-0}"

usage() {
  cat <<USAGE
Live macOS HVF OCI allow-host smoke.

This script packages two runtime proofs:
  1. The exact CLI path:
       mvmctl machine run --hypervisor hvf --image alpine --allow-host google.com -- ps aux
  2. A host-vsock admit/deny relay proof that demonstrates allowed traffic is
     reachable and a non-admitted destination is refused, with no guest NIC.

Required host:
  - macOS on Apple Silicon

Useful overrides:
  MVM_HVF_ALLOW_HOST_OUT_DIR=/tmp/path     evidence directory
  MVM_HVF_ALLOW_HOST_DATA_DIR=/tmp/path    isolated MVM_HOME
  MVM_HVF_ALLOW_HOST_HOST=google.com       allow-host target for the exact CLI proof
  MVM_HVF_ALLOW_HOST_IMAGE=alpine          OCI image for the exact CLI proof
  MVM_HVF_ALLOW_HOST_SKIP_BUILD=1          skip helper binary builds
  MVM_HVF_ALLOW_HOST_SKIP_RELAY_PROOF=1    run only the exact CLI proof
  MVM_HVF_KERNEL=/path/to/kernel           kernel for the relay proof
  MVM_HVF_INITRD=/path/to/initramfs.cpio   initramfs for the relay proof
  MVM_HVF_SUPERVISOR_PATH=/path/to/bin     use an existing supervisor binary
  MVM_SUBSTITUTION_ENDPOINT_PATH=/path/to/bin
  MVM_HVF_ALLOW_HOST_ALLOW_UNSUPPORTED=1   bypass host guard

Evidence is written only under OUT_DIR and /tmp guest build directories.
USAGE
}

host_ok=1
if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  host_ok=0
fi
if [[ "${MVM_HVF_ALLOW_HOST_ALLOW_UNSUPPORTED:-0}" != "1" && "${host_ok}" != "1" ]]; then
  usage >&2
  echo "refusing: this smoke expects macOS on Apple Silicon" >&2
  exit 64
fi

mkdir -p "${OUT_DIR}"
CLI_STDOUT="${OUT_DIR}/machine-run.stdout"
CLI_STDERR="${OUT_DIR}/machine-run.stderr"
RELAY_STDOUT="${OUT_DIR}/relay-proof.stdout"
RELAY_STDERR="${OUT_DIR}/relay-proof.stderr"
SUMMARY="${OUT_DIR}/summary.txt"

cd "${ROOT}"

if [[ "${SKIP_BUILD}" != "1" ]]; then
  cargo build -p mvmctl --bin mvmctl --features embed-host-bins
  cargo build -p mvm-hostd --bin mvm-network-endpoint
  cargo build -p mvm-hostd --bin mvm-hvf-supervisor
fi

MVMCTL_BIN="${MVM_HVF_ALLOW_HOST_MVMCTL:-${ROOT}/target/debug/mvmctl}"
SUPERVISOR_BIN="${MVM_HVF_SUPERVISOR_PATH:-${ROOT}/target/debug/mvm-hvf-supervisor}"
ENDPOINT_BIN="${MVM_SUBSTITUTION_ENDPOINT_PATH:-${ROOT}/target/debug/mvm-network-endpoint}"

if [[ ! -x "${MVMCTL_BIN}" ]]; then
  echo "refusing: mvmctl not executable at ${MVMCTL_BIN}" >&2
  exit 65
fi
if [[ ! -x "${SUPERVISOR_BIN}" ]]; then
  echo "refusing: mvm-hvf-supervisor not executable at ${SUPERVISOR_BIN}" >&2
  exit 66
fi
if [[ ! -x "${ENDPOINT_BIN}" ]]; then
  echo "refusing: mvm-network-endpoint not executable at ${ENDPOINT_BIN}" >&2
  exit 67
fi

run_env=(
  env
  "MVM_HOME=${DATA_DIR}"
  "MVM_HVF_SUPERVISOR_PATH=${SUPERVISOR_BIN}"
  "MVM_SUBSTITUTION_ENDPOINT_PATH=${ENDPOINT_BIN}"
)

echo "==> exact CLI proof"
"${run_env[@]}" \
  "${MVMCTL_BIN}" machine run --hypervisor hvf --image "${IMAGE_REF}" --allow-host "${ALLOW_HOST}" -- ps aux \
  >"${CLI_STDOUT}" 2>"${CLI_STDERR}"

grep -q "/usr/local/bin/mvm-egress-client" "${CLI_STDOUT}" || {
  echo "missing mvm-egress-client in guest process table" >&2
  exit 68
}
grep -q "/usr/local/bin/mvm-guest-agent" "${CLI_STDOUT}" || {
  echo "missing mvm-guest-agent in guest process table" >&2
  exit 69
}

if [[ "${SKIP_RELAY_PROOF}" != "1" ]]; then
  echo "==> relay admit/deny proof guest"
  OUT="${GUEST_OUT}" bash crates/mvm-runtime/examples/hvf-egress-guest/build.sh

  KERNEL="${MVM_HVF_KERNEL:-${HOME}/.cache/mvm/builder-vm/aarch64/vmlinux}"
  INITRD="${MVM_HVF_INITRD:-${GUEST_OUT}/initramfs.cpio}"
  if [[ ! -f "${KERNEL}" ]]; then
    echo "refusing: relay proof kernel missing at ${KERNEL}" >&2
    exit 70
  fi
  if [[ ! -f "${INITRD}" ]]; then
    echo "refusing: relay proof initramfs missing at ${INITRD}" >&2
    exit 71
  fi

  "${run_env[@]}" \
    "MVM_HVF_KERNEL=${KERNEL}" \
    "MVM_HVF_INITRD=${INITRD}" \
    cargo run -p mvm-runtime --example hvf-relay-egress \
    >"${RELAY_STDOUT}" 2>"${RELAY_STDERR}"

  grep -q "admitted destination reachable: true" "${RELAY_STDOUT}" || {
    echo "relay proof did not admit the allowed destination" >&2
    exit 72
  }
  grep -q "non-admitted destination reachable: false" "${RELAY_STDOUT}" || {
    echo "relay proof did not refuse the non-admitted destination" >&2
    exit 73
  }
fi

{
  echo "HVF OCI allow-host smoke: PASS"
  echo "out_dir=${OUT_DIR}"
  echo "cli_stdout=${CLI_STDOUT}"
  echo "cli_stderr=${CLI_STDERR}"
  if [[ "${SKIP_RELAY_PROOF}" != "1" ]]; then
    echo "relay_stdout=${RELAY_STDOUT}"
    echo "relay_stderr=${RELAY_STDERR}"
  fi
} | tee "${SUMMARY}"
