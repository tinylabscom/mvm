#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${MVM_HVF_ALLOW_HOST_OUT_DIR:-/tmp/mvm-hvf-allow-host-smoke-${STAMP}}"
DATA_DIR="${MVM_HVF_ALLOW_HOST_DATA_DIR:-${MVM_HOME:-${OUT_DIR}/data}}"
ALLOW_HOST="${MVM_HVF_ALLOW_HOST_HOST:-example.com}"
DENY_HOST="${MVM_HVF_DENY_HOST:-example.org}"
IMAGE_REF="${MVM_HVF_ALLOW_HOST_IMAGE:-python:3.12-alpine}"

usage() {
  cat <<USAGE
Live macOS HVF OCI vsock-egress smoke. Boots a Python OCI workload and checks
that it has no guest NIC or TUN device, the guest runtime is present, an
allow-listed HTTPS destination works, and an unlisted destination is denied.

Required host: macOS on Apple Silicon.

Useful overrides:
  MVM_HVF_ALLOW_HOST_OUT_DIR=/tmp/path    evidence directory
  MVM_HVF_ALLOW_HOST_DATA_DIR=/tmp/path   isolated MVM_HOME
  MVM_HVF_ALLOW_HOST_HOST=example.com     allowed HTTPS host
  MVM_HVF_DENY_HOST=example.org          denied HTTPS host
  MVM_HVF_ALLOW_HOST_IMAGE=python:3.12-alpine  Python 3 OCI image
  MVM_HVF_SUPERVISOR_PATH=/path/to/bin    use an existing HVF supervisor
  MVM_SUBSTITUTION_ENDPOINT_PATH=/path/to/bin  use an existing endpoint

Evidence is written under OUT_DIR. MVM_HOME and CARGO_TARGET_DIR are honored.
USAGE
}

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  if [[ "${MVM_HVF_ALLOW_HOST_ALLOW_UNSUPPORTED:-0}" != "1" ]]; then
    usage >&2
    echo "refusing: this smoke expects macOS on Apple Silicon" >&2
    exit 64
  fi
fi

if [[ "${ALLOW_HOST}" == "${DENY_HOST}" || -z "${ALLOW_HOST}" || -z "${DENY_HOST}" ]]; then
  echo "refusing: allowed and denied hosts must be distinct, nonempty names" >&2
  exit 65
fi
if [[ -n "${MVM_SKIP_COSIGN_VERIFY+x}" || -n "${MVM_SKIP_HASH_VERIFY+x}" ]]; then
  echo "refusing: verification-bypass environment variables invalidate this smoke" >&2
  exit 65
fi

mkdir -p "${OUT_DIR}"
CLI_STDOUT="${OUT_DIR}/machine-run.stdout"
CLI_STDERR="${OUT_DIR}/machine-run.stderr"
SUMMARY="${OUT_DIR}/summary.txt"

cd "${ROOT}"
cargo build -p mvmctl -p mvm-hostd --features mvmctl/user \
  --bin mvmctl --bin mvm-network-endpoint --bin mvm-hvf-supervisor

TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
if [[ "${TARGET_DIR}" != /* ]]; then
  TARGET_DIR="${ROOT}/${TARGET_DIR}"
fi
MVMCTL_BIN="${TARGET_DIR}/debug/mvmctl"
SUPERVISOR_BIN="${MVM_HVF_SUPERVISOR_PATH:-${TARGET_DIR}/debug/mvm-hvf-supervisor}"
ENDPOINT_BIN="${MVM_SUBSTITUTION_ENDPOINT_PATH:-${TARGET_DIR}/debug/mvm-network-endpoint}"

for binary in "${MVMCTL_BIN}" "${SUPERVISOR_BIN}" "${ENDPOINT_BIN}"; do
  if [[ ! -x "${binary}" ]]; then
    echo "refusing: required binary not executable at ${binary}" >&2
    exit 66
  fi
done

GUEST_PROBE='import pathlib, sys, urllib.error, urllib.request
allowed, denied = sys.argv[1:]
devices = sorted(path.name for path in pathlib.Path("/sys/class/net").iterdir())
if devices != ["lo"] or pathlib.Path("/dev/net/tun").exists():
    raise SystemExit(f"unexpected guest network devices: {devices}")
print("HVF_PROBE_NO_NIC_OK", flush=True)
commands = []
for process in pathlib.Path("/proc").iterdir():
    if process.name.isdigit():
        try:
            commands.append((process / "cmdline").read_bytes().split(b"\0", 1)[0])
        except OSError:
            continue
if b"/mvm/runtime/egress-client" not in commands:
    raise SystemExit("missing guest egress-client process")
print("HVF_PROBE_RUNTIME_OK", flush=True)
with urllib.request.urlopen(f"https://{allowed}", timeout=20) as response:
    if response.status != 200:
        raise SystemExit(f"allowed HTTPS returned {response.status}")
print("HVF_PROBE_ALLOW_OK", flush=True)
try:
    urllib.request.urlopen(f"https://{denied}", timeout=20)
except (urllib.error.HTTPError, urllib.error.URLError):
    print("HVF_PROBE_DENY_ERROR", flush=True)
else:
    raise SystemExit("unlisted HTTPS destination was reachable")
print("HVF_PROBE_DENY_OK", flush=True)'

echo "==> production FlowMux admit/deny proof"
env \
  "MVM_HOME=${DATA_DIR}" \
  "MVM_HVF_SUPERVISOR_PATH=${SUPERVISOR_BIN}" \
  "MVM_SUBSTITUTION_ENDPOINT_PATH=${ENDPOINT_BIN}" \
  "${MVMCTL_BIN}" machine run --hypervisor hvf --image "${IMAGE_REF}" \
    --allow-host "${ALLOW_HOST}:443" -- python3 -c "${GUEST_PROBE}" \
    "${ALLOW_HOST}" "${DENY_HOST}" \
    >"${CLI_STDOUT}" 2>"${CLI_STDERR}"

for marker in HVF_PROBE_NO_NIC_OK HVF_PROBE_RUNTIME_OK HVF_PROBE_ALLOW_OK HVF_PROBE_DENY_ERROR HVF_PROBE_DENY_OK; do
  if ! grep -Fxq "${marker}" "${CLI_STDOUT}"; then
    echo "missing guest proof marker: ${marker}; see ${CLI_STDOUT} and ${CLI_STDERR}" >&2
    exit 67
  fi
done
if ! grep -Fq "egress blocked: ${DENY_HOST}:443 (not in the allow-list)" "${CLI_STDERR}"; then
  echo "missing host policy denial audit for ${DENY_HOST}:443; see ${CLI_STDERR}" >&2
  exit 68
fi

{
  echo "HVF OCI allow-host smoke: PASS"
  echo "out_dir=${OUT_DIR}"
  echo "cli_stdout=${CLI_STDOUT}"
  echo "cli_stderr=${CLI_STDERR}"
} | tee "${SUMMARY}"
