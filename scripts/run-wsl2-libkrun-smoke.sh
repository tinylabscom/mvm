#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

if [ -f "$REPO_ROOT/scripts/dev-env.sh" ]; then
  # shellcheck source=/dev/null
  . "$REPO_ROOT/scripts/dev-env.sh"
fi

if ! grep -qi microsoft /proc/version 2>/dev/null; then
  echo "This smoke wrapper is intended to run inside a WSL2 distro." >&2
  exit 1
fi

if [ ! -c /dev/kvm ]; then
  echo "/dev/kvm is missing; nested KVM is required for the supported WSL2 workload path." >&2
  exit 1
fi

case "$REPO_ROOT" in
  /mnt/*)
    echo "Run this smoke from the WSL ext4 filesystem, not /mnt/<drive>/..." >&2
    exit 1
    ;;
esac

if [ -n "${MVM_DATA_DIR:-}" ]; then
  case "${MVM_DATA_DIR}" in
    /mnt/*)
      echo "MVM_DATA_DIR points at ${MVM_DATA_DIR}; move runtime state onto the WSL ext4 filesystem." >&2
      exit 1
      ;;
  esac
fi

for cmd in cargo curl socat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required host tool: $cmd" >&2
    exit 1
  fi
done

run_mvmctl() {
  cargo run --quiet --bin mvmctl -- "$@"
}

wait_for_exec() {
  vm_name=$1
  attempts=0
  while [ "$attempts" -lt 60 ]; do
    if output=$(run_mvmctl machine exec "$vm_name" -- /bin/sh -lc "printf agent-ready" 2>/dev/null); then
      if [ "$output" = "agent-ready" ]; then
        return 0
      fi
    fi
    attempts=$((attempts + 1))
    sleep 2
  done
  return 1
}

wait_for_local_http() {
  port=$1
  attempts=0
  while [ "$attempts" -lt 30 ]; do
    if curl -fsS "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  return 1
}

SMOKE_TMPDIR=$(mktemp -d /tmp/mvm-wsl2-smoke.XXXXXX)
APP_DIR="$SMOKE_TMPDIR/http-smoke"
FORWARD_LOG="$SMOKE_TMPDIR/forward.log"
FORWARD_PID=""
VM_NAME="wsl2-libkrun-smoke-$$"
LOCAL_FORWARD_PORT=18080

cleanup() {
  set +e
  if [ -n "$FORWARD_PID" ] && kill -0 "$FORWARD_PID" 2>/dev/null; then
    kill "$FORWARD_PID" 2>/dev/null || true
    wait "$FORWARD_PID" 2>/dev/null || true
  fi
  run_mvmctl machine stop "$VM_NAME" --yes >/dev/null 2>&1 || true
  rm -rf "$SMOKE_TMPDIR"
}
trap cleanup EXIT INT TERM

echo "==> WSL2/libkrun backend lifecycle smoke"
MVM_LIBKRUN_E2E=1 cargo test -p mvm-backend --test libkrun_lifecycle_e2e -- --ignored --nocapture

echo "==> Scaffold temporary HTTP workload manifest"
run_mvmctl init "$APP_DIR" --preset http >/dev/null

echo "==> Build workload artifacts"
run_mvmctl build image "$APP_DIR"

echo "==> Transient CLI smoke (`run --json --receipt`)"
MVM_LIVE_SMOKE=1 \
MVM_RUN_SMOKE_MANIFEST="$APP_DIR" \
  cargo test --test smoke_run_json_receipt -- --nocapture

echo "==> Persistent boot on libkrun"
run_mvmctl machine run -d --name "$VM_NAME" --manifest "$APP_DIR" --hypervisor libkrun

echo "==> Wait for guest-agent readiness"
if ! wait_for_exec "$VM_NAME"; then
  echo "guest agent never became reachable via \`machine exec\`" >&2
  exit 1
fi

echo "==> Verify simple exec and in-guest HTTP health"
run_mvmctl machine exec "$VM_NAME" -- /bin/sh -lc "printf exec-ok"
run_mvmctl machine exec "$VM_NAME" -- /bin/sh -lc "curl -fsS http://127.0.0.1:8080/ >/dev/null"

echo "==> Verify allow-host egress on transient libkrun run"
run_mvmctl machine run --manifest "$APP_DIR" --hypervisor libkrun --allow-host example.com:80 -- \
  /bin/sh -lc "curl -fsS http://example.com/ >/dev/null"

echo "==> Verify localhost port forwarding"
run_mvmctl machine forward "$VM_NAME" -p "${LOCAL_FORWARD_PORT}:8080" >"$FORWARD_LOG" 2>&1 &
FORWARD_PID=$!
if ! wait_for_local_http "$LOCAL_FORWARD_PORT"; then
  echo "localhost:${LOCAL_FORWARD_PORT} never became reachable through \`machine forward\`" >&2
  echo "--- forward log ---" >&2
  cat "$FORWARD_LOG" >&2
  exit 1
fi

echo "==> Verify clean stop and cleanup"
kill "$FORWARD_PID" 2>/dev/null || true
wait "$FORWARD_PID" 2>/dev/null || true
FORWARD_PID=""
run_mvmctl machine stop "$VM_NAME" --yes
if run_mvmctl ls --json | grep -F "\"name\":\"$VM_NAME\"" >/dev/null 2>&1; then
  echo "VM $VM_NAME still appears in \`mvmctl ls --json\` after stop" >&2
  exit 1
fi

echo "WSL2/libkrun smoke passed."
