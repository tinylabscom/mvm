#!/usr/bin/env bash
# Boot a real Firecracker guest under a non-dev, no-ad-hoc plan. The flake
# bakes the workload's Python entrypoint into its image; no machine exec is
# used to inject the operation after admission.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MVMCTL="${MVMCTL:-${CARGO_BIN_EXE_mvmctl:-${repo}/target/debug/mvmctl}}"
own_home=0
home="${MVM_HOME:-}"
if [ -z "$home" ]; then
  home="$(mktemp -d)"
  own_home=1
fi
export MVM_HOME="$home"
name="bdd-local-mailbox-$$"
missing="bdd-no-retention-$$"
id="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
fixture="${repo}/features/suites/s40_mission_demo/fixtures"

cleanup() {
  status=$?
  trap - EXIT
  "$MVMCTL" machine stop "$name" --yes >/dev/null 2>&1 || true
  "$MVMCTL" machine rm "$name" --yes >/dev/null 2>&1 || true
  "$MVMCTL" machine stop "$missing" --yes >/dev/null 2>&1 || true
  "$MVMCTL" machine rm "$missing" --yes >/dev/null 2>&1 || true
  if [ "$own_home" -eq 1 ]; then rm -rf -- "$home"; fi
  exit "$status"
}
trap cleanup EXIT

mkdir -m 700 "$home/config"
printf 'max_mailbox_retention_ms = 600000\n' >"$home/config/config.toml"

launch=(
  machine run -d --entrypoint --name "$name" --profile standard
  --hypervisor firecracker --flake "$fixture" --timeout 300
  --mailbox "$id" --mailbox-retention-ms 600000
)
"$MVMCTL" "${launch[@]}" >"$home/launch.log" 2>&1 || {
  cat "$home/launch.log" >&2
  exit 1
}
for marker in mailbox-local-pending mailbox-local-receipt-verified mailbox-local-ack-committed; do
  grep -qF "$marker" "$home/launch.log" || {
    cat "$home/launch.log" >&2
    echo "missing booted guest marker: $marker" >&2
    exit 1
  }
done

pidfile="$home/vms/$name/mailbox.pid"
test -s "$pidfile" || { echo "production mailbox helper did not start" >&2; exit 1; }
journal="$(find "$home/keys" -type d -name '*.journal')"
anchor="$(find "$home/keys" -type f -name '*.anchor')"
test -n "$journal" && test -d "$journal"
test -n "$anchor" && test -f "$anchor"
test "$(printf '%s\n' "$journal" | wc -l)" -eq 1
test "$(printf '%s\n' "$anchor" | wc -l)" -eq 1
"$MVMCTL" trust audit verify
echo "booted guest: verified V2 acceptance and signed Receive/ACK"

# No signed retention means production must refuse before publishing a helper
# or any local-durable receipt, even when the guest has a mailbox grant.
if "$MVMCTL" machine run -d --name "$missing" --profile standard \
  --entrypoint --hypervisor firecracker --flake "$fixture" \
  --mailbox "$id" 2>"$home/refusal"; then
  echo "production accepted a mailbox without signed retention" >&2
  exit 1
fi
grep -q 'signed retention' "$home/refusal" || {
  cat "$home/refusal" >&2
  echo "production refusal did not name signed retention" >&2
  exit 1
}
test ! -e "$home/vms/$missing/mailbox.pid"
echo "booted guest: missing retention refused before helper readiness"

"$MVMCTL" machine stop "$name" --yes
test -d "$journal" && test -f "$anchor"
"$MVMCTL" trust audit verify
echo "booted guest: retained journal survived the VM stop"
echo "WITNESS_RESULT=pass"
