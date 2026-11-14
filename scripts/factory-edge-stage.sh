#!/usr/bin/env bash
# Stage the factory-edge demo: start its three workloads ahead of the
# presentation so the demo itself, scripts/factory-edge-demo-live.sh, drives
# machines that are already running and shows the work and the refusal without
# waiting on a launch.
#
#   scripts/factory-edge-stage.sh          stage the workloads (replaces any earlier staging)
#   scripts/factory-edge-stage.sh --down   remove the staged workloads
#
# Three named machines are started in the background, each holding its own
# scoped network grant:
#   fe-line-a-<id>, fe-line-b-<id>   inspection workloads that each send a result to the
#                          one destination they are granted, every INSPECT_EVERY
#                          seconds (5); every lookup becomes a signed chain
#                          entry, so a fast cadence slows explain and verify;
#                          the host records each lookup as dns.resolved
#   fe-maint-<id>          the maintenance workload; after ATTEMPT_AFTER seconds
#                          it asks for a destination it was not granted, and
#                          asks again every ATTEMPT_EVERY seconds
#
# The workloads act on their own, so nothing is run inside them from the host:
# the dev-only exec verb is never used, which keeps the posture the demo shows.
#
# Like the demo, this ASSUMES an installed mvmctl and a prepared home and
# installs nothing: a missing prerequisite stops it before anything starts, and
# any first-use preparation that happens while staging is reported as a FINDING
# and fails it. Prepare once, outside the demo:
#   mvmctl image pull curlimages/curl:8.21.0     (with MVM_HOME set)
#   and one throwaway `mvmctl run` of that image, so the runtime is built.
#
#   MVMCTL, MVM_HOME, HYPERVISOR, BUILDER, IMAGE, GRANT_A, GRANT_B, APPROVED,
#   UNAPPROVED, WAIT_SECS   as in factory-edge-demo-live.sh
#   ATTEMPT_AFTER   seconds before the maintenance workload's first request
#                   (default 30)
#   ATTEMPT_EVERY   seconds between its requests (default 30)
#   INSPECT_EVERY   seconds between an inspection workload's requests (default 5)
set -uo pipefail

MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-curlimages/curl:8.21.0}"
GRANT_A="${GRANT_A:-pypi.org:443}"
GRANT_B="${GRANT_B:-files.pythonhosted.org:443}"
APPROVED="${APPROVED:-api.github.com:443}"
UNAPPROVED="${UNAPPROVED:-example.com}"
WAIT_SECS="${WAIT_SECS:-120}"
ATTEMPT_AFTER="${ATTEMPT_AFTER:-30}"
ATTEMPT_EVERY="${ATTEMPT_EVERY:-30}"
INSPECT_EVERY="${INSPECT_EVERY:-5}"
if [ -z "${HYPERVISOR:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then HYPERVISOR=hvf; else HYPERVISOR=firecracker; fi
fi
case "$HYPERVISOR" in hvf | firecracker) ;; *) echo "FAIL unsupported HYPERVISOR=$HYPERVISOR (hvf or firecracker)" >&2; exit 2 ;; esac
bld=(); [ -z "${BUILDER:-}" ] || bld=(--builder "$BUILDER")
export MVM_HOME="${MVM_HOME:-$HOME/.mvm-demo}"
export MVM_RESIDENCY=cold

# Each staging gets its own names, so `mvmctl explain <name>` never matches an earlier staging's runs.
id="$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
LINE_A="fe-line-a-$id"; LINE_B="fe-line-b-$id"; MAINT="fe-maint-$id"
tmp="$(mktemp -d)"
errlog="$tmp/stderr.log"; : > "$errlog"
cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && grep -q 'mvmctl bootstrap' "$errlog"; then
    echo "FINDING: the install asked for 'mvmctl bootstrap'. A release must run with no bootstrap step." >&2
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
mvm() { "$MVMCTL" ${bld[@]+"${bld[@]}"} "$@" 2>>"$errlog"; }
say() { echo "PASS $*"; }
fail() {
  echo "FAIL $*" >&2
  if [ -s "$errlog" ]; then echo "--- mvmctl log (last lines) ---" >&2; tail -n 12 "$errlog" >&2; fi
  exit 1
}
status_of() { mvm machine ls 2>/dev/null </dev/null | awk -v n="$1" '$1 == n { print $3 }'; }
until_ok() { # <what> <cmd...>
  local what="$1" end=$((SECONDS + WAIT_SECS)); shift
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || fail "timed out waiting for $what"
    sleep 0.5
  done
}
is_running() { [ "$(status_of "$1")" = running ]; }
# The host's record that a workload looked up its granted destination (an allowed lookup).
allowed_for() { # <vm>: a lookup recorded since this staging began
  [ "$(python3 -I -c "
import json, sys
from datetime import datetime
t = lambda s: datetime.fromisoformat(s.replace('Z', '+00:00'))
vm, since = sys.argv[1], t(sys.argv[2])
n = 0
for line in open(sys.argv[3], errors='replace'):
    if 'dns.resolved' not in line or vm not in line: continue
    try: e = json.loads(line)['entry']
    except Exception: continue
    if e.get('event') == 'dns.resolved' and e['labels'].get('vm_name') == vm and t(e['timestamp']) >= since: n += 1
print(n)" "$1" "$staged_at" "$MVM_HOME/audit/local.jsonl")" -ge 1 ]
}
down() { # remove every machine an earlier staging left behind
  local m
  for m in $(mvm machine ls 2>/dev/null </dev/null | awk '$1 ~ /^fe-(line-a|line-b|maint)-/ { print $1 }'); do
    mvm machine stop "$m" --yes >/dev/null 2>&1 </dev/null || true
    mvm machine rm "$m" --yes >/dev/null 2>&1 </dev/null || true
  done
}

if [ "${1:-}" = --down ]; then down; echo "staged workloads removed"; exit 0; fi

echo "== 0. preconditions (nothing is installed or prepared here)"
mvm --version >/dev/null 2>&1 || fail "no usable mvmctl ($MVMCTL): the demo assumes it is installed"
[ -d "$MVM_HOME" ] || fail "demo home $MVM_HOME does not exist: prepare it first (mvmctl image pull $IMAGE, then one throwaway run)"
mvm image ls </dev/null | grep -qF "${IMAGE#docker.io/}" \
  || fail "$IMAGE is not cached in $MVM_HOME: prepare it first (mvmctl image pull $IMAGE); staging does not install"
say "mvmctl $(mvm --version | awk '{print $2}') on $HYPERVISOR, home $MVM_HOME, $IMAGE cached"

echo "== 1. staging the three workloads"
down
staged_at="$(python3 -I -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())")"
# An inspection workload's work: send a result to its granted destination, repeatedly.
inspect() { echo "while true; do curl -sS -m 10 -o /dev/null https://$1/ >/dev/null 2>&1; sleep $INSPECT_EVERY; done"; }
start() { # <name> <grant> <script>
  mvm run -d --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$1" --allow-host "$2" -- sh -c "$3" >/dev/null </dev/null \
    || fail "could not start $1"
}
start "$LINE_A" "$GRANT_A" "$(inspect "${GRANT_A%%:*}")"
start "$LINE_B" "$GRANT_B" "$(inspect "${GRANT_B%%:*}")"
start "$MAINT" "$APPROVED" "sleep $ATTEMPT_AFTER; while true; do curl -sS -m 10 https://$UNAPPROVED/ >/dev/null 2>&1; sleep $ATTEMPT_EVERY; done"
for m in "$LINE_A" "$LINE_B" "$MAINT"; do until_ok "$m to be running" is_running "$m"; done
say "all three workloads are running"
for m in "$LINE_A" "$LINE_B"; do until_ok "the host to record $m's lookup of its granted destination" allowed_for "$m"; done
say "both inspection workloads are working: the host recorded each one's lookup of its granted destination"

if grep -q -E 'first use only|Preparing the (workload kernel|guest runtime)|runtime not prepared' "$errlog"; then
  echo "FINDING: install-time preparation ran while staging ($(grep -m1 -E 'first use only|Preparing the|runtime not prepared' "$errlog")). Prepare the home before the demo." >&2
  exit 1
fi
say "no install-time preparation ran"
echo "STAGED: the maintenance workload makes its first request in ${ATTEMPT_AFTER}s. Run scripts/factory-edge-demo-live.sh."
