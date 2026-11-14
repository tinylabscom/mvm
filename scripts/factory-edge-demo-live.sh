#!/usr/bin/env bash
# Live runbook for the factory-edge presentation on ONE real machine (beats 3 to
# 5 of the "Proposed factory-edge presentation" in
# specs/contracts/host-interface-distributed-execution.md). It observes three
# workloads that scripts/factory-edge-stage.sh started ahead of time, each
# holding its own scoped network grant: the two inspection workloads keep
# working, the maintenance workload asks for a destination it was not granted
# and the host refuses and records it, the refusal is read back through
# `mvmctl explain`, and the suspect workload is stopped and a fresh one launched
# under a new plan.
#
# Run the stage script first. Nothing is run inside the workloads from the host,
# so the dev-only exec verb is never used.
#
# The demo ASSUMES an installed mvmctl, a prepared home and staged workloads.
# Nothing here installs, pulls an image or prepares a runtime: a missing
# prerequisite stops the run before it starts, and any first-use preparation
# that happens during the run is reported as a FINDING and fails it. Every wait
# is a poll for the condition it waits on, not a fixed pause.
#
# This is a CLI proof of the demo. The same operations are what Studio will
# drive through the `mvm-client` library; this script is the reference the
# integration is checked against: read a run back
# (`mvm_client::explain::explain_local_run`), stop a machine, launch a workload
# and verify the audit chain.
#
# For maintainers, what this does NOT show: Studio's own readback, the real
# maintenance and inspection tasks (the workloads are small curl loops over
# synthetic traffic), hot replacement, a production-profile run, or anything on
# a physical line. The inspection workloads' work is observed as the host's
# `dns.resolved` records for their granted destination, because a detached
# machine's own output is not readable from the host. The replacement is a live
# launch, which on v0.28.0-rc.2 costs about three seconds of host-side
# admission and runtime attach before the guest starts; launches boot cold on
# purpose (MVM_RESIDENCY=cold) because a warm claim measured no faster there and
# a warm-claimed run's refusals are recorded under the standby's machine name,
# so `explain` would not show them.
#
#   MVMCTL        the mvmctl to drive (default: mvmctl on PATH)
#   MVM_HOME      the prepared demo home (default: ~/.mvm-demo)
#   HYPERVISOR    hvf (default on macOS) or firecracker (default on Linux)
#   BUILDER       passed as --builder when set
#   IMAGE         OCI image with curl (default: curlimages/curl:8.21.0)
#   APPROVED      the destination the maintenance workload and its replacement
#                 are granted (default: api.github.com:443)
#   UNAPPROVED    the host the maintenance workload asks for (default: example.com)
#   GRANT_A, GRANT_B  the inspection workloads' destinations, as staged
#                 (default: pypi.org:443, files.pythonhosted.org:443)
#   WAIT_SECS     longest any single wait may take (default: 120)
set -uo pipefail

MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-curlimages/curl:8.21.0}"
APPROVED="${APPROVED:-api.github.com:443}"
UNAPPROVED="${UNAPPROVED:-example.com}"
GRANT_A="${GRANT_A:-pypi.org:443}"
GRANT_B="${GRANT_B:-files.pythonhosted.org:443}"
WAIT_SECS="${WAIT_SECS:-120}"
if [ -z "${HYPERVISOR:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then HYPERVISOR=hvf; else HYPERVISOR=firecracker; fi
fi
case "$HYPERVISOR" in hvf | firecracker) ;; *) echo "FAIL unsupported HYPERVISOR=$HYPERVISOR (hvf or firecracker)" >&2; exit 2 ;; esac
bld=(); [ -z "${BUILDER:-}" ] || bld=(--builder "$BUILDER")
export MVM_HOME="${MVM_HOME:-$HOME/.mvm-demo}"
export MVM_RESIDENCY=cold

tmp="$(mktemp -d)"
errlog="$tmp/stderr.log"; : > "$errlog"
started=$SECONDS
mvm() { "$MVMCTL" ${bld[@]+"${bld[@]}"} "$@" 2>>"$errlog"; }
say() { echo "PASS $*"; }
fail() {
  echo "FAIL $*" >&2
  if [ -s "$errlog" ]; then echo "--- mvmctl log (last lines) ---" >&2; tail -n 12 "$errlog" >&2; fi
  exit 1
}
cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && grep -q 'mvmctl bootstrap' "$errlog"; then
    echo "FINDING: the install asked for 'mvmctl bootstrap'. A release must run with no bootstrap step." >&2
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

until_ok() { # <what> <cmd...>   poll; a wait never lasts longer than WAIT_SECS
  local what="$1" end=$((SECONDS + WAIT_SECS)); shift
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || fail "timed out waiting for $what"
    sleep 0.5
  done
}
status_of() { mvm machine ls 2>/dev/null </dev/null | awk -v n="$1" '$1 == n { print $3 }'; }
is_status() { [ "$(status_of "$1")" = "$2" ]; }
chain() { echo "$MVM_HOME/audit/local.jsonl"; }
# How many allowed lookups the host recorded for machine <vm> at or after <iso>.
lookups_since() { # <vm> <iso>
  python3 -I -c "
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
print(n)" "$1" "$2" "$(chain)"
}
has_lookup_since() { [ "$(lookups_since "$1" "$2")" -ge 1 ]; }
now_iso() { python3 -I -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat())"; }
# `mvmctl explain` verifies the whole audit chain, so each run is fetched once and
# read many times.
fetch_explain() { # <name or plan> <slot>
  mvm explain "$1" --json </dev/null >"$tmp/explain.$2.json" || fail "mvmctl explain $1 failed"
}
field() { # <slot> <expression over d>
  python3 -I -c "
import json, sys
d = json.load(open(sys.argv[1]))
print($2)" "$tmp/explain.$1.json"
}
denials_of() { field "$1" "len(d['egress_denials'])"; }
# Refusals the chain holds for machine <vm> that name UNAPPROVED (read straight from the chain).
refusals_of() { # <vm>
  python3 -I -c "
import json, sys
vm, bad = sys.argv[1], sys.argv[2]
n = 0
for line in open(sys.argv[3], errors='replace'):
    if bad not in line or vm not in line: continue
    try: e = json.loads(line)['entry']
    except Exception: continue
    l = e['labels']
    if e.get('event') in ('dns.refused', 'host.flow.denied') and l.get('vm_name') == vm and bad in (l.get('qname', '') + l.get('target', '')): n += 1
print(n)" "$1" "$UNAPPROVED" "$(chain)"
}
has_refusal() { [ "$(refusals_of "$1")" -ge 1 ]; }
token() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }
plan_of() { # <token> -> the plan id the chain recorded for the run bound to it
  python3 -I -c "
import json, sys
tok = sys.argv[1]
for line in open(sys.argv[2], errors='replace'):
    if tok in line:
        try: e = json.loads(line)['entry']
        except Exception: continue
        if e.get('event') == 'plan.admitted':
            print(e['plan_id']); break" "$1" "$(chain)"
}

echo "== 0. preconditions (nothing is installed, prepared or started here)"
mvm --version >/dev/null 2>&1 || fail "no usable mvmctl ($MVMCTL): the demo assumes it is installed"
[ -d "$MVM_HOME" ] || fail "demo home $MVM_HOME does not exist: prepare it first (mvmctl image pull $IMAGE, then one throwaway run)"
# The staged machines carry a per-staging suffix; find the running ones.
running_named() { mvm machine ls 2>/dev/null </dev/null | awk -v p="^$1-" '$1 ~ p && $3 == "running" { print $1; exit }'; }
LINE_A="$(running_named fe-line-a)"; LINE_B="$(running_named fe-line-b)"; MAINT="$(running_named fe-maint)"
for m in "$LINE_A" "$LINE_B" "$MAINT"; do
  [ -n "$m" ] || fail "the three workloads are not all running: stage them first (scripts/factory-edge-stage.sh)"
done
say "mvmctl $(mvm --version | awk '{print $2}') on $HYPERVISOR, home $MVM_HOME, the three workloads are running"

echo "== 1. the inspection workloads are working"
t0="$(now_iso)"
until_ok "inspection workload a to look up its granted destination" has_lookup_since "$LINE_A" "$t0"
until_ok "inspection workload b to look up its granted destination" has_lookup_since "$LINE_B" "$t0"
say "the host is recording both inspection workloads' lookups of their granted destinations (${GRANT_A%%:*}, ${GRANT_B%%:*})"

echo "== 2. the maintenance workload asks for a destination it was not granted"
until_ok "the host to record a refusal for the maintenance workload naming $UNAPPROVED" has_refusal "$MAINT"
fetch_explain "$MAINT" m
[ "$(field m "d['chain_verified']")" = True ] || fail "the audit chain did not verify for the maintenance workload"
[ "$(field m "sum(1 for x in d['egress_denials'] if '$UNAPPROVED' in x['destination'] and x['reason'] == 'policy_denied')")" -ge 1 ] \
  || fail "explain shows no recorded refusal naming $UNAPPROVED for the maintenance workload: $(cat "$tmp/explain.m.json")"
say "explain reads back the host's refusal naming $UNAPPROVED for the maintenance workload (policy_denied)"
denied_at="$(field m "min(x['first_seen'] for x in d['egress_denials'] if '$UNAPPROVED' in x['destination'])")"
fetch_explain "$LINE_A" a; fetch_explain "$LINE_B" b
for slot in a b; do
  [ "$(denials_of "$slot")" = 0 ] || fail "inspection workload $slot has a recorded refusal, so the refusal was not scoped to the maintenance workload"
done
say "the refusal is scoped to the maintenance workload: the inspection workloads have none"

echo "== 3. the inspection workloads keep working through the refusal"
for m in "$LINE_A" "$LINE_B"; do
  until_ok "$m to keep looking up its granted destination after the refusal" has_lookup_since "$m" "$denied_at"
  is_status "$m" running || fail "$m stopped"
done
say "both inspection workloads kept working after the refusal"
mvm trust audit verify >/dev/null </dev/null || fail "mvmctl trust audit verify failed"
say "the audit chain verifies"

echo "== 4. the suspect workload is stopped and a fresh one is launched"
mvm machine stop "$MAINT" --yes >/dev/null </dev/null || fail "could not stop the maintenance workload"
until_ok "the maintenance workload to stop" is_status "$MAINT" stopped
say "the maintenance workload stopped"
fetch_explain "$MAINT" ms
[ "$(field ms "any(e['event'] == 'session.sealed' for e in d['events'])")" = True ] || fail "the maintenance workload's session was not sealed"
[ "$(denials_of ms)" -ge 1 ] || fail "the maintenance workload has no recorded refusal to keep as evidence"
say "its session is sealed and its refusal stays on record"
plan_s="$(field ms "d['plan_id']")"
tok_r="$(token)"
out="$(mvm run --image "$IMAGE" --hypervisor "$HYPERVISOR" --caller-commitment "$tok_r" --allow-host "$APPROVED" -- sh -c 'echo replacement-ready' 2>&1 </dev/null)" \
  || fail "the replacement did not run: $out"
grep -q 'replacement-ready' <<<"$out" || fail "the replacement did not report ready: $out"
plan_r="$(plan_of "$tok_r")"
[ -n "$plan_r" ] && [ -n "$plan_s" ] && [ "$plan_r" != "$plan_s" ] || fail "the replacement did not get a new plan ($plan_s vs $plan_r)"
fetch_explain "$plan_r" r
[ "$(denials_of r)" = 0 ] || fail "the replacement inherited the suspect's refusals"
say "the replacement ran under a new plan and carries none of the suspect's refusals"
mvm trust audit verify >/dev/null </dev/null || fail "mvmctl trust audit verify failed after the relaunch"
say "the audit chain still verifies"

# No install-time work: a prepared home runs the demo without building anything.
if grep -q -E 'first use only|Preparing the (workload kernel|guest runtime)|runtime not prepared' "$errlog"; then
  echo "FINDING: install-time preparation ran during the demo ($(grep -m1 -E 'first use only|Preparing the|runtime not prepared' "$errlog")). Prepare the home before the demo." >&2
  exit 1
fi
say "no install-time preparation ran during the demo"
echo "demo completed in $((SECONDS - started))s"
echo "DEMO_RESULT=pass"
