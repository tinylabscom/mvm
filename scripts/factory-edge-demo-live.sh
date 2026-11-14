#!/usr/bin/env bash
# Live runbook for the factory-edge presentation on ONE real machine (beats 3 to
# 5 of the "Proposed factory-edge presentation" in
# specs/contracts/host-interface-distributed-execution.md): standbys are warmed,
# two inspection workloads and a maintenance workload each claim one, the
# maintenance workload's request for an unapproved destination is refused and
# recorded by the host, the refusal is read back through `mvmctl explain`, and
# the suspect workload is stopped and a fresh one launched under a new plan.
#
# The demo ASSUMES an installed mvmctl and a prepared home. Nothing here
# installs, pulls an image or prepares a runtime: a missing prerequisite stops
# the run before it starts, and any first-use preparation that happens during
# the run is reported as a FINDING and fails it. Prepare once, outside the demo:
#   mvmctl image pull curlimages/curl:8.21.0     (with MVM_HOME set)
#   and one throwaway `mvmctl run` of that image, so the runtime is built.
#
# This is a CLI proof of the demo. The same operations are what Studio will
# drive through the `mvm-client` library; this script is the reference the
# integration is checked against: launch a workload, warm standbys, stop a
# machine, read a run back (`mvm_client::explain::explain_local_run`) and verify
# the audit chain.
#
# What it shows: warm-standby claims; a host-recorded egress denial for one
# workload, read back through explain; two other workloads finishing unaffected
# at the same time; an explicit stop and relaunch that carries nothing over; and
# an audit chain that verifies. What it does NOT show: Studio's own readback,
# the real maintenance and inspection tasks (the workloads are small shell loops
# over synthetic output), hot replacement, a production-profile run, or anything
# on a physical line.
#
# The maintenance workload is launched cold on purpose (see step 2).
# A named or detached machine boots cold by design, so only unnamed transient
# runs claim a standby; the suspect workload must be named to be stopped, and is
# reported as a NOTE. A workload granted NO egress at all fails inside the guest
# and the host records nothing, so the maintenance workload is granted one
# approved destination and asked for a different one; that no-grant behaviour is
# printed as a NOTE, not asserted.
#
#   MVMCTL        the mvmctl to drive (default: mvmctl on PATH)
#   MVM_HOME      the prepared demo home (default: ~/.mvm-demo). Must exist and
#                 already hold IMAGE; the run never creates or fills it
#   HYPERVISOR    hvf (default on macOS) or firecracker (default on Linux)
#   BUILDER       passed as --builder when set
#   IMAGE         OCI image with curl (default: curlimages/curl:8.21.0)
#   APPROVED      the one destination the maintenance workload is granted
#                 (default: api.github.com:443)
#   UNAPPROVED    the host it then asks for (default: example.com)
#   WAIT_SECS     how long to wait for a machine to stop (default: 120)
#   SETTLE_SECS, REQUEST_SECS  pauses so the maintenance request lands while the
#                 inspection workloads still run, and the suspect's request
#                 reaches the host before it is stopped (defaults: 6 and 10)
set -uo pipefail

MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-curlimages/curl:8.21.0}"
APPROVED="${APPROVED:-api.github.com:443}"
UNAPPROVED="${UNAPPROVED:-example.com}"
WAIT_SECS="${WAIT_SECS:-120}"
SETTLE_SECS="${SETTLE_SECS:-6}"
REQUEST_SECS="${REQUEST_SECS:-10}"
LINES_EXPECTED=6
PLAIN_STANDBYS=2   # the two inspection workloads: no egress grant
EGRESS_STANDBYS=1  # the replacement, which holds a grant
if [ -z "${HYPERVISOR:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then HYPERVISOR=hvf; else HYPERVISOR=firecracker; fi
fi
case "$HYPERVISOR" in hvf | firecracker) ;; *) echo "FAIL unsupported HYPERVISOR=$HYPERVISOR (hvf or firecracker)" >&2; exit 2 ;; esac
bld=(); [ -z "${BUILDER:-}" ] || bld=(--builder "$BUILDER")
export MVM_HOME="${MVM_HOME:-$HOME/.mvm-demo}"

SUSPECT="fe-suspect-$$"
tmp="$(mktemp -d)"
errlog="$tmp/stderr.log"; : > "$errlog"
# Every mvmctl call logs its stderr, so the run can tell whether the install
# asked for bootstrap or prepared anything while the demo was running.
mvm() { "$MVMCTL" ${bld[@]+"${bld[@]}"} "$@" 2> >(tee -a "$errlog" >&2); }
say() { echo "PASS $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && grep -q 'mvmctl bootstrap' "$errlog"; then
    echo "FINDING: the install asked for 'mvmctl bootstrap'. A release must run with no bootstrap step." >&2
  fi
  mvm machine stop "$SUSPECT" --yes >/dev/null 2>&1 || true
  mvm machine rm "$SUSPECT" --yes >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

status_of() { mvm machine ls 2>/dev/null | awk -v n="$1" '$1 == n { print $3 }'; }
wait_status() { # <name> <status>
  local end=$((SECONDS + WAIT_SECS))
  until [ "$(status_of "$1")" = "$2" ]; do
    [ "$SECONDS" -lt "$end" ] || fail "$1 did not reach $2: '$(status_of "$1")'"
    sleep 2
  done
}

# A fresh 32-byte token bound into each run's plan, so the run's plan id can be
# found in the audit chain even though an unnamed run prints no name.
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
            print(e['plan_id']); break" "$1" "$MVM_HOME/audit/local.jsonl"
}
# One field of `mvmctl explain <plan> --json`, printed as text.   <plan> <expr over d>
explain_field() {
  mvm explain "$1" --json 2>/dev/null </dev/null | python3 -I -c "
import json, sys
d = json.load(sys.stdin)
print($2)"
}
denials_of() { explain_field "$1" "len(d['egress_denials'])"; }
mode_of() { explain_field "$1" "next((e['labels'].get('mode') for e in d['events'] if e['event'] == 'plan.start_mode'), 'none')"; }
# An unnamed transient run claims a standby when one is ready.      <token> <args...> -- <cmd...>
warm_run() { local tok="$1"; shift; mvm run --image "$IMAGE" --hypervisor "$HYPERVISOR" --caller-commitment "$tok" "$@"; }

echo "== 0. preconditions (nothing is installed or prepared here)"
mvm --version >/dev/null 2>&1 || fail "no usable mvmctl ($MVMCTL): the demo assumes it is installed"
[ -d "$MVM_HOME" ] || fail "demo home $MVM_HOME does not exist: prepare it first (mvmctl image pull $IMAGE, then one throwaway run)"
mvm image ls 2>/dev/null </dev/null | grep -qF "${IMAGE#docker.io/}" \
  || fail "$IMAGE is not cached in $MVM_HOME: prepare it first (mvmctl image pull $IMAGE); the demo does not install"
say "mvmctl $(mvm --version 2>/dev/null | awk '{print $2}') on $HYPERVISOR, home $MVM_HOME, $IMAGE cached"

echo "== 1. standbys are warmed"
# A standby's guest either boots the egress client or does not, and a run claims
# only a standby of its own shape, so a run holding a grant boots cold unless an
# egress standby was warmed for it.
mvm pool warm --image "$IMAGE" "$PLAIN_STANDBYS" >/dev/null </dev/null || fail "could not warm plain standbys"
mvm pool warm --image "$IMAGE" --egress "$EGRESS_STANDBYS" >/dev/null </dev/null || fail "could not warm egress standbys"
idle="$(mvm pool status 2>/dev/null </dev/null | grep -c ' idle ' || true)"
[ "$idle" -ge $((PLAIN_STANDBYS + EGRESS_STANDBYS)) ] || fail "only $idle idle standbys after warming (wanted $((PLAIN_STANDBYS + EGRESS_STANDBYS)))"
say "$idle idle standbys ready ($PLAIN_STANDBYS plain, $EGRESS_STANDBYS with the egress client)"

echo "== 2. two inspection workloads run while a maintenance workload asks for an unapproved destination"
tok_a="$(token)"; tok_b="$(token)"; tok_m="$(token)"
for pair in "a:$tok_a" "b:$tok_b"; do
  n="${pair%%:*}"; t="${pair#*:}"
  warm_run "$t" -- sh -c "for i in 1 2 3 4 5 6; do echo line-ok \$i; sleep 3; done" >"$tmp/$n.out" 2>&1 </dev/null &
  echo $! > "$tmp/$n.pid"
done
sleep "$SETTLE_SECS"  # the maintenance request lands while both are still running
# The maintenance workload is launched cold on purpose. `explain` attributes a
# refusal to a run by its machine name, and a warm-claimed run's refusals are
# recorded under the standby's name, so a warm maintenance workload would show
# an empty denial list even though the chain holds the entry.
maint_out="$(MVM_RESIDENCY=cold warm_run "$tok_m" --allow-host "$APPROVED" -- \
  sh -c "curl -sS -m 15 https://$UNAPPROVED/; echo curl_rc=\$?" 2>&1 </dev/null)"
grep -q 'curl_rc=[1-9]' <<<"$maint_out" || fail "the request to $UNAPPROVED was not refused: $maint_out"
say "the maintenance workload's request to $UNAPPROVED was refused in the guest"
for n in a b; do
  wait "$(cat "$tmp/$n.pid")" || fail "inspection workload $n exited non-zero: $(cat "$tmp/$n.out")"
  got="$(grep -c 'line-ok' "$tmp/$n.out" || true)"
  [ "$got" -eq "$LINES_EXPECTED" ] || fail "inspection workload $n printed $got of $LINES_EXPECTED lines: $(cat "$tmp/$n.out")"
done
say "both inspection workloads finished all $LINES_EXPECTED lines"
plan_a="$(plan_of "$tok_a")"; plan_b="$(plan_of "$tok_b")"; plan_m="$(plan_of "$tok_m")"
for p in "$plan_a" "$plan_b" "$plan_m"; do [ -n "$p" ] || fail "a run left no plan in the audit chain under its token"; done
for pair in "inspection-a:$plan_a" "inspection-b:$plan_b"; do
  [ "$(mode_of "${pair#*:}")" = warm ] || fail "the ${pair%%:*} workload did not claim a warm standby (start mode: $(mode_of "${pair#*:}"))"
done
say "both inspection workloads claimed a warm standby"
[ "$(mode_of "$plan_m")" = cold ] || fail "the maintenance workload was meant to boot cold (start mode: $(mode_of "$plan_m"))"
echo "NOTE the maintenance workload booted cold on purpose: explain cannot attribute a warm-claimed run's refusals to it"

echo "== 3. the host recorded the refusal, for the maintenance workload only"
[ "$(explain_field "$plan_m" "d['chain_verified']")" = True ] || fail "the audit chain did not verify for the maintenance workload"
[ "$(explain_field "$plan_m" "sum(1 for x in d['egress_denials'] if '$UNAPPROVED' in x['destination'])")" -ge 1 ] \
  || fail "explain shows no recorded denial naming $UNAPPROVED for the maintenance workload: $(mvm explain "$plan_m" --json 2>&1 </dev/null)"
[ "$(explain_field "$plan_m" "sum(1 for x in d['egress_denials'] if x['event'] == 'host.flow.denied')")" -ge 1 ] \
  || fail "the recorded denial is not a host.flow.denied entry"
say "explain reads back a host.flow.denied naming $UNAPPROVED for the maintenance workload"
for pair in "inspection-a:$plan_a" "inspection-b:$plan_b"; do
  p="${pair#*:}"
  [ "$(denials_of "$p")" = 0 ] || fail "the ${pair%%:*} workload has a recorded denial, so the refusal was not scoped to the maintenance workload"
  [ "$(explain_field "$p" "any(e['event'] == 'plan.exited' for e in d['events'])")" = True ] || fail "the ${pair%%:*} workload has no plan.exited entry"
done
say "the inspection workloads have no denials and exited normally"
mvm trust audit verify >/dev/null 2>&1 </dev/null || fail "mvmctl trust audit verify failed"
say "the audit chain verifies"

echo "== 4. the suspect workload is stopped and a fresh one is launched"
mvm run -d --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$SUSPECT" --allow-host "$APPROVED" -- \
  sh -c "curl -sS -m 10 https://$UNAPPROVED/; sleep 600" >/dev/null </dev/null || fail "could not launch the suspect workload"
wait_status "$SUSPECT" running
sleep "$REQUEST_SECS"  # let the suspect's request reach the host before it is stopped
mvm machine stop "$SUSPECT" --yes >/dev/null </dev/null || fail "could not stop the suspect workload"
wait_status "$SUSPECT" stopped
say "the suspect workload stopped"
[ "$(explain_field "$SUSPECT" "any(e['event'] == 'session.sealed' for e in d['events'])")" = True ] || fail "the suspect's session was not sealed"
[ "$(denials_of "$SUSPECT")" -ge 1 ] || fail "the suspect has no recorded denial to keep as evidence"
say "its session is sealed and its denial stays on record"
echo "NOTE the suspect is a named machine, which boots cold by design (start mode: $(mode_of "$SUSPECT"))"
tok_r="$(token)"
out="$(warm_run "$tok_r" --allow-host "$APPROVED" -- sh -c 'echo replacement-ready' 2>&1 </dev/null)" || fail "the replacement did not run: $out"
grep -q 'replacement-ready' <<<"$out" || fail "the replacement did not report ready: $out"
plan_r="$(plan_of "$tok_r")"; plan_s="$(explain_field "$SUSPECT" "d['plan_id']")"
[ -n "$plan_r" ] && [ -n "$plan_s" ] && [ "$plan_r" != "$plan_s" ] || fail "the replacement did not get a new plan ($plan_s vs $plan_r)"
[ "$(denials_of "$plan_r")" = 0 ] || fail "the replacement inherited the suspect's denials"
[ "$(mode_of "$plan_r")" = warm ] || fail "the replacement did not claim a warm standby (start mode: $(mode_of "$plan_r"))"
say "the replacement claimed a warm standby under a new plan and carries none of the suspect's denials"
mvm trust audit verify >/dev/null 2>&1 </dev/null || fail "mvmctl trust audit verify failed after the relaunch"
say "the audit chain still verifies"

echo "== 5. note: a workload granted no egress at all"
tok_n="$(token)"
ng_out="$(warm_run "$tok_n" -- sh -c "curl -sS -m 10 https://$UNAPPROVED/; echo curl_rc=\$?" 2>&1 </dev/null)"
plan_n="$(plan_of "$tok_n")"; ng_denials="$(denials_of "$plan_n" 2>/dev/null || echo '?')"
echo "NOTE a workload with no egress grant: $(grep -o 'curl_rc=[0-9]*' <<<"$ng_out" | head -1), host-recorded denials: $ng_denials. The refused destination is only a recorded policy decision when the workload holds some grant."

# No install-time work: a prepared home runs the demo without building anything.
if grep -q -E 'first use only|Preparing the (workload kernel|guest runtime)|runtime not prepared' "$errlog"; then
  echo "FINDING: install-time preparation ran during the demo ($(grep -m1 -E 'first use only|Preparing the|runtime not prepared' "$errlog")). Prepare the home before the demo." >&2
  exit 1
fi
say "no install-time preparation ran during the demo"
echo "== standbys left: $(mvm pool status 2>/dev/null </dev/null | head -1)"
echo "DEMO_RESULT=pass"
