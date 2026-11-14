#!/usr/bin/env bash
# Live runbook for the factory-edge presentation on ONE real machine (beats 3 to
# 5 of the "Proposed factory-edge presentation" in
# specs/contracts/host-interface-distributed-execution.md): three workloads each
# hold their own scoped network grant and start together; the maintenance
# workload asks for a destination it was not granted and the host refuses and
# records it, while both inspection workloads keep working; the refusal is read
# back through `mvmctl explain`; the suspect workload is stopped and a fresh one
# launched under a new plan.
#
# One path: every workload is an unnamed transient launch of the same image,
# started the same way, so what the audience sees is a single launch path. Every
# wait is a poll for the condition it waits on, not a fixed pause.
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
# integration is checked against: launch a workload, stop a machine, read a run
# back (`mvm_client::explain::explain_local_run`) and verify the audit chain.
#
# For maintainers, what this does NOT show: Studio's own readback, the real
# maintenance and inspection tasks (the workloads are small shell loops over
# synthetic output), hot replacement, a production-profile run, or anything on a
# physical line. Launches here boot cold on purpose (MVM_RESIDENCY=cold): on the
# v0.28.0-rc.2 release a warm-standby claim measured no faster through the CLI
# than a cold boot, and a warm-claimed run's refusals are recorded under the
# standby's machine name, so `explain` would not show them.
#
#   MVMCTL        the mvmctl to drive (default: mvmctl on PATH)
#   MVM_HOME      the prepared demo home (default: ~/.mvm-demo). Must exist and
#                 already hold IMAGE; the run never creates or fills it
#   HYPERVISOR    hvf (default on macOS) or firecracker (default on Linux)
#   BUILDER       passed as --builder when set
#   IMAGE         OCI image with curl (default: curlimages/curl:8.21.0)
#   GRANT_A, GRANT_B  the destination each inspection workload is granted
#                 (default: pypi.org:443, files.pythonhosted.org:443). Every
#                 grant must resolve at admission, so the host needs DNS
#   APPROVED      the one destination the maintenance workload is granted
#                 (default: api.github.com:443)
#   UNAPPROVED    the host it then asks for (default: example.com)
#   WAIT_SECS     longest any single wait may take (default: 120)
set -uo pipefail

MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-curlimages/curl:8.21.0}"
GRANT_A="${GRANT_A:-pypi.org:443}"
GRANT_B="${GRANT_B:-files.pythonhosted.org:443}"
APPROVED="${APPROVED:-api.github.com:443}"
UNAPPROVED="${UNAPPROVED:-example.com}"
WAIT_SECS="${WAIT_SECS:-120}"
LINES_EXPECTED=6
if [ -z "${HYPERVISOR:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then HYPERVISOR=hvf; else HYPERVISOR=firecracker; fi
fi
case "$HYPERVISOR" in hvf | firecracker) ;; *) echo "FAIL unsupported HYPERVISOR=$HYPERVISOR (hvf or firecracker)" >&2; exit 2 ;; esac
bld=(); [ -z "${BUILDER:-}" ] || bld=(--builder "$BUILDER")
export MVM_HOME="${MVM_HOME:-$HOME/.mvm-demo}"
export MVM_RESIDENCY=cold

SUSPECT="fe-suspect-$$"
tmp="$(mktemp -d)"
errlog="$tmp/stderr.log"; : > "$errlog"
started=$SECONDS
# mvmctl's own progress chatter goes to a log, so the demo output is only the
# demo; the log is shown when something fails and is read for install-time work.
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
  mvm machine stop "$SUSPECT" --yes >/dev/null 2>&1 || true
  mvm machine rm "$SUSPECT" --yes >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

# Poll until `cmd` succeeds; a wait never lasts longer than WAIT_SECS.
until_ok() { # <what> <cmd...>
  local what="$1" end=$((SECONDS + WAIT_SECS)); shift
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || fail "timed out waiting for $what"
    sleep 0.5
  done
}
status_of() { mvm machine ls 2>/dev/null | awk -v n="$1" '$1 == n { print $3 }'; }
is_status() { [ "$(status_of "$1")" = "$2" ]; }

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
  mvm explain "$1" --json </dev/null | python3 -I -c "
import json, sys
d = json.load(sys.stdin)
print($2)"
}
denials_of() { explain_field "$1" "len(d['egress_denials'])"; }
# One launch path: an unnamed transient run bound to a token.   <token> <grant> -- <cmd...>
launch() { local tok="$1" grant="$2"; shift 2; mvm run --image "$IMAGE" --hypervisor "$HYPERVISOR" --caller-commitment "$tok" --allow-host "$grant" "$@"; }

echo "== 0. preconditions (nothing is installed or prepared here)"
mvm --version >/dev/null 2>&1 || fail "no usable mvmctl ($MVMCTL): the demo assumes it is installed"
[ -d "$MVM_HOME" ] || fail "demo home $MVM_HOME does not exist: prepare it first (mvmctl image pull $IMAGE, then one throwaway run)"
mvm image ls </dev/null | grep -qF "${IMAGE#docker.io/}" \
  || fail "$IMAGE is not cached in $MVM_HOME: prepare it first (mvmctl image pull $IMAGE); the demo does not install"
say "mvmctl $(mvm --version | awk '{print $2}') on $HYPERVISOR, home $MVM_HOME, $IMAGE cached"

echo "== 1. three workloads start together, each with its own scoped grant"
tok_a="$(token)"; tok_b="$(token)"; tok_m="$(token)"
for pair in "a:$tok_a:$GRANT_A" "b:$tok_b:$GRANT_B"; do
  IFS=: read -r n t g_host g_port <<<"$pair"
  launch "$t" "$g_host:$g_port" -- sh -c "for i in 1 2 3 4 5 6; do echo line-ok \$i; sleep 1; done" >"$tmp/$n.out" 2>&1 </dev/null &
  echo $! > "$tmp/$n.pid"
done
launch "$tok_m" "$APPROVED" -- sh -c "curl -sS -m 15 https://$UNAPPROVED/; echo curl_rc=\$?" >"$tmp/m.out" 2>&1 </dev/null &
echo $! > "$tmp/m.pid"
for n in a b m; do wait "$(cat "$tmp/$n.pid")" || fail "workload $n exited non-zero: $(cat "$tmp/$n.out")"; done
grep -q 'curl_rc=[1-9]' "$tmp/m.out" || fail "the request to $UNAPPROVED was not refused: $(cat "$tmp/m.out")"
say "the maintenance workload's request to $UNAPPROVED was refused"
for n in a b; do
  got="$(grep -c 'line-ok' "$tmp/$n.out" || true)"
  [ "$got" -eq "$LINES_EXPECTED" ] || fail "inspection workload $n printed $got of $LINES_EXPECTED lines: $(cat "$tmp/$n.out")"
done
say "both inspection workloads finished all $LINES_EXPECTED lines"
plan_a="$(plan_of "$tok_a")"; plan_b="$(plan_of "$tok_b")"; plan_m="$(plan_of "$tok_m")"
for p in "$plan_a" "$plan_b" "$plan_m"; do [ -n "$p" ] || fail "a run left no plan in the audit chain under its token"; done

echo "== 2. the host recorded the refusal, for the maintenance workload only"
[ "$(explain_field "$plan_m" "d['chain_verified']")" = True ] || fail "the audit chain did not verify for the maintenance workload"
[ "$(explain_field "$plan_m" "sum(1 for x in d['egress_denials'] if '$UNAPPROVED' in x['destination'])")" -ge 1 ] \
  || fail "explain shows no recorded denial naming $UNAPPROVED for the maintenance workload: $(mvm explain "$plan_m" --json </dev/null)"
[ "$(explain_field "$plan_m" "sum(1 for x in d['egress_denials'] if x['event'] == 'host.flow.denied')")" -ge 1 ] \
  || fail "the recorded denial is not a host.flow.denied entry"
say "explain reads back a host.flow.denied naming $UNAPPROVED for the maintenance workload"
denied_at="$(explain_field "$plan_m" "min(x['first_seen'] for x in d['egress_denials'] if '$UNAPPROVED' in x['destination'])")"
for pair in "inspection-a:$plan_a" "inspection-b:$plan_b"; do
  p="${pair#*:}"
  [ "$(denials_of "$p")" = 0 ] || fail "the ${pair%%:*} workload has a recorded denial, so the refusal was not scoped to the maintenance workload"
  ended_at="$(explain_field "$p" "next((e['timestamp'] for e in d['events'] if e['event'] == 'plan.exited'), '')")"
  [ -n "$ended_at" ] || fail "the ${pair%%:*} workload has no plan.exited entry"
  python3 -I -c "
import sys
from datetime import datetime
t = lambda s: datetime.fromisoformat(s.replace('Z', '+00:00'))
sys.exit(0 if t(sys.argv[1]) >= t(sys.argv[2]) else 1)" "$ended_at" "$denied_at" \
    || fail "the ${pair%%:*} workload ended ($ended_at) before the refusal ($denied_at), so it was not working through it"
done
say "both inspection workloads kept working through the refusal and exited normally"
mvm trust audit verify >/dev/null </dev/null || fail "mvmctl trust audit verify failed"
say "the audit chain verifies"

echo "== 3. the suspect workload is stopped and a fresh one is launched"
mvm run -d --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$SUSPECT" --allow-host "$APPROVED" -- \
  sh -c "curl -sS -m 10 https://$UNAPPROVED/; sleep 600" >/dev/null </dev/null || fail "could not launch the suspect workload"
until_ok "the suspect workload to be running" is_status "$SUSPECT" running
end=$((SECONDS + WAIT_SECS))
until [ "$(denials_of "$SUSPECT" 2>/dev/null || echo 0)" -ge 1 ]; do
  [ "$SECONDS" -lt "$end" ] || fail "the suspect's refusal was never recorded"
  sleep 0.5
done
mvm machine stop "$SUSPECT" --yes >/dev/null </dev/null || fail "could not stop the suspect workload"
until_ok "the suspect workload to stop" is_status "$SUSPECT" stopped
say "the suspect workload stopped"
[ "$(explain_field "$SUSPECT" "any(e['event'] == 'session.sealed' for e in d['events'])")" = True ] || fail "the suspect's session was not sealed"
[ "$(denials_of "$SUSPECT")" -ge 1 ] || fail "the suspect has no recorded denial to keep as evidence"
say "its session is sealed and its denial stays on record"
tok_r="$(token)"
out="$(launch "$tok_r" "$APPROVED" -- sh -c 'echo replacement-ready' 2>&1 </dev/null)" || fail "the replacement did not run: $out"
grep -q 'replacement-ready' <<<"$out" || fail "the replacement did not report ready: $out"
plan_r="$(plan_of "$tok_r")"; plan_s="$(explain_field "$SUSPECT" "d['plan_id']")"
[ -n "$plan_r" ] && [ -n "$plan_s" ] && [ "$plan_r" != "$plan_s" ] || fail "the replacement did not get a new plan ($plan_s vs $plan_r)"
[ "$(denials_of "$plan_r")" = 0 ] || fail "the replacement inherited the suspect's denials"
say "the replacement ran under a new plan and carries none of the suspect's denials"
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
