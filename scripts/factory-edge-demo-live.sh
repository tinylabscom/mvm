#!/usr/bin/env bash
# Live runbook for the factory-edge presentation on ONE real machine (beats 3 to
# 5 of the "Proposed factory-edge presentation" in
# specs/contracts/host-interface-distributed-execution.md): two inspection
# workloads keep doing demonstrable work while a maintenance workload's request
# for an unapproved destination is refused and recorded by the host, the
# refusal is read back through `mvmctl explain`, and the suspect workload is
# stopped and a fresh one launched under a new plan.
#
# What it shows: a host-recorded egress denial for one workload, read back
# through the client's explain path; two other workloads finishing unaffected
# at the same time; an explicit stop and relaunch that carries nothing over;
# and an audit chain that verifies. What it does NOT show: Studio's own
# readback (this drives the CLI), the real maintenance and inspection tasks (the
# workloads are small shell loops over synthetic output), hot replacement, a
# production-profile run, or anything on a physical line.
#
# A workload granted NO egress at all fails inside the guest and the host
# records nothing, so the maintenance workload is granted one approved
# destination and asked for a different one. That no-grant behaviour is printed
# as a NOTE, not asserted.
#
# Never runs `mvmctl bootstrap`. If an installed mvmctl asks for it, the run
# fails with a FINDING line: a release must work with no bootstrap step.
#
#   MVMCTL        the mvmctl to drive (default: mvmctl on PATH)
#   HYPERVISOR    hvf (default on macOS) or firecracker (default on Linux)
#   BUILDER       passed as --builder when set
#   MVM_HOME      default: a new empty directory, removed on exit. Point it at
#                 an existing home to reuse its prepared runtime and images
#   IMAGE         OCI image with curl (default: curlimages/curl:8.21.0)
#   APPROVED      the one destination the maintenance workload is granted
#                 (default: api.github.com:443)
#   UNAPPROVED    the host it then asks for (default: example.com)
#   WAIT_SECS     how long to wait for a machine to start or stop (default: 120)
#   SETTLE_SECS, REQUEST_SECS  pauses so the maintenance request lands while the
#                 inspection workloads still run, and the suspect's request
#                 reaches the host before it is stopped (defaults: 6 and 10)
#   SOURCE_BUILD=1  an mvmctl built from source keys its guest runtime by the
#                 source: sets MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build
set -uo pipefail

MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-curlimages/curl:8.21.0}"
APPROVED="${APPROVED:-api.github.com:443}"
UNAPPROVED="${UNAPPROVED:-example.com}"
WAIT_SECS="${WAIT_SECS:-120}"
SETTLE_SECS="${SETTLE_SECS:-6}"
REQUEST_SECS="${REQUEST_SECS:-10}"
LINES_EXPECTED=6
if [ -z "${HYPERVISOR:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then HYPERVISOR=hvf; else HYPERVISOR=firecracker; fi
fi
case "$HYPERVISOR" in hvf | firecracker) ;; *) echo "FAIL unsupported HYPERVISOR=$HYPERVISOR (hvf or firecracker)" >&2; exit 2 ;; esac
[ "${SOURCE_BUILD:-0}" != 1 ] || export MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build
bld=(); [ -z "${BUILDER:-}" ] || bld=(--builder "$BUILDER")

LINE_A="fe-line-a-$$"; LINE_B="fe-line-b-$$"; MAINT="fe-maint-$$"
SUSPECT="fe-suspect-$$"; REPLACEMENT="fe-replacement-$$"

own_home=""
if [ -z "${MVM_HOME:-}" ]; then
  own_home="$(mktemp -d)"; export MVM_HOME="$own_home"
fi
tmp="$(mktemp -d)"
errlog="$tmp/stderr.log"; : > "$errlog"
# Every mvmctl call logs its stderr, so the exit trap can tell whether the
# install asked the user to run bootstrap.
mvm() { "$MVMCTL" ${bld[@]+"${bld[@]}"} "$@" 2> >(tee -a "$errlog" >&2); }
say() { echo "PASS $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && grep -q 'mvmctl bootstrap' "$errlog"; then
    echo "FINDING: the install asked for 'mvmctl bootstrap'. A release must run with no bootstrap step." >&2
  fi
  for m in "$LINE_A" "$LINE_B" "$MAINT" "$SUSPECT" "$REPLACEMENT"; do
    mvm machine stop "$m" --yes >/dev/null 2>&1 || true
    mvm machine rm "$m" --yes >/dev/null 2>&1 || true
  done
  rm -rf "$tmp"
  [ -z "$own_home" ] || rm -rf "$own_home"
}
trap cleanup EXIT

status_of() { mvm machine ls 2>/dev/null | awk -v n="$1" '$1 == n { print $3 }'; }

# One JSON field of `mvmctl explain <name> --json`, printed as text.
# <name> <python expression over d>
explain_field() {
  mvm explain "$1" --json 2>/dev/null </dev/null | python3 -I -c "
import json, sys
d = json.load(sys.stdin)
print($2)"
}
denials_of() { explain_field "$1" "len(d['egress_denials'])"; }

echo "== 0. preparing (mvmctl: $(mvm --version), $HYPERVISOR)"
mvm image pull "$IMAGE" >/dev/null || fail "could not pull $IMAGE"

echo "== 1. two inspection workloads run while a maintenance workload asks for an unapproved destination"
for n in "$LINE_A" "$LINE_B"; do
  mvm run --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$n" -- \
    sh -c "for i in 1 2 3 4 5 6; do echo line-ok \$i; sleep 3; done" >"$tmp/$n.out" 2>&1 </dev/null &
  echo $! > "$tmp/$n.pid"
done
sleep "$SETTLE_SECS"  # the maintenance request lands while both are still running
maint_out="$(mvm run --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$MAINT" --allow-host "$APPROVED" -- \
  sh -c "curl -sS -m 15 https://$UNAPPROVED/; echo curl_rc=\$?" 2>&1 </dev/null)"
grep -q 'curl_rc=[1-9]' <<<"$maint_out" || fail "the request to $UNAPPROVED was not refused: $maint_out"
say "the maintenance workload's request to $UNAPPROVED was refused in the guest"
for n in "$LINE_A" "$LINE_B"; do
  wait "$(cat "$tmp/$n.pid")" || fail "$n exited non-zero: $(cat "$tmp/$n.out")"
  got="$(grep -c 'line-ok' "$tmp/$n.out" || true)"
  [ "$got" -eq "$LINES_EXPECTED" ] || fail "$n printed $got of $LINES_EXPECTED lines: $(cat "$tmp/$n.out")"
done
say "both inspection workloads finished all $LINES_EXPECTED lines"

echo "== 2. the host recorded the refusal, for the maintenance workload only"
[ "$(explain_field "$MAINT" "d['chain_verified']")" = True ] || fail "the audit chain did not verify for $MAINT"
[ "$(explain_field "$MAINT" "sum(1 for x in d['egress_denials'] if '$UNAPPROVED' in x['destination'])")" -ge 1 ] \
  || fail "explain shows no recorded denial naming $UNAPPROVED for $MAINT: $(mvm explain "$MAINT" --json 2>&1 </dev/null)"
[ "$(explain_field "$MAINT" "sum(1 for x in d['egress_denials'] if x['event'] == 'host.flow.denied')")" -ge 1 ] \
  || fail "the recorded denial is not a host.flow.denied entry"
say "explain reads back a host.flow.denied naming $UNAPPROVED for $MAINT"
for n in "$LINE_A" "$LINE_B"; do
  [ "$(denials_of "$n")" = 0 ] || fail "$n has a recorded denial, so the refusal was not scoped to the maintenance workload"
  [ "$(explain_field "$n" "any(e['event'] == 'plan.exited' for e in d['events'])")" = True ] || fail "$n has no plan.exited entry"
done
say "the inspection workloads have no denials and exited normally"
mvm trust audit verify >/dev/null 2>&1 </dev/null || fail "mvmctl trust audit verify failed"
say "the audit chain verifies"

echo "== 3. the suspect workload is stopped and a fresh one is launched"
mvm run -d --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$SUSPECT" --allow-host "$APPROVED" -- \
  sh -c "curl -sS -m 10 https://$UNAPPROVED/; sleep 600" >/dev/null </dev/null || fail "could not launch $SUSPECT"
wait_status() { # <name> <status>
  local end=$((SECONDS + WAIT_SECS))
  until [ "$(status_of "$1")" = "$2" ]; do
    [ "$SECONDS" -lt "$end" ] || fail "$1 did not reach $2: '$(status_of "$1")'"
    sleep 2
  done
}
wait_status "$SUSPECT" running
sleep "$REQUEST_SECS"  # let the suspect's request reach the host before it is stopped
mvm machine stop "$SUSPECT" --yes >/dev/null </dev/null || fail "could not stop $SUSPECT"
wait_status "$SUSPECT" stopped
say "the suspect workload stopped"
[ "$(explain_field "$SUSPECT" "any(e['event'] == 'session.sealed' for e in d['events'])")" = True ] || fail "$SUSPECT's session was not sealed"
[ "$(denials_of "$SUSPECT")" -ge 1 ] || fail "$SUSPECT has no recorded denial to carry forward as evidence"
say "its session is sealed and its denial stays on record"
out="$(mvm run --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$REPLACEMENT" --allow-host "$APPROVED" -- \
  sh -c 'echo replacement-ready' 2>&1 </dev/null)" || fail "the replacement did not run: $out"
grep -q 'replacement-ready' <<<"$out" || fail "the replacement did not report ready: $out"
suspect_plan="$(explain_field "$SUSPECT" "d['plan_id']")"
replacement_plan="$(explain_field "$REPLACEMENT" "d['plan_id']")"
[ -n "$suspect_plan" ] && [ -n "$replacement_plan" ] && [ "$suspect_plan" != "$replacement_plan" ] \
  || fail "the replacement did not get a new plan ($suspect_plan vs $replacement_plan)"
[ "$(denials_of "$REPLACEMENT")" = 0 ] || fail "the replacement inherited the suspect's denials"
say "the replacement ran under a new plan and carries none of the suspect's denials"
mvm trust audit verify >/dev/null 2>&1 </dev/null || fail "mvmctl trust audit verify failed after the relaunch"
say "the audit chain still verifies"

echo "== 4. note: a workload granted no egress at all"
NOGRANT="fe-nogrant-$$"
ng_out="$(mvm run --image "$IMAGE" --hypervisor "$HYPERVISOR" --name "$NOGRANT" -- \
  sh -c "curl -sS -m 10 https://$UNAPPROVED/; echo curl_rc=\$?" 2>&1 </dev/null)"
ng_denials="$(denials_of "$NOGRANT" 2>/dev/null || echo '?')"
mvm machine rm "$NOGRANT" --yes >/dev/null 2>&1 || true
echo "NOTE a workload with no egress grant: $(grep -o 'curl_rc=[0-9]*' <<<"$ng_out" | head -1), host-recorded denials: $ng_denials. The refused destination is only a recorded policy decision when the workload holds some grant."
echo "DEMO_RESULT=pass"
