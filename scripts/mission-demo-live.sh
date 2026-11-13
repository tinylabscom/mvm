#!/usr/bin/env bash
# Live runbook for the mission demo on ONE real machine: a granted guest
# delivers a message, a planted compromise is denied, the workload is
# quarantined and terminated, replaced under a new epoch with new keys, the old
# state is refused, and the audit chain verifies without any message body.
#
# What it shows: the contain, terminate and replace sequence on a real VM, on
# the host it runs on. What it does NOT show: delivery into a second guest or
# between hosts (the three-node story is the scripted, simulated demo), a
# production-profile run, or a physical memory wipe.
#
# Never runs `mvmctl bootstrap`. If an installed mvmctl asks for it, the run
# fails with a FINDING line: a release must work with no bootstrap step.
#
#   MVMCTL             the mvmctl to drive (default: mvmctl on PATH)
#   HYPERVISOR         hvf (default on macOS) or firecracker (default on Linux)
#   BUILDER            passed as --builder when set
#   MVM_HOME           default: a new empty directory, removed on exit
#   IMAGE              OCI image to boot (default: alpine)
#   WAIT_SECS          how long to wait for a guest or a stop (default: 120)
#   QUARANTINE_DEADLINE  seconds before a quarantine that has not finished is
#                      reported as wedged (default: 90)
#   SOURCE_BUILD=1     an mvmctl built from source keys its guest runtime by
#                      the source: sets MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build
#   EXPECT_SCRUB_AUDIT=1   (hvf only) also require the signed
#                      plan.guest_memory_scrubbed audit entry
#   EXPECT_EGRESS_DENIAL_AUDIT=1   also require that the guest's refused outbound
#                      attempt left a flow.egress.denied or host.flow.denied
#                      entry naming the destination. Without it a missing
#                      entry is printed as a FINDING and does not fail the run:
#                      the attempt failing and the host auditing the decision
#                      are separate facts.
#   EGRESS_PROBE=1     after the evidence step, run one allowed and one denied
#                      outbound request through the egress channel (a curl
#                      image with --allow-host example.com, so this needs the
#                      network and a pull of that image) and require the
#                      host's audited flow.allowed and flow.denied decisions
#                      and `explain`'s denial summary. Off by default: it adds
#                      two short transient guests and changes nothing before it.
#   MVM_FIRECRACKER_BIN, MVM_MAILBOX_PATH
#                      read by mvmctl; leave unset to test an install
#
# On hvf the run also reads the supervisor's RAM scrub record while the machine
# is quarantined, and fails with the supervisor's stack if the quarantine does
# not finish.
set -uo pipefail

MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-alpine}"
WAIT_SECS="${WAIT_SECS:-120}"
if [ -z "${HYPERVISOR:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then HYPERVISOR=hvf; else HYPERVISOR=firecracker; fi
fi
case "$HYPERVISOR" in hvf | firecracker) ;; *) echo "FAIL unsupported HYPERVISOR=$HYPERVISOR (hvf or firecracker)" >&2; exit 2 ;; esac
[ "${SOURCE_BUILD:-0}" != 1 ] || export MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build
bld=(); [ -z "${BUILDER:-}" ] || bld=(--builder "$BUILDER")

NAME="demo-$$"
FIRST="aircraft-observation-1"
SECOND="fresh-under-epoch-2"
UNREAD="left-unread-in-the-old-workload"
CONTAINED="exfiltrate-to-someone-else"
ID="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"

own_home=""
if [ -z "${MVM_HOME:-}" ]; then
  own_home="$(mktemp -d)"; export MVM_HOME="$own_home"
fi
errlog="$(mktemp)"
# Every mvmctl call logs its stderr, so the exit trap can tell whether the
# install asked the user to run bootstrap.
mvm() { "$MVMCTL" ${bld[@]+"${bld[@]}"} "$@" 2> >(tee -a "$errlog" >&2); }
say() { echo "PASS $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
state_dir() { echo "$MVM_HOME/vms/$NAME"; }
# First 12 hex digits of the SHA-256 of a file (macOS has shasum, many Linux
# hosts only sha256sum).
sha12() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1"; else sha256sum "$1"; fi | cut -c1-12; }

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && grep -q 'mvmctl bootstrap' "$errlog"; then
    echo "FINDING: the install asked for 'mvmctl bootstrap'. A release must run with no bootstrap step." >&2
  fi
  rm -f "$errlog" "/tmp/mission-demo-$$".*
  mvm machine stop "$NAME" --yes >/dev/null 2>&1 || true
  mvm machine rm "$NAME" --yes >/dev/null 2>&1 || true
  [ -z "$own_home" ] || rm -rf "$own_home"
}
trap cleanup EXIT

# Run until `cmd` succeeds or WAIT_SECS pass.
wait_for() { # <what> <cmd...>
  local what="$1" end=$((SECONDS + WAIT_SECS)); shift
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || fail "timed out waiting for $what"
    sleep 2
  done
}

# shellcheck source-path=SCRIPTDIR source=lib/mailbox-frame.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/mailbox-frame.sh"
OWN=000     # the guest's own mailbox
OTHER=377   # anyone else: must be refused
recv() { mvm machine mailbox recv "$NAME"; }
got() { [ "$(recv)" = "$1" ]; }
launch() { mvm machine run -d --image "$IMAGE" --mailbox "$ID" --hypervisor "$HYPERVISOR" --name "$NAME" -- sleep 900 >/dev/null; }
audit_dir="$MVM_HOME/audit"
count() { grep -rhoF "$1" "$audit_dir" 2>/dev/null | wc -l | tr -d ' '; }

echo "== 1. a granted guest boots (mvmctl: $(mvm --version), $HYPERVISOR)"
mvm image pull "$IMAGE" >/dev/null
launch
wait_for "the guest to take commands" mvm machine exec "$NAME" -- true
[ "$(mvm machine exec "$NAME" -- cat /proc/cmdline | grep -o 'mvm.mailbox=1' | wc -l)" -eq 1 ] || fail "not exactly one mvm.mailbox=1"
say "granted guest booted with exactly one mvm.mailbox=1"

echo "== 2. the guest delivers a message to its host mailbox"
mailbox_write_frame "$NAME" "$OWN" "$FIRST"
wait_for "the message" got "$FIRST"; say "message read back exactly"
[ -z "$(recv)" ] || fail "mailbox not empty after reading"; say "mailbox empty after reading"

echo "== 3. a planted compromise is denied"
mailbox_write_frame "$NAME" "$OTHER" "$CONTAINED"; sleep 8
[ -z "$(recv)" ] || fail "a message to another recipient was queued"; say "a message to another mailbox was refused"
denials() { grep -rhE 'flow\.egress\.denied|host\.flow\.denied' "$audit_dir" 2>/dev/null | grep -cF example.com || true; }
denied_before="$(denials)"
if mvm machine exec "$NAME" -- sh -c 'wget -T 4 -q -O- http://example.com >/dev/null 2>&1'; then fail "the guest reached the network"; fi
say "an outbound connection from the guest failed (this shows it fails, not why)"
# Whether the host audited the refusal is a separate question from the attempt
# failing; give the entry a few seconds to be written before judging.
for _ in 1 2 3 4 5 6 7 8 9 10; do [ "$(denials)" -gt "$denied_before" ] && break; sleep 1; done
if [ "$(denials)" -gt "$denied_before" ]; then
  say "the refused outbound attempt left an audited egress denial naming example.com"
elif [ "${EXPECT_EGRESS_DENIAL_AUDIT:-0}" = 1 ]; then
  fail "the refused outbound attempt left no flow.egress.denied or host.flow.denied entry naming example.com"
else
  echo "FINDING: the refused outbound attempt left no flow.egress.denied or host.flow.denied entry naming example.com; the failure is observed but the host's decision is not audited here."
fi

echo "== 4. a running workload cannot be replaced"
out="$(mvm machine replace "$NAME" 2>&1)" && fail "replace succeeded on a running machine"
grep -q "machine stop $NAME" <<<"$out" || fail "replace did not name machine stop: $out"
say "replace refused while running, naming \`machine stop $NAME\`"

echo "== 5. contain: quarantine and terminate"
# A frame left unread in the workload being contained: step 8 proves its
# replacement cannot read it.
mailbox_write_frame "$NAME" "$OWN" "$UNREAD"; sleep 3
secret="$(state_dir)/mailbox-epoch.secret"
[ -s "$secret" ] || fail "no per-launch secret at $secret"
old_secret="$(sha12 "$secret")"
scrub_before="$(count plan.guest_memory_scrubbed)"
keep="/tmp/mission-demo-$$.scrub"; qlog="/tmp/mission-demo-$$.quarantine"
mvm machine quarantine "$NAME" --reason "demo: planted compromise" >"$qlog" 2>&1 &
qp=$!
deadline=$((SECONDS + ${QUARANTINE_DEADLINE:-90}))
while kill -0 "$qp" 2>/dev/null || [ -d "$(state_dir)" ]; do
  # hvf writes its RAM scrub record before the state directory goes away.
  [ "$HYPERVISOR" != hvf ] || { [ -f "$(state_dir)/ram-scrub.json" ] && cp "$(state_dir)/ram-scrub.json" "$keep" 2>/dev/null; }
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "WEDGE: the quarantine did not finish in ${QUARANTINE_DEADLINE:-90} s" >&2
    if [ "$HYPERVISOR" = hvf ]; then
      sp="$(awk '{print $1}' "$(state_dir)/hvf.pid" 2>/dev/null)"
      [ -z "$sp" ] || { echo "WEDGE: supervisor pid=$sp state=$(ps -o stat= -p "$sp" 2>/dev/null)" >&2
        timeout 25 sample "$sp" 3 -file "/tmp/mission-demo-$$.sample" >/dev/null 2>&1 && echo "WEDGE: stack sample at /tmp/mission-demo-$$.sample" >&2; }
    fi
    kill "$qp" 2>/dev/null; fail "quarantine wedged"
  fi
  sleep 0.05
done
wait "$qp" || fail "quarantine failed: $(tail -2 "$qlog")"
grep -q "quarantined $NAME: it will not launch again until replaced" "$qlog" || fail "unexpected quarantine output: $(cat "$qlog")"
[ ! -d "$(state_dir)" ] || fail "the state directory survived the quarantine"
[ ! -e "$secret" ] || fail "the per-launch secret survived the quarantine"
say "quarantined and stopped; per-launch secret (sha256 $old_secret...) is gone"
if [ "$HYPERVISOR" = hvf ]; then
  [ -s "$keep" ] && say "RAM scrub record: $(cat "$keep")" || echo "NOTE no ram-scrub.json was captured (the poll can miss it)"
fi

echo "== 6. a quarantined workload cannot relaunch"
out="$(launch 2>&1)" && fail "relaunch of a quarantined workload succeeded"
grep -qi "quarantin" <<<"$out" || fail "relaunch refusal did not name quarantine: $out"
say "relaunch refused: quarantined"

echo "== 7. replace under a new epoch"
out="$(mvm machine replace "$NAME" 2>&1)" || fail "replace failed: $out"
grep -q "$NAME may launch again under execution epoch 2" <<<"$out" || fail "expected epoch 2: $out"
say "$out"
grep -q "\"epoch\": *2" "$MVM_HOME/host-interface/workloads.json" || fail "the ledger is not at epoch 2"
say "the ledger is at epoch 2"

echo "== 8. the replacement runs under new keys; the old state is refused"
launch; wait_for "the replacement to take commands" mvm machine exec "$NAME" -- true
new_secret="$(sha12 "$secret")"
[ "$new_secret" != "$old_secret" ] || fail "the replacement has the old per-launch secret"
say "per-launch secret changed ($old_secret... -> $new_secret...)"
[ -z "$(recv)" ] || fail "the replacement could read a message from the old workload"
say "the frame left unread in the old workload is not readable by its replacement"
mailbox_write_frame "$NAME" "$OWN" "$SECOND"; wait_for "a fresh message under the new epoch" got "$SECOND"
say "a fresh message under the new epoch is read exactly"

echo "== 9. the evidence"
vout="$(mvm trust audit verify 2>&1)" || fail "audit chain does not verify: $vout"
grep -q "VERIFIED" <<<"$vout" || fail "no VERIFIED line: $vout"
say "audit chain verifies: $(grep -m1 VERIFIED <<<"$vout")"
for ev in workload.quarantined workload.replaced; do
  grep -rhF "$ev" "$audit_dir" | grep -qF "$NAME" || fail "no $ev entry for $NAME in the audit log"
  say "audit has $ev for $NAME"
done
grep -rhF mailbox.read "$audit_dir" >/dev/null || fail "no mailbox.read entry in the audit log"
say "audit has mailbox.read"
if [ "${EXPECT_SCRUB_AUDIT:-0}" = 1 ]; then
  [ "$HYPERVISOR" = hvf ] || fail "EXPECT_SCRUB_AUDIT is an hvf check"
  [ "$(count plan.guest_memory_scrubbed)" -gt "$scrub_before" ] || fail "the containment added no plan.guest_memory_scrubbed entry"
  say "this run added a plan.guest_memory_scrubbed entry (signed, counts only)"
fi
! grep -rqF -e "$FIRST" -e "$SECOND" -e "$CONTAINED" -e "$UNREAD" "$audit_dir" || fail "a message body is in the audit log"
say "no message body appears in the audit log"
if [ "${EGRESS_PROBE:-0}" = 1 ]; then
  echo "== 10. a denied outbound request is audited and explained"
  CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.21.0}"
  mvm image pull "$CURL_IMAGE" >/dev/null || fail "could not pull $CURL_IMAGE"
  ALLOW="egress-allow-$$"; DENY="egress-deny-$$"
  out="$(mvm machine run --name "$ALLOW" --image "$CURL_IMAGE" --allow-host example.com --timeout 180 -- curl -fsSL https://example.com 2>&1 </dev/null)" \
    || fail "the allowed request failed: $out"
  say "an allowed request through the egress channel succeeded"
  out="$(mvm machine run --name "$DENY" --image "$CURL_IMAGE" --allow-host example.com --timeout 180 -- curl -fsSL https://blocked.example 2>&1 </dev/null)"; rc=$?
  [ "$rc" -eq 22 ] || fail "the denied request exited $rc, expected 22: $out"
  say "a denied request through the egress channel exited 22"
  flow() { grep -rhF "$1" "$audit_dir" | grep -F "$2" | grep -cF "$3" || true; }
  [ "$(flow host.flow.allowed "$ALLOW" example.com)" -ge 1 ] || fail "no host.flow.allowed entry for $ALLOW naming example.com"
  say "audit has host.flow.allowed for $ALLOW naming example.com"
  [ "$(flow host.flow.denied "$DENY" blocked.example)" -ge 1 ] || fail "no host.flow.denied entry for $DENY naming blocked.example"
  say "audit has host.flow.denied for $DENY naming blocked.example"
  run_id="$(grep -oE 'mvmctl explain [^ ]+ --review' <<<"$out" | head -1 | awk '{print $3}')"
  [ -n "$run_id" ] || fail "the denied run named no explain command: $out"
  eout="$(mvm explain "$run_id" --review 2>&1 </dev/null)" || fail "explain failed: $eout"
  grep -qF "egress denied:" <<<"$eout" && grep -qF "blocked.example:443" <<<"$eout" || fail "explain did not report the denial: $eout"
  say "explain reports the denied destination blocked.example:443"
  mvm machine rm "$ALLOW" --yes >/dev/null 2>&1 || true; mvm machine rm "$DENY" --yes >/dev/null 2>&1 || true
fi
echo "DEMO_RESULT=pass"
