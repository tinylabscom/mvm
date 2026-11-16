#!/usr/bin/env bash
# Live runbook for the mission demo on ONE real machine: a granted guest
# delivers a message, stages a planted compromise, the workload is
# quarantined and terminated, replaced under a new epoch with new keys, the old
# state is not observed, and the audit chain verifies without any message body.
# Empty reads do not prove host refusal or acceptance/purge of unread frames.
# Those unsupported checks leave DEMO_RESULT=partial; exit 0 means the observed
# checks completed, not that the full mission security claim was demonstrated.
#
# What it shows: the contain, terminate and replace sequence on a real VM, on
# the host it runs on. What it does NOT show: delivery into a second guest or
# between hosts (the three-node story is the scripted, simulated demo), a
# production-profile run, or a physical memory wipe.
#
# One command, no setup: if the home has not been prepared, the first launch is
# refused with "is not prepared" and the script prepares it itself (pulls the
# image and does one throwaway run) and launches again. It never runs
# `mvmctl bootstrap`.
#
#   MVMCTL             the mvmctl to drive. Default: this checkout's
#                      target/release/mvmctl when `cargo build --release --locked`
#                      has produced one, otherwise mvmctl on PATH. Build, then run
#                      this script: nothing else is needed.
#   HYPERVISOR         hvf (default on macOS) or firecracker (default on Linux)
#   BUILDER            passed as --builder when set
#   MVM_HOME           default: a new empty directory, removed on exit; with this
#                      checkout's own build, target/mission-demo-home instead,
#                      kept between runs. A build from source compiles its guest
#                      runtime the first time it launches (tens of minutes, one
#                      line of progress every 15 s); a kept home pays that once.
#   IMAGE              OCI image to boot (default: alpine)
#   WAIT_SECS          how long to wait for a guest or a stop (default: 120)
#   QUARANTINE_DEADLINE  seconds before a quarantine that has not finished is
#                      reported as wedged (default: 90)
#   SOURCE_BUILD=1     an mvmctl built from source keys its guest runtime by
#                      the source: sets MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build
#   EXPECT_SCRUB_AUDIT=1   (hvf only) also require the signed
#                      plan.guest_memory_scrubbed audit entry
#   ALLOW_HOST         the one host the workload is granted (default example.com).
#                      The guest has no network interface: every request leaves it
#                      over the vsock egress channel to the host's per-VM endpoint,
#                      and a workload with no grant has no endpoint behind that
#                      channel, so a refusal would be invisible to the host. With a
#                      grant, the planted request for blocked.example crosses the
#                      channel and the endpoint's refusal is audited.
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
#   DRIVER=entrypoint  the workload leaves its own frames and attempts its own
#                      outbound connection from its command, and the host only
#                      observes (`machine logs --stream stdout`, mailbox recv,
#                      the audit chain). Guest markers attest staging/actions,
#                      not host acceptance or refusal. The
#                      default, `exec`, injects frames and the connection
#                      attempt with `machine exec`, a dev-profile verb a
#                      production workload does not have. This is the shape a
#                      production run needs; it is still the dev profile.
#   NETWORK_SEGMENT=1  after the evidence, run mvmd's own Iroh smoke test
#                      (MVMD_DIR, a checkout of mvmd, default ../mvmd) and print
#                      what it shows. Scope, stated on the screen: separate node
#                      and controller processes on this host, Iroh/QUIC over
#                      loopback with the relay disabled. It is not two hosts,
#                      WAN or NAT traversal, object transfer or a microVM
#                      launch, and it never changes the demo's result: a failure
#                      is printed and the demo still ends in its own verdict.
#   MVM_FIRECRACKER_BIN, MVM_MAILBOX_PATH
#                      read by mvmctl; leave unset to test an install
#
# On hvf the run also reads the supervisor's RAM scrub record while the machine
# is quarantined, and fails with the supervisor's stack if the quarantine does
# not finish.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
from_checkout=0
if [ -z "${MVMCTL:-}" ] && [ -x "$here/target/release/mvmctl" ]; then
  MVMCTL="$here/target/release/mvmctl"; from_checkout=1
fi
MVMCTL="${MVMCTL:-mvmctl}"
IMAGE="${IMAGE:-alpine}"
WAIT_SECS="${WAIT_SECS:-120}"
ALLOW_HOST="${ALLOW_HOST:-example.com}"
if [ -z "${HYPERVISOR:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then HYPERVISOR=hvf; else HYPERVISOR=firecracker; fi
fi
case "$HYPERVISOR" in hvf | firecracker) ;; *) echo "FAIL unsupported HYPERVISOR=$HYPERVISOR (hvf or firecracker)" >&2; exit 2 ;; esac
[ "${SOURCE_BUILD:-0}" != 1 ] || export MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build
DRIVER="${DRIVER:-exec}"
case "$DRIVER" in exec | entrypoint) ;; *) echo "FAIL unsupported DRIVER=$DRIVER (exec or entrypoint)" >&2; exit 2 ;; esac
bld=(); [ -z "${BUILDER:-}" ] || bld=(--builder "$BUILDER")

NAME="demo-$$"
FIRST="aircraft-observation-1"
SECOND="fresh-under-epoch-2"
UNREAD="left-unread-in-the-old-workload"
CONTAINED="exfiltrate-to-someone-else"
ID="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"

own_home=""
if [ -z "${MVM_HOME:-}" ]; then
  if [ "$from_checkout" = 1 ]; then
    export MVM_HOME="$here/target/mission-demo-home"; mkdir -p "$MVM_HOME"
  else
    own_home="$(mktemp -d)"; export MVM_HOME="$own_home"
  fi
fi
mvm() { "$MVMCTL" ${bld[@]+"${bld[@]}"} "$@"; }
say() { echo "PASS $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
state_dir() { echo "$MVM_HOME/vms/$NAME"; }
# First 12 hex digits of the SHA-256 of a file (macOS has shasum, many Linux
# hosts only sha256sum).
sha12() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1"; else sha256sum "$1"; fi | cut -c1-12; }

cleanup() {
  rm -f "/tmp/mission-demo-$$".*
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
read_mailbox() {
  message="$(recv)" || fail "mailbox read failed"
}
empty_mailbox() {
  read_mailbox
  [ -z "$message" ] || fail "$1"
}
# Recv is destructive: never discard an unexpected message to find a later one.
wait_message() {
  local expected="$1" end=$((SECONDS + WAIT_SECS)) delay=$(((WAIT_SECS + 14) / 15)) attempt remaining
  for attempt in 1 2 3 4 5; do
    read_mailbox
    [ "$message" != "$expected" ] || return 0
    [ -z "$message" ] || fail "unexpected mailbox message while waiting for $expected"
    [ "$attempt" -lt 5 ] && [ "$SECONDS" -lt "$end" ] || break
    remaining=$((end - SECONDS))
    [ "$delay" -le "$remaining" ] || delay="$remaining"
    sleep "$delay"; delay=$((delay * 2))
  done
  fail "timed out waiting for $expected"
}
# Captured stdout is externally owned; reconcile at most five times. A future
# action-event API could replace this bounded snapshot polling.
wait_action() {
  local action="$1" logs end=$((SECONDS + WAIT_SECS)) delay=$(((WAIT_SECS + 14) / 15)) attempt remaining
  for attempt in 1 2 3 4 5; do
    logs="$(mvm machine logs "$NAME" --stream stdout -n 1000)" || fail "guest logs read failed"
    grep -qxF "MISSION_ACTION=$NAME:$action" <<<"$logs" && return 0
    [ "$attempt" -lt 5 ] && [ "$SECONDS" -lt "$end" ] || break
    remaining=$((end - SECONDS))
    [ "$delay" -le "$remaining" ] || delay="$remaining"
    sleep "$delay"; delay=$((delay * 2))
  done
  fail "timed out waiting for guest action $action"
}
# First use of a home: pull the image and build the workload runtime, which one
# throwaway run does.
prepare() {
  echo "Preparing this machine once (image and runtime)"
  mvm image pull "$IMAGE" >/dev/null || fail "could not pull $IMAGE"
  out="$(mvm machine run --image "$IMAGE" --hypervisor "$HYPERVISOR" -- true 2>&1 </dev/null)" || fail "the first run on this machine failed: $out"
}
# Start the granted persistent machine running `$@`, preparing the home once if
# the launch says it is not prepared.
start_granted() {
  local out
  out="$(mvm machine run -d --image "$IMAGE" --mailbox "$ID" --hypervisor "$HYPERVISOR" --allow-host "$ALLOW_HOST" --name "$NAME" -- "$@" 2>&1)" && return 0
  case "$out" in
    *"is not prepared"*)
      prepare
      out="$(mvm machine run -d --image "$IMAGE" --mailbox "$ID" --hypervisor "$HYPERVISOR" --allow-host "$ALLOW_HOST" --name "$NAME" -- "$@" 2>&1)" && return 0 ;;
  esac
  echo "$out" >&2; return 1
}
launch() { start_granted sleep 900; }
# Guest delays pace the demo, but the host requires observed actions, not time.
workload_first() {
  mailbox_guest_writer
  cat <<EOS
n=\$(grep -o mvm.mailbox=1 /proc/cmdline | wc -l)
if [ "\$n" = 1 ]; then b=$FIRST; else b=bad-cmdline-\$n; fi
mbx_write 000 "\$b" || exit 1
sleep 10; mbx_write 377 $CONTAINED || exit 1
echo 'MISSION_ACTION=$NAME:other-staged'
sleep 5
command -v wget >/dev/null 2>&1 || exit 1
if wget -T 4 -q -O- http://blocked.example >/dev/null 2>&1; then
  echo 'MISSION_ACTION=$NAME:outbound-succeeded'; exit 1
fi
echo 'MISSION_ACTION=$NAME:outbound-failed'
sleep 15; mbx_write 000 $UNREAD || exit 1
echo 'MISSION_ACTION=$NAME:unread-staged'
sleep 900
EOS
}
workload_replacement() {
  mailbox_guest_writer
  printf 'mbx_write 000 %s || exit 1; sleep 900\n' "$SECOND"
}
launch_entrypoint() { start_granted sh -c "$1"; }
audit_dir="$MVM_HOME/audit"
count() { grep -rhoF "$1" "$audit_dir" 2>/dev/null | wc -l | tr -d ' '; }

echo "== 1. a granted guest boots (mvmctl: $(mvm --version), $HYPERVISOR)"
mvm image pull "$IMAGE" >/dev/null || fail "could not pull $IMAGE"
# A refused name lookup (dns.refused) is how the endpoint records a request for a
# host the workload was not granted; a refused connection is a flow denial.
denials() { grep -rhE 'flow\.egress\.denied|host\.flow\.denied|dns\.refused' "$audit_dir" 2>/dev/null | grep -cF blocked.example || true; }
denied_before="$(denials)"
if [ "$DRIVER" = entrypoint ]; then
  launch_entrypoint "$(workload_first)" || fail "entrypoint launch failed"
  say "granted guest launched with its own command; it checks its command line itself"
else
  launch || fail "launch failed"
  wait_for "the guest to take commands" mvm machine exec "$NAME" -- true
  [ "$(mvm machine exec "$NAME" -- cat /proc/cmdline | grep -o 'mvm.mailbox=1' | wc -l)" -eq 1 ] || fail "not exactly one mvm.mailbox=1"
  say "granted guest booted with exactly one mvm.mailbox=1"
fi

echo "== 2. the guest delivers a message to its host mailbox"
[ "$DRIVER" = entrypoint ] || mailbox_write_frame "$NAME" "$OWN" "$FIRST" || fail "first frame staging failed"
wait_message "$FIRST"; say "message read back exactly"
[ "$DRIVER" != entrypoint ] || say "the entrypoint saw exactly one mvm.mailbox=1 (otherwise its frame would differ)"
empty_mailbox "mailbox not empty after reading"; say "mailbox empty after reading"

echo "== 3. observe a planted compromise attempt"
if [ "$DRIVER" = entrypoint ]; then
  wait_action other-staged
  say "guest reported staging a frame for another mailbox (not host acceptance)"
else
  mailbox_write_frame "$NAME" "$OTHER" "$CONTAINED" || fail "other frame staging failed"
  sleep 8
fi
empty_mailbox "a message to another recipient was queued"
say "host mailbox read returned empty after the other-recipient staging"
echo "FINDING: host refusal is unproven; an empty read is not a host decision or proof the staged frame was processed."
if [ "$DRIVER" = entrypoint ]; then
  wait_action outbound-failed
  say "guest reported a failed outbound attempt; the host's decision is checked separately"
else
  if mvm machine exec "$NAME" -- sh -c 'wget -T 4 -q -O- http://blocked.example >/dev/null 2>&1'; then fail "the guest reached the network"; fi
  say "an outbound connection from the guest failed (this shows it fails, not why)"
fi
# Whether the host audited the refusal is a separate question from the attempt
# failing; give the entry a few seconds to be written before judging.
for _ in 1 2 3 4 5 6 7 8 9 10; do [ "$(denials)" -gt "$denied_before" ] && break; sleep 1; done
if [ "$(denials)" -gt "$denied_before" ]; then
  say "the refused outbound attempt left an audited egress denial naming blocked.example"
elif [ "${EXPECT_EGRESS_DENIAL_AUDIT:-0}" = 1 ]; then
  fail "the refused outbound attempt left no flow.egress.denied, host.flow.denied or dns.refused entry naming blocked.example"
else
  echo "FINDING: the refused outbound attempt left no flow.egress.denied, host.flow.denied or dns.refused entry naming blocked.example; the failure is observed but the host's decision is not audited here."
fi

echo "== 4. a running workload cannot be replaced"
out="$(mvm machine replace "$NAME" 2>&1)" && fail "replace succeeded on a running machine"
grep -q "machine stop $NAME" <<<"$out" || fail "replace did not name machine stop: $out"
say "replace refused while running, naming \`machine stop $NAME\`"

echo "== 5. contain: quarantine and terminate"
# A staged frame is not evidence that the host accepted it before containment.
if [ "$DRIVER" = entrypoint ]; then
  wait_action unread-staged
else
  mailbox_write_frame "$NAME" "$OWN" "$UNREAD" || fail "unread frame staging failed"
  sleep 3
fi
echo "FINDING: unread frame host acceptance is unproven; no non-destructive queue evidence is exposed here, so replacement cannot prove its purge."
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

echo "== 8. the replacement runs under new keys; check exact message order"
if [ "$DRIVER" = entrypoint ]; then
  launch_entrypoint "$(workload_replacement)" || fail "replacement entrypoint launch failed"
else
  launch || fail "replacement launch failed"
  wait_for "the replacement to take commands" mvm machine exec "$NAME" -- true
fi
[ -s "$secret" ] || fail "no replacement per-launch secret"
new_secret="$(sha12 "$secret")"
[ "$new_secret" != "$old_secret" ] || fail "the replacement has the old per-launch secret"
say "per-launch secret changed ($old_secret... -> $new_secret...)"
if [ "$DRIVER" = exec ]; then
  empty_mailbox "the replacement could read a message from the old workload"
  mailbox_write_frame "$NAME" "$OWN" "$SECOND" || fail "replacement frame staging failed"
fi
wait_message "$SECOND"
say "a fresh message under the new epoch is read exactly"
empty_mailbox "unexpected message after the replacement's fresh message"
say "no old message observed in the replacement reads (not proof of unread acceptance or erasure)"

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
if [ "${NETWORK_SEGMENT:-0}" = 1 ]; then
  echo "== 11. optional: fleet networking carrier (separate processes, loopback only)"
  echo "Scope: a mvmd node and controller as separate processes on THIS host, talking over Iroh/QUIC on loopback with the relay disabled."
  echo "Not shown: two hosts, WAN or NAT traversal, object transfer, or a microVM launch. A connected carrier authorizes nothing."
  smoke="${MVMD_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../mvmd}/scripts/smoke-iroh.sh"
  if [ ! -f "$smoke" ]; then
    echo "NETWORK_SEGMENT skipped: no $smoke (set MVMD_DIR to a mvmd checkout)"
  else
    net_root="$(mktemp -d)"; net_log="$net_root.log"
    # Bounded so a stuck carrier cannot hold up the demo.
    ( cd "$(dirname "$smoke")/.." && exec bash "$smoke" "$net_root" ) >"$net_log" 2>&1 </dev/null &
    net_pid=$!
    net_end=$((SECONDS + ${NETWORK_SEGMENT_SECS:-240}))
    while kill -0 "$net_pid" 2>/dev/null && [ "$SECONDS" -lt "$net_end" ]; do sleep 1; done
    if kill -0 "$net_pid" 2>/dev/null; then
      kill "$net_pid" 2>/dev/null; echo "NETWORK_SEGMENT did not finish in ${NETWORK_SEGMENT_SECS:-240} s; omitted (the demo's result above is unaffected)"
    elif wait "$net_pid"; then
      sed -n $'s/\033\\[[0-9;]*m//g;/Iroh cross-host node service ready/p' "$net_root/node.log" 2>/dev/null | sed 's/^[^ ]* *//'
      grep -E '"status"|"mode"|"replicated"' "$net_log" | sed 's/^ */  controller health: /'
      echo "NETWORK_SEGMENT ok: node and controller started as separate processes over Iroh (loopback); the controller reports healthy"
    else
      echo "NETWORK_SEGMENT failed; omitted (the demo's result above is unaffected). Last lines:"; tail -5 "$net_log"
    fi
    rm -rf "$net_root" "$net_log"
  fi
fi
echo "DEMO_RESULT=partial"
