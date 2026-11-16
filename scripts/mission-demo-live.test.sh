#!/usr/bin/env bash
# Hermetic test of mission-demo-live.sh. A fake mvmctl models the guest, its
# mailbox queue, quarantine, the epoch ledger and the audit log, so the
# runbook's own logic is checked without booting anything: it must pass when the
# product behaves and fail for each way the product could misbehave. This
# proves the script, not the product; a live run proves the product.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

# Run the actual generated guest writer against a disposable directory.
# stat's Linux syntax is stubbed so this stays hermetic on macOS as well.
# shellcheck source-path=SCRIPTDIR source=lib/mailbox-frame.sh
. "${repo}/scripts/lib/mailbox-frame.sh"
writer="$(mailbox_guest_writer)"
mkdir -p "${work}/guest/outbox"
writer="${writer//\/run\/mvm\/mailbox/${work}/guest}"
for fault in none stat chmod mv; do
  guest_script='stat() { id -u; };'
  [ "$fault" = none ] || guest_script+=" $fault() { return 1; };"
  guest_script+="$writer"$'\nmbx_write 000 hello || exit 1\necho staged'
  if out="$(sh -c "$guest_script")"; then
    [ "$fault" = none ] || fail "writer ignored $fault failure"
    [ "$out" = staged ] || fail "writer did not stage"
  else
    [ "$fault" != none ] || fail "writer failed"
    [ -z "$out" ] || fail "writer reported staging after $fault failed"
  fi
done

cat > "${work}/mvmctl" <<'S'
#!/usr/bin/env bash
# FAKE_MODE: ok | replace-works-running | secret-survives | leaks-old-state | leaks-body
#            | queues-other | needs-bootstrap | wedge
fake="${FAKE_STATE:?}"; mode="${FAKE_MODE:-ok}"; home="${MVM_HOME:?}"
[ "${1:-}" = --builder ] && shift 2
audit="${home}/audit/local.jsonl"; ledger="${home}/host-interface/workloads.json"
mkdir -p "${home}/audit" "${home}/host-interface"
epoch_of() { sed -n "s/.*\"$1\": *{\"epoch\": *\([0-9]*\).*/\1/p" "${ledger}" 2>/dev/null | head -1; }
set_ledger() { printf '{"%s": {"epoch": %s, "quarantined": %s}}\n' "$1" "$2" "$3" > "${ledger}"; }
case "${1:-} ${2:-}" in
  "--version "*) echo "mvmctl fake" ;;
  "image pull") ;;
  "machine run")
    if grep -q 'curlimages' <<<"$*"; then
      cname="$(sed -n 's/.*--name \([^ ]*\).*/\1/p' <<<"$*")"
      if grep -q 'blocked.example' <<<"$*"; then
        [ "${FAKE_FLOW:-ok}" = no-audit ] || echo "{\"event\":\"host.flow.denied\",\"labels\":{\"target\":\"blocked.example:443\",\"vm_name\":\"${cname}\"}}" >> "${audit}"
        echo "[mvm]   mvmctl explain sha256:abc123 --review" >&2; exit 22
      fi
      [ "${FAKE_FLOW:-ok}" = no-audit ] || echo "{\"event\":\"host.flow.allowed\",\"labels\":{\"target\":\"example.com:443\",\"vm_name\":\"${cname}\"}}" >> "${audit}"
      exit 0
    fi
    allargs=" $* "; shift 2; name=""; hv=firecracker
    echo "$allargs" >> "${fake}/runs"
    while [ $# -gt 0 ]; do case "$1" in --name) name="$2"; shift ;; --hypervisor) hv="$2"; shift ;; esac; shift; done
    if [ "${mode}" = needs-bootstrap ] && [ ! -f "${fake}/prepared" ]; then
      # A home that has not been prepared refuses a persistent launch; one
      # throwaway transient run prepares it.
      if [[ "${allargs}" == *" -d "* ]]; then echo "Error: the published OCI guest runtime is not prepared; run \`mvmctl bootstrap\` first" >&2; exit 1; fi
      touch "${fake}/prepared"; exit 0
    fi
    if grep -q '"quarantined": true' "${ledger}" 2>/dev/null; then echo "Error: workload ${name} is quarantined" >&2; exit 1; fi
    [ "${mode}" != launch-failure ] || { echo "launch failed" >&2; exit 1; }
    if [ "${mode}" = replacement-launch-failure ] && [ "$(epoch_of "${name}")" = 2 ]; then echo "replacement launch failed" >&2; exit 1; fi
    mkdir -p "${home}/vms/${name}"; head -c 16 /dev/urandom | od -An -tx1 > "${home}/vms/${name}/mailbox-epoch.secret"
    if [ "${hv}" = hvf ]; then echo "4242 1" > "${home}/vms/${name}/hvf.pid"; fi
    [ -f "${ledger}" ] || set_ledger "${name}" 1 false
    touch "${fake}/running.${name}"; echo "${hv}" > "${fake}/hv"
    [ "${mode}" = leaks-old-state ] || : > "${fake}/queue"
    if [ "${DRIVER:-exec}" = entrypoint ]; then
      if [ "$(epoch_of "${name}")" = 1 ]; then
        for action in other-staged outbound-failed unread-staged; do
          grep -qF "MISSION_ACTION=$name:$action" <<<"$allargs" || exit 2
        done
        [ "${mode}" != wrong-first ] || echo unexpected >> "${fake}/queue"
        [ "${mode}" = missing-first ] || echo aircraft-observation-1 >> "${fake}/queue"
      else
        [ "${mode}" != wrong-second ] || echo unexpected >> "${fake}/queue"
        [ "${mode}" = missing-second ] || echo fresh-under-epoch-2 >> "${fake}/queue"
        [ "${mode}" != trailing-old-state ] || echo left-unread-in-the-old-workload >> "${fake}/queue"
      fi
    fi ;;
  "machine exec")
    if [ "${DRIVER:-exec}" = entrypoint ]; then echo exec >> "${fake}/forbidden-exec"; exit 2; fi
    name="$3"; shift 4; [ -f "${fake}/running.${name}" ] || exit 1
    case "$*" in
      true) ;;
      "cat /proc/cmdline") echo "ro mvm.mailbox=1 quiet" ;;
      sh*wget*) [ "${FAKE_DENIAL:-}" = 1 ] && echo '{"event":"flow.egress.denied","labels":{"destination":"blocked.example"}}' >> "${audit}"
                [ "${FAKE_DENIAL:-}" = dns ] && echo '{"event":"dns.refused","labels":{"qname":"blocked.example","reason":"policy_denied"}}' >> "${audit}"
                exit 1 ;;
      sh*) fill="${*: -2:1}"; body="${*: -1}"
           if [ "${fill}" = 000 ] || [ "${mode}" = queues-other ]; then echo "${body}" >> "${fake}/queue"; fi ;;
      *) echo "fake: unhandled exec: $*" >&2; exit 2 ;;
    esac ;;
  "machine mailbox")
    [ "${mode}" != recv-failure ] || { echo "recv failed" >&2; exit 1; }
    [ "${mode}" != recv-output-failure ] || { printf aircraft-observation-1; exit 1; }
    if [ "${mode}" = empty-recv-failure ] && [ ! -s "${fake}/queue" ]; then exit 1; fi
    [ -s "${fake}/queue" ] || exit 0
    body="$(head -n1 "${fake}/queue")"; sed -i.bak 1d "${fake}/queue"; printf '%s' "${body}"
    echo '{"event":"mailbox.read","labels":{"bytes":"7"}}' >> "${audit}"
    if [ "${mode}" = leaks-body ]; then echo "{\"event\":\"x\",\"labels\":{\"body\":\"${body}\"}}" >> "${audit}"; fi ;;
  "machine logs")
    [ "${mode}" != logs-failure ] || exit 1
    if [ "${mode}" = stale-actions ]; then
      printf 'MISSION_ACTION=old-run:%s\n' other-staged outbound-failed unread-staged
      exit 0
    fi
    [ "${mode}" = missing-contained ] || echo "MISSION_ACTION=$3:other-staged"
    [ "${mode}" = missing-outbound ] || echo "MISSION_ACTION=$3:outbound-failed"
    calls="$(cat "${fake}/log-calls" 2>/dev/null || echo 0)"
    calls=$((calls + 1)); echo "$calls" > "${fake}/log-calls"
    if [ "${mode}" != missing-unread ]; then
      echo "MISSION_ACTION=$3:unread-staged"
      if [ "${mode}" = leaks-old-state ] && [ "$calls" -eq 3 ]; then
        echo left-unread-in-the-old-workload >> "${fake}/queue"; touch "${fake}/unread"
      fi
    fi ;;
  "machine replace")
    name="$3"
    if [ -f "${fake}/running.${name}" ] && [ "${mode}" != replace-works-running ]; then
      echo "Error: ${name} is still running under its current execution epoch; stop it first (\`mvmctl machine stop ${name}\`), then replace it" >&2; exit 1
    fi
    e=$(( $(epoch_of "${name}") + 1 )); set_ledger "${name}" "${e}" false
    echo "{\"event\":\"workload.replaced\",\"labels\":{\"workload\":\"${name}\",\"epoch\":\"${e}\"}}" >> "${audit}"
    echo "${name} may launch again under execution epoch ${e}" ;;
  "machine quarantine")
    name="$3"
    # A wedged quarantine never completes. It must not go on to write the ledger
    # or the audit after its sleep: the shared home belongs to a later case by then.
    [ "${mode}" = wedge ] && { sleep 30; exit 1; }
    rm -f "${fake}/running.${name}"
    if [ "$(cat "${fake}/hv" 2>/dev/null)" = hvf ]; then echo '{"schema_version":1}' > "${home}/vms/${name}/ram-scrub.json"; sleep 0.2
      echo '{"event":"plan.guest_memory_scrubbed","labels":{"scrubbed_pages":"2000"}}' >> "${audit}"; fi
    if [ "${mode}" = secret-survives ]; then mv "${home}/vms/${name}/mailbox-epoch.secret" "${home}/kept.secret"; mkdir -p "${home}/vms/${name}"; cp "${home}/kept.secret" "${home}/vms/${name}/mailbox-epoch.secret"
    else rm -rf "${home}/vms/${name}"; fi
    set_ledger "${name}" "$(epoch_of "${name}")" true
    echo "{\"event\":\"workload.quarantined\",\"labels\":{\"workload\":\"${name}\"}}" >> "${audit}"
    echo "quarantined ${name}: it will not launch again until replaced"
    exit 0 ;;
  "explain "*) printf 'egress denied:\n  blocked.example:443  1x  not in the allow-list\n' ;;
  "trust audit") echo "VERIFIED chain: 7 entries, 1 session, 1 seals" ;;
  "machine stop" | "machine rm") ;;
  *) echo "fake: unhandled: $*" >&2; exit 2 ;;
esac
S
chmod +x "${work}/mvmctl"

# The fake has no asynchronous guest transport. Skip transport pacing, while
# retaining short process waits and the real wedge/network deadline clocks.
real_sleep="$(command -v sleep)"
cat > "${work}/sleep" <<'S'
#!/usr/bin/env bash
case "$1" in 1 | 2 | 3 | 4 | 8) exec "${REAL_SLEEP:?}" 0.01 ;; esac
exec "${REAL_SLEEP:?}" "$@"
S
chmod +x "${work}/sleep"

run() { # <mode> <env assignments...> -> output; the script's own exit status is returned
  local mode="$1"; shift
  rm -rf "${work:?}/state" "${work:?}/home"; mkdir -p "${work}/state" "${work}/home"
  env PATH="${work}:$PATH" REAL_SLEEP="$real_sleep" MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE="${mode}" MVM_HOME="${work}/home" \
    WAIT_SECS=4 QUARANTINE_DEADLINE=3 "$@" bash "${repo}/scripts/mission-demo-live.sh" 2>&1
}
passes() { grep -c '^PASS ' <<<"$1"; }

out="$(run ok HYPERVISOR=firecracker)" || fail "a correct firecracker run failed: ${out}"
grep -q '^DEMO_RESULT=partial$' <<<"${out}" || fail "no partial result (firecracker): ${out}"
grep -q 'RAM scrub record' <<<"${out}" && fail "a firecracker run reported a RAM scrub record"
n="$(passes "${out}")"

out="$(run ok HYPERVISOR=hvf)" || fail "a correct hvf run failed: ${out}"
grep -q '^DEMO_RESULT=partial$' <<<"${out}" || fail "no partial result (hvf): ${out}"
grep -q 'RAM scrub record' <<<"${out}" || fail "the hvf run did not read the RAM scrub record: ${out}"

out="$(run ok HYPERVISOR=hvf EXPECT_SCRUB_AUDIT=1)" || fail "hvf with the scrub audit entry failed: ${out}"
grep -q 'plan.guest_memory_scrubbed' <<<"${out}" || fail "the scrub audit entry was not checked: ${out}"
run ok HYPERVISOR=firecracker EXPECT_SCRUB_AUDIT=1 >/dev/null && fail "EXPECT_SCRUB_AUDIT passed on firecracker"
run ok HYPERVISOR=qemu >/dev/null && fail "an unsupported hypervisor was accepted"
out="$(run ok HYPERVISOR=firecracker FAKE_DENIAL=1 EXPECT_EGRESS_DENIAL_AUDIT=1)" || fail "a run with an audited denial failed under EXPECT_EGRESS_DENIAL_AUDIT: ${out}"
grep -q 'audited egress denial naming blocked.example' <<<"${out}" || fail "the audited denial was not reported: ${out}"
out="$(run ok HYPERVISOR=firecracker FAKE_DENIAL=dns EXPECT_EGRESS_DENIAL_AUDIT=1)" || fail "a refused name lookup (dns.refused) did not count as an audited denial: ${out}"
grep -q 'audited egress denial naming blocked.example' <<<"${out}" || fail "the dns.refused denial was not reported: ${out}"
run ok HYPERVISOR=firecracker EXPECT_EGRESS_DENIAL_AUDIT=1 >/dev/null && fail "EXPECT_EGRESS_DENIAL_AUDIT passed with no denial entry"
out="$(run ok HYPERVISOR=firecracker)" || fail "a run with no denial entry failed without the strict flag: ${out}"
grep -q '^FINDING: the refused outbound attempt left no' <<<"${out}" || fail "the missing denial entry was not reported as a FINDING: ${out}"

bad() { # <mode> <what must be caught>
  local o; o="$(run "$1" HYPERVISOR=firecracker)" && fail "$2: the run passed: ${o}"
  grep -q '^DEMO_RESULT=pass$' <<<"${o}" && fail "$2: printed a pass line"
  return 0
}
bad replace-works-running "a running workload was replaced"
bad secret-survives "the per-launch secret survived the quarantine"
bad leaks-old-state "the replacement could read the old workload's frame"
bad leaks-body "a message body was in the audit log"
bad queues-other "a message to another recipient was queued"
bad launch-failure "initial launch failure"
bad replacement-launch-failure "replacement launch failure"
bad recv-failure "failed mailbox read"
bad empty-recv-failure "failed mailbox read treated as empty"

# Entrypoint observations are a narrowed witness, never proof of unread queue
# acceptance or host refusal. No machine exec is permitted on this path.
out="$(run ok HYPERVISOR=firecracker DRIVER=entrypoint)" || fail "entrypoint observations failed: ${out}"
grep -q '^DEMO_RESULT=partial$' <<<"${out}" || fail "entrypoint must report incomplete host evidence: ${out}"
grep -q 'FINDING:.*host acceptance' <<<"${out}" || fail "missing queue evidence not explained: ${out}"
! grep -q 'PASS.*was refused\|PASS.*frame left unread.*not readable\|DEMO_RESULT=pass' <<<"${out}" || fail "unsupported entrypoint claim: ${out}"
[ ! -f "${work}/state/forbidden-exec" ] || fail "entrypoint used machine exec"
for mode in missing-first wrong-first missing-contained missing-outbound missing-unread stale-actions missing-second wrong-second recv-failure recv-output-failure empty-recv-failure logs-failure launch-failure replacement-launch-failure leaks-old-state trailing-old-state; do
  out="$(run "$mode" HYPERVISOR=firecracker DRIVER=entrypoint)" && fail "entrypoint accepted $mode: ${out}"
  ! grep -q '^DEMO_RESULT=' <<<"${out}" || fail "entrypoint printed a result for $mode: ${out}"
  [ ! -f "${work}/state/forbidden-exec" ] || fail "entrypoint used machine exec in $mode"
  case "$mode" in
    missing-first | missing-second) reason="timed out waiting for" ;;
    wrong-first | wrong-second | leaks-old-state) reason="unexpected mailbox message while waiting for" ;;
    missing-contained | missing-outbound | missing-unread | stale-actions) reason="timed out waiting for guest action" ;;
    recv-failure | recv-output-failure | empty-recv-failure) reason="mailbox read failed" ;;
    logs-failure) reason="guest logs read failed" ;;
    launch-failure | replacement-launch-failure) reason="entrypoint launch failed" ;;
    trailing-old-state) reason="unexpected message after the replacement's fresh message" ;;
  esac
  grep -qF "$reason" <<<"${out}" || fail "wrong failure for $mode: ${out}"
done
# An unprepared home is prepared by the script itself, with no bootstrap step.
out="$(run needs-bootstrap HYPERVISOR=firecracker)" || fail "an unprepared home was not prepared: ${out}"
grep -q "^Preparing this machine once" <<<"${out}" || fail "the script did not say it was preparing: ${out}"
grep -q "DEMO_RESULT=partial" <<<"${out}" || fail "the run did not complete after preparing: ${out}"
! grep -qi "bootstrap" <<<"${out}" || fail "the run mentioned bootstrap: ${out}"
out="$(run wedge HYPERVISOR=firecracker)" && fail "a wedged quarantine passed"
grep -q 'WEDGE' <<<"${out}" || fail "a wedged quarantine was not reported: ${out}"

# The workload is granted one host so its requests cross the vsock egress
# channel and the endpoint's refusal is audited; ALLOW_HOST overrides it.
out="$(run ok HYPERVISOR=firecracker)" || fail "the default run failed: ${out}"
grep -q -- ' --allow-host example.com ' "${work}/state/runs" || fail "the granted launch carried no --allow-host example.com: $(cat "${work}/state/runs")"
out="$(run ok HYPERVISOR=firecracker ALLOW_HOST=granted.example)" || fail "a run with ALLOW_HOST failed: ${out}"
grep -q -- ' --allow-host granted.example ' "${work}/state/runs" || fail "ALLOW_HOST was not used: $(cat "${work}/state/runs")"

# The optional egress probe: allowed and denied requests must both be audited
# and explained; without the audit entries the run must fail.
out="$(run ok HYPERVISOR=firecracker EGRESS_PROBE=1)" || fail "a correct run with EGRESS_PROBE failed: ${out}"
grep -q 'audit has host.flow.denied for egress-deny-' <<<"${out}" || fail "the denial audit was not checked: ${out}"
grep -q 'explain reports the denied destination' <<<"${out}" || fail "explain was not checked: ${out}"
out="$(run ok HYPERVISOR=firecracker EGRESS_PROBE=1 FAKE_FLOW=no-audit)" && fail "EGRESS_PROBE passed with no flow audit entries: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" && fail "EGRESS_PROBE printed a pass line without flow audit entries"

# The optional networking segment states its scope and can never change the
# demo's verdict: a carrier that fails, hangs, or is not installed is reported
# and the demo still ends in its own result.
mvmd="${work}/mvmd"; mkdir -p "${mvmd}/scripts"
fake_smoke() { printf '#!/usr/bin/env bash\n%s\n' "$1" > "${mvmd}/scripts/smoke-iroh.sh"; }
fake_smoke 'echo "{\"status\": \"ok\"}"; echo "iroh smoke test passed"'
out="$(run ok HYPERVISOR=firecracker NETWORK_SEGMENT=1 MVMD_DIR="${mvmd}")" || fail "a passing network segment broke the run: ${out}"
grep -q "separate processes on THIS host" <<<"${out}" || fail "the segment did not state its scope: ${out}"
grep -q "Not shown: two hosts, WAN or NAT traversal" <<<"${out}" || fail "the segment did not state what it does not show: ${out}"
grep -q "^NETWORK_SEGMENT ok" <<<"${out}" || fail "a passing segment was not reported ok: ${out}"
grep -q '^DEMO_RESULT=partial$' <<<"${out}" || fail "the demo lost its verdict after the segment"
fake_smoke 'echo "node failed to bind"; exit 1'
out="$(run ok HYPERVISOR=firecracker NETWORK_SEGMENT=1 MVMD_DIR="${mvmd}")" || fail "a failing network segment failed the demo: ${out}"
grep -q "^NETWORK_SEGMENT failed" <<<"${out}" || fail "a failing segment was not reported: ${out}"
grep -q '^DEMO_RESULT=partial$' <<<"${out}" || fail "a failing segment changed the demo's verdict"
fake_smoke 'sleep 30'
out="$(run ok HYPERVISOR=firecracker NETWORK_SEGMENT=1 NETWORK_SEGMENT_SECS=2 MVMD_DIR="${mvmd}")" || fail "a hung network segment failed the demo: ${out}"
grep -q "^NETWORK_SEGMENT did not finish" <<<"${out}" || fail "a hung segment was not omitted: ${out}"
out="$(run ok HYPERVISOR=firecracker NETWORK_SEGMENT=1 MVMD_DIR="${work}/no-such-checkout")" || fail "a missing mvmd failed the demo: ${out}"
grep -q "^NETWORK_SEGMENT skipped" <<<"${out}" || fail "a missing mvmd was not reported as skipped: ${out}"
out="$(run ok HYPERVISOR=firecracker)" || fail "the default run failed"
! grep -q "NETWORK_SEGMENT\|networking carrier" <<<"${out}" || fail "the segment ran without being asked for: ${out}"

# The audit checks must be about THIS run: an earlier run's entries must not
# satisfy them. The fake writes nothing for a replace it refuses, so a missing
# entry is a failure even though older lines mention the same events.
echo "ok ($n checks per run)"
