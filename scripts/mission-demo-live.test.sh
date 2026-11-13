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
    shift 2; name=""; hv=firecracker
    while [ $# -gt 0 ]; do case "$1" in --name) name="$2"; shift ;; --hypervisor) hv="$2"; shift ;; esac; shift; done
    if [ "${mode}" = needs-bootstrap ]; then echo "Error: runtime not prepared; run \`mvmctl bootstrap\` first" >&2; exit 1; fi
    if grep -q '"quarantined": true' "${ledger}" 2>/dev/null; then echo "Error: workload ${name} is quarantined" >&2; exit 1; fi
    mkdir -p "${home}/vms/${name}"; head -c 16 /dev/urandom | od -An -tx1 > "${home}/vms/${name}/mailbox-epoch.secret"
    if [ "${hv}" = hvf ]; then echo "4242 1" > "${home}/vms/${name}/hvf.pid"; fi
    [ -f "${ledger}" ] || set_ledger "${name}" 1 false
    touch "${fake}/running.${name}"; echo "${hv}" > "${fake}/hv"
    [ "${mode}" = leaks-old-state ] || : > "${fake}/queue" ;;
  "machine exec")
    name="$3"; shift 4; [ -f "${fake}/running.${name}" ] || exit 1
    case "$*" in
      true) ;;
      "cat /proc/cmdline") echo "ro mvm.mailbox=1 quiet" ;;
      sh*wget*) [ "${FAKE_DENIAL:-}" = 1 ] && echo '{"event":"flow.egress.denied","labels":{"destination":"example.com"}}' >> "${audit}"; exit 1 ;;
      sh*) fill="${*: -2:1}"; body="${*: -1}"
           if [ "${fill}" = 000 ] || [ "${mode}" = queues-other ]; then echo "${body}" >> "${fake}/queue"; fi ;;
      *) echo "fake: unhandled exec: $*" >&2; exit 2 ;;
    esac ;;
  "machine mailbox")
    [ -s "${fake}/queue" ] || exit 0
    body="$(head -n1 "${fake}/queue")"; sed -i.bak 1d "${fake}/queue"; printf '%s' "${body}"
    echo '{"event":"mailbox.read","labels":{"bytes":"7"}}' >> "${audit}"
    if [ "${mode}" = leaks-body ]; then echo "{\"event\":\"x\",\"labels\":{\"body\":\"${body}\"}}" >> "${audit}"; fi ;;
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
    [ "${mode}" = wedge ] && sleep 30
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

run() { # <mode> <env assignments...> -> output; the script's own exit status is returned
  local mode="$1"; shift
  rm -rf "${work:?}/state" "${work:?}/home"; mkdir -p "${work}/state" "${work}/home"
  env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE="${mode}" MVM_HOME="${work}/home" \
    WAIT_SECS=4 QUARANTINE_DEADLINE=3 "$@" bash "${repo}/scripts/mission-demo-live.sh" 2>&1
}
passes() { grep -c '^PASS ' <<<"$1"; }

out="$(run ok HYPERVISOR=firecracker)" || fail "a correct firecracker run failed: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" || fail "no pass line (firecracker): ${out}"
grep -q 'RAM scrub record' <<<"${out}" && fail "a firecracker run reported a RAM scrub record"
n="$(passes "${out}")"

out="$(run ok HYPERVISOR=hvf)" || fail "a correct hvf run failed: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" || fail "no pass line (hvf): ${out}"
grep -q 'RAM scrub record' <<<"${out}" || fail "the hvf run did not read the RAM scrub record: ${out}"

out="$(run ok HYPERVISOR=hvf EXPECT_SCRUB_AUDIT=1)" || fail "hvf with the scrub audit entry failed: ${out}"
grep -q 'plan.guest_memory_scrubbed' <<<"${out}" || fail "the scrub audit entry was not checked: ${out}"
run ok HYPERVISOR=firecracker EXPECT_SCRUB_AUDIT=1 >/dev/null && fail "EXPECT_SCRUB_AUDIT passed on firecracker"
run ok HYPERVISOR=qemu >/dev/null && fail "an unsupported hypervisor was accepted"
out="$(run ok HYPERVISOR=firecracker FAKE_DENIAL=1 EXPECT_EGRESS_DENIAL_AUDIT=1)" || fail "a run with an audited denial failed under EXPECT_EGRESS_DENIAL_AUDIT: ${out}"
grep -q 'audited egress denial naming example.com' <<<"${out}" || fail "the audited denial was not reported: ${out}"
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
out="$(run needs-bootstrap HYPERVISOR=firecracker)" && fail "an install that needs bootstrap passed"
grep -q "^FINDING: the install asked for 'mvmctl bootstrap'" <<<"${out}" || fail "no bootstrap finding: ${out}"
out="$(run wedge HYPERVISOR=firecracker)" && fail "a wedged quarantine passed"
grep -q 'WEDGE' <<<"${out}" || fail "a wedged quarantine was not reported: ${out}"

# The optional egress probe: allowed and denied requests must both be audited
# and explained; without the audit entries the run must fail.
out="$(run ok HYPERVISOR=firecracker EGRESS_PROBE=1)" || fail "a correct run with EGRESS_PROBE failed: ${out}"
grep -q 'audit has host.flow.denied for egress-deny-' <<<"${out}" || fail "the denial audit was not checked: ${out}"
grep -q 'explain reports the denied destination' <<<"${out}" || fail "explain was not checked: ${out}"
out="$(run ok HYPERVISOR=firecracker EGRESS_PROBE=1 FAKE_FLOW=no-audit)" && fail "EGRESS_PROBE passed with no flow audit entries: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" && fail "EGRESS_PROBE printed a pass line without flow audit entries"

# The audit checks must be about THIS run: an earlier run's entries must not
# satisfy them. The fake writes nothing for a replace it refuses, so a missing
# entry is a failure even though older lines mention the same events.
echo "ok ($n checks per run)"
