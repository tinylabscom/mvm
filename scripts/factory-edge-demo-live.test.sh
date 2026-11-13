#!/usr/bin/env bash
# Hermetic test of factory-edge-demo-live.sh. A fake mvmctl models per-machine
# status, the egress denials the host records, plans and sessions, so the
# runbook's own logic is checked without booting anything: it must pass when
# the product behaves and fail for each way the product could misbehave. This
# proves the script, not the product; a live run proves the product.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "${work}/mvmctl" <<'S'
#!/usr/bin/env bash
# FAKE_MODE: ok | request-not-refused | no-denial | denial-on-inspection | line-short
#            | chain-broken | not-host-entry | replacement-inherits | same-plan | no-seal
#            | never-stops | audit-fails | needs-bootstrap
st="${FAKE_STATE:?}"; mode="${FAKE_MODE:-ok}"
[ "${1:-}" = --builder ] && shift 2
plan_of() { case "$1" in fe-replacement-*) [ "${mode}" = same-plan ] && echo "plan-suspect" || echo "plan-$1" ;; fe-suspect-*) echo "plan-suspect" ;; *) echo "plan-$1" ;; esac; }
denied() { # does the host hold a denial for $1
  case "$1" in
    fe-maint-*) [ "${mode}" != no-denial ] ;;
    fe-suspect-*) [ "${mode}" != no-denial ] ;;
    fe-line-a-*) [ "${mode}" = denial-on-inspection ] ;;
    fe-replacement-*) [ "${mode}" = replacement-inherits ] ;;
    *) return 1 ;;
  esac
}
case "${1:-} ${2:-}" in
  "--version "*) echo "mvmctl fake" ;;
  "image pull") ;;
  "run "*)
    shift; name=""; detach=0
    while [ $# -gt 0 ]; do case "$1" in --name) name="$2"; shift ;; -d) detach=1 ;; --) shift; break ;; esac; shift; done
    if [ "${mode}" = needs-bootstrap ]; then echo "Error: runtime not prepared; run \`mvmctl bootstrap\` first" >&2; exit 1; fi
    echo running > "${st}/status.${name}"
    if [ "${detach}" = 1 ]; then echo "started machine ${name}"; exit 0; fi
    echo done > "${st}/status.${name}"; touch "${st}/exited.${name}"
    case "${name}" in
      fe-line-a-*) n=6; [ "${mode}" = line-short ] && n=3; for i in $(seq 1 "${n}"); do echo "line-ok ${i}"; done ;;
      fe-line-b-*) for i in 1 2 3 4 5 6; do echo "line-ok ${i}"; done ;;
      fe-maint-*) if [ "${mode}" = request-not-refused ]; then echo "curl_rc=0"; else echo "curl: (6) Could not resolve host"; echo "curl_rc=6"; fi ;;
      fe-replacement-*) echo "replacement-ready" ;;
      fe-nogrant-*) echo "curl: (6) Could not resolve host"; echo "curl_rc=6" ;;
    esac ;;
  "machine ls") echo "NAME KIND STATUS HEALTH BACKEND"; for f in "${st}"/status.*; do [ -e "$f" ] || continue; n="${f##*/status.}"; s="$(cat "$f")"; [ "$s" = done ] && continue; echo "${n} persistent ${s} - hvf"; done ;;
  "machine stop")
    n="$3"; [ "${mode}" = never-stops ] || echo stopped > "${st}/status.${n}"
    [ "${mode}" = no-seal ] || touch "${st}/sealed.${n}" ;;
  "machine rm") ;;
  "trust audit") [ "${mode}" = audit-fails ] && { echo "TAMPERED" >&2; exit 1; }; echo "VERIFIED chain: 7 entries, 1 session, 1 seal" ;;
  "explain "*)
    n="$2"; ev='{"event":"plan.admitted"}'
    [ -e "${st}/exited.${n}" ] && ev="${ev},{\"event\":\"plan.exited\"}"
    [ -e "${st}/sealed.${n}" ] && ev="${ev},{\"event\":\"session.sealed\"}"
    verified=true; [ "${mode}" = chain-broken ] && verified=false
    den='[]'
    if denied "${n}"; then e=host.flow.denied; [ "${mode}" = not-host-entry ] && e=other.event; den="[{\"destination\":\"example.com:443\",\"event\":\"${e}\",\"reason\":\"policy_denied\"}]"; fi
    printf '{"plan_id":"%s","chain_verified":%s,"events":[%s],"egress_denials":%s}\n' "$(plan_of "${n}")" "${verified}" "${ev}" "${den}" ;;
  *) echo "fake: unhandled: $*" >&2; exit 2 ;;
esac
S
chmod +x "${work}/mvmctl"

run() { # <mode> <env assignments...> -> output; the script's own exit status is returned
  local mode="$1"; shift
  rm -rf "${work:?}/state" "${work:?}/home"; mkdir -p "${work}/state" "${work}/home"
  env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE="${mode}" MVM_HOME="${work}/home" \
    WAIT_SECS=4 SETTLE_SECS=0 REQUEST_SECS=0 "$@" bash "${repo}/scripts/factory-edge-demo-live.sh" 2>&1
}
passes() { grep -c '^PASS ' <<<"$1"; }

out="$(run ok HYPERVISOR=hvf)" || fail "a correct hvf run failed: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" || fail "no pass line (hvf): ${out}"
grep -q '^NOTE a workload with no egress grant' <<<"${out}" || fail "the no-grant note was not printed: ${out}"
n="$(passes "${out}")"
out="$(run ok HYPERVISOR=firecracker)" || fail "a correct firecracker run failed: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" || fail "no pass line (firecracker): ${out}"
run ok HYPERVISOR=qemu >/dev/null && fail "an unsupported hypervisor was accepted"

bad() { # <mode> <what must be caught> <text the failure must name>
  local o; o="$(run "$1" HYPERVISOR=hvf)" && fail "$2: the run passed: ${o}"
  grep -q '^DEMO_RESULT=pass$' <<<"${o}" && fail "$2: printed a pass line"
  grep -qF "$3" <<<"${o}" || fail "$2: failed, but not for the expected reason ($3): ${o}"
  return 0
}
bad request-not-refused "the unapproved request succeeded" "was not refused"
bad no-denial "the host recorded no denial" "no recorded denial naming"
bad not-host-entry "the denial is not a host.flow.denied entry" "not a host.flow.denied"
bad denial-on-inspection "an inspection workload has a denial" "refusal was not scoped"
bad line-short "an inspection workload did not finish its work" "printed 3 of 6 lines"
bad chain-broken "the audit chain did not verify" "did not verify"
bad audit-fails "trust audit verify failed" "mvmctl trust audit verify failed"
bad never-stops "the suspect workload never stopped" "did not reach stopped"
bad no-seal "the suspect's session was not sealed" "session was not sealed"
bad replacement-inherits "the replacement inherited the suspect's denials" "inherited the suspect's denials"
bad same-plan "the replacement reused the suspect's plan" "did not get a new plan"
out="$(run needs-bootstrap HYPERVISOR=hvf)" && fail "an install that needs bootstrap passed"
grep -q "^FINDING: the install asked for 'mvmctl bootstrap'" <<<"${out}" || fail "no bootstrap finding: ${out}"

echo "ok ($n checks per run)"
