#!/usr/bin/env bash
# Hermetic test of factory-edge-demo-live.sh. A fake mvmctl models the cached
# image, per-machine status, the egress denials the host records, plans,
# sessions and their timestamps, so the runbook's own logic is checked without
# booting anything: it must pass when the product behaves and fail for each way
# the product could misbehave. This proves the script, not the product; a live
# run proves the product.
#
# It also holds the demo's presentation rule: the output an audience sees shows
# one launch path and carries no caveat, so a passing run may not print a NOTE or
# mention a standby.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "${work}/mvmctl" <<'S'
#!/usr/bin/env bash
# FAKE_MODE: ok | request-not-refused | no-denial | suspect-no-denial | denial-on-inspection
#   | line-short | chain-broken | not-host-entry | replacement-inherits | same-plan
#   | no-seal | never-stops | audit-fails | needs-bootstrap | image-missing
#   | inspection-ends-first | prep-ran
st="${FAKE_STATE:?}"; mode="${FAKE_MODE:-ok}"; home="${MVM_HOME:?}"
[ "${1:-}" = --builder ] && shift 2
audit="${home}/audit/local.jsonl"
key() { printf '%s' "$1" | tr ':/' '__'; }
get() { cat "${st}/$1.$(key "$2")" 2>/dev/null || true; }
put() { printf '%s' "$3" > "${st}/$1.$(key "$2")"; }
suspect_plan="sha256:p-suspect"
case "${1:-} ${2:-}" in
  "--version "*) echo "mvmctl fake" ;;
  "image ls") [ "${mode}" = image-missing ] || echo "docker.io/curlimages/curl:8.21.0  sha256:abc  now  36M" ;;
  "run "*|"run")
    shift; name=""; detach=0; tok=""
    while [ $# -gt 0 ]; do case "$1" in --name) name="$2"; shift ;; -d) detach=1 ;; --caller-commitment) tok="$2"; shift ;; --allow-host) shift ;; --) shift; break ;; esac; shift; done
    cmd="$*"
    [ "${mode}" = needs-bootstrap ] && { echo "Error: runtime not prepared; run \`mvmctl bootstrap\` first" >&2; exit 1; }
    [ "${mode}" = prep-ran ] && echo "[mvm] Preparing the workload kernel (first use only)..." >&2
    case "${cmd}" in
      *line-ok*) role=inspection; if [ -e "${st}/seen-a" ]; then label=b; else label=a; touch "${st}/seen-a"; fi ;;
      *replacement-ready*) role=replacement ;;
      *sleep*) role=suspect ;;
      *) role=maintenance ;;
    esac
    if [ -n "${name}" ]; then plan="sha256:p-${name}"; ident="${name}"; else plan="sha256:p-${tok}"; ident="unnamed-${tok:0:6}"; fi
    [ "${role}" = suspect ] && plan="${suspect_plan}"
    [ "${mode}" = same-plan ] && [ "${role}" = replacement ] && plan="${suspect_plan}"
    put role "${plan}" "${role}"; put label "${plan}" "${label:-}"
    mkdir -p "${home}/audit"
    [ -z "${tok}" ] || echo "{\"entry\":{\"plan_id\":\"${plan}\",\"event\":\"plan.admitted\",\"image_name\":\"${ident}\",\"labels\":{\"c\":\"${tok}\"}}}" >> "${audit}"
    if [ "${detach}" = 1 ]; then echo running > "${st}/status.${name}"; echo "started machine ${name}"; exit 0; fi
    touch "${st}/exited.$(key "${plan}")"
    case "${role}" in
      inspection) n=6; [ "${mode}" = line-short ] && n=3; for i in $(seq 1 "${n}"); do echo "line-ok ${i}"; done ;;
      maintenance) if [ "${mode}" = request-not-refused ]; then echo "curl_rc=0"; else echo "curl: (6) Could not resolve host"; echo "curl_rc=6"; fi ;;
      replacement) echo "replacement-ready" ;;
    esac ;;
  "machine ls") echo "NAME KIND STATUS HEALTH BACKEND"; for f in "${st}"/status.*; do [ -e "$f" ] || continue; echo "${f##*/status.} persistent $(cat "$f") - hvf"; done ;;
  "machine stop")
    n="$3"; [ "${mode}" = never-stops ] || echo stopped > "${st}/status.${n}"
    [ "${mode}" = no-seal ] || touch "${st}/sealed.$(key "${suspect_plan}")" ;;
  "machine rm") ;;
  "trust audit") [ "${mode}" = audit-fails ] && { echo "TAMPERED" >&2; exit 1; }; echo "VERIFIED chain: 7 entries, 1 session, 1 seal" ;;
  "explain "*)
    ref="$2"; case "${ref}" in sha256:p-*) plan="${ref}" ;; fe-suspect-*) plan="${suspect_plan}" ;; *) plan="sha256:p-${ref}" ;; esac
    role="$(get role "${plan}")"
    ended="2026-01-01T00:00:20Z"; [ "${mode}" = inspection-ends-first ] && [ "${role}" = inspection ] && ended="2026-01-01T00:00:05Z"
    ev='{"event":"plan.admitted","timestamp":"2026-01-01T00:00:01Z","labels":{}}'
    [ -e "${st}/exited.$(key "${plan}")" ] && ev="${ev},{\"event\":\"plan.exited\",\"timestamp\":\"${ended}\",\"labels\":{}}"
    [ -e "${st}/sealed.$(key "${plan}")" ] && ev="${ev},{\"event\":\"session.sealed\",\"timestamp\":\"${ended}\",\"labels\":{}}"
    verified=true; [ "${mode}" = chain-broken ] && verified=false
    has=0
    case "${role}" in
      maintenance) [ "${mode}" = no-denial ] || has=1 ;;
      suspect) [ "${mode}" = no-denial ] || [ "${mode}" = suspect-no-denial ] || has=1 ;;
      inspection) [ "$(get label "${plan}")" = a ] && [ "${mode}" = denial-on-inspection ] && has=1 ;;
      replacement) [ "${mode}" = replacement-inherits ] && has=1 ;;
    esac
    den='[]'
    if [ "${has}" = 1 ]; then e=host.flow.denied; [ "${mode}" = not-host-entry ] && e=other.event; den="[{\"destination\":\"example.com:443\",\"event\":\"${e}\",\"reason\":\"policy_denied\",\"first_seen\":\"2026-01-01T00:00:10Z\"}]"; fi
    printf '{"plan_id":"%s","chain_verified":%s,"events":[%s],"egress_denials":%s}\n' "${plan}" "${verified}" "${ev}" "${den}" ;;
  *) echo "fake: unhandled: $*" >&2; exit 2 ;;
esac
S
chmod +x "${work}/mvmctl"

run() { # <mode> <env assignments...> -> output; the script's own exit status is returned
  local mode="$1"; shift
  rm -rf "${work:?}/state" "${work:?}/home"; mkdir -p "${work}/state" "${work}/home"
  env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE="${mode}" MVM_HOME="${work}/home" \
    WAIT_SECS=3 "$@" bash "${repo}/scripts/factory-edge-demo-live.sh" 2>&1
}
passes() { grep -c '^PASS ' <<<"$1"; }

out="$(run ok HYPERVISOR=hvf)" || fail "a correct hvf run failed: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" || fail "no pass line (hvf): ${out}"
grep -q '^demo completed in [0-9]*s$' <<<"${out}" || fail "the elapsed time was not reported: ${out}"
grep -q '^NOTE' <<<"${out}" && fail "a passing run printed a caveat line: ${out}"
grep -qi 'standby\|cold\|warm' <<<"${out}" && fail "a passing run showed more than one launch path: ${out}"
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
bad suspect-no-denial "the suspect's refusal was never recorded" "refusal was never recorded"
bad not-host-entry "the denial is not a host.flow.denied entry" "not a host.flow.denied"
bad denial-on-inspection "an inspection workload has a denial" "refusal was not scoped"
bad line-short "an inspection workload did not finish its work" "printed 3 of 6 lines"
bad inspection-ends-first "an inspection workload ended before the refusal" "was not working through it"
bad chain-broken "the audit chain did not verify" "did not verify"
bad audit-fails "trust audit verify failed" "mvmctl trust audit verify failed"
bad never-stops "the suspect workload never stopped" "waiting for the suspect workload to stop"
bad no-seal "the suspect's session was not sealed" "session was not sealed"
bad replacement-inherits "the replacement inherited the suspect's denials" "inherited the suspect's denials"
bad same-plan "the replacement reused the suspect's plan" "did not get a new plan"
bad image-missing "the image was not cached" "is not cached"
out="$(run needs-bootstrap HYPERVISOR=hvf)" && fail "an install that needs bootstrap passed"
grep -q "^FINDING: the install asked for 'mvmctl bootstrap'" <<<"${out}" || fail "no bootstrap finding: ${out}"
out="$(run prep-ran HYPERVISOR=hvf)" && fail "a run that prepared its runtime during the demo passed"
grep -q '^FINDING: install-time preparation ran during the demo' <<<"${out}" || fail "install-time preparation was not reported: ${out}"
rm -rf "${work}/home2"
out="$(env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" MVM_HOME="${work}/home2" HYPERVISOR=hvf bash "${repo}/scripts/factory-edge-demo-live.sh" 2>&1)" && fail "a missing demo home passed"
grep -q 'does not exist' <<<"${out}" || fail "a missing demo home was not reported: ${out}"
[ ! -e "${work}/home2" ] || fail "the run created the demo home it was meant to find prepared"

echo "ok ($n checks per run)"
