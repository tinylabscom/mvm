#!/usr/bin/env bash
# Hermetic test of factory-edge-demo-live.sh. A fake mvmctl models the cached
# image, the warm standby pool (plain and egress-capable), per-machine status,
# the egress denials the host records, plans and sessions, so the runbook's own
# logic is checked without booting anything: it must pass when the product
# behaves and fail for each way the product could misbehave. This proves the
# script, not the product; a live run proves the product.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "${work}/mvmctl" <<'S'
#!/usr/bin/env bash
# FAKE_MODE: ok | request-not-refused | no-denial | denial-on-inspection | line-short
#   | chain-broken | not-host-entry | replacement-inherits | same-plan | no-seal
#   | never-stops | audit-fails | needs-bootstrap | image-missing | pool-short
#   | inspection-cold | replacement-cold | maintenance-warm | prep-ran
st="${FAKE_STATE:?}"; mode="${FAKE_MODE:-ok}"; home="${MVM_HOME:?}"
[ "${1:-}" = --builder ] && shift 2
audit="${home}/audit/local.jsonl"
key() { printf '%s' "$1" | tr ':/' '__'; }
get() { cat "${st}/$1.$(key "$2")" 2>/dev/null || true; }
put() { printf '%s' "$3" > "${st}/$1.$(key "$2")"; }
pool_get() { cat "${st}/pool.$1" 2>/dev/null || echo 0; }
pool_add() { echo $(( $(pool_get "$1") + $2 )) > "${st}/pool.$1"; }
suspect_plan="sha256:p-suspect"
case "${1:-} ${2:-}" in
  "--version "*) echo "mvmctl fake" ;;
  "image ls") [ "${mode}" = image-missing ] || echo "docker.io/curlimages/curl:8.21.0  sha256:abc  now  36M" ;;
  "pool warm")
    shift 2; egress=0; n=1
    while [ $# -gt 0 ]; do case "$1" in --egress) egress=1 ;; --image) shift ;; [0-9]*) n="$1" ;; esac; shift; done
    [ "${mode}" = pool-short ] && n=0
    if [ "${egress}" = 1 ]; then pool_add egress "${n}"; else pool_add plain "${n}"; fi ;;
  "pool status")
    total=$(( $(pool_get plain) + $(pool_get egress) ))
    echo "Supervisor standby pool: ${total} idle, 0 claimed, 0 parked, 0 dead"
    for i in $(seq 1 "${total}"); do echo "  standby-${i} · idle · pid ${i} · 2 vcpu / 512 MiB"; done ;;
  "run "*|"run")
    shift; name=""; detach=0; tok=""; grant=0
    while [ $# -gt 0 ]; do case "$1" in --name) name="$2"; shift ;; -d) detach=1 ;; --caller-commitment) tok="$2"; shift ;; --allow-host) grant=1; shift ;; --) shift; break ;; esac; shift; done
    cmd="$*"
    [ "${mode}" = needs-bootstrap ] && { echo "Error: runtime not prepared; run \`mvmctl bootstrap\` first" >&2; exit 1; }
    [ "${mode}" = prep-ran ] && echo "[mvm] Preparing the workload kernel (first use only)..." >&2
    case "${cmd}" in
      *line-ok*) role=inspection; if [ -e "${st}/seen-a" ]; then label=b; else label=a; touch "${st}/seen-a"; fi ;;
      *replacement-ready*) role=replacement ;;
      *sleep*) role=suspect ;;
      *) if [ "${grant}" = 1 ]; then role=maintenance; else role=nogrant; fi ;;
    esac
    if [ -n "${name}" ]; then plan="sha256:p-${name}"; ident="${name}"; else plan="sha256:p-${tok}"; ident="unnamed-${tok:0:6}"; fi
    [ "${role}" = suspect ] && plan="${suspect_plan}"
    [ "${mode}" = same-plan ] && [ "${role}" = replacement ] && plan="${suspect_plan}"
    # the start mode: a named run boots cold, MVM_RESIDENCY=cold forces cold, else claim a standby of its shape
    if [ -n "${name}" ]; then sm=none
    elif [ "${MVM_RESIDENCY:-}" = cold ] && [ "${mode}" != maintenance-warm ]; then sm=cold
    elif [ "${mode}" = inspection-cold ] && [ "${role}" = inspection ]; then sm=cold
    elif [ "${mode}" = replacement-cold ] && [ "${role}" = replacement ]; then sm=cold
    else
      shape=plain; [ "${grant}" = 1 ] && shape=egress
      if [ "$(pool_get "${shape}")" -gt 0 ]; then echo $(( $(pool_get "${shape}") - 1 )) > "${st}/pool.${shape}"; sm=warm; else sm=cold; fi
    fi
    put role "${plan}" "${role}"; put sm "${plan}" "${sm}"; put label "${plan}" "${label:-}"
    mkdir -p "${home}/audit"
    [ -z "${tok}" ] || echo "{\"entry\":{\"plan_id\":\"${plan}\",\"event\":\"plan.admitted\",\"image_name\":\"${ident}\",\"labels\":{\"c\":\"${tok}\"}}}" >> "${audit}"
    if [ "${detach}" = 1 ]; then echo running > "${st}/status.${name}"; echo "started machine ${name}"; exit 0; fi
    touch "${st}/exited.$(key "${plan}")"
    case "${role}" in
      inspection) n=6; [ "${mode}" = line-short ] && n=3; for i in $(seq 1 "${n}"); do echo "line-ok ${i}"; done ;;
      maintenance|nogrant) if [ "${mode}" = request-not-refused ] && [ "${role}" = maintenance ]; then echo "curl_rc=0"; else echo "curl: (6) Could not resolve host"; echo "curl_rc=6"; fi ;;
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
    role="$(get role "${plan}")"; sm="$(get sm "${plan}")"
    ev='{"event":"plan.admitted","labels":{}}'
    [ "${sm}" = none ] || ev="${ev},{\"event\":\"plan.start_mode\",\"labels\":{\"mode\":\"${sm}\"}}"
    [ -e "${st}/exited.$(key "${plan}")" ] && ev="${ev},{\"event\":\"plan.exited\",\"labels\":{}}"
    [ -e "${st}/sealed.$(key "${plan}")" ] && ev="${ev},{\"event\":\"session.sealed\",\"labels\":{}}"
    verified=true; [ "${mode}" = chain-broken ] && verified=false
    has=0
    case "${role}" in
      maintenance|suspect) [ "${mode}" = no-denial ] || has=1 ;;
      inspection) [ "$(get label "${plan}")" = a ] && [ "${mode}" = denial-on-inspection ] && has=1 ;;
      replacement) [ "${mode}" = replacement-inherits ] && has=1 ;;
    esac
    den='[]'
    if [ "${has}" = 1 ]; then e=host.flow.denied; [ "${mode}" = not-host-entry ] && e=other.event; den="[{\"destination\":\"example.com:443\",\"event\":\"${e}\",\"reason\":\"policy_denied\"}]"; fi
    printf '{"plan_id":"%s","chain_verified":%s,"events":[%s],"egress_denials":%s}\n' "${plan}" "${verified}" "${ev}" "${den}" ;;
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
grep -q '^NOTE the maintenance workload booted cold on purpose' <<<"${out}" || fail "the cold-maintenance note was not printed: ${out}"
grep -q 'both inspection workloads claimed a warm standby' <<<"${out}" || fail "warm claims were not checked: ${out}"
grep -q 'the replacement claimed a warm standby' <<<"${out}" || fail "the warm replacement was not checked: ${out}"
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
bad inspection-cold "an inspection workload booted cold" "did not claim a warm standby"
bad replacement-cold "the replacement booted cold" "replacement did not claim a warm standby"
bad maintenance-warm "the maintenance workload claimed a standby" "meant to boot cold"
bad pool-short "the pool had too few standbys" "idle standbys after warming"
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
