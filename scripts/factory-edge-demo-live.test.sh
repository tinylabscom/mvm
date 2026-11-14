#!/usr/bin/env bash
# Hermetic test of the factory-edge demo: factory-edge-stage.sh, which starts the
# workloads ahead of time, and factory-edge-demo-live.sh, which observes them. A
# fake mvmctl models the cached image, the staged machines and their status, the
# lookups and refusals the host records in its audit chain, plans and sessions,
# so the runbooks' own logic is checked without booting anything: they must pass
# when the product behaves and fail, for the named reason, for each way it could
# misbehave. This proves the scripts, not the product; a live run proves the
# product.
#
# It also holds the presentation rule: the output an audience sees shows one
# launch path and carries no caveat, so a passing run may not print a NOTE or
# mention a standby.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "${work}/mvmctl" <<'S'
#!/usr/bin/env bash
# FAKE_MODE: ok | image-missing | never-running | stage-no-work | prep-ran | needs-bootstrap
#   | no-refusal | denial-on-inspection | chain-broken | audit-fails | never-stops | no-seal
#   | replacement-inherits | same-plan | inspection-silent | inspection-stops-after-refusal
st="${FAKE_STATE:?}"; mode="${FAKE_MODE:-ok}"; home="${MVM_HOME:?}"
[ "${1:-}" = --builder ] && shift 2
chain="${home}/audit/local.jsonl"
ts() { python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc) + timedelta(seconds=${1:-1})).isoformat())"; }
key() { printf '%s' "$1" | tr ':/' '__'; }
role_of() { case "$1" in fe-line-a-*) echo line-a ;; fe-line-b-*) echo line-b ;; fe-maint-*) echo maint ;; *) echo other ;; esac; }
emit() { # <event> <vm> <labels-json>
  mkdir -p "${home}/audit"
  printf '{"entry":{"event":"%s","timestamp":"%s","plan_id":"sha256:p-%s","image_name":"%s","labels":%s}}\n' "$1" "$(ts 0)" "$2" "$2" "$3" >> "${chain}"
}
machines() { for f in "${st}"/m.*; do [ -e "$f" ] || continue; echo "${f##*/m.}"; done; }
case "${1:-} ${2:-}" in
  "--version "*) echo "mvmctl fake" ;;
  "image ls") [ "${mode}" = image-missing ] || echo "docker.io/curlimages/curl:8.21.0  sha256:abc  now  36M" ;;
  "run "*|"run")
    shift; name=""; detach=0; tok=""; grant=""
    while [ $# -gt 0 ]; do case "$1" in --name) name="$2"; shift ;; -d) detach=1 ;; --caller-commitment) tok="$2"; shift ;; --allow-host) grant="$2"; shift ;; --) shift; break ;; esac; shift; done
    [ "${mode}" = needs-bootstrap ] && { echo "Error: runtime not prepared; run \`mvmctl bootstrap\` first" >&2; exit 1; }
    [ "${mode}" = prep-ran ] && echo "[mvm] Preparing the workload kernel (first use only)..." >&2
    if [ "${detach}" = 1 ]; then
      [ "${mode}" = never-running ] && echo created > "${st}/m.${name}" || echo running > "${st}/m.${name}"
      case "$(role_of "${name}")" in
        maint) [ "${mode}" = no-refusal ] || emit dns.refused "${name}" "{\"vm_name\":\"${name}\",\"qname\":\"example.com\",\"qtype\":\"AAAA\",\"reason\":\"policy_denied\"}" ;;
        line-*) [ "${mode}" = stage-no-work ] || emit dns.resolved "${name}" "{\"vm_name\":\"${name}\",\"qname\":\"${grant%%:*}\",\"qtype\":\"AAAA\"}" ;;
      esac
      echo "started machine ${name}"; exit 0
    fi
    # a transient run bound to a token: the replacement
    mkdir -p "${home}/audit"
    plan="sha256:p-${tok}"; [ "${mode}" = same-plan ] && plan="$(cat "${st}/maint-plan" 2>/dev/null || echo sha256:p-x)"
    printf '{"entry":{"event":"plan.admitted","timestamp":"%s","plan_id":"%s","image_name":"unnamed","labels":{"c":"%s"}}}\n' "$(ts 0)" "${plan}" "${tok}" >> "${chain}"
    echo "replacement-ready" ;;
  "machine ls")
    echo "NAME KIND STATUS HEALTH BACKEND"
    for m in $(machines); do
      echo "${m} persistent $(cat "${st}/m.${m}") - hvf"
    done ;;
  "__tick "*|"__tick")
    # a running inspection workload keeps working: the host records another lookup
    [ "${mode}" = stage-no-work ] || [ "${mode}" = inspection-silent ] && exit 0
    for m in $(machines); do
      [ "$(cat "${st}/m.${m}")" = running ] || continue
      case "$(role_of "${m}")" in line-a|line-b) emit dns.resolved "${m}" "{\"vm_name\":\"${m}\",\"qname\":\"pypi.org\",\"qtype\":\"AAAA\"}" ;; esac
    done ;;
  "machine stop")
    n="$3"; [ "${mode}" = never-stops ] || echo stopped > "${st}/m.${n}"
    [ "${mode}" = no-seal ] || touch "${st}/sealed.${n}"
    echo "sha256:p-${n}" > "${st}/maint-plan" ;;
  "machine rm") rm -f "${st}/m.$3" "${st}/sealed.$3" ;;
  "trust audit") [ "${mode}" = audit-fails ] && { echo "TAMPERED" >&2; exit 1; }; echo "VERIFIED chain: 7 entries, 1 session, 1 seal" ;;
  "explain "*)
    ref="$2"; role="$(role_of "${ref}")"; plan="sha256:p-${ref}"
    ev='{"event":"plan.admitted","timestamp":"2026-01-01T00:00:01Z","labels":{}}'
    [ -e "${st}/sealed.${ref}" ] && ev="${ev},{\"event\":\"session.sealed\",\"timestamp\":\"2026-01-01T00:00:30Z\",\"labels\":{}}"
    verified=true; [ "${mode}" = chain-broken ] && verified=false
    seen="2026-01-01T00:00:10Z"; [ "${mode}" = inspection-stops-after-refusal ] && seen="2999-01-01T00:00:10Z"
    has=0
    case "${role}" in
      maint) [ "${mode}" = no-refusal ] || has=1 ;;
      line-a) [ "${mode}" = denial-on-inspection ] && has=1 ;;
      other) [ "${mode}" = replacement-inherits ] && has=1 ;;
    esac
    den='[]'
    [ "${has}" = 1 ] && den="[{\"destination\":\"DNS lookup of example.com\",\"event\":\"dns.refused\",\"reason\":\"policy_denied\",\"first_seen\":\"${seen}\"}]"
    printf '{"plan_id":"%s","chain_verified":%s,"events":[%s],"egress_denials":%s}\n' "${plan}" "${verified}" "${ev}" "${den}" ;;
  *) echo "fake: unhandled: $*" >&2; exit 2 ;;
esac
S
chmod +x "${work}/mvmctl"

fresh() { rm -rf "${work:?}/state" "${work:?}/home"; mkdir -p "${work}/state" "${work}/home"; }
envrun() { # <mode> <script> <env assignments...>: the script runs while a ticker models ongoing work
  local mode="$1" script="$2" rc tick; shift 2
  ( while :; do env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE="${mode}" MVM_HOME="${work}/home" "${work}/mvmctl" __tick >/dev/null 2>&1 || true; sleep 0.1; done ) &
  tick=$!
  env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE="${mode}" MVM_HOME="${work}/home" \
    WAIT_SECS=3 ATTEMPT_AFTER=0 "$@" bash "${repo}/scripts/${script}" 2>&1; rc=$?
  kill "${tick}" 2>/dev/null; wait "${tick}" 2>/dev/null || true
  return "${rc}"
}
stage() { envrun "$1" factory-edge-stage.sh "${@:2}"; }
demo() { envrun "$1" factory-edge-demo-live.sh "${@:2}"; }
both() { # <stage-mode> <demo-mode>: a fresh home, staged, then the demo
  fresh; local o
  o="$(stage "$1" HYPERVISOR=hvf)" || { printf '%s\n' "${o}"; return 1; }
  demo "$2" HYPERVISOR=hvf
}

# ---- the staging script ----
fresh
out="$(stage ok HYPERVISOR=hvf)" || fail "a correct staging failed: ${out}"
grep -q '^STAGED:' <<<"${out}" || fail "staging did not report STAGED: ${out}"
[ "$(ls "${work}"/state/m.* | wc -l | tr -d ' ')" = 3 ] || fail "staging did not start three machines"
out2="$(stage ok HYPERVISOR=hvf)" || fail "staging twice failed: ${out2}"
[ "$(ls "${work}"/state/m.* | wc -l | tr -d ' ')" = 3 ] || fail "a second staging left more than three machines (it must replace the earlier one)"
out3="$(env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE=ok MVM_HOME="${work}/home" HYPERVISOR=hvf bash "${repo}/scripts/factory-edge-stage.sh" --down 2>&1)"
[ "$(ls "${work}"/state/m.* 2>/dev/null | wc -l | tr -d ' ')" = 0 ] || fail "--down did not remove the staged machines: ${out3}"

bad_stage() { # <mode> <what must be caught> <text the failure must name>
  fresh; local o; o="$(stage "$1" HYPERVISOR=hvf)" && fail "$2: staging passed: ${o}"
  grep -qF "$3" <<<"${o}" || fail "$2: failed, but not for the expected reason ($3): ${o}"
}
bad_stage image-missing "the image was not cached" "is not cached"
bad_stage never-running "a workload never ran" "to be running"
bad_stage stage-no-work "an inspection workload did no work" "to record"
out="$(fresh; stage prep-ran HYPERVISOR=hvf)" && fail "staging that prepared its runtime passed"
grep -q '^FINDING: install-time preparation ran while staging' <<<"${out}" || fail "install-time preparation was not reported: ${out}"
rm -rf "${work}/home2"
out="$(env MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" MVM_HOME="${work}/home2" HYPERVISOR=hvf bash "${repo}/scripts/factory-edge-stage.sh" 2>&1)" && fail "a missing demo home passed staging"
grep -q 'does not exist' <<<"${out}" || fail "a missing demo home was not reported: ${out}"
[ ! -e "${work}/home2" ] || fail "staging created the demo home it was meant to find prepared"

# ---- the demo script ----
out="$(both ok ok)" || fail "a correct staged demo failed: ${out}"
grep -q '^DEMO_RESULT=pass$' <<<"${out}" || fail "no pass line: ${out}"
grep -q '^demo completed in [0-9]*s$' <<<"${out}" || fail "the elapsed time was not reported: ${out}"
grep -q '^NOTE' <<<"${out}" && fail "a passing run printed a caveat line: ${out}"
grep -qi 'standby\|cold\|warm' <<<"${out}" && fail "a passing run showed more than one launch path: ${out}"
n="$(grep -c '^PASS ' <<<"${out}")"
fresh; out="$(demo ok HYPERVISOR=hvf)" && fail "the demo ran with nothing staged: ${out}"
grep -q 'stage them first' <<<"${out}" || fail "an unstaged demo did not say to stage first: ${out}"
envrun ok factory-edge-demo-live.sh HYPERVISOR=qemu >/dev/null && fail "an unsupported hypervisor was accepted"

bad() { # <demo-mode> <what must be caught> <text the failure must name>
  local o; o="$(both ok "$1")" && fail "$2: the run passed: ${o}"
  grep -q '^DEMO_RESULT=pass$' <<<"${o}" && fail "$2: printed a pass line"
  grep -qF "$3" <<<"${o}" || fail "$2: failed, but not for the expected reason ($3): ${o}"
  return 0
}
bad inspection-silent "an inspection workload stopped working" "to look up its granted destination"
bad no-refusal "explain does not show a refusal the chain holds" "explain shows no recorded refusal"
o="$(both no-refusal ok)" && fail "the host recorded no refusal: the run passed: ${o}"
grep -qF "to record a refusal" <<<"${o}" || fail "a refusal missing from the chain was not reported: ${o}"
bad denial-on-inspection "an inspection workload has a refusal" "refusal was not scoped"
bad inspection-stops-after-refusal "an inspection workload stopped at the refusal" "after the refusal"
bad chain-broken "the audit chain did not verify" "did not verify"
bad audit-fails "trust audit verify failed" "mvmctl trust audit verify failed"
bad never-stops "the suspect workload never stopped" "to stop"
bad no-seal "the suspect's session was not sealed" "was not sealed"
bad replacement-inherits "the replacement inherited refusals" "inherited the suspect's refusals"
bad same-plan "the replacement reused the suspect's plan" "did not get a new plan"
out="$(fresh; stage ok HYPERVISOR=hvf >/dev/null; demo prep-ran HYPERVISOR=hvf)" && fail "a demo that prepared its runtime passed"
grep -q '^FINDING: install-time preparation ran during the demo' <<<"${out}" || fail "install-time preparation was not reported: ${out}"
out="$(fresh; stage ok HYPERVISOR=hvf >/dev/null; demo needs-bootstrap HYPERVISOR=hvf)" && fail "an install that needs bootstrap passed"
grep -q "^FINDING: the install asked for 'mvmctl bootstrap'" <<<"${out}" || fail "no bootstrap finding"

echo "ok ($n checks per run)"
