#!/usr/bin/env bash
#
# Gate tests for the mvm_run blind-retry guard in scripts/dev-env.sh.
#
# The guard exists to stop one specific failure: re-issuing an identical
# command right after it failed, which transcript analysis showed in 30% of
# sampled Kimi sessions and 18% of Codex sessions (one session re-ran the
# same failing command 16 times in a row). Each re-run has a predictable
# outcome and burns time and context.
#
# Each case runs in a subshell with dev_state_root redirected to a temp dir
# so no test pollutes the worktree's real .mvm-test state.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

failures=0

# run_mvm <state-dir> <cmd...> — sources dev-env.sh in a subshell, points
# dev_state_root at the given dir, then runs mvm_run. Prints "<rc>\t<stderr>".
run_mvm() {
    local state_dir="$1"
    shift
    MVM_STATE_DIR="${state_dir}" bash -c '
        source scripts/dev-env.sh
        dev_state_root="${MVM_STATE_DIR}"
        mvm_run "$@" 2>"${MVM_STATE_DIR}/stderr.tmp"
        printf "%s" "$?" > "${MVM_STATE_DIR}/rc.tmp"
    ' _ "$@"
    printf "%s\t" "$(cat "${state_dir}/rc.tmp")"
    cat "${state_dir}/stderr.tmp"
}

ok=0
check() {
    local desc="$1" want_rc="$2" want_guard="$3" got
    got="$4"
    local got_rc="${got%%$'\t'*}" got_err="${got##*$'\t'}"
    if [ "${got_rc}" = "${want_rc}" ]; then
        case "${got_err}" in
            *mvm_run:*) has_guard=1 ;;
            *) has_guard=0 ;;
        esac
        if [ "${has_guard}" = "${want_guard}" ]; then
            printf 'ok   %s\n' "${desc}"
            ok=$((ok + 1))
            return 0
        fi
    fi
    printf 'FAIL %s\n     want rc=%s guard=%s\n     got  rc=%s stderr=%s\n' \
        "${desc}" "${want_rc}" "${want_guard}" "${got_rc}" "${got_err}"
    failures=$((failures + 1))
}

# A succeeding command passes through with rc 0 and leaves no marker.
s1="${TMP}/success"; mkdir -p "${s1}"
check "succeeding command runs and leaves no marker" 0 0 \
    "$(run_mvm "${s1}" true)"
[ ! -f "${s1}/last-failed-cmd" ] || { echo "FAIL: marker exists after success"; failures=$((failures + 1)); }

# A failing command passes its rc through and records the marker.
s2="${TMP}/fail-once"; mkdir -p "${s2}"
check "failing command runs (rc passthrough) and records marker" 3 0 \
    "$(run_mvm "${s2}" sh -c 'exit 3')"
marker="$(cat "${s2}/last-failed-cmd")"
case "${marker}" in
    ""|*"exit 3"*) echo "FAIL: marker content '${marker}'"; failures=$((failures + 1)) ;;
esac

# The identical command is refused: rc 1, guard message, original not re-run.
check "identical re-run is refused with guard message" 1 1 \
    "$(run_mvm "${s2}" sh -c 'exit 3')"

# A different command after a failure is allowed to run.
check "different command after failure is allowed" 0 0 \
    "$(run_mvm "${s2}" true)"
[ ! -f "${s2}/last-failed-cmd" ] || { echo "FAIL: marker not cleared by success"; failures=$((failures + 1)); }

# After a success, the previously-failing identical command may run again.
check "after a success the same command may run again" 4 0 \
    "$(run_mvm "${s2}" sh -c 'exit 4')"

# Arguments are compared verbatim: same binary, different args, is allowed.
s3="${TMP}/args"; mkdir -p "${s3}"
run_mvm "${s3}" sh -c 'exit 5' >/dev/null || true
check "distinct argv with the same joined string is allowed" 0 0 \
    "$(run_mvm "${s3}" sh -c exit 5)"

# Secret-bearing invocations are fingerprinted and redacted.
s4="${TMP}/secret"; mkdir -p "${s4}"
secret_value="top-secret-token"
run_mvm "${s4}" sh -c 'exit 9' -- "${secret_value}" >/dev/null || true
secret_retry="$(run_mvm "${s4}" sh -c 'exit 9' -- "${secret_value}")"
case "$(cat "${s4}/last-failed-cmd")" in
    *"${secret_value}"*) echo "FAIL: secret leaked into marker"; failures=$((failures + 1)) ;;
esac
case "${secret_retry}" in
    *"${secret_value}"*) echo "FAIL: secret leaked into guard output"; failures=$((failures + 1)) ;;
esac
check "secret-bearing retry is refused without echoing the secret" 1 1 \
    "${secret_retry}"

if [ "${failures}" -gt 0 ]; then
    printf '%d gate test(s) failed\n' "${failures}" >&2
    exit 1
fi
printf 'all dev-run-guard tests passed (%d checks)\n' "${ok}"
