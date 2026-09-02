#!/usr/bin/env bash
#
# Gate tests for cargo-target-dir-guard.sh.
#
# The guard exists to stop one specific failure: cargo type-checking this
# tree against artifacts recycled from another source tree, which surfaces
# as an E0063 naming a field that exists in none of the sources being
# compiled. Both wrong answers are expensive. Reclaiming a deliberate
# override breaks a real choice and re-downloads gigabytes of cache;
# keeping an inherited value preserves the poisoning it exists to stop —
# the value is "almost never deliberate: it is left over from a shell that
# exported it in a different worktree" (scripts/dev-env.sh).
#
# Each case runs the guard in a subshell because it mutates the exported
# env; stderr is captured to assert the guard speaks up when it acts.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
GUARD="scripts/cargo-target-dir-guard.sh"

failures=0

# Runs the guard in a clean subshell and prints "<final>\t<warned>".
run_guard() {
    GUARD="${GUARD}" CARGO_TARGET_DIR="$1" bash -c '
        source "${GUARD}"
        if [ -n "${CARGO_TARGET_DIR:-}" ]; then
            printf "%s" "${CARGO_TARGET_DIR}"
        else
            printf "UNSET"
        fi
    ' 2>guard-stderr.tmp
    local stderr
    stderr=$(cat guard-stderr.tmp)
    rm -f guard-stderr.tmp
    case "${stderr}" in
        *cargo-target-dir-guard:*) printf "\t1" ;;
        *) printf "\t0" ;;
    esac
}

# check <description> <want final value> <want warned 0|1> <inherited value>
check() {
    local desc="$1" want_value="$2" want_warn="$3" inherit="$4"
    local got_value got_warn
    local outcome
    outcome=$(run_guard "${inherit}")
    got_value="${outcome%%$'\t'*}"
    got_warn="${outcome##*$'\t'}"

    if [ "${got_value}" = "${want_value}" ] && [ "${got_warn}" = "${want_warn}" ]; then
        printf 'ok   %s\n' "${desc}"
    else
        printf 'FAIL %s\n     want value=%s warn=%s\n     got  value=%s warn=%s\n' \
            "${desc}" "${want_value}" "${want_warn}" "${got_value}" "${got_warn}"
        failures=$((failures + 1))
    fi
}

# An unset variable is not claimed; nothing to reclaim.
outcome=$(GUARD="${GUARD}" bash -c '
    source "${GUARD}"
    if [ -n "${CARGO_TARGET_DIR:-}" ]; then printf "%s" "${CARGO_TARGET_DIR}"; else printf "UNSET"; fi
' 2>guard-stderr.tmp)
[ ! -s guard-stderr.tmp ] || { echo "FAIL: unset case must stay silent"; cat guard-stderr.tmp; failures=$((failures + 1)); }
rm -f guard-stderr.tmp
if [ "${outcome}" = "UNSET" ]; then
    printf 'ok   unset CARGO_TARGET_DIR stays unset and silent\n'
else
    printf 'FAIL unset CARGO_TARGET_DIR became %s\n' "${outcome}"
    failures=$((failures + 1))
fi

# A value already inside this worktree is a real override and is honored,
# including the dev-env state dir the worktree wrappers use.
check "target dir inside the worktree is honored" \
    "${ROOT}/target" 0 "${ROOT}/target"
check "worktree dev-env target dir is honored" \
    "${ROOT}/.mvm-test/target" 0 "${ROOT}/.mvm-test/target"

# Anything outside the tree is reclaimed, loudly: another worktree, a
# sibling shared dir, a relative path that resolves per-cwd.
check "another worktree's target dir is reclaimed" \
    "${ROOT}/target" 1 "/some/other/worktree/target"
check "sibling shared target dir is reclaimed" \
    "${ROOT}/target" 1 "/some/other/.target-shared"
check "relative target dir is reclaimed" \
    "${ROOT}/target" 1 ".target-relative"

# The escape hatch keeps the inherited value, still loudly.
outcome=$(GUARD="${GUARD}" MVM_DEV_ENV_KEEP_INHERITED=1 CARGO_TARGET_DIR="/some/other/target" bash -c '
    source "${GUARD}"
    printf "%s" "${CARGO_TARGET_DIR}"
' 2>guard-stderr.tmp)
stderr=$(cat guard-stderr.tmp)
rm -f guard-stderr.tmp
if [ "${outcome}" = "/some/other/target" ] && [ -n "${stderr}" ]; then
    printf 'ok   MVM_DEV_ENV_KEEP_INHERITED=1 keeps the inherited value, loudly\n'
else
    printf 'FAIL keep-inherited: got %s stderr=%s\n' "${outcome}" "${stderr}"
    failures=$((failures + 1))
fi

if [ "${failures}" -gt 0 ]; then
    printf '%d gate test(s) failed\n' "${failures}" >&2
    exit 1
fi
printf 'all cargo-target-dir-guard tests passed\n'
