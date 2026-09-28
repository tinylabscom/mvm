#!/usr/bin/env sh

if [ -n "${BASH_SOURCE:-}" ]; then
    dev_env_path="${BASH_SOURCE}"
elif [ -n "${ZSH_VERSION:-}" ]; then
    dev_env_path="${(%):-%N}"
else
    dev_env_path="$0"
fi

dev_env_dir=$(
    CDPATH= cd -- "$(dirname -- "$dev_env_path")" >/dev/null 2>&1 && pwd
)
repo_root=$(
    CDPATH= cd -- "${dev_env_dir}/.." >/dev/null 2>&1 && pwd
)
dev_state_root="${repo_root}/.mvm-test"

# Point one dev-env variable at this worktree, reclaiming it from another one.
#
# These were `${VAR:-default}`, which lets an inherited value win. That reads
# as deference to a deliberate override, but the value is almost never
# deliberate: it is left over from a shell that sourced this file in a
# *different* worktree, and `export` carries it into every child from then on.
# Two source trees then share one CARGO_TARGET_DIR, and cargo fingerprints
# embed absolute paths — so each alternation between the trees recompiles the
# whole workspace, and concurrent builds serialize on that one target dir's
# lock. Nothing reports this; the build is simply slow forever.
#
# A value already inside this worktree is honoured as-is (that is a real
# override). One pointing outside is reclaimed, loudly. Set
# MVM_DEV_ENV_KEEP_INHERITED=1 to keep it anyway.
_mvm_dev_env_claim() {
    _mvm_name="$1"
    _mvm_want="$2"
    eval "_mvm_have=\${${_mvm_name}:-}"

    if [ -z "${_mvm_have}" ] || [ "${_mvm_have}" = "${_mvm_want}" ]; then
        export "${_mvm_name}=${_mvm_want}"
        return 0
    fi

    case "${_mvm_have}" in
        "${repo_root}"/*)
            export "${_mvm_name}=${_mvm_have}"
            return 0
            ;;
    esac

    if [ -n "${MVM_DEV_ENV_KEEP_INHERITED:-}" ]; then
        printf 'dev-env: keeping inherited %s=%s (outside %s)\n' \
            "${_mvm_name}" "${_mvm_have}" "${repo_root}" >&2
        export "${_mvm_name}=${_mvm_have}"
        return 0
    fi

    printf 'dev-env: %s pointed outside this worktree (%s) — reclaiming to %s\n' \
        "${_mvm_name}" "${_mvm_have}" "${_mvm_want}" >&2
    export "${_mvm_name}=${_mvm_want}"
}

_mvm_dev_env_claim MVM_HOME "${dev_state_root}"
_mvm_dev_env_claim CARGO_TARGET_DIR "${dev_state_root}/target"
_mvm_dev_env_claim CARGO_HOME "${dev_state_root}/cargo"

export MVM_NO_LEGACY_BANNER="${MVM_NO_LEGACY_BANNER:-1}"

unset -f _mvm_dev_env_claim
unset _mvm_name _mvm_want _mvm_have

# Blind-retry guard. mvm_run <cmd...> runs the command; on failure it records a
# non-reversible argv fingerprint in .mvm-test/last-failed-cmd, and the next
# mvm_run of the identical argv is refused until the marker is cleared (by a
# successful different command, `rm .mvm-test/last-failed-cmd`, or editing the
# command). Re-running a failed command verbatim is the single largest
# observed agent inefficiency; this makes the failure visible and forces a
# diagnose-first step. Variables are _mvm_run_*-prefixed; no `local` so the
# file stays POSIX-sh sourceable.
_mvm_run_hash_stream() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r | awk '{print $1}'
    else
        cksum | awk '{print $1 "-" $2}'
    fi
}

_mvm_run_fingerprint() {
    (
        for _mvm_run_arg do
            _mvm_run_len=${#_mvm_run_arg}
            printf '%s\n%s\n' "${_mvm_run_len}" "${_mvm_run_arg}"
        done
    ) | _mvm_run_hash_stream
}

mvm_run() {
    _mvm_run_state="${dev_state_root}/last-failed-cmd"
    _mvm_run_key="$(_mvm_run_fingerprint "$@")"

    if [ -f "${_mvm_run_state}" ] && [ "$(cat "${_mvm_run_state}")" = "${_mvm_run_key}" ]; then
        printf 'mvm_run: refusing blind re-run of a command that just failed (fingerprint %s)\n' "${_mvm_run_key}" >&2
        printf 'mvm_run: diagnose the failure, change one thing, or clear the marker: rm %s\n' "${_mvm_run_state}" >&2
        return 1
    fi

    "$@"
    _mvm_run_rc=$?

    if [ "${_mvm_run_rc}" -ne 0 ]; then
        mkdir -p "${dev_state_root}"
        printf '%s' "${_mvm_run_key}" > "${_mvm_run_state}"
    else
        rm -f "${_mvm_run_state}"
    fi

    return "${_mvm_run_rc}"
}
