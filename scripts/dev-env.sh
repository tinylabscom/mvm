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
