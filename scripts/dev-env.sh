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

export MVM_HOME="${MVM_HOME:-${dev_state_root}}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${dev_state_root}/target}"
export CARGO_HOME="${CARGO_HOME:-${dev_state_root}/cargo}"
export MVM_NO_LEGACY_BANNER="${MVM_NO_LEGACY_BANNER:-1}"
