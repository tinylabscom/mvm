"""SDK environment-variable names, generated from `schema/sdk-env-v0.json`.

Do not edit `vars.py` by hand. The names are owned by the Rust registry
at `crates/mvm-sdk/src/env.rs`; to refresh after a change there, run
`cargo xtask gen-stubs` from the workspace root.
"""

from mvm._env.vars import (
    MVM_CLI_BIN_ENV,
    MVM_MACHINE_MAX_OUTPUT_ENV,
    MVM_MACHINE_TIMEOUT_ENV,
    MVM_SDK_MODE_ENV,
    MVM_SDK_OUT_PATH_ENV,
    MVM_SDK_RUN_PROFILE_ENV,
)

__all__ = [
    "MVM_CLI_BIN_ENV",
    "MVM_MACHINE_MAX_OUTPUT_ENV",
    "MVM_MACHINE_TIMEOUT_ENV",
    "MVM_SDK_MODE_ENV",
    "MVM_SDK_OUT_PATH_ENV",
    "MVM_SDK_RUN_PROFILE_ENV",
]
