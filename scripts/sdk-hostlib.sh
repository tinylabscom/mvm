#!/usr/bin/env bash

# Build the in-process SDK host library beside the selected mvmctl and export
# the exact path used by the language SDKs. Callers source this file so the
# exported path remains in their environment.
build_sdk_hostlib() {
  local mvmctl_path="$1"
  local hostlib_ext="so"
  local hostlib_path

  echo "==> building the SDK host library beside mvmctl"
  cargo build -p mvm-hostlib
  if [[ "$(uname -s)" == "Darwin" ]]; then
    hostlib_ext="dylib"
  fi
  hostlib_path="$(dirname "$mvmctl_path")/libmvm_hostlib.${hostlib_ext}"
  if [[ ! -f "$hostlib_path" ]]; then
    echo "!!! expected host library at $hostlib_path, but it was not built." >&2
    return 1
  fi

  export MVM_HOSTLIB_PATH="$hostlib_path"
}
