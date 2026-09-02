#!/usr/bin/env bash
set -euo pipefail

# Cargo constructs its own dynamic-library search path before it invokes the
# compiler, replacing a path exported by the parent shell. Add the toolchain's
# actual lib directory after Cargo has done that so rustc's rust-objcopy child
# can load libLLVM.dylib.
rustc_bin="$1"
shift
rust_sysroot="$("$rustc_bin" --print sysroot)"
existing_loader_path="${DYLD_FALLBACK_LIBRARY_PATH:-}"
if [[ -n "$existing_loader_path" ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="$rust_sysroot/lib:$existing_loader_path"
else
  export DYLD_FALLBACK_LIBRARY_PATH="$rust_sysroot/lib"
fi

exec "$rustc_bin" "$@"
