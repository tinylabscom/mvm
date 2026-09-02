#!/usr/bin/env bash
# Source this (do not execute it) before a cargo build that links binaries on
# macOS. Takes the workspace root as $1.
#
# Some pinned macOS nightlies ship rust-objcopy with an RPATH relative to its
# rustlib bin directory even though libLLVM lives at the sysroot's lib
# directory. rustc's strip step then aborts with SIGABRT and only warns, so the
# build succeeds while emitting larger, unstripped binaries behind a wall of
# "Library not loaded: @rpath/libLLVM.dylib" noise.
#
# Exporting the loader path from the calling shell is not enough on its own:
# SIP strips every DYLD_* variable across an exec of a protected binary, and
# the wrapper's own `#!/usr/bin/env bash` shebang is one. That is why the
# wrapper re-derives the path itself rather than trusting what it inherits.
# Build scripts are sibling processes launched by Cargo, while compiler helpers
# inherit from rustc, so seed the parent for the first case and use the wrapper
# for the second; either half alone leaves some rust-objcopy invocations unable
# to load libLLVM.

if [[ "$(uname -s)" != "Darwin" ]]; then
  return 0 2>/dev/null || exit 0
fi

_mvm_workspace_root="$1"
_mvm_rust_channel="$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' "${_mvm_workspace_root}/rust-toolchain.toml")"
_mvm_rust_sysroot="$(rustup run "${_mvm_rust_channel}" rustc --print sysroot)"
if [[ -n "${DYLD_FALLBACK_LIBRARY_PATH:-}" ]]; then
  export DYLD_FALLBACK_LIBRARY_PATH="${_mvm_rust_sysroot}/lib:${DYLD_FALLBACK_LIBRARY_PATH}"
else
  export DYLD_FALLBACK_LIBRARY_PATH="${_mvm_rust_sysroot}/lib"
fi
export RUSTC_WRAPPER="${_mvm_workspace_root}/scripts/rustc-macos-loader.sh"
unset _mvm_workspace_root _mvm_rust_channel _mvm_rust_sysroot
