# `just build-supervisors` strips its binaries again

`just embed` carried a macOS-only repair for a broken `rust-objcopy` RPATH in
the pinned nightly. `just build-supervisors` links the same `mvm-hostd`
binaries and did not, so every supervisor it produced was emitted unstripped
behind a page of `Library not loaded: @rpath/libLLVM.dylib` warnings.

The repair is now one sourceable script, `scripts/macos-objcopy-env.sh`, used
by both recipes. It is a no-op off Darwin. The prose that used to live inline
in `embed` moved into the script, along with the reason the two halves (parent
export for build scripts, `RUSTC_WRAPPER` for compiler helpers) are both
needed: SIP strips `DYLD_*` across the wrapper's own `#!/usr/bin/env bash`
shebang, so the wrapper has to re-derive the sysroot rather than inherit it.

Verified by A/B on identical cold builds into an empty `CARGO_TARGET_DIR`:
`-p libkrun-sys --release` emits 2 `libLLVM.dylib` warnings without the repair
and 0 with it, and a full `just build-supervisors --release` is clean.

Not changed, and worth a follow-up decision: `release-build` and
`release-build-target` are plain `cargo build --release` and hit the same
defect on a macOS host. They were left alone because setting `RUSTC_WRAPPER`
there displaces a globally configured `sccache`, which is a trade the release
lanes should make deliberately rather than inherit from this fix.
