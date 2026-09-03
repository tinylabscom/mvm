---
title: SIP strips DYLD_* before the rustc wrapper runs, so the loader path must be re-derived
date: 2026-09-02
tags: [macos, toolchain, build, justfile, falsification]
---

Some pinned macOS nightlies ship `rust-objcopy` with `LC_RPATH` of
`@loader_path/../lib`, resolving to `lib/rustlib/aarch64-apple-darwin/lib`,
while `libLLVM.dylib` actually lives at the sysroot's `lib/`. rustc's strip step
spawns it, dyld aborts with SIGABRT, and rustc only *warns* — so the build
succeeds and silently emits unstripped binaries.

Measured on this host (nightly-2026-08-25): `rust-objcopy --version` fails
bare and succeeds under either `DYLD_FALLBACK_LIBRARY_PATH=$sysroot/lib` or
`DYLD_LIBRARY_PATH=$sysroot/lib`. The library is present; only the search path
is wrong.

**Exporting the variable from the calling shell does nothing.** SIP strips every
`DYLD_*` variable across an exec of a protected binary, and
`scripts/rustc-macos-loader.sh` starts with `#!/usr/bin/env bash` — `/usr/bin/env`
is protected. Probed directly with a logging `RUSTC_WRAPPER`: a parent that
exported the path was observed as `UNSET` in all seven wrapper invocations. That
is *why* the wrapper re-derives the sysroot itself instead of trusting what it
inherits; the parent export covers build scripts, which Cargo launches as
siblings of rustc rather than children. Neither half is redundant.

Do not try to reproduce this in a scratch crate. A one-file `cargo new` with
`strip = true` on the release profile emits zero warnings with and without the
wrapper — the strip path that shells out to `rust-objcopy` is not reached. A/B
against a real workspace crate instead: `-p libkrun-sys --release` into an empty
`CARGO_TARGET_DIR` gives 2 warnings without the repair and 0 with it.

Reading the warnings is its own trap: Cargo replays cached diagnostic text from
units it did not rebuild. Two consecutive runs "after the fix" both showed
warnings that had already been emitted by an earlier build. The `dyld[PID]` in
the note line is the only way to tell — a repeated PID is a replay, a new PID is
a live failure. Compare PIDs before concluding anything about a fix.
