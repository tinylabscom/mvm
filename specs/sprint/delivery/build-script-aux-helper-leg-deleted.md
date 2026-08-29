# `mvm-cli(build)` no longer compiles the per-VM host helpers

Plan: `specs/plans/2026-08-28-build-script-drops-the-aux-helper-leg.md`

`crates/mvm-cli/build.rs`'s second leg ran seven sequential nested
`cargo build -p mvm-hostd --bin …` invocations into a private target directory.
All seven binaries are plain `[[bin]]`s that a workspace `cargo build` already
puts in `target/<profile>/`, where `mvm_vmm::host::aux_bin::resolve` already
looked. The leg existed so `cargo run -p mvm-cli` would yield sibling bins, and
it charged a duplicate compile of `mvm-hostd`'s whole closure per worktree for
that convenience.

Measured on aarch64 macOS, running the build script directly with cargo's env so
its cost is isolated: a content-key miss with the nested binaries absent went
**60.37s → 0.13s**, nested `cargo build` invocations **7 → 0**, and the
`rerun-if-changed` set **1013 → 648** files (the aux key hashed `mvm-hostd`'s
closure, which reaches `mvm-runtime`). The nested target dir went **13.6 GB →
649 MB** in the main checkout, with a 3.6–4.5 GB `aux-helper-target` deleted
from each worktree that had one.

The `.mvm-stale` marker, the `MVM_ALLOW_STALE_AUX` escape hatch and the
spawn-time refusal in `aux_bin::resolve` are gone with it. That is a
strengthening, not a relaxation: the marker existed because the build script
reused binaries it could not prove were current, and cargo rebuilds a helper
when its sources change, so there is no stale state left to detect.

`just build` now depends on `just build-supervisors`, which builds
`-p mvm-hostd --bins` and probes for `libkrun.h` before the
`--features libkrun-sys` invocation — so it also stops failing on hosts without
libkrun, which it did before.

Retires `specs/plans/2026-08-26-aux-helper-staleness-gate.md`, closes the
`MVM_LIBKRUN_HEADER` rerun-if-env-changed item in
`specs/plans/2026-08-17-embedded-binary-content-store.md`, and moots §2 of
`specs/plans/2026-08-15-aux-helper-binary-freshness.md`.
