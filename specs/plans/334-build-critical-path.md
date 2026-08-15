# Plan 334 — Cut `mvm-cli`'s build script off the inner loop

Backing: historical
Validation: none

**Status:** DELIVERED
**Date:** 2026-08-14
**Owner:** mvm

## Summary

A one-line edit to `crates/mvm-core/src/lib.rs` cost **288s**. Of a 178.9s
instrumented rebuild, **175.9s (98%) was `mvm-cli`'s build script**, and ~93% of
that was the `cargo-zigbuild` musl cross-compile of the embedded host binaries.

Fixed by reusing already-cross-compiled musl binaries in the **debug profile
only**. Measured **288s -> 15s**.

## Measurements (2026-08-14, aarch64 macOS, 16 cores)

`cargo build -p mvm-cli --timings` after a whitespace edit to `mvm-core`:

| Unit | Time |
|---|---|
| total build | 178.9s |
| `mvm-cli` build script (`run-custom-build`) | **175.9s** |
| every library crate (`core`,`agentd`,`vmm`,`backends`,`runtime`,`hostd`,`client`) | finished by **6.9s** |
| `mvm-cli` crate itself | 2.8s |

Build-script leg split, after an `mvm-core` edit:

| Leg | Time |
|---|---|
| musl `cargo-zigbuild` (1 of 6 bins) | **105s** |
| musl leg, whole set | ~163s |
| native aux-helper leg (4 bins) | **13s** |

Inner loops, at `jobs=6`:

| Edit | Before | After |
|---|---|---|
| `mvm-core` | 288s, 13 crates | **15s** |
| `mvm-hostd` | 27s, 6 crates | unchanged |
| `mvm-cli` | 2s, 1 crate | unchanged |

## Fix

`crates/mvm-cli/build.rs`: when `PROFILE == "debug"`, copy an existing
cross-compiled binary out of the shared nested target dir instead of re-running
`cargo-zigbuild`. Anything else — including `--release` and custom profiles —
rebuilds from source, so shipped bytes are always freshly compiled and the
single-download property is untouched.

Deliberate choices:

- **Explicit `== "debug"`, not `!= "release"`.** Cargo reports PROFILE as
  `debug`/`release`; keying on the negative would silently reuse under a custom
  profile such as `release-witness`, which is exactly where fresh bytes matter.
- **Native per-VM helpers still always rebuild** (13s). Those are the
  supervisors where a stale binary silently yields a guest that ignores your
  edit (#2058, "stale supervisor makes a fixed build look broken"). The 93% win
  is entirely in the musl leg, so that risk is not worth taking for 13s.
- **`MVM_EMBEDDED_BINS_REUSED` is exported** so a reused set is observable
  rather than silently assumed.
- **`just embed-refresh`** drops the cache when fresh bytes are wanted in dev.

Tests keep passing because the four files asserting `EMBEDDED` is populated
check the *name set*, the *SHA match* and *idempotency* — none require freshly
compiled bytes, and the embedded set still hashes its real contents.

## Hypotheses measured and REFUTED

Recorded so they are not re-proposed. Five of six failed:

- **Nested-build feature ping-pong** (`libkrun-sys` flip across a shared target
  dir): rebuild after the flip compiled **0** crates.
- **Cross-invocation fingerprint thrash** (`cargo check --workspace
  --all-targets` vs `cargo build -p mvm-cli`): **0** crates.
- **Dependency count.** Deps are cached and do not recompile on an inner-loop
  edit. Cut them for *security surface*, not build time.
- **tree-sitter `opt-level = 3`** on ~24MB of generated C: forced full C rebuild
  measured **15s**. Dropping the override saves seconds, not minutes.
- **The 9-deep serial critical path.** Extracting `mvm-agentd/src/vsock/` to let
  agentd build in parallel targets a segment worth **1.9s of 178.9s (1%)**. The
  LOC-derived "~30%" estimate was wrong by ~30x. **Parked.**
  (The seam itself is real and clean if ever needed: `vsock/` + `probes.rs` +
  `integrations.rs` = ~11K LOC, reverse edges are wire types only.)

## Out of scope / follow-ups

- **Host oversubscription.** ~30 worktrees x default `jobs`=16 on a 16-core box
  gave load average 73–114 with 11.5M pageouts. Addressed out-of-band with
  `[build] jobs = 6` in `~/.cargo/config.toml` (global, not the repo's
  `.cargo/config.toml`, which would throttle CI and other contributors). Running
  fewer concurrent worktrees remains the largest available lever.
- `mvm-observability` split and `mvm-core` dep trimming are justified by
  **security surface**, not build time.
