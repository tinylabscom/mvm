# Contributor sidecar recovery guidance

Backing: shipped-source
Validation: check-sprint-append

**Status:** COMPLETE
**Date:** 2026-09-01

## Problem

The source-checkout SDK-sidecar recovery path currently sends contributors
through three misleading diagnostics:

- an unembedded release binary recommends plain `just embed`, which produces a
  debug binary and therefore does not repair the executable they invoked;
- the pinned macOS nightly's `rust-objcopy` has an incorrect loader RPATH, so
  embedding emits repeated `libLLVM.dylib` warnings despite the library being
  present in the Rust sysroot;
- normal builder-egress teardown prints `signal: 15 (SIGTERM)` as though the
  builder failed.

The stale-sidecar warning also names the former `crates/mvm-sdk` owner rather
than the current `crates/mvm-host-services` cdylib, and gives no cache path with
which to diagnose a provenance mismatch. Mounting a checkout compounds the
confusion: `--mount` snapshots every byte without honoring `.gitignore`, and
the in-memory materializer can be killed by large nested `target/` trees.

## Work

- [x] Make `just embed` restore the pinned Rust sysroot library directory at
      the macOS rustc boundary, after Cargo constructs its loader path, while
      preserving any existing value, including inside the nested reproducible
      cargo-zigbuild invocation.
- [x] Make `just embed` build native per-VM helpers with the same profile as
      `mvmctl`, so the HVF supervisor is adjacent to the executable at runtime.
- [x] Make the unembedded-binary refusal distinguish debug and release rebuild
      commands and require invoking the rebuilt path.
- [x] Make stale-sidecar guidance name the actual cdylib owner, successful
      completion criterion, and inspected provenance marker.
- [x] Suppress provenance diagnostics when no SDK sidecar was selected; an
      unbound run with unknown libc must not probe the synthetic `unknown/`
      cache path and falsely call it a published artifact.
- [x] Treat SIGTERM of the owned builder-egress endpoint as expected teardown,
      not an unconditional stderr failure line.
- [x] Document that directory mounts are unfiltered in-memory snapshots and
      give an actionable narrow/staged-directory workaround.
- [x] Refuse directory snapshots above the in-memory walker ceiling before
      allocating file buffers, stream the unsealed ext4 output, and tolerate
      entries that vanish from a live host tree during capture.
- [x] Version host-side OCI injection semantics in the cached-rootfs identity
      so a Rust image cached before image-environment propagation is
      rematerialized and exposes `cargo`, `rustc`, and `rustup` on `PATH`; keep
      that version directly in the rootfs tag rather than behind the binary-
      identity sidecar, whose cached digest cannot observe host-only behavior.
- [x] Add focused regressions, run workspace tests/check/Clippy, and synchronize
      sprint and refactor status.

## Validation

- `just embed --release` completed with the macOS rustc-boundary loader repair;
  the fresh final strip emitted no `libLLVM.dylib` warning.
- `cargo test --workspace` passed on the macOS host.
- `cargo check --workspace` and `cargo clippy --workspace -- -D warnings`
  passed on the macOS host.
- Focused embed-recipe, unembedded-binary, sidecar-provenance, mount-help, and
  builder-egress teardown regressions passed, including native-helper profile
  parity, the unbound unknown-
  libc false-warning path, bounded mount preflight, vanished-entry handling,
  sparse output parity, and OCI injection-semantics cache invalidation.
- No live microVM command was run on the macOS host; builder-VM/live validation
  remains governed by the repository execution-boundary rules.
