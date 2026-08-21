# Artifact acquisition contract

Backing: user-requested
Validation: workspace gates

**Status:** COMPLETE
**Opened:** 2026-08-20

## Goal

Make artifact acquisition an explicit product contract: official release
binaries download verified artifacts and never implicitly invoke local build
tools, while contributor binaries build source-matched artifacts deliberately
and report the cold-build phase clearly.

## Work

- [x] Add an explicit compiled source/release channel and release-boundary tests.
- [x] Route boot image, workload kernel, runtime overlay, initramfs, and guest
      runtime defaults through the shared channel.
- [x] Extend bootstrap to prepare every launch-critical runtime artifact.
- [x] Make contributor guest compilation a named, concise phase with verbose
      raw Cargo output available on request.
- [x] Measure the guest target-cache layout and safely reuse dependency output
      without allowing stale source artifacts.
- [x] Run focused, workspace, gated, and clippy validation; update sprint and
      refactor rollup.

## Validation

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `just check-gated`
- release-channel policy and source-detection tests
- release-asset structure and guest-binary-list synchronization gates
- project builder-VM realization of
  `nix/images/runtime-overlay#runtime-overlay` for `aarch64-linux`, including
  executable checks for all six published OCI guest shims
