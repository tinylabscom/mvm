---
title: "A global rustflags variable silently replaces per-target flags, which broke every musl guest library build"
author: Ari
date: 2026-11-16
branch: main
cost: { minutes: 4, tokens: 27797 }
id: l-a0a6a048
scope: repo
status: active
src: agent
touches:
  - crates/mvm-build/src/guest_agent_build.rs
  - crates/mvm-build/src/guest_bins/extras.rs
---

## Decided

Cargo uses only the single highest-priority rustflags source and never merges them: CARGO_ENCODED_RUSTFLAGS, then RUSTFLAGS, then target-specific flags (including CARGO_TARGET_<TRIPLE>_RUSTFLAGS), then build-level flags. Any lint allowance or extra flag for the guest builds must therefore be added inside the per-target value, not set globally.

In the code: apply_zigbuild_env in crates/mvm-build/src/guest_agent_build.rs set CARGO_ENCODED_RUSTFLAGS to silence zig's linker notice (a change merged 2026-11-16). crates/mvm-build/src/guest_bins/extras.rs passes -C target-feature=-crt-static for musl cdylibs through CARGO_TARGET_<TRIPLE>_RUSTFLAGS, so the global value shadowed it. rustc then printed 'dropping unsupported crate type cdylib' and libmvm_host_services.so was never produced, failing guest-bins and both e2e-docs shards in the validation Release run 43956686058.

## Tried and ruled out

Reading rc.8's failure (release runtime requires verified launch evidence, fixed by the bundle-boot change) as the whole story: the next dispatch failed earlier, in the guest runtime build, so that fix is not yet proven end to end.

## Watch out

Per-shard e2e-docs logs are unreadable until the whole Release run completes, so a queued run hides the real failure. The source build of the guest runtime is not exercised by the cheap merge-queue gate, so a change like this reaches main unnoticed; only the Release e2e lane catches it.
