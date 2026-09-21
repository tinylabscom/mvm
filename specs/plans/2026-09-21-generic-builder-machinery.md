# Generic builder machinery

Backing: shipped-source
Validation: check-sprint-append

Issue: #3323

**Status: COMPLETE**

## Goal

Make the QEMU and driver-backed builder paths independent of the optional
libkrun implementation. VMM-neutral image/cache, Stage 0 store, transport,
runtime-overlay, egress, job identity, seed identity, and resource defaults
must live under generic builder modules. A generic-only build must not compile
or depend on `libkrun-sys`.

## Work

- [x] Move `BuilderVmImage`, cache readers, Stage 0 store preparation, and job
      identity into VMM-neutral modules while retaining compatibility exports.
- [x] Move disk transport, runtime-overlay attachment, and builder egress
      helpers out of `libkrun_builder`; update QEMU, HVF, runtime, and CLI
      callers to use generic paths.
- [x] Keep generic builder capability unconditional, make `builder-libkrun`
      the optional backend feature, make `libkrun-sys` optional, and gate the
      libkrun modules. This follows the newer unconditional-capability decision
      rather than reviving the removed `mvm-build/builder-vm` switch.
- [x] Single-source the duplicate job-id format, Stage 0 seed-store hash, and
      identical builder resource defaults.
- [x] Update the build-egress caller gate and add focused positive, negative,
      and edge-case tests for the moved helpers.
- [x] Pass formatting, generic-only dependency/check witnesses, 14,706
      process-isolated workspace tests, zero-warning all-target Clippy,
      gated-target checks, all 74 repository gates, and prepare the
      issue-closing change for protected merge-queue delivery.

## Validation

- `cargo nextest run --workspace`: 14,706 passed, 27 skipped.
- `cargo test --workspace --doc`: green.
- `just lint`: formatting, all-target workspace Clippy, BDD-target Clippy,
  model gates, and the pinned fast-Cargo policy are green.
- `just check-gated`: Linux all-target cross-check and the feature-gated BDD
  target are green.
- `cargo run -p xtask -- check-all`: all 74 repository gates are green.
- `cargo check -p mvm-build --no-default-features --lib` and the
  `generic_builder_surface` integration test are green.
- `cargo tree -p mvm-build --no-default-features -e normal` contains neither
  `libkrun-sys` nor another libkrun dependency.

## Security invariants

- Builder egress remains `trusted_build_egress`; no workload launch path may
  call it.
- Runtime overlays remain read-only and mandatory for lean builder images.
- Cache manifests and recorded digests remain admission gates before shared
  cache bytes enter an isolated root.
- Stage 0 seed markers remain bound to sorted Nix-store membership and an ext4
  filesystem without the recorded error bit.
