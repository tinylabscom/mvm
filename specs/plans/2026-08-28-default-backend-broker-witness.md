# Default-backend host-services broker witness

**Status:** IN PROGRESS
**Date:** 2026-08-28
**Issue:** [#2988](https://github.com/tinylabscom/mvm/issues/2988)

## Goal

Run the live SDK host-services broker witnesses on the default Linux
Firecracker and macOS HVF backends without adding virtio-fs support or letting
a pre-boot volume refusal satisfy the negative scenario.

## Checklist

- [x] Replace the host-directory fixture share with a deterministic read-only
      ext4 fixture disk built by the existing pure materializer.
- [x] Require the unbound scenario to observe the guest-visible `not bound`
      broker result in addition to its nonzero exit.
- [x] Add focused coverage for ext4 materialization and the read-only block
      volume command, and compile the complete conformance target.
- [ ] Run workspace tests, formatting, policy gates, and zero-warning Clippy.
- [ ] Capture live Firecracker and HVF broker witnesses in CI.
- [ ] Merge the tested pull request and close #2988 through its linkage.

## Validation

- `cargo test -p mvm-conformance --test service_plane_fixture`
- `cargo test -p mvm-conformance --features bdd --test conformance --no-run`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --all -- --check`
- `cargo run -p xtask -- check-sprint-append`
- `cargo run -p xtask -- check-plan-names`
