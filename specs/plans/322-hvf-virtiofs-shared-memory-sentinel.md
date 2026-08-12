# Plan 322 — HVF virtio-fs shared-memory sentinel

**Status:** COMPLETE

**Last updated:** 2026-08-11

An HVF `machine run --mount` boot exposed a queue-backed virtio-fs device with
no DAX window. Its unimplemented virtio-MMIO shared-memory registers read as
zero, so Linux interpreted address 0 and length 0 as a present region, rejected
the device, failed to find the `uvol0` tag, and killed PID 1. The CLI reported
the downstream symptom as a 30-second guest-agent readiness timeout.

## Work

- [x] Reproduce the exact Alpine directory-share command and capture the guest
      console before transient teardown.
- [x] Add a transport regression test for the absent shared-memory-region
      register contract.
- [x] Return the virtio-MMIO all-one length and base sentinel for every selected
      shared-memory id while the queue-backed virtio-fs device has no DAX
      window.
- [x] Run the complete `mvm-vmm` suite and formatting check.
- [x] Rebuild the native HVF supervisor and prove the original command exits
      successfully with the host checkout visible at `/work`.

## Verification

- [x] `cargo fmt --all -- --check`
- [x] `cargo test -p mvm-vmm` — 456 passed
- [x] `cargo check --workspace`
- [x] Workspace unit and integration tests pass serially; `cargo test
      --workspace --doc` passes separately after the repository sync test's
      nested Cargo invocation.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` on macOS
- [x] Native macOS HVF: `machine run --image alpine --mount .:/work -v -- ls
      /work` exits 0 and lists the mounted checkout.
