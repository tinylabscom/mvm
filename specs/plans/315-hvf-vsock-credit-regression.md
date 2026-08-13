# Plan 315 — HVF virtio-vsock transmit-credit regression

## Status

**COMPLETE.** Opened 2026-08-10 after
the documented README `pandas` example reproduced a PyPI wheel hash mismatch
on the HVF backend. The package index and TLS endpoint are not the source of
the mismatch: the current `mvm-vmm` transport retained transmit-credit readers
and consumers, but no longer recorded the guest's advertised `buf_alloc` and
`fwd_cnt` values.

## Root cause

Commit `1a515ae44` added per-connection host-to-guest credit tracking and tests
for a 10 MiB lossless relay plus credit exhaustion/resumption. Commit
`ca68dd9c0` removed `VsockTransportCore::record_tx_credit`, its call before
packet dispatch, and both regression tests while retaining the rest of the
credit-limited relay. Consequently `tx_credit_available` always falls back to
`HOST_BUF_ALLOC`, `consume_tx_credit` has no map entry to update, and a fast
host response can overrun the guest receive window.

## Scope and acceptance

- [x] Restore bounded per-connection recording of every guest packet's
      advertised transmit credit before handler dispatch.
- [x] Clear transmit-credit state whenever a connection or the device is torn
      down, including snapshot preparation.
- [x] Restore focused tests proving the host stops at the advertised window,
      resumes only after `OP_CREDIT_UPDATE`, and removes state on teardown.
- [x] Treat activity in either direction as connection activity so a long
      download survives beyond the request side's 60-second idle timeout.
- [x] Restore a multi-megabyte deterministic relay test that proves byte-for-byte
      delivery without truncation.
- [x] Add a live BDD scenario for the documented `python:3.12` + `pandas`
      workflow through the admitted PyPI hosts.
- [x] Run focused `mvm-vmm` tests on the macOS host.
- [x] Run `cargo test --workspace` and `cargo check --workspace` on the macOS
      host.
- [x] Run workspace all-target Clippy and the Linux-gated `mvm-vmm` tests —
      the CI `test-linux` and `lint-core` lanes passed on PR #2324; a local
      x86_64 Linux cross-build (`cargo zigbuild --target
      x86_64-unknown-linux-gnu -p mvm-vmm --lib --all-features`) passes on
      current `main`.
- [x] Record the repair in `specs/SPRINT.md` and
      `specs/REFACTOR-STATUS.md`.

## Verification evidence

- `cargo test -p mvm-vmm --quiet`: 446 passed.
- The focused credit group covers counter wrap, table bound,
  connection-wide idle eviction, teardown, first-window stop/resume, and the
  deterministic 32 MiB byte-for-byte relay. A zero-wait clock witness advances
  beyond 60 seconds and proves transmit progress keeps a download connection
  alive while wholly idle connections are still removed. A separate
  token-bucket witness simulates a continuous 4 GiB transfer to prove the
  throughput budget has no lifetime download quota.
- `cargo check --workspace`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings` on macOS: passed.
- `cargo zigbuild --target x86_64-unknown-linux-gnu -p mvm-vmm --lib
  --all-features` with the pinned Rust 1.96 toolchain: passed.
- `cargo test --workspace -- --test-threads=1`: passed, including all doctests.
  The serial run passed both `mvm-hostd` isolation tests that had failed in
  separate earlier aggregate runs and then passed alone.
- The non-live BDD run parsed the new live scenario and passed 170 of 172
  runnable scenarios. Its two failures are the TypeScript SDK fixtures, whose
  generated `dist/index.js` was not built because the direct safe runner did
  not execute `just bdd`'s npm preparation steps.
- The broader Linux workspace cross-build is currently blocked outside this
  plan by `mvm-sdk`'s `SubprocessBackend` missing the all-features
  `backend_capabilities` trait method. The macOS 26 execution tier has no
  interactive project builder-VM command path, so Linux-native tests and
  all-target Clippy remain open for CI or a builder-enabled session.

## Non-goals

- Changing the public egress policy or `--allow-host` semantics.
- Disabling pip hash verification or retrying corrupted downloads.
- Adding a second network path around the existing vsock-only boundary.
- Changing Plan 313's response-streaming or usage-accounting scope.
