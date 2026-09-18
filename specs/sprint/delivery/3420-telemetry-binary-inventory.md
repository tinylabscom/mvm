# Telemetry binary inventory and drift gate

Issue #3420, W1a of `2026-09-17-host-mediated-telemetry`; epic #3419 remains open.

The offline `check-telemetry-inventory` gate discovers all 45 Cargo workspace
binary targets, including implicit and disabled-feature targets. The strict
inventory records 28 runtime capture gaps and 17 reasoned non-runtime exclusions.
CI's `check-all` rejects missing, stale, duplicate, source-moved and feature-drifted
entries. It validates entrypoint navigation anchors, not runtime initialization.
There is deliberately no status that awards runtime coverage.

Protocol pipes and command/function return values are not telemetry. Diagnostics
remain required for the runner, extension provider and CLI; their result channels
are excluded from the declared stdio family.

## Validation

All cargo commands used the isolated worktree environment and
`scripts/cargo-stable.sh` (Rust 1.97.1).

- Seventeen inventory tests pass, including real Cargo discovery, malformed
  inventory, classification roundtrip, drift, traversal and result-stream rules.
- Three gate-registration tests pass; all 69 `check-all` gates pass.
- Workspace clippy and xtask all-target clippy pass with warnings denied.
- The serialized workspace run, with `RUST_LOG` unset, completed 13,782 unit and
  integration tests without a failure. Two existing
  `run_build_surfaces_environment_gaps` tests were excluded because they can
  launch a real builder from macOS. An initial run was deliberately stopped at
  that boundary. The existing `mk_guest_eval_assertions_all_pass_when_nix_available`
  test invoked Nix on macOS before its boundary violation was identified; that
  result is not accepted as builder-VM validation and must not be repeated there.
- The broad run's doctest phase initially failed to resolve `mvm_sdk` using the
  ambient Homebrew rustdoc. A separate `test --workspace --doc` run with
  `RUSTDOC` explicitly resolved by `rustup which --toolchain 1.97.1 rustdoc`
  passes. This is not a claim that the unrestricted original command passed.
- `cargo audit` and `cargo deny check` pass; the existing unmaintained
  `proc-macro-error2` advisory remains a warning.
- `cargo machete` reports six unchanged findings, reproduced on the unchanged
  design checkout: `mvm-capture` (anyhow, tracing), `mvm-client` (tar),
  `mvm-hostd` (etherparse), `mvm-runtime-fuzz-backend` (tempfile), and
  `third_party/am-fs-ext4` (am-fs-core). No dependencies changed in this slice.

Linux-only and real-backend certification remain open. This slice changes no
runtime, transport, subscriber, VM launch or export behavior. It does not prove
nonblocking emission, loss accounting, early-boot coverage or detached collection.
Remaining library/SDK/init sources, launcher/backend mappings, startup witnesses,
the executable acceptance harness and hardware-qualified measurements remain in
W1; W2–W7 remain open. Do not close #3420 or #3419 on this delivery alone.
