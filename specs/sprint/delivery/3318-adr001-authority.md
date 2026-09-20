# ADR-001 security authority matches the shipped guest

Issue #3318, item A2.4 of `2026-09-15-the-big-cleanup`.

ADR-001 now names the sealed guest's actual privilege boundary:
`mvm-setpriv --no-new-privs` establishes the no-new-privileges invariant, then
the guest agent drops the capability bounding set with `PR_CAPBSET_DROP` before
launching the workload. The builder VM's separate util-linux
`setpriv --bounding-set=-all` mechanism remains documented only where it runs.

Claim 3's backend-scoping rationale now lives in ADR-001 itself instead of
citing nonexistent numbered ADRs 106 and 107. Contributor guidance no longer
assumes that ADR numbering stops at 051 and now describes the live HVF,
Firecracker, QEMU and explicit libkrun selection contract.

The temporary ADR-coverage exceptions introduced while #3318 remained open are
removed and protected by regression tests. Four live `specs/claims/` references
identified by the original audit were already corrected by #3309; this change
does not rewrite historical plans or explicit records of those earlier
findings.

## Validation

- `cargo fmt --all --check`
- `just dev-cargo test -p xtask`: 810 tests passed, zero failed
- `just dev-cargo test -p mvm-agentd`: 769 library tests passed, plus all binary
  and integration targets
- `env -u RUST_LOG RUSTC_WRAPPER= just dev-cargo test --workspace --
  --test-threads=1`: full serialized workspace and doctest suite passed
- `just dev-clippy`: workspace clippy passed with warnings denied
- `just dev-check`: workspace check passed
- `just dev-cargo run -p xtask -- check-adr-coverage`: 53 ADRs discovered,
  zero broken references
- `just dev-cargo run -p xtask -- check-witness-citations`: 237 citations
  resolved
- `just dev-cargo run -p xtask -- check-stubs`: no drift
- `just dev-cargo run -p xtask -- check-conformance`: 20 claims match the model
- `just dev-cargo run -p xtask -- check-all`: all 72 repository gates passed
