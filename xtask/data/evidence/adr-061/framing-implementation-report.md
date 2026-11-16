# P1 implementation report: lower bounded host framing

Backing: historical
Validation: none

**Plan:** [framing prerequisite](framing-prerequisite-plan.md)

**Issue:** [#5510, section G](https://github.com/tinylabscom/mvm/issues/5510)

**Branch:** `refactor/adr-061-host-framing`

**Base:** `052276763f889960b0fd16cb7d58583e6cce4ec5` plus the uncommitted P1 changes

**Outcome at completion of local validation:** implementation and listed
validation complete; not yet committed, published or landed. This report records
that validation snapshot; subsequent publication status is tracked by the pull
request and linked issue.

The owner authorized P1 implementation after reviewing its plan. That later
authorization does not rewrite the immutable plan's earlier planning-only
record and does not authorize later prerequisites or landing.

## Changes

- Moved the asynchronous framing implementation and tests into
  `crates/mvm-core/src/framing.rs`, gated by existing `hostd-transport`.
- Hostd explicitly requests that feature and preserves its public module path
  through `pub use mvm_core::framing`.
- Left all production call sites and error adapters unchanged. Updated stale
  ownership comments in the audit server, service adapter and libkrun framing.
- Preserved constants, error variants/messages/source chains, generic bounds,
  serialization, cap-before-allocation, short-I/O completion and write ordering.
  A comparison with the base implementation, excluding comments and tests,
  found the production framing code unchanged.
- No default-feature, dependency-version, Cargo.lock, process, key-custody,
  guest-protocol or synchronous-framing change.

## Tests and review

The original four hostd framing tests passed before editing. Eight additional
behavioral tests were added and all twelve passed before moving the implementation.
All twelve subsequently passed in core with only `hostd-transport` selected.

The added cases cover fixed wire bytes, successful short reads/writes, exact
caller-cap boundaries, prefix truncation, empty-body decoding, serialization
failure before output, terminal write failure after progress, no flush and no
implicit sender cap. Two hostd integration tests check both public paths,
caller-cap behavior and error-type identity.

The scoped source review found no blocking defect. Its test-hardening suggestion
was applied: the partial-write fixture counts terminal errors so an erroneous
bounded retry would fail the assertion.

## Validation results

| Check | Result |
| --- | --- |
| Original framing baseline | 4 passed |
| Expanded framing tests before relocation | 12 passed |
| `cargo check -p mvm-core --no-default-features --lib` | Passed |
| `cargo check -p mvm-core --no-default-features --features hostd-transport --lib` | Passed |
| `just tests::scoped mvm-core framing::tests --lib --no-default-features --features hostd-transport` | 12 passed |
| `just tests::scoped mvm-hostd '' --test framing_compat` | 2 passed |
| Hostd library filters `audit_signer`, `host_signer`, `broker`, `supervisor::services` | All passed |
| Hostd `telemetry_signer` and `egress_secret_leak_gate` integration targets | Passed |
| `cargo check --workspace` | Passed |
| `cargo test --workspace` | Passed |
| `cargo clippy --workspace -- -D warnings` | Passed |
| `just check::gated` | Passed: Linux cross-check and required-feature BDD compilation |
| `cargo run -p xtask -- check-core-runtime-free` | Passed |
| `cargo run -p xtask -- check-guest-agent-runtime-free` | Passed |
| `cargo run -p xtask -- check-sdk-transport-free` | Passed |
| `cargo run -p xtask -- check-all` | Passed: 86 gates |
| `cargo fmt --all -- --check` | Passed |
| Production-code comparison, Cargo.lock comparison, `git diff --check` | Passed |

### Environment and retry details

- Builds used worktree-local output and the already-cached Cargo home.
  Cargo dependency resolution was offline.
- The first caller run had ten audit-signer test failures at Unix socket bind,
  before framing, because the inherited temporary path exceeded macOS `SUN_LEN`.
  The rerun used invocation-local `TMPDIR=/tmp`; the same audit suite then
  passed all 62 tests. No socket behavior or persistent machine setting changed.
- The initial broad validation was stopped after its successful workspace check
  to apply the short temporary path to tests. The replacement batch passed the
  scoped suites, workspace tests, Clippy, gated checks and closure checks.
- That batch exhausted its overall one-hour budget during `check-all`.
  The footprint scanner had also reported the deleted hostd framing path:
  it enumerates Git-tracked files, while this change was unstaged.
- Final footprint and `check-all` validation used a temporary `GIT_INDEX_FILE`
  containing the P1 additions/deletion, so enumeration matched the intended
  source change. The real index was not staged or reset. With its own time
  budget, `check-all` completed successfully, including generated-stub/parity
  checks. No gate implementation or allowlist was weakened.
- Rust-footprint enforcement remains suspended by the upstream decision; its
  successful measurement is not a claim that a footprint ceiling was enforced.

## Deviations and remaining boundaries

No behavioral or architectural deviation from P1. The implementation adds one
extra ownership-comment correction in the audit-signer server. Validation
required a short temporary path and an isolated index view as described above.

Linux code was cross-checked, not executed on a Linux host. No live microVM,
hardware, density or launch-latency witness was run. No later prerequisite,
role extraction, commit, PR, push or merge is included. The broader issue and
its implementation/density checkboxes remain open.
