# Audit-client ownership prerequisite: implementation evidence

Backing: preview
Validation: none

Refs [#5510](https://github.com/tinylabscom/mvm/issues/5510) and accepted
[ADR-061](../../../../specs/adrs/061-crate-layout-by-where-code-runs.md).
Implements the [immutable plan](audit-client-prerequisite-plan.md) against
`4c84cf9bb4fe74da2fb8d81a0aaec1470e869a37`. This report records scoped evidence,
not a publication decision or a claim that the entire restructuring is complete.

## Change and ownership evidence

- Moved all 380 lines of `crates/mvm-hostd/src/broker/audit_client.rs` to
  `crates/mvm-hostd/src/audit/audit_client.rs`, including the three original tests.
- Added `audit::audit_client`; replaced the broker module declaration with
  `pub use crate::audit::audit_client`.
- Replaced exactly three `crate::broker::audit_client` references in
  `audit/assurance.rs` with the audit-owned path.
- Added `crates/mvm-hostd/tests/audit_client_compat.rs` and the plan/report.
  No other callers, dependency declarations, feature selections or lockfile changed.

Python compared `git show` of the pinned broker source against the relocated
file as bytes: exactly equal, 12,893 bytes, SHA-256
`b534d4988bfce932bb2fb4f4e6b55372387c0d60b64e1163dd8326a2f22265f6`.
This is stronger than equality after normalizing comments and paths: no
normalization was needed. A separate equality assertion proved assurance
changed only those three paths. Equality assertions also covered workspace
and hostd manifests, `Cargo.lock`, broker daemon, audit/beacon handlers and
broker binary. The old file is absent and the facade has no implementation.

The one-call-per-connection direct and resident-helper routes, framing,
response cap, error mapping, correlation and deadline behavior are unchanged.
The reverse assurance-to-broker client edge is gone; unrelated remaining
ADR-061 ownership cuts are deliberately not part of this slice.

## Commands and observed results

Host: Darwin arm64; rustc 1.97.1, cargo 1.97.1.
Each Cargo shell used:

```sh
source scripts/dev-env.sh
export CARGO_HOME=/tmp/mvm-5538-cargo CARGO_NET_OFFLINE=true TMPDIR=/tmp
```

The worktree kept its own target and MVM state directories. The cache was
sufficient; no online dependency resolution was needed.

| Phase | Exact command | Result |
| --- | --- | --- |
| Before any Rust source edit | `cargo test -p mvm-hostd --lib broker::audit_client::tests` | 3 passed |
| Before any Rust source edit | `cargo test -p mvm-hostd --lib audit::assurance::sink_tests` | 3 passed |
| After move | `cargo test -p mvm-hostd --lib audit::audit_client::tests` | 3 passed |
| After move | `cargo test -p mvm-hostd --lib audit::assurance::sink_tests` | 3 passed |
| After move | `cargo test -p mvm-hostd --lib broker` | 163 passed |
| After move, repeated after formatting-only edits | `cargo test -p mvm-hostd --test audit_client_compat` | 5 passed each run |
| Final format gate | `cargo fmt --all -- --check` | passed |
| Scoped lint gate | `cargo clippy -p mvm-hostd --all-targets -- -D warnings` | passed |
| Tracked patch whitespace | `git diff --check` | passed |

Both baseline commands completed successfully before relocation, in one
sequential background command (initial compilation took 4m45s).
The broker filter also includes names containing broker in stream,
supervisor and egress modules; it is not a full hostd suite.

Initial format checks reported only line wrapping in the new integration
test. One standalone format check was killed by an overly short one-second
tool timeout; it was rerun with a sufficient bound. The requested wrapping
was applied, and the final format check passed before clippy. No compiler,
test or clippy failure occurred.

## What the integration evidence means

Compile-time assignments demonstrate client and error type identity across
both public paths. Bounded UDS fixtures check the complete direct request,
helper VM injection and preservation of the other request fields, successful
responses, typed signer refusals, exact-cap acceptance and zero-cap refusal
from the length prefix alone, missing-socket and decode errors, and the
unexpected helper-response protocol error.

Fixture accept/read/write and client futures run together under a five-second
timeout; no fixture thread or detached task is spawned. Request allocation is
bounded before reading its body. Another test uses both real in-process server
implementations with fresh temporary chains: successful append persists one
entry per route and an invalid category returns the existing typed refusal
without a second entry. Its accept loops are owned by a bounded select; their
existing connection tasks remain confined to the test runtime, which is
dropped after the test. It uses ephemeral generated keys, not stored credentials.

## Limits and handoff

No subprocess launch, live VM, hardware, Linux-specific, Windows or
malicious-host claim is made. This is host-library/Unix evidence, not an
extension to ADR-001's backend guarantees. Tests do not exhaust every error
variant or add production deadlines/correlation checks.

After integration into the parent worktree, a fresh review found no blocking
source-level findings and independently confirmed byte equality and the three
assurance path substitutions. The parent then ran, serially and successfully:

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
just check::gated
cargo run -p xtask -- check-all
```

The aggregate gate reported 86 gates clean. It used a temporary Git index
representing the relocation and new files; the real index was not staged.
This parent validation used the existing cached Cargo home and invocation-local
`TMPDIR=/tmp`, with isolated worktree target/state directories.

At completion of local validation, no commit, push, PR publication or Git merge
was performed for this slice, and P2 was not amended. The remaining audit-to-
supervisor chain-substrate dependency still blocks independent audit extraction.
