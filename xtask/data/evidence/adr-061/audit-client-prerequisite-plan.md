# Audit-client ownership prerequisite

Backing: preview
Validation: none

Immutable plan for [#5510](https://github.com/tinylabscom/mvm/issues/5510),
following accepted [ADR-061](../../../../specs/adrs/061-crate-layout-by-where-code-runs.md).
Source pin: `4c84cf9bb4fe74da2fb8d81a0aaec1470e869a37`.
This slice has implementation authorization only; P2 and its PR are untouched.

## Bounded change

Move the entire `mvm-hostd/src/broker/audit_client.rs`, including its tests,
to `src/audit/audit_client.rs`. Declare the audit module and re-export that
module from broker, preserving public type identity without wrappers.
Change only the three canonical client references in `audit/assurance.rs`.
Existing broker daemon, audit/beacon handlers and broker binary retain their
imports through the facade. No dependency, feature, server, configuration,
key, process, chain substrate, stream vocabulary or composition changes.

The client opens one Unix socket per append, writes length-prefixed JSON,
checks the response length before allocating, decodes and shuts down.
Direct requests retain the append protocol; helper requests inject the selected
VM ID and map helper responses back to append responses. Preserve typed
transport errors, typed signer refusals, unexpected-helper-response refusal,
the 64 KiB default response cap and caller-selected caps. Preserve existing
request correlation and deadline behavior; do not consolidate framing.

## Sequence and evidence

1. Finish baseline `broker::audit_client::tests` and
   `audit::assurance::sink_tests` before any source edit.
2. Perform the whole-file move and facade/canonical-reference edits.
3. Add Unix `audit_client_compat` integration coverage: assignments across both
   public client/error paths; direct and helper wire fixtures; cap refusal;
   typed signer and transport errors. Bound fixture accept, read, write and
   client waits together, with no detached task or thread left behind.
4. Compare the moved file byte-for-byte to the source pin (stronger than
   normalized executable-source equivalence), including all original tests.
   Verify assurance differs only by canonical path and all other callers,
   manifests and lockfile are untouched.
5. Run `cargo fmt --all -- --check`, scoped client and assurance tests,
   the broker library filter, integration test and scoped hostd clippy with
   warnings denied. Use `scripts/dev-env.sh`, cached Cargo home, offline Cargo
   when available and invocation-local `TMPDIR=/tmp`.

Record commands, counts, ownership evidence and limitations in a separate
implementation report. Full workspace gates and fresh review belong to the
parent before publication; do not stage, commit, push, open a PR or merge.

## Security and lifecycle

The trusted host's signer remains the key owner; the client owns only its
per-call socket and request. Success/error/cancellation ownership and refusal
semantics are unchanged. This is a source ownership cut, not a new authority
path or a security guarantee. Unix wire fixtures are not live signer-process,
VM, hardware, malicious-host or physical-erasure evidence. ADR-001 remains
the shipped-claims authority. Stop if an unanticipated contract decision arises.
