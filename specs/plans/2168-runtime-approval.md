# Plan 2168 — Unified runtime policy and human approval

Status: COMPLETE

## Objective

Define one typed, fail-closed policy and approval model that composes with the
durable agent-session contract. Static signed admission remains authoritative;
human approval is an additional decision for an already-admissible operation.

## Work items

- [x] Audit signed admission, existing policy DTOs, command gating, audit
      records, and conformance surfaces.
- [x] Document decision precedence, typed scopes, bounded metadata, lifecycle,
      and the compatibility map before implementation.
- [x] Add typed policy operations, rules, admission binding, deterministic
      precedence, and fail-closed evaluation.
- [x] Add approval request/response types and durable lifecycle events on the
      existing agent-session envelope.
- [x] Enforce authorization, expiry, cancellation, first-valid-response,
      replay, duplicate, and stale-response behavior.
- [x] Keep raw commands, paths, credentials, and PII out of policy/approval
      records and audit projections.
- [x] Re-export the shared contract through `mvm-client` and `mvm-sdk`.
- [x] Add serialization, policy-matrix, approval-lifecycle, tamper, and
      security tests plus non-`@wip` BDD scenarios.
- [x] Run formatting, package/workspace validation, targeted normal Clippy,
      and non-`@wip` BDD validation. No builder-VM check is required because
      this change is pure contract/policy logic and adds no Linux-only path.

Validation: `cargo fmt --all -- --check`, focused approval tests (5/5),
workspace `cargo check --workspace --all-targets`, targeted Clippy, and BDD
source checking all pass. The full workspace/all-target Clippy gate also
passed in the commit hook. The BDD harness was first run without the
repository's `just bdd` preparation, which caused five local prerequisite
failures: the worktree-restricted remote-template cache, an unbuilt
TypeScript distribution, and an unbuilt `xtask` binary. Running the supported
preparation (`cargo build -p xtask`, `npm ci`, and the TypeScript build) clears
the SDK/tooling failures; the remote-template failure is likewise confined to
the host sandbox rather than product behavior. The three new policy-approval
scenarios passed after the terminal-response ordering fix. The full workspace
test link was not completed in this host environment because it remained in a
silent large-binary link; package and focused tests were green.

## Compatibility boundary

This plan does not replace signed `ExecutionPlan` admission, network/secret
enforcement, sealed-production restrictions, or the existing audit chain. It
adds a shared typed decision and approval layer at the existing boundaries and
uses the #2167 durable journal for approval history.
