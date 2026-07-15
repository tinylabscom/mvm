---
title: "ADR-015: hostd-IPC protocol versioning"
status: Accepted
date: 2026-05-11
related: ADR-001 (microVM security posture); ADR-014 (signed audited execution plans); plan 60 Phase 8 (mvmd integration contract verification)
---

## Status

Accepted. `mvm_core::protocol::PROTOCOL_VERSION` shipped 2026-05-11 alongside the mvm-side stability test that pins the constant. mvmd's `tests/mvmd_compat.rs` (Phase 8, mvmd-repo work) reads it as the fixed point its frozen-byte fixtures pin against.

## Context

`mvm-hostd` ↔ `mvmd` IPC runs over a Unix socket at `/run/mvm/hostd.sock` (default; configurable). The wire format is length-prefixed JSON envelopes carrying `HostdRequest` and `HostdResponse` enums defined in `mvm_core::protocol::protocol`. Plan 60 Phase 8 closes the cross-repo contract: mvmd's CI must catch wire-format drift before a PR merges, regardless of which repo the breaking change lands in.

Until this ADR, the protocol surface had no version label. Add a field to a `HostdRequest` variant, rebuild both sides locally, observe nothing breaking — and downstream consumers on a pinned mvm version would fail mysteriously when their mvmd talked to the new mvm-hostd.

Three problems the version constant solves:

1. **Compatibility detection at handshake.** A daemon receiving an envelope can read `PROTOCOL_VERSION` from the peer's identification frame and refuse cleanly if the peer is ahead or behind by a known-incompatible step.
2. **CI gate against drift.** mvmd's `tests/mvmd_compat.rs` pins frozen-byte fixtures for the canonical envelope shapes (`AgentRequest::Reconcile`, `HostdRequest::Start`, `HostdResponse::Started`). If the bytes change without the constant bumping, the test fails on the mvmd side — caught before merge.
3. **Documented bump policy.** Operators auditing a deployment can `grep PROTOCOL_VERSION` and see which generation of the wire format the binary speaks.

## Decision

### The constant

```rust
// crates/mvm-core/src/protocol/protocol.rs
pub const PROTOCOL_VERSION: u32 = 1;
```

`u32` (not `u8` / `u64`) because:

- `u8` caps at 255, which is conservative for a long-lived project where the constant might bump every few months over years.
- `u64` is overkill; a wire-format version that exceeds 4 billion suggests something deeper has gone wrong.
- `u32` matches the existing `SIDECAR_SCHEMA_VERSION: u32` in `mvm_security::snapshot_hmac` and `SCHEMA_VERSION: u32` in `mvm_plan` — consistent type across the project's various schema versions.

### Bump policy

**Increment `PROTOCOL_VERSION` when ANY of the following change in a way that's not backward-compatible with a peer at the previous version:**

- A new `HostdRequest` or `HostdResponse` variant is added that older peers can't downgrade or ignore gracefully. (Most variant additions are NOT forward-compat because serde rejects unknown variants on the receive side; adding a variant usually requires a bump unless deliberately gated behind feature negotiation.)
- A field is added to an existing variant in a position that shifts wire layout. (serde JSON is name-keyed, so positional shifts are rare — but if we ever migrate to CBOR or bincode, positional changes become breaking.)
- A field's semantic meaning changes. Same name, different semantics — for example, `timeout_secs` previously meant total wall-clock but now means per-attempt. Wire is unchanged; semantics aren't.
- The frame encoding shifts. (length-prefixed JSON today; switching to CBOR or msgpack is a wire-level break.)

**Do NOT bump for:**

- New fields with `#[serde(default)]` — older clients keep parsing; older messages keep being parseable. This is the standard forward-compat extension shape.
- New variants that older clients refuse with a typed error rather than crashing. (Requires the receiving end's match to be `#[serde(other)]`-tagged or to handle deserialization errors gracefully — not the default behaviour, but worth designing for.)
- Comments, docstrings, internal helpers, or test-only changes.

### The mvmd-side gate

`tests/mvmd_compat.rs` in the mvmd repo:

1. Reads `mvm_core::protocol::PROTOCOL_VERSION` from the linked-in mvm dependency.
2. Loads its own frozen-byte fixtures from `tests/fixtures/v{N}/{request_name}.json`.
3. For each canonical envelope (`AgentRequest::Reconcile`, `HostdRequest::Start`, `HostdResponse::Started`):
   - Constructs the value in code with deterministic field contents.
   - Serializes via `serde_json::to_string`.
   - Compares byte-for-byte against the on-disk fixture.

When the constant bumps, the test refuses to run until the fixture set under `tests/fixtures/v{NEW}/` is added — forcing the bump and the wire-shape recapture into the same commit.

### What goes in a fresh fixture set

The fixtures cover one canonical instance of each top-level envelope. They're deliberately minimal — extending them to cover every variant would make the test brittle to legitimate refactors. The canonical instances:

- `AgentRequest::Reconcile { tenant_id, pool_id, expected_instances: 1, force: false }`
- `HostdRequest::StartInstance { tenant_id, pool_id, instance_id }`
- `HostdResponse::Started { instance_id, pid, started_at_unix_secs }`

If a field name on any of these changes, the fixture-set must regenerate. The tighter the canonical set, the more aggressive the "did we mean to change this?" check.

## Consequences

### Positive

- **Wire drift gets caught at PR review.** A diff that changes `HostdRequest` shape without bumping the constant fails mvmd's CI; the reviewer sees the breakage in one place.
- **Compat negotiation is grounded.** The mvmd↔mvm-hostd handshake can refuse incompatible versions immediately rather than fail-on-first-bad-message.
- **Operators get a grep-able version.** `mvmctl --version` could later surface this alongside the binary version; ops can answer "what wire format does this build speak?" without reading source.

### Negative

- **The bump policy is enforced by convention + test, not by the type system.** A maintainer could forget to bump. The mvmd-side fixture test is the main backstop; reviewers checking for "did the wire change?" are the secondary.
- **Frozen-byte fixtures are brittle to JSON whitespace.** Solved by using `serde_json::to_string` (compact) consistently on both the fixture-gen and the comparison side.
- **No graceful downgrade.** A peer at v2 refusing to talk to a v1 peer is correct but inflexible. Future variant additions might want feature-flag negotiation to allow partial-compat communication; the current contract is "match versions or refuse." Sufficient for the single-deploy-unit posture we have today; revisit if mvmd starts supporting heterogeneous clusters.

### Out of scope (named)

- **Plumbing the version into a handshake frame.** Today both sides just verify equality before talking. The frame-level negotiation lands when mvm-hostd ships a real bind/accept loop (Phase 8 mvmd-side work; ADR-014 documents the supervisor lift this depends on).
- **Multi-version compatibility shims.** If mvmd needs to talk to a mvm-hostd at v1 while it itself is at v2, the shim layer lives in mvmd — not in mvm-core::protocol.
- **Wire-format migration helpers.** The "v1 → v2 fixture upgrade" tool is mvmd's concern; mvm-core::protocol just defines the current shape.

## References

- `crates/mvm-core/src/protocol/protocol.rs` — `PROTOCOL_VERSION` constant + bump-policy docstring.
- `crates/mvm-core/src/protocol/protocol.rs` — `HostdRequest` / `HostdResponse` definitions.
- `specs/plans/60-mvm-libkrun-migration.md` Phase 8 — the cornerstone this ADR enables.
- ADR-001 §"Out of scope" — host-trust assumptions; the wire format trusts the peer above the socket-perms layer.
- ADR-014 — signed audited ExecutionPlan; the mvm-hostd lift consumes the plan after Phase 8 ships.
