# ADR-015: hostd IPC carries an explicit wire-protocol version

## Status

Accepted.

## Context

`mvm-hostd` speaks a length-prefixed JSON envelope protocol
(`HostdRequest` / `HostdResponse`, defined in `mvm_core::protocol`) over
a Unix socket. Without a version label on that wire format, adding a
field to a request variant, rebuilding both sides locally, and observing
nothing break would let a downstream consumer pinned to an older mvm
version fail mysteriously once its peer moved ahead.

## Decision

### The constant

```rust
// crates/mvm-core/src/protocol/protocol.rs
pub const PROTOCOL_VERSION: u32 = 2;
```

`u32`: large enough that a long-lived project bumping every few months
for years won't run out, small enough that exceeding it would signal
something has gone wrong elsewhere.

### Bump policy

**Increment `PROTOCOL_VERSION` when any of the following change in a way
that is not backward-compatible with a peer at the previous version:**

- A new `HostdRequest` or `HostdResponse` variant is added that an older
  peer can't downgrade or ignore gracefully. Serde rejects unknown
  variants on receipt, so most variant additions are not forward-
  compatible and require a bump unless deliberately gated by feature
  negotiation.
- A field is added to an existing variant in a position that shifts wire
  layout. Rare under name-keyed JSON, but a future move to a
  position-sensitive encoding would make this common.
- A field's semantic meaning changes with the same name — e.g. a
  `timeout_secs` field that used to mean total wall-clock now meaning
  per-attempt. The wire is unchanged; the semantics aren't.
- The frame encoding itself shifts (e.g. length-prefixed JSON to CBOR).

**Do not bump for:** new fields carrying `#[serde(default)]` (older
clients keep parsing; older messages keep being parseable — the standard
forward-compatible extension shape); new variants an older client
refuses cleanly with a typed error rather than crashing; or comments,
docstrings, internal helpers, and test-only changes.

### History

- `1` — initial shape.
- `2` — workspace-volume attach: `workspace_id` threaded through every
  instance-scoped `HostdRequest` variant, and `volumes: Vec<VolumeAttach>`
  added to `StartInstance`. Every new field carries `#[serde(default)]`
  so old payloads still deserialize; the bump exists because the byte
  output changes (JSON keys appear once defaults are present), which is
  exactly the kind of drift the downstream fixture pin needs to catch.

### The cross-repo gate

The mvmd repo's `tests/mvmd_compat.rs` reads `PROTOCOL_VERSION` from its
linked mvm dependency and compares canonical envelope instances —
`HostdRequest::StartInstance` and `HostdResponse::Ok` — against its own
frozen-byte fixtures under `tests/fixtures/v{N}/`. When the constant
bumps, the test refuses to run until the matching fixture set is added,
forcing the bump and the wire-shape recapture into the same commit. The
fixture set stays deliberately minimal — one canonical instance per
top-level envelope — so it stays sensitive to real wire changes without
becoming brittle to unrelated refactors.

mvm-side, `protocol_version_is_two` pins the constant directly, so a PR
can't silently change it without the test failing and prompting the
mvmd-side fixture regeneration.

## Consequences

Wire drift gets caught at PR review: a diff that changes `HostdRequest`
or `HostdResponse` shape without bumping the constant fails mvmd's CI in
one place, with a fixture diff a reviewer can read directly.

The bump policy is enforced by convention plus test, not by the type
system — a maintainer could still forget to bump on a subtler
compatibility break, and the fixture tests are the backstop, not a
guarantee.

There is no graceful cross-version negotiation. A peer at a different
version refuses to talk rather than partially interoperating — correct
for the current single-deploy-unit posture, and revisited only if mvmd
needs to support a heterogeneous fleet of hostd versions at once.

This constant versions the hostd Unix-socket IPC protocol only. The
guest-agent vsock protocol (`mvm_guest::vsock::PROTOCOL_VERSION`) and the
builder daemon's protocol (`mvm_build::builderd_protocol::PROTOCOL_VERSION`)
are separate wire protocols with their own version constants and their
own compatibility rules — each is versioned independently because each
connects a different pair of processes with a different compatibility
requirement.
