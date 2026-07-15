# ADR 053 - Guest Protocol Versioning, Runtime Readiness, and First-Use DX

**Status**: Proposed
**Date**: 2026-05-14
**Cross-refs**: ADR-002, ADR-007, ADR-014, ADR-041, plan 41, plan 52, plan 72, plan 74

## Context

Plan 74 records a set of runtime and developer-experience lessons from
the `banger` project. The useful pattern is not the media domain. It
is the product shape:

- a thin local control process wraps a mature runtime;
- small typed messages carry control state;
- large bytes move over a separate streaming path;
- version mismatch is detected early;
- the user sees the current wait reason instead of a silent hang;
- the first-use path starts from the user's workflow, not from
  architecture.

mvm already has the right security substrate: signed execution plans,
vsock-only host to guest control, `deny_unknown_fields` on protocol
types, verified boot, audit chains, and a managed builder VM direction
from ADR-014 / plan 72. What is missing is a single contract tying
protocol versioning, readiness, progress, builder mode, receipts, and
first-use DX together.

Without that contract, the same command can fail in ways that look the
same to users but mean very different things:

- the backend accepted launch but the guest agent is not reachable;
- the agent is reachable but too old for the requested verb;
- the agent is ready but services are still warming;
- the builder VM is fetching a cold Nix closure;
- the command used host Nix instead of the managed builder VM;
- a streaming operation is backpressured rather than hung.

## Decision

mvm will treat guest protocol compatibility, runtime readiness, builder
mode, progress events, and receipts as explicit product contracts.

### 1. Guest protocol hello

Every new guest-agent session begins with a protocol negotiation
request. The host sends its protocol version, minimum supported
version, host binary version, and requested capabilities. The guest
replies with its protocol version, minimum supported version, agent
binary version, and supported capabilities.

Mismatch returns a typed error before dispatching the operational
request. The error must indicate the required action when known:
upgrade host, rebuild guest image, or downgrade host.

Hard cutover: there is no `Ping` compatibility shim. A non-hello first
request in a session is rejected with `ProtocolMismatch`
(`required_action = upgrade_host`) and the connection is closed. Old
guest images that pre-date this contract must be rebuilt
(`mvmctl dev down && mvmctl dev up`); old host binaries that have not
adopted the hello prelude must be upgraded. The rationale is in
plan 74 W1 — soft compatibility windows accumulate shim code that has
to be removed later anyway, and the parallel libkrun builder-VM
transition (ADR-014 / plan 72) already requires contributors to
rebuild their dev VM, so layering a separate hello-compat window on
top of that buys nothing.

Protocol types remain closed Rust enums with
`#[serde(deny_unknown_fields)]`.

### 2. Capability negotiation

Capabilities are closed enum values, not ad hoc strings. Initial
capabilities cover existing surfaces:

- `Ping`
- `IntegrationStatus`
- `EntrypointStatus`
- `RunEntrypoint`
- `FilesystemRpc`
- `ProcessRpc`
- `Console`
- `VolumeMount`
- `UpdateIdleTimeout`

Mandatory unsupported capabilities fail closed before the command runs.
Optional capabilities may be ignored only when the caller explicitly
marks them optional.

### 3. Runtime readiness is separate from lifecycle

`InstanceStatus` remains the coarse lifecycle state: created, ready,
running, warm, sleeping, stopped, destroyed. A new readiness field
explains whether a running instance is usable:

- backend launch accepted;
- guest agent connecting;
- guest agent ready;
- services starting;
- services ready;
- degraded;
- backpressured;
- stopping.

Readiness changes must not require invalid lifecycle transitions. They
are status details, not replacement lifecycle states.

### 4. Control plane and data plane stay separate

Small requests and responses remain on the guest control protocol.
Large data paths use streaming, chunking, or dedicated transfer
surfaces. At minimum, docs classify each protocol surface as control
plane or data plane and name its frame cap, chunk size, terminal event,
backpressure behavior, and redaction rule.

Payload bytes are never copied into audit entries, readiness messages,
progress events, or receipts. Receipts may store hashes.

### 5. Backpressure is product state

Backpressure has typed reasons, including:

- guest agent unavailable;
- service health pending;
- output consumer slow;
- input buffer full;
- artifact transfer blocked;
- builder busy.

The first implementation slice wires one high-volume operation,
preferably `ProcWait`, before broadening the model.

### 6. Managed builder VM is the default builder mode

`mvmctl` defaults to the managed builder VM for Nix builds. Host Nix is
not selected implicitly, even if present.

Supported builder modes:

- `managed-builder-vm` - default; mvm-owned Linux builder VM, mvm-owned
  store disk, controlled mounts, controlled egress, auditable behavior.
- `host-nix` - explicit opt-in only; uses the host's Nix daemon,
  substituters, sandbox settings, and store state.
- `remote-builder` - reserved future mode.

`mvmctl doctor` may detect host Nix, but it reports it as optional
acceleration or debugging tooling unless the user selected `host-nix`.

When `host-nix` is selected, the CLI prints and records a
reproducibility and security note. The receipt records
`builder_mode = "host-nix"` so later audit and support work can see
that the host trust boundary was expanded intentionally.

### 7. Progress events are structured

Long-running commands emit structured progress events and render human
text from those events. CLI text, JSON output, Studio, MCP tools, logs,
and receipts should not each invent separate status vocabularies.

Initial events include:

- builder mode selected;
- builder image ready;
- Nix eval started;
- Nix build started;
- cache state observed;
- backend launch accepted;
- guest agent connecting;
- guest agent ready;
- services starting;
- services ready;
- backpressure observed;
- receipt written.

### 8. Receipts are default-safe

Successful `run`, `up`, and `build` commands can write a small receipt
with:

- command id;
- plan id or signed-plan hash when present;
- image hash or bundle hash;
- backend;
- builder mode;
- protocol version;
- capability set;
- phase durations;
- cache state summary;
- audit-chain pointer;
- output hashes.

Receipts must not store raw argv values, environment values, stdin,
stdout, stderr, secrets, tokens, or user data unless another accepted
ADR creates a more specific receipt contract.

### 9. Explainability is a first-class command surface

Reserve `mvmctl explain <receipt-path-or-error-id>` for mapping common
failures to causes and next actions:

- protocol mismatch;
- missing required capability;
- missing builder image;
- backend unavailable;
- egress denied;
- service health timeout;
- cache miss or cold store;
- host-Nix cross-system failure.

### 10. Docs start with first use

Getting-started docs should lead with "run your first thing" and then
link to architecture, security model, and backend details. Protocol and
builder internals belong in reference docs, not at the top of the
first-use path.

## Consequences

**Positive.**

- Users can distinguish "booting", "agent unavailable", "services not
  ready", "protocol mismatch", and "backpressured" without reading raw
  logs.
- Host Nix remains available to power users without silently weakening
  the default security and reproducibility story.
- Receipts and structured progress make CLI, Studio, MCP, and support
  workflows share one vocabulary.
- The protocol compatibility window is explicit rather than accidental.

**Costs.**

- Every guest-agent caller that depends on a non-legacy capability must
  negotiate before dispatch.
- Existing CLI progress output needs to be routed through structured
  events rather than one-off strings.
- Receipts require careful redaction tests.
- Host-Nix opt-in needs support and docs even though it is not the
  default path.

**Risks.**

- Protocol hello strands any pre-hello guest image at first contact.
  Mitigation: clear `ProtocolMismatch` payload (`required_action =
  upgrade_host`), a documented `mvmctl dev down && mvmctl dev up`
  rebuild path, and a release note when the contract lands. There is
  no compat shim — see §1.
- Readiness can duplicate lifecycle state. Mitigation: lifecycle stays
  coarse; readiness explains usability.
- Progress events can become too detailed. Mitigation: closed enums and
  workflow-level renderers.
- Receipts can leak sensitive data. Mitigation: hashes and metadata
  only, with tests that assert payload absence.

## Test expectations

- Serde roundtrip tests for protocol hello, mismatch, capabilities,
  readiness, progress events, and receipts.
- Unknown-field rejection tests for every new wire type.
- Backward compatibility tests for older `InstanceState` JSON.
- CLI golden tests for protocol mismatch, missing capability, missing
  builder image, backend unavailable, and service health timeout.
- Receipt redaction tests proving stdin/stdout/stderr/env payloads are
  not stored.
- Builder-mode tests proving host Nix is not selected implicitly.

## Migration

Implementation is sequenced in plan 74:

1. Land this ADR.
2. Add protocol hello and capability negotiation behind helpers.
3. Add readiness fields with serde defaults.
4. Inventory and document control-plane/data-plane boundaries.
5. Add one backpressure event path.
6. Add first-use DX and builder-mode policy.
7. Add structured progress, receipts, and `explain`.
8. Document builder egress and cache explainability.

Every guest-agent session — including a pure `Ping` reachability
probe — begins with a `ProtocolHello`. Pre-hello guest images receive
`ProtocolMismatch { required_action: upgrade_host }` on their first
incoming request and must be rebuilt; the host CLI surfaces a single
clear "rebuild your dev VM" hint when this fires.

## References

- Plan 74 - `specs/plans/84-banger-runtime-lessons.md`
- ADR-002 - `specs/adrs/002-microvm-security-posture.md`
- ADR-007 - `specs/adrs/007-function-call-entrypoints.md`
- ADR-014 - `specs/adrs/014-vmbackend-single-trait.md`
- ADR-041 - `specs/adrs/041-signed-audited-execution-plans.md`
- Plan 41 - `specs/plans/81-function-entrypoints-design.md`
- Plan 52 - `specs/plans/52-fd3-control-channel-and-session-attach.md`
- Plan 72 - `specs/plans/72-builder-vm-via-libkrun.md`
