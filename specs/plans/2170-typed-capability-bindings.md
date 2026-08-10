# Plan 2170 — Typed capability bindings

Status: READY FOR REVIEW

## Objective

Add a versioned, transport-neutral capability binding contract to the existing
host broker. A guest may invoke a capability only when the host admitted the
exact capability and descriptor digest for that workload. The handler remains
host-owned; credentials, host paths, and handler internals never cross the
guest boundary.

## Design

- `mvm-contract::protocol::agent_capability` owns the wire DTOs:
  `CapabilityId` (`ServiceId` plus verb), `SchemaRef`, `CapabilityLimits`,
  `CapabilityDescriptor`, `CapabilityBinding`, `CapabilityInvocation`,
  `CapabilityFailureCode`, and digest-only `CapabilityAuditEvent` values.
- A descriptor is versioned by its `ServiceId`, names the verb explicitly,
  identifies input and output schemas by stable names and SHA-256 digests, and
  carries maximum input/output bytes plus a maximum execution time. Descriptor
  and binding validation rejects empty names, invalid IDs, zero or excessive
  limits, and mismatched service/verb identities.
- `ServiceCall` gains an optional capability invocation section. It is omitted
  for the existing legacy host-service calls, so their serialized shape stays
  unchanged. A typed call carries the protocol version, exact binding, bounded
  invocation ID, and digest of the existing `payload` value.
- `mvm-hostd::broker::Registry` gains per-verb registrations and a separate
  admission allowlist. Typed dispatch checks, in order: protocol version,
  registered descriptor, exact admitted binding, input digest and byte limit,
  handler schema parsing, cancellation/timeout, and output byte limit. A
  replayed invocation ID is refused before the handler runs. Legacy dispatch
  remains on the existing path and never widens typed admission.
- `RegisterVm` carries an optional list of exact typed bindings in addition to
  the existing service list. The host-signed control request is the only source
  of the typed allowlist; a guest cannot register or widen it.
- Audit events contain only capability IDs, descriptor/binding digests,
  invocation IDs, input/output digests, and closed outcome codes. They cover
  registration, admission, invocation, refusal, timeout, cancellation, and
  handler failure. No input/output JSON, credentials, tokens, or host error
  text is recorded.

## Implementation checklist

- [x] Add and test the no-`std` capability contract and stable serialization.
- [x] Add typed bindings to the signed broker registration DTO.
- [x] Extend `ServiceCall` with the backward-compatible invocation envelope.
- [x] Implement registry registration, exact allowlist admission, replay
      refusal, bounded input/output, timeout, cancellation, and audit hooks.
- [x] Route typed calls through the real UDS broker server and preserve the
      existing legacy service path.
- [x] Add positive and negative BDD scenarios plus focused protocol tests for
      version mismatch, binding downgrade/confused deputy, denial, malformed
      input, oversized input/output, timeout, cancellation, replay, handler
      failure, and secret non-exposure.
- [x] Update the sprint and refactor rollup, run the required host validation,
      and link the evidence from issue #2170.

Validation evidence: `cargo check --workspace`, focused contract/host/guest
tests, the real host broker UDS round trip, the conformance BDD target compile,
and targeted clippy all pass. The full `mvm-agentd` unit run has one unrelated
macOS sandbox failure in `vsock::connection::tests::test_connect_response_preserves_bytes_after_ack`
(`Operation not permitted`); its other 627 tests pass. Running the BDD binary
itself remains dependent on a freshly built `mvmctl`; the repository's embedded
helper build did not finish on this host.

## Close gate

Close #2170 only after a real client/UDS round trip proves an admitted typed
capability succeeds, every listed refusal path is covered, audit records are
digest-only, and workspace tests/checks/clippy plus the relevant BDD suite are
green.
