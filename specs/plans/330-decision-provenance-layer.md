# Plan 330 — Decision provenance layer for `mvm`

**Status:** RFC / planning
**Issue:** #330
**Date:** 2026-08-13
**Owner:** mvm
**Related:** `specs/research/semantica-decision-provenance-assessment.md`, ADR-001, ADR-014

## Summary

Add a **decision-provenance layer** on top of `mvm`'s existing chain-signed audit substrate so that every security-relevant control-plane decision records **who** authorized it and **why**. Keep the existing Ed25519 chain-signed log as the source of truth; do not introduce a new authority or a heavy external dependency.

This is the implementation of the gap identified in `semantica-decision-provenance-assessment.md`: `mvm` has strong cryptographic provenance but lacks first-class decision records with causal links and standards-based export.

## Background

`mvm` already records:

- content-addressed `ExecutionPlan`s signed by the host signer;
- chain-signed `AuditEntry` events in `tenant.jsonl` / `local.jsonl`;
- RFC-6962 Merkle roots;
- capability invocations, approval lifecycles, and admission events.

What is missing:

- a durable, structured record of the **authorizer principal** (human, on-call rotation, or automated system);
- a free-form **rationale** for approvals, denials, and admissions;
- a **ticket / change / incident reference**;
- causal links between decisions (admission → launch → egress allow → checkpoint);
- standards-based regulator export (PROV-O / RDF).

The codebase explicitly acknowledges this gap:

```rust
/// Terminal operator outcome. Reasons remain outside durable metadata.
pub enum ApprovalOutcome {
    Approved,
    Denied,
}
```

## Goals

1. Every admission, launch, egress, checkpoint, approval, and control-plane decision is attributable to a principal and a rationale.
2. The chain-signed audit log remains the single source of truth.
3. Existing audit readers continue to work; new fields are backward-compatible.
4. Regulators and auditors can export decision chains to PROV-O / RDF.
5. No new runtime authority is introduced; provenance records decisions, it does not make them.

## Non-goals

1. Replace existing signing, grants, capability bindings, or policy enforcement.
2. Add a Python, graph database, or heavy AI-platform dependency.
3. Build a general-purpose knowledge graph.
4. Adopt `tibet-core` or Semantica as a runtime dependency.

## Design

### Core types

```rust
/// Content-addressed decision record. Stored as a chain-signed audit event.
pub struct DecisionRecord {
    pub decision_id: DecisionId,
    pub version: u32,
    pub category: DecisionCategory,
    pub actor: ActorRef,
    pub scenario: DecisionScenario,
    pub reasoning: String,
    pub outcome: DecisionOutcome,
    pub confidence: Option<f64>,
    pub timestamp: DateTime<Utc>,
    pub causal_links: Vec<CausalLink>,
    pub metadata: DecisionMetadata,
}

/// Principal that authorized the decision.
pub struct ActorRef {
    pub principal: String,        // human/on-call/service identity
    pub key_id: String,           // signing key identifier
    pub key_role: Option<ControlKeyRole>, // Promoter / Inventory / Orchestrator
}

/// What triggered the decision.
pub struct DecisionScenario {
    pub plan_id: Option<PlanId>,
    pub workload_addr: Option<SemanticAddress>,
    pub capability_id: Option<CapabilityId>,
    pub approval_id: Option<ApprovalRequestId>,
}

/// Link to a prior decision.
pub struct CausalLink {
    pub relation: CausalRelation, // Caused, Influenced, PrecedentFor, Invalidated
    pub decision_id: DecisionId,
}

/// Free-form compliance metadata.
pub struct DecisionMetadata {
    pub ticket_ref: Option<String>,
    pub policy_ref: Option<String>,
    pub regulation_scope: Vec<String>, // e.g. ["EU-AI-Act", "NIS2"]
}

/// Cryptographic binding to the existing audit substrate.
pub struct AttestationBinding {
    pub plan_id: Option<PlanId>,
    pub workload_addr: Option<SemanticAddress>,
    pub artifact_digests: BTreeMap<String, String>,
    pub audit_entry_hash: String,
    pub signer_pubkey: String,
}
```

### Serialization

`DecisionRecord` serializes as an `AuditEntry` event under a new `decision_record` label or as an enriched payload on existing events. The canonical JSON of the decision body (minus `decision_id`) is SHA-256 hashed to produce `DecisionId`, so the record is content-addressed and independently verifiable.

### Storage

- **Source of truth:** existing chain-signed `tenant.jsonl` / `local.jsonl`.
- **Derived index:** optional content-addressed decision store (append-only, rebuildable from the chain).

### Export

- **PROV-O / RDF / Turtle:** read-only exporter over the chain-signed log.
- **Optional TIBET-compatible JSON:** future interoperability serialization, not a runtime dependency.

## Phases

### Phase 0 — RFC and ADR

- [ ] Write `specs/plans/330-decision-provenance-layer.md` (this file).
- [ ] Write or update ADR defining `DecisionRecord`, `AttestationBinding`, PROV-O mapping, and explicit rejection of external provenance platforms as dependencies.
- [ ] Identify all decision points in `mvm-hostd`, `mvm-agentd`, and `mvmd` control-plane paths.
- [ ] Define backward-compatibility contract for `tenant.jsonl` readers.
- [ ] Get RFC approved.

### Phase 1 — PROV-O export of existing events

Read-only exporter; no new runtime instrumentation.

- [x] Add `mvm-contract::provenance` module with PROV-O entity/activity/agent types.
- [x] Implement exporter that reads existing `tenant.jsonl` and emits Turtle/RDF.
- [ ] Map existing events:
  - `plan.admitted` → `prov:Activity`
  - host signer → `prov:Agent`
  - `plan_id` → `prov:Entity`
- [x] Add round-trip tests: export → parse → verify signatures still hold on original chain (partial: unit tests added; full chain-signature verification deferred to Phase 3).
- [ ] Validate output with a compliance/ops stakeholder.
- [ ] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`.

### Phase 2 — Enrich existing audit events

Add structured decision fields to events that already exist.

- [x] Extend `ApprovalResponse` with `reason: Option<String>` and `ticket_ref: Option<String>`.
- [x] Extend `AgentApprovalEvent::Responded` with the same fields.
- [x] Extend `AuditEntry` with optional `authorizer_principal`, `authorization_reason`, `authorization_ticket_ref`; chain-signed plan events carry the same metadata via canonical labels so existing `PlanAuditEntry` readers keep working.
- [x] Emit admission **refusals** as chain-signed events with rationale.
- [x] Emit orchestrator `ControlKey` usage events (kid, role, action, authorizer principal).
- [x] Add serde round-trip and schema tests for all enriched types.
- [ ] Add negative tests: missing rationale on required events fails validation (deferred to Phase 3 when `DecisionRecord` validation rules land).
- [x] Update audit reader (`mvm-client::audit`) to surface new fields.
- [x] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`.

### Phase 3 — DecisionRecord API and content-addressed store

- [ ] Add `DecisionRecord`, `ActorRef`, `DecisionScenario`, `CausalLink`, `DecisionMetadata`, `AttestationBinding` types to `mvm-contract::provenance`.
- [ ] Implement `DecisionId` as SHA-256 of canonical decision body.
- [ ] Add `DecisionRecordBuilder`.
- [ ] Integrate `DecisionRecord` emission into `AuditEmitter` for admission/launch/egress/checkpoint/approval events.
- [ ] Add optional content-addressed decision store under `~/.mvm/decisions/` (rebuildable from chain).
- [ ] Ensure decision store is derivable from the chain-signed log.
- [ ] Add tests: builder, content-address stability, store rebuild, chain verification.
- [ ] Update CLI `mvmctl trust audit` subcommands to optionally include decision records.
- [ ] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`.

### Phase 4 — Query API and causal chains

- [ ] Implement `trace_decision_chain(decision_id)` over the decision store.
- [ ] Implement `analyze_decision_impact(decision_id)` (forward traversal).
- [ ] Implement `find_similar_decisions(scenario)` by category and artifact digests.
- [ ] Add read-only query commands to `mvmctl` or `mvm-client`.
- [ ] Add property-based tests for chain traversal.
- [ ] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`.

### Phase 5 — Optional standards interoperability

- [ ] Evaluate `tibet-core` as an export format (not dependency) for decision records.
- [ ] If valuable, add optional TIBET-JSON serializer without taking a crate dependency.
- [ ] Evaluate C2PA / in-toto / SPDX relevance for build-time vs runtime provenance.
- [ ] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md`.

## Testing strategy

- **Serde round-trip tests** for every new type.
- **Content-address stability** tests: same decision body → same `DecisionId`.
- **Chain verification** tests: decision records verify as part of the existing chain.
- **Rebuild tests:** delete decision store, replay chain, store recovers.
- **PROV-O export tests:** parse generated Turtle with an RDF library in tests only.
- **Negative tests:** refusal events include rationale; missing rationale on required events fails validation.
- **Regression tests:** existing audit readers still parse old and new `tenant.jsonl`.

## Guardrails

- Do not introduce a Python / graph DB / LLM dependency.
- Do not make the provenance layer an authority.
- Do not store secrets, tokens, or PII in decision metadata.
- Do not break the existing chain-signed log format.
- Keep the decision store derivable from the chain.
- Run `cargo clippy --workspace -- -D warnings` after every phase.
- Run `cargo test --workspace` after every phase.

## Risks

| Risk | Mitigation |
|---|---|
| Schema churn in early versions | Version `DecisionRecord`, keep it an enrichment on existing events, not a replacement. |
| PII / secrets in rationale | Validation rejects or redacts known patterns; field-level encryption optional. |
| Performance cost of decision store | Store is optional and rebuildable; index lazily. |
| Regulator wants a specific format | PROV-O export first; TIBET/C2PA/in-toto as optional serializers later. |
| Scope creep into policy engine | Strict non-goal: provenance records only; enforcement stays in existing code. |

## Open questions

1. Should human approvals require a `reason` field, or remain optional?
2. Which existing events beyond admission/launch/egress/checkpoint/approval should carry decision records in Phase 2?
3. Should the decision store be per-tenant or global?
4. Do we need retention / tombstone semantics for decision records under GDPR?
5. Is PROV-O the right primary export, or should we prioritize a simpler JSON-LD format first?

## Deliverables

- [ ] `specs/plans/330-decision-provenance-layer.md`
- [ ] Updated or new ADR
- [ ] `crates/mvm-contract/src/provenance.rs` (types, builder, exporter traits)
- [ ] `crates/mvm-hostd/src/audit/decisions.rs` (emitter integration)
- [ ] `crates/mvm-client/src/provenance/` (query + export CLI)
- [ ] `specs/sprint/delivery/330-decision-provenance-layer.md` (when complete)
- [ ] Updated `specs/SPRINT.md`
- [ ] Updated `specs/REFACTOR-STATUS.md`
