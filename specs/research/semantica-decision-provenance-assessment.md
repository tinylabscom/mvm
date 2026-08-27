# Research — Semantica-style decision provenance with UOR/mvm attestation bindings

**Status:** Research note; no implementation commitment
**Date:** 2026-08-05
**Owner:** mvm
**Source:** [semantica-agi/semantica](https://github.com/semantica-agi/semantica) README/API surface, plus in-tree mvm audit/addressing code
**Related:** [`uor-hologram-cross-project-recon.md`](./uor-hologram-cross-project-recon.md), [`uor-addr-integration-assessment.md`](./uor-addr-integration-assessment.md), ADR-014 (signed audited execution plans), ADR-001 (security posture), Plan 280 (transcript-root audit binding)

## TL;DR

Semantica is a Python knowledge-graph / decision-intelligence platform. It is **not a direct fit** for `mvm` because of language, dependency weight, and trusted-compute-base mismatch. However, its **decision-provenance semantics** (`record_decision`, causal links, impact analysis, PROV-O export) are a useful reference for the next layer of `mvm`'s audit story.

`mvm` already owns the harder cryptographic foundation:

- content-addressed `ExecutionPlan` (`plan_id` = SHA-256 of plan body);
- UOR-ADDR-compatible `WorkloadAddress` for Workload IR (JCS + NFC + SHA-256);
- chain-signed audit entries with Ed25519;
- RFC-6962 Merkle roots;
- image/checkpoint lineage with hash-links.

The highest-value near-term move is **not** to adopt Semantica or build a full decision graph, but to write an RFC defining a minimal `DecisionRecord` + `AttestationBinding` model that re-uses those existing primitives. The first executable increment should probably be **PROV-O export of existing chain-signed audit events** — it validates the value proposition without new runtime instrumentation.

## What Semantica is

Semantica positions itself as an "open-source Palantir for AI agents." Its public surface includes:

- `ContextGraph` — typed entities, relationships, point-in-time snapshots;
- `record_decision()` — first-class decision objects with scenario, reasoning, outcome, confidence;
- `add_causal_relationship()` — `CAUSED`, `INFLUENCED`, `PRECEDENT_FOR` links;
- `trace_decision_chain()` / `analyze_decision_impact()` / `find_similar_decisions()`;
- `ProvenanceManager` — W3C PROV-O lineage on every fact;
- `RDFExporter` — Turtle / JSON-LD / N-Triples export;
- `ReteEngine` / `DatalogReasoner` — deterministic rule-based reasoning;
- `ConflictDetector` — conflicting-fact detection and resolution;
- Polyglot graph storage (Neo4j, FalkorDB, Blazegraph, Jena, RDF4J, etc.).

It is Python, depends on Faiss, graph databases, vector stores, LLM provider SDKs, and enterprise data platform connectors. It is an **application/data platform**, not an isolation/execution platform.

## What mvm already has

| Capability | mvm primitive | Where it lives |
| --- | --- | --- |
| Content-addressed execution identity | `plan_id` = SHA-256 over load-bearing `ExecutionPlan` fields | `crates/mvm-core/src/plan/content_id.rs` |
| Semantic content identity for structured IR | `WorkloadAddress` = `sha256(JCS(NFC(Workload)))`, UOR-ADDR JSON realization | `crates/mvm-core/src/workload_address.rs` |
| Chain-signed tamper-evident audit log | `AuditEmitter` + `FileAuditSigner`, Ed25519 per-tenant `tenant.jsonl` | `crates/mvm-hostd/src/audit/emitter.rs` |
| Merkle transparency root | `SignedAuditRoot` over RFC-6962 tree | `crates/mvm-hostd/src/audit/emitter.rs`, `mvm_contract::merkle` |
| Image/checkpoint lineage with hash-links | `ImageNode.node_digest` / `parent_digest`; `emit_checkpoint_forked` labels | `crates/mvm-hostd/src/audit/emitter.rs` |
| Normalized audit read API | `VerifiedAuditEvent`, `LocalAuditReader` | `crates/mvm-client/src/audit/` |
| Threat findings + gate decisions | `ThreatFinding`, `GateDecision` on `AuditEntry` | `crates/mvm-contract/src/policy/audit.rs` |

In other words, `mvm` already implements the UOR/Hologram-style attestation substrate: content addresses + signatures + hash-linked chains + Merkle roots. What it does not yet have is the **semantic decision layer** on top: first-class decisions, causal links, impact queries, and standards-based export.

## Direct comparison on the three questions

### 1. Audit logging

| | Semantica | mvm today |
| --- | --- | --- |
| Unit of record | Decision / entity / fact / relationship | `AuditEntry` / `LocalAuditEvent` with event name + labels |
| Verifiability | PROV-O graph + SHACL validation | Ed25519 chain signatures + Merkle root + content-addressed plan |
| Tamper evidence | Structural (graph shape) | Cryptographic (signature invalidates on mutation) |
| Granularity | Business/AI decisions | Control-plane lifecycle events |

Semantica's audit story is richer semantically but weaker cryptographically. `mvm` should not replace its chain-signed log with Semantica's Python graph store.

### 2. Attestation provenance

| | Semantica | mvm / UOR |
| --- | --- | --- |
| Provenance model | W3C PROV-O: who/what/when/source | Content-addressed artifacts + signed chain entries |
| Trust anchor | Source metadata, extractor confidence | Ed25519 host signer, recomputable content addresses |
| Binding | Links a fact to a source document | Links an output to exact bytes of plan/image/kernel/state |
| Standards | PROV-O, RDF, JSON-LD, Turtle, OWL, SHACL | In-house, but addresses are UOR-ADDR compatible |

Semantica can *describe* attestations in PROV-O. It cannot *generate* cryptographically bound attestation envelopes. The binding primitive in `mvm` is the existing content-address + signature pair, not anything Semantica supplies.

### 3. Policy decision records

| | Semantica | mvm today |
| --- | --- | --- |
| Decision model | `record_decision()` + causal links + precedent search + impact map | Quality gates (`GateDecision`), evaluation reports, admission events |
| Rules engine | Rete, Datalog, SPARQL, SHACL | Policy resolver, network egress rules, verb grants |
| Reasoning output | `ExplanationGenerator` with steps/justification | `GateDecision::Blocked { pattern, reason }`, audit labels |
| Export | PROV-O / RDF for regulator submission | JSONL + Merkle root; no standard semantic export |

This is the area where Semantica is strongest relative to `mvm` today. `mvm` records *that* a gate fired; it does not yet record decisions as first-class, causally linked, queryable objects with standardized export.

## A minimal design sketch (no code)

If `mvm` adds a decision-provenance layer, it should be a thin semantic coating over the existing audit substrate, not a new runtime authority.

### Core concepts

- **`DecisionId`** — content-addressed identifier derived from the canonical JSON of a decision body.
- **`DecisionRecord`** — category, scenario, reasoning, outcome, confidence, timestamp, causal links, metadata.
- **`AttestationBinding`** — binds the decision to `plan_id`, optional `WorkloadAddress`, artifact digests, chain entry hash, signer pubkey.
- **`CausalLink`** — `Caused`, `Influenced`, `PrecedentFor`, `Invalidated`.
- **`ProvenanceGraph`** — derived read-only view over decision records; supports `trace_decision_chain`, `analyze_decision_impact`, `find_similar_decisions`, `state_at`.
- **`ProvenanceExporter`** — deterministic PROV-O / RDF / Turtle / JSON-LD output.

### Layered architecture

```text
┌─────────────────────────────────────────────┐
│  ProvenanceGraph query + PROV-O export      │  ← new, read-only/query-only
├─────────────────────────────────────────────┤
│  DecisionRecord store (content-addressed)   │  ← new append-only store
├─────────────────────────────────────────────┤
│  Chain-signed audit log (existing)          │  ← source of truth
│  tenant.jsonl / local.jsonl, Merkle root    │
└─────────────────────────────────────────────┘
```

The chain-signed log remains the source of truth. The decision store is a derived, content-addressed cache of full decision bodies. A verifier can:

1. Recompute `DecisionId` from the decision body.
2. Find the matching chain-signed `AuditEntry` and verify its Ed25519 signature.
3. Recompute `plan_id` and `WorkloadAddress` from the plan/workload.
4. Confirm artifact digests against OCI/checkpoint manifests.

### Example lifecycle as decisions

1. `admission` — admits workload worker-v2 for tenant acme.
2. `launch` — launches on firecracker backend, causally linked to admission.
3. `egress_policy` — allows outbound TCP to api.example.com:443, influenced by launch.
4. `checkpoint_created` — freezes guest state, influenced by launch.
5. `plan_exited` — workload terminated, influenced by launch.

A forensic query `trace_decision_chain(egress_allow_id)` returns admission → launch → egress allow. A regulator export bundles the chain as PROV-O.

## What to adopt, what to reject

| Semantica idea | Verdict for mvm |
| --- | --- |
| First-class `DecisionRecord` with causal links | **Adopt pattern** — fills a real gap in queryability and regulator export. |
| PROV-O / RDF / Turtle export | **Adopt pattern** — standard compliance format, deterministic and signable. |
| `record_decision()` builder API | **Adopt pattern** — nicer ergonomics than raw audit labels. |
| Rete / Datalog rules engine | **Reject as duplicate** — `mvm` already has policy enforcement; the provenance layer should record decisions, not make them. |
| Python implementation, graph DB backends, vector stores | **Reject** — language/dependency/TCB mismatch. |
| LLM-based entity/relation extraction | **Reject** — non-deterministic, out of scope for a runtime provenance layer. |
| Conflict detection / deduplication over facts | **Defer** — useful only after the core decision graph exists and has enough data to conflict. |

## Integration with UOR/Hologram (if it ever matters)

The `AttestationBinding` struct should reserve an extension slot for a UOR/Hologram envelope without depending on UOR crates:

```rust
// Conceptual only
pub struct AttestationBinding {
    pub plan_id: PlanId,
    pub workload_addr: Option<WorkloadAddress>,
    pub artifact_digests: BTreeMap<String, String>,
    pub audit_entry_hash: String,
    pub signer_pubkey: String,
    // Future: UOR/Hologram inference attestation
    pub uor_attestation: Option<serde_json::Value>,
}
```

If `mvm` ever hosts `hologram-ai` workloads (see `uor-hologram-cross-project-recon.md` §5.4), the UOR `UorAttestationResult` (with `artifact_cid`, `store_cid`, `attestation_cid`) can sit in that slot and be causally linked to admission/launch decisions. No UOR crate dependency is required at the provenance layer — only a JSON-shaped field and a content-address verification routine `mvm` already implements.

## Recommended phasing

| Phase | Timing | Work | Gate |
| --- | --- | --- | --- |
| **0 — RFC** | Now (days) | Write `specs/plans/` or ADR defining `DecisionRecord`, `AttestationBinding`, store layout, PROV-O mapping, and explicit rejection of Semantica-as-dependency. | RFC approved. |
| **1 — PROV-O export of existing events** | Next sprint | Add a read-only exporter that converts the existing chain-signed audit log (`tenant.jsonl` entries) into PROV-O Turtle. No new runtime instrumentation, no new decision store. | A regulator/auditor stakeholder confirms the output is useful. |
| **2 — Decision record API** | After Phase 1 proves value | Introduce `DecisionRecordBuilder` and a content-addressed decision store; emit decisions alongside existing `AuditEmitter` calls for admission/launch/egress/checkpoint events. | Existing audit tests still pass; new decision graph tests pass. |
| **3 — Query API + rule checking** | After Phase 2 stabilizes | Add `trace_decision_chain`, `analyze_decision_impact`, `find_similar_decisions`, and lightweight policy-rule checks over the decision graph. | Concrete query from ops/compliance team is answerable. |
| **4 — UOR/Hologram interop** | Triggered only | Populate `uor_attestation` field for AI-microVM workloads if the `ai` command leaves deferred status. | Concrete `hologram-ai` hosting requirement. |

## Guardrails

- **Do not add a Python / Semantica dependency.** It violates the limit-dependencies rule and explodes the trusted compute base.
- **Do not make the provenance layer an authority.** It records and queries decisions; policy enforcement stays where it is today.
- **Do not store secrets in decision metadata.** The same secrecy rules that apply to audit labels apply here.
- **Do not deduplicate decision records across tenants.** Content addresses can act as a cross-tenant confirmation oracle (see `uor-hologram-cross-project-recon.md` §7.4).
- **Do not break the existing chain-signed log format.** New decision events must serialize as backward-compatible `AuditEntry` events.
- **Keep the decision store derivable from the chain.** The chain remains the source of truth; the store can be rebuilt from it.

## Bottom line

Semantica is a useful **design reference** for decision provenance, but not a **dependency** or **direct implementation** for `mvm`. `mvm` should borrow the semantics (first-class decisions, causal links, PROV-O export) and bind them to its existing UOR-compatible content addresses and chain-signed audit substrate.

The next artifact should be an RFC, not code. The smallest executable increment after that is PROV-O export of the audit log that already exists.
