# Plan: Execution Contract — Artifact Identity Qualification

Backing: preview
Validation: none

**Status:** Draft — awaiting PR review  
**Date:** 2026-08-25  
**Branch:** `feat/execution-contract-qualification`  
**Source:** `specs/research/MVM_Execution_Contract_Qualification_Answers.md`

This plan tracks the implementation work surfaced by answering the artifact-identity qualification questions in `specs/research/MVM_Execution_Contract_Qualification_Questions.docx`. The immediate goal is to close the gaps that matter most for MVM's execution-evidence story, without adopting an underspecified logical-identity dependency.

## Context

The qualification brief asked whether MVM's Execution Contract could become a future consumer of a typed artifact-identity / derivation layer. The answers showed that MVM is currently **digest-only and verification-first**: every load-bearing artifact is re-hashed at admission, the contract is a signed JSON schema, and the join between authorization and execution is the content-addressed `plan_id` carried through audit entries and receipts.

The answers also surfaced concrete gaps:

1. `ExecutionReceipt` is missing the fields that would make it a complete, self-contained auditable join point (exit state, output digests, log root, timing, admitted capabilities).
2. There is no explicit vocabulary for distinguishing recomputed, attested, asserted, and unverified identity claims.
3. Hardware-backed runtime attestation is stubbed, so the strongest claim — that the authorized workload actually ran inside a measured boundary — is not yet production-ready.
4. Continuation-state confidentiality needs guardrails against deterministic public addresses over low-entropy secrets.
5. Typed derivation edges and model/dataset artifact identity are not needed today but should be designed so they can be added without disturbing exact-byte verification.

## Goals

- Make the `ExecutionReceipt` the single, verifiable join point for authorization, artifact identity, runtime measurement, and observed execution.
- Add an explicit verification-status taxonomy before any logical-identity work lands.
- Close the measured-boot / hardware-attestation gap enough to support a real "what ran" claim.
- Put continuation-state confidentiality guardrails in place.
- Produce design documents for typed derivation edges and model/dataset artifact references, gated behind opt-in schema extensions.

## Non-goals

- Replacing exact-byte verification with logical identity.
- Adopting a UOR dependency before its Same relation and issuer-binding semantics are specified.
- Breaking existing plan signatures or audit-chain compatibility.

## Workstreams

### Workstream 1 — Complete the execution receipt

**Priority:** P0 — start immediately after this plan merges.  
**Why:** Q9 asks what a receipt contains. Today the receipt repeats `plan_id` and audit-root extensions but omits exit state, output digests, log root, timing, and admitted capabilities. These exist as separate audit entries; they need to be folded into the signed receipt (or as normative extensions) so a verifier can check one artifact.

- [x] **1.1 Audit the current receipt payload.**
  - Read `crates/mvm-core/src/receipt.rs`, `crates/mvm-hostd/src/audit/receipt_export.rs`, and `crates/mvm-hostd/src/audit/emitter.rs`.
  - List every audit entry type that carries information the receipt should summarize (`plan.exited`, `flow.egress.*`, etc.).
  - Decide whether each field belongs as a top-level receipt field or as a normative extension.

- [x] **1.2 Design the complete receipt schema.**
  - Added to `ExecutionReceipt`:
    - `started_at`, `ended_at`
    - `exit_code`
    - `granted_capabilities`
  - Deferred to a follow-up (needs new audit events or plan threading):
    - `output_digests: Vec<ArtifactDigest>`
    - `network_destinations` admitted (from egress/ingress policy)
  - The existing Merkle audit root remains available in extensions as
    `mvm.audit_root`; a separate `log_root` field can be added once workload
    logs are digested into a per-run Merkle tree.
  - Ensure the new fields are covered by the receipt's content-address (`receipt_id`).

- [x] **1.3 Implement receipt population in the audit exporter.**
  - Update `mvm-hostd/src/audit/receipt_export.rs` to derive the new fields from matching audit entries.
  - Ensure `plan.exited` entries map cleanly to `ExecutionReceipt` outcomes.

- [x] **1.4 Update receipt verification and archive export.**
  - Update `mvm-hostd/src/audit/receipt_archive_verify.rs` to check the new fields.
  - Update `.mvmev` archive construction in `mvm-hostd/src/audit/receipt_archive.rs` if needed.

- [x] **1.5 Add tests.**
  - Serde roundtrip tests for the new receipt shape.
  - Tests that `receipt_id` changes when a new field changes.
  - Integration test producing a receipt and asserting each new field is populated.
  - Negative test: a receipt with mismatched `log_root` or `output_digests` fails verification.

- [x] **1.6 Run gates.**
  - `cargo check --workspace`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `just check-gated`
  - Update this plan and `specs/SPRINT.md` with status.

**Acceptance criteria (v1):** A verifier can take a single `ExecutionReceipt` and confirm the contract identifier, exact artifact digests, admitted capabilities, start/end times, and exit code, all signed by the host. Network destinations and output digests remain as cited audit entries or deferred to a follow-up that adds the necessary audit events.

### Workstream 2 — Explicit verification-status taxonomy

**Priority:** P1 — do before any logical-identity extension lands.  
**Why:** Q6 warns that recomputed digests and asserted logical addresses must not look equally verified.

- [ ] **2.1 Define the taxonomy.**
  - Add a type such as:
    ```rust
    pub enum IdentityProvenance {
        Recomputed,   // host rehashed exact bytes
        Attested,     // issuer attestation verified
        Asserted,     // untested claim
        Unavailable,  // could not be checked
    }
    ```
  - Place it in `mvm-core` near the other identity types.

- [ ] **2.2 Wire it into artifact-reference extension points.**
  - Add a `provenance` field to any new artifact-reference extension struct.
  - Ensure receipts that cite logical identities include the provenance value.

- [ ] **2.3 Add tests and documentation.**
  - Unit tests for each variant.
  - Doc comment explaining why silent mixing is forbidden.

**Acceptance criteria:** It is impossible for a verified digest and an asserted logical address to be displayed or verified through the same code path without an explicit status marker.

### Workstream 3 — Hardware-backed runtime attestation

**Priority:** P1 — needed for the strongest "what ran" claim.  
**Why:** Q4 asks how authorization evidence joins execution evidence. The audit chain provides a host-signed join; TEE-backed measurement is currently stubbed.

- [ ] **3.1 Pick the first provider.**
  - Choose between TPM2, SEV-SNP, and TDX based on builder-VM and target-backend availability.
  - Document the choice in this plan.

- [ ] **3.2 Implement the provider.**
  - Replace `AttestationError::NotYetImplemented` in `crates/mvm-core/src/crypto/attestation/provider.rs` for the chosen provider.
  - Produce a real hardware quote/report.

- [ ] **3.3 Bind measurements to the plan.**
  - Wire `AttestationBody.boot_measurement` to the dm-verity root-hash instead of the placeholder.
  - Ensure `RuntimeAttestationChallenge` binds `plan_id`, image digest, and policy digest into the hardware report-data.

- [ ] **3.4 Integrate with assurance trial.**
  - Update `crates/mvm-contract/src/assurance/binding.rs` and `outcome.rs` to require the hardware evidence when the plan's `AttestationRequirement` demands it.

- [ ] **3.5 Add tests and evidence vectors.**
  - Mock-provider tests for verification logic.
  - End-to-end test producing a hardware-backed receipt on a supported backend (builder VM or HVF exception host).

**Acceptance criteria:** A plan with `attestation.mode = sev_snp` (or chosen provider) cannot launch unless the microVM produces a verifiable quote whose report-data binds the admitted `plan_id` and image digest.

### Workstream 4 — Continuation-state confidentiality guardrails

**Priority:** P1 — low-cost, high-impact safety rule.  
**Why:** The continuation-state section of the brief warns that deterministic public addresses over low-entropy secrets become confirmation oracles.

- [ ] **4.1 Audit current state handles.**
  - Review `SnapshotAt`, checkpoint code in `crates/mvm-runtime/src/checkpoint/`, and durable-session plans.
  - Confirm no external handle is derived deterministically from state content.

- [ ] **4.2 Add a design rule and helper.**
  - Add a `StateHandle` newtype that is randomly generated at creation time.
  - Document: external handles are random; server-side state is encrypted; tenant-scoped keyed identity stays internal.

- [ ] **4.3 Add a regression test.**
  - Two identical checkpoint payloads under the same tenant must receive different external handles.
  - A handle must not be derivable from the payload bytes.

**Acceptance criteria:** It is impossible to confirm a candidate continuation state by recomputing a deterministic public address.

### Workstream 5 — Design typed derivation edges

**Priority:** P2 — design now, implement only when a concrete use case appears.  
**Why:** Q7 asks whether the contract can express typed derivation relations. It cannot today, and this is the strongest future fit for a UOR-like layer.

- [ ] **5.1 Write an ADR or design note.**
  - Define `ArtifactDerivation` struct with:
    - `relation_type` (closed, versioned enum: `QuantizationOf`, `FineTuneOf`, `AdapterOf`, `ConversionOf`, `RelabelingOf`, …)
    - `subject_digest` and `object_digest` (exact byte identities)
    - optional logical subject/object identifiers
    - issuer key id
    - signature over the edge
    - revocation handle
  - Specify how edges would ride as an `ExecutionPlan` extension without changing exact-byte verification.

- [ ] **5.2 Prototype the type.**
  - Add the type behind a feature gate or in a design branch.
  - Add serde roundtrip and signature-verification tests.

- [ ] **5.3 Review with UOR stakeholders.**
  - Use the design note to drive the qualification conversation.

**Acceptance criteria:** A design document exists that MVM and UOR can review together; no production code path depends on the new type yet.

### Workstream 6 — Design model/dataset artifact reference profile

**Priority:** P2 — blocked on the deferred `ai` command, but the design should be ready.  
**Why:** Q1 and Q5 ask whether the answer differs for models/datasets. MVM has no such artifact type today.

- [ ] **6.1 Survey the deferred AI design.**
  - Read `specs/notes/2026-07-29-ai-command-design.md`.
  - Identify where model/dataset references would enter the `ExecutionPlan` or workload IR.

- [ ] **6.2 Write a design note.**
  - Define `ModelArtifactRef` / `DatasetArtifactRef` with digest, format tag, runtime capability requirements, and optional derivation edges.
  - Specify how it reuses the existing OCI provenance pipeline.

- [ ] **6.3 Prototype behind a feature gate.**
  - Add the types without wiring them into the active boot path.
  - Add roundtrip tests.

**Acceptance criteria:** A design document and gated type exist so the `ai` command can adopt them when implementation resumes.

### Workstream 7 — Close pre-spawn binary TOCTOU window

**Priority:** P3 — acknowledged gap, implement when platform work is scheduled.  
**Why:** Explored during admission/launch research; not directly raised by the qualification questions but part of the trust boundary.

- [ ] **7.1 Track existing work.**
  - Monitor `crates/mvm-hostd/src/supervisor/services/binary_integrity.rs` and `spawn.rs`.
  - File or update an issue for fd-based spawn (`fexecve` on Linux, `posix_spawn`-with-fd on macOS).

- [ ] **7.2 Implement when scheduled.**
  - Verify the binary into an fd and execute without re-opening the path.

**Acceptance criteria:** No time-of-check/time-of-use window between signature verification and process execution.

### Workstream 8 — Implement `--with-transcripts` evidence archives

**Priority:** P3 — designed, waiting for a production caller.  
**Why:** Mentioned in `specs/adrs/110-execution-receipt-evidence-archive.md` as not yet implemented.

- [ ] **8.1 Add a production caller for sealed transcripts.**
  - Wire `emit_transcript_sealed` into the runtime capture path.
  - Implement the `--with-transcripts` CLI flag on archive export.

- [ ] **8.2 Add tests.**
  - Export a `.mvmev` archive with transcripts and verify offline.

**Acceptance criteria:** A transcript archive can be produced, exported, and verified offline.

### Workstream 9 — Verified kernel-cache reads

**Priority:** P3 — tracked separately.  
**Why:** `specs/plans/288-kernel-cache-verify-on-read.md` already covers this.

- [ ] **9.1 Do not duplicate.**
  - Coordinate with Plan 288.
  - Adopt the `VerifiedKernel` type when it lands.

**Acceptance criteria:** Kernel cache reads are verified on every use, or the type system prevents unverified reads.

## Definition of done

- [ ] Workstream 1 is complete: receipts are complete and tests are green.
- [ ] Workstream 2 is complete: verification-status taxonomy exists and is wired to extension points.
- [ ] Workstream 3 has at least one hardware provider implemented and tested end-to-end.
- [ ] Workstream 4 is complete: continuation-state handles are opaque and regression-tested.
- [ ] Workstream 5 and 6 have approved design notes and gated prototypes.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes.
- [ ] `cargo test --workspace` passes.
- [ ] `just check-gated` passes.
- [ ] This plan and `specs/SPRINT.md` are updated with final status.

## Sequencing

1. Land this plan (the PR you are reviewing now).
2. Start **Workstream 1 — Complete the execution receipt**.
3. Parallel tracks after WS1 begins:
   - Workstream 2 (verification taxonomy) in parallel with WS1, since it affects how new receipt extensions are tagged.
   - Workstream 4 (continuation-state confidentiality) as a small, independent safety change.
4. Workstream 3 (hardware attestation) once a provider is chosen and test hardware is available.
5. Workstreams 5 and 6 as design documents, reviewed with UOR / AI stakeholders.
6. Workstreams 7, 8, and 9 picked up when their preconditions (platform scheduling, transcript sealing, Plan 288) are met.

## References

- `specs/research/MVM_Execution_Contract_Qualification_Questions.docx`
- `specs/research/MVM_Execution_Contract_Qualification_Answers.md`
- `specs/adrs/110-execution-receipt-evidence-archive.md`
- `specs/adrs/001-microvm-security-posture.md`
- `specs/refactor/12-semantic-address-pilot.md`
- `specs/notes/2026-07-29-ai-command-design.md`
- `specs/plans/288-kernel-cache-verify-on-read.md`
- `crates/mvm-core/src/receipt.rs`
- `crates/mvm-hostd/src/audit/receipt_export.rs`
- `crates/mvm-hostd/src/audit/receipt_archive.rs`
- `crates/mvm-hostd/src/audit/receipt_archive_verify.rs`
- `crates/mvm-core/src/crypto/attestation/provider.rs`
- `crates/mvm-contract/src/assurance/binding.rs`
- `crates/mvm-core/src/semantic_address.rs`
