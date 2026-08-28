# NANDA-style execution receipts and conformance badges

**Status:** In progress. WS1–WS4 complete. WS5–WS6 pending.

**Date:** 2026-08-06
**Owner:** mvm
**Source:** [`specs/research/nanda-agent-evidence-protocols-assessment.md`](../research/nanda-agent-evidence-protocols-assessment.md)

**Goal:** Define and ship two portable, offline-verifiable attestation artifacts
built on mvm's existing Ed25519 chain-signing, JCS canonicalization, and
content-addressing primitives:

1. **`ExecutionReceipt`** — a signed, chainable proof that a specific workload ran
   under a specific authority at a specific time.
2. **`ConformanceBadge`** — a signed, corpus-pinned export of the existing
   MVM-SEC claim/witness program, letting a runtime or SDK prove which claims it
   satisfies without a live CI query.

Both are **derived artifacts** over existing sources of truth (the chain-signed
audit log and `model/claims.toml`). They do not become new runtime authorities.

## Why this plan exists

mvm already records strong host-side evidence: signed `ExecutionPlan`s, a
chain-signed audit log (`tenant.jsonl`), content-addressed artifacts, and a
claim/witness program (`model/claims.toml`). That evidence is currently
internal-format and process-bound. A workload operator who wants to prove to an
external auditor _"this exact plan ran at this time under this authority"_ must
export the internal audit log. A runtime or SDK vendor who wants to prove
conformance to MVM-SEC claims must point at CI logs and generated markdown.

The NANDA family of protocols (`sm-arp`, `sm-aae`, `sm-conformance`) defines
portable signed envelopes for agent actions and conformance. They are Python
reference implementations and not a dependency fit, but their design patterns
are directly applicable. This plan borrows the shapes and re-implements them in
Rust on mvm's existing cryptographic substrate.

## What already exists (do not rebuild)

| Capability                      | mvm primitive                                                | Where it lives                                                        |
| ------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------- |
| Signed workload admission       | `ExecutionPlan` signed by host signer                        | `crates/mvm-core/src/plan/`, `crates/mvm-hostd/src/plan_admission.rs` |
| Chain-signed audit log          | `AuditEmitter` + `FileAuditSigner`                           | `crates/mvm-hostd/src/audit/emitter.rs`                               |
| Audit verifier parity           | Host + `no_std`/`wasm32` verifiers over frozen signed corpus | Plan 274 WS4, `tests/vectors/audit-chain-v1.jsonl`                    |
| Merkle transparency root        | `SignedAuditRoot` over RFC-6962 tree                         | `crates/mvm-hostd/src/audit/emitter.rs`, `mvm_contract::merkle`       |
| Content-addressed plan identity | `plan_id` = SHA-256 over canonical plan body                 | `crates/mvm-core/src/plan/content_id.rs`                              |
| Content-addressed IR identity   | `WorkloadAddress` = `sha256(JCS(NFC(Workload)))`             | `crates/mvm-core/src/workload_address.rs`                             |
| Conformance claim ledger        | `model/claims.toml` + `xtask check-claim-catalog`            | `model/claims.toml`, `xtask/src/claims_ledger.rs`                     |
| JCS canonicalization + SHA-256  | Used for `WorkloadAddress`, `plan_id`, etc.                  | `serde_jcs`, `sha2`                                                   |
| Ed25519 signing                 | Host signer, audit chain                                     | `ed25519-dalek`                                                       |

## Non-goals

- _*No Python / sm-* dependency._* Implement in Rust, reuse mvm's existing
  `ed25519-dalek` and `serde_jcs` stack.
- **No new runtime authority.** Receipts and badges prove; they do not decide.
  Admission stays in `plan_admission` and the host signer.
- **No breaking change to the existing audit log format.** New receipt events
  must serialize as backward-compatible `AuditEntry` events.
- **No human-oversight or delegation protocol yet.** Those are deferred until a
  concrete requirement appears (Phase 4 in the research note).
- **No transparency log or PKI.** The base layer verifies offline with `did:key`
  - Ed25519 + JCS + SHA-256. Lab counter-signatures and attested CI may layer on
    top later.

## Design — ExecutionReceipt

An `ExecutionReceipt` is a signed JSON envelope that proves one step in a
workload lifecycle.

### Envelope

```json
{
  "payload": {
    "schema_version": 1,
    "receipt_id": "sha256:<hex>",
    "receipt_type": "plan.admitted",
    "plan_id": "sha256:<hex>",
    "image_node_digest": "sha256:<hex>",
    "agent_id": "agent-1",
    "principal_did": "did:key:z6Mk...",
    "host_did": "did:key:z6Mk...",
    "action": {
      "verb": "run",
      "resource": "sha256:<plan_id>",
      "params": { "backend": "hvf" }
    },
    "outcome": "authorized",
    "granted_by": null,
    "prev_receipt_id": null,
    "issued_at": "2026-08-06T00:00:00+00:00",
    "extensions": {}
  },
  "signed_by": "did:key:z6Mk...",
  "signed_at": "2026-08-06T00:00:00+00:00",
  "signature": "<base64-ed25519>"
}
```

### Field semantics

| Field               | Required | Meaning                                                                                             |
| ------------------- | -------- | --------------------------------------------------------------------------------------------------- |
| `schema_version`    | yes      | Const `1` for this version.                                                                         |
| `receipt_id`        | yes      | Content-address of the canonical receipt body (`sha256(JCS(payload))`).                             |
| `receipt_type`      | yes      | Wire-stable event name, e.g. `plan.admitted`, `plan.launched`, `plan.exited`, `checkpoint.created`. |
| `plan_id`           | yes      | The admitted `ExecutionPlan` content address.                                                       |
| `image_node_digest` | no       | Content-address of the image lineage node, when applicable.                                         |
| `agent_id`          | no       | Identifier for the acting agent/workload.                                                           |
| `principal_did`     | no       | `did:key` of the human or principal the agent acts for.                                             |
| `host_did`          | yes      | `did:key` of the host signer.                                                                       |
| `action`            | yes      | `{verb, resource, params}` describing what was attempted.                                           |
| `outcome`           | yes      | One of `authorized`, `running`, `succeeded`, `failed`, `refused`.                                   |
| `granted_by`        | no       | Citation to a principal grant or oversight approval receipt.                                        |
| `prev_receipt_id`   | no       | SHA-256 of the previous receipt for this principal/host chain.                                      |
| `issued_at`         | yes      | RFC 3339 UTC timestamp inside the signed payload.                                                   |
| `extensions`        | no       | Namespace-prefixed extensions; preserved but not required to be interpreted.                        |
| `signed_by`         | yes      | `did:key` derived from the signing public key.                                                      |
| `signed_at`         | yes      | RFC 3339 UTC timestamp **outside** the signed payload (forgeable, not trusted).                     |
| `signature`         | yes      | Base64 Ed25519 signature over `canonical_json(payload)`.                                            |

### Canonicalization and signing

- Canonical encoding is **RFC 8785 (JCS)** over the payload.
- Signed value space is constrained to ASCII strings, integers, booleans, null,
  and nested objects/arrays — no floats, no non-ASCII strings, no raw bytes.
- `signature = base64(Ed25519_sign(seed, canonical_json(payload)))` using
  standard base64 (RFC 4648 §4).
- `signed_by` MUST be the `did:key` derived from the signing public key
  (multibase base58btc over multicodec `0xed01 ‖ pubkey32`).

### Chain semantics

- Each receipt MAY reference its predecessor via `prev_receipt_id`.
- Two independent chains are expected: one per host signer (continuity of host
  operations) and one per principal/agent (continuity of agent actions).
- A verifier checks chain continuity by verifying each signature and confirming
  `prev_receipt_id` matches the previous receipt's `receipt_id`.
- Gap detection: a missing `receipt_id` in the expected sequence is treated as a
  break in the chain.

### Mapping to existing `AuditEntry` events

| Existing event         | Receipt type           | Outcome      |
| ---------------------- | ---------------------- | ------------ |
| `plan.admitted`        | `plan.admitted`        | `authorized` |
| `plan.launched`        | `plan.launched`        | `running`    |
| `plan.failed`          | `plan.exited`          | `failed`     |
| workload exit 0        | `plan.exited`          | `succeeded`  |
| `checkpoint.created`   | `checkpoint.created`   | `succeeded`  |
| `checkpoint.restored`  | `checkpoint.restored`  | `succeeded`  |
| `stream.input_refused` | `stream.input_refused` | `refused`    |

## Design — ConformanceBadge

A `ConformanceBadge` is a signed export of the existing claim/witness program.

### Envelope

```json
{
  "payload": {
    "schema_version": 1,
    "runtime": "mvmctl",
    "protocol_versions": ["0.1"],
    "suite_digest": "sha256:<hex>",
    "completed_at": "2026-08-06T00:00:00+00:00",
    "exit_status": 0,
    "passed": 42,
    "failed": 0,
    "skipped": 0,
    "xfailed": 0,
    "xpassed": 0,
    "errored": 0,
    "total_vectors": 42,
    "skipped_vectors": [],
    "claims": ["MVM-SEC-08", "MVM-SEC-09", "MVM-SEC-10"],
    "witness_kinds": {
      "MVM-SEC-08": ["fn"],
      "MVM-SEC-09": ["fn"],
      "MVM-SEC-10": ["fn", "ci"]
    },
    "extensions": {
      "mvm.build": "<commit-sha>",
      "mvm.branch": "main"
    }
  },
  "signed_by": "did:key:z6Mk...",
  "signed_at": "2026-08-06T00:00:00+00:00",
  "signature": "<base64-ed25519>"
}
```

### Field semantics

- `suite_digest`: SHA-256 over the mvm conformance vector corpus (feature files
  under `features/suites/`, frozen golden vectors, and `model/claims.toml`).
- `claims`: the set of MVM-SEC claim IDs covered by the badge.
- `witness_kinds`: which kinds of evidence each claim rests on, derived from
  `model/claims.toml`.
- `extensions.mvm.build`: commit SHA or release tag of the runtime/SDK being
  tested, so a regressed redeploy cannot ride an old badge.
- Counts follow the same honesty rules as `sm-conformance`: `failed`,
  `exit_status`, `errored`, `xfailed` must all be zero unless the verifier opts
  into signature-only mode.

### Trust ladder

| Rung               | Meaning                                                                                       |
| ------------------ | --------------------------------------------------------------------------------------------- |
| Self-signed        | Runtime/SDK vendor asserts its own conformance.                                               |
| Lab counter-signed | A neutral party re-runs the mvm test suite and signs an envelope wrapping the vendor's badge. |
| Attested CI        | Badge produced inside a trusted CI pipeline (SLSA/Sigstore/in-toto).                          |

For admission of an untrusted runtime, a relying party SHOULD require lab
re-run or attested CI.

## Workstreams

### WS1 — RFC and type design (Phase 0)

**Goal:** Produce an approved RFC with concrete types, canonicalization rules,
and wire formats. This workstream gates all others.

- [x] Finalize `ExecutionReceipt` payload schema and envelope.
- [ ] Finalize `ConformanceBadge` payload schema and envelope.
- [ ] Decide whether the host signer's `did:key` is derived from the existing
      host signer keypair or a separate receipt-signing keypair.
- [ ] Decide whether `ExecutionReceipt` events are emitted into the existing
      `tenant.jsonl` audit log, a separate `receipts.jsonl`, or both.
- [ ] Decide the corpus definition for the conformance badge `suite_digest`.
- [ ] Produce JSON Schemas for both envelopes.
- [ ] Add an ADR referencing this plan and the research note.
- [ ] Update `specs/research/nanda-agent-evidence-protocols-assessment.md` to
      mark Phase 0 complete and link to this plan.

**Deliverables:**

- Approved `specs/plans/298-nanda-receipts-and-conformance-badges.md` (this file).
- Approved ADR under `specs/adrs/`.
- JSON Schemas under `schema/` (or a new `schema/receipt-v0.json` and
  `schema/conformance-badge-v0.json`).

### WS2 — Core types and canonicalization

**Goal:** Implement the receipt and badge types in `mvm-core` with JCS
canonicalization and Ed25519 signing/verification.

- [x] Add `ExecutionReceipt` and `ConformanceBadge` types in `mvm-core`.
- [x] Implement JCS canonicalization helpers constrained to the admissible value
      space (ASCII strings, integers, booleans, null, nested objects/arrays).
- [x] Implement Ed25519 signing/verification with `did:key` derivation and
      parsing (new `did_key` module).
- [x] Add unit tests for canonicalization determinism, signature roundtrip,
      tamper detection, invalid value-space rejection, and chain continuity.
- [ ] Add frozen golden-vector files for both envelopes (deferred to WS3/WS5).

**Files likely touched:**

- `crates/mvm-core/src/receipt.rs` (new)
- `crates/mvm-core/src/conformance_badge.rs` (new)
- `crates/mvm-core/src/lib.rs`
- `crates/mvm-core/Cargo.toml`

### WS3 — Read-only receipt exporter

**Goal:** Add a tool/CLI command that converts existing chain-signed audit
entries into signed `ExecutionReceipt`s.

- [x] Add `mvmctl trust audit receipts export` (or similar) command.
- [x] Implement derivation from `AuditEntry` to `ExecutionReceipt`.
- [x] Ensure exported receipts verify offline end-to-end.
- [x] Add integration tests using the frozen audit corpus.

**Files touched:**

- `crates/mvm-hostd/src/audit/receipt_export.rs` (new)
- `crates/mvm-hostd/src/audit/mod.rs`
- `crates/mvm-cli/src/commands/ops/audit.rs`
- `crates/mvm-cli/src/commands/tests.rs`
- `tests/audit_total_coverage.rs`
- `tests/audit_receipt_export.rs` (new)
- `Cargo.toml` (dev-dependency for integration test)

### WS4 — Runtime emission of receipts

**Goal:** Emit `ExecutionReceipt`s alongside `AuditEmitter` for
admission/launch/exit/checkpoint events.

- [x] Extend `AuditEmitter` to optionally emit receipts.
- [x] Wire receipt emission into `plan.admitted`, `plan.launched`, `plan.exited`,
      and checkpoint events.
- [x] Ensure existing audit tests still pass.
- [x] Add receipt chain continuity tests.

**Files touched:**

- `crates/mvm-hostd/src/audit/receipt_store.rs` (new)
- `crates/mvm-hostd/src/audit/mod.rs`
- `crates/mvm-hostd/src/audit/emitter.rs`
- `crates/mvm-cli/src/commands/vm/up/admission.rs`
- `crates/mvm-cli/src/commands/vm/checkpoint.rs`
- `crates/mvm-cli/src/commands/vm/checkpoint/revert.rs`
- `crates/mvm-client/src/launch/mod.rs`

### WS5 — Conformance badge generator

**Goal:** Produce an mvm conformance badge over MVM-SEC vectors.

- [ ] Define the badge corpus (feature files + frozen vectors + `model/claims.toml`).
- [ ] Implement `suite_digest` computation.
- [ ] Add `mvmctl conformance badge generate` (or similar) command.
- [ ] Add verifier command `mvmctl conformance badge verify` with admission gates
      (`--expected-suite-digest`, `--expected-total-vectors`, `--max-skipped`,
      `--expected-build`, `--max-age-days`).
- [ ] Add integration tests with planted-defect badges.

**Files likely touched:**

- `crates/mvm-cli/src/commands/cmd_conformance.rs` (new)
- `xtask/src/check_conformance.rs` (badge generation hook)
- `model/claims.toml`

### WS6 — Documentation and registry conventions

**Goal:** Document the badge distribution convention and update conformance
artifacts.

- [ ] Document `.well-known/conformance.json` and `.nanda/conformance.json`
      conventions for mvm runtimes/SDKs.
- [ ] Update `CONFORMANCE.md` generation to mention badge availability.
- [ ] Update public docs under `public/src/content/docs/`.

## Security considerations

- **S1 — Receipts and badges are not authorities.** They prove what happened;
  they do not make admission decisions. The signed `ExecutionPlan` + host signer
  remain the sole admission authority.
- **S2 — Self-signed badges are self-attestation only.** A valid signature
  proves key-holding, not that a run happened. For untrusted runtime admission,
  require lab counter-signature or attested CI.
- **S3 — No secrets in receipts or badges.** Follow the same rules as audit
  labels: never include raw secrets, tokens, PII, or structured secret metadata.
- **S4 — Cross-tenant oracle.** Content-addressed receipt IDs can act as a
  cross-tenant confirmation oracle. Keep receipt stores within the per-tenant
  boundary.
- **S5 — Freshness from signed timestamps only.** `signed_at` and
  `countersigned_at` sit outside the signed payload and are forgeable. Gate
  freshness on `completed_at` / `issued_at` only.
- **S6 — Verify-on-read for derived stores.** A receipt store or badge cache hit
  must re-verify the signature and content address; a mismatch is a tamper/skew
  signal and must fail closed.
- **S7 — No breaking change to existing audit format.** New receipt events must
  serialize as backward-compatible `AuditEntry` events.

## Global constraints

- Work in a dedicated worktree per workstream after WS1 is approved; git only
  from the main checkout (`git -C <wt-abs>`).
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments.
- Rust: zero clippy warnings, no `unwrap()` in production code, nightly
  `rustfmt` before push.
- Every new function/type ships with tests: positive path, negative path, edge
  cases.
- Every new `xtask` gate is added to **both** `.github/workflows/ci.yml` and
  `.github/workflows/ci-full.yml` Lint jobs.
- Every new gate gets a falsifiability row in `specs/VERIFICATION.md`.
- Tick this plan's checkboxes and update `specs/SPRINT.md` +
  `specs/REFACTOR-STATUS.md` in the same commit as the work.

## Sequencing

1. **WS1 (RFC)** — must complete and be approved before any code work.
2. **WS2 (core types)** — independent of WS3/WS4/WS5; can start as soon as WS1
   approves the schemas.
3. **WS3 (read-only exporter)** and **WS5 (conformance badge)** — parallel;
   both depend only on WS2.
4. **WS4 (runtime emission)** — depends on WS3 proving the derivation mapping
   is correct.
5. **WS6 (docs)** — final polish, can proceed in parallel with WS4/WS5.

## Bottom line

This plan defines an mvm-native **ExecutionReceipt** and **ConformanceBadge**
built on existing Ed25519/JCS/SHA-256 primitives. The artifacts make mvm's
existing audit and conformance evidence portable and agent-aware without
becoming new authorities or taking external dependencies. Start with WS1; do not
schedule WS2–WS6 until the RFC is approved.
