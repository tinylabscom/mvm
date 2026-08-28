# Research — NANDA-style agent receipts, authority, and conformance for mvm

**Status:** Research note; no implementation commitment
**Date:** 2026-08-06
**Owner:** mvm
**Source:** [github.com/Sharathvc23](https://github.com/Sharathvc23?tab=repositories) repositories, collectively aligned with Project NANDA
**Related:** ADR-001 (security posture), ADR-014 (signed audited execution plans), Plan 274 (witness rigor), Plan 276 (content-addressing conformance and defense), Plan 280 (transcript-root audit binding), Plan 288 (kernel cache verify-on-read)

## TL;DR

Sharathvc23 publishes a family of MIT-licensed Python reference implementations for an "Enterprise Internet of Agents" built around Project NANDA. The most relevant pieces for mvm are:

- **sm-arp** — signed, chainable receipts for what an agent did.
- **sm-aae** — signed pre-action authorization envelopes (authorized / denied / conditional).
- **sm-dat** — principal-signed, scoped, revocable delegation tokens.
- **sm-conformance** — signed, offline-verifiable conformance badges over a vector corpus.
- **sm-oversight** — M-of-N human-approval receipts riding on ARP.
- **sm-divergence / sm-resolver** — cross-registry corroboration to detect omission or equivocation.
- **sm-airlock** — capability-gated plugin sandbox.
- **sm-enclave** — speculative execution with staged commit/discard.

These are **not a direct fit** for mvm as dependencies: they are Python, working-draft protocols, and they target the agent-to-agent / human-to-agent layer rather than the VM isolation layer. But they are a **useful design reference** for making mvm's existing audit and admission evidence portable and agent-aware. The highest-value near-term moves are:

1. An mvm-native **ExecutionReceipt** — a signed, chainable proof of what was run, by whom, under what authority, built on mvm's existing Ed25519 chain-signing and `ExecutionPlan`.
2. An mvm-native **ConformanceBadge** — a signed, corpus-pinned, offline-verifiable export of the existing `model/claims.toml` / claim-witness program, letting a runtime or SDK prove which MVM-SEC claims it satisfies.

## What the NANDA family is

| Repository                                                      | One-line description                                                               | Relevance to mvm                                                                 |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| [sm-arp](https://github.com/Sharathvc23/sm-arp)                 | Agency Receipt Protocol — signed receipts any runtime can emit and verify offline. | Adjacent to mvm's chain-signed audit log; defines a portable receipt envelope.   |
| [sm-aae](https://github.com/Sharathvc23/sm-aae)                 | Attested Action Envelope — per-agent-chained pre-action authorization verdict.     | Could shape a signed admission/envelope step before a workload runs.             |
| [sm-dat](https://github.com/Sharathvc23/sm-dat)                 | Delegated Authority Token — scoped, time-bounded, revocable human-to-agent grant.  | Reference for delegation/attenuation if mvm ever needs multi-hop authority.      |
| [sm-conformance](https://github.com/Sharathvc23/sm-conformance) | Signed, offline-verifiable protocol-conformance badges.                            | Very close in spirit to mvm's `model/claims.toml` / claim-witness program.       |
| [sm-oversight](https://github.com/Sharathvc23/sm-oversight)     | Human approve/deny/escalate gestures with M-of-N quorum, as ARP receipts.          | Could inform a human-in-the-loop gate before production runs.                    |
| [sm-divergence](https://github.com/Sharathvc23/sm-divergence)   | Cross-registry omission/equivocation detection via multi-source corroboration.     | Relevant to artifact mirrors and content-addressed caches.                       |
| [sm-resolver](https://github.com/Sharathvc23/sm-resolver)       | Source-agnostic corroboration kernel (`Resolver[T]`, `View`, `Corroborator`).      | The diff/comparison primitive under `sm-divergence`.                             |
| [sm-airlock](https://github.com/Sharathvc23/sm-airlock)         | Capability-gated plugin sandbox (allowlist + rate limits + optional attestation).  | Conceptually adjacent to mvm's host-services broker and guest-agent verb grants. |
| [sm-enclave](https://github.com/Sharathvc23/sm-enclave)         | Speculative execution sandbox with staged side effects and commit/discard.         | Pattern for isolating agent tool side effects inside a microVM.                  |
| [sm-parc](https://github.com/Sharathvc23/sm-parc)               | Portable Agent Reputation Credential over receipts.                                | Longer-term: reputation over a workload's receipt history.                       |

All of these are Python, zero-to-few runtime dependencies, and explicitly framed as reference implementations rather than production services. They use Ed25519, JCS (RFC 8785), and `did:key` as the common signing layer.

## What mvm already has

| Capability                      | mvm primitive                                                  | Where it lives                                                        |
| ------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------- |
| Signed workload admission       | `ExecutionPlan` signed by the host signer                      | `crates/mvm-core/src/plan/`, `crates/mvm-hostd/src/plan_admission.rs` |
| Chain-signed audit log          | `AuditEmitter` + `FileAuditSigner`, per-tenant `tenant.jsonl`  | `crates/mvm-hostd/src/audit/emitter.rs`                               |
| Audit verifier parity           | Host + `no_std`/`wasm32` verifiers over a frozen signed corpus | Plan 274 WS4, `tests/vectors/audit-chain-v1.jsonl`                    |
| Merkle transparency root        | `SignedAuditRoot` over RFC-6962 tree                           | `crates/mvm-hostd/src/audit/emitter.rs`, `mvm_contract::merkle`       |
| Content-addressed plan identity | `plan_id` = SHA-256 over canonical plan body                   | `crates/mvm-core/src/plan/content_id.rs`                              |
| Content-addressed IR identity   | `WorkloadAddress` = `sha256(JCS(NFC(Workload)))`               | `crates/mvm-core/src/workload_address.rs`                             |
| Conformance claim ledger        | `model/claims.toml` + `xtask check-claim-catalog`              | `model/claims.toml`, `xtask/src/claims_ledger.rs`                     |
| Artifact verify-on-read         | `mvm_core::action::verify_artifacts_on_disk`                   | Plan 276 WS6 (#2053)                                                  |
| OCI provenance in audit         | Resolved digest + layer digest set recorded on `image.created` | `crates/mvm-hostd/src/audit/emitter.rs`                               |

mvm already owns the harder foundation: hardware-isolated microVMs, signed plans, chain-signed audit logs, content-addressed artifacts, and a claim/witness program. The NANDA work adds a vocabulary for making that evidence **agent-aware and portable**.

## Direct comparison on five questions

### 1. Execution receipts / audit logging

|                | NANDA (sm-arp)                                                            | mvm today                                                            |
| -------------- | ------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Unit of record | `receipt` — one agent action, signed by the agent, with `authority_chain` | `AuditEntry` — one control-plane lifecycle event, signed by the host |
| Verifiability  | Ed25519 + JCS + `did:key`; offline                                        | Ed25519 + chain signatures + Merkle root                             |
| Portability    | Runtime-agnostic envelope; any stack can emit/verify                      | Internal format; consumed by mvm tools                               |
| Authority      | `principal_did` + `authority_chain` of grants                             | Host signer + signed `ExecutionPlan`                                 |
| Denied actions | Not ARP's focus                                                           | Refusals are recorded (e.g., `stream.input_refused`)                 |

**Gap:** mvm records strong host-side evidence, but a workload operator who wants to prove _"this exact plan ran at this time under this authority"_ to an external auditor currently exports the internal audit log. A standardized receipt shape would make that proof portable.

### 2. Pre-action authorization

|                | sm-aae                                  | mvm today                                  |
| -------------- | --------------------------------------- | ------------------------------------------ |
| Verdict values | `authorized` / `denied` / `conditional` | Binary admit/refuse at `plan_admission`    |
| Chainability   | Per-agent hash chain (`prev_hash`)      | Hash chain via `prev_hash` on `AuditEntry` |
| Scope          | Any action under policy                 | Workload launch and runtime grants         |

**Gap:** mvm has no explicit "conditional" admission state, and refusals are not always first-class signed artifacts. Making a denied admission a signed, verifiable record (rather than an absent event) would help agentic consumers retry or escalate correctly.

### 3. Delegation and attenuation

|             | sm-dat                                                             | mvm today                                                              |
| ----------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| Grantor     | Principal's key (human)                                            | Host signer                                                            |
| Scope       | Action categories, per-action caps, per-period budgets, allowlists | `ExecutionPlan` fields: egress allowlist, mounts, secrets, verb grants |
| Revocation  | Revocation list URL + `INDETERMINATE` if unknown                   | Not currently modeled for principal grants                             |
| Attenuation | Child grant cannot widen parent                                    | Not applicable — single-hop host-signed plans                          |

**Gap:** mvm plans are single-hop. If a user ever needs to delegate plan-issuance authority (e.g., CI runner issues a sub-plan scoped by a principal grant), the DAT three-valued verdict and attenuation check are a clean reference.

### 4. Conformance badges

|                      | sm-conformance                                                | mvm today                                       |
| -------------------- | ------------------------------------------------------------- | ----------------------------------------------- |
| Signed envelope      | Ed25519 over JCS payload                                      | N/A (claims are ledger rows, not signed badges) |
| Corpus pinning       | `suite_digest` = SHA-256 over vector corpus                   | `model/claims.toml` witnesses + feature files   |
| Offline verification | Anyone verifies against embedded `did:key`                    | CI gates + `xtask` checks                       |
| Distribution         | `.nanda/conformance.json` and `/.well-known/conformance.json` | Generated `CONFORMANCE.md`                      |

**Gap:** mvm's conformance is process-bound. A signed badge would let a runtime or SDK prove conformance offline — useful for fleet nodes, SDK distributions, or third-party auditors.

### 5. Human oversight

|                   | sm-oversight                                                 | mvm today                           |
| ----------------- | ------------------------------------------------------------ | ----------------------------------- |
| Mechanism         | M-of-N signed approve/deny/escalate gestures as ARP receipts | No explicit human-approval protocol |
| Binding           | Executed action cites the approval receipt                   | `ExecutionPlan` is host-signed      |
| Compliance target | EU AI Act Article 14                                         | N/A                                 |

**Gap:** mvm gates production workloads structurally (`MVM-SEC-15`: no shell/exec/PTY). A human-oversight receipt layer would be the natural next step if mvm adds "production run requires human approval."

## Deep dive — why `sm-conformance` is the closest fit

Of the NANDA repos, `sm-conformance` is the most immediately useful for mvm because it solves the same problem mvm is already solving with `model/claims.toml`, `xtask` gates, and `CONFORMANCE.md`: **how does a runtime prove it satisfies a set of mechanical claims, and how does a relying party re-verify that proof offline?**

### What `sm-conformance` actually specifies

The badge is a signed JSON envelope:

```json
{
  "payload": {
    "schema_version": 1,
    "runtime": "my-runtime",
    "protocol_versions": ["0.1"],
    "suite_digest": "sha256:<hex>",
    "completed_at": "2026-05-31T00:00:00+00:00",
    "exit_status": 0,
    "passed": 42,
    "failed": 0,
    "skipped": 0,
    "xfailed": 0,
    "xpassed": 0,
    "extensions": { "conformance.run.build": "<commit-sha>" }
  },
  "signed_by": "did:key:z6Mk...",
  "signed_at": "2026-05-31T00:00:00+00:00",
  "signature": "<base64-ed25519>"
}
```

The signature covers the **RFC 8785 (JCS)** canonicalization of the payload, with the value space constrained to ASCII strings, integers, booleans, null, and nested objects/arrays — no floats, no non-ASCII strings, no raw bytes. This is the same canonicalization discipline mvm already uses for `WorkloadAddress` and `plan_id`.

Key properties:

| Property                 | How it works                                                   | Why it matters for mvm                                                            |
| ------------------------ | -------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Corpus pinning**       | `suite_digest = sha256:<hex>` over the vector corpus           | A badge proves _which_ suite was passed, not just _that_ something passed.        |
| **Result gating**        | `failed`, `exit_status`, `errored`, `xfailed` must all be zero | Verification ≠ conformance; a verified badge with `failed: 99` is still rejected. |
| **Skip transparency**    | `skipped_vectors` enumerates skipped vectors                   | Prevents a runtime from skipping the adversarial vectors and still looking clean. |
| **Build binding**        | `extensions.conformance.run.build` names the tested build      | Prevents a regressed redeploy from riding an old badge.                           |
| **Trust ladder**         | Self-signed → lab counter-signed → attested CI                 | Honest about what a self-signature does and does not prove.                       |
| **Offline verification** | Needs only `did:key` + Ed25519 + JCS + SHA-256                 | No service, no transparency log, no PKI on the verification path.                 |

### Threat-model honesty

`sm-conformance` is explicit about what a self-signed badge does **not** prove:

> A valid signature proves only: "the holder of key `K` asserts that runtime `R` ran suite `S` and produced these counts at time `completed_at`." It does not prove the run happened, was honest, or is still true.

This maps directly to mvm's existing honesty discipline: `model/claims.toml` records claims and witnesses, and `xtask check-honesty` / `check-conformance` enforce that the claims are backed. A signed badge would be a _portable export_ of that ledger state, not a replacement for the ledger itself.

### Trust ladder and mvm's existing CI story

| `sm-conformance` rung  | mvm analogue                                                  | Gap                                                             |
| ---------------------- | ------------------------------------------------------------- | --------------------------------------------------------------- |
| **Self-signed**        | A runtime signs its own badge                                 | mvm has no signed badge today.                                  |
| **Lab counter-signed** | A neutral party re-runs mvm's test suite and signs the result | Could be a CI job or a third-party auditor.                     |
| **Attested CI**        | Badge produced in a SLSA/Sigstore/in-toto pipeline            | mvm already uses GitHub Actions; this is a natural composition. |

mvm's CI already runs the mechanical checks. The step that is missing is packaging the result as a signed, offline-verifiable artifact rather than a generated markdown file.

## A minimal design sketch — mvm ExecutionReceipt and ConformanceBadge

The smallest useful borrow is a signed **ExecutionReceipt** — a portable proof that a specific workload ran under a specific authority at a specific time — plus an **mvm ConformanceBadge** derived from the existing claim/witness program. Both should be thin semantic coatings over mvm's existing audit and conformance substrates, not new runtime authorities.

### Core concepts

- **`ExecutionReceipt`** — signed envelope with:
  - `receipt_id`: content-address of the canonical receipt body.
  - `plan_id`: the admitted `ExecutionPlan` content address.
  - `image_node_digest`: content-address of the image lineage node.
  - `agent_id` / `principal_did`: who asked for the run.
  - `host_did`: `did:key` of the host signer.
  - `action`: `{verb, resource, params}` — e.g., `{"verb": "run", "resource": "<plan_id>", "params": {"backend": "hvf"}}`.
  - `outcome`: `succeeded` / `failed` / `refused`.
  - `granted_by`: optional citation to a principal grant / oversight approval.
  - `prev_receipt_id`: hash link to the principal's or host's previous receipt.
  - `issued_at`: RFC 3339 timestamp.
  - `sig`: Ed25519 signature over JCS-canonical body.
- **`ExecutionReceiptLog`** — append-only, chain-signed store, derived from but not replacing the existing `AuditEntry` chain.
- **`ReceiptVerifier`** — offline verification: signature → chain continuity → plan_id recomputation → image digest match.
- **`ConformanceBadge`** — signed envelope derived from `model/claims.toml` and the claim-witness run, with:
  - `suite_digest`: SHA-256 over the mvm conformance vector corpus (feature files + frozen golden vectors + `model/claims.toml`).
  - `claims`: the set of MVM-SEC claim IDs covered by the badge.
  - `witness_kinds`: which kinds of evidence each claim rests on (`fn`, `ci`, etc.).
  - `passed` / `failed` / `skipped` / `errored` counts from the test run.
  - `extensions.mvm.build`: commit SHA or release tag of the runtime/SDK being tested.
  - `signed_by`: `did:key` of the runtime or SDK vendor.
  - `signature`: Ed25519 over JCS-canonical payload.
- **`BadgeVerifier`** — offline verification: signature → schema → `suite_digest` match → pass-gate → skip-policy → freshness/build binding.

The badge is **not** the source of truth for conformance; it is a signed export of the existing claim/witness ledger. The source of truth remains `model/claims.toml` + the actual tests + `xtask` gates. A badge detached from that context proves nothing.

### Layered architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  ExecutionReceipt export / query / verify                   │  ← new, read-only/query-only
├─────────────────────────────────────────────────────────────┤
│  ExecutionReceipt store (content-addressed)                 │  ← new derived store
├─────────────────────────────────────────────────────────────┤
│  ConformanceBadge (signed export of claim/witness ledger)   │  ← new derived artifact
├─────────────────────────────────────────────────────────────┤
│  Chain-signed audit log + claim/witness ledger (existing)   │  ← source of truth
│  tenant.jsonl / model/claims.toml / Merkle root / checkpoint│
└─────────────────────────────────────────────────────────────┘
```

The existing audit log and claim ledger remain the sources of truth. The receipt store and conformance badge are derived, content-addressed artifacts. A verifier can rebuild both from the existing sources.

### Example lifecycle as receipts

1. `plan.admitted` → emit `ExecutionReceipt` with `outcome: authorized`, `granted_by: <principal_grant>`.
2. `plan.launched` → emit receipt with `outcome: running`.
3. `plan.exited` → emit receipt with `outcome: succeeded` or `failed`, linking to launch.
4. `checkpoint.created` → emit receipt linking to launch and exit.
5. External auditor verifies the chain offline using only the host's `did:key`.

## What to adopt, what to reject

| NANDA idea                                                                   | Verdict for mvm                                                                                                                 |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Portable signed receipt envelope (ARP)                                       | **Adopt pattern** — define an mvm-native `ExecutionReceipt` over existing primitives.                                           |
| Pre-action authorization envelope with `authorized/denied/conditional` (AAE) | **Adopt pattern** — make admission verdicts explicit and signed, including denials.                                             |
| Principal-signed scoped delegation (DAT)                                     | **Defer** — only when a concrete multi-hop/offline delegation requirement appears; then evaluate against Macaroons/Biscuit/DAT. |
| Signed conformance badges (sm-conformance)                                   | **Adopt pattern** — let runtimes/SDKs ship an offline-verifiable badge for MVM-SEC claims.                                      |
| M-of-N human oversight receipts (sm-oversight)                               | **Defer** — only if mvm adds a human-approval gate for production workloads.                                                    |
| Cross-registry corroboration (sm-divergence)                                 | **Learn from** — useful if mvm ever supports artifact mirrors or a fleet registry.                                              |
| Capability-gated plugin sandbox (sm-airlock)                                 | **Learn from** — conceptually matches host-services broker allowlisting.                                                        |
| Speculative execution sandbox (sm-enclave)                                   | **Learn from** — pattern for staging agent tool side effects inside a microVM.                                                  |
| Python implementations as dependencies                                       | **Reject** — language/TCB/dependency mismatch.                                                                                  |
| `did:key` as the universal identity layer                                    | **Adopt selectively** — good for receipts; mvm's host signer can expose a `did:key` without changing internal key handling.     |

## Integration with existing plans

| Plan                                      | Connection                                                                                                            |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Plan 274 (witness rigor)                  | Receipt format should be added to the ≥2-verifier corpus work; a `no_std` verifier must be able to validate receipts. |
| Plan 276 (content-addressing conformance) | `ExecutionReceipt.receipt_id` and corpus pinning should use the σ/κ separation already introduced in WS7.             |
| Plan 280 (transcript-root audit binding)  | A receipt can carry a transcript root anchor, binding the signed proof to captured workload I/O.                      |
| Plan 288 (kernel cache verify-on-read)    | Receipts for kernel/cache artifacts could carry `StorageAddress` (κ) and `ProtocolDigest` (σ) bindings.               |

## Recommended phasing

| Phase                                | Status | Timing                | Work                                                                                                                                                                | Gate                                                                                                                                   |
| ------------------------------------ | ------ | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| **0 — RFC**                          | - [x]  | Approved              | Write an ADR or plan defining `ExecutionReceipt`, canonicalization (JCS), signature scheme, `prev_receipt_id` chain, and mapping to existing `AuditEntry` events.   | RFC approved. See [`specs/plans/298-nanda-receipts-and-conformance-badges.md`](../plans/298-nanda-receipts-and-conformance-badges.md). |
| **1 — Read-only receipt exporter**   | - [ ]  | Next sprint           | Add a tool/CLI command that converts existing chain-signed audit entries into signed `ExecutionReceipt`s. No new runtime instrumentation.                           | An exported receipt verifies offline end-to-end.                                                                                       |
| **2 — Runtime emission**             | - [ ]  | After Phase 1         | Emit receipts alongside `AuditEmitter` for admission/launch/exit/checkpoint events.                                                                                 | Existing audit tests pass; new receipt chain tests pass.                                                                               |
| **3 — Conformance badge**            | - [ ]  | Parallel to Phase 1–2 | Produce an mvm conformance badge over MVM-SEC vectors using the same JCS/Ed25519/`did:key` convention. Derived from `model/claims.toml` + the existing test corpus. | Badge verifies offline, pins the vector corpus, and gates `failed == 0`.                                                               |
| **4 — Human oversight / delegation** | - [ ]  | Triggered only        | Add oversight receipts or DAT-style delegation only when a concrete requirement appears.                                                                            | Concrete stakeholder need with a threat model.                                                                                         |

## Guardrails

- _*Do not add a Python / sm-* dependency._* Implement in Rust, reuse mvm's existing `ed25519-dalek` and `serde_jcs` stack.
- **Do not make receipts an authority.** They prove what happened; admission decisions stay in `plan_admission` and the host signer.
- **Do not break the existing audit log format.** New receipt events must serialize as backward-compatible `AuditEntry` events.
- **Do not store secrets in receipt metadata.** The same secrecy rules that apply to audit labels apply here.
- **Do not reuse receipt IDs across tenants.** Content addresses can act as a cross-tenant confirmation oracle.
- **Keep receipts derivable from the chain.** The chain-signed audit log remains the source of truth; the receipt store can be rebuilt from it.
- **Do not treat a conformance badge as the source of truth for claims.** The badge is a signed export of `model/claims.toml` + test results; the ledger and the actual tests remain authoritative.
- **Do not accept a self-signed badge as proof a run happened.** For admission of an untrusted runtime, require lab counter-signature or attested CI (the `sm-conformance` trust ladder).
- **No `Plan N` / `ADR-\d+` / `#NNNN` tokens in code comments.** Process references belong in this spec doc and commit messages, not in source comments.

## Bottom line

The Sharathvc23 / Project NANDA repositories are a useful **design reference** for making mvm's existing attestation substrate portable and agent-aware. They are not a dependency or direct implementation fit. Two next steps are equally actionable:

1. Define an mvm-native **ExecutionReceipt** format — a signed, chainable, offline-verifiable proof of what was run, by whom, under what authority — layered on the existing chain-signed audit log.
2. Define an mvm-native **ConformanceBadge** format — a signed, corpus-pinned export of the existing `model/claims.toml` / claim-witness program, letting a runtime or SDK prove which MVM-SEC claims it satisfies without requiring a live CI query.

Both should be implemented in Rust, reusing mvm's existing `ed25519-dalek` and `serde_jcs` stack, and both should remain derived artifacts over existing sources of truth rather than becoming new authorities.

The next artifact should be an RFC or plan, not code. The smallest executable increments after that are a read-only receipt exporter over the existing audit log, and a badge generator over the existing claim/witness ledger.
