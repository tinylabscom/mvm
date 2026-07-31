# Research — UOR-Foundation × Hologram-Technologies cross-project reconnaissance

**Status:** Research note; no implementation commitment
**Date:** 2026-07-30
**Owner:** mvm
**Source:** [UOR-Foundation](https://github.com/UOR-Foundation) and [Hologram-Technologies](https://github.com/Hologram-Technologies) GitHub orgs, deep-read at code level (43 repos surveyed, 24 read in depth)
**Related:** [`uor-addr-integration-assessment.md`](./uor-addr-integration-assessment.md), [`uor-framework-integration-exploration.md`](./uor-framework-integration-exploration.md)

## TL;DR

Three findings reframe the collaboration question:

1. **The "exceptional mathematics" is real but does not touch content-addressing.**
   `F1` is a serious, axiom-clean 116K-LOC Lean 4 formalization — but its payload
   is *open* Riemann-Hypothesis number theory (RH is honestly encoded as `none`,
   never asserted proven). The `atlas-12288` "atlas" is 44 lines of modular
   arithmetic. The E₈/12288/Monster vocabulary is typing scaffolding over a
   conventional canonicalize-then-hash core. It buys nothing over `sha256 +
   serde_jcs`. Confirmed independently by four separate deep reads.

2. **mvm is ahead on every security-critical primitive.** The entire ecosystem
   trusts content-hash-only ("the name is the hash", verify-by-re-derivation).
   There is **no per-bundle signing, no signed ExecutionPlan, no hash-linked
   signed audit chain, and no temporal/nonce admission** anywhere in it — Ed25519
   appears only in `hologram-network`'s wire layer and as unimplemented trait
   seams. mvm's `key_id`-pinned signed bundles, validity-window/nonce plans, and
   RFC-6962 Merkle audit chain are strictly stronger. Adopt their content-identity
   and dedup ideas as a **complement layered under** mvm's authenticity, never as
   a replacement for it.

3. **The prior disposition holds and extends.** The two existing UOR research
   notes already concluded "conform to UOR-ADDR JSON, take no crate dependency,
   reject Prism/atlas/PrimeShield." Deep reads confirm that. What those notes did
   not cover — and where the upside is — is **Hologram's runtime/control-plane
   layer** and the **ecosystem-wide conformance/honesty methodology**, which is a
   superset of mvm's claim ledger and the highest-ROI thing to borrow.

The chosen next focus (§6) is a concrete upgrade to mvm's claim→witness program,
drawn from patterns that five independent repos in the ecosystem re-invented.

## Scope and method

Ten reading agents shallow-cloned and read the assigned repos at source level
(README + Cargo manifests + crate roots + the addressing/canonicalization/crypto
modules + test counts), plus one agent grounding the mapping in mvm/mvmd's actual
code. Clusters: `uor-addr`; `UOR-Framework`+`template`; `prism`; the κ-registry
family; the VV/conformance governance; the `F1`/`atlas` mathematics; the newest
Rust cores (`uor-r4`/`uor-matmul`/`hologram-catX`); Hologram compute/AI
(`hologram`/`-ai`/`-apps`); Hologram runtime (`-sandbox`/`-vm`/`holospaces`/`-os`/
`-network`/`-storage`); and mvm/mvmd surfaces.

## The two layers

- **UOR-Foundation** — math + addressing + governance.
  - *Real & published:* `uor-addr` (the κ-label engine; crates.io/npm/pypi/C/wasm,
    Apache-2.0), `UOR-Framework`/`prism` (Witt-tower/2-adic ontology, hash-agnostic,
    **ships no crypto**), `kappa-registry` (a working OCI-`/v2/`-style content-addressed
    registry).
  - *Aspirational/empty:* `uor-vv`/`uor-conformance`/`uor-nanda` (single-commit,
    unlicensed scaffolds — the real governance content lives in
    `Hologram-Technologies/arch-map/standards`), and the `F1`/`atlas` math *as
    engineering*.
- **Hologram-Technologies** — the runtime built on UOR.
  - *Production-grade:* `hologram`/`hologram-ai` (κ-addressed verifiable inference,
    ~190K LOC), `holospaces` (a workload control plane — the mvmd analog),
    `hologram-network` (real P2P placement + the one Ed25519 signing surface),
    `hologram-storage` (BLAKE3 CAS + fail-closed `PipelineCertificate`).
  - The deep math and the real κ engine live in the **public** `hologram` repo
    (`Hologram-Technologies/hologram`), consumed by git-rev pin — e.g. `holospaces`
    pins its `hologram-substrate-core`/`-realizations`/`-runtime-wasmtime`/`-exec`
    crates at rev `18f553d`. (`hologram-sandbox` and `release` are the private repos,
    not the substrate.)

## Decision matrix

Verdict legend: **Adopt** (take the pattern/idea) · **Collaborate** (complementary,
worth a shared spec/interop) · **Study** (design reference) · **Reject/Skip** (do
not take).

| Primitive / repo | Maturity | mvm/mvmd surface | Verdict |
| --- | --- | --- | --- |
| `uor-addr` κ-label engine | Real, published, Apache-2.0 | `SemanticAddress`+`serde_jcs`; bundle addressing | **Study/align** — do not depend (drags `prism` + ~156 transitive crates incl. FHE/tensor; routes SHA-256 through `prism::crypto`). |
| Conformance/honesty methodology (`template`, `uor-matmul`, `hologram*/model`) | Real, multiple impls | claim ledger + `check-claim-catalog` + cucumber | **Adopt patterns** — §6. Highest ROI, no dependency. |
| `uor-registry` replayable ledger | Working prototype | claims catalog; provable-state-DAG | **Adopt pattern** — CI-write-only, content-addressed, `state_address` per run. |
| `hologram-ai` inference + `stream()` provider IF | Production | deferred `ai` command | **Collaborate/interop** — flagship opportunity (§5.4). |
| `holospaces` control plane + `hologram-network` scheduler | Active | mvmd tenants/pools/instances/placement | **Study** — concrete design reference (§5.5). |
| `hologram-sandbox` constraint-solver backend selection | Prototype | `VmBackend`/`builder_attempt_order`; mvmd placement | **Study** — cleaner than env/flag/auto-detect. |
| `kappa-registry` (verify-on-write, KBND delta, RBSR replication) | Real, single-node, auth-stub | networked bundle registry/fetch | **Study** — if a networked registry is ever needed. |
| `KappaDisk` content-addressed block device (sector dedup) | Real | mvm-fs; warm snapshot-fork (Plan 265) | **Study** |
| `UOR-Framework`/`prism` (`certify_from_trace`, Witt-tower) | Mature, DOI'd | ExecutionPlan/IR; audit re-verify | **Study only** — no crypto, no JCS, custom binary canonical form. |
| `F1`/`atlas`/12288/E₈/Monster math | F1 serious but RH **open**; atlas toy | none | **Skip as dependency/foundation** — borrow only F1's honesty-audit pattern. |
| Hash-only trust model; raw-KVM/wasm isolation | — | — | **Reject as replacement** — Firecracker+jailer+dm-verity+signed-plan is stronger. |

## Ranked integration opportunities

### 5.1 Conformance & honesty methodology upgrade — do first
Pattern adoption, no dependency. Detailed in §6. The single strongest signal in
the whole survey: five independent repos re-invented a discipline that is a
superset of mvm's claim ledger.

### 5.2 Content-addressed, replayable claims ledger
Project `specs/claims/catalog.md` into a content-addressed, CI-write-only form
(`uor-registry` pattern): each claim → canonical object → address; catalog →
`registry.json`; witness-mapping changes → `lineage.jsonl`; each gate run →
`log.jsonl` with a `state_address`. Upgrades drift-detection from text-grep to
address-equality; makes the ledger independently replayable. Natural extension of
the provable-state-DAG epic.

### 5.3 `uor-addr` — confirm "conform, don't consume", and harden
`uor-addr::json::address` *is* the `SemanticAddress` pattern, productionized.
Grounding correction: `SemanticAddress` **already NFC-normalizes before JCS**
(`crates/mvm-core/src/semantic_address.rs:168`), so the "NFC bug" one agent flagged
does not apply there; but `ir_hash`/`plan_id`/bundle paths do *not* NFC-normalize.
Almost certainly benign (structured/ASCII data), but it is exactly what a replay
golden vector (§6, U4) should pin. Low-risk borrows: the fixed-width ASCII-validated
`KappaLabel<N>` newtype as a hardening of `SemanticAddress`; keep pinning the
published UOR-ADDR fixtures. Collaboration thread: a *lightweight* uor-addr-conformant
crate that does not drag `prism`, so the wire label interoperates across all sibling
projects without the FHE/tensor tax. (Check `uor-addr-1` v0.1 on crates.io —
`uor-matmul` uses it behind an optional `kappa` feature; it may be the lighter cut.)

### 5.4 AI-microVM ↔ `hologram-ai` interop — flagship collaboration
The deferred `ai` command and Hologram's stack are complementary, not competing:
- `hologram-apps/apps/code/holo-code-providers.mjs` is "pluggable AI runtimes behind
  one `stream()` interface" — a ready template for the `ai`-command runtime seam.
- `hologram-ai` is a real HF-safetensors → `.holo` → wasm verifiable-inference runtime.
- **Thesis:** an mvm AI-microVM *hosts* a `hologram-ai` `.holo`/wasm workload as one
  pluggable runtime. Hologram brings content-addressed verifiable inference; mvm
  brings the hardware isolation, default-deny egress, and signed/chained audit their
  wasm-in-browser sandbox lacks. That division of labor is the collaboration.
- Honesty caveat: reject the "O(1) inference" framing. Only two mechanisms are
  genuinely O(1) (finite-domain activation LUTs `[u16;65536]`, ~28× and bit-identical;
  and content-label graph memoization). Their own `ADR-0019` documents that
  content-addressed elision collapses at long context, forcing a classical resident
  KV-cache. Real, not magic.

### 5.5 mvmd control-plane patterns from `holospaces` + `hologram-network`
Direct design reference for the fleet layer. `holospaces` maps tenant→`Operator`,
pool→`Roster`, instance→`Holospace` (identity = κ of its `Source`, so
reproducible-by-content), host→`Peer`, lifecycle→`Session` (boot →
suspend-to-κ-snapshot → resume → migrate-by-resolving-the-κ-closure → terminate —
parallels warm snapshot-fork Plan 265 + checkpoint lineage), control loop →
`Configuration/Directive` (monotonic `seq`, content-addressed, capability authz).
`hologram-network`'s capability∩load∩locality scheduler + 3× consistent-hash
replication is a concrete placement reference. Borrow the data model; keep mvm's
signed/audited authority (theirs is capability-only, unsigned).

## 6. Deep-dive — conformance & honesty methodology upgrade

**Why this one.** Five independent repos (`template`, `uor-matmul`, `hologram`,
`hologram-storage`, `uor-vv`/`arch-map`) converged on nearly the same claim-discipline,
and it is a superset of mvm's. mvm already has ~60% of it: `specs/claims/catalog.md`
+ `xtask check-claim-catalog` (witness existence + contiguity, typed `fn:`/`ci:`
witnesses) + the cucumber `mvm-conformance` harness + the mutation-witness gate. The
five deltas below are pure pattern adoption — no external dependency, no new crate —
and each aligns with a lesson mvm already learned the hard way.

### U1 — Evidence/honesty tiers per claim
- **Source:** `template/model/ids.toml` (`some-true`/`build`/`open`); Hologram
  evidence levels.
- **Now:** mvm distinguishes numbered claims 1–15 (Shipped) from Preview claim 16
  and the "promotion pending" claims 14/OCI, but only in prose.
- **Upgrade:** add an explicit `tier:` column to `catalog.md`:
  `shipped` (live `fn:`+`ci:` witness, in the ADR-001 numbered table) ·
  `preview` (machine-checked witness, not yet promoted to numbered prose) ·
  `open` (measured, never asserted). Gate in `check-claim-catalog`: `shipped`
  requires both witness kinds live; `open` must **not** appear in the numbered
  ADR-001 prose table.
- **Risk/effort:** low / small — a column + a parse rule.

### U2 — Prose over-claim meta-gate
- **Source:** `uor-matmul/crates/uor-matmul-conformance/src/meta.rs` (fails if an
  `open`/`some-true` claim's text uses assertive words). Governance analog: the
  `arch-map` "Public-claims coordination" rule.
- **Upgrade:** a lint (extend `check-claim-catalog` or a sibling `check-claim-prose`)
  that scans each `preview`/`open` claim's prose and **fails** on assertive verbs
  ("proves", "guarantees", "verified", "ensures", "cannot", "impossible") absent a
  `shipped` witness. Catches over-claiming in ADR-001 / claim docs. Complements the
  existing `check-no-spec-refs` prose gate and codifies the informal "no arm may
  claim proven" rule.
- **Risk/effort:** low / small — a word-list lint scoped by tier.

### U3 — Falsifiability / planted-defect table (machine-checked)
- **Source:** `template/VERIFICATION.md` (every gate must have a *recorded planted
  defect that fired*) — the exact machine-checked form of mvm's own
  "a test double that can't falsify its assumption is worthless" rule.
- **Now:** mvm already ships a mutation-witness gate (cargo-mutants, surface derived
  from the claims ledger).
- **Upgrade:** require every claim witness to carry a recorded red-proof. Add a
  `falsified_by:` reference per witness in `catalog.md` pointing at the
  mutation/negative-test that goes red when the witness is broken; gate fails if a
  witness has no recorded red-proof. Turns the mutation-witness gate from
  "nice-to-have" into the falsifiability ledger the ecosystem formalizes.
- **Risk/effort:** medium — needs a stable red-proof identifier per witness; builds
  directly on the existing mutation surface.

### U4 — Replay golden-vector lane
- **Source:** UOR Gate-4 four-category taxonomy (positive/negative/edge/**replay**);
  `uor-registry` `log.jsonl` `state_address` byte-stability discipline.
- **Now:** `SemanticAddress` pins 12 UOR-ADDR fixtures + one golden vector.
- **Upgrade:** a first-class frozen corpus (`tests/vectors/…`) of canonicalization
  inputs → expected addresses, checked byte-for-byte each PR across **every**
  content-address surface: `SemanticAddress`, `ir_hash`, `plan_id`,
  `bundle_sha256`/manifest, the audit `prev_hash` spine, and the RFC-6962 Merkle
  root. Catches silent canonicalization drift — `serde_jcs` version bumps, serde
  field reordering, the `ir_hash`/`plan_id` NFC question (§5.3) — before it changes
  an address in the field. This is the regression gate mvm currently lacks.
- **Risk/effort:** low / medium — mostly test data + a harness; no production code
  change.

### U5 — "≥2 independent implementations" oracle bar
- **Source:** UOR Gate-4 "positive/negative/edge/replay vectors must pass on ≥2
  independent implementations."
- **Now:** mvm already maintains multiple verifiers of the same wire format:
  `mvm_hostd` file-based `verify_audit_chain`, the `mvm_protocol` no_std/wasm
  `verify_audit_chain_bytes` (`MirrorEntry`, CI-pinned by
  `mvm_verify_matches_supervisor_chain`), and the riscv32 ESP32 verifier (edge tier).
- **Upgrade:** ship the U4 replay corpus as *one shared vector set* that host + wasm
  + ESP32 verifiers must all pass; record in `catalog.md` which claims are backed by
  ≥2 independent verifiers. Realizes UOR's "external oracle" bar with implementations
  mvm already ships — near-zero new code, high assurance.
- **Risk/effort:** low / small — wiring existing verifiers to a shared corpus.

### Sequencing
U1 and U4 first (foundational, lowest risk). U2 and U3 build on the U1 tier field.
U5 leverages verifiers that already exist. All five are pattern adoption; none takes
a UOR/Hologram crate dependency. A `specs/plans/` doc would be the next artifact once
this moves from research to execution (scan for the next free plan number first).

## 7. Content-addressing for attestation and defense

Follow-up analysis on three questions: is content-addressable data useful for mvm's
hash/attestation features; can a Hologram `holospace` run inside a microVM; and can
content-addressing defend against attacks.

### 7.1 Content-addressing supplies integrity — one of attestation's four properties

Attestation needs four properties; content-addressing supplies exactly one.

| Property | Question | Mechanism | mvm status |
| --- | --- | --- | --- |
| Integrity | *what* are the bytes | content-address (the hash **is** the tamper check) | shipped everywhere |
| Authenticity | *who* authorized them | Ed25519 `key_id` pinning | shipped |
| Freshness | *when* / is it stale | validity window + nonce replay store | shipped |
| Ordering | *in what sequence* | hash-linked signed audit chain + RFC-6962 Merkle | shipped |

The whole UOR/Hologram ecosystem stops at **integrity** (content-hash-only,
verify-by-re-derivation). mvm already layers the other three on top, so
content-addressing does not *complete* mvm's attestation — mvm completed it already.
UOR's additive value is narrow: semantic identity (already realized in
`SemanticAddress`), canonicalization rigor (§6 U4/U5), and coverage breadth (§7.2).

### 7.2 The coverage gap: content-address the kernel + cache, verify on read

mvm content-addresses the high-value artifacts (WorkloadIR, bundles, plans, audit
entries, OCI digests, dm-verity roothash) but still trusts-by-path in the build/runtime
cache. The standout is the **workload kernel**: it has no staleness check, so cache skew
currently mimics real bugs. Content-addressing the kernel + build-cache artifacts with
**verify-on-read (re-derivation on cache hit)** — the `KappaStore` discipline — closes
that class as both an attestation-coverage gain and a bug-class killer. Highest-value,
lowest-drama place to extend content-addressing.

### 7.3 Running a holospace inside a microVM: three scenarios, one worth doing

- **(a) The emulator holospace nested in a microVM — skip.** A `holospaces` holospace
  boots a guest in a *software CPU emulator* in wasm. A Firecracker microVM already
  virtualizes at hardware speed; nesting the emulator is double-virtualization for no gain.
- **(b) A wasm-container holospace nested in a microVM — real but niche.** The
  `hologram-space` `ContainerRuntime` runs wasm natively (wasmtime). Wrapping an
  *untrusted third-party* hologram workload in Firecracker is legitimate defense-in-depth
  — worthwhile only if mvmd is ever asked to host someone else's hologram workloads.
- **(c) Adopt the holospace object model over real microVMs — the win, needs none of
  their code.** Reproducible-by-content instance identity (κ of the `Source`), and
  especially **migrate-by-resolving-the-κ-closure** (ship the κ; the target resolves the
  content-addressed closure from a shared store; only missing blocks transfer) — a direct
  multiplier on warm snapshot-fork (Plan 265) and mvmd fleet migration.

No build blocker for (a)/(b): the κ engine + `ContainerRuntime` + emulator HAL are in
the **public** `hologram` repo (`holospaces` builds against them at git-rev pin
`18f553d`), so a wasm-container holospace is runnable today; the only gating factor is
whether mvmd ever needs to host third-party hologram workloads. **Net: don't run the
*emulator* holospace in a microVM (double-virtualization); the durable win is (c) — run
mvm's microVMs as if they were holospaces (content-addressed identity +
migrate-by-κ-closure) over real Firecracker isolation.**

### 7.4 Content-addressing as a defense — threat model

**Defends well (a real, specific attack class).** Substitution/tampering (any bit-flip
changes the address), cache poisoning (a poisoned entry has a different address and can't
masquerade), TOCTOU-on-content (the address pins exact bytes between check and use), and
supply-chain artifact swap *when the address is pinned in a signed manifest*. Converts
"trust the source" into "verify the bytes."

**The rule that must not break — address ≠ authorization.** A content-address says *what*
the bytes are, never *whether they may run*. A valid-but-malicious artifact has a perfectly
valid address. This is the structural weakness of the UOR/Hologram hash-only trust model
(their control plane authorizes by capability, not signature — cf. the "restored child is
unauthorizable" finding). mvm's defense is precisely that it gates on a signed, plan-bound
authorization *on top of* the content-address. Keep that ordering inviolable:
content-address for integrity, signature + plan for authority, **never the hash as
permission**.

**Highest-value defensive gain — canonicalization robustness (anti parser-differential).**
A content-addressed system is only as safe as its canonicalizer. If two nodes' canonicalizers
disagree (JCS byte-order vs UTF-16, NFC vs not, number canonicalization, duplicate-key
handling), an attacker crafts one input that addresses *differently on different nodes* — a
policy-bypass / parser-differential attack. UOR-addr's discipline (multi-format canonical
forms + NFC + 19k normalization vectors + ≥2 independent implementations) is exactly this
defense. It is the same work as §6 U4 (replay vectors across every surface) + U5
(host/wasm/ESP32 verifiers pass one corpus): those are not merely quality gates, they are
the anti-parser-differential control.

**Side channel to watch (multi-tenant) — cross-tenant dedup leak.** Content-addressed dedup
*across* tenants leaks "tenant A holds the same content as tenant B," and since an address
fingerprints known content, an attacker with a candidate file can confirm a guest holds it
by testing whether its address appears. κ-dedup is safe *within* a trust boundary and a leak
*across* one. mvm's per-tenant isolation already implies the right boundary; a future
content-addressed cache must not dedup across it.

### 7.5 Two convergent pursuits

Both reinforce §6 and require no UOR/Hologram dependency:

1. **Broaden content-addressing coverage + verify-on-read** — kernel/cache first (§7.2);
   closes a live attack *and* a bug class. Signing/authorization stays strictly on top.
2. **Harden canonicalization as an explicit defense** — replay vectors across every
   content-address surface + the ≥2-verifier oracle bar (§6 U4/U5), reframed as the
   anti-parser-differential control (§7.4).

## 8. Interop hazards and alignment points

Concrete cross-project mechanics that decide whether mvm and the UOR/Hologram
addresses can ever line up:

- **Hash-axis fragmentation — decide before any κ interop.** mvm standardizes on
  SHA-256; `uor-addr` defaults SHA-256 but `uor-r4`/`hologram` mint on the BLAKE3
  axis. A κ-label is `<axis>:<hex>`, so the *same bytes* get *different addresses* on
  different axes — mixing axes across a fleet fragments identity. Interop must pin one
  axis (SHA-256 keeps mvm unchanged; BLAKE3 buys speed + agility but re-addresses
  everything).
- **Canonical wire-form divergence.** Three address strings are in play: mvm's
  `sha256:<hex>`, UOR-Foundation's kappa `<axis>:<hex>`, and `uor:sha256:<hex>`
  (uor-registry). mvm's `sha256:<hex>` equals the kappa SHA-256 form byte-for-byte;
  the `uor:` prefix is the outlier. Picking the canonical form is a governance call.
- **`key_id` is the same *family*, not identical.** mvm `sha256(pubkey)[..32hex]`;
  kappa-registry `sha256("alg:" ‖ pubkey)[..16hex]`; hologram-catX `blake3(pubkey)`.
  All "hash-of-pubkey prefix" — a shared derivation is reachable but needs agreement
  on hash + prefix-input (raw vs alg-tagged) + truncation length.
- **Attestation canonicalization is the real shared-spec surface.** `uor-addr`'s
  `schema::codemodule_signed` admits in-toto Statement v1 / SLSA / sigstore JSON before
  addressing it — overlapping claim-11 sealed-volume SBOM/attestation and claim-14 OCI
  provenance. **Security naming trap:** those `signed`/`codemodule_signed` realizations
  verify **no** cryptographic signature (the predicate is a digest cost-model, not
  Ed25519). Anyone reading "signed" as "authenticated" opens a hole — signing stays
  mvm's job. Aligning on one in-toto/SLSA canonicalization is a genuine collaboration
  surface (alignment, not a code dependency).
- **Crypto agility (forward note).** Hologram carries dual-hash identity (sha256 primary
  + blake3 `alsoKnownAs`) + SRI + multibase/CIDv1. mvm is sha256-only. Not needed today,
  but the pattern is the migration path if SHA-256 ever has to move.
- **Distributed content-addressed transport (if mvmd ever needs it).** `kappa-registry`
  ships range-based set reconciliation (Meyer 2023) for anti-entropy replication;
  `hologram-network`/`hologram-catX` use iroh / iroh-blobs for p2p content-addressed
  transport. mvm's bundle transport has neither — these are the reference designs if
  fleet-scale artifact distribution becomes a requirement.

## 9. Patterns filed for later

Not opportunities to act on now, but worth recording against the provable-state-DAG and
mvmd identity work:

- **Producer/verifier code-independence (`certify_from_trace`).** The producer
  (catamorphism) emits a `Trace`; an *independent* verifier (anamorphism) re-certifies
  from the trace alone, sharing no evaluation code. A clean framing of "the audit
  verifier must not share code with the emitter" — reinforces §6 U5's ≥2-implementation
  bar.
- **Compile-time seal regime.** prism's `Validated`/`Grounded`/`Certified` are
  constructible only through the sanctioned path (`pub(crate)` ctors), so *holding the
  type is proof it came through admission* — a compile-time analog to mvm's runtime
  synthesize→sign→verify→admit gate; interesting for making illegal ExecutionPlan states
  unrepresentable.
- **Fail-closed proof artifacts.** `hologram-storage`'s `PipelineCertificate` refuses to
  issue unless resolution is complete (σ==1.0) — the "no partial proof" discipline the
  provable-state-DAG wants.
- **mvmd identity / agent-interop watch (track, don't adopt).** `hologram-os` builds
  operator identity on W3C DIDs + Verifiable Credentials; `uor-nanda` is an agent-interop
  ("Nanda") profile. If mvmd's tenant/operator identity or agent interop ever needs a
  standards-based story, these are the sibling reference points — currently unread in
  depth.

## 10. Maturity, stability, and what this recon did not read

- **Pre-1.0 churn.** The foundation is early: `uor-addr` 0.2, `uor-prism` 0.4,
  `uor-foundation` 0.5. Any dependency (even transitive) inherits a fast-moving,
  pre-1.0 API surface — a further reason the disposition is "conform, don't consume."
- **Now-private repos.** `hologram-sandbox` (the constraint-solver backend selection in
  §5 / the matrix) and `release` are private as of this read; their code is no longer
  externally readable, so treat those references as pattern-level only.
- **Deliberately not read (next reads if we go deeper):**
  - `uor-foundation` / `uor-foundation-sdk` — the *actual* κ-derivation engine that
    `uor-addr` and `prism` consume as a binary dep; never read directly. Required to
    evaluate the real UOR addressing engine rather than its façades.
  - `uor-addr-1` (crates.io) vs `uor-addr` — the lighter crate identity `uor-matmul` uses
    behind a `kappa` feature; unresolved whether it drops the prism tax.
  - `hologram-os` DID/VC identity layer and `uor-nanda` agent-interop profile.
  - `hologram-catX`'s internal `uor` crate (its own `[u8;32]`, possibly not `uor-addr`).

## 11. Proposed phasing and timeline

Most of the value is decoupled from any external party and can move now; the interop and
runtime items are **trigger-gated**, not calendar-gated. So the honest answer to "when
should we consider this" is: Phase 1 now, the rest when its trigger fires.

| Phase | Timing | Work | Gate / trigger |
| --- | --- | --- | --- |
| **0 — Decide & scope** | Now (days) | Adopt "conform, don't consume" as explicit policy; pin SHA-256 as the canonical axis; turn §6 U1–U5 + §7.5 defensive coverage into a `specs/plans/` doc. | None. |
| **1 — Methodology + defensive coverage** | Next 1–2 sprints | U1 tiers · U4 replay-vector lane · U2 prose over-claim gate · U3 falsifiability table · U5 ≥2-verifier oracle bar; content-address kernel + build cache with verify-on-read. All in-house, no dependency. | Phase 0 plan approved. |
| **2 — Interop alignment** | Mid-term, triggered | Agree axis + wire-form + in-toto/SLSA canonicalization with the sibling projects; read `uor-foundation` (the real κ engine); evaluate `uor-addr-1` (lighter crate). | A real second consumer of the addresses **and** a UOR/Hologram-side conversation. |
| **3 — Runtime / fleet / AI** | Long-term, opportunistic | holospace object model (migrate-by-κ-closure) into mvmd; `hologram-ai` interop for the deferred `ai` command; distributed transport (RBSR / iroh-blobs). | A concrete mvmd migration/scale requirement, or the `ai` command leaving deferred status. |

**Bottom line:** consider **Phase 1 now** — it is the highest-ROI, lowest-risk, fully
in-house work, and it doubles as security hardening (the two defensive pursuits). Hold
Phases 2–3 until their trigger appears; revisit this doc when it does.

## Guardrails — what to explicitly not do

- **Do not take the `uor-addr`/`uor-prism`/`uor-foundation` crate dependency.** It
  collides with the binding "limit dependencies / reuse workspace crypto" rule and
  duplicates `sha2`+`serde_jcs`+`ed25519-dalek` already in the tree.
- **Do not adopt hash-only trust as a replacement** for the signed+chained model.
- **Do not adopt their isolation** (raw-KVM, wasm-in-browser, software emulator).
- **Do not chase the 12288/E₈/RH math** as an engineering foundation — it is not one
  yet, by the authors' own honest admission.
- **Never dedup content-addressed storage across a tenant/trust boundary** — a
  shared address reveals two tenants hold identical content, and an address
  fingerprints known content (a cross-tenant confirmation oracle). Dedup within a
  boundary; never across it.
- **Licensing gap:** `uor-vv`/`uor-conformance`/`uor-nanda`/`arch-map` ship no
  LICENSE. Even as sibling projects, reusable text/scripts need a license before
  verbatim reuse.

## Appendix — per-repo anchors

Selected code anchors validated during the read (external repos cloned under
`/tmp/uor-research/`; mvm paths are in-tree).

| Anchor | What it shows |
| --- | --- |
| `uor-addr/crates/uor-addr/src/json/pipeline.rs` | κ-label minting = the `SemanticAddress` pattern, productionized |
| `uor-addr/crates/uor-addr/src/label.rs` (`KappaLabel<N>`) | Fixed-width ASCII-validated address newtype (hardening pattern) |
| `uor-addr` deps: `uor-foundation`/`uor-prism-*` (~156 transitive) | The substrate tax that makes the crate dep prohibitive |
| `kappa-registry/src/kappa.rs`, `bundle.rs` | Multi-axis content address + verify-on-write + KBND delta bundle re-verify |
| `kappa-registry/src/crypto/mod.rs` | `key_id = sha256(alg:pubkey)[..N]` — same construction as mvm |
| `uor-registry/README.md` + `log.jsonl` | CI-write-only content-addressed catalog + replayable `state_address` (§5.2) |
| `template/AGENTS.md` + `VERIFICATION.md` + `model/ids.toml` | The claim-tier + falsifiability discipline (§6 U1/U3) |
| `uor-matmul/crates/uor-matmul-conformance/src/meta.rs` | The prose over-claim meta-gate (§6 U2) |
| `F1/scripts/honesty_audit.sh`, `F1/F1Square.lean` | Self-enforcing "every claim's status is a machine-checked artifact" |
| `atlas-12288/lean/UOR/Prime/Structure.lean` | The 12288/R96 "atlas" is a 44-line modulo classifier (the substance behind the marketing) |
| `hologram/crates/hologram-compute/src/cpu/lut.rs` | The defensible core of "O(1) inference" (bit-identical activation LUT) |
| `hologram-ai/docs/adrs/0019-*resident-kv.md` | Content-addressed elision collapses at long context — the reality check |
| `hologram-apps/apps/code/holo-code-providers.mjs` | Pluggable-inference `stream()` provider IF (§5.4) |
| `hologram-sandbox/crates/hologram-sandbox-types/src/constraint.rs` | Hard/soft constraint backend selection (cleaner than `builder_attempt_order`) |
| `holospaces/crates/holospaces/src/{realizations,config,boot,disk}.rs` | κ-address, content-addressed `Configuration`, suspend-to-κ-snapshot, `KappaDisk` dedup |
| `hologram-network/src/compute/scheduler.rs` | Capability/load/locality placement + 3× replication (mvmd reference) |
| `hologram-storage/src/ontology/certificate.rs` | Fail-closed (σ==1.0) content-addressed proof artifact |
| mvm `crates/mvm-core/src/semantic_address.rs:59,152,168` | `sha256(JCS(NFC(IR)))`; already NFC-normalizes (corrects §5.3) |
| mvm `crates/mvm-core/src/plan/bundle.rs:616,954` | `verify_plan_bundle` / `read_and_verify_bundle` rejection ladders |
| mvm `crates/mvm-protocol/src/verify.rs:169`, `merkle.rs` | no_std audit-chain verifier + RFC-6962 transparency tree (the "≥2 impls" bar, §6 U5) |
