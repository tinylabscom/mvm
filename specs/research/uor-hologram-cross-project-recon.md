# Research — UOR-Foundation × Hologram-Technologies cross-project reconnaissance

**Status:** Research note; no implementation commitment
**Date:** 2026-07-30
**Owner:** mvm
**Source:** [UOR-Foundation](https://github.com/UOR-Foundation) and [Hologram-Technologies](https://github.com/Hologram-Technologies) GitHub orgs, deep-read at code level (43 repos surveyed, 24 read in depth)
**Related:** [`uor-addr-integration-assessment.md`](./uor-addr-integration-assessment.md), [`uor-framework-integration-exploration.md`](./uor-framework-integration-exploration.md)
**Updated:** 2026-07-31 — added §7.6 (data-plane provability at the vsock chokepoint, from a code-grounded read of the sealed-transcript ↔ audit-chain binding), §7.7 (identity & permissions in the packet — signed capability vs hashed claim), and a §9 note on a machine-checked Lean-4 reference spec as the third verifier.
**Updated:** 2026-08-01 — a second, deeper pass (upstream crate source + primary literature, not just repo-level reads) **reverses finding 2** and adds four sections: §7.8 (σ/κ separation and the transform descriptor), §7.9 (verify-on-read as the founding definition, with the measured corruption rates behind it), §7.10 (deduplication scope as a side-channel decision), and §7.11 (reconciliation prerequisites among mutually distrusting peers). The original finding 2 — "mvm is ahead on every security-critical primitive" — was drawn from a survey that missed `kappa-registry`'s enforcement surface; see §7.1.

## TL;DR

Three findings reframe the collaboration question:

1. **The "exceptional mathematics" is real but does not touch content-addressing.**
   `F1` is a serious, axiom-clean 116K-LOC Lean 4 formalization — but its payload
   is *open* Riemann-Hypothesis number theory (RH is honestly encoded as `none`,
   never asserted proven). The `atlas-12288` "atlas" is 44 lines of modular
   arithmetic. The E₈/12288/Monster vocabulary is typing scaffolding over a
   conventional canonicalize-then-hash core. It buys nothing over `sha256 +
   serde_jcs`. Confirmed independently by four separate deep reads.

2. **Attestation coverage across the ecosystem is asymmetric, and integrity is
   the shared gap.** *(Revised 2026-08-01 — this replaces "mvm is ahead on every
   security-critical primitive", which the first pass got wrong.)* `kappa-registry`
   does enforce authenticity, freshness and ordering: closed-constructor asserter
   anchors held by a compile-fail test, hybrid-logical-clock watermarks giving
   O(1) bulk invalidation before a timestamp, and an Ed25519-signed epoch chain
   over a seven-leaf, domain-separated, backward-linked Merkle root with per-leaf
   selective disclosure. What **no** surveyed system enforces is **integrity on
   read**: `kappa-registry` verifies at four of thirteen write paths and at no read
   path, and mvm's workload kernel and build cache are trusted-by-path for the same
   reason. That is the one property a content address exists to supply, and it is
   unenforced everywhere. mvm's `key_id`-pinned signed bundles, validity-window/nonce
   plans and RFC-6962 Merkle audit chain remain strong and stay the authority layer —
   but "mvm is ahead" was the wrong conclusion, and the gap is shared, not theirs.

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
| `uor-addr` κ-label engine | Real, published, Apache-2.0 | `WorkloadAddress`+`serde_jcs`; bundle addressing | **Study/align** — do not depend (drags `prism` + ~156 transitive crates incl. FHE/tensor; routes SHA-256 through `prism::crypto`). |
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
`uor-addr::json::address` *is* the `WorkloadAddress` pattern, productionized.
Grounding correction: `WorkloadAddress` **already NFC-normalizes before JCS**
(`crates/mvm-core/src/workload_address.rs:168`), so the "NFC bug" one agent flagged
does not apply there; but `ir_hash`/`plan_id`/bundle paths do *not* NFC-normalize.
Almost certainly benign (structured/ASCII data), but it is exactly what a replay
golden vector (§6, U4) should pin. Low-risk borrows: the fixed-width ASCII-validated
`KappaLabel<N>` newtype as a hardening of `WorkloadAddress`; keep pinning the
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
- **Now:** `WorkloadAddress` pins 12 UOR-ADDR fixtures + one golden vector.
- **Upgrade:** a first-class frozen corpus (`tests/vectors/…`) of canonicalization
  inputs → expected addresses, checked byte-for-byte each PR across **every**
  content-address surface: `WorkloadAddress`, `ir_hash`, `plan_id`,
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
  `mvm_hostd` file-based `verify_audit_chain`, the `mvm_contract` no_std/wasm
  `verify_audit_chain_bytes` (`MirrorEntry`, CI-pinned by
  `mvm_verify_matches_supervisor_chain`), and the riscv32 ESP32 verifier (edge tier).
- **Upgrade:** ship the U4 replay corpus as *one shared vector set* that host + wasm
  + ESP32 verifiers must all pass; record in `catalog.md` which claims are backed by
  ≥2 independent verifiers. Realizes UOR's "external oracle" bar with implementations
  mvm already ships — near-zero new code, high assurance.
- **Risk/effort:** low / small — wiring existing verifiers to a shared corpus.
- **Logical endpoint:** the strongest form of this bar swaps "≥2 independent *implementations*"
  for "≥1 machine-checked *specification* the implementations conform to" — a Lean-4 reference
  spec over the same U4 corpus, with the golden vectors as the model↔code bridge. Recorded in
  §9; it is a bounded spike, not Phase-1 work.

### Sequencing
U1 and U4 first (foundational, lowest risk). U2 and U3 build on the U1 tier field.
U5 leverages verifiers that already exist. All five are pattern adoption; none takes
a UOR/Hologram crate dependency. A `specs/plans/` doc would be the next artifact once
this moves from research to execution (scan for the next free plan number first).

## 7. Content-addressing for attestation and defense

Follow-up analysis on three questions: is content-addressable data useful for mvm's
hash/attestation features; can a Hologram `holospace` run inside a microVM; and can
content-addressing defend against attacks.

### 7.1 Attestation needs four properties — and integrity is the one nobody enforces

*Revised 2026-08-01. The first pass recorded this table as "content-addressing
supplies integrity; mvm already has the other three; the ecosystem stops at
integrity." A deeper read of `kappa-registry` shows both halves of that were wrong:
they have the other three too, and **neither side enforces integrity on read**.*

| Property | Question | Mechanism | Coverage |
| --- | --- | --- | --- |
| **Integrity** | *what* are the bytes | content address, **recomputed and compared** | The property content-addressing exists to supply. `kappa-registry`: verified on 4 of 13 write paths, on **no** read path. mvm: trusted-by-path for the workload kernel and build cache. **The shared gap.** |
| Authenticity | *who* authorized them | Ed25519 key pinning · closed-constructor anchors | Shipped in mvm. Shipped in `kappa-registry` — an asserter anchor has no public constructor and a compile-fail test holds the boundary. |
| Freshness | *when* / is it stale | validity window · nonce replay store · watermarks | Shipped in mvm. Shipped in `kappa-registry` as O(1) bulk invalidation before a timestamp over a hybrid logical clock. |
| Ordering | *in what sequence* | hash-linked signed chain · Merkle root | Shipped in mvm. Shipped in `kappa-registry` as a seven-leaf domain-separated Ed25519-signed epoch root, backward-linked, with per-leaf selective disclosure. |

**`kappa-registry` maturity, corrected.** Eleven crates, 30,742 lines, store format
v5. It passes 1032/1032 OCI distribution-spec v1.1 conformance and 187/187 kappa
conformance across five levels with zero warnings. It ships encryption at rest
across blob content, storage paths and every index table; Veilid-transported
federation with Merkle-search-tree reconciliation; auditable key-directory absence
proofs; and the signed epoch chain above. The earlier "real, single-node, auth-stub"
characterisation understated it materially. It is not a prototype — it is a
conformant substrate that does not yet enforce the property its addressing scheme
implies.

**The asymmetry, stated directly.** Authenticity, freshness and ordering are well
covered on both sides. Integrity — the property a content address is supposed to
deliver for free — is the one no surveyed system enforces on read. *A signed chain
over addresses that were never checked attests to pointers, not to content.* That
reframes §7.2 from "a coverage gain" to "the one unenforced property", and it is why
verify-on-read is now the lead item rather than the tail.

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

### 7.6 Data-plane provability at the vsock chokepoint

Follow-up analysis on two questions raised after the first pass: since mvm mediates *all*
vsock, is the chokepoint a place content-addressing earns a property it can't get elsewhere;
and does content-addressing help with "routing traffic between microVMs." Both were grounded
in a fresh code read of the data-plane topology and the audit-chain binding.

**The chokepoint is architecturally special — and that is the whole leverage.** mvm is strict
hub-and-spoke: every guest talks *only* to its own host supervisor over AF_VSOCK (host CID is
the sole peer), and there is **no VM↔VM data path** — east-west guest-to-guest flow is
explicitly out of scope in the audit layer. Unlike a diffuse network, one trusted point
mediates 100% of the data plane. That is exactly the condition under which a content-addressed,
ordered, chain-anchored *transcript* of the data plane is actually achievable — on an open
network it is not.

**What the chain covers today.** The chain-signed + RFC-6962 Merkle audit log already binds the
control plane and data-plane *metadata* — flow open/close (`FlowEvent`), service-call facts,
and (already content-addressed **and** chain-anchored) checkpoint/image/fork lineage digests
(`emit_checkpoint_forked` records `parent_digest`/`child_digest` and fails closed on a tampered
parent). Data-plane *bytes* are captured separately by `transcript_sink` as encrypted chunks
sealed under the host KEK, deliberately kept off the chain ("raw payload bytes never touch the
chain-signed audit log").

**The gap (code-grounded, decisive).** The sealed transcript is not bound to the chain in *any*
form. No aggregate content-address of the manifest is ever computed — each `ChunkRecord` carries
the sha256 of its own on-disk ciphertext for local tamper-checking, but nothing rolls those into
a manifest root. The only seal record is a `TranscriptSealed` line carrying an opaque,
operator-assigned `capture_id` + a chunk count, written to the **local, unsigned** `audit.jsonl`
— not the host-signed chain. Consequence: an operator with filesystem access could delete or
swap a sealed capture (or individual chunks) and the tamper-evident chain would show **no**
discrepancy, because it never recorded the transcript's content-address. The metadata is
chain-bound; the payload transcript is orphaned from it.

**The fix that respects the deliberate off-chain-bytes decision.** Compute a content-address — a
Merkle root over the manifest's per-chunk digests + capture binding — and emit it as an
`AuditEmitter` label. The chain then commits to "here is the κ of the exact byte-transcript that
crossed between this guest and host," while the plaintext stays sealed under the KEK and off the
chain. That upgrades the chokepoint from proving *that* a flow happened (metadata) to binding
*what* crossed: provable execution of the **data flow**, not only the admission decision — the
"provable execution with content-addressable claims" property, realized at the one point that
sees every byte.

**Why not the tempting version** (hash each payload straight onto the chain): a hash of a
low-entropy or secret payload on a third-party-verifiable chain is a confirmation oracle — the
same leak class as the cross-tenant dedup side channel (§7.4). Content-address the *sealed
manifest root*, never the plaintext; the bytes stay under the KEK.

**Invariants preserved.** Address ≠ authorization (§7.4): the transcript κ attests what crossed,
never authorizes it — the signed, plan-bound admission stays the sole authority. Verify-on-read
fails closed: a manifest whose recomputed root ≠ the chained value is a tamper signal, reject
never serve. dm-verity roothash chain (claim 3) is unchanged. This is in-house, no dependency —
the same "content-address a coverage gap, anchor it, verify on read" family as §7.2, touching
only `mvm-hostd`'s emitter + the transcript manifest; it slots into Phase-1 defensive coverage
(§11).

**On "routing between microVMs."** There is no VM↔VM data path in mvm — a guest reaches another
only by transiting the host's north-south gateway as ordinary (default-deny, policy-gated)
egress; the "routing" surfaces are per-VM host-terminated chokepoints (vsock port allowlist,
`gateway_bridge`, `NetworkProvider` egress policy, egress proxy), not a central message router.
So **content-addressed routing is a mvmd fleet concern, not an mvm one** — it maps to Hologram's
migrate-by-κ-closure (§7.3(c)) at Phase 3, and even there address ≠ authorization holds (κ says
*what*, the signed plan says *whether*). Where inter-VM *lineage* does exist in mvm — warm
snapshot-fork parent/child — it is **already** content-addressed and chain-anchored, which
validates the instinct in the one place it currently has teeth.

### 7.7 Identity and permissions in the packet — signed capability vs hashed claim

Follow-up on "can UOR hold identity and permissions in the data packet?" — the sharpest form
of the address ≠ authorization question (§7.4). The answer differs by what "identity/permissions"
means, so split it.

**Three things, three different answers.** *Identity of the data* (what the bytes are): a
content-address supplies it for free; mvm does this everywhere. *Authenticity of the principal*
(which trusted authority issued it): a hash **cannot** — an address says what the bytes are,
never who signed them. That needs a signature verified against an already-trusted public key;
`key_id` / `signer_id` only selects or fingerprints that key and is not proof by itself.
*Permissions* (what may this do, where may it go): this is the trap.

**The trap — content-addressing a capability is not authority.** Put `permissions: [...]` in a
packet and content-address it, and κ certifies only "this packet *contains* this permission
string," never that the permission was *granted*. Anyone can craft a packet asserting any
permission and it gets a perfectly valid address; the hash authenticates the bytes, not the
authority behind them. So this merely turns "trust the claim" into "trust the bytes of the claim"
— zero elevation of trust. This is exactly the structural weakness of UOR/Hologram's
capability-only, unsigned control plane, and why the standing rule is: κ layers *under* signed
authority, never *as* it.

**The form that works — a signed capability, which mvm already ships.** Carry the permission with
the data, but signed rather than merely hashed: (1) **signed** by an authority whose public key
the verifier already trusts (authenticity); (2) **bound** to session/principal +
destination/scope + validity window + nonce (freshness, anti-replay); and (3) optionally
**content-addressed underneath** when a stable integrity/reference handle is useful. The
signature makes it authority; κ never does. That is precisely what the content-addressed,
signed, validity/nonce-bound `ExecutionPlan` supplies (claim 8), what the broker enforces
per-service from `ExecutionPlan.services` before dispatch (claim 12), and what the secrets path
returns as destination- and time-bound signed credentials (claim 13). The guest-side `VerbGrant`
is the narrower form: host-signed and bound to a session, plan nonce, expiry, and verb set.

**What is already bound.** `ExecutionPlan.plan_id` is the SHA-256 content-address of the plan's
load-bearing body, and every chain-signed `AuditEntry` — including flow open/close — records that
`plan_id`. The existing data-plane *metadata* therefore already answers "which admitted signed
authority governed this flow." A second capability κ on every flow would duplicate that binding.
The genuinely missing link is the one identified in §7.6: the encrypted byte-transcript's sealed
manifest has no aggregate root in the signed chain. Emit that root through the existing
plan-bound audit entry and it automatically binds the exact capture to the same `plan_id`. A
separate digest for a narrower capability becomes useful only if a future action is authorized
by a capability independently of the plan; otherwise its signature already supplies integrity
and its nonce/session binding makes cache deduplication nearly valueless.

**Caveats.** Do not sign every packet on the hot vsock path. Authenticate and bind authority at
session/connection admission, then carry only the already-bound flow/session identity. Any
capability digest is a content fingerprint; keep it within the tenant/trust boundary (the §7.4
cross-tenant leak rule).

**Restored children need the existing grant path completed, not a new capability system.** The
factory-parent boot now receives the host-signer public key as host identity without receiving a
workload grant (#1959 fixed the boot half). The production post-restore path still sends
`grant_envelope: None`; it should instead deliver a freshly host-signed `VerbGrantEnvelope` bound
to the child's newly admitted plan/session and verify it against that boot-pinned key. The
separate current hard blocker is the unaudited factory parent (#1962). Neither problem requires
offline delegation or a new wire format.

**Delegation is trigger-gated.** If a future fleet use case genuinely needs a holder to attenuate
authority without re-contacting the issuer — especially multi-hop or offline delegation — then
evaluate an established attenuatable-capability format (for example Macaroons or Biscuit) against
a written bearer/replay/revocation threat model. Do not invent a custom Ed25519 + hash-chain
scheme, and do not add this machinery merely to rotate a child grant while the host issuer is
already online.

**Net.** Right read as "a *signed* capability travels with the session/data" (mvm already does
this); a trap read as "content-addressing *is* the permission" (UOR/Hologram's gap). The bounded
new work is the §7.6 sealed-transcript-root audit binding plus completion of Plan 255's existing
post-restore grant delivery. A general attenuatable capability remains deferred until an actual
delegation requirement appears.

### 7.8 σ/κ separation and the transform descriptor

*Added 2026-08-01. New material; ranked as an **adopt** alongside the methodology
upgrade.*

Every transform applied at rest separates the digest a protocol names content by
from the digest of the bytes actually stored. This is the general case, not an
encryption special case, and the precedents are unanimous: git object IDs have never
hashed the bytes on disk in any implementation (loose objects are deflated, packed
objects are delta-encoded against a base); ZFS compresses and encrypts beneath a
checksum carried in the parent block pointer; deduplicating backup systems address
chunks while files are manifests; columnar table formats address manifests which
address encoded files.

- **σ** is the protocol digest, computed over plaintext — the ETag, the content-digest
  header, the object identifier.
- **κ** is the storage address, computed over the bytes at rest — it derives the path,
  it is the verification target, and it is the unit of federated transfer.

Under the identity transform the two are numerically equal and remain **distinct
quantities**. The type separation is what stops the property regressing silently.

Two consequences:

1. **σ is a set.** One storage address is reachable by two or more protocol digests.
   That is exactly what a dual-hash transition requires and what multi-axis
   registration provides — and it is the real answer to the SHA-256-vs-BLAKE3
   question in §8, which "pin one axis" would foreclose.
2. **The descriptor is an open enumeration, not a boolean.**

   ```
   framing  : Whole | Fixed{frame_size} | Chunked{manifest}
   per_frame: [ Identity | Aead | Deflate | Delta{base} | Erasure{k,m} ]
   seek_map : Implicit | Explicit{cumulative} | None
   ```

   Framing is the outer layer and transforms apply per frame. That is what makes
   ranged reads into transformed content possible: whole-object sealing means a
   ten-byte range request against a ten-gigabyte object must process the whole
   object, which removes the operation rather than slowing it.

**Why now, while mvm is still all-identity-transform.** Modelling this as a single
label — or as an optional "encrypted" flag — costs one format migration per transform
family, forever. Modelling the axis once, while every transform in the tree is still
`Identity`, costs a newtype pair and no migration.

### 7.9 Verify-on-read is the founding definition, not an enhancement

*Added 2026-08-01.*

The archival system that established content-addressing as a systems primitive
specified that **on retrieval, both client and server compute the fingerprint and
compare it to the one requested**. The claim content-addressing makes is not "the
name is a hash"; it is "a block cannot be modified without changing its address" —
and that claim is cashable only if something recomputes. §7.1's finding is that
nobody does.

The corruption rate is measured, not hypothetical. A field study of 1.53 million
drives over 41 months recorded more than 400,000 checksum mismatches. Nearline drives
develop them an order of magnitude more often than enterprise drives. Mismatches
within a disk are **not independent** — they show high spatial and temporal locality —
and mismatches across disks in the same system are not independent either. A
follow-on study found 8% were discovered during RAID reconstruction, i.e. correlated
with the moment redundancy is already degraded.

The second corruption class in that taxonomy is the one that matters most here:
**identity discrepancies** — an intact block that is the *wrong* block. Content-addressing
detects it for free; a path-trusting store cannot see it at all. This is precisely the
workload-kernel cache-skew class that currently mimics real bugs in mvm.

Practical form, by object size:

- **Small objects** — rehash before responding.
- **Streamed objects** — carry a running hash across frames, deliver the verdict in a
  trailer.
- **Cold objects** — background scrub over the reachability walk. This is the only tier
  that catches the locality pattern above; on-access verification never visits the
  blocks that are quietly rotting.

### 7.10 Deduplication scope is a side-channel decision, and the conformant answer is free

*Added 2026-08-01. Sharpens the cross-tenant dedup rule already stated in §7.4.*

Cross-user deduplication with a truthful existence response **is** an oracle: one bit
per probe, and a target drawn from an enumerable set is recoverable in proportion to
its entropy. The foundational study concluded cross-user dedup should be disabled by
default, and that public storage should provide unlinkability of users and data even
when data is encrypted before upload.

Two facts make the fix cheap in registry terms:

- The distribution specification once required a cross-repository mount to name a
  source the client has read access to — an authorizable check. **Version 1.1 made
  that source optional**, so a mount may be attempted with no source to authorize
  against.
- The same specification states a registry unable or unwilling to mount should return
  202 and begin the upload session, and that a push with or without an attempted mount
  takes **the same number of API requests**.

**Consequence: declining a cross-namespace mount is fully conformant.** Same request
count, same client code path, no error a client does not already handle.
Namespace-scoped dedup by default — with cross-namespace mounts honoured only where
the caller is authorized on the source — costs bandwidth, not correctness, and is
stronger than any probabilistic scheme because nothing has to be misreported.

Under per-namespace key derivation the property is stronger still: identical plaintext
yields different ciphertext, a different address and a different path, so the
cross-tenant oracle **cannot form arithmetically** rather than being prevented by
policy.

No CVE, advisory or published threat model was located for cross-tenant
blob-existence side channels in container registries. The attack has been in the
literature since 2010 and appears unexamined in this industry as a named class.

### 7.11 Reconciliation prerequisites among mutually distrusting peers

*Added 2026-08-01. Gates the §8 "distributed content-addressed transport" item.*

Range-based set reconciliation and Merkle-search-tree page diffing remain the right
references, with two prerequisites that must be settled **before** either is used
among peers that do not trust each other.

- **The fingerprint must be multiset-homomorphic.** Where it is not — an XOR
  aggregation being the common case — a peer withholds arbitrary data by claiming
  absence. This requires no collision-finding and is invisible to functional testing,
  because reconciliation converges cleanly with data missing. All commonly cited
  candidates except non-commutative Cayley hashes are usable.
- **A search-tree root is not necessarily a cryptographic commitment.** The widely used
  MST implementation derives page and root digests from a non-cryptographic 128-bit
  hash under a fixed key, independent of the user-supplied hasher — which governs key
  and value digests only. That is appropriate for detecting accidental divergence and
  inadequate for a signed root. **A reconciliation root and an attested root are
  different structures with different requirements**; do not sign the former.

### 7.12 The nine axes, and where content-addressing breaks

*Added 2026-08-01.*

Across roughly three hundred systems surveyed — block, file, object, content-addressed,
package distribution, backup, table format, log, key-value, vector, graph and
domain-specific families — nine axes cover the design space: naming, mutability,
granularity, access, verification, consistency, transport, topology, and **transform**.

**Transform (D9) is the axis that silently invalidates naive content-addressing**, is
present in every mature storage system, and is what motivates §7.8. Nine patterns
recur across every family — name/content separation, Merkle structure over content,
transform at rest with an identity case, chunk-and-reassemble, append-only log with a
signed or ordered root, anti-entropy reconciliation, tiering and lifecycle,
multi-tenancy with isolation, attestation with provenance. Every surveyed system is a
combination of these; none introduces a tenth.

## 8. Interop hazards and alignment points

Concrete cross-project mechanics that decide whether mvm and the UOR/Hologram
addresses can ever line up:

- **Hash-axis handling — a σ set, not a pinned axis.** *(Revised 2026-08-01.)* mvm
  standardizes on SHA-256; `uor-addr` defaults SHA-256 but `uor-r4`/`hologram` mint on
  the BLAKE3 axis. A κ-label is `<axis>:<hex>`, so the *same bytes* get *different
  addresses* on different axes. The first pass concluded "interop must pin one axis";
  §7.8 supersedes that. The resolution is a **σ set** — one storage address reachable
  by more than one protocol digest. Pinning a single axis would foreclose exactly the
  dual-hash transition and multi-axis registration that make the fragmentation
  survivable.
- **Transform agreement — settle it before either side ships a non-identity transform.**
  Addresses stop meaning the same thing across projects the moment either side
  compresses, encrypts, deltas or erasure-codes at rest (§7.8). Agreeing the descriptor
  while everything is still `Identity` is free; agreeing it afterwards is a format
  migration on both sides.
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
- **Machine-checked reference spec (Lean 4) as the third oracle.** The endpoint of §6 U5:
  model the small, pure, `no_std` audit-chain verifier (`mvm_contract::verify`) plus the
  canonicalization/address algebra (JCS+NFC, RFC-6962 Merkle) as a Lean-4 *specification*, and
  make the host + wasm + ESP32 Rust verifiers conform to it over the U4 golden-vector corpus.
  Lean becomes a machine-checked oracle — exactly the shape of UOR's `F1`, a serious Lean-4
  formalization that is scrupulously honest that its RH payload stays *open*. **Honesty
  boundary** (why this is filed, not claimed): Lean proves properties of the *model* —
  canonicalization total/deterministic/injective, verifier sound-and-complete, Merkle inclusion
  sound — **not** that builds are *hermetic* (an operational property discharged by the microVM
  sandbox + nix pins + the reproducibility double-build, claim 7, never by a theorem) and
  **not** SHA-256 collision resistance (assumed, and named the F1 way). With no mature Rust
  extraction, model↔code correspondence is a *tested* bridge (the vectors), not a proof. So the
  precise answer to "can Lean 4 prove our hermetic/hashable/attestable builds?" is: it proves
  the *verifier and address algebra* sound and yields a formal reference oracle; the sandbox
  proves hermeticity; the two compose and neither substitutes. Cost — a heavy toolchain + a
  proof-maintenance burden against the "limit dependencies" rule — makes this a bounded spike on
  one target (the `no_std` verifier), not a proof lane.
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
| **0 — Decide & scope** | Now (days) | Adopt "conform, don't consume" as explicit policy; establish the **σ-set contract** for addresses (§7.8 — *not* "pin one axis", which the first pass proposed); turn §6 U1–U5 + §7.5 defensive coverage into a `specs/plans/` doc. | None. |
| **1 — Methodology + defensive coverage** | Next 1–2 sprints | Content-address the workload kernel + build cache with **verification on read as well as on write** (§7.9 — now the lead item, per the revised §7.1); U4 replay-vector lane (recording σ **and** κ wherever a transform is in play); U1 tiers · U2 prose over-claim gate · U3 falsifiability table · U5 ≥2-verifier oracle bar. All in-house, no dependency. *(The §7.6 sealed-transcript root anchoring listed here originally shipped separately — see plan 280.)* | Phase 0 plan approved. |
| **2 — Interop alignment** | Mid-term, triggered | Agree the **σ-set contract, canonical wire form and transform descriptor** with the sibling projects **before either side ships a non-identity transform** (§7.8); agree in-toto/SLSA canonicalization; read `uor-foundation` (the real κ engine); evaluate `uor-addr-1` (lighter crate). | A real second consumer of the addresses **and** a UOR/Hologram-side conversation. |
| **3 — Runtime / fleet / AI** | Long-term, opportunistic | holospace object model (migrate-by-κ-closure) into mvmd; content-addressed inter-VM routing (mvmd only — no east-west path in mvm, §7.6); evaluate an established attenuatable-capability format only if offline/multi-hop delegation becomes a concrete requirement (§7.7); `hologram-ai` interop for the deferred `ai` command; distributed transport (RBSR / iroh-blobs) **with §7.11's multiset-homomorphic-fingerprint and attested-root prerequisites settled first**. | A concrete mvmd migration/scale requirement, a concrete offline/multi-hop delegation requirement, or the `ai` command leaving deferred status. |

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
- **Never derive an address from a non-collision-resistant digest.** MD5, CRC32C
  and CRC64 are required as *attestations* and disqualified as *addresses*. Enforce
  with disjoint types and a compile-fail test, not with review.
- **Never sign state that cannot be substantiated.** The order is content → index →
  root → signature → publication. A crash before signing is recoverable; the reverse
  order forks the chain and has no recovery path.
- **Never sign a reconciliation root.** An MST page/root digest from a
  non-cryptographic hash detects accidental divergence and is not a commitment
  (§7.11).
- **Licensing gap:** `uor-vv`/`uor-conformance`/`uor-nanda`/`arch-map` ship no
  LICENSE. Even as sibling projects, reusable text/scripts need a license before
  verbatim reuse.

## Appendix — per-repo anchors

Selected code anchors validated during the read (external repos cloned under
`/tmp/uor-research/`; mvm paths are in-tree).

| Anchor | What it shows |
| --- | --- |
| `uor-addr/crates/uor-addr/src/json/pipeline.rs` | κ-label minting = the `WorkloadAddress` pattern, productionized |
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
| mvm `crates/mvm-core/src/workload_address.rs:59,152,168` | `sha256(JCS(NFC(IR)))`; already NFC-normalizes (corrects §5.3) |
| mvm `crates/mvm-core/src/plan/bundle.rs:616,954` | `verify_plan_bundle` / `read_and_verify_bundle` rejection ladders |
| mvm `crates/mvm-contract/src/verify.rs:169`, `merkle.rs` | no_std audit-chain verifier + RFC-6962 transparency tree (the "≥2 impls" bar, §6 U5) |
