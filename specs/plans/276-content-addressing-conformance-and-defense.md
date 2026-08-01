# Content-addressing conformance and defense: claim tiers, an over-claim gate, replay vectors, and cache verify-on-read

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Proposed, reconciled against `main` **and against the 2026-08-01 recon revision**. Phase 0/1 of the UOR × Hologram cross-project recon (`specs/research/uor-hologram-cross-project-recon.md`). WS0 and WS2 are **already satisfied by shipped work** (see "Landed since this plan was written"); WS1 and WS5 are narrower than first written because the substrate they proposed to invent already exists. **WS6 is now the lead workstream, not the tail** — see "The premise changed" below. Not yet scheduled into `specs/SPRINT.md`; do not start a workstream until an owner moves it into the active sprint.

**Goal:** Close the integrity-on-read gap and harden mvm's claim→witness program, taking **zero** UOR/Hologram code dependency. Two outcomes: (1) the build/runtime cache — the kernel first — becomes content-addressed and **verified on read**, closing a live cache-skew/poisoning class and the identity-discrepancy class with it; (2) the claim ledger gains a single reconciled evidence tier, a replay-vector lane, and an explicit two-verifier oracle bar. Both fall out of the same canonicalization-rigor effort; see recon §6 (methodology) and §7 (defense).

## The premise changed

The first draft of this plan rested on recon finding 2 as originally written — *"mvm is ahead on every security-critical primitive; the ecosystem stops at integrity."* The 2026-08-01 recon revision **reverses that finding**, and the reversal is load-bearing here:

- `kappa-registry` does enforce authenticity, freshness and ordering (closed-constructor anchors held by a compile-fail test, hybrid-logical-clock watermarks, an Ed25519-signed seven-leaf domain-separated backward-linked epoch root). The ecosystem does not "stop at integrity."
- What **no** surveyed system enforces is **integrity on read**. `kappa-registry` verifies at 4 of 13 write paths and no read path; mvm's workload kernel and build cache are trusted-by-path. That is the one property a content address exists to supply.
- Verification on retrieval is the *founding definition* of content-addressing, not an enhancement: the original archival design specified that on retrieval both sides recompute the fingerprint and compare. A signed chain over addresses that were never checked attests to pointers, not to content.

Two consequences for this plan. **WS6 moves from tail to lead** — it is no longer "broader coverage", it is the unenforced property. And **WS0's axis decision inverts**: "pin SHA-256 as the canonical axis" is superseded by the σ-set contract (recon §7.8), because pinning one axis forecloses the dual-hash transition that makes axis fragmentation survivable.

**Architecture:** Seven workstreams, each its own PR, sharing no code:

- **WS0** Decide & scope (Phase 0) — **done**, except the policy + σ-set ratification lines.
- **WS1** Claim evidence tiers (recon U1) — **reconcile two tier vocabularies that already exist**, not invent one.
- **WS2** Prose over-claim meta-gate (recon U2) — **shipped** as `xtask check-no-overclaim`.
- **WS3** Replay golden-vector lane (recon U4) — open; now records σ **and** κ wherever a transform is in play.
- **WS4** Two-verifier oracle bar (recon U5) — extend existing host/no_std parity.
- **WS5** Falsifiability binding (recon U3) — bind red-proofs to witnesses; the gates and the `VERIFICATION.md` rows already exist.
- **WS6** Content-address kernel + build cache, **verify on read** (recon §7.1/§7.9) — **the lead item, and blocking plan 279 WS1**.
- **WS7** σ/κ separation and the transform descriptor (recon §7.8) — new; cheap now, a per-transform-family format migration later.

**Tech Stack:** Rust, `xtask` (gates), the claims ledger — the `<!-- claims-catalog:begin -->` / `<!-- claims-catalog:end -->` table embedded in `specs/adrs/001-microvm-security-posture.md` (parsed by `xtask/src/claims_ledger.rs`) plus the `model/claims.toml` conformance ID register — `specs/VERIFICATION.md` (falsifiability), `cargo-nextest`, `mvm-conformance` (cucumber), GitHub Actions (`ci.yml` + `ci-full.yml` Lint jobs, `security.yml`). SHA-256 + `serde_jcs` + `ed25519-dalek` (existing; **no new crypto, no new runtime dependency**).

> **Path correction.** Earlier revisions of this plan referenced `specs/claims/catalog.md`. That file does not exist and this plan must not recreate it. There are two ledger surfaces and they are both authoritative for different things: `model/claims.toml` is the ID register (`id`, `level`, `suite`, `statement`, typed `fn:`/`ci:` witnesses; `CONFORMANCE.md` is generated from it), and the ADR-001 marker-delimited table is what `check-claim-catalog` walks for witness existence and contiguity.

**What mvm already has (extend, do not rebuild):**

- `xtask check-claim-catalog` — witness existence + contiguity over the ADR-001 ledger table.
- `xtask check-no-overclaim` — the U2 gate, already shipped and stronger than U2 specified.
- `xtask check-honesty`, `check-doc-claims`, `check-conformance`, `check-adr-coverage` — the surrounding prose/claim gate family.
- `xtask check-mutation-witnesses` (#1934) and `check-claim-witness-freshness` (#2000, which notices a claim-bearing lane that stops *running*, not only one that fails).
- `model/claims.toml` — already carries `level = some-true | build | open`, i.e. the `template/model/ids.toml` honesty axis recon U1 named as its source pattern.
- `specs/VERIFICATION.md` §Falsifiability — 36 recorded planted-defect rows.
- Host↔no_std audit-verifier parity (`mvm_verify_matches_supervisor_chain`, `crates/mvm-hostd/src/supervisor/audit_file.rs`).
- `SemanticAddress` = `sha256(JCS(NFC(IR)))`, pinned to published UOR-ADDR fixtures by `matches_published_uor_addr_json_fixtures`.

This plan builds on those; it does not duplicate them.

## Provenance

Sourced from a code-level read of UOR-Foundation + Hologram-Technologies (`specs/research/uor-hologram-cross-project-recon.md`). The disposition is **conform, don't consume**: adopt the ecosystem's conformance/honesty discipline as patterns; take no `uor-addr`/`uor-prism`/`uor-foundation` dependency. Recon Phases 2 (interop alignment) and 3 (runtime/fleet/AI) are trigger-gated and out of scope here.

The recon gained §7.6 (data-plane provability at the vsock chokepoint) and §7.7 (identity and permissions in the packet — signed capability vs hashed claim) on 2026-07-31, **after** the first draft of this plan. Both have since been discharged by shipped work rather than by a workstream here; see below. Their durable output for this plan is a set of non-goals, not new scope.

## Landed since this plan was written

Recorded so no workstream re-proposes them.

- [x] **Prose over-claim meta-gate (WS2 / recon U2)** — `xtask check-no-overclaim` (`xtask/src/check_no_overclaim.rs`). It is broader than U2 asked for: rather than a curated assertive-verb list, it builds a `phrase → (claim, status, exempt_paths)` index from claim frontmatter embedded in `specs/adrs/**/*.md` and refuses any gated phrase on user-facing surface (`.md` **and** `.rs`) unless the owning claim is `Shipped`. Status vocabulary is `Planned | Preview | Shipped | Not-claimed`, with `Not-claimed` treated as `Planned`.
- [x] **Sealed data-plane transcript root anchored into the audit chain (recon §7.6)** — plan 280 (`specs/plans/280-transcript-root-audit-binding.md`, **Complete**), shipped in #2017. Manifest format v2 carries an RFC-6962 Merkle root over the capture binding, bounds, wrapped-key metadata and ordered ciphertext chunk records; the host chain-signs that address and `mvmctl trust audit transcript export` requires an exact anchor in a valid tenant chain. Plaintext and plaintext digests never enter the root — the §7.4 confirmation-oracle rule holds. v1 manifests fail closed on export. Recon §11 listed this as Phase-1 work and this plan never carried it as a workstream; it is closed either way.
- [x] **Post-restore child verb grant (recon §7.7)** — #2019 delivers a freshly host-signed grant bound to the restored child's newly admitted plan/session (`crates/mvm-runtime/src/workload_runner/child_grant.rs`). §7.7's conclusion was that this needed the existing grant path completed, not a new capability system; that is what shipped.

## Global Constraints

- Each workstream gets its own worktree/branch/PR; git via `git -C <wt-abs>`. (The original recon worktree `../.worktrees/mvm-uor-hologram` on `docs/uor-hologram-recon` merged in #1964 and is gone — do not look for it.)
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs-in-comments`); spec docs may reference them.
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push (CI Lint uses nightly rustfmt); `cargo nextest run --workspace` + `cargo test --workspace --doc` green before any task is marked done.
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or PR body.
- Scratch files under `/tmp/`, never in the working tree.
- Every new `xtask` gate is added to **both** `.github/workflows/ci.yml` and `.github/workflows/ci-full.yml` Lint jobs — the gate list is duplicated and a gate in only one silently does not run.
- Every new gate gets a row in `specs/VERIFICATION.md` §Falsifiability recording the planted defect that proved it fires.
- Tick this plan's checkboxes and update `specs/SPRINT.md` + `specs/REFACTOR-STATUS.md` in the same commit as the work.

## Non-goals (do not re-propose)

- **No `uor-addr`/`uor-prism`/`uor-foundation` dependency.** It drags the prism substrate (~156 transitive crates incl. FHE/tensor) and duplicates existing `sha2`/`serde_jcs`/`ed25519-dalek`. Conform to the wire label; do not consume the crate.
- **No hash-only trust.** Content-addressing stays an integrity layer *under* the signed, plan-bound authorization — never the hash as permission (see S1).
- **No BLAKE3 *migration*.** SHA-256 stays the axis mvm mints on, and nothing in this plan re-addresses an existing artifact. But do **not** re-propose "pin SHA-256 as the canonical axis" as a policy: the 2026-08-01 recon supersedes it with the σ-set contract (WS7), under which one storage address is reachable by more than one protocol digest. Pinning forecloses the dual-hash transition; minting on SHA-256 does not.
- **No runtime/fleet/AI interop** (holospace object model, hologram-ai, distributed transport) — recon Phase 3, trigger-gated.
- **No third claims-ledger file.** `specs/claims/catalog.md` is gone and stays gone; extend `model/claims.toml` and the ADR-001 table.
- **No new capability system, and no custom Ed25519 + hash-chain delegation scheme** (recon §7.7). A content-addressed permission is not authority — κ certifies that a packet *contains* a permission string, never that it was *granted*. mvm's signed, validity/nonce-bound `ExecutionPlan` (claim 8), broker `services` binding (claim 12) and destination-bound signed credentials (claim 13) are already the working form. An established attenuatable format (Macaroons, Biscuit) is evaluated **only** when a concrete offline or multi-hop delegation requirement appears, and then against a written bearer/replay/revocation threat model.
- **No per-packet signing on the hot vsock path** (recon §7.7). Authenticate and bind authority at session/connection admission; carry only the already-bound flow/session identity afterwards. Every chain-signed `AuditEntry` already records the governing `plan_id`, so a second capability digest per flow would duplicate an existing binding.

## Security considerations — settle before writing code

- **S1 — address ≠ authorization (invariant).** Every new content-address check verifies integrity only. It must never become an admission decision; the signed `ExecutionPlan` + `key_id`-pinned bundle remain the sole authority. WS6's verify-on-read gates *cache trust*, not *workload admission*.
- **S2 — cross-tenant dedup is an oracle, not merely a leak.** A truthful existence response across a trust boundary yields one bit per probe, and a target drawn from an enumerable set is recoverable in proportion to its entropy. Key WS6's cache within the existing per-tenant boundary. Two notes from recon §7.10: refusing a cross-namespace mount is *fully conformant* under the distribution spec (same request count, same client path, no unhandled error), so the safe default costs bandwidth rather than correctness; and under per-namespace key derivation the oracle cannot form **arithmetically** — identical plaintext yields different ciphertext, a different address and a different path — which is strictly better than preventing it by policy.
- **S3 — verify-on-read must fail closed.** A cache hit whose recomputed address ≠ the key is a tamper/skew signal: reject + evict, never serve. Absence of a hash must not fall back to trusting the path.
- **S4 — do not weaken dm-verity.** Content-addressing the kernel is additive provenance; the workload rootfs dm-verity roothash chain (claim 3) is unchanged and remains authoritative for the sealed rootfs.
- **S5 — NFC decision.** `SemanticAddress` NFC-normalizes; `ir_hash`/`plan_id` do not. WS3 pins the *current* behavior as a replay vector first (freeze what ships), then WS1/owner decides whether to converge on NFC — never silently change an address.
- **S7 — an address digest must be collision-resistant; an attestation digest need not be.** MD5, CRC32C and CRC64 are legitimate *attestations* and disqualified as *addresses*. Enforce the distinction with disjoint types and a compile-fail test, not with review — the same posture `mvm_core::semantic_address` already takes by having no conversions between identity families.
- **S8 — never sign state that cannot be substantiated.** The order is content → index → root → signature → publication. A crash before signing is recoverable; the reverse order forks the chain with no recovery path. This binds WS3's transcript-root vector and any future signed root.
- **S9 — a reconciliation root is not a commitment.** If distributed transport is ever revisited (recon Phase 3), the fingerprint must be multiset-homomorphic — an XOR aggregation lets a peer withhold arbitrary data by claiming absence, with no collision-finding and no functional-test signal — and an MST page/root digest from a non-cryptographic hash must never be signed. Out of scope here; recorded so it is not rediscovered late.
- **S6 — one tier vocabulary, or the gates disagree.** Two independent honesty axes are live: `model/claims.toml` `level` (`some-true` | `build` | `open`) and the ADR claim-frontmatter `status` (`Planned` | `Preview` | `Shipped` | `Not-claimed`) that `check-no-overclaim` enforces. Nothing currently checks them against each other, so a claim can read `open` in the register and `Shipped` in its frontmatter — which would silently disengage the over-claim gate on a property that was only ever measured. WS1 exists to close that, and must not introduce a third vocabulary.

## Workstreams

### WS0 — Decide & scope (Phase 0)
- [x] Land this plan + `specs/research/uor-hologram-cross-project-recon.md` (#1964).
- [ ] Owner ratifies "conform, don't consume" as recorded policy (a line in ADR-001, or a short ADR referencing the recon).
- [ ] Record the **σ-set contract** as the address-identity policy (one storage address reachable by ≥1 protocol digest), superseding the earlier "pin SHA-256 as the canonical axis" line. SHA-256 remains what mvm mints on.
- [ ] Owner moves WS1 + WS3–WS7 into `specs/SPRINT.md` when scheduling; until then they stay Proposed.

### WS1 — Reconcile the claim evidence tiers (U1)

Scope changed: the tier fields exist, unreconciled (S6). Do not add a `tier:` column.

- [ ] Define the mapping between `model/claims.toml` `level` and ADR claim-frontmatter `status`, and record it in ADR-001 next to the ledger table (the exhaustive pairs, including which combinations are illegal).
- [ ] Extend `xtask check-claim-catalog` to fail on a claim whose `level` and `status` disagree — specifically, `level = "open"` with `status = "Shipped"`, which would disengage `check-no-overclaim` on a measured-not-asserted property.
- [ ] Enforce the witness bar per status: `Shipped` requires a live `fn:` **and** `ci:` witness; `Preview` requires ≥1; `open` must not appear in the ADR-001 numbered prose table.
- [ ] Backfill any claim whose two fields currently disagree; claim 16 (egress-substitution leak-gate) and the OCI-provenance claim are the known promotion-pending cases.
- [ ] Gate wired into `ci.yml` + `ci-full.yml` Lint; falsifiability row in `VERIFICATION.md` (planted: flip an `open` claim's frontmatter to `Shipped` → gate fires).

### WS2 — Prose over-claim meta-gate (U2) — shipped
- [x] `xtask check-no-overclaim` scans user-facing `.md` and `.rs` for phrases gated by a claim whose `status` is not `Shipped`, honouring per-claim `exempt_paths`.
- [x] Wired into the Lint lanes; `VERIFICATION.md` carries its falsifiability row.

No residual work. WS1's cross-field check is what makes this gate trustworthy — a claim mistiered to `Shipped` disengages it, which is why S6 is a security consideration and not a tidiness one.

### WS3 — Replay golden-vector lane (U4)

The remaining high-value item, and untouched. `xtask check-content-address-determinism` is **not** this lane — it only asserts the non-build `serde_json` unit reachable from `mvm-core`/`mvm-protocol` does not carry `preserve_order`. That pins one drift mechanism; it pins no address. There is no vector corpus in the tree.

- [ ] Create a frozen `(input → expected address)` corpus for **every** surface: `SemanticAddress`, `ir_hash`, `plan_id`, `bundle_sha256`/manifest, the audit `prev_hash` spine, the RFC-6962 Merkle root, and the plan-280 transcript manifest root (new since the first draft — it is a content address on the signed chain and must not drift either).
- [ ] A test recomputes each and asserts byte-equality; fails on any canonicalization drift (`serde_jcs` bump, field reorder, NFC change).
- [ ] Seed with current shipped behavior (freezes S5's NFC status quo). Include astral-plane-key + Unicode-normalization edge vectors.
- [ ] Where a transform is in play, record **both σ and κ** — only the pair pins the encoding (WS7 / recon §7.8). Every surface in mvm is `Identity` today, so today the two are equal; the vector must still carry both so the day one of them stops being `Identity` is a vector diff and not a silent re-address.
- [ ] Run in nextest (workspace); `VERIFICATION.md` row (planted: reorder a JCS key emitter → vector mismatch fires).

### WS4 — Two-verifier oracle bar (U5)
- [ ] Make the WS3 replay corpus the shared vector set the existing host↔no_std audit-verifiers both consume (`mvm_verify_matches_supervisor_chain` pins the equivalence today over ad-hoc input, not a frozen corpus).
- [ ] Add the riscv32/ESP32 verifier (edge tier) as the third independent oracle over the same corpus where it builds.
- [ ] Record in `model/claims.toml` which claims are backed by ≥2 independent verifiers.
- [ ] `VERIFICATION.md` row (planted: diverge one verifier's canonicalizer → parity test fires).

### WS5 — Falsifiability binding (U3)

Narrower than first written: the mutation surface, the freshness gate and the 36 `VERIFICATION.md` rows all exist. What is missing is the *binding* from a witness to its red-proof.

- [ ] Add a `falsified_by:` field per witness in `model/claims.toml` pointing at the mutation/negative-test that goes red when the witness breaks.
- [ ] Extend `check-claim-catalog` (or `check-mutation-witnesses`) to fail if a witness has no recorded red-proof.
- [ ] Backfill red-proof references; note the CI-only witnesses that mutation testing structurally cannot reach (mirror plan 274 WS3).
- [ ] `VERIFICATION.md` row (planted: strip a witness's red-proof → gate fires).

### WS6 — Content-address the kernel + build cache, verify on read (lead item)

**Why this is first.** Per the revised recon §7.1, integrity-on-read is the one attestation property no surveyed system enforces — not a coverage nicety. **Downstream dependency: plan 279 WS1 (`ActionDigest`) is blocked on this landing** — plan 279 states the closure explicitly ("`~/.mvm/dev/builds/<rev>/` is served on a hit if `rootfs.ext4` merely exists as a file … Closing this is plan 276 WS6, not this plan"). `specs/SPRINT.md` already carries the same note.

- [ ] Identify the workload/builder kernel cache read path (the one with no staleness check) and the `mvm-build` artifact cache read paths, including `~/.mvm/dev/builds/<rev>/`.
- [ ] Add a content-address (SHA-256) to each cached artifact's key and verify **on read** on every hit (recompute, compare, fail closed per S3; evict on mismatch). `mvm_core::pack_cache` already implements exactly this discipline for packs — reuse it rather than writing a second cache.
- [ ] Verify on read *as well as* on write. Recon §7.1 measured `kappa-registry` at 4 of 13 write paths verified and **no** read path; a write-only check is the failure mode to avoid, not the target.
- [ ] Size the check to the object (recon §7.9): rehash small artifacts before serving; carry a running hash across frames for streamed artifacts and deliver the verdict in a trailer; add a background scrub over the reachability walk for cold artifacts — on-access verification never visits the blocks that are quietly rotting, and the measured corruption pattern has high spatial and temporal locality.
- [ ] Cover the **identity-discrepancy** class explicitly, not just bit-rot: an intact artifact that is the *wrong* artifact. This is the workload-kernel cache-skew that currently mimics real bugs, and a path-trusting cache cannot see it at all.
- [ ] Keep caching within the per-tenant/trust boundary (S2); dm-verity roothash chain unchanged (S4).
- [ ] Tests: cache-hit-verifies, tampered-cache-entry-rejected, skewed-kernel-detected, wrong-but-intact-artifact-detected. `VERIFICATION.md` row (planted: flip a byte in a cached kernel → verify-on-read rejects; swap two intact cached kernels → identity discrepancy fires).

### WS7 — σ/κ separation and the transform descriptor (recon §7.8)

New scope from the 2026-08-01 revision. Every mvm content-address surface is `Identity`-transform today, so σ and κ are numerically equal everywhere and this is a type separation with no migration. The moment any surface compresses, encrypts, deltas or erasure-codes at rest, modelling this as one label — or as an "encrypted" boolean — costs a format migration per transform family. Precedent is unanimous: git object IDs never hash the bytes on disk (loose objects deflated, packed objects delta-encoded), and ZFS compresses and encrypts beneath a checksum carried in the parent block pointer.

- [ ] Introduce the pair as disjoint types with no conversion: **σ** the protocol digest over plaintext, **κ** the storage address over bytes at rest (path derivation, verification target, unit of transfer). Extend `mvm_core::semantic_address`'s identity taxonomy rather than starting a new one.
- [ ] Model σ as a **set** — one κ reachable by ≥1 σ — which is what a dual-hash transition and multi-axis registration need, and what WS0's σ-set contract records as policy.
- [ ] Represent the descriptor as an open enumeration, not a boolean: `framing: Whole | Fixed{frame_size} | Chunked{manifest}`, `per_frame: [Identity | Aead | Deflate | Delta{base} | Erasure{k,m}]`, `seek_map: Implicit | Explicit{cumulative} | None`. Framing is the outer layer; transforms apply per frame, which is what keeps ranged reads possible — whole-object sealing turns a ten-byte range request against a large object into a whole-object operation, removing the operation rather than slowing it.
- [ ] Enforce S7 at the type level: an address family that admits MD5/CRC32C/CRC64 must not compile. Compile-fail test, not review.
- [ ] `VERIFICATION.md` row (planted: add a σ→κ conversion → compile-fail test fires).

## Sequencing

Reordered by the 2026-08-01 revision. **WS6 first** — integrity-on-read is the unenforced property, and plan 279 WS1 is blocked behind it. **WS3 second**, freezing address behavior before anything else touches it. **WS7 alongside WS3** — the σ/κ types are what WS3's vectors record, and doing it while every transform is still `Identity` is the whole reason it is cheap. Then WS1 (it makes `check-no-overclaim` trustworthy per S6), then WS4 (consumes WS3's corpus). WS5 is independent throughout. WS0's remaining ratification items are paperwork and gate nothing. Each workstream is its own PR.

## Relationship to the build/CAS thread

`specs/research/fast-attestable-content-addressed-builds-and-lean4.md` (#2011) and plan 279 cover the same content-addressing question from the build side. The seam is WS6 and it is deliberately owned here — 279 defers to it by name. Two consequences:

- Do not re-derive a CAS in WS6. `mvm_core::pack_cache` is a content-addressed cache with verify-on-read, quarantine staging and atomic-rename publish; `mvm_core::packs::PackManifest` is already a SLSA-shaped provenance manifest.
- The Lean 4 endpoint of recon §6 U5 (a machine-checked reference spec as the third oracle, recon §9) is scoped in the build/CAS research doc, not here. This plan stops at the ≥2-implementation bar.

## Deferred to later recon phases (out of scope)

Recon Phase 2 (interop alignment — the σ-set contract, canonical wire form and the transform descriptor agreed with the sibling projects **before either side ships a non-identity transform**; in-toto/SLSA canonicalization; reading `uor-foundation`; evaluating `uor-addr-1`) and Phase 3 (holospace object model into mvmd, `hologram-ai` interop for the `ai` command, distributed transport, and an attenuatable-capability format only on a concrete delegation trigger) are trigger-gated per recon §11 and are not part of this plan.

Phase 3's distributed-transport item carries two prerequisites recorded in S9 and recon §7.11 — a multiset-homomorphic fingerprint, and never signing a reconciliation root. They are noted here so they are not rediscovered after an implementation exists.
