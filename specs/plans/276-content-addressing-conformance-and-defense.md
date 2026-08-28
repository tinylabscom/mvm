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
- `WorkloadAddress` = `sha256(JCS(NFC(IR)))`, pinned to published UOR-ADDR fixtures by `matches_published_uor_addr_json_fixtures`.

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
- **S5 — NFC decision.** `WorkloadAddress` NFC-normalizes; `ir_hash`/`plan_id` do not. WS3 pins the *current* behavior as a replay vector first (freeze what ships), then WS1/owner decides whether to converge on NFC — never silently change an address.
- **S7 — an address digest must be collision-resistant; an attestation digest need not be.** MD5, CRC32C and CRC64 are legitimate *attestations* and disqualified as *addresses*. Enforce the distinction with disjoint types and a compile-fail test, not with review — the same posture `mvm_core::workload_address` already takes by having no conversions between identity families.
- **S8 — never sign state that cannot be substantiated.** The order is content → index → root → signature → publication. A crash before signing is recoverable; the reverse order forks the chain with no recovery path. This binds WS3's transcript-root vector and any future signed root.
- **S9 — a reconciliation root is not a commitment.** If distributed transport is ever revisited (recon Phase 3), the fingerprint must be multiset-homomorphic — an XOR aggregation lets a peer withhold arbitrary data by claiming absence, with no collision-finding and no functional-test signal — and an MST page/root digest from a non-cryptographic hash must never be signed. Out of scope here; recorded so it is not rediscovered late.
- **S6 — the two honesty registers are separate, and the witness bar is the real gap.** *(Corrected 2026-08-02. The first draft of this said `model/claims.toml` `level` and the ADR claim-frontmatter `status` were two vocabularies over the same claims, and that a claim reading `open` in one and `Shipped` in the other would silently disengage `check-no-overclaim`. That is wrong. They are separate registers with no shared key: the model holds 16 numbered `MVM-SEC-NN` claims keyed by number, the frontmatter holds 3 phrase-gating claims keyed by name — `trust-gradient`, `catalog`, `egress-no-secret-to-guest` — and no claim appears in both. No mistiering of the kind described is reachable.)* The register's honesty half is already enforced: `check-honesty` is the behavioural gate over `open`/`some-true` IDs and `check-conformance` the structural one. What nothing enforced was the **evidence** half — a claim could be delisted from a whole kind of witness with every gate green.

## Workstreams

### WS0 — Decide & scope (Phase 0)
- [x] Land this plan + `specs/research/uor-hologram-cross-project-recon.md` (#1964).
- [ ] Owner ratifies "conform, don't consume" as recorded policy (a line in ADR-001, or a short ADR referencing the recon).
- [ ] Record the **σ-set contract** as the address-identity policy (one storage address reachable by ≥1 protocol digest), superseding the earlier "pin SHA-256 as the canonical axis" line. SHA-256 remains what mvm mints on.
- [ ] Owner moves WS1 + WS3–WS7 into `specs/SPRINT.md` when scheduling; until then they stay Proposed.

### WS1 — Pin the evidence each claim rests on (U1)

Scope corrected twice on contact with the data, and both corrections are worth recording because each was a plausible-sounding rule that the tree refuses.

**U1 as written is not implementable here.** It asks that a `shipped` claim carry both a live `fn:` and a live `ci:` witness. Eight of the fifteen `build`-level claims fail that bar today, and for several the failure is structural rather than an oversight: MVM-SEC-04 ("no DevOnly verbs in a production-safe run") and MVM-SEC-05 (fuzz coverage) are properties of runtime policy and CI, observable through conformance and workflow witnesses. Forcing an `fn:` witness for every claim buys fabricated tests, not assurance. Enforcing one bar across claims that differ in kind is the wrong shape.

**What the tree actually lacked** was any pin on the evidence a claim rests on. `check-claim-catalog` verifies that *listed* witnesses exist, and the ledger cross-check catches a witness removed from one file — but removing it from both `model/claims.toml` and the ADR-001 row, which is how a witness would really be retired, left every gate green. Demonstrated: delisting `ci:seccomp-functional` from both files reported `clean (16 claims, 48 witnesses verified)`, with claim 1 having quietly lost its only CI evidence.

- [x] Add `witness_kinds` to each claim in `model/claims.toml`, declaring the kinds of evidence that claim legitimately rests on, with the non-uniformity explained in the file rather than left implicit.
- [x] Extend `check-claim-catalog`: every declared kind must have ≥1 live witness, and every present kind must be declared. Dropping a kind becomes an explicit edit to the declaration — visible in review, and reading as the reduction in evidence it is.
- [x] Falsifiability rows for both directions, each with the planted defect recorded.
- [ ] Consider whether the three frontmatter claims should also carry a witness declaration; they are gated by phrase today and by nothing else.

### WS2 — Prose over-claim meta-gate (U2) — shipped
- [x] `xtask check-no-overclaim` scans user-facing `.md` and `.rs` for phrases gated by a claim whose `status` is not `Shipped`, honouring per-claim `exempt_paths`.
- [x] Wired into the Lint lanes; `VERIFICATION.md` carries its falsifiability row.

No residual work. WS1's cross-field check is what makes this gate trustworthy — a claim mistiered to `Shipped` disengages it, which is why S6 is a security consideration and not a tidiness one.

### WS3 — Replay golden-vector lane (U4)

Premise verified before building, and this time it held: five of seven surfaces had no frozen address at all. `WorkloadAddress` (13 literals, incl. 12 published UOR-ADDR fixtures) and the plan-280 transcript root were the exceptions. `bundle_sha256`'s single literal was `sha256("abc")` — a textbook vector pinning lowercase-hex output, not a bundle address.

The sharpest finding is what the existing `ir_hash` tests are: **all four are relational** — stable for identical input, key-order independent, different values differ, 64 hex long. A canonicalization change that moves every address consistently satisfies all of them. Demonstrated by planting exactly that (hash the canonical form with a trailing newline): the four unit tests stayed green and only the new vectors fired.

- [x] `crates/mvm-contract/tests/address_vectors.rs` — 14 vectors over `ir_hash`, `leaf_hash`, `interior_hash`, `merkle_root`. Includes the RFC-6962 odd-tail case (promote, never duplicate — the property that avoids the duplicate-leaf forgery) and astral-plane keys, where JCS's UTF-16 sort order diverges from UTF-8.
- [x] NFC and NFD forms pinned as *different* addresses, recording in a test that `ir_hash` does not normalize (S5's status quo) rather than leaving it as tribal knowledge.
- [x] `compute_plan_id` vectors in `plan/content_id.rs`. Worth pinning specifically because this surface does **not** use JCS — it relies on serde_json's default key ordering, which holds only while `preserve_order` is off. `check-content-address-determinism` pins that feature flag; nothing pinned the address the flag protects.
- [x] `bundle_sha256` vectors in `plan/bundle.rs`, including a raw-byte case (NUL, 0xff, 0x80) that a digest passing through any string conversion would fail.
- [x] Seeded from shipped behaviour, so they freeze what ships rather than asserting what it ought to be. `MVM_PRINT_ADDRESS_VECTORS=1` prints instead of asserting, making a reseed a deliberate act with a diff that has to be justified.
- [x] Falsifiability rows for both crates, each with the planted defect recorded.
- [x] The audit `prev_hash` spine, closed by WS4: the spine is exercised by the frozen signed corpus, whose `a_reordered_corpus_breaks_the_chain` vector swaps two validly-signed entries and must fail — signatures alone do not order a chain.
- [ ] Fold `WorkloadAddress`'s existing 13 goldens into the same corpus shape, so WS4 has one vector set rather than two conventions.

### WS4 — Two-verifier oracle bar (U5)

**What the bar actually needed.** `mvm_verify_matches_supervisor_chain` already compared the two implementations, but over a chain generated **fresh with a random key on every run**. Those bytes exist only inside that process, so they can never reach a verifier that does not link the host signer — and an oracle bar means little if each implementation only ever sees input it produced itself.

**Honesty about the third verifier.** The riscv32 target is `cargo build -p mvm-contract --lib` only; bare metal has no test harness, so it is a *compile* oracle, not an executing one. The executing pair is the host verifier and the `no_std` mirror, with wasm executing the mirror a second way. Claiming three executing oracles would have been wrong.

- [x] `tests/vectors/audit-chain-v1.jsonl` + `.pubkey` — a signed chain frozen on disk. Deterministic via a fixed signing seed and fixed timestamps (Ed25519 is deterministic per RFC 8032). `MVM_REGEN_AUDIT_CORPUS=1` rewrites it.
- [x] `mvm-hostd` owns generating it and asserts the committed bytes still match what the signer emits, so the corpus cannot drift from the writer unnoticed — the failure names the real consequence: every chain already written just became unverifiable.
- [x] The `no_std` mirror reads the same bytes via `include_str!` rather than the filesystem, which is what lets the identical test execute under `wasm32-wasip1`.
- [x] Vectors cover the shapes the two must agree on: optional-field absence (`skip_serializing_if`), content-address labels that lineage verification reads back, a tampered entry, and a reordering of validly-signed entries.
- [x] `model/claims.toml` records `independent_verifiers` on MVM-SEC-08, with the two corpus tests as witnesses. The field is documented as meaning *one shared corpus*, since implementations that only see their own output agree by construction.
- [x] Falsifiability: diverging the mirror's serialization of an absent optional field fires `SignatureInvalid` over the shared corpus.

### WS5 — Falsifiability binding (U3)

Narrower than first written: the mutation surface, the freshness gate and the 36 `VERIFICATION.md` rows all exist. What is missing is the *binding* from a witness to its red-proof.

- [ ] Add a `falsified_by:` field per witness in `model/claims.toml` pointing at the mutation/negative-test that goes red when the witness breaks.
- [ ] Extend `check-claim-catalog` (or `check-mutation-witnesses`) to fail if a witness has no recorded red-proof.
- [ ] Backfill red-proof references; note the CI-only witnesses that mutation testing structurally cannot reach (mirror plan 274 WS3).
- [ ] `VERIFICATION.md` row (planted: strip a witness's red-proof → gate fires).

### WS6 — Content-address the caches, verify on read (lead item; dev-build half shipped)

**Why this is first.** Per the revised recon §7.1, integrity-on-read is the one attestation property no surveyed system enforces — not a coverage nicety. **Downstream dependency: plan 279 WS1 (`ActionDigest`) was blocked on this** — plan 279 states the closure explicitly ("`~/.mvm/dev/builds/<rev>/` is served on a hit if `rootfs.ext4` merely exists as a file … Closing this is plan 276 WS6, not this plan").

There are two read paths and they fail differently. The dev-build artifact cache is closed; the kernel cache is not.

**Shipped in #2053 — the dev-build artifact cache (`~/.mvm/dev/builds/<rev>/`):**

- [x] `mvm_core::action` carries the canonical action/artifact types and `verify_artifacts_on_disk`; the build-cache record content-addresses the artifacts rather than naming a directory.
- [x] Verify on read on every hit, failing closed per S3: an absent record, an unparseable record, or one that fails verification is a **cold miss**, so a hit that cannot be re-verified is never served.
- [x] Eviction removes **both the record and the build directory**. Evicting only the record leaves the poisoned tree in place under a name a later build can re-adopt — trust-by-name through the back door. (This is the sharper half of the fix and the reason a record-only eviction is not sufficient.)
- [x] Also closed a mid-build leak: a failure between materialisation and completion left `dev_builds_dir()` populated, because cleanup was only reached on the success path.
- [x] Keeps caching within the per-tenant/trust boundary (S2 — the dev build cache is already per-`MVM_HOME`); dm-verity roothash chain untouched (S4). Per S1 this gates *cache trust*, never workload admission.

**Still open — the workload/builder kernel cache (`~/.mvm/cache/builder-vm/<arch>/kernels/<label>/vmlinux`):**

- [ ] It remains path-trusting: `mvm_build::kernel_fetch::resolve_kernel` returns `Cached(path)` on `path.exists()`, and `resolve_pinned_kernel_with` maps that arm straight to a path with no check. Worse than the plan first assumed — `verify_fetched_kernel`, which hashes against `KernelArtifactId::artifact_hash` and deletes on mismatch, **has no production caller at all**: not on the fetch path, not on the read path, despite its own doc saying installed builds should verify against the pin before boot. Wiring it needs the published per-arch expected hash threaded to both sites (the release checksum manifest, as `download_dev_image` already does). **Scoped as plan 288** (`specs/plans/288-kernel-cache-verify-on-read.md`), which also removes the shape that let the check drift unconnected: `KernelResolution::Cached` hands out a bare `PathBuf`, so nothing signals that a step was skipped.
- [ ] Cover the **identity-discrepancy** class here too: an intact kernel that is the *wrong* kernel is exactly the cache skew that mimics real bugs, and an existence check cannot see it.
- [ ] Size the check to the object (recon §7.9). Full rehash on every hit is correct and bounded where a hit replaces a builder-VM boot, but the cold tier is unaddressed: a background scrub over the reachability walk is the only tier that catches the measured corruption locality, since on-access verification never visits the blocks that are quietly rotting.

### WS7 — σ/κ separation and the transform descriptor (recon §7.8)

**Premise corrected.** This workstream said σ/κ was "cheap now because every mvm content-address surface is `Identity`-transform today." That is wrong, and the correction strengthens the case rather than weakening it — there are already two live non-identity transforms:

- An **OCI layer is `tar+gzip`**. The digest the fetch path verifies is over the compressed bytes — κ. The config's `diff_id` is the uncompressed digest — σ. `diff_id` is written only into test fixtures and is never read or verified; not a vulnerability, since verifying κ transitively pins what it decompresses to, but σ is declared-and-unconsumed.
- A **sealed transcript stores ciphertext**, so `ChunkRecord.sha256_hex` is κ. σ is deliberately absent, because a plaintext digest on a third-party-verifiable chain is a confirmation oracle (S2).

The tree was already keeping them apart correctly, under different names. What it lacked was a type that makes the distinction unrepresentable-if-wrong rather than a convention.

- [x] `mvm_core::at_rest`: `ProtocolDigest` (σ) and `StorageAddress` (κ) as disjoint newtypes over the validated `Sha256Hex`, with no `From`/`Into`/`Deref` between them.
- [x] σ modelled as a **set** — `AddressBinding` holds one κ and a `BTreeSet` of σ, which is what a dual-hash transition and multi-axis registration need and what a single-value σ forecloses.
- [x] The descriptor as an open enumeration, not a boolean: `Framing` (whole / fixed / chunked-by-manifest) × `per_frame: Vec<FrameTransform>` (identity / aead / deflate / delta / erasure) × `SeekMap` (implicit / explicit / absent). A chunked manifest is typed κ, since it is itself a stored object.
- [x] S7 enforced by construction: both constructors go through `Sha256Hex`, whose width check rejects MD5 (32 hex), CRC32C (8) and CRC64 (16). Those stay legitimate attestations and are disqualified as addresses without review having to catch it.
- [x] Compile-fail doctest, and it needed sharpening: the first version used a bare `let kappa: StorageAddress = sigma;`, which never compiles whatever impls exist, so it passed **with a `From` bridge present** — a vacuous test. Rewritten to `sigma.into()`, which compiles exactly when a bridge exists; planting the bridge now fails it.
- [x] Cross-referenced from the `workload_address` taxonomy prose, which separates *what* is identified; this is the orthogonal *which bytes* axis.
- [ ] Adopt the types at the two live sites — the OCI layer/`diff_id` pair and the transcript chunk records. Deliberately separate: introducing the vocabulary is additive, and changing what those paths store is a format question that wants its own review.

## Sequencing

**Done:** WS2 (shipped before this plan was written), WS6's dev-build half (#2053), WS1.

**Next, in order:**

1. **WS3 — the replay golden-vector corpus.** The foundational item, and the only one with no substrate in the tree at all: `check-content-address-determinism` pins the `serde_json preserve_order` drift mechanism, not any address. It goes first because it freezes address behaviour before anything else touches it, and because WS4 consumes its corpus.
2. **WS7 — σ/κ separation**, alongside WS3. The types are what WS3's vectors record, and every surface being `Identity` today is the entire reason this is cheap now and a per-transform-family migration later.
3. **WS4 — the ≥2-verifier bar.** Blocked on WS3's corpus existing; the verifiers themselves (host, no_std/wasm, riscv32) already do.
4. **WS5 — falsifiability binding.** Independent of the rest. The mutation surface, the freshness gate and the `VERIFICATION.md` rows all exist, so this is the witness → red-proof binding and nothing more.
5. **WS6's kernel half** — scoped separately as plan 288, because it needs the published pin threaded through the release surface.

WS0's remaining ratification items are paperwork and gate nothing. Each workstream is its own PR.

**A note for whoever picks these up.** Two of this plan's workstreams turned out to be specified against a tree that did not match the spec: WS2 was already shipped and broader than described, and WS1's premise — two tier vocabularies over the same claims — was simply false, since the two registers share no key. Both were caught by reading the code before writing any, and both corrections are recorded above rather than quietly amended. Treat the remaining descriptions as hypotheses to verify first, not as instructions.

## Relationship to the build/CAS thread

`specs/research/fast-attestable-content-addressed-builds-and-lean4.md` (#2011) and plan 279 cover the same content-addressing question from the build side. The seam is WS6 and it is deliberately owned here — 279 defers to it by name. Two consequences:

- Do not re-derive a CAS in WS6. `mvm_core::pack_cache` is a content-addressed cache with verify-on-read, quarantine staging and atomic-rename publish; `mvm_core::packs::PackManifest` is already a SLSA-shaped provenance manifest.
- The Lean 4 endpoint of recon §6 U5 (a machine-checked reference spec as the third oracle, recon §9) is scoped in the build/CAS research doc, not here. This plan stops at the ≥2-implementation bar.

## Deferred to later recon phases (out of scope)

Recon Phase 2 (interop alignment — the σ-set contract, canonical wire form and the transform descriptor agreed with the sibling projects **before either side ships a non-identity transform**; in-toto/SLSA canonicalization; reading `uor-foundation`; evaluating `uor-addr-1`) and Phase 3 (holospace object model into mvmd, `hologram-ai` interop for the `ai` command, distributed transport, and an attenuatable-capability format only on a concrete delegation trigger) are trigger-gated per recon §11 and are not part of this plan.

Phase 3's distributed-transport item carries two prerequisites recorded in S9 and recon §7.11 — a multiset-homomorphic fingerprint, and never signing a reconciliation root. They are noted here so they are not rediscovered after an implementation exists.
