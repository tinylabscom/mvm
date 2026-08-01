# Content-addressing conformance and defense: claim tiers, an over-claim gate, replay vectors, and cache verify-on-read

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Proposed, reconciled against `main` on 2026-08-01. Phase 0/1 of the UOR × Hologram cross-project recon (`specs/research/uor-hologram-cross-project-recon.md`). WS0 and WS2 are **already satisfied by shipped work** (see "Landed since this plan was written"); WS1 and WS5 are narrower than first written because the substrate they proposed to invent already exists. WS3, WS4 and WS6 are the real remaining scope. Not yet scheduled into `specs/SPRINT.md`; do not start a workstream until an owner moves it into the active sprint.

**Goal:** Harden mvm's claim→witness program and broaden content-addressing coverage, taking **zero** UOR/Hologram code dependency. Two convergent outcomes: (1) the claim ledger gains a single reconciled evidence tier, a replay-vector lane, and an explicit two-verifier oracle bar; (2) the build/runtime cache — the kernel first — becomes content-addressed with verify-on-read, closing a live cache-skew/poisoning class. Both fall out of the same canonicalization-rigor effort; see recon §6 (methodology) and §7 (defense).

**Architecture:** Six workstreams, each its own PR, sharing no code:

- **WS0** Decide & scope (Phase 0) — **done**, except the axis ratification line.
- **WS1** Claim evidence tiers (recon U1) — **reconcile two tier vocabularies that already exist**, not invent one.
- **WS2** Prose over-claim meta-gate (recon U2) — **shipped** as `xtask check-no-overclaim`.
- **WS3** Replay golden-vector lane (recon U4) — **open**, and the highest-value remaining item.
- **WS4** Two-verifier oracle bar (recon U5) — extend existing host/no_std parity.
- **WS5** Falsifiability binding (recon U3) — bind red-proofs to witnesses; the gates and the `VERIFICATION.md` rows already exist.
- **WS6** Content-address kernel + build cache, verify-on-read (recon §7.2 defensive coverage) — **open, and blocking plan 279 WS1**.

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
- **No BLAKE3 re-axis.** SHA-256 stays the canonical axis (WS0); a second axis is a Phase-2 interop decision, not this plan.
- **No runtime/fleet/AI interop** (holospace object model, hologram-ai, distributed transport) — recon Phase 3, trigger-gated.
- **No third claims-ledger file.** `specs/claims/catalog.md` is gone and stays gone; extend `model/claims.toml` and the ADR-001 table.
- **No new capability system, and no custom Ed25519 + hash-chain delegation scheme** (recon §7.7). A content-addressed permission is not authority — κ certifies that a packet *contains* a permission string, never that it was *granted*. mvm's signed, validity/nonce-bound `ExecutionPlan` (claim 8), broker `services` binding (claim 12) and destination-bound signed credentials (claim 13) are already the working form. An established attenuatable format (Macaroons, Biscuit) is evaluated **only** when a concrete offline or multi-hop delegation requirement appears, and then against a written bearer/replay/revocation threat model.
- **No per-packet signing on the hot vsock path** (recon §7.7). Authenticate and bind authority at session/connection admission; carry only the already-bound flow/session identity afterwards. Every chain-signed `AuditEntry` already records the governing `plan_id`, so a second capability digest per flow would duplicate an existing binding.

## Security considerations — settle before writing code

- **S1 — address ≠ authorization (invariant).** Every new content-address check verifies integrity only. It must never become an admission decision; the signed `ExecutionPlan` + `key_id`-pinned bundle remain the sole authority. WS6's verify-on-read gates *cache trust*, not *workload admission*.
- **S2 — cross-tenant dedup is a leak.** WS6's content-addressed cache must not dedup across a tenant/trust boundary (a shared address confirms two tenants hold identical content; an address fingerprints known content). Key the cache within the existing per-tenant boundary.
- **S3 — verify-on-read must fail closed.** A cache hit whose recomputed address ≠ the key is a tamper/skew signal: reject + evict, never serve. Absence of a hash must not fall back to trusting the path.
- **S4 — do not weaken dm-verity.** Content-addressing the kernel is additive provenance; the workload rootfs dm-verity roothash chain (claim 3) is unchanged and remains authoritative for the sealed rootfs.
- **S5 — NFC decision.** `SemanticAddress` NFC-normalizes; `ir_hash`/`plan_id` do not. WS3 pins the *current* behavior as a replay vector first (freeze what ships), then WS1/owner decides whether to converge on NFC — never silently change an address.
- **S6 — one tier vocabulary, or the gates disagree.** Two independent honesty axes are live: `model/claims.toml` `level` (`some-true` | `build` | `open`) and the ADR claim-frontmatter `status` (`Planned` | `Preview` | `Shipped` | `Not-claimed`) that `check-no-overclaim` enforces. Nothing currently checks them against each other, so a claim can read `open` in the register and `Shipped` in its frontmatter — which would silently disengage the over-claim gate on a property that was only ever measured. WS1 exists to close that, and must not introduce a third vocabulary.

## Workstreams

### WS0 — Decide & scope (Phase 0)
- [x] Land this plan + `specs/research/uor-hologram-cross-project-recon.md` (#1964).
- [ ] Owner ratifies "conform, don't consume" as recorded policy (a line in ADR-001, or a short ADR referencing the recon).
- [ ] Pin SHA-256 as the canonical content-address axis (documented; BLAKE3 deferred to Phase 2).
- [ ] Owner moves WS1 + WS3–WS6 into `specs/SPRINT.md` when scheduling; until then they stay Proposed.

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

### WS6 — Content-address the kernel + build cache, verify-on-read (defense)

**Downstream dependency: plan 279 WS1 (`ActionDigest`) is blocked on this landing** — plan 279 states the closure explicitly ("`~/.mvm/dev/builds/<rev>/` is served on a hit if `rootfs.ext4` merely exists as a file … Closing this is plan 276 WS6, not this plan"). `specs/SPRINT.md` already carries the same note. Schedule WS6 accordingly; it is no longer the independent tail of this plan.

- [ ] Identify the workload/builder kernel cache read path (the one with no staleness check) and the `mvm-build` artifact cache read paths, including `~/.mvm/dev/builds/<rev>/`.
- [ ] Add a content-address (SHA-256) to each cached artifact's key and verify-on-read on every hit (recompute, compare, fail closed per S3; evict on mismatch). `mvm_core::pack_cache` already implements exactly this discipline for packs — reuse it rather than writing a second cache.
- [ ] Keep caching within the per-tenant/trust boundary (S2); dm-verity roothash chain unchanged (S4).
- [ ] Tests: cache-hit-verifies, tampered-cache-entry-rejected, skewed-kernel-detected. `VERIFICATION.md` row (planted: flip a byte in a cached kernel → verify-on-read rejects).

## Sequencing

WS0's two open ratification items are paperwork and gate nothing. **WS3 first** — it freezes address behavior before anything else touches it, and it is the only remaining item with no substrate already in place. WS1 next (it makes `check-no-overclaim` trustworthy per S6). WS4 consumes WS3's corpus, so it follows. WS5 is independent. **WS6 should be scheduled early despite being last in the list**, because plan 279 WS1 waits on it. Each workstream is its own PR.

## Relationship to the build/CAS thread

`specs/research/fast-attestable-content-addressed-builds-and-lean4.md` (#2011) and plan 279 cover the same content-addressing question from the build side. The seam is WS6 and it is deliberately owned here — 279 defers to it by name. Two consequences:

- Do not re-derive a CAS in WS6. `mvm_core::pack_cache` is a content-addressed cache with verify-on-read, quarantine staging and atomic-rename publish; `mvm_core::packs::PackManifest` is already a SLSA-shaped provenance manifest.
- The Lean 4 endpoint of recon §6 U5 (a machine-checked reference spec as the third oracle, recon §9) is scoped in the build/CAS research doc, not here. This plan stops at the ≥2-implementation bar.

## Open — needs the revised recon

A later revision of the recon exists as a published artifact (`a4642b38-55a7-4516-83d4-827aeeb8cb7c`, dated 2026-08-01, method "source-level read · 24 repos · upstream crate source · primary literature"). Its Finding 02 is reframed from "mvm is ahead on every security-critical primitive" to **"attestation coverage across the ecosystem is asymmetric, and integrity is the shared gap"**, and Finding 03 to "conform, don't consume — and the conformance discipline is the asset". That is a posture change, not a wording change: this plan's premise is that mvm is strictly ahead and only needs coverage breadth.

- [ ] Fold the revised findings into the recon note and re-check this plan's premise against them — in particular whether "integrity is the shared gap" changes WS6's priority relative to WS3.

## Deferred to later recon phases (out of scope)

Recon Phase 2 (interop alignment — axis / wire-form / in-toto canonicalization, reading `uor-foundation`, evaluating `uor-addr-1`) and Phase 3 (holospace object model into mvmd, `hologram-ai` interop for the `ai` command, distributed transport, and an attenuatable-capability format only on a concrete delegation trigger) are trigger-gated per recon §11 and are not part of this plan.
