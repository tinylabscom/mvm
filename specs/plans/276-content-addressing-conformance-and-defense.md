# Content-addressing conformance and defense: claim tiers, an over-claim gate, replay vectors, and cache verify-on-read

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Proposed — Phase 0/1 of the UOR × Hologram cross-project recon (`specs/research/uor-hologram-cross-project-recon.md`). Not yet scheduled into `specs/SPRINT.md`; do not start a workstream until an owner moves it into the active sprint.

**Goal:** Harden mvm's claim→witness program and broaden content-addressing coverage, taking **zero** UOR/Hologram code dependency. Two convergent outcomes: (1) the claim ledger gains evidence tiers, a prose over-claim gate, a replay-vector lane, and an explicit two-verifier oracle bar; (2) the build/runtime cache — the kernel first — becomes content-addressed with verify-on-read, closing a live cache-skew/poisoning class. Both fall out of the same canonicalization-rigor effort; see recon §6 (methodology) and §7 (defense).

**Architecture:** Six workstreams, each its own PR, sharing no code:

- **WS0** Decide & scope (Phase 0): ratify "conform, don't consume" as policy; pin SHA-256 as the canonical content-address axis; land this plan + the recon note.
- **WS1** Claim evidence tiers (recon U1).
- **WS2** Prose over-claim meta-gate (recon U2).
- **WS3** Replay golden-vector lane (recon U4).
- **WS4** Two-verifier oracle bar (recon U5) — extend existing host/no_std parity.
- **WS5** Falsifiability binding (recon U3) — extend `specs/VERIFICATION.md` + the mutation-witness gate.
- **WS6** Content-address kernel + build cache, verify-on-read (recon §7.2 defensive coverage).

**Tech Stack:** Rust, `xtask` (gates), `specs/claims/catalog.md` + `specs/adrs/001-microvm-security-posture.md` (the ledger), `specs/VERIFICATION.md` (falsifiability), `cargo-nextest`, `mvm-conformance` (cucumber), GitHub Actions (`ci.yml` + `ci-full.yml` Lint jobs, `security.yml`). SHA-256 + `serde_jcs` + `ed25519-dalek` (existing; **no new crypto, no new runtime dependency**).

**What mvm already has (extend, do not rebuild):** `xtask check-claim-catalog` (witness existence + contiguity); the mutation-witness gate (`check-mutation-witnesses`, #1934); `specs/VERIFICATION.md` §Falsifiability rows; host↔no_std audit-verifier parity (`mvm_verify_matches_supervisor_chain`); and `SemanticAddress` = `sha256(JCS(NFC(IR)))` pinned to published UOR-ADDR fixtures. This plan builds on those; it does not duplicate them.

## Provenance

Sourced from a code-level read of UOR-Foundation + Hologram-Technologies (`specs/research/uor-hologram-cross-project-recon.md`). The disposition is **conform, don't consume**: adopt the ecosystem's conformance/honesty discipline as patterns; take no `uor-addr`/`uor-prism`/`uor-foundation` dependency. Recon Phases 2 (interop alignment) and 3 (runtime/fleet/AI) are trigger-gated and out of scope here.

## Global Constraints

- Work in the dedicated worktree `../.worktrees/mvm-uor-hologram` on branch `docs/uor-hologram-recon` (this plan + the recon note land there first); each later workstream gets its own worktree/branch/PR. git via `git -C <wt-abs>`.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs-in-comments`); spec docs may reference them.
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push (CI Lint uses nightly rustfmt); `cargo nextest run --workspace` + `cargo test --workspace --doc` green before any task is marked done.
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or PR body.
- Scratch files under `/tmp/`, never in the working tree.
- Every new `xtask` gate is added to **both** `.github/workflows/ci.yml` and `.github/workflows/ci-full.yml` Lint jobs — the gate list is duplicated and a gate in only one silently does not run.
- Every new gate gets a row in `specs/VERIFICATION.md` §Falsifiability recording the planted defect that proved it fires.
- Tick this plan's checkboxes and update `specs/SPRINT.md` in the same commit as the work.

## Non-goals (do not re-propose)

- **No `uor-addr`/`uor-prism`/`uor-foundation` dependency.** It drags the prism substrate (~156 transitive crates incl. FHE/tensor) and duplicates existing `sha2`/`serde_jcs`/`ed25519-dalek`. Conform to the wire label; do not consume the crate.
- **No hash-only trust.** Content-addressing stays an integrity layer *under* the signed, plan-bound authorization — never the hash as permission (see S1).
- **No BLAKE3 re-axis.** SHA-256 stays the canonical axis (WS0); a second axis is a Phase-2 interop decision, not this plan.
- **No runtime/fleet/AI interop** (holospace object model, hologram-ai, distributed transport) — recon Phase 3, trigger-gated.

## Security considerations — settle before writing code

- **S1 — address ≠ authorization (invariant).** Every new content-address check verifies integrity only. It must never become an admission decision; the signed `ExecutionPlan` + `key_id`-pinned bundle remain the sole authority. WS6's verify-on-read gates *cache trust*, not *workload admission*.
- **S2 — cross-tenant dedup is a leak.** WS6's content-addressed cache must not dedup across a tenant/trust boundary (a shared address confirms two tenants hold identical content; an address fingerprints known content). Key the cache within the existing per-tenant boundary.
- **S3 — verify-on-read must fail closed.** A cache hit whose recomputed address ≠ the key is a tamper/skew signal: reject + evict, never serve. Absence of a hash must not fall back to trusting the path.
- **S4 — do not weaken dm-verity.** Content-addressing the kernel is additive provenance; the workload rootfs dm-verity roothash chain (claim 3) is unchanged and remains authoritative for the sealed rootfs.
- **S5 — NFC decision.** `SemanticAddress` NFC-normalizes; `ir_hash`/`plan_id` do not. WS3 pins the *current* behavior as a replay vector first (freeze what ships), then WS1/owner decides whether to converge on NFC — never silently change an address.

## Workstreams

### WS0 — Decide & scope (Phase 0)
- [ ] Owner ratifies "conform, don't consume" as recorded policy (a line in ADR-001, or a short ADR referencing the recon).
- [ ] Pin SHA-256 as the canonical content-address axis (documented; BLAKE3 deferred to Phase 2).
- [ ] Land this plan + `specs/research/uor-hologram-cross-project-recon.md` (this PR).
- [ ] Owner moves WS1–WS6 into `specs/SPRINT.md` when scheduling; until then they stay Proposed.

### WS1 — Claim evidence tiers (U1)
- [ ] Add a `tier:` field per claim in `specs/claims/catalog.md`: `shipped` | `preview` | `open`.
- [ ] Extend `xtask check-claim-catalog`: `shipped` requires a live `fn:` AND `ci:` witness; `open` must not appear in the ADR-001 numbered prose table; `preview` requires ≥1 witness.
- [ ] Backfill tiers for claims 1–15 (`shipped`), claim 16 (`preview`), and any `open` measured-not-asserted properties.
- [ ] Gate wired into `ci.yml` + `ci-full.yml` Lint; falsifiability row in `VERIFICATION.md` (planted: mistier an `open` claim as `shipped` → gate fires).

### WS2 — Prose over-claim meta-gate (U2)
- [ ] New `xtask` lint (or extend `check-claim-catalog`) scanning `preview`/`open` claim prose in ADR-001 / claim docs; fail on assertive verbs ("proves", "guarantees", "verified", "ensures", "cannot", "impossible") absent a `shipped` witness.
- [ ] Curate the verb list + an allow-mechanism for quoted/negated legitimate uses.
- [ ] Gate wired into both Lint lanes; `VERIFICATION.md` row (planted: add "this proves" to a preview claim → gate fires).

### WS3 — Replay golden-vector lane (U4)
- [ ] Create a frozen `(input → expected address)` corpus for **every** surface: `SemanticAddress`, `ir_hash`, `plan_id`, `bundle_sha256`/manifest, audit `prev_hash` spine, RFC-6962 Merkle root.
- [ ] A test recomputes each and asserts byte-equality; fails on any canonicalization drift (`serde_jcs` bump, field reorder, NFC change).
- [ ] Seed with current shipped behavior (freezes S5's NFC status quo). Include astral-plane-key + Unicode-normalization edge vectors.
- [ ] Run in nextest (workspace); `VERIFICATION.md` row (planted: reorder a JCS key emitter → vector mismatch fires).

### WS4 — Two-verifier oracle bar (U5)
- [ ] Make the WS3 replay corpus the shared vector set the existing host↔no_std audit-verifiers both consume.
- [ ] Add the riscv32/ESP32 verifier (edge tier) as the third independent oracle over the same corpus where it builds.
- [ ] Record in `specs/claims/catalog.md` which claims are backed by ≥2 independent verifiers.
- [ ] `VERIFICATION.md` row (planted: diverge one verifier's canonicalizer → parity test fires).

### WS5 — Falsifiability binding (U3)
- [ ] Add a `falsified_by:` reference per witness in `specs/claims/catalog.md` pointing at the mutation/negative-test that goes red when the witness breaks (reuse the mutation-witness surface #1934 + existing `VERIFICATION.md` rows).
- [ ] Extend `check-claim-catalog` (or the mutation-witness gate) to fail if a claim witness has no recorded red-proof.
- [ ] Backfill red-proof references; note the CI-only witnesses that mutation testing structurally cannot reach (mirror plan 274 WS3).
- [ ] `VERIFICATION.md` row (planted: strip a witness's red-proof → gate fires).

### WS6 — Content-address the kernel + build cache, verify-on-read (defense)
- [ ] Identify the workload/builder kernel cache read path (the one with no staleness check) and the `mvm-build` artifact cache read paths.
- [ ] Add a content-address (SHA-256) to each cached artifact's key and verify-on-read on every hit (recompute, compare, fail closed per S3; evict on mismatch).
- [ ] Keep caching within the per-tenant/trust boundary (S2); dm-verity roothash chain unchanged (S4).
- [ ] Tests: cache-hit-verifies, tampered-cache-entry-rejected, skewed-kernel-detected. `VERIFICATION.md` row (planted: flip a byte in a cached kernel → verify-on-read rejects).

## Sequencing

WS0 first (this PR). Then WS1 + WS3 (foundational, lowest risk; WS3 freezes address behavior before anything else touches it). WS2 and WS5 build on WS1's `tier:` field. WS4 consumes WS3's corpus. WS6 is independent and can run in parallel once WS0 lands. Each workstream is its own PR; none blocks another except the stated dependencies.

## Deferred to later recon phases (out of scope)

Recon Phase 2 (interop alignment — axis / wire-form / in-toto canonicalization, reading `uor-foundation`, evaluating `uor-addr-1`) and Phase 3 (holospace object model into mvmd, `hologram-ai` interop for the `ai` command, distributed transport) are trigger-gated per recon §11 and are not part of this plan.
