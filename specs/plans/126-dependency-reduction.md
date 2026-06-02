# Plan 126 — Dependency reduction

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the real third-party dependency weight — the heavy *optional* features and the duplicate/C-backed crates — and lock a forbidden-dep gate so it stays cut. This is the host/feature counterpart to 124's lean-agent cut; together they are where the dep graph actually shrinks. The 32→17 consolidation (121) delivers ~0 third-party reduction (build-units only), so this plan does not double-count it.

**Architecture:** Measure, prune, re-measure, gate. Each target is a feature-gated heavy dep whose closure is replaced by a lean one or relocated to mvmd: `sigstore` (manifest-verify), `opendal` (template-registry-s3), `pgp` (release signing), `aws-lc-rs` (C/cmake crypto). Then unify the duplicate `oci-client`/`reqwest` majors, and add the gate. Every step records a `cargo tree` delta — no asserted numbers.

**Tech Stack:** `cargo tree`, the `xtask check-forbidden-deps` gate (exists), `object_store` (the opendal replacement, shared with 123), `minisign` (the pgp replacement), `ring` (the aws-lc-rs replacement).

**Prereqs:** 121 (final crate homes). Coordinates with 123 (the `object_store` S3 client) and 127 (the dep-count dashboard consumes the re-baselined methodology).

**Re-baseline (measured 2026-05-31):** `Cargo.lock` is **735 packages** (the brief's "723" was stale) and per-crate closures are ~170 *lower* than an earlier count. Lock the `cargo tree` methodology in Phase A before tracking any delta.

---

## Phase A — re-baseline the methodology

### Task A1: one measurement method, written down

- [ ] **Step 1:** Define the canonical commands: total = `cargo tree --workspace -e no-dev --prefix none | sort -u | wc -l`; per-crate = `cargo tree -p <c> -e no-dev`; default-vs-full-feature = with and without the optional features. Record the **735** baseline + the per-crate closures of the targets below.
- [ ] **Step 2:** Commit a `docs/investigations/dep-baseline.md` with the method + the numbers. 127's dashboard reads from here. Every later task appends its delta.

## Phase B — prune the heavy optional features

### Task B1: `sigstore` (~120–150) — relocate or drop `manifest-verify`

The biggest single closure. It backs cosign verification for claim 14 (OCI provenance). Options: move the verification to **mvmd** (the control plane verifies before admit) or drop the in-`mvmctl` path.

- [ ] **Step 1:** Measure `cargo tree -p <crate that pulls sigstore> --features manifest-verify` closure.
- [ ] **Step 2:** Decide with the claim owner: claim 14's cosign verify is a *prod/admit* concern, and `--prod` admission policy lives in mvmd (memory: prod gate is mvmd's). So **relocate cosign verify to mvmd**; `mvmctl` keeps recording the OCI provenance label (the audit entry) but does not link sigstore. If a local verify is still wanted, gate it behind an off-by-default feature.
- [ ] **Step 3:** Remove `sigstore` from the default + the `mvmctl` build; re-measure. Claim 14's audit-label path (the part `mvmctl` owns) stays green; the cosign-verify gate moves to mvmd's plan. Commit with the delta.

### Task B2: `opendal` (~70) → `object_store`

Pre-decided with 123: one lean S3 client for the repo.

- [ ] **Step 1:** Replace `opendal` (`crates/mvm/Cargo.toml`, optional, template-registry-s3) with `object_store` (the same crate 123's S3 `MountProvider` uses, TLS pinned to `ring`). Failing test — the template-registry-s3 round-trips against `object_store`'s in-memory backend.
- [ ] **Step 2:** Drop `opendal` from the workspace; re-measure (expect ~70 gone, minus `object_store`'s own small closure). Commit.

### Task B3: `pgp` (~80) → `minisign`

Release signing. `pgp`/`sequoia` is a large closure for a sign-and-verify a release artifact.

- [ ] **Step 1:** Measure the `pgp` closure + find its call sites (release signing/verify).
- [ ] **Step 2:** Replace with `minisign` (tiny, Ed25519). Failing test — a release artifact signs + verifies under the new keypair; an old-format signature is *not* silently accepted (no back-compat — first version). Re-measure. Commit.

### Task B4: `aws-lc-rs` → `ring` (~6 + kills a C/cmake build)

`aws-lc-rs` is the C/cmake crypto backend; `ring` covers the same primitives without the native build. (123 already pins `object_store`'s TLS to `ring`; this removes the rest.)

- [ ] **Step 1:** Find what pulls `aws-lc-rs` (`cargo tree -i aws-lc-rs`) — likely rustls's default provider (rustls 0.23+) and/or a TLS stack.
- [ ] **Step 2:** Pin rustls to the `ring` `CryptoProvider` everywhere it's constructed; set the relevant `default-features = false` + `ring` features. Failing test — `cargo tree -i aws-lc-rs` is empty; TLS still works (a smoke connect). The native cmake build is gone (faster cold build — note it). Commit.

## Phase C — unify duplicate majors

### Task C1: `oci-client` / `reqwest` duplicate majors

Two major versions of the same crate inflate the lock + compile time.

- [ ] **Step 1:** `cargo tree -d` (duplicates) — identify the two `reqwest` (and/or `oci-client`) majors + who pulls each.
- [ ] **Step 2:** Align on one major (bump the lagging consumer, or feature-match). Failing test — `cargo tree -d | grep -E 'reqwest|oci-client'` shows one major each; the OCI + HTTP paths still pass their tests. Commit.

## Phase D — lock it

### Task D1: the forbidden-dep gate

- [ ] **Step 1:** Extend `xtask check-forbidden-deps` (exists) to fail if `sigstore`, `opendal`, `pgp`, or `aws-lc-rs` re-enter the default `mvmctl` closure (an allow-list of off-by-default features for the deliberately-gated ones). Failing test — adding one back trips the gate.
- [ ] **Step 2:** Final measure — total before/after in `dep-baseline.md`; the sum of B1–B4 + C1 is the headline reduction (alongside 124's ~25–35 agent crates). Commit. Wire the gate into `ci.yml` (with 128).

## Acceptance

- [ ] `dep-baseline.md` records the method + the 735 baseline + each task's delta (no asserted numbers — measured).
- [ ] `sigstore` out of the `mvmctl` default (cosign verify relocated to mvmd; claim 14's audit-label path intact); `opendal`→`object_store`; `pgp`→`minisign`; `aws-lc-rs` gone (`cargo tree -i aws-lc-rs` empty, C/cmake build removed).
- [ ] One major each for `reqwest`/`oci-client` (`cargo tree -d` clean for them).
- [ ] `check-forbidden-deps` trips if any of the four re-enter the default closure.
- [ ] `cargo test --workspace` + clippy + fmt green; the OCI / template-registry / release-signing / TLS paths still pass.

### deferred follow-ups

- [ ] The mvmd cosign-verify relocation is an **mvmd plan** (this plan only removes it from `mvmctl`).
- [ ] Periodic `cargo tree -d` sweep as the dashboard (127) surfaces new duplicates.

## Self-review

- **Spec coverage (brief 126):** re-baseline (A), sigstore/opendal/pgp/aws-lc-rs prune (B1–B4), oci-client/reqwest unify (C1), the gate (D1). The opendal→object_store unification is the one pre-grounded with 123.
- **Honesty:** every reduction is measured (`cargo tree` delta in `dep-baseline.md`), never asserted; the 735 re-baseline corrects the brief's 723. Claim 14's verify *relocates* (to mvmd), it isn't silently dropped — the audit-label path mvmctl owns stays green.
- **Division of labor:** this is the host/feature cut; 124 is the agent cut; 121 is ~0 — stated so the wins aren't double-counted.
- **Voice:** comments/notes mark the non-obvious (why sigstore relocates rather than drops, why aws-lc-rs removal also kills a cmake build), not the mechanics.
