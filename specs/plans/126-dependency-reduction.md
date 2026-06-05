# Plan 126 — Dependency reduction

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the real third-party dependency weight — the heavy *optional* features and the duplicate/C-backed crates — and lock a forbidden-dep gate so it stays cut. This is the host/feature counterpart to 124's lean-agent cut; together they are where the dep graph actually shrinks. The 32→17 consolidation (121) delivers ~0 third-party reduction (build-units only), so this plan does not double-count it. The whole-crate cuts here are also the **primary size driver** for 156 (binary-size reduction) — 156 re-measures `mvmctl`'s size after each task below lands.

**Architecture:** Measure, prune, re-measure, gate. Each target is a feature-gated heavy dep whose closure is replaced by a lean one or relocated to mvmd: `sigstore` (manifest-verify), `opendal` (template-registry-s3), `pgp` (release signing), `aws-lc-rs` (C/cmake crypto). Then unify the duplicate `oci-client`/`reqwest` majors, and add the gate. Every step records a `cargo tree` delta — no asserted numbers.

**Tech Stack:** `cargo tree`, the `xtask check-forbidden-deps` gate (exists), `object_store` (the opendal replacement, shared with 123), `minisign` (the pgp replacement), `ring` (the aws-lc-rs replacement).

**Prereqs:** 121 (final crate homes). Coordinates with 123 (the `object_store` S3 client), 127 (the dep-count dashboard consumes the re-baselined methodology), and 156 (binary-size reduction — these cuts are its primary size driver; its `check-binary-size` gate is the sibling of D1's `check-forbidden-deps`).

**Baseline (A1 DONE 2026-06-05, `main` @ `bb1cbcbe`):** default binary closure = **407** unique packages; full lockfile = **722**. Method + per-target table in `docs/investigations/dep-baseline.md`. **A1 corrected the Phase-B premises:** `sigstore` + `opendal` are already gated out of the default binary (no default-build cut left); the only default-closure targets are **`pgp` (168)** and **`aws-lc-rs` (16 + a C build)**; and `pgp` is Alpine-tarball verification, not release signing (B3 re-scoped). **Recommended order: B4 first** (cleanest default cut), then the B3 decision.

---

## Phase A — re-baseline the methodology

### Task A1: one measurement method, written down — DONE 2026-06-05

- [x] **Step 1:** Canonical commands defined. Two distinct numbers (don't conflate): **default binary closure** = `cargo tree --workspace -e no-dev --prefix none | sed 's/ (.*)//' | sort -u | wc -l` = **407**; **full lockfile** = `grep -c '^name = ' Cargo.lock` = **722**. Per-crate + feature-on closures recorded in the doc.
- [x] **Step 2:** `docs/investigations/dep-baseline.md` committed with the method + numbers + the corrected per-target findings below.

> **A1 corrected the Phase-B premises.** `sigstore` + `opendal` are **already gated out of the default binary** (their default-build benefit is realized; only feature-on builds pay). The only two targets in the **default** closure are **`pgp` (168 crates)** and **`aws-lc-rs` (16 + a C build)**. And **B3's premise is wrong** — `pgp` is Alpine-tarball verification, not release signing (see B3). See the baseline doc for the full table + the revised task order (B4 first).

## Phase B — prune the heavy optional features

### Task B1: `sigstore` — relocate or drop `manifest-verify`

> **A1 finding:** `sigstore` is **already off the default binary** (gated behind `manifest-verify`; adds ~62 crates only when that feature is on). So there is **no default-closure cut left here** — B1 is now purely the cross-repo decision to relocate cosign-verify to mvmd (the `--prod`/admit gate lives in mvmd). Sequence with mvmd; not a quick win.

It backs cosign verification for claim 14 (OCI provenance). Options: move the verification to **mvmd** (the control plane verifies before admit) or drop the in-`mvmctl` path.

- [ ] **Step 1:** Measure `cargo tree -p <crate that pulls sigstore> --features manifest-verify` closure.
- [ ] **Step 2:** Decide with the claim owner: claim 14's cosign verify is a *prod/admit* concern, and `--prod` admission policy lives in mvmd (memory: prod gate is mvmd's). So **relocate cosign verify to mvmd**; `mvmctl` keeps recording the OCI provenance label (the audit entry) but does not link sigstore. If a local verify is still wanted, gate it behind an off-by-default feature.
- [ ] **Step 3:** Remove `sigstore` from the default + the `mvmctl` build; re-measure. Claim 14's audit-label path (the part `mvmctl` owns) stays green; the cosign-verify gate moves to mvmd's plan. Commit with the delta.

### Task B2: `opendal` (~70) → `object_store`

> **A1 finding:** `opendal` is **already off the default binary** (gated behind `template-registry-s3`). No default-closure cut left; this only shrinks the `template-registry-s3` build. Still worth doing for repo-wide single-S3-client hygiene, coordinated with 123 — but not a default-build win.

Pre-decided with 123: one lean S3 client for the repo.

- [ ] **Step 1:** Replace `opendal` (`crates/mvm/Cargo.toml`, optional, template-registry-s3) with `object_store` (the same crate 123's S3 `MountProvider` uses, TLS pinned to `ring`). Failing test — the template-registry-s3 round-trips against `object_store`'s in-memory backend.
- [ ] **Step 2:** Drop `opendal` from the workspace; re-measure (expect ~70 gone, minus `object_store`'s own small closure). Commit.

### Task B3: `pgp` (168 crates) — re-scoped (NOT a minisign swap)

> **A1 corrected this task.** `pgp` (rpgp 0.17, unconditional dep of `mvm-build`, **168-crate** closure — the single biggest target) is **not** our release signing. It verifies the **Alpine minirootfs tarball's upstream PGP signature** against the embedded `ALPINE_RELEASE_KEY_ASC` in Stage 0 (`crates/mvm-build/src/stage0.rs::verify_alpine_pgp_signature`). It **cannot** move to minisign — Alpine dictates the format.

The tarball is **already SHA-256 hash-pinned in source** for the pinned `ALPINE_VERSION` (`verify_sha256`), so PGP is **defense-in-depth** whose distinct value is mainly at version-bump time. Reducing the 168 crates is a **decision**, not a swap:

- [ ] **Option 1 (biggest, −168):** drop the PGP verify, keep the SHA-256 pin. Removes a defense layer → needs security-owner sign-off + an ADR-002 note + a documented version-bump procedure (verify a new tarball's PGP sig out-of-band before pinning its hash).
- [ ] **Option 3:** gate `verify_alpine_pgp_signature` behind a contributor-only feature if no default/published path reaches it. Audit the call graph first.
- [ ] **Option 2 (low payoff):** lighter OpenPGP verifier — rpgp already *is* the lean choice; sequoia is heavier; no smaller RSA-OpenPGP-verify crate exists. Likely not worth it.

See `docs/investigations/dep-baseline.md` for the full rationale.

### Task B4: `aws-lc-rs` → `ring` — MERGE WITH C1 (not a standalone cut)

> **A1 finding (see `docs/investigations/dep-baseline.md`):** mvm's own `reqwest 0.12` is **already** on `ring`. aws-lc-rs enters **only** via `oci-client → reqwest 0.13 → rustls-platform-verifier` (+ `jsonwebtoken/aws_lc_rs`). **BLOCKED UPSTREAM:** `oci-client` 0.16 **and** 0.17 hardcode aws-lc in their only rustls option (`rustls-tls = ["reqwest/rustls", "jsonwebtoken/aws_lc_rs"]`); no ring feature exists, and feature unification can't remove it. So B4 is **not a config change** — it needs a **fork/replace of `oci-client`** (+ reqwest-major unify + a runtime TLS smoke). Decide before starting.

- [ ] **Step 0 (decision):** fork/patch `oci-client` (add a `reqwest` webpki-ring path + `jsonwebtoken/rust_crypto`), or replace it, or upstream a `rustls-tls-ring` feature, or defer. See the baseline doc's four options.
- [ ] **Step 1:** Once oci-client has a ring path, unify mvm-direct + oci-client on **one reqwest major** and set every rustls consumer to `default-features = false` + ring.
- [ ] **Step 2:** Failing test — `cargo tree -i aws-lc-rs` empty; **a real HTTPS connect succeeds**; `cargo tree -d | grep reqwest` shows one major; the cmake build is gone (note the cold-build delta). Commit.

### Task B5: drop `tokio` from `mvm-core`'s default closure (folds in plan 121's "runtime-free core" follow-up)

`mvm-core` carries `tokio` (`io-util` base + feature-gated `rt`/`net`/`fs`/`sync`) and has since the first workspace import — so CLAUDE.md's "mvm-core is runtime-free" was untrue (plan 121 reconciled the *wording*; this task makes it *true*).

**Scope correction (the Step-1 audit found B5's premise wrong).** There are **two** unconditional async surfaces in core's default build, not one:

1. **`core::framing`** (`read_json_frame`/`write_json_frame`, `tokio::io`) — the live transport for the 4 `mvm-hostd` UDS channels (supervisor proxy + broker / host-signer / audit-signer). mvmd does not use it.
2. **`protocol::protocol`'s hostd IPC transport** (`read_frame`/`write_frame`/`send_request`/`recv_request`/`send_response`/`recv_response`, `tokio::io`) — the live **mvm↔mvmd** wire contract. mvmd's `mvmd-agent` (client) and `mvmd-runtime` (server + `mvm-hostd` bin) consume it via the `mvmctl::core::protocol` facade. The `HostdRequest`/`HostdResponse` types are sync serde and stay in core unconditionally; only the async fns need gating.

The mvm-repo's apparent third consumer — a local `mvm-hostd` daemon at `crates/mvm/src/bin/mvm-hostd.rs` + `crates/mvm/src/hostd/` — was **dead source**: git-tracked but excluded from every build target (`autobins = false` + no `[[bin]]`; no `mod hostd` in `mvm/src/lib.rs`). `cargo build -p mvm` emitted no such binary. Deleted in PR-1. So after PR-1 the protocol transport has **zero compiled in-repo consumers** — mvmd is the sole one, which is why surface 2 can't simply move or delete, only feature-gate + cross-repo opt-in.

**Sequencing — three PRs, because surface 2's de-default touches mvmd.** Workspace feature unification means `cargo tree -p mvm-core` reflects any member that enables `hostd-transport`; so the gate can only pass once no mvm-repo member enables it (mvmd is a separate workspace and doesn't count).

**PR-1 (this branch — DONE):**
- [x] **Step 1:** Audited core's `tokio` users (`cargo tree -i tokio` + grep `tokio::` under `crates/mvm-core/src`). Found the two surfaces above; confirmed framing's 4 callers and the protocol transport's mvmd-only consumer; confirmed the local `mvm-hostd` daemon is uncompiled dead source.
- [x] **Step 2a — framing:** moved `core::framing` → `mvm_hostd::framing`; updated the 4 channel call sites + the `services/frame.rs` adapter. (Coordinate with **plan 122 Task A0**, which extends `framing` with the auth+encryption seam — A0 is unstarted as of 2026-06-04 and operates on framing's new `mvm-hostd` home.)
- [x] **Step 2b — protocol transport:** gated the 6 async fns + `MAX_FRAME_SIZE` + their 3 `#[tokio::test]`s behind a new `hostd-transport` feature; `HostdRequest`/`HostdResponse`/`HOSTD_SOCKET_PATH`/`PROTOCOL_VERSION` stay unconditional. Made `mvm-core`'s `tokio` `optional`, pulled by `hostd-transport` + `manifest-verify`. `hostd-transport` is **in `default`** for now so mvmd keeps building unchanged; added a dev-dep `tokio` (`macros`/`rt`/`io-util`) so the gated tests build regardless of features.
- [x] **Step 2c — dead code:** deleted `crates/mvm/src/bin/mvm-hostd.rs` + `crates/mvm/src/hostd/`.
- [x] **Step 2d — facade feature:** added `hostd-transport = ["mvm-core/hostd-transport"]` to the root `mvmctl` package. Inert here (mvm-core still defaults the feature on), but it makes the feature reachable through the facade so mvmd can opt in **before** PR-2 de-defaults it — keeping the cross-repo rollout acyclic.
- [x] Verified: `mvm-core --no-default-features` compiles **and `cargo tree -p mvm-core --no-default-features -e no-dev` carries no tokio**; `manifest-verify` alone builds; workspace build + `clippy -D warnings` + nightly fmt + 4424 tests + doctests green (4 known macOS-dev env failures only).

**mvmd PR (cross-repo, BEFORE PR-2) — drafted as mvmd plan 54 (`mvmd/specs/plans/54-enable-mvm-core-hostd-transport-feature.md`):**
- [ ] In mvmd, enable `hostd-transport` on the `mvmctl` facade dep (`mvmd/Cargo.toml`: `mvmctl = { path = "../mvm", default-features = false, features = ["hostd-transport"] }`). One line — `mvmd-agent` + `mvmd-runtime` pull the facade via `mvmctl.workspace = true`. The root `mvmctl` package forwards it as `hostd-transport = ["mvm-core/hostd-transport"]` (added in **PR-1**, Step 2d). Safe to land while mvm-core still defaults the feature on (enabling an already-on feature is a no-op), so there's no broken window.

**PR-2 (mvm, branch `feat/plan-126-b5-pr2-default-off` — built; MERGE ONLY AFTER the mvmd PR):**
- [x] Removed `hostd-transport` from `mvm-core`'s `default` (now `default = []`). The forwarding `hostd-transport = ["mvm-core/hostd-transport"]` on the root `mvmctl` facade already landed in PR-1 (Step 2d), so mvmd is opted in by the time this lands.
- [x] Gate: new `xtask check-core-runtime-free` runs `cargo tree -p mvm-core -e no-dev` and fails if `tokio` appears. (A **separate** subcommand, not folded into `check-forbidden-deps`: that gate is lockfile-name-based and `tokio` is legitimately in `Cargo.lock` via mvm-hostd/mvm + the gated features — the runtime-free property is a feature-resolution fact, not a lockfile fact.) Wired into `ci.yml`'s Lint job. CI Test job gains a `cargo nextest run -p mvm-core --features hostd-transport` lane so the gated transport tests stay covered.
- [x] Flipped CLAUDE.md's `mvm-core` line to "the default build has no async/runtime deps."

## Phase C — unify duplicate majors

### Task C1: `oci-client` / `reqwest` duplicate majors

Two major versions of the same crate inflate the lock + compile time.

- [ ] **Step 1:** `cargo tree -d` (duplicates) — identify the two `reqwest` (and/or `oci-client`) majors + who pulls each.
- [ ] **Step 2:** Align on one major (bump the lagging consumer, or feature-match). Failing test — `cargo tree -d | grep -E 'reqwest|oci-client'` shows one major each; the OCI + HTTP paths still pass their tests. Commit.

## Phase D — lock it

### Task D1: the forbidden-dep gate

- [ ] **Step 1:** Extend `xtask check-forbidden-deps` (exists) to fail if `sigstore`, `opendal`, `pgp`, or `aws-lc-rs` re-enter the default `mvmctl` closure (an allow-list of off-by-default features for the deliberately-gated ones), **and** if `tokio` re-enters `mvm-core`'s default closure (the B5 runtime-free-core assertion). Failing test — adding any one back trips the gate.
- [ ] **Step 2:** Final measure — total before/after in `dep-baseline.md`; the sum of B1–B4 + C1 is the headline reduction (alongside 124's ~25–35 agent crates). Commit. Wire the gate into `ci.yml` (with 128), alongside 156's sibling `check-binary-size` gate.

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
