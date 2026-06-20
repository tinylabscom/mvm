# Plan 126 — Dependency reduction

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut the real third-party dependency weight — the heavy *optional* features and the duplicate/C-backed crates — and lock a forbidden-dep gate so it stays cut. This is the host/feature counterpart to 124's lean-agent cut; together they are where the dep graph actually shrinks. The 32→17 consolidation (121) delivers ~0 third-party reduction (build-units only), so this plan does not double-count it. The whole-crate cuts here are also the **primary size driver** for 156 (binary-size reduction) — 156 re-measures `mvmctl`'s size after each task below lands.

**Architecture:** Measure, prune, re-measure, gate. Each target is a feature-gated heavy dep whose closure is replaced by a lean one or relocated to mvmd: `sigstore` (manifest-verify), `opendal` (template-registry-s3), `pgp` (release signing), `aws-lc-rs` (C/cmake crypto). Then unify the duplicate `oci-client`/`reqwest` majors, and add the gate. Every step records a `cargo tree` delta — no asserted numbers.

**Tech Stack:** `cargo tree`, the `xtask check-forbidden-deps` gate (exists), `object_store` (the opendal replacement, shared with 123), `minisign` (the pgp replacement), `ring` (the aws-lc-rs replacement).

**Prereqs:** 121 (final crate homes). Coordinates with 123 (the `object_store` S3 client), 127 (the dep-count dashboard consumes the re-baselined methodology), and 156 (binary-size reduction — these cuts are its primary size driver; its `check-binary-size` gate is the sibling of D1's `check-forbidden-deps`).

**Baseline (A1 DONE 2026-06-05, `main` @ `bb1cbcbe`):** default binary closure = **407** unique packages; full lockfile = **722**. Method + per-target table in `docs/investigations/dep-baseline.md`. **A1 corrected the Phase-B premises:** `sigstore` + `opendal` are already gated out of the default binary (no default-build cut left); the only default-closure targets are **`pgp` (168)** and **`aws-lc-rs` (16 + a C build)**; and `pgp` is Alpine-tarball verification, not release signing (B3 re-scoped). **Recommended order: B4 first** (cleanest default cut), then the B3 decision.

> **Priority update 2026-06-15:** Plan 200 depends on this plan for the
> mechanical default-closure cuts. Keep ownership here: `oci-client` replacement
> / `reqwest` unification / `aws-lc-rs` removal are Plan 126 work, while Plan
> 200 only sets the product requirement that the default `machine run --image`
> path stay lean. Do not duplicate dependency measurement or gates in Plan 200.
>
> **Bookkeeping reconciliation 2026-06-18:** the mvm-side default-closure
> ratchets and final measurement are landed. Plan 126 now stays open only for the
> still-real OCI/TLS stack decision (`oci-client` replacement or fork, `aws-lc-rs`
> removal, and `reqwest`/`oci-client` major unification) plus the documented
> follow-up sweeps below. The `sigstore` prod cosign decision is rehomed to mvmd,
> and the old `pgp` default-closure target was superseded by Plan 160.

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

- [~] **Steps 1-3 rehomed:** `sigstore` is already out of the `mvmctl`
      default closure, so there is no remaining mvm-side default-build cut.
      The prod cosign verification decision belongs to mvmd, where the
      `--prod` admission policy lives. `mvmctl` keeps the OCI provenance audit
      label path; if local cosign verification remains useful, it stays behind
      an off-by-default feature.

### Task B2: `opendal` (~70) → `object_store`

> **A1 finding:** `opendal` is **already off the default binary** (gated behind `template-registry-s3`). No default-closure cut left; this only shrinks the `template-registry-s3` build. Still worth doing for repo-wide single-S3-client hygiene, coordinated with 123 — but not a default-build win.

Pre-decided with 123: one lean S3 client for the repo.

- [x] **DONE** — `crates/mvm/src/vm/template/registry.rs`'s `TemplateRegistry`
  (template-registry-s3) now uses `object_store::aws::AmazonS3` instead of
  `opendal::BlockingOperator`; it owns a current-thread runtime to drive the
  async `get`/`put` from the sync API (mirrors `mvm_storage::s3::S3MountProvider`,
  the same `object_store` 0.11 the 123 S3 `MountProvider` uses). `opendal`
  removed from `crates/mvm/Cargo.toml` + the root workspace.
- [x] **Re-measured:** `cargo tree -i opendal` empty; `opendal` gone from
  `Cargo.lock`; full lockfile **689 → 678 (−11)** (opendal + reqsign + unique
  closure removed; object_store was already in-tree via mvm-storage, so its side
  is free). Default build + `cargo build --workspace` + `nextest -p mvm` green;
  `check-forbidden-deps` clean.

### Task B3: `pgp` (168 crates) — SUPERSEDED by plan 160

> **Superseded 2026-06-05 by plan 160** (`specs/plans/160-stage0-busybox-seed-drop-alpine.md`): `pgp` exists only to verify the Stage-0 **Alpine** seed tarball. Plan 160 drops the Alpine seed entirely (busybox + static-Nix seed) — deleting `pgp` outright instead of gating it. The re-scope below is retained for context.

> **A1 corrected this task.** `pgp` (rpgp 0.17, unconditional dep of `mvm-build`, **168-crate** closure — the single biggest target) is **not** our release signing. It verifies the **Alpine minirootfs tarball's upstream PGP signature** against the embedded `ALPINE_RELEASE_KEY_ASC` in Stage 0 (`crates/mvm-build/src/stage0.rs::verify_alpine_pgp_signature`). It **cannot** move to minisign — Alpine dictates the format.

The tarball is **already SHA-256 hash-pinned in source** for the pinned `ALPINE_VERSION` (`verify_sha256`), so PGP is **defense-in-depth** whose distinct value is mainly at version-bump time. Reducing the 168 crates is a **decision**, not a swap:

- [~] **Closed as superseded:** Plan 160 removed the Alpine seed path from
      the default closure, so `pgp` is no longer a Plan 126 implementation
      target. Any future upstream-tarball verification procedure belongs with
      Stage-0 seed maintenance, not this dependency-reduction plan.

See `docs/investigations/dep-baseline.md` for the full rationale.

### Task B4: `aws-lc-rs` → `ring` — MERGE WITH C1 (not a standalone cut)

> **A1 finding (see `docs/investigations/dep-baseline.md`):** mvm's own `reqwest 0.12` is **already** on `ring`. aws-lc-rs enters **only** via `oci-client → reqwest 0.13 → rustls-platform-verifier` (+ `jsonwebtoken/aws_lc_rs`). **BLOCKED UPSTREAM:** `oci-client` 0.16 **and** 0.17 hardcode aws-lc in their only rustls option (`rustls-tls = ["reqwest/rustls", "jsonwebtoken/aws_lc_rs"]`); no ring feature exists, and feature unification can't remove it. So B4 is **not a config change** — it needs a **fork/replace of `oci-client`** (+ reqwest-major unify + a runtime TLS smoke). Decide before starting.

- [x] **Step 0 (decision, 2026-06-20):** **upstream + rehome** — chosen over carrying a fork. B4 + C1 move to the dependency roadmap; the durable fix (option 3) is now filed upstream as [oras-project/rust-oci-client#274](https://github.com/oras-project/rust-oci-client/pull/274): a `rustls-tls-no-provider = ["reqwest/rustls-no-provider", "jsonwebtoken/rust_crypto"]` feature, mirroring reqwest's own `rustls-no-provider` (consumer installs the ring provider). **Validated against upstream `main`:** `cargo tree --no-default-features --features rustls-tls-no-provider -i aws-lc-rs` is empty and the crate builds — so the change *does* remove aws-lc (`rustls-platform-verifier` is provider-agnostic and does not re-drag it; corrects the earlier worry). We rehome rather than carry a `[patch.crates-io]` fork. **A bridge spike (2026-06-20) showed B4 is bigger than a bump + flip:** patching mvm-oci onto the proven fork removes `aws-lc-rs` + its C build (workspace `cargo tree -i aws-lc-rs` empty; mvm-oci builds + 96 tests green once `new_client` installs the ring provider — `reqwest/rustls-no-provider` resolves the provider at client-build time, so a guard test + a test-helper install are both required), **but** `jsonwebtoken/rust_crypto` (the aws-lc-free JWT backend) pulls the RustCrypto **0.11** line — `sha2`/`digest` 0.11, `block-buffer` 0.12, `crypto-common` 0.2, `const-oid` 0.10 — duplicating the workspace's pinned **0.10** stack and tripping the D2 duplicate-major ratchet. This is inherent to `oci-client` 0.17's `jsonwebtoken` 10.x, not the bridge, so the released post-#274 version drags the same split. Completing B4 therefore also requires a **workspace-wide RustCrypto 0.10→0.11 migration** (or skipping 5 duplicate majors). **Feasibility checked 2026-06-20: that migration is blocked upstream.** mvm's RustCrypto stack is `aes-gcm 0.10`, `ed25519-dalek 2.2`, `hmac 0.12`, `hkdf 0.12`, `aead 0.5`, `cipher 0.4`, `sha2`/`sha1`/`digest` 0.10. On the new (crypto-common 0.2 / digest 0.11) generation `sha2 0.11`, `digest 0.11`, `hmac 0.13`, `hkdf 0.13`, `aead 0.6`, `cipher 0.5` are stable — **but `aes-gcm` (AEAD: snapshot/secret_store) and `ed25519-dalek` (host signer / audit chain / attestation) have no stable release, only `0.11.0-rc.4` and `3.0.0-rc.1`.** Adopting RC crypto in a security-critical workspace is a non-starter under ADR-002, and a partial migration just recreates the split. So **B4 is gated on upstream stable `aes-gcm 0.11` + `ed25519-dalek 3.0`** — revisit then. The D1/D2 gates already hold the regression closed. Refactor-close is no longer gated on this.
- [ ] **Step 1 (rehomed):** when `oci-client` exposes a ring path (our upstream FR, or a later release), unify mvm-direct + oci-client on **one reqwest major** and set every rustls consumer to `default-features = false` + ring.
- [ ] **Step 2 (rehomed):** failing test — `cargo tree -i aws-lc-rs` empty; **a real HTTPS connect succeeds**; `cargo tree -d | grep reqwest` shows one major; the cmake build is gone (note the cold-build delta). Commit.

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

- [x] **Step 1:** `cargo tree -d` — `reqwest 0.12` is mvm's (mvm-cli/-hostd/-build, on `ring`); `reqwest 0.13` is pulled **only** by `oci-client`. `oci-client` itself splits 0.15/0.16.
- [~] **Step 2:** **REJECTED — blocked on B4.** Bumping mvm to `reqwest 0.13` to match oci-client does **not** collapse the tree: a transitive `0.12` holdout remains, the duplicate-major count is unchanged, and 0.13's `rustls` feature forces aws-lc-rs (the B4 block). The unify only lands once `oci-client` is forked (B4 Step 0). Until then, `reqwest` is a recorded entry in the duplicate-major baseline (D2), not a free cut.

## Phase D — lock it

### Task D1: the forbidden-dep gate

- [x] **Step 1:** Extended `xtask check-forbidden-deps` with a default-closure
      ban: it now resolves `mvmctl`'s default-feature normal-edge closure via
      `cargo tree` and fails if `sigstore`, `opendal`, or `pgp` appear there
      (exact package-name match, so siblings like `sigstore-protobuf-specs` don't
      false-trip). The lockfile-name ban (`sea-*`/`mysql`) stays — those must not
      appear at all; the new deps are checked against the *closure*, not the lock,
      because `sigstore` legitimately remains in `Cargo.lock` behind the
      off-by-default `manifest-verify` feature. The gate is already wired into
      `ci.yml` + `ci-full.yml`, so no new CI step is needed. Unit tests cover the
      matcher (exact-match, no-substring, sort/dedup) and an end-to-end run was
      box-free-verified to **trip** when a present crate is added to the ban list
      and pass after revert.
      - `aws-lc-rs` is **deliberately not gated**: it is in the default closure
        today via `oci-client → rustls` (B4 is blocked upstream), so banning it
        would false-fail. Recorded here as the remaining blocker.
      - `tokio`-in-`mvm-core` is already enforced by the separate
        `check-core-runtime-free` gate (B5); not duplicated here.
- [x] **Step 2:** Final measure — total before/after in `dep-baseline.md`;
      default binary closure **407→347 (−60)** and lockfile **722→683 (−39)**.
      The write-up attributes `pgp` removal to Plan 160 rather than double-
      counting it here, records `aws-lc-rs` as the remaining blocked default
      target, and names the four ratchets that hold the cut.

### Task D2: duplicate-major lock-gate (cargo-deny ratchet) — DONE

The forbidden-dep gate (D1) stops the four named heavy deps re-entering;
this complements it by freezing the *whole* duplicate-major set so no
new second-major creeps in silently. Reuses the existing cargo-deny job
rather than a new xtask.

- [x] **Step 1:** `deny.toml` `[bans] multiple-versions` flipped `warn`→`deny` with an audited `skip` baseline (the 23 crates cargo-deny's default-feature graph already carries, grouped by why). A brand-new duplicated crate now fails CI; the existing cuts (tokio drop, opendal→object_store, Alpine seed) can't silently regress. Verified: dropping any baseline entry trips `error[duplicate]`.
- [x] **Step 2 (restore the gate to green):** the cargo-deny + cargo-audit jobs had been red on main since ~2026-06-07 from drift unrelated to duplicates — fixed in the same change so the ratchet means something:
  - `allow-wildcard-paths = true` — a versionless `{ path = "../mvm-verify" }` read as a wildcard; path deps are first-party source, not a registry `*`.
  - `mvm-verify` was `unlicensed` — added `license.workspace = true`.
  - Two new `unmaintained` advisories accepted with rationale (`RUSTSEC-2026-0173` proc-macro-error2, `RUSTSEC-2025-0134` rustls-pemfile); cargo-audit `--ignore` flags kept in sync.
  - `RUSTSEC-2026-0119` (hickory-proto 0.24 O(n²) name-compression DoS): **fixed, not ignored** — bumped `hickory-resolver 0.24→0.26` (migrated the `custom-dns` resolver to the 0.26 `TokioResolver` builder). Also collapsed the `hickory-proto` 0.24/0.26 duplicate.

## Acceptance

- [x] `dep-baseline.md` records the method + the baseline + the Phase D final measure (all numbers measured, never asserted): default binary closure 407→347 (−60), lockfile 722→683 (−39); per-target outcomes (sigstore/opendal/pgp out of the default closure, aws-lc-rs still in / B4 blocked) and the four ratchets that hold the cut.
- [x] `sigstore`, `opendal`, and `pgp` are out of the `mvmctl` default closure;
      `opendal` is replaced by `object_store`; claim 14's mvmctl-owned OCI
      provenance audit-label path remains intact.
- [~] Prod cosign verification is rehomed to mvmd; this plan does not keep it
      as an mvm-side blocker.
- [~] `aws-lc-rs` gone (`cargo tree -i aws-lc-rs` empty, C/cmake build removed).
      **Rehomed (Step-0 decision 2026-06-20):** not achievable by config; `oci-client`
      hardcodes aws-lc and no upstream ring feature exists. Moved to the dependency
      roadmap behind upstream PR [#274](https://github.com/oras-project/rust-oci-client/pull/274) (`rustls-tls-no-provider`, proven aws-lc-free); D1/D2 gates hold the
      regression closed. Not a refactor-close blocker.
- [~] One major each for `reqwest`/`oci-client` (`cargo tree -d` clean for them).
      **Rehomed** with B4 above — the reqwest 0.12/0.13 split only collapses once
      `oci-client` is off the aws-lc path; recorded in the D2 duplicate-major baseline.
- [x] `check-forbidden-deps` trips if `sigstore`/`opendal`/`pgp` re-enter the default closure (`aws-lc-rs` deferred — still in the closure via `oci-client`).
- [ ] `cargo test --workspace` + clippy + fmt green; the OCI / template-registry / release-signing / TLS paths still pass.

### deferred follow-ups

- [~] The mvmd cosign-verify relocation is an **mvmd plan**; this plan only
      keeps `sigstore` out of the `mvmctl` default closure.
- [ ] Periodic `cargo tree -d` sweep as the dashboard (127) surfaces new duplicates.
- [ ] Migrate off the unmaintained `rustls-pemfile` (RUSTSEC-2025-0134) to `rustls_pki_types::pem` and drop the advisory ignore. Direct dep of mvm-hostd (`certs.rs`, `terminator/tls.rs`).
- [ ] Shrink the D2 baseline as upstream majors converge (e.g. the windows-* families, the rustix/linux-raw-sys split) or `oci-client` is forked (drops `reqwest`).

## Self-review

- **Spec coverage (brief 126):** re-baseline (A), sigstore/opendal/pgp/aws-lc-rs prune (B1–B4), oci-client/reqwest unify (C1), the gate (D1). The opendal→object_store unification is the one pre-grounded with 123.
- **Honesty:** every reduction is measured (`cargo tree` delta in `dep-baseline.md`), never asserted; the 735 re-baseline corrects the brief's 723. Claim 14's verify *relocates* (to mvmd), it isn't silently dropped — the audit-label path mvmctl owns stays green.
- **Division of labor:** this is the host/feature cut; 124 is the agent cut; 121 is ~0 — stated so the wins aren't double-counted.
- **Voice:** comments/notes mark the non-obvious (why sigstore relocates rather than drops, why aws-lc-rs removal also kills a cmake build), not the mechanics.
