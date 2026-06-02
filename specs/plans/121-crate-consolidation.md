# Plan 121 — Crate consolidation (32 → 16; `mvm-network` makes 17 in 123) + `crates/deps/*-sys`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reshape the workspace from **32 crates to the 16 existing-code architectural crates** of ADR-066 §1 (the 17th, `mvm-network`, is created by plan 123 when `NetworkProvider` lands), plus a bracketed `crates/deps/*-sys` for the one true FFI crate. Pure structural migration — renames, folds, bin relocations, FFI extraction — that adds **no new third-party deps** (build-units only) and keeps the workspace green + every claim gate intact after each task.

**Architecture:** Every move is mechanical and compiler-checked: the regression guard for a rename is `cargo build --workspace` (a missed reference fails to compile) + `cargo test --workspace` + the xtask claim-gate lints. Each task lands independently (green workspace, own commit). The renames carry the ADR-066 §8 rename-break gate-update checklist (reproduced below as "Rename-break gate checklist") applied **same-commit**: 3 fuzz `working-directory` dirs (`mvm-libkrun`, `mvm-vz`, `mvm-firecracker-bridge`) **plus** the `-p mvm-libkrun --features libkrun-sys` lane, the `sealed-prod-allowlist` script's `-p mvm-core`/`-p mvm-guest` + `policy::security::tests::*`/`vsock::tests::*` count-locks, `check-mvm-host-binaries-sync`'s manifest path, and `check-audit-positional`'s exempt path. (The structural inventory's CI sweep under-counted these — ADR §8 line 158 is authoritative.) Publishes the new `mvmctl` facade + `mvm-core` module map that **mvmd plan 51** consumes.

**Tech Stack:** Rust 2024 workspace, `cargo`, `git mv`, `xtask` (claim-gate lints), `.github/workflows/{ci,security}.yml`, `Justfile`.

**Prereq:** Plan 120's `ArtifactSidecar`→`ArtifactManifest` rename has landed (it touched `mvm-build`/`mvm-base`/`mvm-security`/`mvm` — independent of these crate moves).

**Boundary (what this plan does NOT do):** `mvm-network` (new crate) + the `NetworkProvider`/`StorageProvider` impls → **plan 123**; `mvm-storage` `encrypted` impl → **plan 122**; the lean-agent dep cut → **124**; the real third-party-dep reduction → **126**; fuzz *parity*/new-target work → **128** (this plan only re-points the 3 existing fuzz dirs it moves). So 121 reaches **16** architectural crates; 123 adds the 17th.

---

## Crate-move map (the full plan, from ADR-066 §1 + the inventory ref-counts)

| # | Operation | Source → Dest | Ref scope (inventory) |
|---|---|---|---|
| A1 | fold | `mvm-runner` → `mvm-guest` (`[[bin]]`) | 1 ref (self) |
| A2 | fold | `mvm-base` → `mvm` | 71 refs / 21 files |
| A3 | fold | `mvm-ir` → `mvm-sdk` (`src/ir/`) | 99 refs / 35 files |
| B1 | fold | `mvm-plan` → `mvm-core::plan` | 178 refs / 28 files |
| B2 | fold | `mvm-policy` → `mvm-core::policy` | 66 refs / 14 files |
| B3 | fold | `mvm-security` → `mvm-core::security` | 103 refs / 30 files |
| B4 | dedup | 6 framing / config / paths / subprocess impls → `mvm-core::{framing,config_envelope,paths,subprocess}` | see B4 |
| C1 | FFI extract | `mvm-libkrun` → `crates/deps/libkrun-sys` (binding) + safe wrapper → `mvm-backend` | fuzz dir moves |
| C2 | fold | `mvm-providers`, `mvm-vz` → `mvm-backend` | Swift-interface, no FFI; vz fuzz dir moves |
| D1 | new crate | `mvm-supervisor`+`mvm-broker`+`mvm-host-signer`+`mvm-audit-signer`+`mvm-jailer-lite` → `mvm-hostd` (4 `[[bin]]`s + jailer module) | §3 process model |
| D2 | new crate | `mvm-libkrun-supervisor`+`mvm-vz-drainer`+`mvm-firecracker-bridge` → `mvm-vm-host` (cfg-gated `[[bin]]`s) | fc-bridge fuzz dir moves |
| D3 | new crate | `mvm-addon-dns`+`mvm-addon-vsock-bridge` → `mvm-guest-helpers` (`[[bin]]`s) | in-guest helpers |
| D4 | bin relocate | `mvm-host-vm-init`+`mvm-egress-proxy` → `mvm-build` (`[[bin]]`s, cfg-gated Linux) | builder-VM tools |
| E1 | republish | `mvmctl` facade + `mvm-core` module map; ADR naming fix (`mvm-vm-sidecar`→`mvm-vm-host`) | mvmd plan 51 input |

**Reusable rename recipe** (referenced by the tasks below — do NOT skip the gate step):
1. `git mv` the source dir / merge its `src/` into the destination.
2. In the destination `Cargo.toml`: add the merged deps (dedup), and if it was a `[[bin]]`/lib add the `[[bin]]`/`[lib]` stanza. Remove the source crate from the root `Cargo.toml [workspace] members`.
3. In the destination `lib.rs`: `pub mod <name>;` (for a fold-as-module) or re-export to preserve the public path.
4. Rewrite every consumer ident: `git grep -l '<old_ident>::' -- crates/ | xargs sed -i '' 's/<old_ident>::/<new_path>::/g'` (macOS `sed -i ''`).
5. **Same-commit gate update:** if the moved crate had a fuzz dir or any CI string (inventory §4), update `.github/workflows/*.yml` + `Justfile` in this commit.
6. `cargo build --workspace && cargo test --workspace -q && cargo clippy --workspace -- -D warnings && cargo run -p xtask -- check-spec-numbers check-forbidden-deps check-doc-claims` → all green.
7. Commit.

### Rename-break gate checklist (ADR-066 §8 line 158 — authoritative; apply each in the SAME commit as its move)

- [ ] **C1 (libkrun):** the `-p mvm-libkrun --features libkrun-sys` libkrun-macos lane in `ci.yml` → re-point to `libkrun-sys` / `mvm-backend`; `crates/mvm-libkrun/fuzz` working-dir (`security.yml`) → `crates/deps/libkrun-sys`.
- [ ] **C2 (vz):** `crates/mvm-vz/fuzz` working-dir → `crates/mvm-backend` (the `fuzz_supervisor_config` config-fuzz).
- [ ] **D2 (fc-bridge):** `crates/mvm-firecracker-bridge/fuzz` working-dir → `crates/mvm-vm-host` (`fuzz_bridge_config_json`, `fuzz_passt_hashes_toml`).
- [ ] **B2/B3 (core fold):** the `sealed-prod-allowlist` script's `-p mvm-core` / `-p mvm-guest` invocations + its exact `policy::security::tests::*` / `vsock::tests::*` test-name count-locks (the fold shifts module paths + counts); update `check-audit-positional`'s exempt-path constant → `mvm-core/src/policy/audit.rs`.
- [ ] **D4 (host bins):** update `check-mvm-host-binaries-sync`'s hardcoded `crates/mvm-cli/src/host_binaries/manifest.rs` path (breaks when host-bins fold into `mvm-build`).
- [ ] **Verify-unchanged:** the `oci-*` lanes' `-p mvm-cli` filters (mvm-cli keeps its name — confirm still valid, no edit expected).

---

## Phase A — simple folds (warm-up, low ref-count)

### Task A1: `mvm-runner` → `mvm-guest`

`mvm-runner` has a single in-guest entrypoint-runner `main.rs` and **1** self-reference (inventory). It becomes a `[[bin]]` of `mvm-guest` (which already holds the agent/console/vsock — ADR-066 §1 line 38).

**Files:** move `crates/mvm-runner/src/main.rs` → `crates/mvm-guest/src/bin/mvm-runner.rs`; `crates/mvm-guest/Cargo.toml`; root `Cargo.toml`.

- [ ] **Step 1:** `git mv crates/mvm-runner/src/main.rs crates/mvm-guest/src/bin/mvm-runner.rs` then `git rm -r crates/mvm-runner` (Cargo.toml etc.).
- [ ] **Step 2:** In `crates/mvm-guest/Cargo.toml` add:
  ```toml
  [[bin]]
  name = "mvm-runner"
  path = "src/bin/mvm-runner.rs"
  ```
  and merge any deps `mvm-runner` declared that `mvm-guest` lacks. Remove `"crates/mvm-runner"` from root `Cargo.toml [workspace] members`.
- [ ] **Step 3:** Fix the moved bin's imports — anything it referenced as `mvm_guest::` stays; if it referenced sibling crates, keep those deps.
- [ ] **Step 4:** `cargo build --workspace && cargo test -p mvm-guest -q` → green.
- [ ] **Step 5:** Commit: `git commit -m "refactor(crates): fold mvm-runner into mvm-guest as a [[bin]]"`.

### Task A2: `mvm-base` → `mvm`

`mvm-base` is a Lima-era leftover (ADR-066 §1 line 33). 71 refs across 21 files; dependents are `mvm-backend`, `mvm-supervisor`, `mvm` (inventory). Fold its `src/*` into `mvm` as modules.

**Files:** `crates/mvm-base/src/*` → `crates/mvm/src/base/` (or merge into existing `mvm` modules where names align — e.g. `runtime_meta.rs`, `snapshot_integrity.rs`, `cow.rs`); `crates/mvm/Cargo.toml`; root `Cargo.toml`; all 21 consumer files.

- [ ] **Step 1:** `git mv crates/mvm-base/src crates/mvm/src/base` (then delete the `mvm-base` Cargo.toml + dir). Add `pub mod base;` to `crates/mvm/src/lib.rs`, re-exporting the items consumers used flat (`pub use base::{...}`) so the rewrite in Step 3 is a simple prefix swap.
- [ ] **Step 2:** Merge `mvm-base`'s deps into `crates/mvm/Cargo.toml` (it pulled `mvm-security`, libc — dedup against `mvm`'s existing deps). Drop the `mvm-base = {…}` dep lines from `mvm-backend`, `mvm-supervisor`, `mvm` and the member from root `Cargo.toml`.
- [ ] **Step 3:** Rewrite the 71 refs: `git grep -l 'mvm_base::' -- crates/ | xargs sed -i '' 's/mvm_base::/mvm::base::/g'`. (Inventory files: `mvm-backend/src/{microvm.rs:15,image.rs:4,…}`, `mvm-supervisor/src/{firewall/mod.rs:4,supervisor.rs:4,…}`, `mvm/src/{lib.rs,vm/template/lifecycle.rs:5,…}`.)
- [ ] **Step 4:** `cargo build --workspace && cargo test --workspace -q` → green (the 21 files compile against `mvm::base::`).
- [ ] **Step 5:** Commit: `git commit -m "refactor(crates): fold mvm-base into mvm::base (Lima-era leftover)"`.

### Task A3: `mvm-ir` → `mvm-sdk::ir` (the IR fold)

ADR-066 §6: the IR is the SDK's lowering target; one crate. 99 refs / 35 files; dependents are **only** `mvm-cli` (7 files / 18 refs) + `mvm-sdk` (24 files / 64 refs) — mvmd does **not** consume it (plan 51), so the fold is contained.

**Files:** `crates/mvm-ir/src/*` → `crates/mvm-sdk/src/ir/`; `crates/mvm-sdk/{Cargo.toml,src/lib.rs}`; the 7 `mvm-cli` files; root `Cargo.toml`. Move `crates/mvm-ir/tests/*` → `crates/mvm-sdk/tests/` and `crates/mvm-ir/src/bin/emit_schema.rs` → `crates/mvm-sdk/src/bin/`.

- [ ] **Step 1:** `git mv crates/mvm-ir/src crates/mvm-sdk/src/ir` then move `tests/` + `src/bin/emit_schema.rs` as above; `git rm -r crates/mvm-ir`.
- [ ] **Step 2:** In `crates/mvm-sdk/src/lib.rs` replace the external re-export `pub use mvm_ir::{…}` (line ~114) with `pub mod ir;` + `pub use ir::{…}` (same names) so `mvm_sdk::Workload` etc. keep resolving. In `crates/mvm-sdk/Cargo.toml` delete `mvm-ir = { workspace = true }` and absorb mvm-ir's deps (`serde`, `serde_json` — already present).
- [ ] **Step 3:** Rewrite mvm-sdk-internal refs: `git grep -l 'mvm_ir::' -- crates/mvm-sdk | xargs sed -i '' 's/mvm_ir::/crate::ir::/g'` (inside the crate, `crate::ir::`).
- [ ] **Step 4:** Rewrite mvm-cli's 7 files: `git grep -l 'mvm_ir::' -- crates/mvm-cli | xargs sed -i '' 's/mvm_ir::/mvm_sdk::ir::/g'`; drop `mvm-ir` from `crates/mvm-cli/Cargo.toml` (mvm-cli already deps `mvm-sdk`); remove the member from root `Cargo.toml`.
- [ ] **Step 5:** `cargo build --workspace && cargo test -p mvm-sdk -p mvm-cli -q` → green (incl. the moved `round_trip`/`validate`/`schema_shape` tests + plan 120's `compile_hello_app`).
- [ ] **Step 6:** Commit: `git commit -m "refactor(sdk): fold mvm-ir into mvm-sdk::ir (one SDK crate)"`.

## Phase B — the `mvm-core` fold + the `core::` dedups

`mvm-core` absorbs plan + policy + security as modules (ADR-066 §1 line 29). **Hard constraint: no async/runtime deps may enter `mvm-core`** — these three are pure types + crypto, so verify the merged `Cargo.toml` gains no `tokio`/`async-*`. Order: plan → policy (deps on plan) → security.

### Task B1: `mvm-plan` → `mvm-core::plan`

178 refs / 28 files (biggest single fold); dependents: `mvm`, `mvm-cli`, `mvm-firecracker-bridge`, `mvm-libkrun-supervisor`, `mvm-policy`, `mvm-supervisor`, `mvm-vz-drainer` (inventory).

**Files:** `crates/mvm-plan/src/*` → `crates/mvm-core/src/plan/`; `crates/mvm-core/{Cargo.toml,src/lib.rs}`; 28 consumer files; `crates/mvm-plan/tests/replay_protection.rs` → `crates/mvm-core/tests/`; root `Cargo.toml`.

- [ ] **Step 1:** `git mv crates/mvm-plan/src crates/mvm-core/src/plan`; move `tests/replay_protection.rs`; `git rm -r crates/mvm-plan`. Add `pub mod plan;` to `crates/mvm-core/src/lib.rs`.
- [ ] **Step 2:** Merge `mvm-plan` deps into `crates/mvm-core/Cargo.toml` — **assert none are async/runtime** (`ed25519-dalek`, `serde`, `sha2` etc. are fine). Drop `mvm-plan` from all 7 dependents' `Cargo.toml` (they already dep `mvm-core`) + root members.
- [ ] **Step 3:** `git grep -l 'mvm_plan::' -- crates/ | xargs sed -i '' 's/mvm_plan::/mvm_core::plan::/g'` (28 files: `mvm-cli/src/commands/vm/up.rs:66`, `mvm-supervisor/src/backend.rs:20`, …). Inside `mvm-core` itself, the moved files use `crate::plan::`/`super::` — fix any `mvm_core::` self-refs the sed produced to `crate::`.
- [ ] **Step 4:** `cargo build --workspace && cargo test --workspace -q` → green; **`cargo tree -p mvm-core -e no-dev | grep -E 'tokio|async' && echo "FAIL: async in core" || echo OK`** must print OK.
- [ ] **Step 5:** Commit: `git commit -m "refactor(core): fold mvm-plan into mvm-core::plan"`.

### Task B2: `mvm-policy` → `mvm-core::policy`

66 refs / 14 files; dependents: `mvm-cli`, `mvm-firecracker-bridge`, `mvm-libkrun-supervisor`, `mvm-supervisor`, `mvm-vz-drainer`. Note `mvm-core` already re-exports `policy::security` flat (mvmd's `SessionPolicy` depends on this — plan 51 Task 4); **preserve that re-export.**

**Files:** `crates/mvm-policy/src/*` → `crates/mvm-core/src/policy/`; same Cargo/lib/consumer/root pattern.

- [ ] **Step 1:** `git mv crates/mvm-policy/src crates/mvm-core/src/policy`; `git rm -r crates/mvm-policy`; `pub mod policy;` in `mvm-core/src/lib.rs`; **keep `pub use policy::security;`** if present (guard for mvmd).
- [ ] **Step 2:** Merge deps (no async); drop `mvm-policy` from the 5 dependents + root members. `mvm-policy` depended on `mvm-plan` → now an intra-crate `crate::plan` path.
- [ ] **Step 3:** `git grep -l 'mvm_policy::' -- crates/ | xargs sed -i '' 's/mvm_policy::/mvm_core::policy::/g'`; inside `mvm-core` fix self-refs to `crate::policy::`; in the moved policy files rewrite `mvm_plan::` → `crate::plan::`.
- [ ] **Step 4:** `cargo build --workspace && cargo test --workspace -q` → green; async-in-core check OK; assert `mvm_core::policy::security::SessionPolicy` resolves (`cargo build -p mvm-core` + a grep that the re-export line exists).
- [ ] **Step 5:** Commit: `git commit -m "refactor(core): fold mvm-policy into mvm-core::policy (keep policy::security re-export)"`.

### Task B3: `mvm-security` → `mvm-core::security`

103 refs / 30 files; dependents: `mvm`, `mvm` (`base` now), `mvm-cli`, `mvm-guest`. Pure crypto (attestation, key_rotation, secret_store, snapshot_encryption) — the strictest no-async check.

**Files:** `crates/mvm-security/src/*` → `crates/mvm-core/src/security/`; same pattern.

- [ ] **Step 1:** **Decision: fold it as `mvm_core::crypto`** (settle the name *here* — plans 122/123/127 already reference `mvm_core::crypto::*` as fact). Keep the existing `policy::security` as the distinct session-policy type, which sidesteps the name clash. `git mv crates/mvm-security/src crates/mvm-core/src/crypto`; `git rm -r crates/mvm-security`; `pub mod crypto;` in `mvm-core/src/lib.rs`.
- [ ] **Step 2:** Merge deps (RustCrypto/`zeroize`/`ed25519-dalek` — **no async**); drop `mvm-security` from the 4 dependents + root.
- [ ] **Step 3:** `git grep -l 'mvm_security::' -- crates/ | xargs sed -i '' 's/mvm_security::/mvm_core::crypto::/g'`; fix `mvm-core` self-refs to `crate::`.
- [ ] **Step 4:** `cargo build --workspace && cargo test --workspace -q` → green; async-in-core check OK; **`cargo run -p xtask -- check-no-display-on-secret-types`** still passes (the host-signer redacted-Debug guard now covers the moved code).
- [ ] **Step 5:** Commit: `git commit -m "refactor(core): fold mvm-security into mvm-core (pure crypto; no async in core)"`.

### Task B4: `core::` dedups (framing / config_envelope / paths / subprocess)

ADR-066 §1 line 54: collapse duplicated plumbing now that the folds put it in one crate. **Each dedup is its own red→green→commit cycle** so a regression is bisectable.

**Files:** `crates/mvm-core/src/{framing.rs,config_envelope.rs,paths.rs,subprocess.rs}` (new) + the call sites that had copies.

- [ ] **Step 1 (framing):** Identify the 6 vsock/framing impls (`git grep -l 'fn read_frame\|FramedMessage\|length_delimited\|write_frame' -- crates/`). Write `core::framing::FramedMessage<T>` with pluggable auth, port the most complete impl, add a serde-roundtrip + tampered-frame unit test, then replace each call site with `mvm_core::framing::*`. `cargo test -p mvm-core framing` → green. Commit.
- [ ] **Step 2 (config_envelope):** Find the 4 config/secret loaders (`git grep -l 'deny_unknown_fields' -- crates/ | …`); unify into `core::config_envelope` (one `#[serde(deny_unknown_fields)]` envelope loader); replace call sites; test the fail-closed-on-unknown-field path. Commit.
- [ ] **Step 3 (paths):** Unify the scattered XDG/path helpers (`git grep -l 'dirs::\|\.mvm\|cache/mvm' -- crates/`) into `core::paths`; replace; test. Commit.
- [ ] **Step 4 (subprocess):** Unify the three signer-subprocess templates into one keyless `core::subprocess` scaffold (§3); replace; test. Commit.
- [ ] **Step 5:** Workspace green + clippy; `cargo run -p xtask -- check-forbidden-deps` (the framing/config dedup must not re-introduce a banned dep).

## Phase C — backend + FFI extraction

### Task C1: `mvm-libkrun` → `crates/deps/libkrun-sys` + `mvm-backend`

The **only** true C FFI (bindgen + `rustc-link-lib=krun`, `build.rs:20-72`, `src/sys.rs`). ADR-066 §2: the binding moves to `crates/deps/libkrun-sys` (binding + thin safe wrapper only); the selection/dispatch logic moves into `mvm-backend`. Update the fuzz `working-directory`.

**Files:** create `crates/deps/libkrun-sys/{Cargo.toml,build.rs,src/lib.rs}` (the bindgen surface from `mvm-libkrun/build.rs` + `src/sys.rs`); move the safe wrapper (`mvm-libkrun/src/lib.rs` minus sys) into `crates/mvm-backend/src/libkrun/`; move `crates/mvm-libkrun/fuzz` → `crates/deps/libkrun-sys/fuzz`; `.github/workflows/security.yml` (the `working-directory: crates/mvm-libkrun` line); root `Cargo.toml` (`members` + the fuzz `exclude`).

- [ ] **Step 1:** `git mv crates/mvm-libkrun/build.rs crates/deps/libkrun-sys/build.rs` + `git mv crates/mvm-libkrun/src/sys.rs crates/deps/libkrun-sys/src/lib.rs`; author `crates/deps/libkrun-sys/Cargo.toml` (name `libkrun-sys`, `links = "krun"`, the `libkrun-sys` feature). Add `"crates/deps/libkrun-sys"` to root members.
- [ ] **Step 2:** Move the safe wrapper into `crates/mvm-backend/src/libkrun/mod.rs`; `mvm-backend` deps `libkrun-sys`. Rewrite `mvm_libkrun::` refs (`mvm-backend/src/libkrun.rs:2`, `mvm-libkrun-supervisor`, `mvm-plan`-via-now-core sites) to the new paths.
- [ ] **Step 3 (gate, same commit):** in `.github/workflows/security.yml` change `working-directory: crates/mvm-libkrun` → `crates/deps/libkrun-sys` for `fuzz_supervisor_config`; in root `Cargo.toml [workspace] exclude` change `crates/mvm-libkrun/fuzz` → `crates/deps/libkrun-sys/fuzz`.
- [ ] **Step 4:** `cargo build --workspace` (with + without `--features libkrun-sys` if gated) `&& cargo test -p mvm-backend -q` → green.
- [ ] **Step 5:** Commit: `git commit -m "refactor(backend): extract libkrun C FFI to crates/deps/libkrun-sys; wrapper into mvm-backend"`.

### Task C2: `mvm-providers`, `mvm-vz` → `mvm-backend`

Swift-interface, **no Rust FFI** (inventory §3) — fold straight into `mvm-backend` as modules behind `VmBackend`. Move the `mvm-vz` fuzz dir.

**Files:** `crates/mvm-vz/src/*` → `crates/mvm-backend/src/vz/`; `crates/mvm-providers/src/*` → `crates/mvm-backend/src/providers/` (the `apple_container` interface); `crates/mvm-vz/fuzz` → `crates/mvm-backend/fuzz` (merge); `.github/workflows/security.yml` (`working-directory: crates/mvm-vz`); root `Cargo.toml`.

- [ ] **Step 1:** `git mv` both `src/` trees into `mvm-backend/src/{vz,providers}/`; add `pub mod vz; pub mod providers;` to `mvm-backend/src/lib.rs`. Merge their deps; drop both from root members + from any dependents' Cargo.toml.
- [ ] **Step 2:** Rewrite `mvm_vz::` / `mvm_providers::` refs → `mvm_backend::{vz,providers}::` (`git grep -l … | xargs sed …`).
- [ ] **Step 3 (gate, same commit):** move `crates/mvm-vz/fuzz` → `crates/mvm-backend/fuzz` (it currently has `fuzz_supervisor_config`); update `security.yml` `working-directory: crates/mvm-vz` → `crates/mvm-backend`; update root `exclude`.
- [ ] **Step 4:** `cargo build --workspace && cargo test -p mvm-backend -q` → green.
- [ ] **Step 5:** Commit: `git commit -m "refactor(backend): fold mvm-vz + mvm-providers into mvm-backend (Swift-interface, no FFI)"`.

## Phase D — new container crates + bin relocations

### Task D1: new `mvm-hostd` — 4 `[[bin]]`s + jailer module

ADR-066 §1 line 47 / §3 (the process moat): one crate, **four separate `[[bin]]`s** (supervisor, broker, host-signer, audit-signer) so each role is its own process; `mvm-jailer-lite` becomes a module.

**Files:** create `crates/mvm-hostd/{Cargo.toml,src/lib.rs}` + `src/bin/{mvm-supervisor,mvm-broker,mvm-host-signer,mvm-audit-signer}.rs`; move the 5 source crates' `src/` into `crates/mvm-hostd/src/{supervisor,broker,host_signer,audit_signer,jailer}/`; root `Cargo.toml`; the dependents of each (e.g. anything calling `mvm_supervisor::verify_audit_chain`).

- [ ] **Step 1:** Author `crates/mvm-hostd/Cargo.toml` with the union of the 5 crates' deps + four `[[bin]]` stanzas. `git mv` each crate's `src` into a module dir; each old `main.rs` becomes the matching `src/bin/<name>.rs` calling `mvm_hostd::<module>::run()`.
- [ ] **Step 2:** `pub mod {supervisor,broker,host_signer,audit_signer,jailer};` in `mvm-hostd/src/lib.rs`. Rewrite cross-refs (`mvm_supervisor::`→`mvm_hostd::supervisor::`, etc.); drop the 5 from root members + dependents' Cargo.toml; add `mvm-hostd`.
- [ ] **Step 3:** `cargo build --workspace && cargo test -p mvm-hostd -q` → green; **the claim-8 audit-chain tests** (`verify_audit_chain`) still pass; `cargo run -p xtask -- check-handler-adr-coverage check-handler-policy-schema` — **NOTE:** the inventory found these three `check-handler-*` lints do **not** exist in `xtask` today (they're cited in CLAUDE.md but unbuilt — plan 128 builds them); skip if absent, do not invent.
- [ ] **Step 4:** Commit: `git commit -m "refactor(hostd): consolidate supervisor/broker/signers/jailer into mvm-hostd (4 [[bin]]s)"`.

### Task D2: new `mvm-vm-host` — cfg-gated per-VM `[[bin]]`s

ADR-066 §1 line 48 (finalize the name to `mvm-vm-host`, **not** the stale `mvm-vm-sidecar` — see Task E1): the three per-VM supervisor processes (one process per VM) become cfg-gated `[[bin]]`s of `mvm-vm-host`. Move the firecracker-bridge fuzz dir.

**Files:** create `crates/mvm-vm-host/{Cargo.toml,src/lib.rs}` + cfg-gated `src/bin/{mvm-libkrun-supervisor,mvm-vz-drainer,mvm-firecracker-bridge}.rs`; move the 3 crates' `src/`; move `crates/mvm-firecracker-bridge/fuzz` → `crates/mvm-vm-host/fuzz`; `.github/workflows/security.yml` (the firecracker-bridge `working-directory` + its two fuzz targets `fuzz_bridge_config_json`, `fuzz_passt_hashes_toml`); root `Cargo.toml`.

- [ ] **Step 1:** Author `crates/mvm-vm-host/Cargo.toml` (union deps; three `[[bin]]`s each `#[cfg]`-gated to its backend/OS as today). `git mv` each `src` into a module; old `main.rs` → `src/bin/<name>.rs`.
- [ ] **Step 2:** Rewrite refs (`mvm_firecracker_bridge::` etc. → `mvm_vm_host::…`); drop the 3 from root members; add `mvm-vm-host`.
- [ ] **Step 3 (gate, same commit):** `git mv crates/mvm-firecracker-bridge/fuzz crates/mvm-vm-host/fuzz`; in `security.yml` change `working-directory: crates/mvm-firecracker-bridge` → `crates/mvm-vm-host`; update root `exclude`.
- [ ] **Step 4:** `cargo build --workspace` (per-OS cfg paths) `&& cargo test -p mvm-vm-host -q` → green.
- [ ] **Step 5:** Commit: `git commit -m "refactor(vm-host): consolidate per-VM supervisors into mvm-vm-host (cfg-gated [[bin]]s)"`.

### Task D3: new `mvm-guest-helpers` — in-guest helper `[[bin]]`s

ADR-066 §1 line 46: `mvm-addon-dns` + `mvm-addon-vsock-bridge` → `mvm-guest-helpers` (`[[bin]]`s).

**Files:** create `crates/mvm-guest-helpers/{Cargo.toml,src/lib.rs,src/bin/{mvm-addon-dns,mvm-addon-vsock-bridge}.rs}`; move both crates' `src/`; root `Cargo.toml`; the nix `mkGuest` reference (if `bakeAddonDns` points at a package name — verify `nix/lib/mk-guest.nix` / `nix/packages/` package attr names still resolve, update if a `[[bin]]` path/name changed).

- [ ] **Step 1:** Author the crate + two `[[bin]]`s; `git mv` both `src` trees into modules; drop both from root members; add `mvm-guest-helpers`.
- [ ] **Step 2:** Rewrite any refs; check `nix/packages/*.nix` + `mk-guest.nix` for `mvm-addon-dns`/`mvm-addon-vsock-bridge` build attrs and update the cargo package/bin name if it changed (the binaries' install paths must stay so the guest boot path is unbroken).
- [ ] **Step 3:** `cargo build --workspace && cargo test -p mvm-guest-helpers -q` → green; `nix flake check ./nix/...` for the affected image flake if reachable (else note as a Stage-D live check).
- [ ] **Step 4:** Commit: `git commit -m "refactor(guest): consolidate addon-dns + vsock-bridge into mvm-guest-helpers"`.

### Task D4: `mvm-host-vm-init`, `mvm-egress-proxy` → `mvm-build` `[[bin]]`s

ADR-066 §1 lines 35-36: builder-VM-only Linux tools become `[[bin]]`s of `mvm-build`, cfg-gated inert on non-Linux. **Cross-check ADR-065 / Plan 115:** `crates/mvm-cli/build.rs` cross-compiles these via `cargo-zigbuild`; the `[[bin]]` move must keep their package/bin names so that build.rs + `MVM_HOST_BIN_DIR` + the `check-mvm-host-binaries-sync` xtask lint still resolve.

**Files:** move both crates' `src/` → `crates/mvm-build/src/bin/`; `crates/mvm-build/Cargo.toml` (two cfg-gated `[[bin]]`s); `crates/mvm-cli/build.rs` (the cross-compile target package names); root `Cargo.toml`; verify `xtask check-mvm-host-binaries-sync`.

- [ ] **Step 1:** `git mv crates/mvm-host-vm-init/src/main.rs crates/mvm-build/src/bin/mvm-host-vm-init.rs` (+ egress-proxy); add cfg-gated `[[bin]]` stanzas (`#[cfg(target_os="linux")]`-style inert body off-Linux); `git rm -r` both old crates; drop from root members.
- [ ] **Step 2:** Update `crates/mvm-cli/build.rs` so the embedded-binary cross-compile points at the `mvm-build` package's bins (names unchanged: `mvm-host-vm-init`, `mvm-egress-proxy`).
- [ ] **Step 3:** `cargo build --workspace && cargo run -p xtask -- check-mvm-host-binaries-sync` → green (this lint asserts the embedded host-binary set matches reality — it MUST pass).
- [ ] **Step 4:** Commit: `git commit -m "refactor(build): move host-vm-init + egress-proxy into mvm-build [[bin]]s (ADR-065)"`.

## Phase E — facade republish + finalize

### Task E1: republish facade + `mvm-core` map; fix ADR naming; docs

- [ ] **Step 1:** Update the root facade `src/lib.rs` re-exports (`mvmctl::{core,runtime,build,guest}` → the post-fold crates) so the **public contract mvmd plan 51 consumes** is current. Verify `mvmctl::core::policy::security::SessionPolicy`, `mvmctl::runtime::shell::{run_in_vm,run_in_vm_visible}`, `mvmctl::build::build::pool_build`, `mvmctl::guest::vsock::{GUEST_CID,…}` all still resolve (plan 51's 3 seams).
- [ ] **Step 2:** Fix the ADR-066 naming inconsistency: in `specs/adrs/066-target-architecture.md` lines 48 + 52, change `mvm-vm-sidecar` → `mvm-vm-host` (the crate finalized in D2; kills the "sidecar" overload consistently with `ArtifactSidecar`→`ArtifactManifest`).
- [ ] **Step 3:** Update `CLAUDE.md` "Workspace Structure" + "Key module locations" to the 16-crate reality (mvm-core absorbs plan/policy/security; mvm-sdk absorbs ir; backends + per-VM processes + hostd consolidated; `crates/deps/libkrun-sys`).
- [ ] **Step 4:** Produce the concrete **old→new path table** for mvmd plan 51 Task 1 (every `mvm_plan::`/`mvm_policy::`/`mvm_security::`/`mvm_ir::`/`mvm_base::`/`mvm_runner::` → its new path) and append it to `specs/plans/121-crate-consolidation.md` (this file) under a `## old→new ident map` heading, or note it's already the per-task sed list above.
- [ ] **Step 5:** Final gate sweep: `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo test --workspace && cargo run -p xtask -- check-spec-numbers check-forbidden-deps check-doc-claims check-no-overclaim check-mvm-host-binaries-sync check-no-display-on-secret-types` → all green. Count crates: `ls -d crates/*/Cargo.toml | wc -l` = 16 architectural (+ `crates/deps/libkrun-sys` + fuzz).
- [ ] **Step 6:** Commit: `git commit -m "refactor(crates): republish mvmctl facade + mvm-core map; finalize 32->16 consolidation"`. Tick the brief's Stage C box 121 + the mvmd-plan-51 unblock note.

## Acceptance

- [ ] Workspace is **16 architectural crates** (`mvm-core, mvm-sdk, mvm-sdk-macros, mvm, mvm-build, mvm-guest, mvm-cli, mvm-mcp, mvm-oci, mvm-backend, mvm-storage, mvm-hostd, mvm-vm-host, mvm-guest-helpers, mvm-vz-supervisor`(Swift)`, xtask`) + `crates/deps/libkrun-sys` + the fuzz crates. (`mvm-network` = 17th, plan 123.)
- [ ] `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check` green.
- [ ] **No async/runtime dep entered `mvm-core`** (the `cargo tree | grep tokio` check passes after B1–B3).
- [ ] The **full ADR §8 rename-break checklist** applied same-commit (3 fuzz dirs + `-p mvm-libkrun` lane + sealed-prod-allowlist `-p mvm-core`/`-p mvm-guest` + the `policy::security::tests::*`/`vsock::tests::*` count-locks + `check-audit-positional` exempt path + `check-mvm-host-binaries-sync` manifest path); all existing xtask claim-gate lints green.
- [ ] `mvmctl` facade + `mvm-core` module map current; the old→new ident table is published for mvmd plan 51.
- [ ] ADR-066 + CLAUDE.md reflect the 16-crate reality; `mvm-vm-sidecar`→`mvm-vm-host` fixed.

### deferred follow-ups

- [ ] `mvm-network` (17th crate) + `NetworkProvider`/`StorageProvider` impls → **plan 123**.
- [ ] `mvm-storage` `encrypted` impl → **plan 122**.
- [ ] The lean-agent dep cut (`mvm-guest`) → **124**; the real third-party-dep reduction → **126**.
- [ ] Fuzz *parity* + the missing `check-handler-*` / `check-prod-agent-no-exec` gates → **128** (this plan only re-points the 3 fuzz dirs it moves).

## Self-review

- **Spec coverage:** every row of the ADR-066 §1 crate map (lines 26-50) maps to a task (A1–D4); the §8 rename-break checklist = the 3 fuzz-dir gate updates (C1/C2/D2) + the `check-mvm-host-binaries-sync` guard (D4), applied same-commit per the recipe; the facade/`mvm-core`-map republish for mvmd (E1) is covered. `mvm-network`/encryption/dep-reduction explicitly deferred with plan pointers.
- **No placeholders / real grounding:** ref counts, dependents, and the FFI/CI facts are the inventory's; the only "discover at task time" steps are the dedup *source*-impl locations (B4) and the framing/config call sites — expressed as concrete `git grep` discovery, not vague TODOs. Flagged honestly that the three `check-handler-*` lints **don't exist yet** (CLAUDE.md over-claims them; built in 128) so D1 doesn't invent them.
- **Type/name consistency:** `mvm-vm-host` used throughout (not `mvm-vm-sidecar`); `mvm-core::{plan,policy,security}` and `mvm-sdk::ir` used consistently; the `policy::security` re-export preserved for mvmd's `SessionPolicy` (plan 51 Task 4).
