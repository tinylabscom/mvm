# Release 1 Phase 1 — Vz Deletion — Implementation Plan

**Status: COMPLETE (2026-07-08, branch `feat/plan-229-vz-deletion`).** All tasks
landed with per-task commits; see the Deferred follow-ups and Self-Review below for
the adaptations from the plan (macOS-26 dev VM → libkrun; `checkpoint/fork`
tracked-unsupported; `BuilderBackendChoice::Hvf` instead of `InHouse`).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Execute in an isolated git worktree (the user enforces worktree isolation).

**Goal:** Delete the entire Apple-Virtualization (`vz`) backend from mvm and re-home the one runtime capability that depended on it (`machine checkpoint/fork`) onto a backend-agnostic, tracked-unsupported gate — while keeping libkrun (and its gvproxy path) untouched.

**Architecture:** The macOS-26 default is already the in-house HVF VMM; `vz` is opt-in. This plan removes the opt-in `vz` code path in dependency order: first sever the two runtime consumers (checkpoint gate + dev-VM selection), then delete the `Vz` variant and its backend/supervisor/builder modules, then migrate the Vz-only CI/claim witnesses, ratify ADR-098, and release-engineer v0.17.0. libkrun's gvproxy usage is deliberately out of scope (Phase 2 / plan 226-R1P2).

**Tech Stack:** Rust (Cargo workspace, `cargo nextest`), objc2 (deleted), GitHub Actions, xtask claim-gates.

## Global Constraints

- **Keep libkrun and its gvproxy path fully intact** — this plan touches `vz` only. Do not modify `crates/deps/libkrun-sys/src/gvproxy.rs`, `libkrun.rs::with_gvproxy`, or the libkrun builder.
- **Keep passt untouched** (Linux gateway, retired in R2).
- **Preserve the `mvmctl::runtime::*` re-export contract** so mvmd still builds — do not remove or rename public re-exports from `mvm-backend::base` / the root facade.
- **Gates that must be green before every commit:** `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings`. Prefer `just ci`. On macOS also run `just check-linux` before the final commit of a task that touches `cfg`-gated code.
- **No `#[allow(clippy::too_many_arguments)]`.** Use a params struct if a signature trips the lint.
- Commit messages end with the repo's `Co-Authored-By` trailer; reference `(Plan 226 R1P1)`.

---

### Task 1: Make the checkpoint save/restore gate backend-agnostic (WS-D)

Today `ensure_save_restore_supported()` hard-codes `VzBackend` as the snapshot substrate (`crates/mvm-cli/src/commands/vm/checkpoint.rs:361-373`). That line stops compiling the moment `VzBackend` is deleted, and it is wrong anyway (it ignores the active backend). Redirect it to consult the *selected* backend and bail with a clear, tracked "unsupported" error. When HVF SaveRestore lands (plan 226-R1E), this gate starts passing on HVF with no further change.

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/checkpoint.rs:361-373`
- Test: `crates/mvm-cli/src/commands/vm/checkpoint.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `mvm_core::vm_backend::{SnapshotCapability, VmBackend}` (already imported at line 23); `AnyBackend::snapshot_capability()` / `.name()`.
- Produces: `fn ensure_save_restore_supported(backend: &AnyBackend, action: &str) -> Result<()>` — later tasks and existing callers use this signature.

- [x] **Step 1: Write the failing test**

Add to the `#[cfg(test)]` module in `checkpoint.rs`:

```rust
#[test]
fn save_restore_gate_rejects_backend_without_capability() {
    // The mock backend reports SnapshotCapability::Unsupported (trait default).
    let backend = mvm_backend::AnyBackend::from_hypervisor("mock");
    let err = ensure_save_restore_supported(&backend, "checkpoint")
        .expect_err("mock must not satisfy SaveRestore");
    let msg = err.to_string();
    assert!(msg.contains("checkpoint"), "names the action: {msg}");
    assert!(msg.contains("save/restore"), "names the missing capability: {msg}");
    assert!(msg.contains("HVF"), "points at the tracked HVF re-home: {msg}");
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli save_restore_gate_rejects_backend_without_capability`
Expected: FAIL — `ensure_save_restore_supported` still takes one arg / references `VzBackend`.

- [x] **Step 3: Rewrite the gate to consult the active backend**

Replace lines 361-373 with:

```rust
fn ensure_save_restore_supported(backend: &mvm_backend::AnyBackend, action: &str) -> Result<()> {
    let available = backend.inner().snapshot_capability();
    if !available.satisfies(SnapshotCapability::SaveRestore) {
        bail!(
            "vm {action} requires full-VM save/restore, but backend '{}' reports \
             snapshot tier '{}' on this host. Full-VM checkpoint/fork is being \
             re-homed onto the in-house HVF VMM (tracked in Plan 226 WS-E); it is \
             unavailable on this backend for now.",
            backend.name(),
            available.label()
        );
    }
    Ok(())
}
```

If `inner()` is `pub(crate)` and unreachable from this module, use the public `AnyBackend::snapshot_capability()` accessor instead; if none exists, add a thin `pub fn snapshot_capability(&self) -> SnapshotCapability { self.inner().snapshot_capability() }` to `AnyBackend` in `backend.rs` and call that.

- [x] **Step 4: Update the callers to pass the active backend**

Find every `ensure_save_restore_supported(` call in `checkpoint.rs` (grep within the file). Each call site already resolves an `AnyBackend` for the operation — thread that value in as the first argument. If a call site has no backend in scope, resolve it with `AnyBackend::auto_select()` at that point (matching how the surrounding command resolves its backend).

- [x] **Step 5: Run the test + workspace build to verify green**

Run: `cargo nextest run -p mvm-cli save_restore_gate_rejects_backend_without_capability && cargo build -p mvm-cli`
Expected: PASS + clean build.

- [x] **Step 6: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/checkpoint.rs crates/mvm-backend/src/backend.rs
git commit -m "refactor(checkpoint): backend-agnostic save/restore gate, tracked HVF re-home (Plan 226 R1P1 WS-D)"
```

---

### Task 2: Add `DevBackend::InHouse` and flip macOS-26 dev selection off Vz (WS-B)

`crates/mvm-cli/src/commands/env/dev.rs` still defaults macOS-26 Apple Silicon to `DevBackend::Vz` (`select_dev_backend`, rule 3, lines 89-118) and drives the dev VM through `VzBackend` lifecycle calls (lines 335, 362, 462-463). Introduce an `InHouse` variant, make it the macOS-26 default, and replace the `VzBackend` lifecycle calls with the in-house/HVF backend.

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/dev.rs:29` (import), `:39-56` (enum), `:89-118` (selection), `:121-125` (`builder_prefers_vz`), `:335`, `:362`, `:462-463` (lifecycle calls)
- Test: `crates/mvm-cli/src/commands/env/dev.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: `mvm_backend::AnyBackend` / `HvfBackend`; `Platform`, `is_vz_default_tier`.
- Produces: `DevBackend::InHouse`; `select_dev_backend(...) -> DevBackend` returns `InHouse` on the macOS-26 tier.

- [x] **Step 1: Read the in-house dev-VM lifecycle entry points**

Run: `rg -n "DevBackend::(Libkrun|Vz)" crates/mvm-cli/src/commands/env/dev.rs` and read the three lifecycle sites (status/stop/takeover at 335, 362, 462-463). Confirm the in-house dev VM's status/stop entry point — grep `rg -n "fn (status|stop)" crates/mvm-backend/src/hvf` and `rg -n "InHouse|HvfBackend" crates/mvm-cli/src/commands/env/dev.rs`. Record the exact call you will substitute for `VzBackend.status()` / `VzBackend.stop()`.

- [x] **Step 2: Write the failing selection test**

Add to the `#[cfg(test)]` module:

```rust
#[test]
fn macos_26_apple_silicon_selects_inhouse_dev_backend() {
    let choice = select_dev_backend(
        Platform::MacOS,
        /* prefers_vz */ false,
        /* prefers_libkrun */ false,
        /* has_vz */ true,
        /* is_vz_default_tier */ true,
        /* has_libkrun */ true,
        /* has_kvm */ false,
    );
    assert_eq!(choice, DevBackend::InHouse);
}
```

- [x] **Step 3: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli macos_26_apple_silicon_selects_inhouse_dev_backend`
Expected: FAIL — `DevBackend::InHouse` does not exist / rule 3 returns `Vz`.

- [x] **Step 4: Add the `InHouse` variant and flip the selection**

In the `DevBackend` enum (lines 39-56) replace the `Vz` variant with:

```rust
    /// macOS 26+ Apple Silicon — the in-house HVF VMM dev builder VM. The
    /// canonical macOS dev path (auto-detected on the in-house default tier).
    InHouse,
```

In `select_dev_backend` remove the two `prefers_vz`/`has_vz` Vz branches and rule 3, so the tree reads:

```rust
    // 1. Explicit libkrun override on macOS.
    if prefers_libkrun && has_libkrun && matches!(plat, Platform::MacOS) {
        return DevBackend::Libkrun;
    }
    // 2. macOS 26+ Apple Silicon → in-house HVF dev VM.
    if is_vz_default_tier {
        DevBackend::InHouse
    } else if matches!(plat, Platform::MacOS) && has_libkrun {
        DevBackend::Libkrun
    } else if has_kvm && matches!(plat, Platform::LinuxNative) {
        DevBackend::LinuxKvm
    } else {
        DevBackend::Unsupported
    }
```

Delete the now-unused `prefers_vz`, `has_vz` parameters from `select_dev_backend` and update its one caller. Delete `builder_prefers_vz()` (lines 121-125) and its call sites.

- [x] **Step 5: Re-home the lifecycle calls**

At lines 335, 362, 462-463 replace each `VzBackend` status/stop call with the in-house entry point recorded in Step 1, matched on `DevBackend::InHouse`. Remove `VzBackend` from the `use mvm_backend::{...}` import at line 29 (keep `LibkrunBackend`).

- [x] **Step 6: Run tests + build**

Run: `cargo nextest run -p mvm-cli -- dev && cargo build -p mvm-cli`
Expected: PASS + clean build. Fix any match-exhaustiveness errors on `DevBackend` (the compiler lists them).

- [x] **Step 7: Commit**

```bash
git add crates/mvm-cli/src/commands/env/dev.rs
git commit -m "feat(dev): default macOS-26 dev VM to in-house HVF, drop Vz dev path (Plan 226 R1P1 WS-B)"
```

---

### Task 3: Confirm builder auto-detect + fallback survive Vz removal (WS-C)

The macOS-26 builder already auto-detects `InHouse` with a libkrun fallback (`builder_backend_select.rs`). We are *keeping* libkrun as the fallback — the only change is removing the now-dead `Vz` builder branch. Add a guard test that the macOS auto path is `[InHouse, Libkrun]` with no Vz, then delete the Vz builder wiring.

**Files:**
- Modify: `crates/mvm-build/src/builder_backend_select.rs:31` (import), `:73` (`Vz` variant), `:89` (`.name()`), `:134` (env map), `:189`/`:212` (`VzBuilderVm::new()`), `:280-318` (`builder_attempt_order` Vz arm)
- Delete: `crates/mvm-build/src/vz_builder.rs`
- Test: `crates/mvm-build/src/builder_backend_select.rs` (inline `#[cfg(test)]`)

**Interfaces:**
- Consumes: `BuilderBackendChoice::{InHouse, Libkrun, Qemu}`.
- Produces: `builder_attempt_order` no longer has a `Vz` arm; `BuilderBackendChoice` has no `Vz` variant.

- [x] **Step 1: Write the failing guard test**

```rust
#[test]
fn macos_inhouse_auto_falls_back_to_libkrun_only() {
    let order = builder_attempt_order(
        BuilderBackendChoice::InHouse,
        /* explicit */ false,
        /* is_linux_native */ false,
        /* libkrun_unhealthy */ false,
    );
    assert_eq!(order, vec![BuilderBackendChoice::InHouse, BuilderBackendChoice::Libkrun]);
}

#[test]
fn builder_backend_choice_has_no_vz_variant() {
    // Compile-time guard: every choice round-trips through name() without Vz.
    for c in [BuilderBackendChoice::InHouse, BuilderBackendChoice::Libkrun, BuilderBackendChoice::Qemu] {
        assert_ne!(c.name(), "vz");
    }
}
```

- [x] **Step 2: Run to verify the first passes, second compiles**

Run: `cargo nextest run -p mvm-build macos_inhouse_auto_falls_back_to_libkrun_only builder_backend_choice_has_no_vz_variant`
Expected: `macos_inhouse_auto_falls_back_to_libkrun_only` PASS (behaviour already correct); the second will keep passing until Vz is removed — it is a regression guard.

- [x] **Step 3: Delete the Vz builder wiring**

- Remove `use crate::vz_builder::VzBuilderVm;` (line 31).
- Remove the `Vz` arm from `BuilderBackendChoice` (line 73) and its `.name()` case (line 89).
- Remove the `"vz" => BuilderBackendChoice::Vz` map in `resolve_env_override()` (line 134).
- Remove the `VzBuilderVm::new()` construction arms (lines 189, 212).
- Remove the `BuilderBackendChoice::Vz => vec![...]` arm from `builder_attempt_order` (line ~309).
- `git rm crates/mvm-build/src/vz_builder.rs` and remove its `mod vz_builder;` declaration.

- [x] **Step 4: Fix fallout + build**

Run: `cargo build -p mvm-build` and resolve every match-exhaustiveness / unused-import error the compiler reports (these enumerate the remaining Vz references).

- [x] **Step 5: Run tests**

Run: `cargo nextest run -p mvm-build`
Expected: PASS. Delete or update any Vz-specific builder test that no longer compiles.

- [x] **Step 6: Commit**

```bash
git add -A crates/mvm-build/
git commit -m "refactor(builder): drop Vz builder backend, keep libkrun fallback (Plan 226 R1P1 WS-C)"
```

---

### Task 4: Remove the `Vz` variant from `AnyBackend` and its dispatch arms (WS-A core)

With the two runtime consumers severed (Tasks 1-3), delete the `Vz` variant from the backend enum and every `match` arm. `capability_candidates()` returns a fixed `[AnyBackend; 4]` — dropping Vz changes the arity to `; 3]`.

**Files:**
- Modify: `crates/mvm-backend/src/backend.rs:21` (import), `:474-476` (variant), `:522-540` (`from_hypervisor` doc), `:625-634` (`kind`), `:636-646` (`inner`), `:650-662` (`into_dyn`), `:703-715` (`as_workload_backend`), `:988-994` + `:1162-1163` (tests)
- Modify: `crates/mvm-backend/src/selection.rs:13` (import), `:57-70` (`capability_candidates`)
- Modify: `crates/mvm-backend/src/catalog.rs` (the `descriptor_for_selector("vz")` table entry + `BackendKind::Vz`)
- Test: existing backend tests

**Interfaces:**
- Consumes: nothing new.
- Produces: `AnyBackend` with no `Vz` variant; `BackendKind` with no `Vz`; `capability_candidates() -> [AnyBackend; 3]`.

- [x] **Step 1: Write the failing guard test**

Add to the `#[cfg(test)]` module in `backend.rs`:

```rust
#[test]
fn from_hypervisor_vz_falls_back_to_default_not_vz() {
    // Vz is deleted: the "vz" selector must no longer yield a distinct Vz backend.
    let b = AnyBackend::from_hypervisor("vz");
    assert_ne!(b.name(), "vz", "vz selector must not resolve to a Vz backend");
}
```

- [x] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-backend from_hypervisor_vz_falls_back_to_default_not_vz`
Expected: FAIL — `"vz"` still resolves through the catalog to `AnyBackend::Vz`.

- [x] **Step 3: Delete the variant and dispatch arms**

- Remove `use crate::vz::VzBackend;` (backend.rs:21) and `selection.rs:13`.
- Remove the `Vz(VzBackend)` variant (backend.rs:474-476).
- Remove the `Self::Vz(...) =>` arms from `kind()`, `inner()`, `into_dyn()`, `as_workload_backend()`.
- In `selection.rs`, change `capability_candidates()` return type to `[AnyBackend; 3]` and drop the `AnyBackend::Vz(VzBackend)` entry.
- In `catalog.rs`, remove the `"vz"`/`"apple-container"` selector descriptor and the `BackendKind::Vz` variant (and any `BackendKind::Vz` match arms the compiler flags).
- Delete/rewrite the Vz-specific tests at backend.rs:988-994 (`test_any_backend_from_hypervisor_vz`) and adjust the `vz.pid` → `Vz` test at 1162-1163 (drop the Vz expectation).

- [x] **Step 4: Build and chase the errors**

Run: `cargo build -p mvm-backend`
Expected: the compiler enumerates every remaining `Vz` / `BackendKind::Vz` reference. Fix each (they are all in dispatch/selection/tests). Repeat until clean.

- [x] **Step 5: Run tests**

Run: `cargo nextest run -p mvm-backend from_hypervisor_vz_falls_back_to_default_not_vz && cargo nextest run -p mvm-backend`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add crates/mvm-backend/src/backend.rs crates/mvm-backend/src/selection.rs crates/mvm-backend/src/catalog.rs
git commit -m "refactor(backend): remove the Vz variant from AnyBackend + dispatch (Plan 226 R1P1 WS-A)"
```

---

### Task 5: Delete the Vz backend modules and the Vz supervisor bin (WS-A)

Now that nothing references the `Vz` variant, delete the implementation files. `host_gvproxy.rs` is the **Vz-only** host-side gvproxy lifecycle (its module doc says "for the Vz backend") and is consumed exclusively by `vz.rs` — it goes with Vz. (libkrun's gvproxy lives in `crates/deps/libkrun-sys/src/gvproxy.rs` and stays.)

**Files:**
- Delete: `crates/mvm-backend/src/vz.rs`, `crates/mvm-backend/src/vz_control.rs`, `crates/mvm-build/src/vz.rs`, `crates/mvm-build/src/host_gvproxy.rs`, `crates/mvm-vm-host/src/vz_objc.rs`, `crates/mvm-vm-host/src/bin/mvm-vz-supervisor.rs`
- Modify: the `mod vz;` / `mod vz_control;` / `mod host_gvproxy;` / `mod vz_objc;` declarations in the respective `lib.rs` files; the `[[bin]]` entry for `mvm-vz-supervisor` in `crates/mvm-vm-host/Cargo.toml`; remove the objc2/Virtualization deps from `crates/mvm-vm-host/Cargo.toml` if now unused.

**Interfaces:** none produced; pure deletion.

- [x] **Step 1: Delete the files and module declarations**

```bash
git rm crates/mvm-backend/src/vz.rs crates/mvm-backend/src/vz_control.rs \
       crates/mvm-build/src/vz.rs crates/mvm-build/src/host_gvproxy.rs \
       crates/mvm-vm-host/src/vz_objc.rs crates/mvm-vm-host/src/bin/mvm-vz-supervisor.rs
```

Remove the matching `mod vz;` / `mod vz_control;` / `pub mod vz;` / `mod host_gvproxy;` / `mod vz_objc;` lines (grep each crate's `lib.rs`), and delete the `[[bin]] name = "mvm-vz-supervisor"` block in `crates/mvm-vm-host/Cargo.toml`.

- [x] **Step 2: Build and remove now-unused deps**

Run: `cargo build --workspace`
Expected: compiler flags any remaining `crate::vz::` / `mvm_build::vz::` / `host_gvproxy` references (e.g. `substitution_spawn.rs` UDS transport, `standby_pool.rs` `vz_compat`) and unused deps. Delete the dead code paths (the UDS/`vz_compat` arms are Vz-only). If `objc2`/`objc2-virtualization` are now unreferenced, remove them from `crates/mvm-vm-host/Cargo.toml` and run `cargo update -w` to drop them from the lockfile.

- [x] **Step 3: Confirm the facade re-export contract is intact**

Run: `rg -n "pub use|pub mod" src/lib.rs crates/mvm/src/lib.rs | rg -i "runtime|base"` and confirm no `mvmctl::runtime::*` re-export was removed. The deletion must not change the public facade mvmd consumes.

- [x] **Step 4: Full workspace gate**

Run: `just ci` (or `cargo fmt --all -- --check && cargo nextest run --workspace && cargo test --workspace --doc && cargo clippy --workspace -- -D warnings`). Also run `just check-linux`.
Expected: all green. Delete any remaining Vz-only tests that fail to compile.

- [x] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(backend)!: delete the Vz backend, supervisor bin, and Vz-only gvproxy lifecycle (Plan 226 R1P1 WS-A)"
```

---

### Task 6: Drop the `vz` label/tier assertions in the shared resolver (WS-A tail)

`crates/mvm-cli/src/commands/shared/resolve.rs` has tests that assert `vz`-specific behaviour (`egress_enforcement_label("vz", …)` → `"vz:l4-host-port"`, `resolve_effective_hypervisor("vz")` → `"vz"`). The `egress_enforcement_label` *function* is backend-agnostic (it formats whatever string it's given) and stays; only the `vz` test assertions are removed. `resolve_effective_hypervisor("vz")` still legitimately returns `"vz"` as a pass-through of an explicit value — decide per Step 1.

**Files:**
- Modify: `crates/mvm-cli/src/commands/shared/resolve.rs:349-412` (tests only)

- [x] **Step 1: Decide the `vz` pass-through policy**

`resolve_effective_hypervisor` returns any explicit non-`firecracker` value unchanged (line 250-252). With Vz deleted, `--hypervisor vz` would pass `"vz"` down to `AnyBackend::from_hypervisor("vz")`, which now falls back to the default (Task 4). That is acceptable (clear behaviour: unknown → default). Keep the pass-through; just remove the test that asserts a distinct `vz` tier.

- [x] **Step 2: Remove the `vz` assertions**

Delete the `"vz"` iterations and assertions in `enforcement_tier_uniform_for_deny_all_and_unrestricted` (drop `"vz"` from the `["firecracker", "libkrun", "vz"]` array → `["firecracker", "libkrun"]`), delete the `egress_enforcement_label("vz", &p)` assertion, and delete the `resolve_effective_hypervisor("vz")` assertions (lines ~404-406).

- [x] **Step 3: Run tests**

Run: `cargo nextest run -p mvm-cli -- resolve`
Expected: PASS.

- [x] **Step 4: Commit**

```bash
git add crates/mvm-cli/src/commands/shared/resolve.rs
git commit -m "test(resolve): drop Vz-specific enforcement/tier assertions (Plan 226 R1P1 WS-A)"
```

---

### Task 7: Migrate the Vz-only CI + claim witnesses (WS-F)

Two Vz-named witnesses must be retired without breaking `xtask check-claim-catalog`: the `mvm-vz-supervisor` fuzz step in `security.yml`, and the `fn:vz_rootfs_disk_is_read_only` witness in `specs/claims/catalog.md` claim 1. The libkrun/passt witnesses stay.

**Files:**
- Modify: `.github/workflows/security.yml:355-365` (remove the Vz fuzz step)
- Modify: `specs/claims/catalog.md:30` (claim 1 witness list)
- Delete: `crates/mvm-build/fuzz/` Vz `fuzz_supervisor_config` target + corpus if it lived under the mvm-build fuzz dir (the libkrun one under `crates/deps/libkrun-sys/fuzz` stays)

- [x] **Step 1: Remove the Vz fuzz step**

Delete the `- name: Fuzz Vz SupervisorConfig (host-side)` step (security.yml:355-365) and, if present, its `fuzz_supervisor_config` target under `crates/mvm-build/fuzz/` (`git rm` the target + `Cargo.toml` entry). Leave the libkrun sibling step (lines 330-341) untouched.

- [x] **Step 2: Retire the `fn:vz_rootfs_disk_is_read_only` witness**

The Vz test that backed it is gone. In `specs/claims/catalog.md` claim 1 (line 30), remove `fn:vz_rootfs_disk_is_read_only` from the comma-separated witness list. Confirm the remaining witnesses (`fn:libkrun_refuses_read_only_virtiofs_share`, the seccomp/setpriv ones, the share allow-list ones) still cover claim 1's "no host-fs access beyond explicit shares" property — they do (libkrun + backend-agnostic share enforcement).

- [x] **Step 3: Run the claim-catalog gate**

Run: `cargo run -p xtask -- check-claim-catalog`
Expected: PASS — no named witness points at a deleted symbol.

- [x] **Step 4: Commit**

```bash
git add .github/workflows/security.yml specs/claims/catalog.md
git commit -m "ci(claims): retire Vz-only fuzz + rootfs witnesses (Plan 226 R1P1 WS-F)"
```

---

### Task 8: Ratify ADR-098 and update docs (WS-G + WS-H)

Move ADR-098 (HVF as the macOS backend) from Proposed to Accepted, scoping its Vz-sunset criteria to macOS and recording them met for R1 (warm-restore explicitly deferred to WS-E). Strip Vz from the contributor-facing docs and `CLAUDE.md`, and verify-and-close #1403.

**Files:**
- Modify: `specs/adrs/098-*.md` (status + sunset-criteria section)
- Modify: `CLAUDE.md` (Builder backend selection + macOS deps sections — drop `--builder vz` / Vz auto-default language)
- Modify: `public/src/content/docs/**` any Vz references on the runtime path
- Modify: `specs/REFACTOR-STATUS.md` (tick Plan 226 R1P1 workstreams)

- [x] **Step 1: Ratify ADR-098**

Change ADR-098's `Status: Proposed` → `Status: Accepted (2026-…)`. In its "Vz sunset criteria" section, note: criteria scoped to macOS; representative-workload boot on HVF proven; warm-restore/save-restore criterion tracked separately in Plan 226 WS-E; Linux convergence tracked in Release 2 (Plan 226 R2).

- [x] **Step 2: Update CLAUDE.md + docs**

In `CLAUDE.md`, remove statements that imply Vz is a selectable/auto backend (e.g. "Vz (Apple Virtualization.framework) is the macOS 26+ Apple Silicon backend", the `--builder vz` opt-in line, the `mvm-persistent-builder-vz-*` state-dir note). Replace with "Vz has been removed (Plan 226); HVF is the sole macOS backend." Grep docs: `rg -l -i "\bvz\b|Virtualization.framework|apple-container" public/src/content/docs` and prune runtime-path mentions.

- [x] **Step 3: Verify + close #1403**

Run: `gh issue view 1403` and confirm the "in-house builder not CLI-selectable" bug is fixed on `main` (it is — `--builder inhouse` + auto-detect). Close it: `gh issue close 1403 --comment "Fixed on main: in-house builder is --builder inhouse selectable and macOS-26 auto-detects it; the Vz-deletion residue is completed by Plan 226 R1P1."`

- [x] **Step 4: Update the rollup**

In `specs/REFACTOR-STATUS.md`, tick the Plan 226 R1P1 workstreams as landed and bump the "Last updated" date.

- [x] **Step 5: Gate + commit**

Run: `just ci`
Expected: green (doc/ADR changes don't break tests, but the doc-link gate runs).

```bash
git add specs/adrs CLAUDE.md public/src/content/docs specs/REFACTOR-STATUS.md
git commit -m "docs(adr-098): ratify HVF macOS backend; strip Vz from docs (Plan 226 R1P1 WS-G/H)"
```

---

### Task 9: Final workspace verification + changelog + version bump (WS-H)

**Files:**
- Modify: `CHANGELOG.md`, workspace `Cargo.toml` version, Homebrew formula (if versioned in-repo)

- [x] **Step 1: Full gate on both targets**

Run: `just ci && just check-linux`
Expected: all green.

- [x] **Step 2: Confirm zero Vz residue**

Run: `rg -n -i "VzBackend|mvm-vz-supervisor|vz_objc|vz_builder|host_gvproxy|BackendKind::Vz|DevBackend::Vz" crates/ src/`
Expected: no matches (comments/docs referencing the *removal* are fine; live code/types are not).

- [x] **Step 3: Changelog + version**

Add a `v0.17.0` section to `CHANGELOG.md` summarizing "Removed the Vz (Apple Virtualization.framework) backend; HVF is the sole macOS backend; `machine checkpoint/fork` is temporarily unsupported on macOS pending HVF save/restore (Plan 226 WS-E)." Bump the workspace version to `0.17.0`.

- [x] **Step 4: Commit**

```bash
git add CHANGELOG.md Cargo.toml
git commit -m "release: v0.17.0 — Vz backend removed (Plan 226 R1P1)"
```

---

## Self-Review

- **Spec coverage (against Plan 226 §4 workstreams):** WS-D → Task 1; WS-B → Task 2; WS-C → Task 3; WS-A → Tasks 4-6; WS-F → Task 7; WS-G → Task 8; WS-H → Tasks 8-9. **WS-N (gvproxy delete) and WS-E (HVF SaveRestore) are intentionally NOT in this plan** — they are separate follow-on plans (226-R1P2, 226-R1E); this plan keeps libkrun's gvproxy path intact and leaves `machine checkpoint/fork` descoped with a tracked error.
- **Placeholder scan:** the two "read/decide first" steps (Task 2 Step 1, Task 6 Step 1) resolve a concrete unknown with a named deliverable, not deferred implementation. No TBD/TODO.
- **Type consistency:** `ensure_save_restore_supported(action)` was already backend-agnostic on `main` (kept as-is); `capability_candidates() -> [AnyBackend; 3]` after dropping Vz. **Adapted from the plan:** there is no `DevBackend::InHouse` on `main` — the macOS-26 dev VM falls back to `DevBackend::Libkrun` (see Deferred follow-ups), and the builder choice enum uses the existing `BuilderBackendChoice::Hvf` (renamed from `InHouse`).

## Deferred follow-ups

Landed as part of executing this plan; tracked here per repo convention:

- **Dev-shell VM on macOS-26 temporarily falls back to libkrun.** The plan assumed a
  `DevBackend::InHouse` dev-VM boot existed; it does not on `main` (the HVF dev-VM
  boot rides the unmerged virtio-fs `/work`-share stack, Plan 222). So `mvmctl dev up`
  on macOS 26+ Apple Silicon now selects the **libkrun** dev VM (the documented
  fallback), and the macOS-26 build `ShellEnvironment` (`create_linux_env`) routes
  through the libkrun dev VM's per-port vsock. Flip the dev default to the in-house
  HVF VMM once the HVF dev-VM boot (virtio-fs `/work` share) lands on `main` — a
  one-line change in `select_dev_backend`.
- **`mvm machine checkpoint/fork` and `restore` are tracked-unsupported on macOS.**
  The Vz save/restore path was deleted; the backend-agnostic restore seam
  (`VmFullRestore` / `restore_checkpoint`) is kept and mock-tested, but no macOS
  backend implements `SnapshotCapability::SaveRestore` yet. Returns a clear tracked
  error until Plan 226 WS-E (HVF SaveRestore) lands. Firecracker `vm_full`
  capture/fork on Linux is retained.
- **Inert `mvm-bridge` `VzIngest` endpoint + broader doc Vz mentions.** The
  `BridgeEndpointKind::VzIngest` bridge variant is now dead config (no Vz supervisor
  emits its NDJSON) but references no deleted Rust symbol; and several
  `public/src/content/docs/**` pages still mention Vz as an opt-in backend. Both are
  a docs/dead-config cleanup follow-up; neither is CI-gated or affects runtime.

## Follow-on plans (write after this lands)

- **226-R1P2 — macOS libkrun → vsock egress + delete gvproxy (WS-N).** Investigation-led: wire the inert `MVM_VSOCK_EGRESS` path into `libkrun.rs` gateway selection; resolve the macOS *builder* egress path once gvproxy is gone; then delete `crates/deps/libkrun-sys/src/gvproxy.rs` and its libkrun call sites. Gate: `check-vsock-only-egress` extended to the macOS libkrun path.
- **226-R1E — HVF SaveRestore (WS-E).** Implement `SnapshotCapability::SaveRestore` on the in-house VMM (guest-memory + device-state capture/restore) so `machine checkpoint/fork` returns to macOS. On landing, Task 1's gate passes on HVF unchanged.
- **226-R2 — Linux clean-replacement.** Firecracker→vsock egress + delete passt, validated on the Hetzner KVM box; written after a fresh post-R1 code re-evaluation.
