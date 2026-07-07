# machine reconfigure (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Lift the persistent-machine engine out of `mvm-cli` into a shared `mvm::machine::persist` submodule so both the CLI and `mvm-client-local::LocalBackend` drive one implementation, then wire `LocalBackend::reconfigure_machine` to it for real in-process reconfigure (cpus/memory), replacing the Phase-1 unsupported error.

**Architecture:** The on-disk `MachineSpec` (`~/.mvm/machines/<name>/machine.json`) + its accessors, config diff/reconcile, the reconfigure patch logic, and `validate_machine_memory` move to `crates/mvm/src/machine/persist.rs`. `mvm-cli` re-imports them via `use` (call sites unchanged) and keeps its orchestration (`start_machine`, `patch_from_args`, `machine_is_running`, `stop_running_machine`). `mvm-client-local` gains a `mvm` dependency (acyclic — `mvm` does not depend on `mvm-client-local`) and implements `reconfigure_machine` in-process.

**Tech Stack:** Rust, serde/serde_json, async_trait, tokio (tests), the existing `mvm-core::config`/`naming`/`util` helpers.

## Global Constraints

- Gates (all must pass): `cargo fmt --all -- --check`; `cargo clippy --workspace -- -D warnings`; `cargo nextest run --workspace`; `cargo test --workspace --doc`. Gateway tests need `cargo test -p mvm-client --features remote`.
- `#[allow(clippy::too_many_arguments)]` is banned.
- All `~/.mvm` paths go through `mvm-core::config` helpers.
- No `schema_version` bump; the lifted `MachineSpec` keeps `MACHINE_SPEC_SCHEMA_VERSION = 1` and its `#[serde(deny_unknown_fields)]` + field-level `#[serde(default)]`.
- **Security (claim 10):** `LocalBackend`'s in-process boot (`admit_and_boot_local`) does NOT enforce network policy. Therefore `LocalBackend::reconfigure_machine` MUST refuse `net`/`allow_host` changes with a clear error — never persist-and-relaunch a net change it cannot enforce.
- **Behavior preservation:** the lift is a pure relocation — the CLI `machine reconfigure`/`create`/`start`/`stop`/`run`/`ls`/`rm` behavior and all their tests must be byte-for-byte unchanged. This is a refactor, not a behavior change.
- **Name collision:** `mvm::machine` already has a builder `MachineSpec`. The lifted on-disk type lives in the `persist` submodule; do NOT shadow or rename the builder type. `mvm-cli` imports `mvm::machine::persist::MachineSpec`.
- **Work in the worktree** at `/Users/auser/work/tinylabs/mvmco/mvm/.claude/worktrees/machine-reconfigure-phase2/`. Absolute paths omitting that prefix hit a different checkout.

---

## File Structure

- `crates/mvm/src/machine/persist.rs` (create) — the lifted engine: on-disk `MachineSpec`, `MACHINE_SPEC_SCHEMA_VERSION`, `load_machine_spec`/`load_machine_spec_from_path`/`save_machine_spec`/`overwrite_machine_spec`/`list_machine_specs`, `machine_config_matches`/`machine_config_diff`/`SpecReconcile`/`reconcile_machine_spec`, `ReconfigurePatch`/`apply_patch`, `validate_machine_memory`, plus the moved unit tests.
- `crates/mvm/src/machine/mod.rs` (modify) — `pub mod persist;` + re-export.
- `crates/mvm/src/lib.rs` (modify) — re-export `machine::persist` items if the facade wants them (optional).
- `crates/mvm-cli/src/commands/machine/mod.rs` (modify) — delete the moved definitions; `use mvm::machine::persist::{...}`; adapt `machine_is_running`/`stop_running_machine` to call the CLI-resolved hypervisor; keep `patch_from_args`/`start_machine`/`run_reconfigure`.
- `crates/mvm-client-local/Cargo.toml` (modify) — add `mvm = { workspace = true }`.
- `crates/mvm-client-local/src/lib.rs` (modify) — implement `reconfigure_machine` via the lifted engine.
- `specs/notes/2026-07-05-machine-reconfigure-mvmd-endpoint.md` or a new Plan-226 note (modify/create) — record the LocalBackend network-policy parity follow-up.

---

## Task 1: Create `mvm::machine::persist` with the spec + accessors

**Files:**
- Create: `crates/mvm/src/machine/persist.rs`
- Modify: `crates/mvm/src/machine/mod.rs`
- Test: `crates/mvm/src/machine/persist.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `pub struct MachineSpec { … }` (identical fields to the mvm-cli private one), `pub const MACHINE_SPEC_SCHEMA_VERSION: u32 = 1`, and `pub fn load_machine_spec(&str) -> Result<MachineSpec>`, `load_machine_spec_from_path(&Path)`, `save_machine_spec(&MachineSpec, bool)`, `overwrite_machine_spec(&MachineSpec)`, `list_machine_specs() -> Result<Vec<MachineSpec>>`. Uses `mvm_core::config::{machine_spec_path, machine_state_root}`, `mvm_core::util::atomic_io::atomic_write`, `mvm_core::naming::validate_id`. Error type: `anyhow::Result` (match the crate's convention; if `mvm` uses a different Result alias in `machine/mod.rs`, follow it).

- [ ] **Step 1: Copy the source items verbatim from mvm-cli into the new module**

Open `crates/mvm-cli/src/commands/machine/mod.rs` and copy, unchanged except for `pub` visibility and fully-qualified `mvm_core::…` paths: `MACHINE_SPEC_SCHEMA_VERSION` (line ~50), `struct MachineSpec` (line ~643, keep all serde attrs), `validate_machine_name`→ inline `mvm_core::naming::validate_id`, `save_machine_spec`/`overwrite_machine_spec`/`load_machine_spec`/`load_machine_spec_from_path`/`list_machine_specs` (lines ~1684-1750). Add `crates/mvm/src/machine/persist.rs` starting with a module doc comment explaining this is the on-disk persistent spec (distinct from the builder `MachineSpec` in `mod.rs`).

- [ ] **Step 2: Wire the module**

In `crates/mvm/src/machine/mod.rs` add at the top: `pub mod persist;`. Build: `cargo build -p mvm`.
Expected: compiles (resolve any `use` paths — `mvm_core::config`, `mvm_core::util::atomic_io::atomic_write`, `mvm_core::naming::validate_id`; add `use anyhow::{Context, Result};` or the crate's Result).

- [ ] **Step 3: Move the accessor unit tests**

Move the mvm-cli tests that exercise ONLY these items (spec serde round-trip, load/save/overwrite round-trip, missing-spec error) into `persist.rs`'s test module, adapting paths. Use `tempfile` + `MVM_DATA_DIR` isolation exactly as the originals do (check `crates/mvm/Cargo.toml` has `tempfile` in dev-deps; add if missing).

- [ ] **Step 4: Run the mvm tests**

Run: `cargo test -p mvm machine::persist`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm/src/machine/persist.rs crates/mvm/src/machine/mod.rs crates/mvm/Cargo.toml
git commit -m "feat(mvm): lift on-disk MachineSpec + accessors into machine::persist"
```

---

## Task 2: Move diff/reconcile + patch + memory validation into `persist`

**Files:**
- Modify: `crates/mvm/src/machine/persist.rs`
- Test: same file

**Interfaces:**
- Consumes: `MachineSpec` (Task 1).
- Produces: `pub fn machine_config_matches(&MachineSpec,&MachineSpec)->bool`, `pub fn machine_config_diff(&MachineSpec,&MachineSpec)->String`, `pub enum SpecReconcile { Create, Reuse, Recreate { changed: String } }`, `pub fn reconcile_machine_spec(Option<&MachineSpec>,&MachineSpec,bool)->Result<SpecReconcile>`, `pub struct ReconfigurePatch { pub net: Option<bool>, pub allow_host: Option<Vec<String>>, pub cpus: Option<u32>, pub memory: Option<String>, pub mem_initial: Option<String> }`, `pub fn apply_patch(MachineSpec,&ReconfigurePatch)->MachineSpec`, `pub fn validate_machine_memory(&str, Option<&str>)->Result<(u32, Option<u32>)>`.

- [ ] **Step 1: Move the items verbatim**

Copy from mvm-cli (making them `pub`): `machine_config_matches` (~455), `machine_config_diff` (~472), `SpecReconcile` (~422), `reconcile_machine_spec` (~517), `ReconfigurePatch` (~2925), `apply_patch` (~2966), `validate_machine_memory` (~1231/1312 — it uses `mvm_core::util::parse_human_size`). Keep logic identical.

- [ ] **Step 2: Move their unit tests**

Move the mvm-cli tests `apply_patch_overrides_only_set_fields_and_preserves_rest`, `apply_patch_no_flags_is_noop`, `patch_*` (the ones that test `apply_patch` directly — NOT `patch_from_args`, which stays CLI-side), and any `machine_config_diff`/`reconcile` tests, into `persist.rs`. Adapt the `reconfigure_spec_fixture` helper into this module.

- [ ] **Step 3: Run**

Run: `cargo test -p mvm machine::persist`
Expected: PASS (all moved tests green).

- [ ] **Step 4: Commit**

```bash
git add crates/mvm/src/machine/persist.rs
git commit -m "feat(mvm): move config diff/reconcile + reconfigure patch + memory validation into machine::persist"
```

---

## Task 3: mvm-cli consumes the lifted engine (delete private copies)

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs`

**Interfaces:**
- Consumes: everything from `mvm::machine::persist` (Tasks 1-2).
- Keeps CLI-side: `patch_from_args` (clap → `mvm::machine::persist::ReconfigurePatch`), `start_machine`, `run_reconfigure`, `machine_is_running`, `stop_running_machine`.

- [ ] **Step 1: Delete the moved definitions and import from mvm**

In `crates/mvm-cli/src/commands/machine/mod.rs`, delete the now-duplicated definitions (`MachineSpec`, `MACHINE_SPEC_SCHEMA_VERSION`, the five accessors, `machine_config_matches`/`machine_config_diff`/`SpecReconcile`/`reconcile_machine_spec`, `ReconfigurePatch`, `apply_patch`, `validate_machine_memory`) and add near the other imports:

```rust
use mvm::machine::persist::{
    MachineSpec, MACHINE_SPEC_SCHEMA_VERSION, SpecReconcile, ReconfigurePatch,
    load_machine_spec, load_machine_spec_from_path, save_machine_spec, overwrite_machine_spec,
    list_machine_specs, machine_config_matches, machine_config_diff, reconcile_machine_spec,
    apply_patch, validate_machine_memory,
};
```

Keep `validate_machine_name` local (it wraps `naming::validate_id` and is also used elsewhere) OR import if it moved. The call sites (`load_machine_spec(...)`, `MachineSpec { … }`, `apply_patch(...)`, etc.) stay unchanged because the names now resolve to the imports.

- [ ] **Step 2: Adapt `patch_from_args` to build the lifted `ReconfigurePatch`**

`patch_from_args` already constructs a `ReconfigurePatch { net, allow_host, cpus, memory, mem_initial }`. Since that struct now comes from `mvm::machine::persist`, only the type resolution changes — confirm field names match the lifted struct exactly (they should). Keep `validate_machine_memory` call.

- [ ] **Step 3: Confirm `machine_is_running`/`stop_running_machine` still compile**

These stay in mvm-cli (they use `resolve_effective_hypervisor` + `reap_proxy`, both CLI-only). No change needed — they don't move.

- [ ] **Step 4: Build + full mvm-cli test suite (behavior unchanged)**

Run: `MVM_SKIP_EMBED_BINARIES=1 cargo build -p mvm-cli` then `cargo nextest run -p mvm-cli`
Expected: compiles; ALL mvm-cli tests pass unchanged (the machine tests, ~1175, plus audit coverage). If a test moved to `mvm` in Tasks 1-2 now fails to find a symbol in mvm-cli, delete that duplicate test from mvm-cli (it lives in `persist.rs` now). Do NOT weaken any assertion.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "refactor(machine): mvm-cli consumes mvm::machine::persist (delete private copies)"
```

---

## Task 4: Wire `LocalBackend::reconfigure_machine` in-process

**Files:**
- Modify: `crates/mvm-client-local/Cargo.toml`
- Modify: `crates/mvm-client-local/src/lib.rs`
- Test: `crates/mvm-client-local/src/lib.rs`

**Interfaces:**
- Consumes: `mvm::machine::persist::{load_machine_spec, overwrite_machine_spec, apply_patch, ReconfigurePatch, machine_config_diff, validate_machine_memory}`; `mvm_client::dto::ReconfigureRequest`; the existing `self.backend` (`AnyBackend`) + `admit_and_boot_local`.
- Produces: a real `reconfigure_machine` replacing the Phase-1 unsupported error.

- [ ] **Step 1: Add the `mvm` dependency**

In `crates/mvm-client-local/Cargo.toml` add under `[dependencies]`: `mvm = { workspace = true }`. Run `cargo build -p mvm-client-local` to confirm it resolves with no cycle.
Expected: compiles.

- [ ] **Step 2: Write the failing test**

In `crates/mvm-client-local/src/lib.rs` tests, add (using `MVM_DATA_DIR` isolation + writing a persisted spec via `mvm::machine::persist::save_machine_spec`):

```rust
#[tokio::test]
async fn reconfigure_refuses_network_changes_on_local_backend() {
    let data = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("MVM_DATA_DIR", data.path()); }
    // persist a minimal spec named "web" via the engine (helper below)
    persist_test_spec("web");
    let be = LocalBackend::with_hypervisor("mock");
    let err = be.reconfigure_machine(
        &MachineId("web".into()),
        mvm_client::dto::ReconfigureRequest { net: Some(true), ..Default::default() },
    ).await.unwrap_err();
    assert!(format!("{err}").contains("network"), "must refuse net on local backend");
}

#[tokio::test]
async fn reconfigure_unknown_machine_is_error() {
    let data = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("MVM_DATA_DIR", data.path()); }
    let be = LocalBackend::with_hypervisor("mock");
    let err = be.reconfigure_machine(&MachineId("nope".into()),
        mvm_client::dto::ReconfigureRequest { cpus: Some(2), ..Default::default() })
        .await.unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("does not exist")
         || format!("{err}").to_lowercase().contains("not found"));
}
```

Add a `persist_test_spec(name)` test helper that constructs a `mvm::machine::persist::MachineSpec` (image-backed, cpus 2, memory "512M") and calls `save_machine_spec`.

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p mvm-client-local reconfigure`
Expected: FAIL (current impl returns the generic unsupported error, not the net-specific / not-found ones).

- [ ] **Step 4: Implement `reconfigure_machine`**

Replace the Phase-1 unsupported stub in `impl MvmClient for LocalBackend`:

```rust
async fn reconfigure_machine(
    &self,
    id: &MachineId,
    cfg: mvm_client::dto::ReconfigureRequest,
) -> Result<MachineState> {
    use mvm::machine::persist as mp;
    // Claim-10: this backend's in-process boot does not enforce network
    // policy, so a net/allow_host change would persist-but-not-enforce.
    // Refuse rather than silently fail open.
    if cfg.net.is_some() || cfg.allow_host.is_some() {
        return Err(MvmError::InvalidSpec { reason:
            "changing network policy (net/allow_host) via reconfigure is not \
             supported on the in-process local backend (its boot path does not \
             enforce egress policy); use the CLI verb or the gateway backend".into() });
    }
    let existing = mp::load_machine_spec(&id.0).map_err(backend_err)?;
    let patch = mp::ReconfigurePatch {
        net: None, allow_host: None,
        cpus: cfg.cpus,
        memory: cfg.memory_mib.map(|m| format!("{m}M")),
        mem_initial: None,
    };
    let desired = mp::apply_patch(existing.clone(), &patch);
    mp::validate_machine_memory(&desired.memory, desired.mem_initial.as_deref())
        .map_err(backend_err)?;
    let changed = mp::machine_config_diff(&existing, &desired);
    if changed.is_empty() {
        return Ok(MachineState { id: id.clone(), name: existing.name, status: MachineStatus::Stopped });
    }
    mp::overwrite_machine_spec(&desired).map_err(backend_err)?;
    // Relaunch if running: stop then in-process admitted boot with the new resources.
    let vid = VmId(id.0.clone());
    let was_running = matches!(self.backend.status(&vid), Ok(VmStatus::Running));
    if was_running {
        self.backend.stop(&vid).map_err(backend_err)?;
        // Reuse run_machine's in-process admitted boot with the patched resources.
        let spec = MachineSpec { // the facade DTO
            name: desired.name.clone(),
            image: desired.image.clone().unwrap_or_default(),
            cpus: desired.cpus,
            memory_mib: mvm_core::util::parse_human_size(&desired.memory).map_err(backend_err)?,
            env: vec![],
        };
        return self.run_machine(spec).await;
    }
    Ok(MachineState { id: id.clone(), name: desired.name, status: MachineStatus::Stopped })
}
```

Adjust imports (`VmId`, `VmStatus` already imported; add `mvm_core::util::parse_human_size` if needed). If `desired.image` is `None` (manifest-backed), refuse with a clear error (LocalBackend's run path is image-backed).

- [ ] **Step 5: Run tests**

Run: `cargo test -p mvm-client-local`
Expected: PASS (net-refusal + unknown-machine tests green; existing tests unaffected).

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-client-local/Cargo.toml crates/mvm-client-local/src/lib.rs
git commit -m "feat(mvm-client-local): real in-process reconfigure (cpus/memory; refuses net per claim-10)"
```

---

## Task 5: Docs, follow-up note, status rollup

**Files:**
- Modify: `specs/notes/2026-07-05-machine-reconfigure-design.md` (mark Phase 2 landed; note the LocalBackend net-parity follow-up as Plan 226)
- Modify: `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`
- Modify (if present): `public/src/content/docs/sdk/operations-cookbook.mdx` — update the reconfigure row's SDK columns if the local facade now supports it (cpus/memory only).

- [ ] **Step 1: Design note + Plan 226 follow-up**

In the design note, change Phase 2 status to landed and add a short "Plan 226 (deferred): give `LocalBackend`'s in-process boot network-policy + volume enforcement so reconfigure can change `net`/`allow_host` locally (currently refused)."

- [ ] **Step 2: Status rollup**

Add a Plan 225 entry to `specs/REFACTOR-STATUS.md` (Phase 2 complete: engine lifted to `mvm::machine::persist`, LocalBackend wired for cpus/memory) with the date; adjust `specs/SPRINT.md`.

- [ ] **Step 3: Final gate + commit**

```bash
cargo fmt --all -- --check && cargo test --workspace --doc
git add specs/ public/
git commit -m "docs(machine): Phase 2 landed — engine lift + local reconfigure; Plan 226 net-parity follow-up"
```

---

## Self-Review notes

- **Spec coverage:** engine lift (Tasks 1-2); mvm-cli consumes it with unchanged behavior (Task 3); LocalBackend real reconfigure with claim-10 net-refusal (Task 4); docs/follow-up (Task 5).
- **Risk:** Task 3 is the highest-risk (touches the pervasively-used machine engine). Mitigation: the lift is name-preserving (`use` imports keep call sites identical), and the full mvm-cli suite (~1175 machine tests + audit coverage) gates it. Any behavior drift fails those tests.
- **Type consistency:** the lifted `ReconfigurePatch` fields (`net/allow_host/cpus/memory/mem_initial`) match `patch_from_args` (Task 3) and the LocalBackend patch construction (Task 4). `validate_machine_memory` signature `(&str, Option<&str>) -> Result<(u32, Option<u32>)>` is identical across callers.
- **Claim 10:** LocalBackend refuses net/allow_host (Task 4 test asserts it) — no silent fail-open.
