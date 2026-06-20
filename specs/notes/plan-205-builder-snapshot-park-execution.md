# Plan 205 — Builder snapshot-park (S2.1 unblock) — Execution Plan

**Issue:** #1119. **Unblocks:** builder-residency Step 2 "instant parked builder".

## Feasibility (confirmed by exploration)

The persistent Vz **builder** VM is spawned by the *same* `mvm-vz-supervisor` binary with the *same* `mvm_build::vz::SupervisorConfig` as workloads. The supervisor's control socket + `SAVE`/`RESTORE` handling is fully generic (`mvm-vm-host/src/vz_objc.rs`: `start_control_socket` @987 binds iff `control_socket_path` is `Some`; `dispatch_control` @1336 serves `SAVE <path>` by PAUSE→`saveMachineStateToURL`→resume; `StartupMode::Restore` boots from a snapshot). The builder simply sets `control_socket_path: None` (`vz_builder.rs:1365`). So the unblock is: **enable the socket + reuse the SAVE/RESTORE path**, entirely within `mvm-build` (no `mvm-backend` dep — that crate depends on `mvm-build`, not vice-versa).

**Correctness guard (the one real risk):** the builder holds a read-write `/nix-store` ext4 (cross-process `flock` held by the supervisor process) and an in-guest `builderd` daemon. `SAVE` pauses the VM, so it is safe **only when the builder is idle** (no in-flight dispatch). Slice 2 enforces "park only when idle".

## Slices

- **Slice 1 (this plan, mergeable):** make the persistent vz builder snapshot-capable — enable the control socket + persist the `SupervisorConfig`. Additive; no build-behavior change.
- **Slice 2 (live, follow-on):** the park/resume primitive (`mvm-build` control-socket client → `SAVE`; RESTORE = read persisted config, flip `startup_mode` to `Restore`, re-spawn) + `SessionRecord.snapshot_path` + idle guard + dispatch-time resume + live macOS-26 validation.
- **Slice 3 (follow-on):** auto-park keeper — `SessionRecord.last_activity` + `decide_builder_residency_action` (already shipped, #1121) at the dispatch chokepoint.

---

# Slice 1 — Make the persistent Vz builder snapshot-capable

**Goal:** the persistent vz builder binds a control socket and persists its `SupervisorConfig` to disk, so a later slice can `SAVE` it and `RESTORE` it. No behavior change to builds today (an unused idle listener + one extra file written at start).

**Files:**
- Modify `crates/mvm-build/src/vz_builder.rs` — enable `control_socket_path`; persist the config at start.

## Global Constraints
- No placeholders. No spec/PR/ADR citations in code comments. `#[allow(clippy::too_many_arguments)]` banned.
- Only the **persistent** builder config (`build_vz_persistent_supervisor_config`, ~line 1244, the `control_socket_path: None` at **1365**). Do NOT touch the **one-shot** builder's `control_socket_path: None` at **347** (one-shot builders are torn down per build; they don't need it).
- `mvm-build` must not gain an `mvm-backend` dependency. Use only `mvm-build`-local code + `std`.

### Task 1: enable the control socket on the persistent vz builder

- [ ] **Step 1: failing test** — add a unit test to `vz_builder.rs`'s `#[cfg(test)]` module (beside `build_vz_persistent_supervisor_config_assembles_expected_shape` ~2172) asserting the persistent config now carries a control socket:

```rust
    #[test]
    fn persistent_config_enables_control_socket_for_snapshot_park() {
        let cfg = build_vz_persistent_supervisor_config(/* mirror the existing test's params */)
            .expect("config");
        let sock = cfg.control_socket_path.expect("control socket enabled");
        assert!(sock.ends_with("control.sock"), "got {sock:?}");
        assert!(sock.starts_with(&cfg.vm_state_dir), "socket must live under the VM state dir");
    }
```
(Copy the param construction verbatim from the adjacent `_assembles_expected_shape` test.)

Run: `cargo test -p mvm-build persistent_config_enables_control_socket_for_snapshot_park`
Expected: FAIL — `control_socket_path` is `None`.

- [ ] **Step 2: implement** — at `vz_builder.rs:1365`, replace `control_socket_path: None,` with the per-VM control socket under the state dir (same `<state_dir>/control.sock` shape the workload supervisor uses). Use the `state_dir` already in scope in `build_vz_persistent_supervisor_config` (it's the value assigned to `vm_state_dir`). If a `control.sock` path helper doesn't already exist in `mvm-build`, inline `state_dir.join("control.sock")` (matching `mvm_backend::vz_control::control_socket_path`'s shape). Add a one-line comment that the socket enables idle snapshot-park (no spec refs).

Run: `cargo test -p mvm-build persistent_config_enables_control_socket_for_snapshot_park`
Expected: PASS.

- [ ] **Step 3:** `cargo fmt --all`; `cargo clippy -p mvm-build --all-targets -- -D warnings`; `cargo nextest run -p mvm-build -E 'test(build_vz_persistent)'` (the existing config tests stay green). Commit: `feat(plan-205): enable control socket on the persistent vz builder (snapshot-park S2.1 slice 1)`.

### Task 2: persist the builder's SupervisorConfig to disk

The workload persists its config to `<state_dir>/supervisor-config.json` (`mvm-backend/src/vz.rs:145` `supervisor_config_path` + `:309` `persist_supervisor_config`) so `snapshot_restore` can read it back and flip `startup_mode`. The persistent vz builder currently only pipes the config to the supervisor's stdin (`spawn_vz_supervisor_in_background`, ~1404) and never writes it. RESTORE needs it on disk.

- [ ] **Step 1: failing test** — assert the start path writes the config file. Find the persistent-builder start function (the one that calls `spawn_vz_supervisor_in_background` after `build_vz_persistent_supervisor_config`, ~line 1167). Add a test (or extend an existing start test) that after building+persisting, `<state_dir>/supervisor-config.json` exists and round-trips to a `vz::SupervisorConfig` with `control_socket_path: Some(_)`. If the start path is too live to unit-test directly, instead unit-test a small extracted helper `persist_builder_supervisor_config(state_dir, &cfg) -> Result<PathBuf>` that does the write, and assert the round-trip.

Run it → FAIL (helper/behavior absent).

- [ ] **Step 2: implement** — add a `mvm-build`-local helper:
```rust
const BUILDER_SUPERVISOR_CONFIG_FILE: &str = "supervisor-config.json";

/// Persist the builder's SupervisorConfig next to its VM state so a later
/// snapshot-restore can reload it and flip startup_mode to Restore.
fn persist_builder_supervisor_config(state_dir: &Path, cfg: &crate::vz::SupervisorConfig) -> Result<PathBuf, BuilderVmError> {
    let path = state_dir.join(BUILDER_SUPERVISOR_CONFIG_FILE);
    let json = serde_json::to_vec_pretty(cfg).map_err(/* existing BuilderVmError serde arm */)?;
    std::fs::write(&path, &json).map_err(/* existing BuilderVmError io arm */)?;
    Ok(path)
}
```
Call it in the persistent-builder start path right after `build_vz_persistent_supervisor_config(...)` returns and before/around `spawn_vz_supervisor_in_background`. Match the existing `BuilderVmError` variants for serde/io (grep the enum).

Run the test → PASS.

- [ ] **Step 3:** fmt; clippy `-p mvm-build`; `cargo nextest run -p mvm-build -E 'test(persist_builder) or test(build_vz_persistent)'`. Commit: `feat(plan-205): persist the persistent vz builder SupervisorConfig for snapshot-restore (S2.1 slice 1)`.

## Slice-1 acceptance
- The persistent vz builder config carries `control_socket_path: Some(<state_dir>/control.sock)`.
- Starting it writes `<state_dir>/supervisor-config.json` (round-trips to a `vz::SupervisorConfig`).
- No change to one-shot builders; existing `mvm-build` tests green.
- Live (manual, not gated): a started persistent vz builder now has a bound `control.sock` and a `supervisor-config.json` on disk — the two prerequisites Slice 2's SAVE/RESTORE needs.

## Slice 2 outline (next plan) — the park/resume primitive
- `mvm-build` control-socket client (`UnixStream` → `SAVE <abs>\n` → read `OK`/`ERR`), mirroring `mvm_backend::vz_control::send_command` (~vz_control.rs:39) but local to `mvm-build`.
- `builder_snapshot_save(state_dir, snapshot_path)`: refuse unless the builder is idle (no in-flight dispatch — gate on the dispatch lock / a quiesce probe), then send `SAVE`. Writes `<snapshot>` + `<snapshot>.machine-id`.
- `builder_snapshot_restore(state_dir, snapshot_path)`: read the persisted `supervisor-config.json`, set `startup_mode = StartupMode::Restore { snapshot_path, machine_id_path }`, re-spawn a fresh gvproxy + the supervisor (reuse `spawn_vz_supervisor_in_background`).
- `SessionRecord.snapshot_path: Option<PathBuf>` (+ `#[serde(default)]`); set on park, cleared on resume.
- Dispatch chokepoint (`pipeline/dev_build.rs:595`): if the active session has a `snapshot_path`, RESTORE instead of cold-boot.
- A `mvmctl persistent-builder park` verb (explicit) for the first live proof; the keeper (Slice 3) calls the same primitive on idle.
- **Live macOS-26 validation:** start persistent builder → `park` (SAVE, idle) → `supervisor-config.json` + snapshot + `.machine-id` on disk, builder stopped → next build RESTOREs (no cold boot) → build succeeds; `/nix-store` intact.
