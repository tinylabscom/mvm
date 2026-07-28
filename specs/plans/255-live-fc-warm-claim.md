# Live Firecracker Warm-Claim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Firecracker warm pool functional end to end and **fast** — a spawn boots a clean factory parent and captures its full `{rootfs, memory, vmstate}` triple, and a claim forks a fresh, admitted, audited child by **memory restore** (skipping kernel boot, init, and agent startup) — validated live on a KVM host with the first committed warm-restore latency number.

**Architecture:** Three mature pieces already exist and must be reused, not reimplemented: `capture_vm_full` (pause → save memory → clone rootfs in the pause window → resume, writing `device-anchors.json` so a child remaps the parent's baked-in absolute paths), `FcForkRestorer::restore_fork` (renames `memory.bin` → `mem.bin`, remaps device anchors, calls `warm_restore_instance_from_path`), and `guarded_load_resume` (runs the no-NIC device-model guard *between* load and resume). The merged claim substrate already owns the guarded fork — reserve → verify content + lineage → bind plan → fresh identity → CoW materialize → fork. This slice fills the stubs at the two ends: the `FcDriver` spawn/fork overrides, a backend-agnostic capture in the runner, the `parent_checkpoint` on the persisted handle, and the CLI wiring. The capability flip comes last.

**Tech Stack:** Rust (14-crate workspace), Firecracker VMM over its HTTP-on-UDS API, vsock (no guest NIC), `cargo nextest`, cucumber-rs BDD, live validation on a Linux/KVM host.

## Correction to earlier scoping (read this first)

An earlier draft of this plan asserted Firecracker memory restore was hard-disabled and scoped the child as a cold boot. **That was wrong** — it was read from a stale checkout. Commit `5bfe4c426` landed the restore un-bail before this branch was created. The current, verified state:

- `warm_restore_instance_from_path` (`microvm/snapshot.rs:87`) is **live**: it validates the VM name, calls `guarded_load_resume`, and delivers the VMGenID reseed via `signal_post_restore`.
- `capture_vm_full` (`checkpoint/mod.rs:545`) and `fork_vm_full_fc` (`:406`) are live; `FcForkRestorer` (`firecracker.rs:436`) is the only `ForkVmFullRestorer` impl.
- Still deliberately refused, each needing its own signature/HMAC design: `restore_from_template_snapshot` and the bare `warm_restore_instance`. **Do not use or re-enable those two.**

So this slice delivers the fast path directly. What remains genuinely Plan 265's: page-cache priming, the pre-spawned VMM optimization, density, and the CI-gated SLO.

## Boundary with Plan 265 (do not duplicate)

Plan 265's own doc assigns ownership explicitly:

> **Plan 255** … owns the *substrate*: `SnapshotStore`, memory-snapshot file handling, **the paused-parent warm pool**, and fork identity hygiene. This plan depends on Plan 255 Phases 1–2 and does **not re-own them**.

One real collision to respect: Plan 265 **WS2** carries an unticked item — *"Pre-spawned / pooled Firecracker: wire the existing `standby_pool` … so a restore claims a pre-spawned VMM rather than spawning one. **Overlaps Plan 255 warm-pool work.**"* This slice does **not** implement the pre-spawned-VMM optimization; each claim starts a fresh Firecracker and loads the snapshot into it. Task 7 records the measured cost of that fresh spawn so Plan 265 WS2 has a real baseline to optimize against. Leave that item to 265; do not tick it.

Density note: this slice uses **snapshot-and-release** — the parent is captured to a checkpoint and then killed, so a pool slot costs disk, not RAM. The resident-paused density model is explicitly Plan 265's.

## Global Constraints

Every task's requirements implicitly include this section.

- **Reuse the existing restore machinery.** `capture_vm_full`, `FcForkRestorer::restore_fork`, and `guarded_load_resume` already work and are guarded. Call them. Do not write a second capture or restore path, and do not call the two still-refused entry points named above.
- **No guest NIC, ever.** vsock is the sole boundary. `VmmSpec` has no NIC field — keep it that way. The no-NIC guard runs inside `guarded_load_resume`; never bypass it or restore without it.
- **Never set `trusted_builder: true` on a workload-bearing VM.** It disables the claim-10 egress gate; it exists for the builder VM only.
- **No competitor proper nouns** anywhere — code, comments, tests, commit messages, PR text, branch names.
- **No spec references in code comments.** `Plan`, `ADR`, `#NNNN`, `W#`, `Phase N` are CI-gated by `xtask check-no-spec-refs`. Explain *why* in prose instead. (Files under `specs/` are exempt.)
- **`#[allow(clippy::...)]` is banned outright**, including `too_many_arguments`. Use a params struct (the repo already uses `CaptureVmFullParams`, `ForkParams`, `WarmParams`, `ClaimContext` for exactly this).
- **All `~/.mvm` paths go through `mvm-core::config`** helpers. If a needed path has no helper, **add one to `mvm-core::config`** rather than inlining it.
- **New struct fields get `#[serde(default)]`** — no schema-version bump, no migration shim (mirror `image_sha256` on `StandbyHandle`).
- **No placeholders, no stubs, no TODOs** in delivered code.
- **Gates (run the FULL workspace suite, never a filtered subset):**
  ```bash
  cargo fmt --all -- --check
  cargo nextest run --workspace
  cargo test --workspace --doc
  cargo clippy --workspace --all-targets -- -D warnings
  ```
- **No AI-tool attribution** and no `Co-Authored-By: Claude` trailer in any commit or PR.

## What the warm-pool adoption commit changed (this branch is rebased onto it)

Commit `1c847f458` ("complete vsock-first warm-pool adoption") landed after the
first draft of this plan. It does **not** implement any of this plan's five
stubs — `FcDriver` still has no `spawn_standby_parent` / `fork_standby_child`
override, `standby_pool` is still `false`, `warm_to_target` still calls
`spawn_standby`, and `claim_or_cold` still calls the fail-closed
`claim_standby`. But three of its changes bind this work:

- **`template_id: Option<String>` on both `StandbySpec` and `StandbyHandle`**,
  with a cross-template claim refusal and `StandbyCompat.template_id`. Every
  construction site must set it. In `spawn_standby_parent` it must be
  `spec.template_id.clone()` — hardcoding `None` compiles but silently defeats
  the cross-template refusal tests. Test fixtures may use `None`.
- **The fork restore path now guards and resumes.** `restore_fork` routes
  through `guarded_fork_load_resume` → `load_snapshot_for_fork` +
  `guard_and_resume`. `guard_and_resume` is the shared tail every load path
  funnels through, so the no-NIC guard cannot be bypassed by adding a new load.
  A forked child therefore comes back **resumed**, not paused.
- **The post-restore handshake is fail-closed on three flags** —
  `acknowledged`, `reseeded`, and `clock_resynced`
  (`mvm-agentd/src/vsock/api.rs:160-183`). A restored child is not usable until
  the guest answers all three.

## Key facts verified against the code (do not re-derive)

- `StandbyHandle` is defined in **`mvm-protocol`** (`src/protocol/vm_backend.rs:744`); `CheckpointId` is in **`mvm-core`** (`src/checkpoint.rs:12`). **`mvm-protocol` does not depend on `mvm-core`** and must not — it is the `no_std` foundation. The new handle field is therefore `Option<String>`, converted at the `mvm-runtime` boundary.
- `capture_vm_full` writes content blobs `rootfs.ext4`, `memory.bin`, optional `machine-id`, backend extras via `extra_content` (Firecracker's `vmstate.bin`), guest sidecars, and **`device-anchors.json`** (written unconditionally, `checkpoint/mod.rs:638-648`). It **pauses, captures, and resumes** the VM, resuming on every exit path.
- `FcForkRestorer::restore_fork` expects, in `child_dir`: `memory.bin` (renamed to `mem.bin`) and `device-anchors.json`. Both come from the parent's content dir.
- `materialize_child_from_parent` (`warm_snapshot.rs:37-56`) clones the **whole** content dir into `child_dir`, so a `vm_full` triple flows through the existing claim path unchanged.
- `FcVmFullControl::new(vm_name)` (`firecracker.rs:310`) needs only the VM name.
- `FcDriver::boot` calls `firecracker_guard.defuse()` (`fc.rs:489`), so **Firecracker survives dropping the `RunningVm` handle** — a booted parent stays up for the capture.
- `bind_plan_to_parent` compares the admitted plan's image digest against the parent's `rootfs.ext4` blob, which a `vm_full` checkpoint still carries — the claim-8 gate is unaffected.
- The VM name registry helper is `mvm_runtime::vm::name_registry::registry_path()` (`vm/name_registry.rs:322`).
- `FsSnapshotStore` has only `new(root)` (`mvm-fs/src/snapshot_store.rs:157`); there is **no `snapshots_dir()` in `mvm-core::config`** — Task 5 adds one.
- Live tests are gated two ways: cucumber `@live` (opt in with `MVM_BDD_LIVE=1`) plus `@firecracker` (needs `/dev/kvm` + the `firecracker` binary), and the `#[ignore]`d Rust tests `warm_restore_latency_live` / `warm_restore_refuses_nic_live` (env-gated on `MVM_LIVE_KERNEL` / `MVM_LIVE_ROOTFS`). Neither runs in CI. **No warm-restore latency number is committed anywhere** — only a qualitative "tens of milliseconds".

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `crates/mvm-protocol/src/protocol/vm_backend.rs` | `StandbyHandle.parent_checkpoint` field | 1 |
| `crates/mvm-runtime/src/standby_pool.rs` | round-trips the new field | 1 |
| `crates/mvm-runtime/src/driver/traits.rs` | `vm_full_control` trait method (fail-closed default) | 2 |
| `crates/mvm-runtime/src/driver/fc.rs` | `spawn_standby_parent` + `vm_full_control` | 2 |
| `crates/mvm-runtime/src/driver/fc.rs` | `fork_standby_child` → `FcForkRestorer` | 3 |
| `crates/mvm-runtime/src/workload_runner/runner.rs` | `SpawnContext` + `capture_vm_full` + release | 4 |
| `crates/mvm-runtime/src/backend.rs` | `spawn_standby_via_runner` routing seam | 4 |
| `crates/mvm-core/src/config.rs` | `snapshots_dir()` helper | 5 |
| `crates/mvm-cli/src/commands/pool.rs` | live context assembly + rootfs threading | 5 |
| `crates/mvm-runtime/src/driver/fc.rs` | capability flip + guard tests | 6 |
| `specs/notes/2026-07-28-plan-255-live-fc-warm-claim-validation.md` | live-run evidence + latency | 7 |

---

### Task 1: `parent_checkpoint` on the persisted standby handle

A claim must find the checkpoint its parent was captured as. `StandbySpec` has no checkpoint field and `StandbyHandle` has none, so the id has nowhere to live between spawn and claim.

**Files:**
- Modify: `crates/mvm-protocol/src/protocol/vm_backend.rs:744-757`
- Test: `crates/mvm-runtime/src/standby_pool.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `StandbyHandle.parent_checkpoint: Option<String>` — the checkpoint id as a plain string, because `mvm-protocol` cannot see `mvm-core`'s `CheckpointId`. Task 4 constructs it; Task 5 reads it.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)]` module in `crates/mvm-runtime/src/standby_pool.rs`:

```rust
#[test]
fn record_and_load_round_trip_parent_checkpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let pool = SupervisorStandbyPool::at(tmp.path());
    let mut h = sample_handle("sb-parent-ckpt");
    h.parent_checkpoint = Some("standby-sb-parent-ckpt".to_string());

    pool.record(&h).unwrap();
    let loaded = pool.load("sb-parent-ckpt").unwrap();

    assert_eq!(
        loaded.parent_checkpoint.as_deref(),
        Some("standby-sb-parent-ckpt"),
        "the captured parent checkpoint must survive the pool's on-disk round trip"
    );
}

/// A handle written before this field existed still loads, defaulting to
/// `None` — an uncaptured parent is simply not claimable.
#[test]
fn handle_without_parent_checkpoint_loads_as_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pool = SupervisorStandbyPool::at(tmp.path());
    let dir = tmp.path().join("sb-legacy");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("standby.json"),
        br#"{"id":"sb-legacy","control_socket":"/tmp/s.sock","pid":0,
             "kernel_sha256":"abc","vcpus":2,"mem_mib":512,"binding_nonce":"n",
             "spawned_unix_secs":1,"state":"idle"}"#,
    )
    .unwrap();

    let loaded = pool.load("sb-legacy").unwrap();

    assert_eq!(loaded.parent_checkpoint, None);
}
```

If no `sample_handle` helper exists in that module, write one building a `StandbyHandle` with every field populated and `parent_checkpoint: None`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-runtime standby_pool`
Expected: FAIL — `no field 'parent_checkpoint' on type 'StandbyHandle'`.

- [ ] **Step 3: Add the field**

In `crates/mvm-protocol/src/protocol/vm_backend.rs`, immediately after `image_sha256`:

```rust
    /// The content-addressed checkpoint this parent was captured as, set once
    /// a spawn has captured it. `None` means the parent was never captured, so
    /// it cannot be claimed: a claim verifies content and lineage against this
    /// checkpoint before cloning anything.
    ///
    /// Held as the raw id string rather than a `CheckpointId` because that type
    /// lives a layer up; the runtime converts at its boundary.
    #[serde(default)]
    pub parent_checkpoint: Option<String>,
```

- [ ] **Step 4: Fix every construction site**

Run: `cargo build --workspace --all-targets 2>&1 | grep -A3 'missing field'`

Known site: `crates/mvm-runtime/src/driver/mock.rs:163` → `parent_checkpoint: None`, plus test fixtures. Add the field explicitly at each site (do **not** use `..Default::default()`). Task 4 populates it for real.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-runtime standby_pool`
Expected: PASS.

- [ ] **Step 6: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(standby): carry the captured parent checkpoint on the standby handle"
```

---

### Task 2: Boot a clean parent and expose its capture control

`FcDriver` inherits the fail-closed `spawn_standby_parent` default, so no Firecracker pool can be populated. This task boots a real, clean parent and **leaves it running** — Task 4 captures its live memory, which requires a live VM.

**Two things the implementer must not miss:**

1. **Do not kill the parent here.** `capture_vm_full` pauses, saves memory, and resumes a *live* VM. `FcDriver::boot` calls `firecracker_guard.defuse()`, so Firecracker keeps running after the returned `RunningVm` is dropped — that is intended. Task 4 releases the parent after capture.
2. **A factory parent carries no workload, so it has no egress relay wired.** `trusted_builder` must stay `false`. If the guest's egress gate refuses to boot without a relay, wire the parent a minimal vsock egress port — do **not** flip `trusted_builder` to paper over it. Report which you needed.

**Files:**
- Modify: `crates/mvm-runtime/src/driver/traits.rs` (add `vm_full_control` with a fail-closed default)
- Modify: `crates/mvm-runtime/src/driver/fc.rs` (both overrides, inside `impl VmmDriver for FcDriver`)
- Modify: `crates/mvm-runtime/src/driver/mock.rs` (mock control so Task 4 is testable without KVM)
- Test: `crates/mvm-runtime/src/driver/fc.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `StandbyHandle.parent_checkpoint` (Task 1) — `None` here; Task 4 fills it.
- Produces:
  ```rust
  // on trait VmmDriver, defaulting to None so a backend without a capture
  // control simply cannot back a warm pool
  fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn crate::checkpoint::VmFullControl>> {
      let _ = vm_name;
      None
  }
  ```
  plus `FcDriver::spawn_standby_parent(&self, spec: &StandbySpec) -> std::result::Result<StandbyHandle, StandbyError>` returning a handle for a **running** parent (real pid, `state: StandbyState::Idle`), and `FcDriver::vm_full_control` returning `Some(Box::new(FcVmFullControl::new(vm_name)))`.

The exact types this task constructs, verbatim from `crates/mvm-runtime/src/driver/spec.rs`:

```rust
pub enum KernelImage { Path(PathBuf), Bundled }
pub struct BlockDev { pub source: PathBuf, pub read_only: bool, pub ephemeral: bool, pub slot: u8 }
pub struct ConsoleCapture { pub log_path: PathBuf }
pub struct VmmSpec {
    pub name: String, pub kernel: KernelImage, pub initramfs: Option<PathBuf>,
    pub cmdline: String, pub vcpus: u32, pub memory_mib: u32,
    pub mem_initial_mib: Option<u32>, pub blocks: Vec<BlockDev>,
    pub vsock: Vec<VsockPort>, pub console: ConsoleCapture, pub trusted_builder: bool,
}
```

- [ ] **Step 1: Write the failing tests**

A full boot needs KVM, so unit-test the fail-closed precondition and the control seam — both hold on every host:

```rust
/// A parent with no rootfs cannot be booted, so it is refused up front rather
/// than yielding a handle no claim could ever use.
#[test]
fn spawn_standby_parent_refuses_a_spec_without_an_image() {
    let spec = standby_spec_without_image();

    let err = FcDriver::new().spawn_standby_parent(&spec).unwrap_err();

    assert!(
        matches!(err, StandbyError::SpawnFailed(ref m) if m.contains("rootfs")),
        "expected a SpawnFailed naming the missing rootfs, got: {err:?}"
    );
}

/// Capturing a parent's memory needs a backend-specific control; Firecracker
/// has one, so it must offer it rather than falling through to the default.
#[test]
fn fc_offers_a_vm_full_capture_control() {
    assert!(FcDriver::new().vm_full_control("any-vm").is_some());
}
```

Write `standby_spec_without_image()` building a `StandbySpec` with `image_path: None` and every other field populated plausibly.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: FAIL — the inherited defaults return `StandbyError::Unsupported` and `None`.

- [ ] **Step 3: Add the trait method**

Add `vm_full_control` to `VmmDriver` in `driver/traits.rs` with the `None` default shown above, documenting *why* the default is `None` (a backend that cannot pause-and-save-memory cannot back a warm pool).

- [ ] **Step 4: Implement both overrides on `FcDriver`**

```rust
    fn spawn_standby_parent(
        &self,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        // A factory parent carries no plan, no volumes, no broker endpoint and
        // no guest NIC — nothing that could bind it to one workload. It exists
        // only to be captured and cloned.
        let image = spec.image_path.as_deref().ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "standby '{}' has no rootfs image to boot",
                spec.id
            ))
        })?;

        let parent = VmmSpec {
            name: spec.id.clone(),
            kernel: KernelImage::Path(PathBuf::from(&spec.kernel_path)),
            initramfs: None,
            cmdline: self.workload_base_bootargs(false, true),
            vcpus: u32::from(spec.vcpus),
            memory_mib: spec.mem_mib,
            mem_initial_mib: None,
            blocks: vec![BlockDev {
                source: PathBuf::from(image),
                // The parent's rootfs is the shared base image: never writable,
                // so one parent cannot alter what every child clones.
                read_only: true,
                ephemeral: false,
                slot: 0,
            }],
            vsock: Vec::new(),
            console: ConsoleCapture {
                log_path: PathBuf::from(&spec.vm_state_dir).join("console.log"),
            },
            trusted_builder: false,
        };

        // `boot` returns only once the guest agent answered over vsock, so the
        // memory captured next is of a fully-booted, ready guest — that is what
        // lets a restored child skip boot entirely.
        let vm = self
            .boot(&parent)
            .map_err(|e| StandbyError::SpawnFailed(format!("boot standby parent: {e}")))?;

        // Deliberately left running: the caller captures its live memory, and
        // Firecracker outlives this handle.
        let pid = read_fc_pid(&spec.vm_state_dir).unwrap_or(0);
        drop(vm);

        Ok(StandbyHandle {
            id: spec.id.clone(),
            // Propagate the template identity: a parent bound to one template
            // must never be claimable by a launch of another.
            template_id: spec.template_id.clone(),
            control_socket: spec.control_socket.clone(),
            pid,
            kernel_sha256: spec.kernel_sha256.clone(),
            vcpus: spec.vcpus,
            mem_mib: spec.mem_mib,
            binding_nonce: spec.binding_nonce.clone(),
            spawned_unix_secs: now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: spec.image_sha256.clone(),
            // The caller captures the parent and stamps this.
            parent_checkpoint: None,
        })
    }

    fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn crate::checkpoint::VmFullControl>> {
        Some(Box::new(crate::firecracker::FcVmFullControl::new(vm_name)))
    }
```

For `read_fc_pid`, reuse the existing pid-file helper in `fc.rs` (`fc_pid_path` plus the crate's existing pid read) rather than writing a new one; if no read helper exists, read the `fc.pid` file the boot path already writes. Reuse the same `now_unix_secs` import `mock.rs` uses.

- [ ] **Step 5: Give `MockDriver` a capture control**

Task 4's test needs a driver whose `vm_full_control` returns something without KVM. Add a `MockVmFullControl` implementing `VmFullControl` — `pause`/`resume` record the call, `save_memory` writes a small deterministic file, `rootfs_path` returns a path the test seeded, `device_anchors` returns an empty/default `DeviceAnchors`. Have `MockDriver::vm_full_control` return it.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-runtime driver`
Expected: PASS.

- [ ] **Step 7: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(fc): boot a clean standby parent and expose its capture control"
```

---

### Task 3: `FcDriver::fork_standby_child` — restore the child from the parent's memory

The runner has already verified the parent, minted a fresh `VmId` + VMGenID, and CoW-materialized the parent's whole content dir into `req.child_dir` — which for a `vm_full` checkpoint means `rootfs.ext4`, `memory.bin`, `vmstate.bin`, `device-anchors.json`, and the guest sidecars. That is exactly the layout `FcForkRestorer::restore_fork` consumes, so this override is a delegation, not a reimplementation.

**Files:**
- Modify: `crates/mvm-runtime/src/driver/fc.rs`
- Reference: `crates/mvm-runtime/src/firecracker.rs:436` (`FcForkRestorer::restore_fork`), `crates/mvm-runtime/src/driver/mock.rs:175-196`
- Test: `crates/mvm-runtime/src/driver/fc.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `ChildForkRequest<'a> { child_vm_name: &'a str, child_dir: &'a Path, genid: GenerationToken }` (`driver/traits.rs:22-31`); `FcForkRestorer` (`firecracker.rs`).
- Produces: `FcDriver::fork_standby_child(&self, req: &ChildForkRequest<'_>) -> std::result::Result<(), StandbyError>`.

- [ ] **Step 1: Write the failing tests**

```rust
/// The runner materializes the CoW clone before forking. An absent dir means
/// the clone never landed, so restoring would load something other than the
/// verified parent's content — refuse instead.
#[test]
fn fork_standby_child_refuses_an_unmaterialized_child_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("never-materialized");
    let req = ChildForkRequest {
        child_vm_name: "child-vm-1",
        child_dir: &missing,
        genid: sample_generation_token(),
    };

    let err = FcDriver::new().fork_standby_child(&req).unwrap_err();

    assert!(
        matches!(err, StandbyError::ClaimFailed(ref m) if m.contains("child-vm-1")),
        "expected a ClaimFailed naming the child, got: {err:?}"
    );
}

/// A memory restore needs the parent's saved memory. A clone carrying only a
/// rootfs would silently cold-boot instead of restoring, so it is refused.
#[test]
fn fork_standby_child_refuses_a_clone_without_saved_memory() {
    let tmp = tempfile::tempdir().unwrap();
    let child_dir = tmp.path().join("child");
    std::fs::create_dir_all(&child_dir).unwrap();
    std::fs::write(child_dir.join("rootfs.ext4"), b"rootfs").unwrap();
    let req = ChildForkRequest {
        child_vm_name: "child-vm-2",
        child_dir: &child_dir,
        genid: sample_generation_token(),
    };

    let err = FcDriver::new().fork_standby_child(&req).unwrap_err();

    assert!(
        matches!(err, StandbyError::ClaimFailed(ref m) if m.contains("memory")),
        "expected a ClaimFailed naming the missing memory image, got: {err:?}"
    );
}
```

Write `sample_generation_token()` building `GenerationToken { token: [0u8; GENID_BYTES], content_hash: "test-content-hash".into() }`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: FAIL — the inherited default returns `StandbyError::Unsupported`.

- [ ] **Step 3: Implement the override**

```rust
    fn fork_standby_child(
        &self,
        req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        if !req.child_dir.exists() {
            return Err(StandbyError::ClaimFailed(format!(
                "fork child '{}': child dir {} was never materialized",
                req.child_vm_name,
                req.child_dir.display()
            )));
        }
        // The restorer renames `memory.bin` to Firecracker's canonical load
        // name, so accept either — but require one. Without saved memory this
        // would quietly become a cold boot, losing the whole point of the pool.
        if !req.child_dir.join("memory.bin").exists() && !req.child_dir.join("mem.bin").exists() {
            return Err(StandbyError::ClaimFailed(format!(
                "fork child '{}': clone at {} carries no saved memory image",
                req.child_vm_name,
                req.child_dir.display()
            )));
        }

        // Restore the parent's saved memory into a fresh VMM under the child's
        // own identity. The device-model guard between load and resume refuses
        // any snapshot carrying a network interface, so a restored child cannot
        // reintroduce a path off the box that bypasses vsock.
        crate::checkpoint::ForkVmFullRestorer::restore_fork(
            &crate::firecracker::FcForkRestorer,
            req.child_vm_name,
            req.child_dir,
        )
        .map_err(|e| StandbyError::ClaimFailed(format!("restore forked child: {e}")))?;
        Ok(())
    }
```

`restore_fork` already runs the no-NIC guard and **resumes** the child (it routes through `guarded_fork_load_resume` → `guard_and_resume`), so this override must not add a second guard or a resume of its own.

Deliver `req.genid` by the same mechanism the existing fork path uses: `restore_fork` passes an all-zero token to `warm_restore_instance_from_path` and expects the caller to deliver the real token over vsock once the agent answers. The post-restore handshake is **fail-closed on three flags** — `acknowledged`, `reseeded`, and `clock_resynced` (`mvm-agentd/src/vsock/api.rs:160-183`) — so a child is not usable until the guest answers all three. Follow that contract rather than inventing a second delivery path; the existing checkpoint-fork CLI does it around `mvm-cli/src/commands/vm/checkpoint.rs:1053`. Decide and state in your report whether the handshake belongs in this driver override or in the runner's claim (the runner already owns the child's identity), and keep it in exactly one place.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: PASS.

- [ ] **Step 5: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(fc): restore a forked standby child from the parent's saved memory"
```

---

### Task 4: Capture the parent's full state, then release it

The driver boots the parent and supplies the backend-specific control; the capture itself is backend-agnostic, so it lives in the runner. After capture the parent is released — the checkpoint carries its full state, so a pool slot costs disk rather than RAM.

**Files:**
- Modify: `crates/mvm-runtime/src/workload_runner/runner.rs` (near `ClaimContext` at :237 and `spawn_standby` at :669)
- Modify: `crates/mvm-runtime/src/backend.rs` (near `claim_standby_via_runner` at :683)
- Test: `crates/mvm-runtime/src/workload_runner/runner.rs` + `crates/mvm-runtime/src/backend.rs`

**Interfaces:**
- Consumes: `StandbyHandle.parent_checkpoint` (Task 1); `FcDriver::spawn_standby_parent` + `vm_full_control` (Task 2); `capture_vm_full(store, CaptureVmFullParams, &dyn VmFullControl) -> Result<CheckpointMeta>` (`checkpoint/mod.rs:545`).
- Produces:
  ```rust
  pub struct SpawnContext<'a> { pub checkpoints: &'a CheckpointStore }

  impl<D: VmmDriver, S: EndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
      pub fn spawn_standby_captured(
          &self,
          ctx: &SpawnContext<'_>,
          spec: &StandbySpec,
      ) -> std::result::Result<StandbyHandle, StandbyError>;
  }

  impl AnyBackend {
      pub fn spawn_standby_via_runner(
          &self,
          ctx: &crate::workload_runner::SpawnContext<'_>,
          spec: &mvm_core::vm_backend::StandbySpec,
      ) -> std::result::Result<StandbyHandle, StandbyError>;
  }
  ```

- [ ] **Step 1: Write the failing test**

```rust
/// A spawned parent is claimable only once captured: the handle must carry the
/// checkpoint a later claim verifies content and lineage against, and that
/// checkpoint must carry saved memory — a rootfs-only capture would make every
/// claim a cold boot.
#[test]
fn spawn_standby_captured_stamps_a_memory_carrying_checkpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let store = CheckpointStore::at(tmp.path().join("checkpoints"));
    let rootfs = tmp.path().join("parent-rootfs.ext4");
    std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

    let runner = test_runner_with_mock_driver();
    let spec = standby_spec_with_image(&rootfs);

    let handle = runner
        .spawn_standby_captured(&SpawnContext { checkpoints: &store }, &spec)
        .unwrap();

    let id = handle
        .parent_checkpoint
        .expect("a captured parent must carry its checkpoint id");
    let meta = store.read_meta(&CheckpointId::new(id)).unwrap();
    assert_eq!(meta.class, CheckpointClass::VmFull);
    assert!(
        meta.content.iter().any(|b| b.name == "memory.bin"),
        "the capture must carry saved memory, got: {:?}",
        meta.content.iter().map(|b| &b.name).collect::<Vec<_>>()
    );
}
```

Reuse whatever runner-construction helper this file's existing tests already use for `MockDriver`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run -p mvm-runtime workload_runner`
Expected: FAIL — `no method named 'spawn_standby_captured'`.

- [ ] **Step 3: Implement `SpawnContext` + `spawn_standby_captured`**

Place `SpawnContext` next to `ClaimContext` (runner.rs:237), matching its doc-comment style. Then, alongside the existing `spawn_standby` (:669):

```rust
    pub fn spawn_standby_captured(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        // The driver boots the parent and leaves it running; capturing a live
        // VM's memory is backend-agnostic, so it lives here rather than in any
        // one driver.
        let mut handle = self.driver.spawn_standby_parent(spec)?;

        let control = self.driver.vm_full_control(&spec.id).ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "backend cannot capture a warm parent's memory for standby '{}'",
                spec.id
            ))
        })?;

        let id = CheckpointId::new(format!("standby-{}", spec.id));
        let captured = capture_vm_full(
            ctx.checkpoints,
            CaptureVmFullParams {
                id,
                vm_name: spec.id.clone(),
                supervisor_config_digest: String::new(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                // Firecracker does not use a supervisor-config blob; its
                // presence is what marks a checkpoint as originating elsewhere.
                supervisor_config_src: None,
                tag: None,
                created_unix: now_unix_secs(),
            },
            control.as_ref(),
        );

        // Release the parent either way: the checkpoint carries its full state,
        // so a pool slot costs disk rather than a resident VM. On a failed
        // capture this also stops a stranded guest.
        self.release_standby_parent(&spec.id);

        let meta = captured
            .map_err(|e| StandbyError::SpawnFailed(format!("capture standby parent: {e}")))?;

        handle.pid = 0;
        handle.parent_checkpoint = Some(meta.id.as_str().to_string());
        Ok(handle)
    }
```

Write `release_standby_parent(&self, vm_name: &str)` as a small private helper that attaches to the VM and kills it, logging (not propagating) a failure — a parent that cannot be reaped must not fail an otherwise-good capture, but it must be visible. Check `CaptureVmFullParams`' exact field types before writing (`checkpoint/mod.rs:527`), and match what other construction sites pass for `supervisor_config_digest` if a real digest is available.

- [ ] **Step 4: Add the `AnyBackend` routing seam**

Mirror `claim_standby_via_runner` (backend.rs:683) exactly — same arms, same fail-closed policy:

```rust
    pub fn spawn_standby_via_runner(
        &self,
        ctx: &crate::workload_runner::SpawnContext<'_>,
        spec: &mvm_core::vm_backend::StandbySpec,
    ) -> std::result::Result<mvm_core::vm_backend::StandbyHandle, mvm_core::vm_backend::StandbyError>
    {
        match self {
            AnyBackend::Firecracker(runner) => runner.spawn_standby_captured(ctx, spec),
            AnyBackend::Libkrun(runner) => runner.spawn_standby_captured(ctx, spec),
            AnyBackend::Hvf(runner) => runner.spawn_standby_captured(ctx, spec),
            // The hermetic lifecycle double has no runner and no checkpoint
            // store; it services the spawn from its own in-memory state.
            #[cfg(feature = "test-support")]
            AnyBackend::Mock(backend) => backend.spawn_standby(spec),
            AnyBackend::Qemu(_) | AnyBackend::Wasm(_) => {
                Err(mvm_core::vm_backend::StandbyError::Unsupported {
                    backend: self.inner().name().to_string(),
                })
            }
        }
    }
```

Add a routing test mirroring the existing `claim_routing::*` tests (qemu and wasm must return `Unsupported`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-runtime workload_runner backend`
Expected: PASS.

- [ ] **Step 6: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(standby): capture a warm parent's full state and release it"
```

---

### Task 5: Wire the CLI — thread the rootfs in, assemble a live claim context

Two gaps close here. `warm_to_target` never passes a rootfs (`WarmParams.image` is documented *"Always `None` today"*), which alone makes a Firecracker parent unbootable. And `claim_or_cold` calls the parameterless, fail-closed `backend.claim_standby(..)` instead of the runner-backed claim.

**Files:**
- Modify: `crates/mvm-core/src/config.rs` (add `snapshots_dir()`)
- Modify: `crates/mvm-cli/src/commands/pool.rs` — `WarmParams` (:119), `warm_to_target` (:145), `claim_or_cold` (:240), `try_warm_claim` (:310), `replenish_after_launch`
- Reference: `crates/mvm-cli/src/commands/vm/checkpoint/lineage.rs:31-52` (`SignedChainAnchor::load()`)
- Test: `crates/mvm-core/src/config.rs` and `crates/mvm-cli/src/commands/pool.rs`

**Interfaces:**
- Consumes: `AnyBackend::spawn_standby_via_runner` + `SpawnContext` (Task 4); `AnyBackend::claim_standby_via_runner` + `ClaimContext` (already on `main`); `StandbyHandle.parent_checkpoint` (Task 1).
- Produces: `mvm_core::config::snapshots_dir() -> PathBuf`; `warm_to_target` and `claim_or_cold` taking `&AnyBackend`; a live `ClaimContext` per claim.

- [ ] **Step 1: Write the failing test**

```rust
/// A parent that was never captured has no checkpoint to verify content and
/// lineage against, so a claim against it must refuse rather than clone
/// unverified content.
#[test]
fn claim_refuses_a_parent_without_a_checkpoint() {
    let handle = sample_handle_without_parent_checkpoint();

    let err = parent_checkpoint_for(&handle).unwrap_err();

    assert!(
        err.to_string().contains("never captured"),
        "expected a refusal naming the uncaptured parent, got: {err}"
    );
}
```

Introduce `parent_checkpoint_for(handle: &StandbyHandle) -> Result<CheckpointId>` resolving the handle's `parent_checkpoint` and failing closed when it is `None`. Keep it a separate function so it is unit-testable without a VM.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run -p mvm-cli commands::pool`
Expected: FAIL — the helper does not exist.

- [ ] **Step 3: Add the `snapshots_dir` config helper**

`FsSnapshotStore` has no production call site yet and `mvm-core::config` has no snapshots path. Add one beside `checkpoints_dir()` (`config.rs:641`), following that function's exact style so it honors `MVM_HOME`, plus a test asserting it sits under `mvm_home()`.

- [ ] **Step 4: Thread the rootfs into the warm path**

Change `WarmParams.backend` from `&'a dyn VmBackend` to `&'a AnyBackend`. Populate `WarmParams.image` from the launch's rootfs (`VmStartConfig.rootfs_path`) at the `replenish_after_launch` call site — a Firecracker parent cannot boot without it. Correct the `image` doc comment, which currently claims it is always `None`. In `warm_to_target`, replace `p.backend.spawn_standby(&spec)` with:

```rust
        let checkpoints = CheckpointStore::open();
        match p
            .backend
            .spawn_standby_via_runner(&SpawnContext { checkpoints: &checkpoints }, &spec)
        {
```

Record the returned handle (now carrying `parent_checkpoint`) exactly as before.

- [ ] **Step 5: Route the claim through the runner**

Change `claim_or_cold`'s `backend` parameter to `&AnyBackend`, and update `try_warm_claim` to pass `backend` directly instead of `backend.as_vm_backend()`. Replace the `backend.claim_standby(&handle, &claim)` call (pool.rs:268) with:

```rust
    // A claim verifies the parent's content and lineage against the checkpoint
    // it was captured as, so an uncaptured parent is unusable by construction.
    let parent_checkpoint = match parent_checkpoint_for(&handle) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(standby = %handle.id, error = %e, "cold-booting");
            let _ = pool.remove(&handle.id);
            return Ok(LaunchDecision::ColdBoot);
        }
    };
    let checkpoints = CheckpointStore::open();
    let snapshots = FsSnapshotStore::new(mvm_core::config::snapshots_dir())?;
    let anchor = SignedChainAnchor::load()?;
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    let ctx = ClaimContext {
        pool,
        checkpoints: &checkpoints,
        snapshots: &snapshots,
        anchor: &anchor,
        parent_checkpoint: &parent_checkpoint,
        registry_path: &registry_path,
    };
    match backend.claim_standby_via_runner(&ctx, &handle, &claim) {
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-cli commands::pool && cargo nextest run -p mvm-core config`
Expected: PASS.

- [ ] **Step 7: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(pool): assemble a live claim context and boot standby parents from the launch rootfs"
```

---

### Task 6: Flip the Firecracker standby capability

Last, and only now: the capability means "can actually spawn+claim a warm parent". Flipping it before Tasks 2-5 would turn a configured warm pool into a silent cold boot plus warning noise.

**Files:**
- Modify: `crates/mvm-runtime/src/driver/fc.rs:363-387` (capabilities + its stale comment), `:719-731` (the guard test)

**Interfaces:**
- Consumes: Tasks 2-5.
- Produces: `FcDriver::capabilities().standby_pool == true`.

- [ ] **Step 1: Update the guard test to assert the new boundary**

`no_selectable_driver_advertises_standby_pool_yet` asserts *every* driver is off. Firecracker now supports it, so rename the test and pin the real split:

```rust
/// Firecracker owns a live spawn+claim path, so it advertises the pool. The
/// capability means "can actually spawn+claim a warm parent", so every other
/// driver stays off until it grows those live ops.
#[test]
fn only_firecracker_advertises_the_standby_pool() {
    use crate::driver::{HvfDriver, LibkrunDriver, MockDriver};
    use crate::qemu::QemuBackend;
    use crate::wasm_backend::WasmBackend;

    assert!(FcDriver::new().capabilities().standby_pool);
    assert!(!LibkrunDriver::new().capabilities().standby_pool);
    assert!(!HvfDriver::new().capabilities().standby_pool);
    assert!(!MockDriver::default().capabilities().standby_pool);
    assert!(!QemuBackend.capabilities().standby_pool);
    assert!(!WasmBackend::new().capabilities().standby_pool);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: FAIL on the first assertion.

- [ ] **Step 3: Flip `standby_pool` and correct the comment**

Set `standby_pool: true` and replace the stale "stays off … flips true with that slice" comment with one describing the shipped behavior.

**Do not blanket-flip the neighbouring flags.** `snapshots`, `snapshot_capability`, and `fs_quick_checkpoint` gate other surfaces (user-facing snapshot verbs). This driver now performs `vm_full` captures for the pool, which may or may not be what those flags mean. Check what each actually gates before changing it, change only what is now genuinely true, and state your reasoning in your report.

- [ ] **Step 4: Run the full suite**

Run: `cargo nextest run --workspace`
Expected: PASS. Other tests may assert the old capability shape — find and update each.

- [ ] **Step 5: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(fc): advertise the standby pool now that spawn and claim are live"
```

---

### Task 7: Live validation and the first committed warm-restore number

Everything above is hermetic. This is the acceptance gate: the chain must run on real Firecracker — and it produces something the codebase does not yet have anywhere, a recorded warm-restore latency.

**Files:**
- Create: `specs/notes/2026-07-28-plan-255-live-fc-warm-claim-validation.md`

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: recorded evidence (commands + verbatim output) plus measured latencies.

- [ ] **Step 1: Get the branch onto the box**

Host: `ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -i ~/.ssh/hetzner-rvproxy root@88.99.197.234`

Use a **fresh** checkout dir under `/root`. Do not touch `/root/mvm`, `/root/mvm-plan265`, or any `/root/mvm-plan255-warm-pool-*` — those belong to other sessions. Confirm `/dev/kvm` exists before building.

- [ ] **Step 2: Build in release**

```bash
cargo build --release --bin mvmctl
```

Release matters: the only prior figure (~60 ms) was a debug build and is explicitly attributed to `curl`-subprocess and fresh-spawn overhead, not the restore itself.

- [ ] **Step 3: Drive spawn → claim and capture the evidence**

Populate a pool of one, then launch a workload that claims it. Record verbatim:
1. the parent boots and its agent reaches ready;
2. the parent is captured — `~/.mvm/pool/<id>/standby.json` carries a non-null `parent_checkpoint`, and that checkpoint's meta shows class `vm_full` with a `memory.bin` blob;
3. the parent is released (no Firecracker process survives the capture);
4. a claim mints a **fresh** VM name distinct from the parent's, and the child comes up **without a kernel boot** — the console log must show no fresh boot sequence, proving a restore rather than a cold boot;
5. `mvmctl trust audit verify` exits zero and the chain carries the claim's `plan.admitted` / `plan.launched` entries.

- [ ] **Step 4: Measure**

Record, in release, with several repetitions (report median and spread, not a single sample):
- cold boot to agent-ready (the baseline);
- warm claim to agent-ready (the headline);
- the split between fresh-Firecracker-spawn cost and snapshot-load cost, if separable — this is the baseline Plan 265 WS2's pre-spawned-VMM work will optimize against.

- [ ] **Step 5: Prove the fail-closed paths on the live host**

Confirm each refusal actually refuses — do not infer from code:
- corrupt the captured checkpoint's content, then claim → refused, parent quarantined, no child started;
- a handle whose `parent_checkpoint` is absent → cold boot, no clone;
- a clone stripped of its memory image → refused (Task 3's guard), not a silent cold boot;
- a failed claim leaves no orphaned child dir under `~/.mvm/vms/`;
- confirm the restored child's device model carries no network interface (the guard inside `guarded_load_resume` is the enforcement; verify it is exercised rather than assumed).

- [ ] **Step 6: Write the validation note**

Record exact commands, verbatim output, host details (kernel, Firecracker version, release build), and the measured numbers with their spread. If anything failed, write down what failed rather than only what passed. State explicitly which costs remain (fresh VMM spawn per claim) and that they are Plan 265 WS2's to optimize.

- [ ] **Step 7: Commit**

```bash
git add specs/notes/2026-07-28-plan-255-live-fc-warm-claim-validation.md
git commit -m "docs: record the live Firecracker warm-claim validation run"
```

---

## Done when

- All seven tasks' boxes are ticked.
- The full gate set passes: `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace --all-targets -- -D warnings`.
- The live run on the KVM host is recorded, with measured warm and cold latencies and the fail-closed cases.
- `specs/plans/255-vsock-first-snapshot-egress-adoption.md` and `specs/SPRINT.md` are updated to reflect this slice landing, in the same change.
- The design note `specs/notes/2026-07-28-plan-255-live-fc-warm-claim-design.md` is corrected — its "Non-goals" and "Convergence to sub-second" sections describe the superseded cold-boot scoping.
