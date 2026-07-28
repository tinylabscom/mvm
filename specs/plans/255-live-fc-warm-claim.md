# Live Firecracker Warm-Claim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Firecracker warm pool functional end to end — `spawn_standby` boots a clean factory parent and captures it as a content-addressed checkpoint, and a claim forks a fresh, admitted, audited child that actually boots on real Firecracker — validated live on a KVM host.

**Architecture:** The merged claim substrate already owns the guarded fork (reserve → verify content + lineage → bind plan → fresh identity → CoW materialize → fork). This slice fills the stubs beneath and above it: two `FcDriver` overrides doing the VMM work (boot a parent to agent-ready then quiesce it; cold-boot a child from the CoW clone), a runner-level capture turning a quiesced parent into a checkpoint, a `parent_checkpoint` field carrying that id on the persisted handle, and CLI wiring that assembles a live `ClaimContext`. The capability flip comes last, once the pool can actually be populated.

**Tech Stack:** Rust (14-crate workspace), Firecracker VMM over its HTTP-on-UDS API, vsock (no guest NIC), `cargo nextest`, live validation on a Linux/KVM host.

## Global Constraints

Every task's requirements implicitly include this section.

- **The child is a COLD BOOT, not a memory restore.** Firecracker memory restore is hard-disabled (`crates/mvm-runtime/src/microvm/snapshot.rs` — `warm_restore_instance`, `warm_restore_instance_from_path`, `restore_from_template_snapshot` all `bail!`). Never call, re-enable, or work around those. Sub-second restore is a separate effort.
- **No guest NIC, ever.** vsock is the sole boundary. `VmmSpec` deliberately has no NIC field — keep it that way; never add a `network-interfaces` PUT to any Firecracker config here.
- **Never set `trusted_builder: true` on a workload-bearing VM.** It disables the claim-10 egress gate. It exists for the builder VM only.
- **No competitor proper nouns** anywhere — code, comments, tests, commit messages, PR text, branch names.
- **No spec references in code comments.** `Plan`, `ADR`, `#NNNN`, `W#`, `Phase N` are CI-gated by `xtask check-no-spec-refs`. Explain *why* in prose instead. (Files under `specs/` are exempt — this rule is about code.)
- **`#[allow(clippy::...)]` is banned outright**, including `too_many_arguments`. When a function trips the lint, introduce a params struct (this repo already uses `CaptureFsQuickParams`, `WarmParams`, `StandbySpecParams`, `ClaimContext` for exactly this).
- **All `~/.mvm` paths go through `mvm-core::config`** helpers (`mvm_pool_dir`, `vms_dir`, `checkpoints_dir`, `vm_state_dir`, …). Never build them from `std::env::var("HOME")`. If a needed path has no helper, **add one to `mvm-core::config`** rather than inlining it.
- **New struct fields get `#[serde(default)]`** — no schema-version bump, no migration shim (mirror the existing `image_sha256` field on `StandbyHandle`).
- **Reuse first.** `FcDriver::boot` already spawns Firecracker, drives the NIC-less config PUTs, starts the instance, and blocks until the guest agent answers. Call it; do not reimplement it.
- **No placeholders, no stubs, no TODOs** in delivered code.
- **Gates (run the FULL workspace suite, never a filtered subset):**
  ```bash
  cargo fmt --all -- --check
  cargo nextest run --workspace
  cargo test --workspace --doc
  cargo clippy --workspace --all-targets -- -D warnings
  ```
- **No AI-tool attribution** and no `Co-Authored-By: Claude` trailer in any commit or PR.

## Key facts verified against the code (do not re-derive)

- `StandbyHandle` is defined in **`mvm-protocol`** (`src/protocol/vm_backend.rs:744`); `CheckpointId` is defined in **`mvm-core`** (`src/checkpoint.rs:12`). **`mvm-protocol` does not depend on `mvm-core`** and must not — it is the `no_std` foundation. Therefore the new handle field is `Option<String>`, converted to/from `CheckpointId` at the `mvm-runtime` boundary.
- A checkpoint's content dir holds **`rootfs.ext4`** (`checkpoint/mod.rs:555,585`). `materialize_child_from_parent` clones that content dir into `child_dir`, so the child's rootfs is **`child_dir/rootfs.ext4`** (`warm_snapshot.rs:37-56`; confirmed by `checkpoint/mod.rs:1146`).
- The VM name registry path helper is **`mvm_runtime::vm::name_registry::registry_path()`** (`vm/name_registry.rs:322`).
- **`FsSnapshotStore` has only `new(root)`** (`mvm-fs/src/snapshot_store.rs:157`) — no `open()`, and **no production call site exists yet**. There is **no `snapshots_dir()` in `mvm-core::config`**; Task 5 adds one.
- Nothing in the codebase gates behavior on the `fs_quick_checkpoint` capability — it is advertised metadata only.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `crates/mvm-protocol/src/protocol/vm_backend.rs` | `StandbyHandle.parent_checkpoint` field | 1 |
| `crates/mvm-runtime/src/standby_pool.rs` | round-trips the new field | 1 |
| `crates/mvm-runtime/src/driver/fc.rs` | `spawn_standby_parent` (boot→ready→quiesce) | 2 |
| `crates/mvm-runtime/src/driver/fc.rs` | `fork_standby_child` (cold-boot child) | 3 |
| `crates/mvm-runtime/src/workload_runner/runner.rs` | `SpawnContext` + capture into `parent_checkpoint` | 4 |
| `crates/mvm-runtime/src/backend.rs` | `spawn_standby_via_runner` routing seam | 4 |
| `crates/mvm-core/src/config.rs` | `snapshots_dir()` helper | 5 |
| `crates/mvm-cli/src/commands/pool.rs` | live context assembly + rootfs threading | 5 |
| `crates/mvm-runtime/src/driver/fc.rs` | capability flip + guard tests | 6 |
| `specs/notes/2026-07-28-plan-255-live-fc-warm-claim-validation.md` | live-run evidence | 7 |

---

### Task 1: `parent_checkpoint` on the persisted standby handle

A claim must find the checkpoint its parent was captured as. `StandbySpec` has no checkpoint field and `StandbyHandle` has none, so the id has nowhere to live between spawn and claim.

**Files:**
- Modify: `crates/mvm-protocol/src/protocol/vm_backend.rs:744-757`
- Modify: `crates/mvm-runtime/src/standby_pool.rs` (tests only)
- Test: `crates/mvm-runtime/src/standby_pool.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `StandbyHandle.parent_checkpoint: Option<String>` — the checkpoint id as a plain string, because `mvm-protocol` cannot see `mvm-core`'s `CheckpointId`. Tasks 2 and 4 construct it; Task 5 reads it.

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

In `crates/mvm-protocol/src/protocol/vm_backend.rs`, add to `StandbyHandle` immediately after `image_sha256`:

```rust
    /// The content-addressed checkpoint this parent was captured as, set once
    /// a spawn has captured a quiesced parent. `None` means the parent was
    /// never captured, so it cannot be claimed: a claim verifies content and
    /// lineage against this checkpoint before cloning anything.
    ///
    /// Held as the raw id string rather than a `CheckpointId` because that type
    /// lives a layer up; the runtime converts at its boundary.
    #[serde(default)]
    pub parent_checkpoint: Option<String>,
```

- [ ] **Step 4: Fix every construction site**

Adding a field breaks every struct literal. Find them all and add the field explicitly (do **not** reach for `..Default::default()`):

Run: `cargo build --workspace --all-targets 2>&1 | grep -A3 'missing field'`

Known site: `crates/mvm-runtime/src/driver/mock.rs:163` (`MockDriver::spawn_standby_parent` → `parent_checkpoint: None`), plus test fixtures. Set `None` everywhere in this task; Task 4 populates it for real.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run -p mvm-runtime standby_pool`
Expected: PASS (both new tests).

- [ ] **Step 6: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(standby): carry the captured parent checkpoint on the standby handle"
```

---

### Task 2: `FcDriver::spawn_standby_parent` — boot a clean parent, then quiesce it

`FcDriver` inherits the fail-closed default today, so no Firecracker pool can ever be populated. This override boots a real, clean parent and leaves it quiesced so Task 4's capture sees a stable rootfs.

**Two things the implementer must not miss:**

1. **The boot is validation, not content.** The workload rootfs is read-only (dm-verity sealed), so booting does not mutate it — the captured bytes would be identical without the boot. The boot proves this rootfs produces a working guest (a pool slot that cannot boot is worse than useless) and is the seam a later memory capture requires. Do not "optimize" it away.
2. **A factory parent carries no workload, so it has no egress relay wired.** `VmmSpec.trusted_builder` must stay `false` (it is workload-bearing content). If the guest's egress gate refuses to boot without a relay, wire the parent a minimal vsock egress port — do **not** flip `trusted_builder` to paper over it. Report which you needed.

**Files:**
- Modify: `crates/mvm-runtime/src/driver/fc.rs` (add the override inside `impl VmmDriver for FcDriver`, lines 350-512)
- Reference: `crates/mvm-runtime/src/driver/mock.rs:132-173` (the reference impl)
- Test: `crates/mvm-runtime/src/driver/fc.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `StandbyHandle.parent_checkpoint` (Task 1) — `None` here; Task 4 fills it.
- Produces: `FcDriver::spawn_standby_parent(&self, spec: &StandbySpec) -> std::result::Result<StandbyHandle, StandbyError>`, returning a handle with `pid: 0` (nothing runs after quiesce) and `state: StandbyState::Idle`.

The exact types this task constructs, verbatim from `crates/mvm-runtime/src/driver/spec.rs`:

```rust
pub enum KernelImage { Path(PathBuf), Bundled }

pub struct BlockDev { pub source: PathBuf, pub read_only: bool, pub ephemeral: bool, pub slot: u8 }

pub struct ConsoleCapture { pub log_path: PathBuf }

pub struct VmmSpec {
    pub name: String,
    pub kernel: KernelImage,
    pub initramfs: Option<PathBuf>,
    pub cmdline: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub mem_initial_mib: Option<u32>,
    pub blocks: Vec<BlockDev>,
    pub vsock: Vec<VsockPort>,
    pub console: ConsoleCapture,
    pub trusted_builder: bool,
}
```

- [ ] **Step 1: Write the failing test**

A full boot needs KVM, so the unit test covers the fail-closed precondition that must hold on every host:

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
```

Write `standby_spec_without_image()` building a `StandbySpec` with `image_path: None` and every other field populated plausibly.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: FAIL — the inherited default returns `StandbyError::Unsupported`, not `SpawnFailed`.

- [ ] **Step 3: Implement the override**

Add inside `impl VmmDriver for FcDriver`:

```rust
    fn spawn_standby_parent(
        &self,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        // A factory parent carries no plan, no volumes, no broker endpoint and
        // no guest NIC — nothing that could bind it to one workload. It exists
        // only to prove this rootfs boots and to be cloned.
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
                // so one parent boot cannot alter what every child clones.
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

        // `boot` returns only once the guest agent answered over vsock, so
        // reaching here proves this rootfs produces a working guest.
        let vm = self
            .boot(&parent)
            .map_err(|e| StandbyError::SpawnFailed(format!("boot standby parent: {e}")))?;

        // Quiesce before the caller captures: an fs-only checkpoint carries no
        // memory, so the rootfs must be stable and not mid-write.
        vm.kill()
            .map_err(|e| StandbyError::SpawnFailed(format!("quiesce standby parent: {e}")))?;

        Ok(StandbyHandle {
            id: spec.id.clone(),
            control_socket: spec.control_socket.clone(),
            // Nothing runs after the quiesce; the parent is saved state.
            pid: 0,
            kernel_sha256: spec.kernel_sha256.clone(),
            vcpus: spec.vcpus,
            mem_mib: spec.mem_mib,
            binding_nonce: spec.binding_nonce.clone(),
            spawned_unix_secs: now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: spec.image_sha256.clone(),
            // The caller captures the quiesced parent and stamps this.
            parent_checkpoint: None,
        })
    }
```

Reuse the same `now_unix_secs` import `mock.rs` uses — do not write a second clock helper. Compare the `BlockDev` shape against the normal workload cold-boot path's rootfs device and match it if it differs.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: PASS.

- [ ] **Step 5: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(fc): boot and quiesce a clean standby parent"
```

---

### Task 3: `FcDriver::fork_standby_child` — cold-boot the child from the CoW clone

The runner has already verified the parent, minted a fresh `VmId` + VMGenID, and materialized a copy-on-write clone into `req.child_dir`. This override boots that clone as a fresh Firecracker VM.

**Files:**
- Modify: `crates/mvm-runtime/src/driver/fc.rs`
- Reference: `crates/mvm-runtime/src/driver/mock.rs:175-196` (incl. the `child_dir.exists()` precondition)
- Test: `crates/mvm-runtime/src/driver/fc.rs` (inline `#[cfg(test)]` module)

**Interfaces:**
- Consumes: `ChildForkRequest<'a> { child_vm_name: &'a str, child_dir: &'a Path, genid: GenerationToken }` (`driver/traits.rs:22-31`).
- Produces: `FcDriver::fork_standby_child(&self, req: &ChildForkRequest<'_>) -> std::result::Result<(), StandbyError>`.

- [ ] **Step 1: Write the failing test**

```rust
/// The runner materializes the CoW clone before forking. An absent dir means
/// the clone never landed, so booting would start something other than the
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
```

Write `sample_generation_token()` building `GenerationToken { token: [0u8; GENID_BYTES], content_hash: "test-content-hash".into() }`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: FAIL — the inherited default returns `StandbyError::Unsupported`.

- [ ] **Step 3: Implement the override**

The child's rootfs is `child_dir/rootfs.ext4` — the clone of the parent checkpoint's content dir (verified: `checkpoint/mod.rs:555,585`, `warm_snapshot.rs:37-56`).

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
        let rootfs = req.child_dir.join("rootfs.ext4");
        if !rootfs.exists() {
            return Err(StandbyError::ClaimFailed(format!(
                "fork child '{}': clone at {} carries no rootfs",
                req.child_vm_name,
                rootfs.display()
            )));
        }

        // Memory restore is unavailable on this path, so the child is a cold
        // boot from its own clone: a fresh VMM with no device or memory state
        // inherited from the parent's address space.
        let child = VmmSpec {
            name: req.child_vm_name.to_string(),
            kernel: /* same kernel the parent booted — see Step 4 */,
            initramfs: None,
            cmdline: self.workload_base_bootargs(false, true),
            vcpus: /* the claimed parent's vcpus */,
            memory_mib: /* the claimed parent's mem_mib */,
            mem_initial_mib: None,
            blocks: vec![BlockDev {
                source: rootfs,
                read_only: true,
                ephemeral: false,
                slot: 0,
            }],
            vsock: Vec::new(),
            console: ConsoleCapture {
                log_path: req.child_dir.join("console.log"),
            },
            trusted_builder: false,
        };

        self.boot(&child)
            .map_err(|e| StandbyError::ClaimFailed(format!("boot forked child: {e}")))?;
        Ok(())
    }
```

- [ ] **Step 4: Resolve the child's kernel and resources**

`ChildForkRequest` carries only the name, dir, and genid — it has no kernel or resource fields, so the three commented slots above have no source today. Pick the smallest honest fix and state which you chose in your report:

- **(a)** extend `ChildForkRequest` with the fields the fork needs (`kernel_path`, `vcpus`, `mem_mib`), populated at the single call site in `runner.rs:423-427` from the `StandbyHandle` the claim already holds; or
- **(b)** carry them on the clone (e.g. written beside `rootfs.ext4` at capture time) and read them back here.

Prefer **(a)**: the runner already holds the verified handle, the struct is internal with one call site, and it keeps the child's resources bound to the parent that was actually verified. Update `MockDriver::fork_standby_child` and the hermetic BDD steps for the new field set.

Deliver `req.genid` to the child by the same mechanism the cold-boot launch path already uses for a generation token — search the runtime for existing `GenerationToken` delivery before inventing one.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo nextest run -p mvm-runtime driver::fc`
Expected: PASS.

- [ ] **Step 6: Full gates + commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
git add -A
git commit -m "feat(fc): cold-boot a forked standby child from its clone"
```

---

### Task 4: Capture the quiesced parent into a checkpoint

The driver does VMM work; the capture is backend-agnostic, so it belongs above the driver. The runner gains a spawn context (mirroring the existing `ClaimContext`), captures the quiesced parent with `capture_fs_quick`, and stamps the id onto the handle.

**Files:**
- Modify: `crates/mvm-runtime/src/workload_runner/runner.rs` (near `ClaimContext` at :237 and `spawn_standby` at :669)
- Modify: `crates/mvm-runtime/src/backend.rs` (near `claim_standby_via_runner` at :683)
- Test: `crates/mvm-runtime/src/workload_runner/runner.rs` + `crates/mvm-runtime/src/backend.rs` (inline `#[cfg(test)]` modules)

**Interfaces:**
- Consumes: `StandbyHandle.parent_checkpoint: Option<String>` (Task 1); `FcDriver::spawn_standby_parent` (Task 2); existing `capture_fs_quick(store: &CheckpointStore, params: CaptureFsQuickParams) -> Result<CheckpointMeta>` (`checkpoint/mod.rs:913`) and `CaptureFsQuickParams` (`checkpoint/mod.rs:122`).
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
  Task 5 calls `spawn_standby_via_runner`.

- [ ] **Step 1: Write the failing test**

```rust
/// A spawned parent is claimable only once captured: the handle must carry the
/// checkpoint a later claim verifies content and lineage against.
#[test]
fn spawn_standby_captured_stamps_the_parent_checkpoint() {
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
    let meta = store
        .read_meta(&CheckpointId::new(id))
        .expect("the checkpoint must be readable");
    assert_eq!(meta.vm_name, spec.id);
}
```

Reuse whatever runner-construction helper this file's existing tests already use for `MockDriver`; do not add a second one.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo nextest run -p mvm-runtime workload_runner`
Expected: FAIL — `no method named 'spawn_standby_captured'`.

- [ ] **Step 3: Implement `SpawnContext` + `spawn_standby_captured`**

Place `SpawnContext` next to `ClaimContext` (runner.rs:237), matching its doc-comment style:

```rust
/// The store a spawn needs to turn a booted, quiesced parent into a
/// content-addressed checkpoint a later claim can verify against.
pub struct SpawnContext<'a> {
    /// Content-addressed checkpoint store the captured parent is written to.
    pub checkpoints: &'a CheckpointStore,
}
```

Then, alongside the existing `spawn_standby` (:669):

```rust
    pub fn spawn_standby_captured(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        // The driver boots the parent and leaves it quiesced; the capture is
        // backend-agnostic, so it lives here rather than in any one driver.
        let mut handle = self.driver.spawn_standby_parent(spec)?;

        let rootfs = spec.image_path.as_deref().ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "standby '{}' has no rootfs image to capture",
                spec.id
            ))
        })?;

        let id = CheckpointId::new(format!("standby-{}", spec.id));
        let meta = capture_fs_quick(
            ctx.checkpoints,
            CaptureFsQuickParams {
                id,
                vm_name: spec.id.clone(),
                rootfs: PathBuf::from(rootfs),
                supervisor_config_digest: String::new(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                tag: None,
                created_unix: now_unix_secs(),
                // The driver killed the parent before returning, so its
                // read-only rootfs is stable.
                quiesced: true,
            },
        )
        .map_err(|e| StandbyError::SpawnFailed(format!("capture standby parent: {e}")))?;

        handle.parent_checkpoint = Some(meta.id.as_str().to_string());
        Ok(handle)
    }
```

Check `CaptureFsQuickParams`' exact field types before writing (`checkpoint/mod.rs:122`). For `supervisor_config_digest`, search the other `CaptureFsQuickParams` construction sites and match what they pass rather than defaulting to an empty string if a real digest is available.

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
git commit -m "feat(standby): capture a quiesced parent into a verifiable checkpoint"
```

---

### Task 5: Wire the CLI — thread the rootfs in, assemble a live claim context

Two gaps close here. `warm_to_target` never passes a rootfs (`WarmParams.image` is documented *"Always `None` today"*), which alone makes a Firecracker parent unbootable. And `claim_or_cold` calls the parameterless, fail-closed `backend.claim_standby(..)` instead of the runner-backed claim.

**Files:**
- Modify: `crates/mvm-core/src/config.rs` (add `snapshots_dir()`)
- Modify: `crates/mvm-cli/src/commands/pool.rs` — `WarmParams` (:119), `warm_to_target` (:145), `claim_or_cold` (:240), `try_warm_claim` (:310), `replenish_after_launch`
- Reference: `crates/mvm-cli/src/commands/vm/checkpoint/lineage.rs:31-52` (`SignedChainAnchor::load()`)
- Test: `crates/mvm-core/src/config.rs` and `crates/mvm-cli/src/commands/pool.rs` (inline `#[cfg(test)]` modules)

**Interfaces:**
- Consumes: `AnyBackend::spawn_standby_via_runner` + `SpawnContext` (Task 4); `AnyBackend::claim_standby_via_runner` + `ClaimContext` (already on `main`); `StandbyHandle.parent_checkpoint: Option<String>` (Task 1).
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
- Modify: `crates/mvm-runtime/src/driver/fc.rs:378` (`standby_pool`), `:384` (`fs_quick_checkpoint`), `:363-387` (the stale comment), `:719-731` (the guard test)

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
Expected: FAIL on the first assertion (`standby_pool` is still `false`).

- [ ] **Step 3: Flip the capability and correct the comment**

Set `standby_pool: true`. Set `fs_quick_checkpoint: true` — this driver now produces fs-quick captures, and leaving it `false` misreports the backend (nothing gates behavior on this flag, so it is a truthfulness fix). Replace the stale "stays off … flips true with that slice" comment with one describing the shipped behavior.

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

### Task 7: Live validation on a KVM host

Everything above is hermetic. This is the acceptance gate: the chain must run on real Firecracker.

**Files:**
- Create: `specs/notes/2026-07-28-plan-255-live-fc-warm-claim-validation.md`

**Interfaces:**
- Consumes: Tasks 1-6.
- Produces: recorded evidence (commands + verbatim output) that the live chain works.

- [ ] **Step 1: Get the branch onto the box**

Host: `ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -i ~/.ssh/hetzner-rvproxy root@88.99.197.234`

Use a **fresh** checkout dir under `/root`. Do not touch `/root/mvm`, `/root/mvm-plan265`, or any `/root/mvm-plan255-warm-pool-*` — those belong to other sessions. Confirm `/dev/kvm` exists before building.

- [ ] **Step 2: Build**

```bash
cargo build --release --bin mvmctl
```

- [ ] **Step 3: Drive spawn → claim and capture the evidence**

Populate a pool of one, then launch a workload that claims it. Record verbatim:
1. the parent boots and its agent reaches ready;
2. the parent is captured — `~/.mvm/pool/<id>/standby.json` carries a non-null `parent_checkpoint`;
3. a claim mints a **fresh** VM name distinct from the parent's, and the child boots with its agent reaching ready;
4. `mvmctl trust audit verify` exits zero and the chain carries the claim's `plan.admitted` / `plan.launched` entries.

- [ ] **Step 4: Prove the fail-closed paths on the live host**

Confirm each refusal actually refuses — do not infer from code:
- corrupt the captured checkpoint's content, then claim → refused, parent quarantined, no child booted;
- claim a handle whose `parent_checkpoint` is absent → cold boot, no clone;
- a failed claim leaves no orphaned child dir under `~/.mvm/vms/`.

- [ ] **Step 5: Write the validation note**

Record exact commands, verbatim output, host details (kernel, Firecracker version), and measured boot timings for parent and child. State plainly that the child is a cold boot and the timings are **not** a warm-restore figure. If anything failed, write down what failed rather than only what passed.

- [ ] **Step 6: Commit**

```bash
git add specs/notes/2026-07-28-plan-255-live-fc-warm-claim-validation.md
git commit -m "docs: record the live Firecracker warm-claim validation run"
```

---

## Done when

- All seven tasks' boxes are ticked.
- The full gate set passes: `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace --all-targets -- -D warnings`.
- The live run on the KVM host is recorded, including the fail-closed cases.
- `specs/plans/255-vsock-first-snapshot-egress-adoption.md` and `specs/SPRINT.md` are updated to reflect this slice landing, in the same change.
