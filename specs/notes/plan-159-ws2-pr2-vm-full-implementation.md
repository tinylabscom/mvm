# Plan 159 WS-2 PR2 — `vm_full` checkpoint + restore + fork — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `vm_full` checkpoint class — full machine memory state — with same-identity `restore` and new-identity `fork`, all through the unified `checkpoint` surface, reusing the existing Vz SAVE/RESTORE primitives.

**Architecture:** Generalize PR1's single-blob checkpoint content to a small manifest (`rootfs` + `memory` + `machine-id`). `capture_vm_full` orchestrates one host-side pause window (`PAUSE → SAVE → clone rootfs → RESUME`) via the existing `vz_control` verbs. `restore_checkpoint` copies the checkpoint rootfs back and reuses `VzBackend::snapshot_restore`. The `vm_full` fork arm builds a fresh child supervisor-config (new name → new MAC) pointed at the copied memory blob. The Vz I/O is abstracted behind a small trait so the orchestration is host-side unit-testable; the live round-trip is the spike's job.

**Tech Stack:** Rust 2024, serde, sha2, the Vz `vz_control` newline protocol, `StartupMode::Restore`, `host_gvproxy::derive_mac`.

**Design doc:** `specs/notes/plan-159-ws2-pr2-vm-full-design.md`
**Worktree:** `../mvm-159-ws2b` (branch `feat/plan-159-ws2-vm-full`).

**Standing rules:** library-first (ops `pub` in `mvm-backend`/`mvm-core`, CLI thin); all `~/.mvm` paths via `mvm_core::config`; reuse before reimplement; builder/params-struct over positional args; no `clippy::too_many_arguments` suppression; no spec/PR/plan/Task refs in code comments; no `Co-Authored-By` trailer; `cargo fmt --all`; clippy `-D warnings`; checkpoints are disposable local state (no migration).

---

## File Structure

| File | Change |
|------|--------|
| `specs/notes/plan-159-ws2-pr2-vm-full-design.md` *(exists)* | append the spike decision record (Task 1) |
| `crates/mvm-core/src/checkpoint.rs` | `ContentBlob`; `CheckpointMeta.content_sha256` → `content: Vec<ContentBlob>`; builder updates |
| `crates/mvm-backend/src/checkpoint/mod.rs` | manifest verify (`verify_content`/replace `only_file_in`); update `capture_fs_quick` + `fork_checkpoint`; add `VmFullControl` trait, `CaptureVmFullParams` + `capture_vm_full`, `RestoreParams` + `restore_checkpoint`, vm_full fork arm + `build_child_supervisor_config` |
| `crates/mvm-backend/src/vz.rs` | `VzVmFullControl` impl of the trait (pause/save/resume/rootfs); a `spawn_restore_with_config` helper factored from `snapshot_restore` |
| `crates/mvm-cli/src/commands/vm/checkpoint.rs` | `--class` on create; `Restore` subcommand; route vm_full; `bind_checkpoint_restored`; thin wiring |
| `crates/mvm-cli/src/commands/vm/audit_chain.rs` | `emit_checkpoint_restored` |
| `crates/mvm-cli/src/commands/vm/pause.rs` | retire `snapshot save`/`snapshot restore` arms |
| `crates/mvm-cli/src/commands/mod.rs` | drop the retired snapshot subcommands from help if needed |
| `tests/audit_total_coverage.rs` | register `CheckpointRestored` + posture |
| `specs/REFACTOR-STATUS.md`, `specs/plans/159-vz-inspired-macos-dx.md` | rollup |

---

## Task 1: Feasibility spike — Vz cross-identity restore (decision gate)

This is an **investigation task**, not a TDD unit. It resolves two parameters the fork arm (Task 7) needs, and writes a decision record. It runs on this macOS-26 host (the Vz builder works here); the dev-VM init-EOF flakiness means use a **long-lived workload image**, not the dev shell.

**Files:**
- Append findings to: `specs/notes/plan-159-ws2-pr2-vm-full-design.md` (a `## Spike decision record` section)

- [ ] **Step 1: Boot a long-lived Vz workload and save its memory.**

Bring up a VM that stays alive (e.g. an example workload that sleeps), then exercise the existing path:
```bash
# from the worktree; pick a long-lived example flake
cargo run -- up --flake examples/<long-lived> --hypervisor vz --name spiketest --wait &
# once running, save its memory via the snapshot CLI (the existing path)
mkdir -p /tmp/mvm-spike
cargo run -- snapshot save spiketest --path /tmp/mvm-spike/mem.bin --hypervisor vz
ls -la /tmp/mvm-spike/   # expect mem.bin + mem.bin.machine-id
```
Record: does SAVE succeed, and is the `.machine-id` sidecar written?

- [ ] **Step 2: Attempt restore into a NEW identity (fresh machine-id, new name/MAC).**

Construct a second VM state dir with a *different* name (so `derive_mac` yields a new MAC) whose `supervisor-config.json` mirrors `spiketest`'s but with `startup_mode = Restore { snapshot_path: mem.bin, machine_id_path: None }` (None → supervisor mints a fresh `VZGenericMachineIdentifier`). Spawn the supervisor and observe whether `restoreMachineStateFromURL` succeeds or errors.

Concretely: copy `~/.mvm/vms/spiketest/supervisor-config.json` to a new dir, edit `name`, `vm_state_dir`, drop `machine_id_path`, set the restore snapshot path, and run `mvm-vz-supervisor` with it on stdin (mirror how `snapshot_restore` spawns). Capture the supervisor stderr / console.log.

Record: **does Vz restore a memory image under a fresh machine-id?** (the core A-vs-B question).

- [ ] **Step 3: If Step 2 fails, retry with the parent's machine-id + a new MAC.**

Same as Step 2 but `machine_id_path: Some(mem.bin.machine-id)` (inherit identity) while keeping the new name (new MAC). Boot the child and check: does restore succeed, and **does guest networking work** (the guest kernel holds the parent's old MAC in its restored memory)? Probe from inside via the agent or console.

Record: does identity-inherited restore work, and does the child have functional networking with a different host MAC?

- [ ] **Step 4: Write the decision record.**

Append to the design doc a `## Spike decision record` with:
- `FRESH_MACHINE_ID: bool` — true if Step 2 succeeded (fork mints a fresh machine-id); false if it requires inheriting the parent's (Step 3).
- `ALLOW_PARENT_RUNNING: bool` — true (semantic A: two live copies) if restore-into-new-identity works AND networking survives a new MAC; false (semantic B: restore-as-new from a stopped parent) otherwise.
- A one-paragraph rationale citing the observed supervisor output.

These two booleans parameterize Task 7. Default expectation: aim for `FRESH_MACHINE_ID=true, ALLOW_PARENT_RUNNING=true` (semantic A); fall back to B per the observations.

- [ ] **Step 5: Commit the decision record.**
```bash
git add specs/notes/plan-159-ws2-pr2-vm-full-design.md
git commit -m "docs(plan-159): WS-2 PR2 fork feasibility spike decision record"
```

> **Note for the executor:** if the live Vz boot is too flaky to complete Steps 2-3 in this environment, record that explicitly and set the conservative fallback (`FRESH_MACHINE_ID=false, ALLOW_PARENT_RUNNING=false` → semantic B) so the fork arm ships the safe restore-as-new; the live A-path can be re-validated in a dedicated bringup session. Do NOT block the whole PR on a flaky live boot.

---

## Task 2: Content manifest model (mvm-core)

Replace the single `content_sha256: String` with a `content: Vec<ContentBlob>` manifest so both classes share one model.

**Files:**
- Modify: `crates/mvm-core/src/checkpoint.rs`

- [ ] **Step 1: Write the failing tests** — replace the existing `content_sha256` assertions in the test module and add:

```rust
    #[test]
    fn meta_carries_a_content_manifest() {
        let meta = CheckpointMeta::builder(
            CheckpointId::new("c1"),
            CheckpointClass::VmFull,
            "vm",
        )
        .content(vec![
            ContentBlob { name: "rootfs.ext4".into(), sha256: "aa".into() },
            ContentBlob { name: "memory.bin".into(), sha256: "bb".into() },
            ContentBlob { name: "machine-id".into(), sha256: "cc".into() },
        ])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        let json = serde_json::to_string(&meta).unwrap();
        let back: CheckpointMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.content.len(), 3);
        assert_eq!(back.content[1].name, "memory.bin");
    }

    #[test]
    fn content_blob_roundtrips_and_denies_unknown() {
        let b: ContentBlob = serde_json::from_str(r#"{"name":"x","sha256":"y"}"#).unwrap();
        assert_eq!(b.name, "x");
        assert!(serde_json::from_str::<ContentBlob>(r#"{"name":"x","sha256":"y","z":1}"#).is_err());
    }
```
(Update any existing test that used `.content_sha256(...)` / `meta.content_sha256` to the manifest form.)

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-core checkpoint:: 2>&1 | tail -15` → compile error (`ContentBlob`/`.content` absent).

- [ ] **Step 3: Implement** — add `ContentBlob`, swap the field, update the builder:

```rust
/// One named artifact inside a checkpoint's `content/` dir, with its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentBlob {
    pub name: String,
    pub sha256: String,
}
```
In `CheckpointMeta`, replace `pub content_sha256: String,` with `pub content: Vec<ContentBlob>,`. In `CheckpointMeta::builder`, replace the `content_sha256: String::new(),` initializer with `content: Vec::new(),`. In `CheckpointMetaBuilder`: replace the `content_sha256` field with `content: Vec<ContentBlob>`, replace the `content_sha256(...)` method with:
```rust
    pub fn content(mut self, content: Vec<ContentBlob>) -> Self {
        self.content = content;
        self
    }
```
and update `build()` to move `content`.

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-core checkpoint:: 2>&1 | tail -15` → green.
- [ ] **Step 5: Guard runtime-free** — `cargo xtask check-core-runtime-free 2>&1 | tail -3` → passes.
- [ ] **Step 6: Commit**
```bash
git add crates/mvm-core/src/checkpoint.rs
git commit -m "feat(checkpoint): content manifest (Vec<ContentBlob>) replacing single hash"
```

---

## Task 3: Manifest integrity verify + fs_quick on the manifest (mvm-backend)

Update `capture_fs_quick` and `fork_checkpoint` to the manifest; replace `only_file_in` with a manifest verify that works for one *or* many blobs.

**Files:**
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs`

- [ ] **Step 1: Write/adjust the failing tests** — the existing fork tests (`fork_clones_content_and_records_lineage`, `fork_refuses_tampered_content`, `fork_refuses_multi_file_content`) must keep passing under the new model, except `fork_refuses_multi_file_content` changes meaning (multi-file is now valid for vm_full; for fs_quick the manifest has exactly one entry). Update that test to assert tamper-detection via the manifest instead, and add:

```rust
    #[test]
    fn verify_content_passes_for_intact_blobs_and_fails_on_tamper() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        // intact
        verify_content(&store, &parent).unwrap();
        // tamper the single blob
        let blob = store.content_dir(&parent.id).join("rootfs.ext4");
        std::fs::write(&blob, b"tampered").unwrap();
        assert!(verify_content(&store, &parent).is_err());
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-backend checkpoint::tests::verify_content 2>&1 | tail -12` → `verify_content` absent.

- [ ] **Step 3: Implement** — replace `only_file_in` with a manifest-driven verify, and make `capture_fs_quick`/`fork_checkpoint` build/consume `content`:

```rust
/// Verify every blob named in `meta.content` exists in the checkpoint's content
/// dir and hashes to its recorded value. Fail-closed: any missing or mismatched
/// blob is an error.
pub fn verify_content(store: &CheckpointStore, meta: &CheckpointMeta) -> Result<()> {
    let dir = store.content_dir(&meta.id);
    for blob in &meta.content {
        let path = dir.join(&blob.name);
        let actual = sha256_file_hex(&path)
            .with_context(|| format!("hashing checkpoint blob {}", path.display()))?;
        if actual != blob.sha256 {
            anyhow::bail!(
                "checkpoint '{}' blob {:?} failed integrity (sha256): expected {}, got {}",
                meta.id, blob.name, blob.sha256, actual
            );
        }
    }
    Ok(())
}
```
In `capture_fs_quick`, after cloning, build a one-entry manifest:
```rust
    let name = file_name.to_string_lossy().into_owned();
    let content_sha256 = sha256_file_hex(&dst)?;
    let meta = CheckpointMeta::builder(params.id, CheckpointClass::FsQuick, params.vm_name)
        .tag(params.tag)
        .created_unix(params.created_unix)
        .content(vec![mvm_core::checkpoint::ContentBlob { name, sha256: content_sha256 }])
        .supervisor_config_digest(params.supervisor_config_digest)
        .build();
```
In `fork_checkpoint`, replace the `only_file_in` + single-hash check with `verify_content(store, &parent)?`, then clone EACH blob in `parent.content` into `dest_dir`, and set the child's `.content(parent.content.clone())` (the child's blobs are byte-identical clones, same hashes). Delete the now-unused `only_file_in`. Keep the `VmFull`-class guard for now (Task 7 replaces it).

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-backend checkpoint::tests 2>&1 | tail -15` → all green.
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-backend/src/checkpoint/mod.rs
git commit -m "feat(checkpoint): manifest-based integrity verify; fs_quick on the manifest"
```

---

## Task 4: `VmFullControl` trait + `capture_vm_full` (mvm-backend)

Abstract the Vz I/O behind a trait so the capture *orchestration* (pause→save→clone→resume order) is unit-testable, then implement `capture_vm_full`.

**Files:**
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs`

- [ ] **Step 1: Write the failing test** — with a recording mock that asserts ordering and produces fake blobs:

```rust
    use std::cell::RefCell;

    struct MockControl {
        rootfs: PathBuf,
        events: RefCell<Vec<&'static str>>,
    }
    impl VmFullControl for MockControl {
        fn pause(&self) -> Result<()> { self.events.borrow_mut().push("pause"); Ok(()) }
        fn resume(&self) -> Result<()> { self.events.borrow_mut().push("resume"); Ok(()) }
        fn save_memory(&self, memory_path: &Path) -> Result<()> {
            self.events.borrow_mut().push("save");
            std::fs::write(memory_path, b"mem").unwrap();
            std::fs::write(format!("{}.machine-id", memory_path.display()), b"mid").unwrap();
            Ok(())
        }
        fn rootfs_path(&self) -> Result<PathBuf> { Ok(self.rootfs.clone()) }
    }

    #[test]
    fn capture_vm_full_orders_pause_save_clone_resume_and_builds_triple() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = tmp.path().join("live-rootfs.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        let ctl = MockControl { rootfs, events: RefCell::new(vec![]) };
        let meta = capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: CheckpointId::new("v1"),
                vm_name: "vm".into(),
                supervisor_config_digest: "d".into(),
                tag: None,
                created_unix: 9,
            },
            &ctl,
        ).unwrap();
        // ordering: pause must precede save, save precede resume
        assert_eq!(*ctl.events.borrow(), vec!["pause", "save", "resume"]);
        // triple present + verifiable
        assert_eq!(meta.class, CheckpointClass::VmFull);
        let names: Vec<_> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"rootfs.ext4") && names.contains(&"memory.bin") && names.contains(&"machine-id"));
        verify_content(&store, &meta).unwrap();
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-backend capture_vm_full_orders 2>&1 | tail -12` → trait/fn absent.

- [ ] **Step 3: Implement** — the trait + capture. The rootfs clone happens **between** save and resume (inside the pause window):

```rust
/// Host-side control over a running VM's memory + disk, abstracted so the
/// capture orchestration is testable without a live hypervisor.
pub trait VmFullControl {
    /// Pause vCPUs (idempotent if already paused).
    fn pause(&self) -> Result<()>;
    /// Save machine memory state to `memory_path` while paused; also writes a
    /// `<memory_path>.machine-id` sidecar.
    fn save_memory(&self, memory_path: &Path) -> Result<()>;
    /// Resume vCPUs.
    fn resume(&self) -> Result<()>;
    /// Absolute path to the VM's live rootfs image.
    fn rootfs_path(&self) -> Result<PathBuf>;
}

pub struct CaptureVmFullParams {
    pub id: CheckpointId,
    pub vm_name: String,
    pub supervisor_config_digest: String,
    pub tag: Option<String>,
    pub created_unix: u64,
}

/// Capture a running VM's consistent {rootfs, memory, machine-id} triple in one
/// pause window. The disk clone happens while paused so memory and disk match.
pub fn capture_vm_full(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
) -> Result<CheckpointMeta> {
    use mvm_core::checkpoint::ContentBlob;
    let content_dir = store.content_dir(&params.id);
    std::fs::create_dir_all(&content_dir)
        .with_context(|| format!("creating {}", content_dir.display()))?;

    let memory = content_dir.join("memory.bin");
    let rootfs_dst = content_dir.join("rootfs.ext4");
    let machine_id = content_dir.join("machine-id");

    control.pause().context("pausing VM for vm_full capture")?;
    // From here, RESUME on every exit path so a failure never strands the guest.
    let captured = (|| {
        control.save_memory(&memory).context("saving machine memory")?;
        let live_rootfs = control.rootfs_path()?;
        crate::base::cow::clone_rootfs_for_instance(&live_rootfs, &rootfs_dst)
            .context("cloning rootfs in the pause window")?;
        let sidecar = PathBuf::from(format!("{}.machine-id", memory.display()));
        std::fs::rename(&sidecar, &machine_id)
            .or_else(|_| std::fs::copy(&sidecar, &machine_id).map(|_| ()))
            .with_context(|| format!("collecting machine-id sidecar {}", sidecar.display()))?;
        Ok::<(), anyhow::Error>(())
    })();
    let resumed = control.resume();
    captured?;
    resumed.context("resuming VM after vm_full capture")?;

    let content = vec![
        ContentBlob { name: "rootfs.ext4".into(), sha256: sha256_file_hex(&rootfs_dst)? },
        ContentBlob { name: "memory.bin".into(), sha256: sha256_file_hex(&memory)? },
        ContentBlob { name: "machine-id".into(), sha256: sha256_file_hex(&machine_id)? },
    ];
    let meta = CheckpointMeta::builder(params.id, CheckpointClass::VmFull, params.vm_name)
        .tag(params.tag)
        .created_unix(params.created_unix)
        .content(content)
        .supervisor_config_digest(params.supervisor_config_digest)
        .build();
    store.write_meta(&meta)?;
    Ok(meta)
}
```

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-backend checkpoint::tests 2>&1 | tail -12` → green.
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-backend/src/checkpoint/mod.rs
git commit -m "feat(checkpoint): VmFullControl trait + capture_vm_full pause-window capture"
```

---

## Task 5: `VzVmFullControl` impl (mvm-backend/vz.rs)

Wire the trait to the real Vz control verbs.

**Files:**
- Modify: `crates/mvm-backend/src/vz.rs`

- [ ] **Step 1: Write the failing test** — a construction/path test (no live VM):
```rust
    #[test]
    fn vz_vm_full_control_resolves_rootfs_from_supervisor_config() {
        // Build a temp state dir with a supervisor-config.json naming a rootfs disk,
        // assert rootfs_path() returns it. (Mirror vz_rootfs_from_supervisor_config.)
        // ... construct VzVmFullControl { vm_name } against a temp MVM_DATA_DIR ...
    }
```
(Match the real `VzBackend` test idioms in the file; if a full path test is awkward, at minimum a doc-test-free unit asserting the SAVE/PAUSE/RESUME command strings are well-formed.)

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement** — reuse `vz_control` + the existing `snapshot_save`/`pause`/`resume` plumbing. Note the pause-ordering trick: because the supervisor's `save()` only resumes if the VM *was running*, calling our `pause()` first means the subsequent `SAVE` saves-while-paused and does not resume:

```rust
pub struct VzVmFullControl {
    vm_name: String,
}
impl VzVmFullControl {
    pub fn new(vm_name: impl Into<String>) -> Self { Self { vm_name: vm_name.into() } }
    fn sock(&self) -> std::path::PathBuf {
        vz_control::control_socket_path(&vm_state_dir(&self.vm_name))
    }
}
impl crate::checkpoint::VmFullControl for VzVmFullControl {
    fn pause(&self) -> anyhow::Result<()> {
        vz_control::send_command(&self.sock(), "PAUSE").map(|_| ())
    }
    fn resume(&self) -> anyhow::Result<()> {
        vz_control::send_command(&self.sock(), "RESUME").map(|_| ())
    }
    fn save_memory(&self, memory_path: &std::path::Path) -> anyhow::Result<()> {
        if !memory_path.is_absolute() {
            anyhow::bail!("save_memory requires an absolute path");
        }
        // Already paused by capture orchestration → SAVE saves-while-paused and
        // leaves the guest paused; the .machine-id sidecar is written alongside.
        vz_control::send_command(&self.sock(), &format!("SAVE {}", memory_path.display())).map(|_| ())
    }
    fn rootfs_path(&self) -> anyhow::Result<std::path::PathBuf> {
        let state_dir = vm_state_dir(&self.vm_name);
        // reuse the same resolution the CLI uses for the rootfs disk
        let cfg: vz::SupervisorConfig = serde_json::from_slice(
            &std::fs::read(state_dir.join(SUPERVISOR_CONFIG_FILE_NAME))?
        )?;
        cfg.disks.iter().find(|d| d.id == "rootfs")
            .map(|d| std::path::PathBuf::from(&d.path))
            .context("supervisor config has no rootfs disk")
    }
}
```

- [ ] **Step 4: Run to verify pass + clippy.**
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-backend/src/vz.rs
git commit -m "feat(vz): VzVmFullControl bridging vm_full capture to control verbs"
```

---

## Task 6: `restore_checkpoint` (same-identity resume)

**Files:**
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs` (orchestration), `crates/mvm-backend/src/vz.rs` (reuse `snapshot_restore`)

`restore_checkpoint` verifies the manifest, copies the checkpoint's `rootfs.ext4` back onto the VM's live rootfs path (so disk matches the saved memory), then delegates to the existing `VzBackend::snapshot_restore(id, memory.bin, machine-id)`. No `StartupMode` change — the rootfs is put in place *before* the restore spawn.

- [ ] **Step 1: Write the failing test** — orchestration via a restore seam mock asserting: verify → rootfs materialized at the target → restore invoked with (memory, machine-id):
```rust
    #[test]
    fn restore_checkpoint_materializes_rootfs_then_restores() {
        // seed a vm_full checkpoint (use capture_vm_full + MockControl),
        // call restore_checkpoint with a MockRestore that records the memory +
        // machine-id paths it was handed and a dest rootfs path it should receive;
        // assert the dest rootfs now holds the checkpoint's rootfs bytes and the
        // restore seam saw memory.bin + machine-id.
    }
```
(Define a small `trait VmFullRestore { fn restore(&self, rootfs_dst: &Path, memory: &Path, machine_id: &Path) -> Result<()>; }` mocked in the test; `VzBackend` implements it by copying the rootfs then calling `snapshot_restore`.)

- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement** `RestoreParams { checkpoint: CheckpointId, target_vm: String }`, `restore_checkpoint(store, params, restore: &dyn VmFullRestore)`: read+`verify_content`, refuse non-`VmFull`, resolve the three blob paths, call `restore.restore(...)`. The `VzBackend` `VmFullRestore` impl: `clone_rootfs_for_instance(content/rootfs.ext4 → vm_state_dir(target)/rootfs.ext4)` then `self.snapshot_restore(&VmId(target), memory, Some(machine_id))`.
- [ ] **Step 4: Run → green; clippy.**
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-backend/src/checkpoint/mod.rs crates/mvm-backend/src/vz.rs
git commit -m "feat(checkpoint): restore_checkpoint same-identity resume"
```

---

## Task 7: `vm_full` fork arm (spike-parameterized)

**Files:**
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs`, `crates/mvm-backend/src/vz.rs`

Replace `fork_checkpoint`'s `VmFull` refusal. The mechanics are identical to fs_quick fork (verify + clone all blobs into the child's dest dir + lineage meta) PLUS building a child supervisor-config with a new identity and spawning it in restore mode. **Two parameters come from Task 1's decision record** — set these two consts from it:
```rust
// From the spike decision record (Task 1).
const FORK_FRESH_MACHINE_ID: bool = true;   // false → inherit parent's machine-id
const FORK_ALLOW_PARENT_RUNNING: bool = true; // false → require parent VM stopped (semantic B)
```

- [ ] **Step 1: Write the failing tests** — `build_child_supervisor_config` is a pure function (no spawn) → fully unit-testable:
```rust
    #[test]
    fn child_config_gets_new_name_mac_and_restore_mode() {
        // given a parent SupervisorConfig (construct a minimal one), produce a
        // child config for "childvm" pointed at the child's memory.bin:
        let child = build_child_supervisor_config(&parent_cfg, "childvm", "/d/childvm", "/d/childvm/memory.bin", /*machine_id*/ None).unwrap();
        assert_eq!(child.name, "childvm");
        assert_ne!(child_mac(&child), child_mac(&parent_cfg)); // new MAC via derive_mac(name)
        assert!(matches!(child.startup_mode, mvm_build::vz::StartupMode::Restore { .. }));
    }
```
Plus a `fork_checkpoint` vm_full test using a mock spawn seam asserting blobs cloned + child config built + lineage recorded (no live VM).

- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement** — `build_child_supervisor_config(parent_cfg, child_name, child_state_dir, memory_path, machine_id_path) -> SupervisorConfig`: clone parent_cfg, set `name = child_name` (the supervisor rebuilds the MAC from the name via `derive_mac` at boot — confirm by reading how `vz.rs:1071` derives it; if MAC is baked in the config, set it explicitly to `host_gvproxy::derive_mac(child_name)`), set `vm_state_dir`, rewrite disk paths into the child dir, set `startup_mode = Restore { snapshot_path: memory_path, machine_id_path }`. Route `fork_checkpoint`: if `parent.class == VmFull`, verify+clone all blobs into `dest_dir`, build the child config (machine_id per `FORK_FRESH_MACHINE_ID`), enforce `FORK_ALLOW_PARENT_RUNNING` (if false, refuse when the parent VM PID is live), spawn via the child config (reuse the `snapshot_restore` spawn path factored into a `spawn_supervisor_with_config` helper), write lineage meta. Auto-boot is inherent (the spawn resumes).
- [ ] **Step 4: Run → green; clippy.**
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-backend/src/checkpoint/mod.rs crates/mvm-backend/src/vz.rs
git commit -m "feat(checkpoint): vm_full fork arm (new-identity restore)"
```

---

## Task 8: Audit `checkpoint.restored` + expose bind helpers

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/audit_chain.rs`, `crates/mvm-cli/src/commands/vm/checkpoint.rs`, `tests/audit_total_coverage.rs`

- [ ] **Step 1: Add `emit_checkpoint_restored`** mirroring `emit_checkpoint_forked`:
```rust
    pub fn emit_checkpoint_restored(
        &self,
        plan: &ExecutionPlan,
        checkpoint_id: &str,
        vm_name: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "checkpoint.restored",
            [
                ("checkpoint_id".to_string(), checkpoint_id.to_string()),
                ("vm_name".to_string(), vm_name.to_string()),
            ],
        )
    }
```
- [ ] **Step 2: Add `LocalAuditKind::CheckpointRestored`** in `crates/mvm-core/src/policy/audit.rs` (beside `CheckpointForked`), and register `"CheckpointRestored"` + the `("restore", AuditPosture::Emits("CheckpointRestored"))` row in `CHECKPOINT_SUB` in `tests/audit_total_coverage.rs`.
- [ ] **Step 3: Make `bind_checkpoint_created/forked` `pub(crate)` and add `bind_checkpoint_restored`** in checkpoint.rs (same best-effort vs fatal posture: restore best-effort like create). Emitter tests + coverage test.

> **Library-API note (investigate):** the design calls for the bind helpers to be reachable by `mvmd`. They depend on `AuditEmitter`/`host_signer`/`plan_persist`, which live in `mvm-cli` (a bin crate mvmd does not consume). Fully hoisting them to a lib is a larger refactor. For PR2, make them `pub(crate)` (clean in-crate API) and record in the design doc that **mvmd-reachable audit binding requires hoisting `AuditEmitter` to a lib crate** — a tracked follow-up, not PR2 scope. The *operations* (capture/restore/fork) ARE already lib API in `mvm-backend`, which satisfies the core library-API requirement; the audit binding is the one piece still CLI-bound.

- [ ] **Step 4: Run** `cargo test -p mvm-cli checkpoint_ 2>&1 | tail -8` + `cargo test --test audit_total_coverage 2>&1 | tail -8` → green.
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-core/src/policy/audit.rs crates/mvm-cli/src/commands/vm/audit_chain.rs crates/mvm-cli/src/commands/vm/checkpoint.rs tests/audit_total_coverage.rs
git commit -m "feat(audit): checkpoint.restored event + pub(crate) bind helpers"
```

---

## Task 9: CLI — `--class`, `restore`, route vm_full, retire `snapshot save/restore`

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/checkpoint.rs`, `crates/mvm-cli/src/commands/vm/pause.rs`, `crates/mvm-cli/src/commands/tests.rs`

- [ ] **Step 1: Write the failing parse tests:**
```rust
    #[test]
    fn test_checkpoint_create_vm_full_parses() {
        let cli = Cli::try_parse_from(["mvmctl","checkpoint","create","myvm","--class","vm-full"]).unwrap();
        assert!(matches!(cli.command, Commands::Checkpoint(vm::checkpoint::CheckpointArgs { command: vm::checkpoint::CheckpointCmd::Create { .. } })));
    }
    #[test]
    fn test_checkpoint_restore_parses() {
        assert!(Cli::try_parse_from(["mvmctl","checkpoint","restore","ckpt-abc"]).is_ok());
    }
    #[test]
    fn test_snapshot_save_is_gone() {
        assert!(Cli::try_parse_from(["mvmctl","snapshot","save","vm","--path","/x"]).is_err());
    }
```
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement:**
  - Add `#[arg(long, value_enum, default_value = "fs-quick")] class: CheckpointClassArg` to `Create` (a small clap `ValueEnum { FsQuick, VmFull }`). Route: `FsQuick` → existing `create` (quiesced); `VmFull` → new `create_vm_full(name, tag, json)` which requires the VM **running** (invert `vm_is_running`), builds `VzVmFullControl::new(name)`, calls `capture_vm_full`, binds `checkpoint.created` with class `"vm_full"`.
  - Add `Restore { id: String }` subcommand → `restore(id)`: validate id, read meta, build the `VzBackend` restore seam, call `restore_checkpoint`, bind `checkpoint.restored`.
  - `fork` already routes through `fork_checkpoint`, which now handles `vm_full` — make `fork`'s success message note auto-boot for vm_full.
  - In `pause.rs`, delete the `Save`/`Restore` arms of `SnapshotCmd` (keep `Ls`/`Rm`); update `run_snapshot` dispatch. Update any help/registration so `snapshot save/restore` no longer parse.
- [ ] **Step 4: Run** `cargo test -p mvm-cli test_checkpoint_ test_snapshot 2>&1 | tail -15` → green; `cargo clippy -p mvm-cli -- -D warnings`.
- [ ] **Step 5: Commit**
```bash
git add -A
git commit -m "feat(cli): checkpoint --class vm_full + restore; retire snapshot save/restore"
```

---

## Task 10: Full gates + rollup + PR

- [ ] **Step 1:** `cargo fmt --all` → `cargo clippy --workspace -- -D warnings` (zero) → `cargo nextest run --workspace -E 'not package(mvm-backend)'` + `cargo nextest run -p mvm-backend -E 'test(checkpoint) or test(vz)'` (the mvm-backend codesign-SIGKILL workaround) → `cargo test --workspace --doc`. Fix any REAL failure in checkpoint/vz code; known `HOME_TEST_LOCK`/fs2-flock flakes pass single-threaded — confirm, don't chase.
- [ ] **Step 2:** Update `specs/REFACTOR-STATUS.md` PLAN 159 WS-2 line to note vm_full + restore + fork landed (PR3 = `checkpoint diff` + pause/resume wiring remains); bump the date. Tick the matching items in `specs/plans/159-vz-inspired-macos-dx.md`.
- [ ] **Step 3:** Commit docs; push; open the PR (the controller does the final review + finishing-a-development-branch).

---

## Notes for the implementer
- Tasks 2-9 are host-side unit-testable via the `VmFullControl`/restore/spawn seams; the **live Vz round-trip is Task 1's spike** + one optional manual validation.
- Keep the CLI thin: all capture/restore/fork logic stays in `mvm-backend::checkpoint`; the CLI resolves args, builds the Vz seam impls, and binds audit.
- No process-artifact references in code comments. Reuse `clone_rootfs_for_instance`, `sha256_file`, `vz_control`, `snapshot_restore`, `derive_mac` — do not reimplement.

---

## Deferred follow-ups (tracked; not PR2 scope)

- [ ] **Hoist `AuditEmitter` (+ `host_signer`, `plan_persist`) into a library crate** so the
      checkpoint audit binding (`bind_checkpoint_created/restored/forked`) is reachable by
      `mvmd`, not just the `mvm-cli` binary. Agreed as the **next** change after PR2 (option b
      from the PR2 scope decision). The checkpoint *operations* are already library API in
      `mvm-backend`; this closes the remaining gap so mvmd-driven checkpoints/forks emit
      identical chain-signed `checkpoint.*` events. Likely lands the emitter in `mvm-hostd`
      (which already owns the supervisor-side audit + `verify_audit_chain`) or a small
      `mvm-core::audit` seam, with `mvm-cli` consuming it.
