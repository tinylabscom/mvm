# Plan 159 WS-2 PR3 — `checkpoint diff` + Vz `pause/resume` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish Plan 159 WS-2 — add `mvmctl checkpoint diff <a> <b>` (metadata + manifest comparison) and wire `mvmctl pause/resume` to the Vz backend (native vCPU quiesce), leaving Firecracker's sealed-snapshot pause untouched.

**Architecture:** A pure `diff_checkpoints(meta_a, meta_b) -> CheckpointDiff` in `mvm-backend::checkpoint` (the CLI reads both metas and renders). For pause/resume: add a `vz.pid` arm to `AnyBackend::for_started_vm`, then branch `run_pause`/`run_resume` — a resolved Vz VM dispatches to `VzBackend::pause()`/`resume()`; everything else keeps the existing `snapshot_io_for` seal path.

**Tech Stack:** Rust 2024, serde, clap. Reuses the merged checkpoint subsystem (`CheckpointStore`/`CheckpointMeta`/`ContentBlob`), `AnyBackend`/`VmId`, the `vz_control` PAUSE/RESUME verbs.

**Design doc:** `specs/notes/plan-159-ws2-pr3-diff-pause-resume-design.md`
**Worktree:** `../mvm-159-ws2pr3` (branch `feat/plan-159-ws2-pr3`).

**Standing rules:** library-first (pure helper in mvm-backend, CLI thin); no `clippy::too_many_arguments` suppression; no spec/PR/plan refs in code comments; no `Co-Authored-By`; `cargo fmt --all`; clippy `-D warnings`. `mvm-backend` SIGKILLs under nextest on this macOS host — use plain `cargo test` for targeted runs; known `HOME_TEST_LOCK`/fs2-flock flakes pass single-threaded.

**Ground-truth pins:**
- `CheckpointMeta { id: CheckpointId, class: CheckpointClass, vm_name: String, tag: Option<String>, parent: Option<CheckpointId>, created_unix: u64, content: Vec<ContentBlob>, supervisor_config_digest: String, audit_ref: Option<String> }`; `ContentBlob { name: String, sha256: String }`. `CheckpointClass { FsQuick, VmFull }` (serde `rename_all = "snake_case"`). `CheckpointId::new(s)` / `.as_str()`. `CheckpointStore::open()` / `.read_meta(&id) -> Result<CheckpointMeta>`.
- `AnyBackend::for_started_vm(name) -> Option<AnyBackend>` (probes `qemu.pid`/`libkrun.pid`/`fc.pid`); `AnyBackend::Vz(VzBackend)` variant exists; `VzBackend` is a unit struct; `AnyBackend::pause/resume` forward to the inner `VmBackend`. `VzBackend::pause/resume` send `PAUSE`/`RESUME` via `vz_control`. `vz::PID_FILE_NAME = "vz.pid"`. `VmId::from(&str)`.
- `mvm-cli/.../vm/checkpoint.rs`: `CheckpointCmd` enum (`Create/Restore/Ls/Rm/Fork`), `run_checkpoint` dispatch, `validated_checkpoint_id`, `ls(json)`, imports `CheckpointStore`, `class_str` from `mvm_hostd::audit::bind`, `crate::json_out::emit_json`, `crate::ui`.
- `mvm-cli/.../vm/pause.rs`: `PauseArgs`/`ResumeArgs` (`name`, `--hypervisor` default `firecracker`), `run_pause`/`run_resume`, `snapshot_io_for`, registry `set_paused`/`touch_last_active`, `mvm_core::audit_emit!(WorkloadSleep/WorkloadWake, ...)`, `signal_post_restore`.

---

## File Structure

| File | Change |
|------|--------|
| `crates/mvm-backend/src/checkpoint/mod.rs` | `diff_checkpoints` + `CheckpointDiff`/`BlobDelta`/`BlobStatus`/`LineageRelation` |
| `crates/mvm-backend/src/backend.rs` | `vz.pid` arm in `for_started_vm` |
| `crates/mvm-cli/src/commands/vm/checkpoint.rs` | `Diff { a, b, json }` subcommand + `diff()` render |
| `crates/mvm-cli/src/commands/vm/pause.rs` | Vz dispatch branch in `run_pause`/`run_resume` |
| `crates/mvm-cli/src/commands/tests.rs` (or the checkpoint/pause test modules) | parse tests |
| `specs/REFACTOR-STATUS.md`, `specs/plans/159-vz-inspired-macos-dx.md` | flip WS-2 to done |

---

## Task 1: `diff_checkpoints` pure helper (mvm-backend)

**Files:**
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs`

- [ ] **Step 1: Write the failing tests** — add to the `#[cfg(test)] mod tests`:

```rust
    fn fs_quick_meta(id: &str, vm: &str, parent: Option<&str>, rootfs_sha: &str) -> CheckpointMeta {
        use mvm_core::checkpoint::ContentBlob;
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, vm)
            .parent(parent.map(CheckpointId::new))
            .content(vec![ContentBlob { name: "rootfs.ext4".into(), sha256: rootfs_sha.into() }])
            .supervisor_config_digest("cfg")
            .created_unix(10)
            .build()
    }

    #[test]
    fn diff_identical_metas_has_no_changes() {
        let a = fs_quick_meta("a", "vm", None, "aaaa");
        let b = fs_quick_meta("b", "vm", None, "aaaa");
        let d = diff_checkpoints(&a, &b);
        assert!(d.blobs.iter().all(|x| x.status == BlobStatus::Unchanged));
        assert!(d.supervisor_config_digest_same);
        assert_eq!(d.lineage, LineageRelation::Unrelated);
    }

    #[test]
    fn diff_detects_changed_blob() {
        let a = fs_quick_meta("a", "vm", None, "aaaa");
        let b = fs_quick_meta("b", "vm", None, "bbbb");
        let d = diff_checkpoints(&a, &b);
        let rootfs = d.blobs.iter().find(|x| x.name == "rootfs.ext4").unwrap();
        assert_eq!(rootfs.status, BlobStatus::Changed);
        assert_eq!(rootfs.sha_a.as_deref(), Some("aaaa"));
        assert_eq!(rootfs.sha_b.as_deref(), Some("bbbb"));
    }

    #[test]
    fn diff_detects_added_and_removed_blobs_cross_class() {
        use mvm_core::checkpoint::ContentBlob;
        let a = fs_quick_meta("a", "vm", None, "aaaa"); // rootfs only
        let b = CheckpointMeta::builder(CheckpointId::new("b"), CheckpointClass::VmFull, "vm")
            .content(vec![
                ContentBlob { name: "rootfs.ext4".into(), sha256: "aaaa".into() },
                ContentBlob { name: "memory.bin".into(), sha256: "mmmm".into() },
                ContentBlob { name: "machine-id".into(), sha256: "iiii".into() },
            ])
            .supervisor_config_digest("cfg")
            .created_unix(11)
            .build();
        let d = diff_checkpoints(&a, &b);
        let mem = d.blobs.iter().find(|x| x.name == "memory.bin").unwrap();
        assert_eq!(mem.status, BlobStatus::AddedInB);
        let rootfs = d.blobs.iter().find(|x| x.name == "rootfs.ext4").unwrap();
        assert_eq!(rootfs.status, BlobStatus::Unchanged);
        assert_eq!(d.class_a, CheckpointClass::FsQuick);
        assert_eq!(d.class_b, CheckpointClass::VmFull);
        // swapping flips added→removed
        let d2 = diff_checkpoints(&b, &a);
        let mem2 = d2.blobs.iter().find(|x| x.name == "memory.bin").unwrap();
        assert_eq!(mem2.status, BlobStatus::RemovedFromB);
    }

    #[test]
    fn diff_detects_child_lineage() {
        let a = fs_quick_meta("parent", "vm", None, "aaaa");
        let b = fs_quick_meta("child", "vm", Some("parent"), "aaaa");
        assert_eq!(diff_checkpoints(&a, &b).lineage, LineageRelation::BChildOfA);
        assert_eq!(diff_checkpoints(&b, &a).lineage, LineageRelation::AChildOfB);
    }

    #[test]
    fn checkpoint_diff_serializes() {
        let a = fs_quick_meta("a", "vm", None, "aaaa");
        let b = fs_quick_meta("b", "vm", None, "bbbb");
        let json = serde_json::to_string(&diff_checkpoints(&a, &b)).unwrap();
        assert!(json.contains("rootfs.ext4"));
        assert!(json.contains("changed"));
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-backend --lib checkpoint::tests::diff 2>&1 | tail -12` → types/fn absent.

- [ ] **Step 3: Implement** — add to `checkpoint/mod.rs` (the file already imports `mvm_core::checkpoint::{...}` and `serde`-derives elsewhere; add `Serialize` use if needed):

```rust
use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
use serde::Serialize;

/// How blob `name` differs between two checkpoints (B relative to A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobStatus {
    Unchanged,
    Changed,
    AddedInB,
    RemovedFromB,
}

/// Per-blob delta keyed by content-manifest name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlobDelta {
    pub name: String,
    pub status: BlobStatus,
    pub sha_a: Option<String>,
    pub sha_b: Option<String>,
}

/// Lineage relationship between the two checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageRelation {
    /// B's parent is A.
    BChildOfA,
    /// A's parent is B.
    AChildOfB,
    /// Same checkpoint id.
    Same,
    /// No direct parent link.
    Unrelated,
}

/// Structured metadata + manifest diff of two checkpoints (B relative to A).
/// Byte content is never read — a blob sha256 mismatch is the change signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointDiff {
    pub a_id: CheckpointId,
    pub b_id: CheckpointId,
    pub class_a: CheckpointClass,
    pub class_b: CheckpointClass,
    pub vm_name_a: String,
    pub vm_name_b: String,
    pub tag_a: Option<String>,
    pub tag_b: Option<String>,
    pub created_unix_a: u64,
    pub created_unix_b: u64,
    pub supervisor_config_digest_same: bool,
    pub lineage: LineageRelation,
    pub blobs: Vec<BlobDelta>,
}

/// Compare two checkpoint metadata records. Pure — no store/disk access.
pub fn diff_checkpoints(a: &CheckpointMeta, b: &CheckpointMeta) -> CheckpointDiff {
    let lineage = if a.id == b.id {
        LineageRelation::Same
    } else if b.parent.as_ref() == Some(&a.id) {
        LineageRelation::BChildOfA
    } else if a.parent.as_ref() == Some(&b.id) {
        LineageRelation::AChildOfB
    } else {
        LineageRelation::Unrelated
    };

    // Union of blob names, stable-sorted, each classified by side membership.
    let mut names: Vec<&str> = a.content.iter().map(|x| x.name.as_str()).collect();
    for blob in &b.content {
        if !names.contains(&blob.name.as_str()) {
            names.push(blob.name.as_str());
        }
    }
    names.sort_unstable();
    let sha_in = |m: &CheckpointMeta, name: &str| -> Option<String> {
        m.content.iter().find(|x| x.name == name).map(|x| x.sha256.clone())
    };
    let blobs = names
        .iter()
        .map(|name| {
            let sa = sha_in(a, name);
            let sb = sha_in(b, name);
            let status = match (&sa, &sb) {
                (Some(x), Some(y)) if x == y => BlobStatus::Unchanged,
                (Some(_), Some(_)) => BlobStatus::Changed,
                (Some(_), None) => BlobStatus::RemovedFromB,
                (None, Some(_)) => BlobStatus::AddedInB,
                (None, None) => unreachable!("name came from one of the two manifests"),
            };
            BlobDelta { name: name.to_string(), status, sha_a: sa, sha_b: sb }
        })
        .collect();

    CheckpointDiff {
        a_id: a.id.clone(),
        b_id: b.id.clone(),
        class_a: a.class,
        class_b: b.class,
        vm_name_a: a.vm_name.clone(),
        vm_name_b: b.vm_name.clone(),
        tag_a: a.tag.clone(),
        tag_b: b.tag.clone(),
        created_unix_a: a.created_unix,
        created_unix_b: b.created_unix,
        supervisor_config_digest_same: a.supervisor_config_digest == b.supervisor_config_digest,
        lineage,
        blobs,
    }
}
```
(If `CheckpointId`/`CheckpointClass`/`CheckpointMeta`/`Serialize` are already imported at the top of the file, don't duplicate the `use`.)

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-backend --lib checkpoint::tests 2>&1 | tail -12` → all green.
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-backend/src/checkpoint/mod.rs
git commit -m "feat(checkpoint): diff_checkpoints pure metadata+manifest comparison"
```

---

## Task 2: `mvmctl checkpoint diff` subcommand (mvm-cli)

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/checkpoint.rs`

- [ ] **Step 1: Write the failing parse test** — add to the checkpoint tests module (mirror the existing `test_checkpoint_*_parses` in `commands/tests.rs`; check where those live and add there):

```rust
    #[test]
    fn test_checkpoint_diff_parses() {
        let cli = Cli::try_parse_from(["mvmctl","checkpoint","diff","ckpt-a","ckpt-b","--json"]).unwrap();
        assert!(matches!(cli.command,
            Commands::Checkpoint(vm::checkpoint::CheckpointArgs {
                command: vm::checkpoint::CheckpointCmd::Diff { json: true, .. } })));
    }
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-cli test_checkpoint_diff_parses 2>&1 | tail -8` → no `Diff` variant.

- [ ] **Step 3: Implement** — add the `Diff` variant to `CheckpointCmd` (after `Fork`):
```rust
    /// Compare two checkpoints (metadata + content manifest; `b` relative to `a`).
    Diff {
        /// Baseline checkpoint id (`a`).
        a: String,
        /// Compared checkpoint id (`b`).
        b: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
```
Add the dispatch arm in `run_checkpoint`:
```rust
        CheckpointCmd::Diff { a, b, json } => diff(&a, &b, json),
```
Add the handler (uses `diff_checkpoints` + the existing `validated_checkpoint_id`, `CheckpointStore`, `class_str`, `crate::json_out::emit_json`, `crate::ui`):
```rust
fn diff(a: &str, b: &str, json: bool) -> Result<()> {
    let id_a = validated_checkpoint_id(a)?;
    let id_b = validated_checkpoint_id(b)?;
    let store = CheckpointStore::open();
    let meta_a = store
        .read_meta(&id_a)
        .with_context(|| format!("reading checkpoint {a:?}"))?;
    let meta_b = store
        .read_meta(&id_b)
        .with_context(|| format!("reading checkpoint {b:?}"))?;
    let d = mvm_backend::checkpoint::diff_checkpoints(&meta_a, &meta_b);

    if json {
        crate::json_out::emit_json(&d)?;
        return Ok(());
    }

    use mvm_backend::checkpoint::{BlobStatus, LineageRelation};
    ui::info(&format!("checkpoint diff: {a} -> {b}"));
    if d.class_a != d.class_b {
        ui::info(&format!("  class: {} -> {}", class_str(d.class_a), class_str(d.class_b)));
    }
    if d.vm_name_a != d.vm_name_b {
        ui::info(&format!("  vm:    {} -> {}", d.vm_name_a, d.vm_name_b));
    }
    if !d.supervisor_config_digest_same {
        ui::info("  supervisor config: changed");
    }
    let rel = match d.lineage {
        LineageRelation::BChildOfA => format!("{b} is a child of {a}"),
        LineageRelation::AChildOfB => format!("{a} is a child of {b}"),
        LineageRelation::Same => "same checkpoint id".to_string(),
        LineageRelation::Unrelated => "no direct lineage".to_string(),
    };
    ui::info(&format!("  lineage: {rel}"));
    println!("{:<20} STATUS", "BLOB");
    for blob in &d.blobs {
        let status = match blob.status {
            BlobStatus::Unchanged => "unchanged",
            BlobStatus::Changed => "changed",
            BlobStatus::AddedInB => "added",
            BlobStatus::RemovedFromB => "removed",
        };
        println!("{:<20} {}", blob.name, status);
    }
    Ok(())
}
```
(`mvm_backend::checkpoint::diff_checkpoints`/`BlobStatus`/`LineageRelation` are pub from Task 1. `class_str` is already imported from `mvm_hostd::audit::bind`. Add a `use anyhow::Context;` if `with_context` isn't already in scope — the file imports `anyhow::{Context, Result, bail}` per the ground-truth, so it is.)

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-cli test_checkpoint_diff_parses 2>&1 | tail -8`; `cargo build -p mvm-cli 2>&1 | tail -3`; `cargo clippy -p mvm-cli -- -D warnings 2>&1 | tail -6`.
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-cli/src/commands/vm/checkpoint.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(cli): mvmctl checkpoint diff <a> <b>"
```

---

## Task 3: `vz.pid` arm in `for_started_vm` (mvm-backend)

**Files:**
- Modify: `crates/mvm-backend/src/backend.rs`

- [ ] **Step 1: Write the failing test** — add to `backend.rs` tests (set `MVM_DATA_DIR` to a temp dir, write a `vz.pid`, assert the variant; match the file's existing env-lock idiom if present):

```rust
    #[test]
    fn for_started_vm_resolves_vz_by_marker() {
        let tmp = tempfile::tempdir().unwrap();
        // SAFE in tests; config reads MVM_DATA_DIR at call time.
        unsafe { std::env::set_var("MVM_DATA_DIR", tmp.path()) };
        let dir = mvm_core::config::vm_state_dir("vzvm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vz.pid"), "12345").unwrap();
        assert!(matches!(AnyBackend::for_started_vm("vzvm"), Some(AnyBackend::Vz(_))));
        unsafe { std::env::remove_var("MVM_DATA_DIR") };
    }
```
(If the file's existing `for_started_vm` test — the ground-truth mentioned `for_started_vm_resolves_owning_backend_by_marker` — uses a serial env-lock guard, reuse it.)

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-backend --lib for_started_vm_resolves_vz 2>&1 | tail -8` → currently returns `None` (no vz arm) → assert fails.

- [ ] **Step 3: Implement** — in `for_started_vm`, add the `vz.pid` arm after the `fc.pid` branch:
```rust
        } else if dir.join("fc.pid").is_file() {
            Some(Self::Firecracker(FirecrackerBackend))
        } else if dir.join("vz.pid").is_file() {
            Some(Self::Vz(VzBackend))
        } else {
            None
        }
```
Update the doc comment listing markers to include `Vz vz.pid`.

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-backend --lib for_started_vm 2>&1 | tail -8` → both the new vz test + the existing marker test pass.
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-backend/src/backend.rs
git commit -m "feat(backend): for_started_vm resolves Vz by vz.pid marker"
```

---

## Task 4: Vz dispatch in `run_pause`/`run_resume` (mvm-cli)

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/pause.rs`

The Vz VM dispatches to native `pause()`/`resume()` (vCPU quiesce); Firecracker/mock keep the existing seal path. A small testable predicate isolates the routing decision.

- [ ] **Step 1: Write the failing test** — add to pause.rs tests: the routing predicate resolves a `vz.pid` VM to the Vz path:
```rust
    #[test]
    fn is_vz_vm_true_for_vz_marker() {
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("MVM_DATA_DIR", tmp.path()) };
        let dir = mvm_core::config::vm_state_dir("vzvm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vz.pid"), "1").unwrap();
        assert!(is_vz_vm("vzvm"));
        assert!(!is_vz_vm("nope"));
        unsafe { std::env::remove_var("MVM_DATA_DIR") };
    }
```
(Match the file's env-lock idiom if its tests use one.)

- [ ] **Step 2: Run to verify it fails** — `cargo test -p mvm-cli is_vz_vm_true_for_vz_marker 2>&1 | tail -8` → `is_vz_vm` absent.

- [ ] **Step 3: Implement.** Add imports at the top of pause.rs: `use mvm_backend::AnyBackend;` and `use mvm_core::vm_backend::VmId;` (confirm the exact paths — `AnyBackend` is re-exported from `mvm_backend`; `VmId` is `mvm_core::vm_backend::VmId` or `mvm_core::protocol::vm_backend::VmId` — match how other CLI files import it). Add the predicate + the Vz branches:

```rust
/// A running VM whose state dir carries a `vz.pid` marker is a Vz VM — it gets
/// native vCPU pause/resume rather than the Firecracker snapshot-seal path.
fn is_vz_vm(name: &str) -> bool {
    matches!(AnyBackend::for_started_vm(name), Some(AnyBackend::Vz(_)))
}
```
In `run_pause`, before the `snapshot_io_for` line, branch:
```rust
    if is_vz_vm(&args.name) {
        AnyBackend::Vz(mvm_backend::vz::VzBackend)
            .pause(&VmId::from(args.name.as_str()))
            .with_context(|| format!("pausing Vz VM {:?}", args.name))?;
        let registry_path = mvm::vm::name_registry::registry_path();
        if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
            let _ = registry.set_paused(&args.name, true);
            let _ = registry.save(&registry_path);
        }
        println!("{}: paused (vz, vCPUs quiesced)", args.name);
        mvm_core::audit_emit!(WorkloadSleep, vm: &args.name, "backend=vz");
        return Ok(());
    }
```
In `run_resume`, before the `snapshot_io_for` line, branch (note: NO `signal_post_restore` — the guest never left memory):
```rust
    if is_vz_vm(&args.name) {
        AnyBackend::Vz(mvm_backend::vz::VzBackend)
            .resume(&VmId::from(args.name.as_str()))
            .with_context(|| format!("resuming Vz VM {:?}", args.name))?;
        let registry_path = mvm::vm::name_registry::registry_path();
        if let Ok(mut registry) = mvm::vm::name_registry::VmNameRegistry::load(&registry_path) {
            let _ = registry.set_paused(&args.name, false);
            let _ = registry.touch_last_active(&args.name, mvm_core::time::utc_now());
            let _ = registry.save(&registry_path);
        }
        println!("{}: resumed (vz, vCPUs running)", args.name);
        mvm_core::audit_emit!(WorkloadWake, vm: &args.name, "backend=vz");
        return Ok(());
    }
```
(`AnyBackend::Vz(VzBackend).pause(...)` uses the `AnyBackend::pause` forwarder. Alternatively call `mvm_backend::vz::VzBackend.pause(&id)` directly via the `VmBackend` trait — pick whichever resolves cleanly; `AnyBackend` is already imported for `is_vz_vm`. If calling the trait method directly needs `use mvm_core::vm_backend::VmBackend;` in scope, add it.)

Update the `PauseArgs`/`ResumeArgs` `--hypervisor` doc to note Vz VMs are auto-detected and quiesced (no `--hypervisor vz` needed).

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-cli is_vz_vm 2>&1 | tail -8`; `cargo build -p mvm-cli 2>&1 | tail -3`; `cargo clippy -p mvm-cli -- -D warnings 2>&1 | tail -8`. Confirm the existing FC/mock pause tests still pass: `cargo test -p mvm-cli --lib pause 2>&1 | tail -8`.
- [ ] **Step 5: Commit**
```bash
git add crates/mvm-cli/src/commands/vm/pause.rs
git commit -m "feat(cli): pause/resume dispatch Vz VMs to native vCPU quiesce"
```

---

## Task 5: Gates + rollup + PR

- [ ] **Step 1: Workspace gates.**
```bash
cargo fmt --all && cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings 2>&1 | tail -20
cargo nextest run --workspace -E 'not package(mvm-backend)' 2>&1 | tail -20
cargo test -p mvm-backend checkpoint:: 2>&1 | tail -6     # plain cargo test (nextest SIGKILLs mvm-backend)
cargo test -p mvm-backend for_started_vm 2>&1 | tail -4
cargo test --workspace --doc 2>&1 | tail -10
```
Fix REAL failures in the new code. Known `HOME_TEST_LOCK`/fs2-flock + degraded-builder-store flakes pass single-threaded / are pre-existing — confirm, don't chase.

- [ ] **Step 2: Flip WS-2 to done.** In `specs/REFACTOR-STATUS.md`, change the PLAN 159 `WS-2 checkpoint+fork` line from `[~]` to `[x]` and update its tail from `Remaining: checkpoint diff + pause/resume wiring (PR3)` to note both landed (PR3) — WS-2 complete. Bump `**Last updated:**` to 2026-06-11. In `specs/plans/159-vz-inspired-macos-dx.md`, tick the WS-2 `checkpoint diff` + `pause/resume` items.

- [ ] **Step 3: Commit + push + open PR** (controller runs final review + finishing-a-development-branch).
```bash
git add specs/REFACTOR-STATUS.md specs/plans/159-vz-inspired-macos-dx.md
git commit -m "docs(plan-159): WS-2 complete — checkpoint diff + Vz pause/resume"
```

---

## Notes for the implementer
- `diff_checkpoints` is pure (no store access) — fully unit-tested. The CLI reads the two metas and renders.
- The Vz pause/resume native path can't be unit-tested end-to-end (it hits a live control socket); the routing (`is_vz_vm` / `for_started_vm` vz arm) IS unit-tested. The live pause→resume round-trip is a manual-validation note, not a blocker (same constraint as PR1/PR2).
- Do NOT touch the Firecracker/mock seal path — it stays exactly as-is; Vz is an additive branch before it.
- No process-artifact refs in code comments; reuse `validated_checkpoint_id`, `class_str`, `for_started_vm`, the registry + `audit_emit!` helpers.
