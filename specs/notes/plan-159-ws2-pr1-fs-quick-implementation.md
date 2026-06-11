# Plan 159 WS-2 PR1 — `fs_quick` checkpoint + fork — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a unified, audit-bound `checkpoint` subsystem whose first class — `fs_quick` (APFS copy-on-write rootfs clone of a quiesced VM) — lets a user freeze a microVM's filesystem state and `fork` new sandbox instances from it in seconds.

**Architecture:** Pure checkpoint *types* in `mvm-core`; the *store + capture + fork* logic in `mvm-backend` (reusing `base::cow::clone_rootfs_for_instance`); audit kinds in `mvm-core::policy::audit` with emitters in `mvm-cli`; the `mvmctl checkpoint` command group + `cache prune` GC in `mvm-cli`. No new VMM code; all core logic is host-side and testable without booting a VM.

**Tech Stack:** Rust 2024, `serde` (`deny_unknown_fields`), `sha2`, `clap` derive, `tempfile` (tests), the existing `AuditEmitter` chain-signing spine.

**Design doc:** `specs/notes/plan-159-ws2-fs-quick-checkpoint-fork-design.md`

**Worktree:** `../mvm-159-ws2` (branch `feat/plan-159-ws2-checkpoint-fork`).

**Standing project rules that bind this plan:** all `~/.mvm` paths go through `mvm_core::config`; reuse before reimplementing; many small testable functions + builder pattern; no `clippy::too_many_arguments` suppression; no spec/PR/plan citations in code comments; no `Co-Authored-By: Claude` trailer; `cargo fmt --all`; `cargo nextest run --workspace` + `cargo clippy --workspace -- -D warnings` green before "done".

---

## File Structure

| File | Responsibility |
|------|----------------|
| `crates/mvm-core/src/checkpoint.rs` *(create)* | `CheckpointId`, `CheckpointClass`, `CheckpointMeta` + builder. Pure types, no runtime deps. |
| `crates/mvm-core/src/lib.rs` *(modify)* | `pub mod checkpoint;` |
| `crates/mvm-core/src/config.rs` *(modify)* | `checkpoints_dir()` helper. |
| `crates/mvm-backend/src/checkpoint/mod.rs` *(create)* | `CheckpointStore` (CRUD/tag/lineage), `capture_fs_quick`, `fork_checkpoint`. |
| `crates/mvm-backend/src/lib.rs` *(modify)* | `pub mod checkpoint;` |
| `crates/mvm-core/src/policy/audit.rs` *(modify)* | `CheckpointCreated`, `CheckpointForked` kinds. |
| `crates/mvm-cli/src/commands/vm/audit_chain.rs` *(modify)* | `emit_checkpoint_created` / `emit_checkpoint_forked`. |
| `tests/audit_total_coverage.rs` *(modify)* | register the two kinds + `checkpoint` posture. |
| `crates/mvm-core/src/protocol/vm_backend.rs` *(modify)* | `VmCapabilities.fs_quick_checkpoint` field. |
| `crates/mvm-backend/src/{vz,apple_container,libkrun,firecracker,docker,...}.rs` *(modify)* | set the new capability field. |
| `crates/mvm-cli/src/commands/vm/checkpoint.rs` *(create)* | `checkpoint create/ls/rm/fork` group + dispatch. |
| `crates/mvm-cli/src/commands/mod.rs` *(modify)* | register `Checkpoint` command. |
| `crates/mvm-cli/src/commands/ops/cache.rs` *(modify)* | untagged-checkpoint GC sweep. |
| `crates/mvm-cli/src/commands/tests.rs` *(modify)* | CLI parse tests. |

---

## Task 1: `CheckpointMeta` types (mvm-core)

**Files:**
- Create: `crates/mvm-core/src/checkpoint.rs`
- Modify: `crates/mvm-core/src/lib.rs` (add `pub mod checkpoint;` next to the other `pub mod` lines)

- [ ] **Step 1: Write the failing tests** — append to the new file's `#[cfg(test)]` after writing the types in Step 3; for TDD, first create `crates/mvm-core/src/checkpoint.rs` containing ONLY this test module so it fails to compile (types absent):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_roundtrips_through_json() {
        let meta = CheckpointMeta::builder(
            CheckpointId::new("ckpt-abc123"),
            CheckpointClass::FsQuick,
            "myvm",
        )
        .content_sha256("deadbeef")
        .supervisor_config_digest("cfg99")
        .tag(Some("golden".to_string()))
        .parent(Some(CheckpointId::new("ckpt-parent")))
        .created_unix(1_700_000_000)
        .build();

        let json = serde_json::to_string(&meta).unwrap();
        let back: CheckpointMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
        assert_eq!(back.class, CheckpointClass::FsQuick);
        assert_eq!(back.parent.unwrap().as_str(), "ckpt-parent");
    }

    #[test]
    fn meta_rejects_unknown_fields() {
        let json = r#"{"id":"x","class":"fs_quick","vm_name":"v","tag":null,
            "parent":null,"created_unix":1,"content_sha256":"h",
            "supervisor_config_digest":"d","audit_ref":null,"bogus":true}"#;
        assert!(serde_json::from_str::<CheckpointMeta>(json).is_err());
    }

    #[test]
    fn builder_defaults_are_none() {
        let meta = CheckpointMeta::builder(
            CheckpointId::new("c1"),
            CheckpointClass::FsQuick,
            "vm",
        )
        .content_sha256("h")
        .supervisor_config_digest("d")
        .created_unix(5)
        .build();
        assert!(meta.tag.is_none());
        assert!(meta.parent.is_none());
        assert!(meta.audit_ref.is_none());
    }

    #[test]
    fn class_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&CheckpointClass::VmFull).unwrap(),
            "\"vm_full\""
        );
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-core checkpoint:: 2>&1 | tail -20`
Expected: compile error — `CheckpointMeta` / `CheckpointId` / `CheckpointClass` not found.

- [ ] **Step 3: Write the implementation** — prepend above the test module in `crates/mvm-core/src/checkpoint.rs`:

```rust
//! Immutable, audit-bound records of frozen microVM state. A checkpoint is the
//! origin a `fork` clones a new sandbox instance from.

use serde::{Deserialize, Serialize};

/// Stable identifier for a checkpoint (also its on-disk directory name under
/// `config::checkpoints_dir()`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckpointId(String);

impl CheckpointId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The capture mechanism behind a checkpoint. Only `FsQuick` is populated in
/// this PR; `VmFull` is reserved so the later memory-state path slots into the
/// same model with no new surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointClass {
    /// APFS copy-on-write clone of a quiesced rootfs (filesystem only).
    FsQuick,
    /// Full machine memory state via the supervisor save/restore path.
    VmFull,
}

/// On-disk metadata for one checkpoint (`<checkpoints_dir>/<id>/meta.json`).
/// `audit_ref` is a non-load-bearing back-pointer backfilled after the
/// chain-signed entry is emitted; integrity verification relies on
/// `content_sha256`, not on `audit_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointMeta {
    pub id: CheckpointId,
    pub class: CheckpointClass,
    pub vm_name: String,
    pub tag: Option<String>,
    pub parent: Option<CheckpointId>,
    pub created_unix: u64,
    pub content_sha256: String,
    pub supervisor_config_digest: String,
    pub audit_ref: Option<String>,
}

impl CheckpointMeta {
    pub fn builder(
        id: CheckpointId,
        class: CheckpointClass,
        vm_name: impl Into<String>,
    ) -> CheckpointMetaBuilder {
        CheckpointMetaBuilder {
            id,
            class,
            vm_name: vm_name.into(),
            tag: None,
            parent: None,
            created_unix: 0,
            content_sha256: String::new(),
            supervisor_config_digest: String::new(),
            audit_ref: None,
        }
    }
}

/// Builder so callers set only the fields they have; avoids a long positional
/// constructor.
pub struct CheckpointMetaBuilder {
    id: CheckpointId,
    class: CheckpointClass,
    vm_name: String,
    tag: Option<String>,
    parent: Option<CheckpointId>,
    created_unix: u64,
    content_sha256: String,
    supervisor_config_digest: String,
    audit_ref: Option<String>,
}

impl CheckpointMetaBuilder {
    pub fn tag(mut self, tag: Option<String>) -> Self {
        self.tag = tag;
        self
    }
    pub fn parent(mut self, parent: Option<CheckpointId>) -> Self {
        self.parent = parent;
        self
    }
    pub fn created_unix(mut self, secs: u64) -> Self {
        self.created_unix = secs;
        self
    }
    pub fn content_sha256(mut self, h: impl Into<String>) -> Self {
        self.content_sha256 = h.into();
        self
    }
    pub fn supervisor_config_digest(mut self, d: impl Into<String>) -> Self {
        self.supervisor_config_digest = d.into();
        self
    }
    pub fn audit_ref(mut self, r: Option<String>) -> Self {
        self.audit_ref = r;
        self
    }
    pub fn build(self) -> CheckpointMeta {
        CheckpointMeta {
            id: self.id,
            class: self.class,
            vm_name: self.vm_name,
            tag: self.tag,
            parent: self.parent,
            created_unix: self.created_unix,
            content_sha256: self.content_sha256,
            supervisor_config_digest: self.supervisor_config_digest,
            audit_ref: self.audit_ref,
        }
    }
}
```

Then add to `crates/mvm-core/src/lib.rs` (alphabetically among the `pub mod` lines, e.g. right after `pub mod catalog;` / before `pub mod config;`):

```rust
pub mod checkpoint;
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mvm-core checkpoint:: 2>&1 | tail -20`
Expected: 4 passed.

- [ ] **Step 5: Guard the runtime-free invariant** — `mvm-core` must stay async-free.

Run: `cargo xtask check-core-runtime-free 2>&1 | tail -5`
Expected: passes (the new module pulls only `serde`).

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-core/src/checkpoint.rs crates/mvm-core/src/lib.rs
git commit -m "feat(checkpoint): CheckpointMeta types + builder in mvm-core"
```

---

## Task 2: `config::checkpoints_dir()` helper (mvm-core)

**Files:**
- Modify: `crates/mvm-core/src/config.rs` (add next to `mvm_keys_dir` / the other `~/.mvm` subdir helpers, ~line 426)

- [ ] **Step 1: Write the failing test** — add to the `#[cfg(test)] mod tests` in `config.rs`:

```rust
#[test]
fn checkpoints_dir_is_under_data_dir() {
    let temp = tempfile::tempdir().unwrap();
    // Safe in tests: config reads MVM_DATA_DIR at call time.
    unsafe { std::env::set_var("MVM_DATA_DIR", temp.path()) };
    let dir = checkpoints_dir();
    assert_eq!(dir, temp.path().join("checkpoints"));
    unsafe { std::env::remove_var("MVM_DATA_DIR") };
}
```

(If neighbouring tests use a different env-set idiom, match theirs — grep `MVM_DATA_DIR` in `config.rs` tests first.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-core checkpoints_dir_is_under_data_dir 2>&1 | tail -10`
Expected: compile error — `checkpoints_dir` not found.

- [ ] **Step 3: Write the implementation** — add beside `mvm_keys_dir()`:

```rust
/// Immutable checkpoint store: `<mvm_data_dir>/checkpoints/`. Each checkpoint
/// is a subdirectory `<id>/` holding `meta.json` + cloned `content/`.
pub fn checkpoints_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_data_dir()).join("checkpoints")
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mvm-core checkpoints_dir_is_under_data_dir 2>&1 | tail -10`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/config.rs
git commit -m "feat(config): checkpoints_dir helper"
```

---

## Task 3: `CheckpointStore` (mvm-backend)

**Files:**
- Create: `crates/mvm-backend/src/checkpoint/mod.rs`
- Modify: `crates/mvm-backend/src/lib.rs` (add `pub mod checkpoint;` among the `pub mod` lines)

- [ ] **Step 1: Write the failing tests** — create `crates/mvm-backend/src/checkpoint/mod.rs` with the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};

    fn meta(id: &str, tag: Option<&str>, parent: Option<&str>) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .tag(tag.map(String::from))
            .parent(parent.map(CheckpointId::new))
            .content_sha256("h")
            .supervisor_config_digest("d")
            .created_unix(1)
            .build()
    }

    #[test]
    fn write_then_read_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let m = meta("c1", None, None);
        store.write_meta(&m).unwrap();
        assert_eq!(store.read_meta(&CheckpointId::new("c1")).unwrap(), m);
    }

    #[test]
    fn list_and_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        store.write_meta(&meta("a", None, None)).unwrap();
        store.write_meta(&meta("b", None, None)).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
        store.remove(&CheckpointId::new("a")).unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn by_tag_filters() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        store.write_meta(&meta("a", Some("gold"), None)).unwrap();
        store.write_meta(&meta("b", None, None)).unwrap();
        let tagged = store.by_tag("gold").unwrap();
        assert_eq!(tagged.len(), 1);
        assert_eq!(tagged[0].id.as_str(), "a");
    }

    #[test]
    fn children_of_finds_lineage() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        store.write_meta(&meta("parent", None, None)).unwrap();
        store.write_meta(&meta("child", None, Some("parent"))).unwrap();
        let kids = store.children_of(&CheckpointId::new("parent")).unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].id.as_str(), "child");
    }

    #[test]
    fn content_dir_path_is_under_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let p = store.content_dir(&CheckpointId::new("c1"));
        assert_eq!(p, tmp.path().join("c1").join("content"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-backend checkpoint::tests 2>&1 | tail -20`
Expected: compile error — `CheckpointStore` not found.

- [ ] **Step 3: Write the implementation** — prepend to `crates/mvm-backend/src/checkpoint/mod.rs`:

```rust
//! Host-side checkpoint store + the fs_quick capture/fork operations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};

/// Filesystem-backed registry over `config::checkpoints_dir()` (or any root,
/// for tests). Layout: `<root>/<id>/meta.json` + `<root>/<id>/content/`.
pub struct CheckpointStore {
    root: PathBuf,
}

impl CheckpointStore {
    /// Production constructor — uses the canonical `~/.mvm/checkpoints` path.
    pub fn open() -> Self {
        Self::at(mvm_core::config::checkpoints_dir())
    }

    /// Test/explicit-root constructor.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn dir_for(&self, id: &CheckpointId) -> PathBuf {
        self.root.join(id.as_str())
    }

    pub fn content_dir(&self, id: &CheckpointId) -> PathBuf {
        self.dir_for(id).join("content")
    }

    fn meta_path(&self, id: &CheckpointId) -> PathBuf {
        self.dir_for(id).join("meta.json")
    }

    pub fn write_meta(&self, meta: &CheckpointMeta) -> Result<()> {
        let dir = self.dir_for(&meta.id);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating checkpoint dir {}", dir.display()))?;
        let json = serde_json::to_vec_pretty(meta).context("serializing checkpoint meta")?;
        let path = self.meta_path(&meta.id);
        std::fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn read_meta(&self, id: &CheckpointId) -> Result<CheckpointMeta> {
        let path = self.meta_path(id);
        let bytes =
            std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn list(&self) -> Result<Vec<CheckpointMeta>> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).context("reading checkpoints dir"),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = CheckpointId::new(entry.file_name().to_string_lossy().into_owned());
            if self.meta_path(&id).exists() {
                out.push(self.read_meta(&id)?);
            }
        }
        Ok(out)
    }

    pub fn by_tag(&self, tag: &str) -> Result<Vec<CheckpointMeta>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|m| m.tag.as_deref() == Some(tag))
            .collect())
    }

    pub fn children_of(&self, parent: &CheckpointId) -> Result<Vec<CheckpointMeta>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|m| m.parent.as_ref() == Some(parent))
            .collect())
    }

    pub fn remove(&self, id: &CheckpointId) -> Result<()> {
        let dir = self.dir_for(id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("removing {}", dir.display()))?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
```

Add to `crates/mvm-backend/src/lib.rs`:

```rust
pub mod checkpoint;
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mvm-backend checkpoint::tests 2>&1 | tail -20`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backend/src/checkpoint/mod.rs crates/mvm-backend/src/lib.rs
git commit -m "feat(checkpoint): CheckpointStore over checkpoints_dir"
```

---

## Task 4: `capture_fs_quick` (mvm-backend)

**Files:**
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs` (append the function + tests)

The capture takes already-resolved inputs (the caller, in the CLI task, resolves the VM's rootfs path, quiesced-state check, and config digest). This keeps the function pure and unit-testable without a VM. The quiesced precondition is expressed as an explicit `quiesced: bool` argument so the unit test can exercise the refusal path.

- [ ] **Step 1: Write the failing tests** — add to the test module:

```rust
    use std::io::Write;

    fn write_fake_rootfs(dir: &Path) -> PathBuf {
        let p = dir.join("rootfs.ext4");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"fake-ext4-bytes").unwrap();
        p
    }

    #[test]
    fn capture_refuses_when_not_quiesced() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = write_fake_rootfs(tmp.path());
        let params = CaptureFsQuickParams {
            id: CheckpointId::new("c1"),
            vm_name: "vm".into(),
            rootfs: rootfs.clone(),
            supervisor_config_digest: "d".into(),
            tag: None,
            created_unix: 7,
            quiesced: false,
        };
        let err = capture_fs_quick(&store, params).unwrap_err();
        assert!(err.to_string().contains("quiesced"));
    }

    #[test]
    fn capture_clones_hashes_and_writes_meta() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = write_fake_rootfs(tmp.path());
        let params = CaptureFsQuickParams {
            id: CheckpointId::new("c1"),
            vm_name: "vm".into(),
            rootfs,
            supervisor_config_digest: "d".into(),
            tag: Some("gold".into()),
            created_unix: 7,
            quiesced: true,
        };
        let meta = capture_fs_quick(&store, params).unwrap();
        // content cloned
        let content_blob = store.content_dir(&meta.id).join("rootfs.ext4");
        assert_eq!(std::fs::read(&content_blob).unwrap(), b"fake-ext4-bytes");
        // hash recorded over the cloned blob
        assert_eq!(meta.content_sha256.len(), 64);
        assert_eq!(meta.tag.as_deref(), Some("gold"));
        // persisted
        assert_eq!(store.read_meta(&meta.id).unwrap(), meta);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-backend checkpoint::tests::capture 2>&1 | tail -20`
Expected: compile error — `capture_fs_quick` / `CaptureFsQuickParams` not found.

- [ ] **Step 3: Write the implementation** — append to `checkpoint/mod.rs` (above the test module). It reuses `crate::base::cow::clone_rootfs_for_instance` and hashes via `sha2`:

```rust
use mvm_core::checkpoint::{CheckpointClass, CheckpointMeta};

/// Inputs for an `fs_quick` capture. Grouped into a struct so the call site
/// reads clearly and we never thread a long positional argument list.
pub struct CaptureFsQuickParams {
    pub id: CheckpointId,
    pub vm_name: String,
    /// Absolute path to the VM's live rootfs image to clone.
    pub rootfs: PathBuf,
    pub supervisor_config_digest: String,
    pub tag: Option<String>,
    pub created_unix: u64,
    /// The caller asserts the VM is stopped or paused-and-synced. A non-quiesced
    /// capture is refused: an fs_quick checkpoint has no memory, so the rootfs
    /// must be in a clean, deterministic state.
    pub quiesced: bool,
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    use sha2::Digest;
    let bytes = std::fs::read(path).with_context(|| format!("hashing {}", path.display()))?;
    let mut h = sha2::Sha256::new();
    h.update(&bytes);
    Ok(format!("{:x}", h.finalize()))
}

/// Freeze a quiesced VM's rootfs into an immutable fs_quick checkpoint via APFS
/// copy-on-write. Returns the persisted metadata. Audit binding is the caller's
/// responsibility (it owns the ExecutionPlan + signer).
pub fn capture_fs_quick(
    store: &CheckpointStore,
    params: CaptureFsQuickParams,
) -> Result<CheckpointMeta> {
    if !params.quiesced {
        anyhow::bail!(
            "refusing fs_quick checkpoint of a non-quiesced VM '{}': stop or pause it first",
            params.vm_name
        );
    }
    let content_dir = store.content_dir(&params.id);
    std::fs::create_dir_all(&content_dir)
        .with_context(|| format!("creating {}", content_dir.display()))?;

    let file_name = params
        .rootfs
        .file_name()
        .context("rootfs path has no file name")?;
    let dst = content_dir.join(file_name);
    crate::base::cow::clone_rootfs_for_instance(&params.rootfs, &dst)
        .context("cloning rootfs into checkpoint content")?;

    let content_sha256 = sha256_file_hex(&dst)?;

    let meta = CheckpointMeta::builder(params.id, CheckpointClass::FsQuick, params.vm_name)
        .tag(params.tag)
        .created_unix(params.created_unix)
        .content_sha256(content_sha256)
        .supervisor_config_digest(params.supervisor_config_digest)
        .build();
    store.write_meta(&meta)?;
    Ok(meta)
}
```

Confirm `sha2` is a dependency of `mvm-backend` (it almost certainly is via the workspace). If `cargo test` reports it missing, add `sha2.workspace = true` to `crates/mvm-backend/Cargo.toml` `[dependencies]`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mvm-backend checkpoint::tests 2>&1 | tail -20`
Expected: all checkpoint tests pass (7 total now).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backend/src/checkpoint/mod.rs crates/mvm-backend/Cargo.toml
git commit -m "feat(checkpoint): capture_fs_quick CoW capture of a quiesced rootfs"
```

---

## Task 5: `fork_checkpoint` (mvm-backend)

**Files:**
- Modify: `crates/mvm-backend/src/checkpoint/mod.rs` (append the function + tests)

`fork_checkpoint` materializes a child instance's rootfs by CoW-cloning a checkpoint's verified content into a destination directory the caller supplies (the CLI resolves the new VM's state dir via `config::vm_state_dir`). It returns the forked child's metadata (with `parent` set). Booting the child is the CLI's job (Task 8). This keeps the primitive boot-free and unit-testable.

- [ ] **Step 1: Write the failing tests** — add to the test module:

```rust
    fn seed_fs_quick_checkpoint(store: &CheckpointStore, tmp: &Path, id: &str) -> CheckpointMeta {
        let rootfs = write_fake_rootfs(tmp);
        capture_fs_quick(
            store,
            CaptureFsQuickParams {
                id: CheckpointId::new(id),
                vm_name: "parentvm".into(),
                rootfs,
                supervisor_config_digest: "d".into(),
                tag: None,
                created_unix: 1,
                quiesced: true,
            },
        )
        .unwrap()
    }

    #[test]
    fn fork_clones_content_and_records_lineage() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let dst = tmp.path().join("childvm-state");
        let child = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("f1"),
                child_vm_name: "childvm".into(),
                dest_dir: dst.clone(),
                created_unix: 2,
            },
        )
        .unwrap();
        assert_eq!(child.parent.as_ref().unwrap(), &parent.id);
        assert_eq!(child.vm_name, "childvm");
        // content materialized into dest
        assert_eq!(
            std::fs::read(dst.join("rootfs.ext4")).unwrap(),
            b"fake-ext4-bytes"
        );
        // child persisted with lineage queryable
        assert_eq!(store.children_of(&parent.id).unwrap().len(), 1);
    }

    #[test]
    fn fork_refuses_vm_full_in_this_pr() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        // hand-write a vm_full checkpoint meta (no content needed for the guard)
        let m = CheckpointMeta::builder(
            CheckpointId::new("vf"),
            CheckpointClass::VmFull,
            "vm",
        )
        .content_sha256("h")
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&m).unwrap();
        let err = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: m.id,
                child_id: CheckpointId::new("f"),
                child_vm_name: "c".into(),
                dest_dir: tmp.path().join("d"),
                created_unix: 2,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("vm_full"));
    }

    #[test]
    fn fork_refuses_tampered_content() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        // tamper: overwrite the stored content blob after capture
        let blob = store.content_dir(&parent.id).join("rootfs.ext4");
        std::fs::write(&blob, b"tampered").unwrap();
        let err = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: parent.id,
                child_id: CheckpointId::new("f"),
                child_vm_name: "c".into(),
                dest_dir: tmp.path().join("d"),
                created_unix: 2,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("integrity") || err.to_string().contains("sha256"));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-backend checkpoint::tests::fork 2>&1 | tail -20`
Expected: compile error — `fork_checkpoint` / `ForkParams` not found.

- [ ] **Step 3: Write the implementation** — append above the test module:

```rust
/// Inputs for forking a child instance from a checkpoint.
pub struct ForkParams {
    pub checkpoint: CheckpointId,
    /// New checkpoint-id recording this fork's lineage.
    pub child_id: CheckpointId,
    pub child_vm_name: String,
    /// Where to materialize the child's rootfs (the new VM's state dir).
    pub dest_dir: PathBuf,
    pub created_unix: u64,
}

/// Branch a new sandbox lineage from a checkpoint: verify the source content's
/// integrity, CoW-clone it into `dest_dir`, and record a child checkpoint whose
/// `parent` points back to the source. Boot of the child is the caller's job.
pub fn fork_checkpoint(store: &CheckpointStore, params: ForkParams) -> Result<CheckpointMeta> {
    let parent = store.read_meta(&params.checkpoint)?;
    if parent.class != CheckpointClass::FsQuick {
        anyhow::bail!(
            "cannot fork checkpoint '{}': class vm_full is not supported yet",
            parent.id
        );
    }

    // Locate + integrity-check the single content blob.
    let content_dir = store.content_dir(&parent.id);
    let blob = first_file_in(&content_dir)?;
    let actual = sha256_file_hex(&blob)?;
    if actual != parent.content_sha256 {
        anyhow::bail!(
            "checkpoint '{}' content failed integrity (sha256): expected {}, got {}",
            parent.id,
            parent.content_sha256,
            actual
        );
    }

    std::fs::create_dir_all(&params.dest_dir)
        .with_context(|| format!("creating {}", params.dest_dir.display()))?;
    let blob_name = blob.file_name().context("content blob has no file name")?;
    let dst = params.dest_dir.join(blob_name);
    crate::base::cow::clone_rootfs_for_instance(&blob, &dst)
        .context("cloning checkpoint content into child instance")?;

    let child = CheckpointMeta::builder(
        params.child_id,
        CheckpointClass::FsQuick,
        params.child_vm_name,
    )
    .parent(Some(parent.id))
    .created_unix(params.created_unix)
    .content_sha256(actual)
    .supervisor_config_digest(parent.supervisor_config_digest)
    .build();
    store.write_meta(&child)?;
    Ok(child)
}

fn first_file_in(dir: &Path) -> Result<PathBuf> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("reading content dir {}", dir.display()))?
    {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            return Ok(entry.path());
        }
    }
    anyhow::bail!("checkpoint content dir {} has no file", dir.display())
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mvm-backend checkpoint::tests 2>&1 | tail -20`
Expected: all checkpoint tests pass (10 total).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-backend/src/checkpoint/mod.rs
git commit -m "feat(checkpoint): fork_checkpoint with integrity check + lineage"
```

---

## Task 6: Audit kinds + emitters

**Files:**
- Modify: `crates/mvm-core/src/policy/audit.rs` (add variants after `PoolWarm`, ~line 169)
- Modify: `crates/mvm-cli/src/commands/vm/audit_chain.rs` (add two emit methods + tests)
- Modify: `tests/audit_total_coverage.rs` (register tokens + posture)

- [ ] **Step 1: Add the audit kinds** — in `audit.rs`, directly after the `PoolWarm,` variant:

```rust
    /// `mvmctl checkpoint create` froze a VM's filesystem state into an
    /// immutable fs_quick checkpoint. `detail` carries `id=<ckpt> class=fs_quick`.
    CheckpointCreated,
    /// `mvmctl checkpoint fork` branched a new sandbox from a checkpoint.
    /// `detail` carries `parent=<ckpt> child=<ckpt>`.
    CheckpointForked,
```

- [ ] **Step 2: Write the failing emitter tests** — in `audit_chain.rs` `#[cfg(test)] mod tests`, mirroring `vm_snapshot_saved_records_path_hash_and_size`:

```rust
    #[test]
    fn checkpoint_created_records_id_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-C");

        emitter
            .emit_checkpoint_created(&plan, "ckpt-abc", "fs_quick", "deadbeef", "myvm")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.created"));
        assert!(content.contains("ckpt-abc"));
        assert!(content.contains("deadbeef"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn checkpoint_forked_records_lineage() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-F");

        emitter
            .emit_checkpoint_forked(&plan, "ckpt-parent", "ckpt-child", "childvm")
            .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.forked"));
        assert!(content.contains("ckpt-parent"));
        assert!(content.contains("ckpt-child"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }
```

(Match the exact `AuditEmitter` test constructor the neighbouring snapshot test uses — the survey shows `AuditEmitter::with_dir(key, dir.path())` and `fixture_plan(...)`; copy those helpers' real names from the file.)

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p mvm-cli checkpoint_ 2>&1 | tail -20`
Expected: compile error — `emit_checkpoint_created` not found.

- [ ] **Step 4: Write the emitters** — in `audit_chain.rs`, beside `emit_vm_snapshot_saved`:

```rust
    pub fn emit_checkpoint_created(
        &self,
        plan: &ExecutionPlan,
        checkpoint_id: &str,
        class: &str,
        content_sha256: &str,
        vm_name: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "checkpoint.created",
            [
                ("checkpoint_id".to_string(), checkpoint_id.to_string()),
                ("class".to_string(), class.to_string()),
                ("content_sha256".to_string(), content_sha256.to_string()),
                ("vm_name".to_string(), vm_name.to_string()),
            ],
        )
    }

    pub fn emit_checkpoint_forked(
        &self,
        plan: &ExecutionPlan,
        parent_id: &str,
        child_id: &str,
        child_vm_name: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "checkpoint.forked",
            [
                ("parent_id".to_string(), parent_id.to_string()),
                ("child_id".to_string(), child_id.to_string()),
                ("child_vm_name".to_string(), child_vm_name.to_string()),
            ],
        )
    }
```

- [ ] **Step 5: Register in coverage test** — in `tests/audit_total_coverage.rs`:
  - Add `"CheckpointCreated"` and `"CheckpointForked"` to the `KNOWN_TOKENS` array (beside `"PoolWarm"`).
  - Add a `CHECKPOINT_SUB` posture table beside `POOL_SUB`:

```rust
const CHECKPOINT_SUB: &[(&str, AuditPosture)] = &[
    ("create", AuditPosture::Emits("CheckpointCreated")),
    ("fork", AuditPosture::Emits("CheckpointForked")),
    ("ls", AuditPosture::ReadOnly),
    ("rm", AuditPosture::ReadOnly),
];
```

  - Add to the `AUDIT_POSTURE` table beside the `"pool"` row:

```rust
    ("checkpoint", AuditPosture::DelegatesToSub(CHECKPOINT_SUB)),
```

  (If `rm` is later made to audit a deletion, revisit; for PR1 `rm` only removes a local dir, consistent with `snapshot rm` being `ReadOnly` in posture terms.)

- [ ] **Step 6: Run to verify pass**

Run: `cargo test -p mvm-cli checkpoint_ 2>&1 | tail -10 && cargo test --test audit_total_coverage 2>&1 | tail -10`
Expected: emitter tests pass; coverage test passes.

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-core/src/policy/audit.rs crates/mvm-cli/src/commands/vm/audit_chain.rs tests/audit_total_coverage.rs
git commit -m "feat(audit): checkpoint.created / checkpoint.forked chain events"
```

---

## Task 7: `VmCapabilities.fs_quick_checkpoint`

**Files:**
- Modify: `crates/mvm-core/src/protocol/vm_backend.rs` (`VmCapabilities` struct, ~line 394)
- Modify: every `fn capabilities()` impl: `crates/mvm-backend/src/{vz,apple_container,libkrun,firecracker,docker,cloud_hypervisor}.rs` and any mock backend.

- [ ] **Step 1: Write the failing test** — in `crates/mvm-backend/src/vz.rs` tests (or wherever `capabilities()` is tested):

```rust
    #[test]
    fn vz_advertises_fs_quick_checkpoint_when_apfs() {
        // fs_quick relies on clonefile(2), available on macOS APFS hosts.
        let caps = VzBackend::default().capabilities();
        assert_eq!(caps.fs_quick_checkpoint, cfg!(target_os = "macos"));
    }
```

(Use the real `VzBackend` constructor the file uses — grep the existing `capabilities` test in `vz.rs`.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-backend fs_quick_checkpoint 2>&1 | tail -10`
Expected: compile error — no field `fs_quick_checkpoint`.

- [ ] **Step 3: Add the field** — in `vm_backend.rs` `VmCapabilities`:

```rust
    /// Can freeze a quiesced rootfs into an fs_quick checkpoint via filesystem
    /// copy-on-write (APFS `clonefile` on macOS). Independent of `snapshots`,
    /// which is the memory-state save/restore capability.
    pub fs_quick_checkpoint: bool,
```

- [ ] **Step 4: Set it in every impl.** macOS-CoW backends advertise `true` on macOS; others `false`:

  - `vz.rs` `capabilities()`: `fs_quick_checkpoint: cfg!(target_os = "macos"),`
  - `apple_container.rs` `capabilities()`: `fs_quick_checkpoint: cfg!(target_os = "macos"),`
  - `libkrun.rs`, `firecracker.rs`, `docker.rs`, `cloud_hypervisor.rs`, and any mock: `fs_quick_checkpoint: false,`

  Find them all:

```bash
rg -n "fn capabilities" crates/mvm-backend/src
rg -n "VmCapabilities \{" crates/mvm-backend crates/mvm-core
```

  Add the field to each literal. The compiler enforces completeness — a missing field fails the build, so none can be silently skipped.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p mvm-backend fs_quick_checkpoint 2>&1 | tail -10 && cargo build -p mvm-backend 2>&1 | tail -5`
Expected: test passes; workspace builds (no missing-field errors).

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-core/src/protocol/vm_backend.rs crates/mvm-backend/src
git commit -m "feat(backend): advertise fs_quick_checkpoint capability"
```

---

## Task 8: `mvmctl checkpoint` command group

**Files:**
- Create: `crates/mvm-cli/src/commands/vm/checkpoint.rs`
- Modify: `crates/mvm-cli/src/commands/vm/mod.rs` (add `pub(in crate::commands) mod checkpoint;`)
- Modify: `crates/mvm-cli/src/commands/mod.rs` (register the `Checkpoint` variant + dispatch)
- Modify: `crates/mvm-cli/src/commands/tests.rs` (parse tests)

This task wires the pure primitives to the CLI. The `create` path resolves the VM's rootfs + quiesced state + config digest and calls `capture_fs_quick`, then binds audit exactly as `snap_save` does. The `fork` path resolves the child's state dir via `config::vm_state_dir`, calls `fork_checkpoint`, binds audit, and (unless `--no-start`) boots the child.

- [ ] **Step 1: Write the failing parse tests** — in `commands/tests.rs`, beside the snapshot tests:

```rust
    #[test]
    fn test_checkpoint_create_parses() {
        let cli = Cli::try_parse_from([
            "mvmctl", "checkpoint", "create", "myvm", "--tag", "gold",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Checkpoint(vm::checkpoint::CheckpointArgs {
                command: vm::checkpoint::CheckpointCmd::Create { .. }
            })
        ));
    }

    #[test]
    fn test_checkpoint_fork_parses() {
        let cli = Cli::try_parse_from([
            "mvmctl", "checkpoint", "fork", "ckpt-abc", "--new-id", "child",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_checkpoint_ls_json_parses() {
        let cli = Cli::try_parse_from(["mvmctl", "checkpoint", "ls", "--json"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Checkpoint(vm::checkpoint::CheckpointArgs {
                command: vm::checkpoint::CheckpointCmd::Ls { json: true }
            })
        ));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-cli test_checkpoint_ 2>&1 | tail -15`
Expected: compile error — `vm::checkpoint` / `Commands::Checkpoint` absent.

- [ ] **Step 3: Write the command module** — create `crates/mvm-cli/src/commands/vm/checkpoint.rs`:

```rust
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use mvm_backend::checkpoint::{
    capture_fs_quick, fork_checkpoint, CaptureFsQuickParams, CheckpointStore, ForkParams,
};
use mvm_core::checkpoint::CheckpointId;

use crate::Cli;
use crate::commands::clap_vm_name;
use mvm_backend::base::ui;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct CheckpointArgs {
    #[command(subcommand)]
    pub command: CheckpointCmd,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub(in crate::commands) enum CheckpointCmd {
    /// Freeze a quiesced VM's filesystem state into an immutable fs_quick
    /// checkpoint (APFS copy-on-write).
    Create {
        /// VM whose rootfs to checkpoint (must be stopped or paused).
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Pin this checkpoint against `cache prune` GC.
        #[arg(long)]
        tag: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List checkpoints.
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// Remove a checkpoint and its content.
    Rm {
        /// Checkpoint id to remove.
        id: String,
    },
    /// Branch a new sandbox instance from a checkpoint (materializes the
    /// child's rootfs + lineage; boot it with `mvmctl up`/`start`).
    Fork {
        /// Source checkpoint id.
        id: String,
        /// Name for the new VM instance (auto-generated if omitted).
        #[arg(long)]
        new_id: Option<String>,
    },
}

pub(in crate::commands) fn run_checkpoint(_cli: &Cli, args: CheckpointArgs) -> Result<()> {
    match args.command {
        CheckpointCmd::Create { name, tag, json } => create(&name, tag, json),
        CheckpointCmd::Ls { json } => ls(json),
        CheckpointCmd::Rm { id } => rm(&id),
        CheckpointCmd::Fork { id, new_id } => fork(&id, new_id),
    }
}
```

  Then implement the four helpers in the same file. Reuse the VM-state resolution + quiesced check + audit binding that `pause.rs::snap_save` already performs. The audit binding mirrors `snap_save` verbatim (best-effort when no persisted plan/signer, **fatal on a signing error for `fork`** so we never ship an unaudited fork):

```rust
fn checkpoint_id_for(vm_name: &str, now: u64) -> CheckpointId {
    // Deterministic, collision-resistant enough for a local store; the VM name
    // plus capture time uniquely identify a checkpoint on one host.
    CheckpointId::new(format!("ckpt-{vm_name}-{now}"))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn create(name: &str, tag: Option<String>, json: bool) -> Result<()> {
    // Resolve the VM's rootfs path and quiesced state from real primitives:
    //  - rootfs lives at `<vm_state_dir>/<state.rootfs>`, where `state.rootfs`
    //    is the filename persisted in the VM's saved state (see
    //    `mvm_backend::microvm` line ~286: `format!("{}/{}", abs_dir, state.rootfs)`).
    //    Load that persisted state to get the filename; do NOT hardcode a name.
    //  - quiesced == the registry entry exists and is not running (stopped) or
    //    is paused, via `VmNameRegistry::lookup`.
    let registry = mvm::vm::name_registry::VmNameRegistry::load(
        &mvm::vm::name_registry::registry_path(),
    )
    .context("loading the VM name registry")?;
    let reg = registry
        .lookup(name)
        .with_context(|| format!("VM {name:?} is not registered"))?;
    let quiesced = !reg.running || reg.paused;

    let state_dir = mvm_core::config::vm_state_dir(name);
    let rootfs = resolve_vm_rootfs_path(&state_dir)
        .with_context(|| format!("locating the rootfs image for VM {name:?}"))?;
    let config_digest = String::new(); // not load-bearing for fs_quick; PR2 pins it

    let store = CheckpointStore::open();
    let now = now_unix();
    let meta = capture_fs_quick(
        &store,
        CaptureFsQuickParams {
            id: checkpoint_id_for(name, now),
            vm_name: name.to_string(),
            rootfs,
            supervisor_config_digest: config_digest,
            tag,
            created_unix: now,
            quiesced,
        },
    )?;

    // Chain-signed audit binding (best-effort, mirrors snap_save).
    if let Ok(plan) = super::plan_persist::read_plan(name) {
        if let Ok(signer) = super::host_signer::load_or_init() {
            if let Ok(emitter) = super::audit_chain::AuditEmitter::new(signer.signing) {
                if let Err(e) = emitter.emit_checkpoint_created(
                    &plan,
                    meta.id.as_str(),
                    "fs_quick",
                    &meta.content_sha256,
                    name,
                ) {
                    tracing::warn!(error = %e, "audit emit_checkpoint_created failed (non-fatal)");
                }
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&meta)?);
    } else {
        ui::success(&format!("Checkpoint {} created.", meta.id));
    }
    Ok(())
}

fn ls(json: bool) -> Result<()> {
    let store = CheckpointStore::open();
    let items = store.list()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else if items.is_empty() {
        ui::info("No checkpoints.");
    } else {
        for m in &items {
            let parent = m.parent.as_ref().map(|p| p.as_str()).unwrap_or("-");
            let tag = m.tag.as_deref().unwrap_or("-");
            ui::info(&format!(
                "{} · {:?} · vm={} · parent={} · tag={}",
                m.id, m.class, m.vm_name, parent, tag
            ));
        }
    }
    Ok(())
}

fn rm(id: &str) -> Result<()> {
    CheckpointStore::open().remove(&CheckpointId::new(id))?;
    ui::success(&format!("Removed checkpoint {id}."));
    Ok(())
}

fn fork(id: &str, new_id: Option<String>) -> Result<()> {
    let store = CheckpointStore::open();
    let now = now_unix();
    let child_vm_name = new_id.unwrap_or_else(|| format!("{id}-fork-{now}"));
    let dest_dir = mvm_core::config::vm_state_dir(&child_vm_name);

    let child = fork_checkpoint(
        &store,
        ForkParams {
            checkpoint: CheckpointId::new(id),
            child_id: CheckpointId::new(format!("fork-{child_vm_name}-{now}")),
            child_vm_name: child_vm_name.clone(),
            dest_dir,
            created_unix: now,
        },
    )?;

    // Audit binding — fatal on a signing error: never ship an unaudited fork.
    // Best-effort only when no plan/signer is provisioned yet (mirrors snap_save).
    if let Ok(plan) = super::plan_persist::read_plan(&child.vm_name) {
        if let Ok(signer) = super::host_signer::load_or_init() {
            if let Ok(emitter) = super::audit_chain::AuditEmitter::new(signer.signing) {
                emitter
                    .emit_checkpoint_forked(&plan, id, child.id.as_str(), &child.vm_name)
                    .context("auditing the fork (refusing an unaudited fork)")?;
            }
        }
    }

    ui::success(&format!(
        "Forked {} from checkpoint {} into VM '{}'. Start it with: mvmctl up --name {}",
        child.id, id, child.vm_name, child.vm_name
    ));
    Ok(())
}

/// Resolve the host-side rootfs image path for a quiesced VM. The rootfs
/// filename is the `rootfs` field of `mvm_backend::base::config::MvmState`
/// (joined onto the VM dir, exactly as `microvm.rs` builds
/// `format!("{}/{}", abs_dir, state.rootfs)`).
fn resolve_vm_rootfs_path(state_dir: &std::path::Path) -> Result<PathBuf> {
    let raw = std::fs::read_to_string(state_dir.join(".mvm-state"))
        .with_context(|| format!("reading VM state in {}", state_dir.display()))?;
    let state: mvm_backend::base::config::MvmState =
        serde_json::from_str(&raw).context("parsing .mvm-state")?;
    Ok(state_dir.join(state.rootfs))
}
```

  > **Task 8 Step 0 — pin the host-side rootfs location (one bounded investigation).**
  > The snippet above assumes the host keeps a `.mvm-state` file beside the
  > rootfs in `vm_state_dir(name)`. That is the Firecracker/legacy layout;
  > **the libkrun and Vz backends may store the rootfs image elsewhere** (their
  > supervisor configs, not a host `.mvm-state`). Before implementing `create`,
  > trace where the *active* macOS backend (Vz / apple_container) persists the
  > bootable rootfs image for a named VM — start at `mvm_backend::vz` /
  > `apple_container::prepare_instance_rootfs` and the supervisor config that
  > names the rootfs. Make `resolve_vm_rootfs_path` return that real path for the
  > macOS backends (the only ones advertising `fs_quick_checkpoint = true`); a
  > backend that doesn't expose a host-side rootfs image yields a clean
  > "fs_quick checkpoint unsupported for this VM's backend" error. This is the
  > single integration seam in PR1 — everything else is unit-pinned.
  >
  > **Scope note — fork materializes only (no auto-boot in PR1):** the approved design said "fork boots by default," but pinning the start path showed booting a forked child pulls in the full `up` start path + plan synthesis and is not validatable on the local (flaky) Vz boot — which defeats the host-side-testable rationale for doing `fs_quick` first. PR1 therefore *materializes* the child (rootfs + lineage + audit) and prints the `mvmctl up` hint; **boot-on-fork moves to the start of PR2**, where the live-Vz path is already in scope. This keeps every line of PR1 unit-testable.

- [ ] **Step 4: Register the command** — in `commands/vm/mod.rs`:

```rust
pub(in crate::commands) mod checkpoint;
```

  In `commands/mod.rs`, add the enum variant beside `Snapshot`:

```rust
    /// Freeze + fork microVM filesystem state (`create`, `ls`, `rm`, `fork`).
    Checkpoint(vm::checkpoint::CheckpointArgs),
```

  and the dispatch arm beside `Commands::Snapshot`:

```rust
        Commands::Checkpoint(a) => vm::checkpoint::run_checkpoint(&cli, a),
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p mvm-cli test_checkpoint_ 2>&1 | tail -15`
Expected: the three parse tests pass.

- [ ] **Step 6: Full build + clippy on the touched crates**

Run: `cargo clippy -p mvm-cli -p mvm-backend -p mvm-core -- -D warnings 2>&1 | tail -15`
Expected: zero warnings (watch for `too_many_arguments` — the param structs prevent it).

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/checkpoint.rs crates/mvm-cli/src/commands/vm/mod.rs crates/mvm-cli/src/commands/mod.rs crates/mvm-cli/src/commands/tests.rs crates/mvm-cli/src/commands/vm/pause.rs crates/mvm-cli/src/commands/vm/up.rs
git commit -m "feat(cli): mvmctl checkpoint create/ls/rm/fork"
```

---

## Task 9: `cache prune` GC for untagged checkpoints

**Files:**
- Modify: `crates/mvm-cli/src/commands/ops/cache.rs` (add a sweep block mirroring the flow-byte-log retention sweep)

- [ ] **Step 1: Write the failing test** — add to `cache.rs` tests (or a new `#[cfg(test)]` block):

```rust
    #[test]
    fn prune_removes_untagged_keeps_tagged() {
        use mvm_backend::checkpoint::CheckpointStore;
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let mk = |id: &str, tag: Option<&str>, age: u64| {
            CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
                .tag(tag.map(String::from))
                .content_sha256("h")
                .supervisor_config_digest("d")
                .created_unix(age)
                .build()
        };
        store.write_meta(&mk("old-untagged", None, 0)).unwrap();
        store.write_meta(&mk("old-tagged", Some("gold"), 0)).unwrap();

        let now = 10_000_000u64;
        let removed = super::sweep_untagged_checkpoints(&store, now, /*max_age_secs*/ 1).unwrap();
        assert_eq!(removed, 1);
        assert!(store.read_meta(&CheckpointId::new("old-tagged")).is_ok());
        assert!(store.read_meta(&CheckpointId::new("old-untagged")).is_err());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p mvm-cli prune_removes_untagged_keeps_tagged 2>&1 | tail -10`
Expected: compile error — `sweep_untagged_checkpoints` not found.

- [ ] **Step 3: Write the sweep helper + wire it** — add to `cache.rs`:

```rust
/// Remove untagged checkpoints older than `max_age_secs`. Tagged checkpoints
/// are pinned and never swept. Returns the count removed.
pub(super) fn sweep_untagged_checkpoints(
    store: &mvm_backend::checkpoint::CheckpointStore,
    now_unix: u64,
    max_age_secs: u64,
) -> anyhow::Result<usize> {
    let mut removed = 0;
    for m in store.list()? {
        if m.tag.is_some() {
            continue;
        }
        if now_unix.saturating_sub(m.created_unix) > max_age_secs {
            store.remove(&m.id)?;
            removed += 1;
        }
    }
    Ok(removed)
}
```

  Then call it from the prune flow, mirroring the flow-byte-log block (const TTL, dry-run branch, accumulate `removed`):

```rust
    // Untagged-checkpoint GC: tagged checkpoints are user-pinned; untagged ones
    // follow cache retention.
    const CHECKPOINT_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
    let ckpt_store = mvm_backend::checkpoint::CheckpointStore::open();
    if dry_run {
        if !ckpt_store.list().unwrap_or_default().is_empty() {
            ui::info("(dry-run) Would sweep expired untagged checkpoints.");
        }
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        match sweep_untagged_checkpoints(&ckpt_store, now, CHECKPOINT_MAX_AGE_SECS) {
            Ok(n) => removed += n,
            Err(e) => ui::warn(&format!("checkpoint sweep failed: {e}")),
        }
    }
```

  (Match the actual variable names in `cache.rs` — `removed`, `dry_run`, `ui` — confirmed present from the flow-byte-log block.)

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mvm-cli prune_removes_untagged_keeps_tagged 2>&1 | tail -10`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/ops/cache.rs
git commit -m "feat(cache): prune untagged checkpoints, keep tagged"
```

---

## Task 10: Full-suite green + status rollup

**Files:**
- Modify: `specs/REFACTOR-STATUS.md`
- Modify: `specs/plans/159-vz-inspired-macos-dx.md` (tick the WS-2 fs_quick items the PR delivers)

- [ ] **Step 1: Format + full lint + full test**

Run:
```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings 2>&1 | tail -20
cargo nextest run --workspace -E 'not package(mvm-backend)' 2>&1 | tail -20
cargo nextest run -p mvm-backend -E 'test(checkpoint)' 2>&1 | tail -20
cargo test --workspace --doc 2>&1 | tail -10
```
Expected: fmt clean; zero clippy warnings; tests pass. (The `mvm-backend` exclusion + targeted re-run is the documented macOS codesign-SIGKILL workaround; on Linux CI the full `--workspace` run covers it.)

- [ ] **Step 2: Update the rollup** — in `specs/REFACTOR-STATUS.md`, under `PLAN 159`, change the `WS-2 checkpoint+fork` line to show the fs_quick slice landed, e.g.:

```
  [~] WS-2 checkpoint+fork — fs_quick class (APFS-CoW checkpoint + fork + audit
      + capability + GC) landed; vm_full (memory save/restore) + diff remain
```

  Bump `**Last updated:**`. In `specs/plans/159-vz-inspired-macos-dx.md`, tick the WS-2 checklist items this PR satisfies (fs_quick class, fork, `--tag` GC, capability flip) and leave `vm_full` / `checkpoint diff` / `pause/resume` wiring unticked.

- [ ] **Step 3: Commit**

```bash
git add specs/REFACTOR-STATUS.md specs/plans/159-vz-inspired-macos-dx.md
git commit -m "docs(plan-159): WS-2 fs_quick checkpoint+fork landed"
```

- [ ] **Step 4: Push + open PR**

```bash
git push -u origin feat/plan-159-ws2-checkpoint-fork
gh pr create --title "feat(checkpoint): Plan 159 WS-2 PR1 — fs_quick checkpoint + fork" \
  --body "First slice of Plan 159 WS-2: a unified, audit-bound checkpoint subsystem with the fs_quick (APFS copy-on-write) class. Adds mvmctl checkpoint create/ls/rm/fork, chain-signed checkpoint.created/forked audit events, the fs_quick_checkpoint capability, and untagged-checkpoint GC in cache prune. vm_full (memory save/restore) and checkpoint diff are the next PRs. Design: specs/notes/plan-159-ws2-fs-quick-checkpoint-fork-design.md."
```

---

## Notes for the implementer

- **Run `xtask check-no-spec-refs` discipline by hand:** none of the code comments above cite a plan/PR/ADR — keep it that way.
- **Quiesced resolution is the one place to be careful:** `create` must refuse a running VM. The unit test covers the primitive; the CLI test in Task 8 only covers parsing. A live end-to-end (boot a long-lived workload, `checkpoint create`, `checkpoint fork`, confirm the child boots) belongs in a manual bringup pass — the local Vz dev VM exits on init-EOF, so prefer a long-lived workload image over the dev shell.
- **If `capture_fs_quick`'s `clone_rootfs_for_instance` returns `CloneStrategy::Copied`** on a non-APFS host, the checkpoint still works (byte copy); the capability flag is what gates the *DX promise*, not the function.
