//! Host-side checkpoint store + the fs_quick capture/fork operations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob};

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
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
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
            std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

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

/// Inputs for forking a child instance from a checkpoint.
pub struct ForkParams {
    pub checkpoint: CheckpointId,
    /// New checkpoint-id recording this fork's lineage.
    pub child_id: CheckpointId,
    pub child_vm_name: String,
    /// Where to materialize the child's rootfs (the new VM's state dir).
    pub dest_dir: PathBuf,
    pub created_unix: u64,
    /// Serialized `SignedExecutionPlan` JSON for the child's own claim-8
    /// admission. When `Some`, the spawner injects it into the child's
    /// `SupervisorConfig.plan` so the supervisor re-verifies it at start.
    /// `None` is accepted for test/dev use but skips claim-8 enforcement
    /// (the spawner receives no plan to verify).
    pub child_plan_json: Option<String>,
    /// Tenant id for the admitted child plan (mirrors `child_plan_json`).
    /// The supervisor uses this to derive the audit-substrate paths.
    pub child_tenant_id: Option<String>,
}

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
                meta.id,
                blob.name,
                blob.sha256,
                actual
            );
        }
    }
    Ok(())
}

/// Spawns a forked child's supervisor in restore mode from its rewritten
/// `SupervisorConfig`. The CLI-facing `vm_full` fork orchestration (which used
/// to live in this module as `fork_vm_full`) was Vz-only and is descoped as of
/// Plan 226 R1P1 WS-D — `mvmctl vm checkpoint fork` now refuses vm_full
/// parents outright (see `full_vm_checkpoint_unsupported_error` in
/// `mvm-cli`'s `checkpoint.rs`). This trait itself stays: the warm-pool
/// standby-claim path (`vz::vz_claim_standby`) still spawns a claimant
/// supervisor through it directly, independent of the descoped CLI engine.
pub trait ChildSupervisorSpawner {
    fn spawn(&self, config: &mvm_build::vz::SupervisorConfig) -> Result<()>;
}

/// Branch a new sandbox lineage from a checkpoint: verify the source content's
/// integrity, CoW-clone it into `dest_dir`, and record a child checkpoint whose
/// `parent` points back to the source. Boot of the child is the caller's job.
///
/// fs_quick only — a vm_full checkpoint carries saved memory and forking it
/// was Vz-only CLI-facing behavior descoped by Plan 226 R1P1 WS-D (see
/// `full_vm_checkpoint_unsupported_error` in `mvm-cli`'s `checkpoint.rs`).
pub fn fork_checkpoint(store: &CheckpointStore, params: ForkParams) -> Result<CheckpointMeta> {
    let parent = store.read_meta(&params.checkpoint)?;
    if parent.class != CheckpointClass::FsQuick {
        anyhow::bail!(
            "cannot fork checkpoint '{}' (class vm_full) via fork_checkpoint: vm_full forking \
             was Vz-only and is not supported",
            parent.id
        );
    }

    verify_content(store, &parent)?;

    std::fs::create_dir_all(&params.dest_dir)
        .with_context(|| format!("creating {}", params.dest_dir.display()))?;
    let content_dir = store.content_dir(&parent.id);
    for blob in &parent.content {
        crate::base::cow::clone_rootfs_for_instance(
            &content_dir.join(&blob.name),
            &params.dest_dir.join(&blob.name),
        )
        .with_context(|| format!("cloning checkpoint blob {}", blob.name))?;
    }

    let child = CheckpointMeta::builder(
        params.child_id,
        CheckpointClass::FsQuick,
        params.child_vm_name,
    )
    .parent(Some(parent.id))
    .created_unix(params.created_unix)
    .content(parent.content.clone())
    .supervisor_config_digest(parent.supervisor_config_digest)
    .build();
    store.write_meta(&child)?;
    Ok(child)
}

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
    /// The live VM's persisted supervisor config, copied into the checkpoint so
    /// restore can rebuild the state dir (every stop reaps the live one).
    pub supervisor_config_src: PathBuf,
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
    let content_dir = store.content_dir(&params.id);
    std::fs::create_dir_all(&content_dir)
        .with_context(|| format!("creating {}", content_dir.display()))?;

    let memory = content_dir.join("memory.bin");
    let rootfs_dst = content_dir.join("rootfs.ext4");
    let machine_id = content_dir.join("machine-id");

    control.pause().context("pausing VM for vm_full capture")?;
    // From here, RESUME on every exit path so a failure never strands the guest.
    let captured = (|| {
        control
            .save_memory(&memory)
            .context("saving machine memory")?;
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

    // Persist the launch config into the checkpoint. Restore needs it to resolve
    // the target rootfs path and to spawn the supervisor, but every stop reaps
    // the VM's state dir — so without storing it here the round-trip is
    // unreachable. (Static during the pause window; copied after resume.)
    let config_dst = content_dir.join(crate::vz::SUPERVISOR_CONFIG_FILE_NAME);
    std::fs::copy(&params.supervisor_config_src, &config_dst).with_context(|| {
        format!(
            "copying supervisor config {} into checkpoint",
            params.supervisor_config_src.display()
        )
    })?;

    let mut content = vec![
        ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: sha256_file_hex(&rootfs_dst)?,
        },
        ContentBlob {
            name: "memory.bin".into(),
            sha256: sha256_file_hex(&memory)?,
        },
        ContentBlob {
            name: "machine-id".into(),
            sha256: sha256_file_hex(&machine_id)?,
        },
        ContentBlob {
            name: crate::vz::SUPERVISOR_CONFIG_FILE_NAME.into(),
            sha256: sha256_file_hex(&config_dst)?,
        },
    ];

    // Mirror the fs_quick path: when the source rootfs directory carries a
    // mvm-meta.json sidecar, include it so that forks of this vm_full checkpoint
    // can read the sidecar from their content dir and boot through the
    // runtime-meta gate (image_is_sealed / fork grant reconciliation).
    // The sidecar read is from the static source dir — outside the pause window
    // is fine.
    let live_rootfs_for_sidecar = control.rootfs_path()?;
    if let Some(sidecar_blob) =
        copy_guest_sidecar_if_present(&live_rootfs_for_sidecar, &content_dir)?
    {
        content.push(sidecar_blob);
    }

    let meta = CheckpointMeta::builder(params.id, CheckpointClass::VmFull, params.vm_name)
        .tag(params.tag)
        .created_unix(params.created_unix)
        .content(content)
        .supervisor_config_digest(params.supervisor_config_digest)
        .build();
    store.write_meta(&meta)?;
    Ok(meta)
}

/// Restores a vm_full checkpoint's saved state into a target VM, abstracted so
/// the orchestration is testable without a live hypervisor.
pub trait VmFullRestore {
    /// Materialize `rootfs_src` onto the target VM's rootfs, then restore the
    /// machine `memory` + `machine_id`, and resume. The target must already be
    /// stopped — callers must ensure no live supervisor is racing the rootfs.
    ///
    /// `config_src`, when present, is the launch config persisted in the
    /// checkpoint; the backend rebuilds the target state dir from it (every stop
    /// reaps the live one). `None` for legacy checkpoints — fall through to the
    /// existing live-state-dir behavior.
    fn restore(
        &self,
        target_vm: &str,
        rootfs_src: &Path,
        memory: &Path,
        machine_id: &Path,
        config_src: Option<&Path>,
    ) -> Result<()>;
}

/// Rebuild a stopped VM's persisted supervisor config at `target_config` from
/// the checkpoint's `config_src`, unless one is already present. Restore needs
/// it to resolve the rootfs target + spawn the supervisor, but the per-VM
/// drainer reaps the state dir on every stop. Side-effect-free when the target
/// already exists, so it's safe to call unconditionally.
pub(crate) fn reconstruct_state_config(config_src: &Path, target_config: &Path) -> Result<()> {
    if target_config.exists() {
        return Ok(());
    }
    if let Some(parent) = target_config.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating restore target state dir {}", parent.display()))?;
    }
    std::fs::copy(config_src, target_config).with_context(|| {
        format!(
            "reconstructing supervisor config at {} from checkpoint",
            target_config.display()
        )
    })?;
    Ok(())
}

// `RestoreParams` + the CLI-facing `restore_checkpoint` orchestration (same-
// identity vm_full resume) were Vz-only and are descoped by Plan 226 R1P1
// WS-D — `mvmctl vm checkpoint restore` now always refuses (see
// `full_vm_checkpoint_unsupported_error` in `mvm-cli`'s `checkpoint.rs`).
// `VmFullRestore` itself stays defined: the vz module's backend type still
// implements it for the warm-pool claim path's own restore helper,
// independent of this descoped CLI engine.

fn sha256_file_hex(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing {}", path.display()))
}

/// Copy the `mvm-meta.json` guest sidecar from the directory that contains
/// `src_rootfs` into `content_dir`, and return a `ContentBlob` for it.
///
/// Returns `None` (no-op) when the sidecar is absent — unsealed/dev images
/// have no sidecar and must not error. Call from both `capture_fs_quick` and
/// `capture_vm_full` so that the sidecar propagation stays DRY.
fn copy_guest_sidecar_if_present(
    src_rootfs: &Path,
    content_dir: &Path,
) -> Result<Option<ContentBlob>> {
    let src_dir = src_rootfs
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let src_sidecar = src_dir.join(mvm_build::builder_vm::SIDECAR_FILENAME);
    if !src_sidecar.exists() {
        return Ok(None);
    }
    let dst_sidecar = content_dir.join(mvm_build::builder_vm::SIDECAR_FILENAME);
    std::fs::copy(&src_sidecar, &dst_sidecar).with_context(|| {
        format!(
            "copying mvm-meta.json sidecar into checkpoint content dir {}",
            content_dir.display()
        )
    })?;
    Ok(Some(ContentBlob {
        name: mvm_build::builder_vm::SIDECAR_FILENAME.into(),
        sha256: sha256_file_hex(&dst_sidecar)?,
    }))
}

/// How blob `name` differs between two checkpoints (B relative to A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobStatus {
    Unchanged,
    Changed,
    AddedInB,
    RemovedFromB,
}

/// Per-blob delta keyed by content-manifest name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlobDelta {
    pub name: String,
    pub status: BlobStatus,
    pub sha_a: Option<String>,
    pub sha_b: Option<String>,
}

/// Lineage relationship between the two checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageRelation {
    BChildOfA,
    AChildOfB,
    Same,
    Unrelated,
}

/// Structured metadata + manifest diff of two checkpoints (B relative to A).
/// Byte content is never read — a blob sha256 mismatch is the change signal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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

    let mut names: Vec<&str> = a.content.iter().map(|x| x.name.as_str()).collect();
    for blob in &b.content {
        if !names.contains(&blob.name.as_str()) {
            names.push(blob.name.as_str());
        }
    }
    names.sort_unstable();
    let sha_in = |m: &CheckpointMeta, name: &str| -> Option<String> {
        m.content
            .iter()
            .find(|x| x.name == name)
            .map(|x| x.sha256.clone())
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
            BlobDelta {
                name: name.to_string(),
                status,
                sha_a: sa,
                sha_b: sb,
            }
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

    let name = file_name.to_string_lossy().into_owned();
    let content_sha256 = sha256_file_hex(&dst)?;
    let mut content = vec![ContentBlob {
        name,
        sha256: content_sha256,
    }];

    // When the source rootfs directory carries a mvm-meta.json sidecar, include it
    // as a second blob so that any fork materialised from this checkpoint can boot
    // through the runtime-meta gate (which reads the sidecar from the rootfs dir).
    if let Some(sidecar_blob) = copy_guest_sidecar_if_present(&params.rootfs, &content_dir)? {
        content.push(sidecar_blob);
    }

    let meta = CheckpointMeta::builder(params.id, CheckpointClass::FsQuick, params.vm_name)
        .tag(params.tag)
        .created_unix(params.created_unix)
        .content(content)
        .supervisor_config_digest(params.supervisor_config_digest)
        .build();
    store.write_meta(&meta)?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob};

    fn meta(id: &str, tag: Option<&str>, parent: Option<&str>) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .tag(tag.map(String::from))
            .parent(parent.map(CheckpointId::new))
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "h".into(),
            }])
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
        store
            .write_meta(&meta("child", None, Some("parent")))
            .unwrap();
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
                child_plan_json: None,
                child_tenant_id: None,
            },
        )
        .unwrap();
        assert_eq!(child.parent.as_ref().unwrap(), &parent.id);
        assert_eq!(child.vm_name, "childvm");
        assert_eq!(
            std::fs::read(dst.join("rootfs.ext4")).unwrap(),
            b"fake-ext4-bytes"
        );
        // byte-identical clone → manifest hashes are preserved
        assert_eq!(child.content, parent.content);
        assert_eq!(store.children_of(&parent.id).unwrap().len(), 1);
    }

    #[test]
    fn fork_checkpoint_redirects_vm_full_to_fork_vm_full() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let m = CheckpointMeta::builder(CheckpointId::new("vf"), CheckpointClass::VmFull, "vm")
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "h".into(),
            }])
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
                child_plan_json: None,
                child_tenant_id: None,
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
                child_plan_json: None,
                child_tenant_id: None,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("integrity") || err.to_string().contains("sha256"));
    }

    // ── capture sidecar tests ────────────────────────────────────────────────

    fn seed_fs_quick_with_sidecar(store: &CheckpointStore, tmp: &Path, id: &str) -> CheckpointMeta {
        let rootfs = write_fake_rootfs(tmp);
        std::fs::write(
            tmp.join(mvm_build::builder_vm::SIDECAR_FILENAME),
            br#"{"accessible":true,"overlay_aware":false}"#,
        )
        .unwrap();
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
    fn capture_includes_sidecar_blob_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_fs_quick_with_sidecar(&store, tmp.path(), "c1");
        assert_eq!(meta.content.len(), 2, "rootfs + sidecar blobs expected");
        let names: Vec<&str> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"rootfs.ext4"));
        assert!(names.contains(&mvm_build::builder_vm::SIDECAR_FILENAME));
        // sha256 is non-empty
        let sidecar_blob = meta
            .content
            .iter()
            .find(|b| b.name == mvm_build::builder_vm::SIDECAR_FILENAME)
            .unwrap();
        assert!(!sidecar_blob.sha256.is_empty());
    }

    #[test]
    fn capture_has_single_blob_without_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_fs_quick_checkpoint(&store, tmp.path(), "c1");
        assert_eq!(meta.content.len(), 1, "only rootfs blob when no sidecar");
        assert_eq!(meta.content[0].name, "rootfs.ext4");
    }

    #[test]
    fn fork_two_blob_checkpoint_materializes_both_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_with_sidecar(&store, tmp.path(), "p1");
        assert_eq!(parent.content.len(), 2);
        let dst = tmp.path().join("childvm-state");
        let child = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("f1"),
                child_vm_name: "childvm".into(),
                dest_dir: dst.clone(),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
        )
        .unwrap();
        assert_eq!(child.content.len(), 2);
        assert!(
            dst.join("rootfs.ext4").exists(),
            "rootfs must be present in dest"
        );
        assert!(
            dst.join(mvm_build::builder_vm::SIDECAR_FILENAME).exists(),
            "sidecar must be present in dest"
        );
        // The lineage metadata carries the same two blob records as the parent.
        assert!(child.content.iter().any(|b| b.name == "rootfs.ext4"));
        assert!(
            child
                .content
                .iter()
                .any(|b| b.name == mvm_build::builder_vm::SIDECAR_FILENAME)
        );
    }

    #[test]
    fn verify_content_passes_for_intact_blobs_and_fails_on_tamper() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        verify_content(&store, &parent).unwrap();
        // tamper the single blob
        let blob = store.content_dir(&parent.id).join("rootfs.ext4");
        std::fs::write(&blob, b"tampered").unwrap();
        assert!(verify_content(&store, &parent).is_err());
    }

    use std::cell::RefCell;

    struct MockControl {
        rootfs: PathBuf,
        events: RefCell<Vec<&'static str>>,
    }
    impl VmFullControl for MockControl {
        fn pause(&self) -> Result<()> {
            self.events.borrow_mut().push("pause");
            Ok(())
        }
        fn resume(&self) -> Result<()> {
            self.events.borrow_mut().push("resume");
            Ok(())
        }
        fn save_memory(&self, memory_path: &Path) -> Result<()> {
            self.events.borrow_mut().push("save");
            std::fs::write(memory_path, b"mem").unwrap();
            std::fs::write(format!("{}.machine-id", memory_path.display()), b"mid").unwrap();
            Ok(())
        }
        fn rootfs_path(&self) -> Result<PathBuf> {
            Ok(self.rootfs.clone())
        }
    }

    #[test]
    fn capture_vm_full_orders_pause_save_clone_resume_and_builds_triple() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = tmp.path().join("live-rootfs.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        let ctl = MockControl {
            rootfs,
            events: RefCell::new(vec![]),
        };
        let config = tmp.path().join("supervisor-config.json");
        std::fs::write(&config, b"{\"cfg\":true}").unwrap();
        let meta = capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: CheckpointId::new("v1"),
                vm_name: "vm".into(),
                supervisor_config_digest: "d".into(),
                supervisor_config_src: config,
                tag: None,
                created_unix: 9,
            },
            &ctl,
        )
        .unwrap();
        assert_eq!(*ctl.events.borrow(), vec!["pause", "save", "resume"]);
        assert_eq!(meta.class, CheckpointClass::VmFull);
        let names: Vec<_> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(
            names.contains(&"rootfs.ext4")
                && names.contains(&"memory.bin")
                && names.contains(&"machine-id")
                // The launch config is now captured so restore can rebuild the
                // reaped state dir.
                && names.contains(&"supervisor-config.json")
        );
        verify_content(&store, &meta).unwrap();
    }

    #[test]
    fn capture_vm_full_includes_sidecar_blob_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        // Place the rootfs and the sidecar in the same directory so that the
        // parent-dir lookup finds the sidecar alongside the rootfs.
        let rootfs_dir = tmp.path().join("vm-state");
        std::fs::create_dir_all(&rootfs_dir).unwrap();
        let rootfs = rootfs_dir.join("rootfs.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        std::fs::write(
            rootfs_dir.join(mvm_build::builder_vm::SIDECAR_FILENAME),
            br#"{"accessible":true,"overlay_aware":false}"#,
        )
        .unwrap();
        let ctl = MockControl {
            rootfs,
            events: RefCell::new(vec![]),
        };
        let config = tmp.path().join("supervisor-config.json");
        std::fs::write(&config, b"{\"cfg\":true}").unwrap();
        let meta = capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: CheckpointId::new("v2"),
                vm_name: "vm".into(),
                supervisor_config_digest: "d".into(),
                supervisor_config_src: config,
                tag: None,
                created_unix: 10,
            },
            &ctl,
        )
        .unwrap();
        let names: Vec<&str> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(
            names.contains(&mvm_build::builder_vm::SIDECAR_FILENAME),
            "expected sidecar blob in vm_full content; got {names:?}"
        );
        let sidecar_blob = meta
            .content
            .iter()
            .find(|b| b.name == mvm_build::builder_vm::SIDECAR_FILENAME)
            .unwrap();
        assert!(
            !sidecar_blob.sha256.is_empty(),
            "sidecar sha256 must be non-empty"
        );
        // integrity check must pass (blob is on disk at the right hash)
        verify_content(&store, &meta).unwrap();
        // The sidecar file must actually be present in the content dir.
        assert!(
            store
                .content_dir(&meta.id)
                .join(mvm_build::builder_vm::SIDECAR_FILENAME)
                .exists(),
            "sidecar must be on disk in the checkpoint content dir"
        );
    }

    #[test]
    fn capture_vm_full_no_sidecar_blob_without_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = tmp.path().join("live-rootfs.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        // No sidecar in tmp.path() — the rootfs parent dir is clean.
        let ctl = MockControl {
            rootfs,
            events: RefCell::new(vec![]),
        };
        let config = tmp.path().join("supervisor-config.json");
        std::fs::write(&config, b"{\"cfg\":true}").unwrap();
        let meta = capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: CheckpointId::new("v3"),
                vm_name: "vm".into(),
                supervisor_config_digest: "d".into(),
                supervisor_config_src: config,
                tag: None,
                created_unix: 11,
            },
            &ctl,
        )
        .unwrap();
        let names: Vec<&str> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(
            !names.contains(&mvm_build::builder_vm::SIDECAR_FILENAME),
            "no sidecar expected when source dir has none; got {names:?}"
        );
    }

    #[test]
    fn reconstruct_state_config_writes_when_absent_and_is_a_noop_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.json");
        std::fs::write(&src, b"FROM-CHECKPOINT").unwrap();

        // Absent target → reconstructed (parent dir created) from the source.
        let target = tmp.path().join("vms/origin/supervisor-config.json");
        reconstruct_state_config(&src, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"FROM-CHECKPOINT");

        // Present target → left untouched (a live config wins, never clobbered).
        std::fs::write(&target, b"LIVE").unwrap();
        reconstruct_state_config(&src, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"LIVE");
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
        let content_blob = store.content_dir(&meta.id).join("rootfs.ext4");
        assert_eq!(std::fs::read(&content_blob).unwrap(), b"fake-ext4-bytes");
        assert_eq!(meta.content.len(), 1);
        assert_eq!(meta.content[0].name, "rootfs.ext4");
        assert_eq!(meta.content[0].sha256.len(), 64);
        assert_eq!(meta.tag.as_deref(), Some("gold"));
        assert_eq!(store.read_meta(&meta.id).unwrap(), meta);
    }

    fn fs_quick_meta(id: &str, vm: &str, parent: Option<&str>, rootfs_sha: &str) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, vm)
            .parent(parent.map(CheckpointId::new))
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: rootfs_sha.into(),
            }])
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
        let a = fs_quick_meta("a", "vm", None, "aaaa");
        let b = CheckpointMeta::builder(CheckpointId::new("b"), CheckpointClass::VmFull, "vm")
            .content(vec![
                ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "aaaa".into(),
                },
                ContentBlob {
                    name: "memory.bin".into(),
                    sha256: "mmmm".into(),
                },
                ContentBlob {
                    name: "machine-id".into(),
                    sha256: "iiii".into(),
                },
            ])
            .supervisor_config_digest("cfg")
            .created_unix(11)
            .build();
        let d = diff_checkpoints(&a, &b);
        assert_eq!(
            d.blobs
                .iter()
                .find(|x| x.name == "memory.bin")
                .unwrap()
                .status,
            BlobStatus::AddedInB
        );
        assert_eq!(
            d.blobs
                .iter()
                .find(|x| x.name == "rootfs.ext4")
                .unwrap()
                .status,
            BlobStatus::Unchanged
        );
        assert_eq!(d.class_a, CheckpointClass::FsQuick);
        assert_eq!(d.class_b, CheckpointClass::VmFull);
        let d2 = diff_checkpoints(&b, &a);
        assert_eq!(
            d2.blobs
                .iter()
                .find(|x| x.name == "memory.bin")
                .unwrap()
                .status,
            BlobStatus::RemovedFromB
        );
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
}
