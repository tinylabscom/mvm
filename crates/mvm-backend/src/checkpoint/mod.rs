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

/// Child inherits the parent checkpoint's machine-id (boot-id / systemd
/// machine-id continuity) rather than minting a fresh one. The forked memory
/// state was captured WITH that identity, so restoring it demands the same id.
///
/// COUPLED with [`FORK_ALLOW_PARENT_RUNNING`]: a fresh id cannot work for a
/// memory restore — VZ validates the machine identifier against the saved
/// state, and the restored memory was captured under the parent's id. Two
/// live VMs sharing a machine-id (and MAC) is the clone model: harmless
/// while every VM sits behind its own gvproxy with no shared L2 segment,
/// which is the invariant that makes the running-parent fork sound.
const FORK_FRESH_MACHINE_ID: bool = false;

/// The fork's source is the sealed checkpoint content (cloned at capture
/// time), never the parent's live disks, so a running parent races nothing.
/// The child duplicates the parent's machine-id and MAC by construction —
/// the restored memory embodies them and VZ validates the device config
/// against the saved state — which is collision-free because every VM runs
/// behind its own gvproxy instance with no shared L2 segment.
const FORK_ALLOW_PARENT_RUNNING: bool = true;

/// Spawns a forked child's supervisor in restore mode from its rewritten
/// `SupervisorConfig`. Abstracted so `fork_vm_full` is testable without booting
/// a real hypervisor; the Vz impl (`VzChildSupervisorSpawner`) lives in `vz`.
pub trait ChildSupervisorSpawner {
    fn spawn(&self, config: &mvm_build::vz::SupervisorConfig) -> Result<()>;
}

/// Branch a new sandbox lineage from a checkpoint: verify the source content's
/// integrity, CoW-clone it into `dest_dir`, and record a child checkpoint whose
/// `parent` points back to the source. Boot of the child is the caller's job.
///
/// fs_quick only — a vm_full checkpoint carries saved memory and must be forked
/// through [`fork_vm_full`], which rewrites the supervisor config and restores
/// the memory state into the new identity.
pub fn fork_checkpoint(store: &CheckpointStore, params: ForkParams) -> Result<CheckpointMeta> {
    let parent = store.read_meta(&params.checkpoint)?;
    if parent.class != CheckpointClass::FsQuick {
        anyhow::bail!(
            "cannot fork checkpoint '{}' (class vm_full) via fork_checkpoint; use fork_vm_full",
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

/// Branch a NEW VM identity from a vm_full checkpoint and boot it (restore-as-
/// new): verify the source triple, clone {rootfs, memory, machine-id} into the
/// child's state dir, rewrite the parent's supervisor config for the child
/// identity, spawn it in restore mode, and record lineage.
///
/// The parent VM MAY be running (see `FORK_ALLOW_PARENT_RUNNING`): the fork
/// clones the sealed checkpoint content, not the parent's live disks. The child
/// inherits the parent's machine-id (see `FORK_FRESH_MACHINE_ID`).
///
/// Claim-8: `params.child_plan_json` and `params.child_tenant_id` carry the
/// child's own admitted plan; the spawner injects them into the child's
/// `SupervisorConfig` so the in-process supervisor re-verifies at start. The
/// caller (CLI) must admit the plan and hash the child's materialized rootfs
/// before calling this function; `None` here skips enforcement (dev/test only).
///
/// Gvproxy-only invariant: the parent config's network must be `Gvproxy` or
/// `None`. A non-gvproxy attachment (e.g. a future bridge-style variant) is
/// refused — an inherited MAC is safe only when every VM sits behind its own
/// per-VM gvproxy with no shared L2 segment.
pub fn fork_vm_full(
    store: &CheckpointStore,
    params: ForkParams,
    spawner: &dyn ChildSupervisorSpawner,
) -> Result<CheckpointMeta> {
    let parent = store.read_meta(&params.checkpoint)?;
    if parent.class != CheckpointClass::VmFull {
        anyhow::bail!(
            "cannot fork_vm_full checkpoint '{}' (class fs_quick); use fork_checkpoint",
            parent.id
        );
    }
    verify_content(store, &parent)?;

    if !FORK_ALLOW_PARENT_RUNNING && vm_is_running(&parent.vm_name) {
        anyhow::bail!(
            "cannot fork checkpoint '{}': parent VM '{}' is still running; stop it first",
            parent.id,
            parent.vm_name
        );
    }

    let parent_cfg_path =
        crate::vz::supervisor_config_path(&mvm_core::config::vm_state_dir(&parent.vm_name));
    let parent_cfg_bytes = std::fs::read(&parent_cfg_path).with_context(|| {
        format!(
            "reading parent supervisor config {}",
            parent_cfg_path.display()
        )
    })?;
    let parent_cfg: mvm_build::vz::SupervisorConfig = serde_json::from_slice(&parent_cfg_bytes)
        .with_context(|| format!("parsing {}", parent_cfg_path.display()))?;

    // Gvproxy-only invariant, checked BEFORE any materialization so a refusal
    // leaves no half-built child state dir: an inherited MAC is collision-free
    // only when both VMs run behind separate gvproxy instances with no shared
    // L2 segment. A non-gvproxy network config (future bridge variant) would
    // violate this; refuse hard, not advisory.
    if let Some(ref net) = parent_cfg.network {
        anyhow::ensure!(
            matches!(net, mvm_build::vz::NetworkConfig::Gvproxy { .. }),
            "vm_full fork requires a gvproxy network config (parent '{}' has a non-gvproxy \
             attachment); memory-forked children inherit the parent MAC, which is safe only \
             when each VM runs behind its own per-VM gvproxy",
            parent.vm_name
        );
    }

    // Clone the captured triple into the child's state dir, then boot the child
    // from its OWN copies — never the parent's live blobs.
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

    let memory_path = params.dest_dir.join("memory.bin");
    let machine_id_path = params.dest_dir.join("machine-id");
    // FORK_FRESH_MACHINE_ID=false → pass the inherited machine-id sidecar so the
    // restored guest keeps the identity its memory state was captured with.
    let machine_id_arg = (!FORK_FRESH_MACHINE_ID).then_some(machine_id_path.as_path());
    let mut child_cfg = crate::vz::build_child_supervisor_config(
        &parent_cfg,
        &params.child_vm_name,
        &params.dest_dir,
        &memory_path,
        machine_id_arg,
    )?;

    // Inject the child's own admitted plan (claim 8). `build_child_supervisor_config`
    // cleared the inherited parent plan fields; set the child's here so the supervisor
    // re-verifies under the child's identity, not the parent's.
    if let Some(ref plan_json) = params.child_plan_json {
        child_cfg.plan = Some(
            serde_json::from_str(plan_json)
                .context("parsing child plan_json for child SupervisorConfig")?,
        );
    }
    if let Some(ref tenant_id) = params.child_tenant_id {
        // Re-derive the audit substrate paths that key off the tenant/VM name
        // now that we have an admitted child identity.
        let substrate = crate::audit_substrate::compute_audit_substrate(
            &params.child_vm_name,
            Some(tenant_id.as_str()),
        )
        .context("computing audit substrate for forked child")?;
        child_cfg.tenant_id = substrate.tenant_id;
        child_cfg.audit_dir = substrate
            .audit_dir
            .map(|p| p.to_string_lossy().into_owned());
        child_cfg.gateway_audit_socket = substrate
            .gateway_audit_socket
            .map(|p| p.to_string_lossy().into_owned());
        child_cfg.signing_key_path = substrate
            .signing_key_path
            .map(|p| p.to_string_lossy().into_owned());
        // Re-enable the claim-10 bridge ingest socket on the child's gvproxy
        // attachment now that the child has an admitted plan + tenant.
        if let Some(mvm_build::vz::NetworkConfig::Gvproxy {
            ref mut events_ingest_socket_path,
            ..
        }) = child_cfg.network
        {
            *events_ingest_socket_path = substrate
                .gateway_events_socket
                .map(|p| p.to_string_lossy().into_owned());
        }
    }

    spawner.spawn(&child_cfg)?;

    let child = CheckpointMeta::builder(
        params.child_id,
        CheckpointClass::VmFull,
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

/// Liveness probe for a VM by name: a non-stale `vz.pid` whose process still
/// exists. Mirrors the host-side pid-file convention the Vz backend writes.
fn vm_is_running(vm_name: &str) -> bool {
    let pid_file = mvm_core::config::vm_state_dir(vm_name).join("vz.pid");
    let Ok(s) = std::fs::read_to_string(&pid_file) else {
        return false;
    };
    let Ok(pid) = s.trim().parse::<i32>() else {
        return false;
    };
    // kill(pid, 0) → 0 if the process exists, -1/ESRCH if not.
    unsafe { libc::kill(pid, 0) == 0 }
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

    let content = vec![
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

/// Restores a vm_full checkpoint's saved state into a target VM, abstracted so
/// the orchestration is testable without a live hypervisor.
pub trait VmFullRestore {
    /// Materialize `rootfs_src` onto the target VM's rootfs, then restore the
    /// machine `memory` + `machine_id`, and resume. The target must already be
    /// stopped — callers must ensure no live supervisor is racing the rootfs.
    fn restore(
        &self,
        target_vm: &str,
        rootfs_src: &Path,
        memory: &Path,
        machine_id: &Path,
    ) -> Result<()>;
}

pub struct RestoreParams {
    pub checkpoint: CheckpointId,
    /// Name of the VM to restore into (must match the supervisor-config shape).
    pub target_vm: String,
}

/// Resume a VM from a vm_full checkpoint (same identity). Verifies the manifest,
/// then hands the three blob paths to the restore seam. Refusing fs_quick here is
/// deliberate: fs_quick has no memory state, so `fork_checkpoint` is the right verb.
pub fn restore_checkpoint(
    store: &CheckpointStore,
    params: RestoreParams,
    restore: &dyn VmFullRestore,
) -> Result<()> {
    let meta = store.read_meta(&params.checkpoint)?;
    if meta.class != CheckpointClass::VmFull {
        anyhow::bail!(
            "checkpoint '{}' is class fs_quick; restore applies to vm_full checkpoints \
             (fork an fs_quick checkpoint instead)",
            meta.id
        );
    }
    verify_content(store, &meta)?;
    let dir = store.content_dir(&meta.id);
    restore.restore(
        &params.target_vm,
        &dir.join("rootfs.ext4"),
        &dir.join("memory.bin"),
        &dir.join("machine-id"),
    )
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing {}", path.display()))
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
    let src_dir = params
        .rootfs
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let src_sidecar = src_dir.join(mvm_build::builder_vm::SIDECAR_FILENAME);
    if src_sidecar.exists() {
        let dst_sidecar = content_dir.join(mvm_build::builder_vm::SIDECAR_FILENAME);
        std::fs::copy(&src_sidecar, &dst_sidecar).with_context(|| {
            format!(
                "copying mvm-meta.json sidecar into checkpoint content dir {}",
                content_dir.display()
            )
        })?;
        content.push(ContentBlob {
            name: mvm_build::builder_vm::SIDECAR_FILENAME.into(),
            sha256: sha256_file_hex(&dst_sidecar)?,
        });
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
        )
        .unwrap();
        assert_eq!(*ctl.events.borrow(), vec!["pause", "save", "resume"]);
        assert_eq!(meta.class, CheckpointClass::VmFull);
        let names: Vec<_> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(
            names.contains(&"rootfs.ext4")
                && names.contains(&"memory.bin")
                && names.contains(&"machine-id")
        );
        verify_content(&store, &meta).unwrap();
    }

    struct MockRestore {
        seen: RefCell<Option<(String, PathBuf, PathBuf, PathBuf)>>,
    }
    impl VmFullRestore for MockRestore {
        fn restore(
            &self,
            target_vm: &str,
            rootfs_src: &Path,
            memory: &Path,
            machine_id: &Path,
        ) -> Result<()> {
            *self.seen.borrow_mut() = Some((
                target_vm.to_string(),
                rootfs_src.to_path_buf(),
                memory.to_path_buf(),
                machine_id.to_path_buf(),
            ));
            Ok(())
        }
    }

    fn seed_vm_full_checkpoint(store: &CheckpointStore, tmp: &Path, id: &str) -> CheckpointMeta {
        let rootfs = tmp.join("live.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        let ctl = MockControl {
            rootfs,
            events: RefCell::new(vec![]),
        };
        capture_vm_full(
            store,
            CaptureVmFullParams {
                id: CheckpointId::new(id),
                vm_name: "origin".into(),
                supervisor_config_digest: "d".into(),
                tag: None,
                created_unix: 1,
            },
            &ctl,
        )
        .unwrap()
    }

    #[test]
    fn restore_checkpoint_verifies_then_hands_blobs_to_restore_seam() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let ckpt = seed_vm_full_checkpoint(&store, tmp.path(), "v1");
        let restore = MockRestore {
            seen: RefCell::new(None),
        };
        restore_checkpoint(
            &store,
            RestoreParams {
                checkpoint: ckpt.id.clone(),
                target_vm: "origin".into(),
            },
            &restore,
        )
        .unwrap();
        let (vm, r, m, mid) = restore.seen.borrow().clone().unwrap();
        let cdir = store.content_dir(&ckpt.id);
        assert_eq!(vm, "origin");
        assert_eq!(r, cdir.join("rootfs.ext4"));
        assert_eq!(m, cdir.join("memory.bin"));
        assert_eq!(mid, cdir.join("machine-id"));
    }

    #[test]
    fn restore_checkpoint_refuses_fs_quick() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let fsq = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let restore = MockRestore {
            seen: RefCell::new(None),
        };
        let err = restore_checkpoint(
            &store,
            RestoreParams {
                checkpoint: fsq.id,
                target_vm: "origin".into(),
            },
            &restore,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("vm_full") || err.to_string().contains("fs_quick"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn restore_checkpoint_refuses_tampered_content() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let ckpt = seed_vm_full_checkpoint(&store, tmp.path(), "v2");
        // Tamper a blob after capture.
        let blob = store.content_dir(&ckpt.id).join("memory.bin");
        std::fs::write(&blob, b"tampered").unwrap();
        let restore = MockRestore {
            seen: RefCell::new(None),
        };
        let err = restore_checkpoint(
            &store,
            RestoreParams {
                checkpoint: ckpt.id,
                target_vm: "origin".into(),
            },
            &restore,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("integrity") || err.to_string().contains("sha256"),
            "unexpected error: {err}"
        );
        // Restore seam must NOT have been called on a tampered checkpoint.
        assert!(restore.seen.borrow().is_none());
    }

    struct MockSpawner {
        seen: RefCell<Option<mvm_build::vz::SupervisorConfig>>,
    }
    impl ChildSupervisorSpawner for MockSpawner {
        fn spawn(&self, config: &mvm_build::vz::SupervisorConfig) -> Result<()> {
            *self.seen.borrow_mut() = Some(config.clone());
            Ok(())
        }
    }

    fn write_parent_supervisor_config(vm_name: &str) {
        // vm_state_dir(vm_name) resolves under MVM_DATA_DIR (set by the caller).
        let dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = mvm_build::vz::SupervisorConfig {
            name: vm_name.into(),
            vm_state_dir: dir.to_string_lossy().into_owned(),
            pid_file_name: Some("vz.pid".into()),
            kernel: mvm_build::vz::KernelConfig {
                path: "/abs/vmlinux".into(),
                cmdline: "console=hvc0 root=/dev/vda".into(),
                initrd_path: None,
            },
            resources: mvm_build::vz::ResourceConfig {
                cpu_count: 2,
                memory_mib: 1024,
            },
            disks: vec![mvm_build::vz::DiskConfig {
                id: "rootfs".into(),
                path: dir.join("rootfs.ext4").to_string_lossy().into_owned(),
                read_only: true,
            }],
            virtio_fs: vec![],
            vsock: mvm_build::vz::VsockConfig {
                ports: vec![],
                socket_dir: dir.join("vsock").to_string_lossy().into_owned(),
                host_listen_ports: vec![],
            },
            console_output_path: None,
            network: Some(mvm_build::vz::NetworkConfig::Gvproxy {
                socket_path: "/gv.sock".into(),
                mac: mvm_build::host_gvproxy::derive_mac(vm_name),
                events_ingest_socket_path: None,
            }),
            balloon: None,
            control_socket_path: None,
            startup_mode: mvm_build::vz::StartupMode::Boot,
            tenant_id: None,
            plan: None,
            bundle: None,
            audit_dir: None,
            gateway_audit_socket: None,
            signing_key_path: None,
        };
        std::fs::write(dir.join("supervisor-config.json"), cfg.to_json().unwrap()).unwrap();
    }

    #[test]
    fn fork_vm_full_clones_triple_rewrites_config_and_records_lineage() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let store = CheckpointStore::at(tmp.path().join("store"));
        // seed_vm_full_checkpoint uses vm_name "origin"; give it a parent config.
        let parent = seed_vm_full_checkpoint(&store, tmp.path(), "v1");
        write_parent_supervisor_config(&parent.vm_name);

        let dest = tmp.path().join("childvm-state");
        let spawner = MockSpawner {
            seen: RefCell::new(None),
        };
        let child = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("f1"),
                child_vm_name: "childvm".into(),
                dest_dir: dest.clone(),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &spawner,
        )
        .unwrap();

        // All three blobs cloned into the child dir.
        for name in ["rootfs.ext4", "memory.bin", "machine-id"] {
            assert!(dest.join(name).exists(), "{name} not cloned");
        }
        // Lineage + class + content carried over.
        assert_eq!(child.class, CheckpointClass::VmFull);
        assert_eq!(child.parent.as_ref().unwrap(), &parent.id);
        assert_eq!(child.vm_name, "childvm");
        assert_eq!(child.content, parent.content);
        assert_eq!(child.content.len(), 3);

        // Spawner invoked with the rewritten child config.
        let cfg = spawner.seen.borrow().clone().unwrap();
        assert_eq!(cfg.name, "childvm");
        assert_eq!(cfg.vm_state_dir, dest.to_string_lossy());
        let rootfs = cfg.disks.iter().find(|d| d.id == "rootfs").unwrap();
        assert_eq!(rootfs.path, dest.join("rootfs.ext4").to_string_lossy());
        match &cfg.startup_mode {
            mvm_build::vz::StartupMode::Restore {
                snapshot_path,
                machine_id_path,
            } => {
                assert_eq!(
                    snapshot_path,
                    &dest.join("memory.bin").display().to_string()
                );
                assert_eq!(
                    machine_id_path.as_deref(),
                    Some(dest.join("machine-id").display().to_string()).as_deref()
                );
            }
            other => panic!("expected Restore, got {other:?}"),
        }

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    #[test]
    fn fork_vm_full_refuses_fs_quick() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }
        let store = CheckpointStore::at(tmp.path().join("store"));
        let fsq = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let spawner = MockSpawner {
            seen: RefCell::new(None),
        };
        let err = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: fsq.id,
                child_id: CheckpointId::new("f"),
                child_vm_name: "c".into(),
                dest_dir: tmp.path().join("d"),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &spawner,
        )
        .unwrap_err();
        assert!(err.to_string().contains("fs_quick"), "unexpected: {err}");
        assert!(spawner.seen.borrow().is_none());
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
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

    // ── vm_full fork: running-parent allowed ─────────────────────────────────

    /// With FORK_ALLOW_PARENT_RUNNING=true, fork_vm_full no longer refuses when
    /// a live pid is present for the parent VM. The fork clones the sealed
    /// checkpoint content, not the parent's live disks, so a running parent is safe.
    #[test]
    fn fork_vm_full_allows_running_parent() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_vm_full_checkpoint(&store, tmp.path(), "v1");
        write_parent_supervisor_config(&parent.vm_name);

        // Write a live-looking vz.pid for the parent VM so vm_is_running() returns true.
        // Use the test process's own pid so kill(pid,0) succeeds.
        let origin_state = mvm_core::config::vm_state_dir(&parent.vm_name);
        std::fs::create_dir_all(&origin_state).unwrap();
        let pid = unsafe { libc::getpid() };
        std::fs::write(origin_state.join("vz.pid"), pid.to_string()).unwrap();

        // With FORK_ALLOW_PARENT_RUNNING=true, fork must succeed despite the live pid.
        let dest = tmp.path().join("childvm-state");
        let spawner = MockSpawner {
            seen: RefCell::new(None),
        };
        let result = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("f-running"),
                child_vm_name: "childvm-running".into(),
                dest_dir: dest.clone(),
                created_unix: 3,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &spawner,
        );
        assert!(
            result.is_ok(),
            "fork_vm_full must allow a running parent (FORK_ALLOW_PARENT_RUNNING=true): {result:?}"
        );
        // Spawner was still invoked.
        assert!(spawner.seen.borrow().is_some());

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    // ── vm_full fork: gvproxy-only invariant ─────────────────────────────────

    /// `network: None` passes the gvproxy-only gate (no NIC = no MAC to
    /// collide). The refusal arm is unreachable today — `NetworkConfig` has
    /// only the `Gvproxy` variant — so this pins the accept side; the gate
    /// exists to fail hard if a bridge-style variant is ever added.
    #[test]
    fn fork_vm_full_accepts_none_network() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_vm_full_checkpoint(&store, tmp.path(), "v1");

        // Write a parent supervisor config with a non-gvproxy (None) network that
        // has been replaced by a hypothetical "bridge" variant — simulate by
        // writing a config whose network is None and verifying the fork still works
        // (None is accepted). Then test with a real variant to ensure the check fires.
        // Since NetworkConfig has only Gvproxy today, test the None path (accepted)
        // and the Gvproxy path (accepted), and verify the error message names the
        // invariant.
        //
        // Write a parent config with network=None: fork must succeed (None means no
        // networking — the invariant only blocks a non-gvproxy L2 attachment).
        let dir = mvm_core::config::vm_state_dir(&parent.vm_name);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg_none = mvm_build::vz::SupervisorConfig {
            name: parent.vm_name.clone(),
            vm_state_dir: dir.to_string_lossy().into_owned(),
            pid_file_name: Some("vz.pid".into()),
            kernel: mvm_build::vz::KernelConfig {
                path: "/abs/vmlinux".into(),
                cmdline: "console=hvc0".into(),
                initrd_path: None,
            },
            resources: mvm_build::vz::ResourceConfig {
                cpu_count: 2,
                memory_mib: 1024,
            },
            disks: vec![mvm_build::vz::DiskConfig {
                id: "rootfs".into(),
                path: dir.join("rootfs.ext4").to_string_lossy().into_owned(),
                read_only: true,
            }],
            virtio_fs: vec![],
            vsock: mvm_build::vz::VsockConfig {
                ports: vec![],
                socket_dir: dir.join("vsock").to_string_lossy().into_owned(),
                host_listen_ports: vec![],
            },
            console_output_path: None,
            network: None,
            balloon: None,
            control_socket_path: None,
            startup_mode: mvm_build::vz::StartupMode::Boot,
            tenant_id: None,
            plan: None,
            bundle: None,
            audit_dir: None,
            gateway_audit_socket: None,
            signing_key_path: None,
        };
        std::fs::write(
            dir.join("supervisor-config.json"),
            cfg_none.to_json().unwrap(),
        )
        .unwrap();

        let spawner = MockSpawner {
            seen: RefCell::new(None),
        };
        let result = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("f-none-net"),
                child_vm_name: "childvm-none-net".into(),
                dest_dir: tmp.path().join("dest-none"),
                created_unix: 4,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &spawner,
        );
        assert!(
            result.is_ok(),
            "fork_vm_full with network=None must succeed (no L2 attachment): {result:?}"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    // ── vm_full fork: child plan injection ───────────────────────────────────

    /// When ForkParams carries a child_plan_json, fork_vm_full injects it into
    /// the spawned child config's `plan` field. The parent's plan is NOT reused.
    #[test]
    fn fork_vm_full_injects_child_plan_into_spawned_config() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_vm_full_checkpoint(&store, tmp.path(), "v1");
        write_parent_supervisor_config(&parent.vm_name);

        let child_plan = serde_json::json!({"workload": "childvm", "type": "child-plan"});
        let child_plan_json = serde_json::to_string(&child_plan).unwrap();

        let dest = tmp.path().join("child-plan-state");
        let spawner = MockSpawner {
            seen: RefCell::new(None),
        };
        fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("f-plan"),
                child_vm_name: "childvm-plan".into(),
                dest_dir: dest.clone(),
                created_unix: 5,
                child_plan_json: Some(child_plan_json.clone()),
                child_tenant_id: None,
            },
            &spawner,
        )
        .unwrap();

        let cfg = spawner.seen.borrow().clone().unwrap();
        // Child carries the injected plan, not None and not the parent's plan.
        assert!(
            cfg.plan.is_some(),
            "child config must carry the injected plan"
        );
        let plan_json = serde_json::to_string(cfg.plan.as_ref().unwrap()).unwrap();
        assert_eq!(
            plan_json, child_plan_json,
            "child plan must match the injected value"
        );
        // No plan leakage from the parent config (which had plan=None).
        // Confirm tenant_id also comes from ForkParams (None here → no substrate).
        assert!(
            cfg.tenant_id.is_none(),
            "tenant_id must be None when child_tenant_id was not provided"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }
}
