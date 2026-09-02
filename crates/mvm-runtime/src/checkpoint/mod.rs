//! Host-side checkpoint store + the fs_quick capture/fork operations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::{
    CheckpointClass, CheckpointDigest, CheckpointId, CheckpointMeta, ContentBlob,
};
use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotId, SnapshotStore};
use mvm_fs::trusted_snapshot::TrustedSnapshotBackend;

use crate::lineage::{LineageAnchor, LineageGraph, LineageRecord};

mod params;
pub use params::{
    CaptureFsQuickParams, CaptureFsQuickParamsBuilder, CaptureVmFullParams,
    CaptureVmFullParamsBuilder, ForkParams, ForkParamsBuilder,
};

pub use mvm_core::checkpoint::SUPERVISOR_CONFIG_BLOB as SUPERVISOR_CONFIG_FILE_NAME;

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

    /// Checkpoints whose parent hash-link is `parent_digest` (its parent's
    /// content-address). Lineage is derived by digest, not by mutable name.
    pub fn children_of(&self, parent_digest: &CheckpointDigest) -> Result<Vec<CheckpointMeta>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|m| m.parent.as_ref() == Some(parent_digest))
            .collect())
    }

    /// Look up a checkpoint by its content-address ([`CheckpointMeta::meta_digest`]).
    /// Scans `list()`; `Ok(None)` when no stored record carries that digest.
    pub fn by_digest(&self, digest: &CheckpointDigest) -> Result<Option<CheckpointMeta>> {
        Ok(self.list()?.into_iter().find(|m| &m.meta_digest == digest))
    }

    pub fn remove(&self, id: &CheckpointId) -> Result<()> {
        let dir = self.dir_for(id);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("removing {}", dir.display()));
            }
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
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

/// Resolves the signature-authenticated content-address a checkpoint's creation
/// was recorded under in the chain-signed audit log.
///
/// Injected (rather than called directly) so this crate's lineage walk stays
/// free of host-key loading, tenant resolution, and audit-file layout — those
/// live in the layer above (the CLI), which owns the host signer. An
/// implementation MUST verify the audit chain's signatures before trusting any
/// label it returns, so the value it yields is one no party but the host could
/// have produced.
pub trait CheckpointChainAnchor {
    /// The content-address recorded for `meta`'s creation in the tenant's
    /// signature-verified audit chain (`checkpoint.created`'s `meta_digest`, or
    /// `checkpoint.forked`'s `child_digest`), or `None` if the chain carries no
    /// creation entry for it.
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>>;
}

/// A checkpoint record participates in the shared, namespace-agnostic lineage
/// walk ([`crate::lineage`]) as a content-addressed record: its stored digest is
/// `meta_digest`, it recomputes via [`CheckpointMeta::compute_meta_digest`], and
/// its parent hash-link is `parent`.
impl LineageRecord for CheckpointMeta {
    fn stored_digest(&self) -> &CheckpointDigest {
        &self.meta_digest
    }
    fn recompute_digest(&self) -> CheckpointDigest {
        self.compute_meta_digest()
    }
    fn parent_link(&self) -> Option<&CheckpointDigest> {
        self.parent.as_ref()
    }
    fn kind(&self) -> &'static str {
        "checkpoint"
    }
    fn id_label(&self) -> String {
        self.id.to_string()
    }
    fn digest_field(&self) -> &'static str {
        "meta_digest"
    }
}

/// Bridge the checkpoint-specific anchor trait onto the generic one, so the
/// shared walk accepts a `&dyn CheckpointChainAnchor` unchanged.
impl LineageAnchor<CheckpointMeta> for dyn CheckpointChainAnchor + '_ {
    fn recorded_creation_digest(&self, meta: &CheckpointMeta) -> Result<Option<CheckpointDigest>> {
        CheckpointChainAnchor::recorded_creation_digest(self, meta)
    }
}

/// Adapts a [`CheckpointStore`] to the generic [`LineageGraph`] the shared walk
/// reads records from.
struct CheckpointGraph<'a>(&'a CheckpointStore);

impl LineageGraph for CheckpointGraph<'_> {
    type Record = CheckpointMeta;
    type Id = CheckpointId;
    fn read(&self, id: &CheckpointId) -> Result<CheckpointMeta> {
        self.0.read_meta(id)
    }
    fn by_digest(&self, digest: &CheckpointDigest) -> Result<Option<CheckpointMeta>> {
        self.0.by_digest(digest)
    }
    fn children_of(&self, parent_digest: &CheckpointDigest) -> Result<Vec<CheckpointMeta>> {
        self.0.children_of(parent_digest)
    }
}

/// Verify one checkpoint record against the signed audit chain: its stored
/// `meta_digest` must equal a recomputation of its own fields (catches a
/// post-seal edit that left the digest stale) AND must equal the
/// signature-verified digest the audit chain recorded at creation (catches a
/// full local re-forge, where an attacker rewrites content, digest, and links
/// all consistently — that survives recompute alone but not the signed chain,
/// which it cannot re-sign without the host key). Fails closed on a drift, a
/// mismatch against the chain, or the absence of any signed creation entry.
fn verify_checkpoint_against_chain(
    anchor: &dyn CheckpointChainAnchor,
    meta: &CheckpointMeta,
) -> Result<()> {
    crate::lineage::verify_record_against_chain(anchor, meta)
}

/// Walk a checkpoint's lineage from `id` up to its genesis root, verifying each
/// record against the **signed** audit chain via `anchor`: at every hop the
/// record's recomputed content-address must equal both its stored `meta_digest`
/// and the digest the host signed into the audit chain at creation. The
/// parent hash-link is followed by content-address, so editing any ancestor's
/// sealed record — content manifest, lineage, anything the digest covers — is
/// caught here even though it is invisible to a plain parent-name back-pointer.
///
/// Fails closed on: a drift between a record and its stored digest, a record
/// whose digest disagrees with the signed chain (or has no signed entry), a
/// parent hash-link that resolves to no stored checkpoint (dangling lineage),
/// or a revisited digest (a would-be cycle — cryptographically infeasible for
/// genuine content-addresses, refused rather than looped on).
///
/// Threat boundary: this proves integrity against edits made *after* the host
/// signed each record. A malicious host that holds the signing key is out of
/// scope (it is out of scope for the whole audit chain), as is a checkpoint
/// that was never audited — for which there is nothing signed to anchor to.
pub fn verify_lineage(
    store: &CheckpointStore,
    id: &CheckpointId,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<()> {
    crate::lineage::verify_lineage_chain(&CheckpointGraph(store), id, anchor)
}

/// Enumerate a checkpoint's ancestry (itself + every ancestor up to genesis),
/// verifying each hop against the signed audit chain. Read-only navigation: it
/// records each node's [`crate::lineage::HopStatus`] and keeps walking rather
/// than bailing, so a caller can render the whole chain with a failed hop marked;
/// it still fails closed on a dangling parent or a cycle via
/// [`crate::lineage::Ancestry::broken`]. The backward analog of the forward
/// [`checkpoint_children`].
pub fn checkpoint_ancestry(
    store: &CheckpointStore,
    id: &CheckpointId,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<crate::lineage::Ancestry<CheckpointMeta>> {
    crate::lineage::collect_ancestry(&CheckpointGraph(store), id, anchor)
}

/// Enumerate a checkpoint's immediate children (forward is a tree — a checkpoint
/// may be forked many times), each verified against the signed audit chain.
pub fn checkpoint_children(
    store: &CheckpointStore,
    parent_digest: &CheckpointDigest,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<Vec<crate::lineage::VerifiedNode<CheckpointMeta>>> {
    crate::lineage::verified_children(&CheckpointGraph(store), parent_digest, anchor)
}

/// A fork restores captured memory into a new runtime identity. Refuse a live
/// parent because its captured device state can still refer to active host
/// resources, and because the child must never become a second owner of those
/// resources while the parent is running.
const FORK_ALLOW_PARENT_RUNNING: bool = false;

/// The child a restore is about to bring up: its fresh identity, its state dir
/// (checkpoint blobs already cloned there), and the CPU share its admitted plan
/// was granted.
///
/// `cpu_grant` rides along rather than being looked up by the restorer because
/// the value that reaches the spawn must be the one that passed
/// [`ensure_child_grants_within_parent`] — a restorer re-reading the plan could
/// bind a number the subset check never saw.
pub struct RestoredChild<'a> {
    /// Fresh, registry-unique name the restored guest runs under.
    pub vm_name: &'a str,
    /// The child's state dir, holding its own copies of every checkpoint blob.
    pub state_dir: &'a Path,
    /// The CPU share the child's admitted plan grants, or `None` for a plan
    /// that grants none — which means unbounded, not zero.
    pub cpu_grant: Option<mvm_contract::grants::CpuGrant>,
}

/// Stages a forked child's snapshot into position and starts the VM. Taken as a
/// callback so [`fork_vm_full`] is testable without a live
/// hypervisor, and so the VMM-specific restorers can live in `mvm-backends`
/// without this crate naming them: `FcForkRestorer` loads Firecracker's
/// snapshot triple, `HvfForkRestorer` maps private RAM and restores the frame.
pub type ForkRestore<'a> = dyn Fn(&RestoredChild<'_>) -> Result<()> + 'a;

/// Branch a new sandbox lineage from a checkpoint: verify the source content's
/// integrity AND its content-address against the signed audit chain, CoW-clone
/// it into `dest_dir`, and record a child checkpoint whose `parent` hash-links
/// to the source. Boot of the child is the caller's job.
///
/// The parent is verified against the signed chain (`anchor`) before any bytes
/// are cloned, so a fork never builds on a checkpoint whose sealed record was
/// edited after it was audited — fail-closed.
///
/// fs_quick only — a vm_full checkpoint carries saved memory and must be forked
/// through [`fork_vm_full`], which restores the memory state into the new
/// identity.
pub fn fork_checkpoint(
    store: &CheckpointStore,
    params: ForkParams,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<CheckpointMeta> {
    let parent = store.read_meta(&params.checkpoint)?;
    if parent.class != CheckpointClass::FsQuick {
        anyhow::bail!(
            "cannot fork checkpoint '{}' (class vm_full) via fork_checkpoint; use fork_vm_full",
            parent.id
        );
    }

    verify_content(store, &parent)?;
    // The parent's sealed record must still match the digest the host signed at
    // creation — refuse to branch from a checkpoint edited after it was audited.
    verify_checkpoint_against_chain(anchor, &parent)?;

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
    .parent(Some(parent.meta_digest.clone()))
    .created_unix(params.created_unix)
    .content(parent.content.clone())
    .supervisor_config_digest(parent.supervisor_config_digest)
    .runtime_source_policy(parent.runtime_source_policy)
    .runtime_overlay_version(parent.runtime_overlay_version)
    // An fs_quick branch presents no plan of its own, so the child inherits
    // rather than restates the parent's permission set — inheritance is the
    // only shape that cannot widen.
    .grants(parent.grants.clone())
    // A fork starts a new lineage, not a continuation of the parent's durable
    // agent session: carrying the binding forward would claim the child is
    // the same session at the same generation and journal cursor as a parent
    // that may still be running, which is two live sandboxes asserting one
    // identity. The child is unbound until something binds it fresh.
    .session(None)
    .build();
    store.write_meta(&child)?;
    Ok(child)
}

/// Branch a new VM identity from a vm_full checkpoint and boot it from the
/// saved machine state.
///
/// Backend-neutral: the clone, the verity-binding check and the lineage record
/// are the same for every VMM, and `restorer` owns the VMM-specific load
/// (Firecracker's `PUT /snapshot/load`, HVF's private RAM mapping plus frame
/// restore). The child's blobs are cloned into `dest_dir` and it boots from its
/// OWN copies, never the parent's.
pub fn fork_vm_full(
    store: &CheckpointStore,
    params: ForkParams,
    restore: &ForkRestore<'_>,
    anchor: &dyn CheckpointChainAnchor,
) -> Result<CheckpointMeta> {
    let parent = store.read_meta(&params.checkpoint)?;
    if parent.class != CheckpointClass::VmFull {
        anyhow::bail!(
            "cannot fork_vm_full checkpoint '{}' (class fs_quick); use fork_checkpoint",
            parent.id
        );
    }
    if params.child_id == parent.id {
        anyhow::bail!(
            "cannot fork checkpoint '{}': child checkpoint id must differ from the parent",
            parent.id
        );
    }
    if params.child_vm_name == parent.vm_name {
        anyhow::bail!(
            "cannot fork checkpoint '{}': child VM name must differ from the parent '{}'",
            parent.id,
            parent.vm_name
        );
    }
    verify_content(store, &parent)?;
    // Same fail-closed posture as fork_checkpoint: the parent's sealed record
    // must still match the digest the host signed at creation before we clone.
    verify_checkpoint_against_chain(anchor, &parent)?;

    if !FORK_ALLOW_PARENT_RUNNING && vm_is_running(&parent.vm_name) {
        anyhow::bail!(
            "cannot fork checkpoint '{}': parent VM '{}' is still running; stop it first",
            parent.id,
            parent.vm_name
        );
    }

    let child_grants = validate_child_fork_plan(&params, parent.grants.as_ref())?;

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

    validate_fork_verity_binding(&parent, &params.dest_dir)?;

    // The bound rides on the spawn, so the grant that just cleared the subset
    // check is what the restorer starts the child's VMM under. Without this the
    // check would decide only what may be *recorded* for the child, and a child
    // admitted to 1.5 cores would restore with no quota at all.
    restore(&RestoredChild {
        vm_name: &params.child_vm_name,
        state_dir: &params.dest_dir,
        cpu_grant: child_grants.as_ref().and_then(|grants| grants.cpu),
    })?;

    let child = CheckpointMeta::builder(
        params.child_id,
        CheckpointClass::VmFull,
        params.child_vm_name,
    )
    .parent(Some(parent.meta_digest.clone()))
    .created_unix(params.created_unix)
    .content(parent.content.clone())
    .supervisor_config_digest(parent.supervisor_config_digest)
    .runtime_source_policy(parent.runtime_source_policy)
    .runtime_overlay_version(parent.runtime_overlay_version)
    // The child's OWN grants, already checked to sit inside the parent's. A
    // grandchild is then bounded by what this restore actually got, not by the
    // wider set its grandparent held.
    .grants(child_grants)
    // Same reasoning as fork_checkpoint: forking a vm_full checkpoint starts a
    // new sandbox lineage, so the child does not inherit the parent's durable
    // agent session binding. It boots as its own identity with its own
    // generation, and something else must bind it to a session before that
    // binding is meaningful.
    .session(None)
    .build();
    store.write_meta(&child)?;
    Ok(child)
}

/// Ensure a cloned checkpoint keeps the complete dm-verity binding and the
/// device-path metadata needed to remap snapshot references to child files.
fn validate_fork_verity_binding(parent: &CheckpointMeta, child_dir: &Path) -> Result<()> {
    let has_verity = parent
        .content
        .iter()
        .any(|blob| blob.name == "rootfs.verity");
    let has_roothash = parent
        .content
        .iter()
        .any(|blob| blob.name == "rootfs.roothash");
    anyhow::ensure!(
        has_verity == has_roothash,
        "checkpoint '{}' has an incomplete dm-verity sidecar set",
        parent.id
    );

    let anchors_path = child_dir.join("device-anchors.json");
    anyhow::ensure!(
        anchors_path.is_file(),
        "checkpoint '{}' is missing device-anchors.json",
        parent.id
    );
    let anchors: DeviceAnchors = serde_json::from_slice(
        &std::fs::read(&anchors_path)
            .with_context(|| format!("reading {}", anchors_path.display()))?,
    )
    .with_context(|| format!("parsing {}", anchors_path.display()))?;

    if has_verity {
        anyhow::ensure!(
            anchors.rootfs_verity.is_some()
                && child_dir.join("rootfs.verity").is_file()
                && child_dir.join("rootfs.roothash").is_file(),
            "checkpoint '{}' would drop its dm-verity binding during fork",
            parent.id
        );
    } else {
        anyhow::ensure!(
            anchors.rootfs_verity.is_none(),
            "checkpoint '{}' has a verity device anchor without sidecars",
            parent.id
        );
    }
    Ok(())
}

/// Validate the child admission envelope before a vm_full restore starts a VMM,
/// returning the permission set the child is admitted to run under.
///
/// The trusted-key signature check happens in the admission supervisor; this
/// boundary still refuses missing, malformed, tenant-mismatched, stale, and
/// incorrectly content-addressed envelopes before any child bytes are cloned.
///
/// It also refuses a child asking for more than `parent_grants`. Every other
/// check here passes for a child that simply wants a bigger permission set: the
/// child plan is separately signed and internally consistent, so without this
/// comparison restore is a laundering path — admit tight, snapshot, restore
/// loose. `parent_grants` comes off the parent's sealed checkpoint record,
/// which is verified against the signed chain before this runs.
fn validate_child_fork_plan(
    params: &ForkParams,
    parent_grants: Option<&mvm_contract::grants::Grants>,
) -> Result<Option<mvm_contract::grants::Grants>> {
    let plan_json = params
        .child_plan_json
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("vm_full fork requires an admitted child plan"))?;
    let tenant_id = params
        .child_tenant_id
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("vm_full fork requires an admitted child tenant"))?;
    let signed: mvm_core::plan::SignedExecutionPlan = serde_json::from_str(plan_json)
        .context("decoding the admitted child SignedExecutionPlan")?;
    anyhow::ensure!(
        signed.0.signature.len() == 64,
        "admitted child plan signature must be 64 bytes"
    );
    anyhow::ensure!(
        !signed.0.signer_id.trim().is_empty(),
        "admitted child plan signer id must not be empty"
    );
    let plan: mvm_core::plan::ExecutionPlan = serde_json::from_slice(&signed.0.payload)
        .context("decoding the admitted child ExecutionPlan payload")?;
    mvm_core::plan::verify_plan_id(&plan).context("validating the admitted child plan id")?;
    anyhow::ensure!(
        plan.tenant.0 == tenant_id,
        "admitted child plan tenant '{}' does not match '{}',",
        plan.tenant.0,
        tenant_id
    );
    let now = chrono::Utc::now();
    anyhow::ensure!(
        plan.valid_from <= now && now < plan.valid_until,
        "admitted child plan is outside its validity window"
    );
    ensure_child_grants_within_parent(plan.grants.as_ref(), parent_grants)?;
    Ok(plan.grants)
}

/// Refuse a child whose grants exceed the permission set its parent checkpoint
/// was sealed under.
///
/// The one decision point for "may this child run under these grants, given the
/// parent it came from". Both restore paths call it — the vm_full fork and the
/// warm-pool claim — because two implementations of a rule like this drift, and
/// a path without one is exactly the hole this exists to close.
///
/// Either side being `None` means `Grants::default()`, never "unchecked". That
/// leaves CPU and wall clock open (absent means unbounded) while holding egress
/// closed (absent means deny-all); skipping the call instead would silently open
/// egress on the very paths that most need it shut.
pub fn ensure_child_grants_within_parent(
    child: Option<&mvm_contract::grants::Grants>,
    parent: Option<&mvm_contract::grants::Grants>,
) -> Result<()> {
    let unbounded_cpu_deny_all_egress = mvm_contract::grants::Grants::default();
    mvm_contract::grants::subset::grants_are_subset(
        child.unwrap_or(&unbounded_cpu_deny_all_egress),
        parent.unwrap_or(&unbounded_cpu_deny_all_egress),
    )
    .map_err(|widening| {
        anyhow::anyhow!(
            "admitted child plan exceeds the permission set its parent checkpoint was \
             captured under: {widening}"
        )
    })
}

/// Liveness probe for a VM by name: any backend pid marker whose process still
/// exists. Missing or malformed markers are treated as stopped.
///
/// Delegates to the shared marker list so a backend cannot be live here and
/// stopped elsewhere. This gates the refuse-to-fork-a-live-parent rule, so a
/// marker this probe does not know reads as stopped and lets a fork through —
/// `vm_is_running_covers_every_catalog_pid_marker` holds the shared list to
/// every backend the catalog registers. Delegating also picks up the
/// `EPERM`-means-alive rule, which matters for a root-owned Firecracker: a bare
/// `kill(pid, 0) == 0` reads that as stopped.
pub fn vm_is_running(vm_name: &str) -> bool {
    mvm_vmm::host::process_liveness::state_dir_has_live_process(&mvm_core::config::vm_state_dir(
        vm_name,
    ))
}

pub use mvm_core::checkpoint::DeviceAnchors;
pub use mvm_vmm::checkpoint::VmFullControl;

/// Capture a running VM's consistent {rootfs, memory, machine-id} triple in one
/// pause window. The disk clone happens while paused so memory and disk match.
pub fn capture_vm_full(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
) -> Result<CheckpointMeta> {
    capture_vm_full_inner(store, params, control, None, None)
}

/// Capture a vm_full checkpoint and stage its immutable bytes in the supplied
/// snapshot store before writing metadata. The resulting snapshot ID is part
/// of the checkpoint's load-bearing digest, so later claims can materialize it
/// without rereading the captured memory image.
pub fn capture_vm_full_with_snapshot_store(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
    snapshot_store: &FsSnapshotStore,
) -> Result<CheckpointMeta> {
    capture_vm_full_inner(store, params, control, Some(snapshot_store), None)
}

/// Capture a vm_full checkpoint and publish its bytes through an immutable
/// trusted-snapshot backend. The backend owns the publication proof, allowing
/// a later claim to materialize without hashing the captured blobs again.
pub fn capture_vm_full_with_trusted_snapshot_backend(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
    backend: &dyn TrustedSnapshotBackend,
) -> Result<CheckpointMeta> {
    capture_vm_full_inner(store, params, control, None, Some(backend))
}

fn capture_vm_full_inner(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
    snapshot_store: Option<&FsSnapshotStore>,
    trusted_backend: Option<&dyn TrustedSnapshotBackend>,
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
        // Collect the machine-id sidecar when the backend wrote one.
        // Backends that do not have a machine-id concept (e.g. Firecracker) skip
        // this step — the blob is absent from the manifest and restore does not
        // require it.
        let sidecar = PathBuf::from(format!("{}.machine-id", memory.display()));
        if sidecar.exists() {
            std::fs::rename(&sidecar, &machine_id)
                .or_else(|_| std::fs::copy(&sidecar, &machine_id).map(|_| ()))
                .with_context(|| format!("collecting machine-id sidecar {}", sidecar.display()))?;
        }
        Ok::<(), anyhow::Error>(())
    })();
    let resumed =
        if params.retain_paused && control.retain_paused_after_capture() && captured.is_ok() {
            Ok(())
        } else {
            control.resume()
        };
    captured?;
    resumed.context("resuming VM after vm_full capture")?;

    let mut content = vec![
        ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: sha256_file_hex(&rootfs_dst)?,
        },
        ContentBlob {
            name: "memory.bin".into(),
            sha256: sha256_file_hex(&memory)?,
        },
    ];

    // Include the machine-id blob when the backend wrote one.
    if machine_id.exists() {
        content.push(ContentBlob {
            name: "machine-id".into(),
            sha256: sha256_file_hex(&machine_id)?,
        });
    }

    // Include any extra blobs the backend wrote alongside save_memory
    // (e.g. Firecracker's vmstate.bin).
    for blob in control.extra_content(&content_dir)? {
        content.push(blob);
    }

    // Persist the launch config into the checkpoint when the backend provides one.
    // Restore needs it to rebuild the state dir the stop reaped. Backends that do
    // not persist a supervisor config omit this blob.
    if let Some(ref src) = params.supervisor_config_src {
        let config_dst = content_dir.join(SUPERVISOR_CONFIG_FILE_NAME);
        std::fs::copy(src, &config_dst).with_context(|| {
            format!(
                "copying supervisor config {} into checkpoint",
                src.display()
            )
        })?;
        content.push(ContentBlob {
            name: SUPERVISOR_CONFIG_FILE_NAME.into(),
            sha256: sha256_file_hex(&config_dst)?,
        });
    }

    // Mirror the fs_quick path: copy guest sidecars (mvm-meta.json,
    // rootfs.verity, rootfs.roothash, rootfs.initrd) so that forks of this
    // vm_full checkpoint can read them from their content dir and boot through
    // the runtime-meta gate plus verity reconstruction.
    // The sidecar read is from the static source dir — outside the pause window
    // is fine.
    let live_rootfs_for_sidecar = control.rootfs_path()?;
    for sidecar_blob in copy_guest_sidecars_if_present(&live_rootfs_for_sidecar, &content_dir)? {
        content.push(sidecar_blob);
    }

    // Capture the absolute host paths the snapshot embeds, so a forked child
    // can remap them to its own copies without editing Firecracker bitcode.
    let anchors = control.device_anchors()?;
    let anchors_path = content_dir.join("device-anchors.json");
    std::fs::write(
        &anchors_path,
        serde_json::to_string_pretty(&anchors).context("serializing device anchors")?,
    )
    .with_context(|| format!("writing {}", anchors_path.display()))?;
    content.push(ContentBlob {
        name: "device-anchors.json".into(),
        sha256: sha256_file_hex(&anchors_path)?,
    });

    // Copy the anchor files the snapshot references (verity sidecar, config,
    // secrets) into the checkpoint so the child can materialize its own copies.
    // The rootfs itself is already cloned above; the vsock UDS is recreated at
    // restore time and must not be copied while the parent is bound to it.
    for src in [
        anchors.rootfs_verity.as_deref(),
        anchors.config.as_deref(),
        anchors.secrets.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let name = src
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("anchor path has no file name: {}", src.display()))?
            .to_string_lossy();
        // A verity anchor is also a guest sidecar when it sits beside the
        // captured rootfs. Keep one manifest entry for the shared bytes; the
        // checkpoint content directory is already the canonical copy.
        if content.iter().any(|blob| blob.name == name) {
            continue;
        }
        let dst = content_dir.join(name.as_ref());
        std::fs::copy(src, &dst)
            .with_context(|| format!("copying anchor {} to checkpoint", src.display()))?;
        content.push(ContentBlob {
            name: name.into_owned(),
            sha256: sha256_file_hex(&dst)?,
        });
    }

    let snapshot_id = if let Some(backend) = trusted_backend {
        if snapshot_store.is_some() {
            anyhow::bail!("capture configured with both snapshot backends");
        }
        let id = format!(
            "trusted-checkpoint-{}-content-{}",
            params.id,
            mvm_core::checkpoint::content_manifest_digest(&content)
        );
        let manifest_digest = mvm_core::checkpoint::content_manifest_digest(&content).to_string();
        let snapshot_id = SnapshotId::with_digest(id.clone(), manifest_digest.clone());
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()
            .context("load host identity for checkpoint snapshot manifest")?;
        mvm_core::crypto::snapshot_sign::sign_manifest(
            &content_dir,
            &manifest_digest,
            &identity.signing,
        )
        .with_context(|| format!("sign trusted checkpoint snapshot manifest {id}"))?;
        backend
            .stage(&snapshot_id, &content_dir)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("staging trusted checkpoint snapshot {id}"))?;
        if let Err(error) = backend
            .seal(&snapshot_id)
            .map_err(anyhow::Error::from)
            .with_context(|| format!("sealing trusted checkpoint snapshot {id}"))
        {
            let _ = backend.remove(&snapshot_id);
            return Err(error);
        }
        Some(id)
    } else {
        snapshot_store
            .map(|snapshots| {
                let id = format!(
                    "checkpoint-{}-content-{}",
                    params.id,
                    mvm_core::checkpoint::content_manifest_digest(&content)
                );
                let manifest_digest =
                    mvm_core::checkpoint::content_manifest_digest(&content).to_string();
                let snapshot_id = SnapshotId::with_digest(id.clone(), manifest_digest.clone());
                snapshots
                    .create(&snapshot_id, &content_dir)
                    .with_context(|| format!("staging checkpoint snapshot {id}"))?;
                let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()
                    .context("load host identity for checkpoint snapshot manifest")?;
                mvm_core::crypto::snapshot_sign::sign_manifest(
                    &snapshots.root().join(&id),
                    &manifest_digest,
                    &identity.signing,
                )
                .with_context(|| format!("sign checkpoint snapshot manifest {id}"))?;
                Ok::<_, anyhow::Error>(Some(id))
            })
            .transpose()?
            .flatten()
    };

    let meta = CheckpointMeta::builder(params.id, CheckpointClass::VmFull, params.vm_name)
        .tag(params.tag)
        .created_unix(params.created_unix)
        .content(content)
        .supervisor_config_digest(params.supervisor_config_digest)
        .runtime_source_policy(params.runtime_source_policy)
        .runtime_overlay_version(params.runtime_overlay_version)
        .snapshot_id(snapshot_id)
        .grants(params.grants)
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

/// The same-identity restore mechanism for the VMM that produced `meta`.
///
/// Dispatch is on the machine-state blob the content manifest names, never on a
/// stored backend label: the bytes a restore would load are what decides which
/// VMM can load them, and a label can drift from them.
pub fn vm_full_restorer_for(meta: &CheckpointMeta) -> Result<Box<dyn VmFullRestore>> {
    match mvm_core::checkpoint::vm_full_origin(meta) {
        Some(mvm_core::checkpoint::VmFullOrigin::Hvf) => {
            Ok(Box::new(crate::hvf_restore::HvfVmFullRestore))
        }
        Some(mvm_core::checkpoint::VmFullOrigin::Firecracker) => anyhow::bail!(
            "checkpoint '{}' was captured on Firecracker, which loads a saved machine state \
             only into a fresh child identity; use `mvmctl machine warm-restore {}`",
            meta.id,
            meta.id
        ),
        Some(mvm_core::checkpoint::VmFullOrigin::Retired) => anyhow::bail!(
            "checkpoint '{}' was captured under a backend that has been removed; nothing on \
             this host can load its saved machine state",
            meta.id
        ),
        None => anyhow::bail!(
            "checkpoint '{}' names no saved machine state; there is nothing to restore",
            meta.id
        ),
    }
}

pub struct RestoreParams {
    pub checkpoint: CheckpointId,
    /// Name of the VM to restore into (must match the supervisor-config shape).
    pub target_vm: String,
}

/// Resume a VM from a vm_full checkpoint (same identity). Verifies the manifest
/// AND the record's content-address against the signed audit chain, then hands
/// the blob paths to the restore seam. Refusing fs_quick here is deliberate:
/// fs_quick has no memory state, so `fork_checkpoint` is the right verb.
///
/// The chain check is the same fail-closed gate `fork_checkpoint` and
/// [`fork_vm_full`] run, for the same reason: bringing a machine back to life is
/// at least as consequential as branching from it, so a record edited after it
/// was audited must not be restorable either.
pub fn restore_checkpoint(
    store: &CheckpointStore,
    params: RestoreParams,
    restore: &dyn VmFullRestore,
    anchor: &dyn CheckpointChainAnchor,
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
    verify_checkpoint_against_chain(anchor, &meta)?;
    let dir = store.content_dir(&meta.id);

    // The checkpoint carries the launch config (for checkpoints captured after
    // this landed). Hand it to the restore seam so the backend can rebuild the
    // target state dir the stop reaped. Older checkpoints lack it → `None`, and
    // the backend falls through to its legacy live-state-dir behavior.
    let stored_config = dir.join(SUPERVISOR_CONFIG_FILE_NAME);
    let config_src = stored_config.is_file().then_some(stored_config.as_path());

    restore.restore(
        &params.target_vm,
        &dir.join("rootfs.ext4"),
        &dir.join("memory.bin"),
        &dir.join("machine-id"),
        config_src,
    )
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    mvm_core::crypto::image_verify::sha256_file(path)
        .with_context(|| format!("hashing {}", path.display()))
}

/// Guest sidecar files that may sit next to `rootfs.ext4` and must be
/// carried into a checkpoint so that forks can reconstruct a verity boot.
const GUEST_SIDECAR_FILES: &[&str] = &[
    mvm_build::builder_vm::SIDECAR_FILENAME,
    "rootfs.verity",
    "rootfs.roothash",
    "rootfs.initrd",
];

/// Copy guest sidecars from the directory that contains `src_rootfs` into
/// `content_dir`, returning a `ContentBlob` for each one that exists.
///
/// Unsealed/dev images may have none of these; the function is a no-op for
/// absent files. Call from both `capture_fs_quick` and `capture_vm_full` so
/// that sidecar propagation stays DRY.
fn copy_guest_sidecars_if_present(
    src_rootfs: &Path,
    content_dir: &Path,
) -> Result<Vec<ContentBlob>> {
    let src_dir = src_rootfs
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut blobs = Vec::new();
    for name in GUEST_SIDECAR_FILES {
        let src_sidecar = src_dir.join(name);
        if !src_sidecar.exists() {
            continue;
        }
        let dst_sidecar = content_dir.join(name);
        std::fs::copy(&src_sidecar, &dst_sidecar).with_context(|| {
            format!(
                "copying {name} sidecar into checkpoint content dir {}",
                content_dir.display()
            )
        })?;
        blobs.push(ContentBlob {
            name: (*name).into(),
            sha256: sha256_file_hex(&dst_sidecar)?,
        });
    }
    Ok(blobs)
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
    // Lineage is a hash-link: B is A's child iff B's parent digest is A's
    // content-address, not iff it names A's (mutable) id.
    let lineage = if a.id == b.id {
        LineageRelation::Same
    } else if b.parent.as_ref() == Some(&a.meta_digest) {
        LineageRelation::BChildOfA
    } else if a.parent.as_ref() == Some(&b.meta_digest) {
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

    // When the source rootfs directory carries guest sidecars (mvm-meta.json,
    // rootfs.verity, rootfs.roothash, rootfs.initrd), include them so that any
    // fork materialised from this checkpoint can boot through the runtime-meta
    // gate and reconstruct a verity rootfs.
    for sidecar_blob in copy_guest_sidecars_if_present(&params.rootfs, &content_dir)? {
        content.push(sidecar_blob);
    }

    let meta = CheckpointMeta::builder(params.id, CheckpointClass::FsQuick, params.vm_name)
        .tag(params.tag)
        .created_unix(params.created_unix)
        .content(content)
        .supervisor_config_digest(params.supervisor_config_digest)
        .runtime_source_policy(params.runtime_source_policy)
        .runtime_overlay_version(params.runtime_overlay_version)
        .grants(params.grants)
        .build();
    store.write_meta(&meta)?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use mvm_core::checkpoint::{
        ApprovalHead, CheckpointClass, CheckpointDigest, CheckpointId, CheckpointMeta, ContentBlob,
        SessionBinding,
    };

    fn meta(id: &str, tag: Option<&str>, parent: Option<CheckpointDigest>) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .tag(tag.map(String::from))
            .parent(parent)
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "h".into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build()
    }

    /// Anchor that echoes each record's own recomputed digest: the signed audit
    /// chain agrees with what's on disk — the honest case.
    struct AgreeingAnchor;
    impl CheckpointChainAnchor for AgreeingAnchor {
        fn recorded_creation_digest(
            &self,
            meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(Some(meta.compute_meta_digest()))
        }
    }

    /// Anchor that reports a fixed, unrelated digest for every record: models a
    /// signed chain that disagrees with the on-disk record (post-audit edit).
    struct DisagreeingAnchor(CheckpointDigest);
    impl CheckpointChainAnchor for DisagreeingAnchor {
        fn recorded_creation_digest(
            &self,
            _meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(Some(self.0.clone()))
        }
    }

    /// Anchor with no signed creation entry for anything: models an un-audited
    /// checkpoint, which chain-anchored verification must refuse.
    struct UnauditedAnchor;
    impl CheckpointChainAnchor for UnauditedAnchor {
        fn recorded_creation_digest(
            &self,
            _meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(None)
        }
    }

    fn unrelated_digest() -> CheckpointDigest {
        CheckpointDigest::parse(format!("sha256:{}", "f".repeat(64))).unwrap()
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
        let parent = meta("parent", None, None);
        store.write_meta(&parent).unwrap();
        store
            .write_meta(&meta("child", None, Some(parent.meta_digest.clone())))
            .unwrap();
        let kids = store.children_of(&parent.meta_digest).unwrap();
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
            runtime_source_policy: None,
            runtime_overlay_version: None,
            tag: None,
            created_unix: 7,
            quiesced: false,
            grants: None,
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
                runtime_source_policy: None,
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
            },
        )
        .unwrap()
    }

    fn test_session_binding() -> SessionBinding {
        SessionBinding {
            session_id: mvm_contract::protocol::agent_session::AgentSessionId::parse(
                "sess-fork-test",
            )
            .unwrap(),
            generation: 2,
            journal_cursor: 40,
            approval_head: ApprovalHead::parse(format!("sha256:{}", "ab".repeat(32))).unwrap(),
        }
    }

    /// Rewrites `meta`'s stored record to carry a `SessionBinding`, as if it
    /// were captured from a VM resuming a durable agent session. Used only to
    /// build fork-test fixtures; capture itself does not yet wire a session in.
    fn bind_to_session(store: &CheckpointStore, meta: &CheckpointMeta) -> CheckpointMeta {
        let bound = CheckpointMeta::builder(meta.id.clone(), meta.class, meta.vm_name.clone())
            .tag(meta.tag.clone())
            .parent(meta.parent.clone())
            .created_unix(meta.created_unix)
            .content(meta.content.clone())
            .supervisor_config_digest(meta.supervisor_config_digest.clone())
            .runtime_source_policy(meta.runtime_source_policy)
            .runtime_overlay_version(meta.runtime_overlay_version.clone())
            .grants(meta.grants.clone())
            .session(Some(test_session_binding()))
            .build();
        store.write_meta(&bound).unwrap();
        bound
    }

    #[test]
    fn fork_checkpoint_does_not_inherit_the_parent_session() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p-session");
        let parent = bind_to_session(&store, &parent);
        assert!(parent.session.is_some());

        let dst = tmp.path().join("childvm-state");
        let child = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("f-session"),
                child_vm_name: "childvm-session".into(),
                dest_dir: dst,
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &AgreeingAnchor,
        )
        .unwrap();

        // A fork branches a new lineage; it must not claim to be the parent's
        // session at the parent's generation and journal cursor.
        assert!(
            child.session.is_none(),
            "forked child must not inherit the parent's session binding"
        );
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
            &AgreeingAnchor,
        )
        .unwrap();
        assert_eq!(child.parent.as_ref().unwrap(), &parent.meta_digest);
        assert_eq!(child.vm_name, "childvm");
        assert_eq!(
            std::fs::read(dst.join("rootfs.ext4")).unwrap(),
            b"fake-ext4-bytes"
        );
        // byte-identical clone → manifest hashes are preserved
        assert_eq!(child.content, parent.content);
        assert_eq!(store.children_of(&parent.meta_digest).unwrap().len(), 1);
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
            &AgreeingAnchor,
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
            &AgreeingAnchor,
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
                runtime_source_policy: None,
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
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
    fn capture_includes_verity_sidecars_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = write_fake_rootfs(tmp.path());
        std::fs::write(tmp.path().join("rootfs.verity"), b"verity-tree").unwrap();
        std::fs::write(tmp.path().join("rootfs.roothash"), b"abc123").unwrap();
        std::fs::write(tmp.path().join("rootfs.initrd"), b"initrd-bytes").unwrap();
        let meta = capture_fs_quick(
            &store,
            CaptureFsQuickParams {
                id: CheckpointId::new("c-verity"),
                vm_name: "parentvm".into(),
                rootfs,
                supervisor_config_digest: "d".into(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants: None,
            },
        )
        .unwrap();
        let names: Vec<&str> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"rootfs.ext4"));
        assert!(names.contains(&"rootfs.verity"));
        assert!(names.contains(&"rootfs.roothash"));
        assert!(names.contains(&"rootfs.initrd"));
        let roothash_blob = meta
            .content
            .iter()
            .find(|b| b.name == "rootfs.roothash")
            .unwrap();
        assert!(!roothash_blob.sha256.is_empty());
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
            &AgreeingAnchor,
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
        fn device_anchors(&self) -> Result<DeviceAnchors> {
            let dir = self.rootfs.parent().unwrap_or(Path::new("."));
            Ok(DeviceAnchors {
                rootfs: self.rootfs.clone(),
                rootfs_verity: dir
                    .join("rootfs.verity")
                    .is_file()
                    .then(|| dir.join("rootfs.verity")),
                config: None,
                secrets: None,
                vsock: dir.join("v.sock"),
            })
        }
    }

    /// A control that can hold its VM paused after a capture, as the HVF one
    /// does for the warm pool.
    struct RetainingControl(MockControl);
    impl VmFullControl for RetainingControl {
        fn pause(&self) -> Result<()> {
            self.0.pause()
        }
        fn resume(&self) -> Result<()> {
            self.0.resume()
        }
        fn save_memory(&self, memory_path: &Path) -> Result<()> {
            self.0.save_memory(memory_path)
        }
        fn rootfs_path(&self) -> Result<PathBuf> {
            self.0.rootfs_path()
        }
        fn device_anchors(&self) -> Result<DeviceAnchors> {
            self.0.device_anchors()
        }
        fn retain_paused_after_capture(&self) -> bool {
            true
        }
    }

    fn capture_with_retention(retain_paused: bool) -> Vec<&'static str> {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = tmp.path().join("live-rootfs.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        let ctl = RetainingControl(MockControl {
            rootfs,
            events: RefCell::new(vec![]),
        });
        capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: CheckpointId::new("retain"),
                vm_name: "vm".into(),
                supervisor_config_digest: "d".into(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: None,
                tag: None,
                created_unix: 9,
                retain_paused,
                grants: None,
            },
            &ctl,
        )
        .unwrap();
        let events = ctl.0.events.borrow().clone();
        drop(ctl);
        events
    }

    /// Retention takes both: a backend that can hold the pause AND a caller
    /// that wants it. Only the warm pool wants it — for the pool the paused
    /// parent is the claim resource. A user checkpointing their own running VM
    /// must get it back running, so the CLI asks for no retention and the
    /// capture resumes even on a retention-capable backend.
    #[test]
    fn capture_resumes_unless_the_caller_asks_for_retention() {
        assert!(
            capture_with_retention(false).contains(&"resume"),
            "a caller that did not ask for retention must get its VM resumed"
        );
        assert!(
            !capture_with_retention(true).contains(&"resume"),
            "the warm pool keeps its captured parent paused"
        );
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
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: Some(config),
                tag: None,
                created_unix: 9,
                retain_paused: false,
                grants: None,
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
        std::fs::write(rootfs_dir.join("rootfs.verity"), b"verity").unwrap();
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
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: Some(config),
                tag: None,
                created_unix: 10,
                retain_paused: false,
                grants: None,
            },
            &ctl,
        )
        .unwrap();
        let names: Vec<&str> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(
            names.contains(&mvm_build::builder_vm::SIDECAR_FILENAME),
            "expected sidecar blob in vm_full content; got {names:?}"
        );
        assert_eq!(
            names
                .iter()
                .filter(|name| **name == "rootfs.verity")
                .count(),
            1,
            "a shared verity sidecar/anchor must appear once: {names:?}"
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
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: Some(config),
                tag: None,
                created_unix: 11,
                retain_paused: false,
                grants: None,
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

    struct MockRestore {
        seen: RefCell<Option<(String, PathBuf, PathBuf, PathBuf)>>,
        config_seen: RefCell<Option<PathBuf>>,
    }
    impl VmFullRestore for MockRestore {
        fn restore(
            &self,
            target_vm: &str,
            rootfs_src: &Path,
            memory: &Path,
            machine_id: &Path,
            config_src: Option<&Path>,
        ) -> Result<()> {
            *self.seen.borrow_mut() = Some((
                target_vm.to_string(),
                rootfs_src.to_path_buf(),
                memory.to_path_buf(),
                machine_id.to_path_buf(),
            ));
            *self.config_seen.borrow_mut() = config_src.map(Path::to_path_buf);
            Ok(())
        }
    }

    fn seed_vm_full_checkpoint(store: &CheckpointStore, tmp: &Path, id: &str) -> CheckpointMeta {
        let rootfs = tmp.join("live.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        let config = tmp.join(format!("{id}-supervisor-config.json"));
        std::fs::write(&config, b"{\"cfg\":true}").unwrap();
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
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: Some(config),
                tag: None,
                created_unix: 1,
                retain_paused: false,
                grants: None,
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
            config_seen: RefCell::new(None),
        };
        restore_checkpoint(
            &store,
            RestoreParams {
                checkpoint: ckpt.id.clone(),
                target_vm: "origin".into(),
            },
            &restore,
            &AgreeingAnchor,
        )
        .unwrap();
        let (vm, r, m, mid) = restore.seen.borrow().clone().unwrap();
        let cdir = store.content_dir(&ckpt.id);
        assert_eq!(vm, "origin");
        assert_eq!(r, cdir.join("rootfs.ext4"));
        assert_eq!(m, cdir.join("memory.bin"));
        assert_eq!(mid, cdir.join("machine-id"));
        // The stored launch config is handed to the seam so the backend can
        // rebuild the reaped state dir.
        assert_eq!(
            restore.config_seen.borrow().clone(),
            Some(cdir.join("supervisor-config.json"))
        );
    }

    #[test]
    fn restore_checkpoint_refuses_fs_quick() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let fsq = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let restore = MockRestore {
            seen: RefCell::new(None),
            config_seen: RefCell::new(None),
        };
        let err = restore_checkpoint(
            &store,
            RestoreParams {
                checkpoint: fsq.id,
                target_vm: "origin".into(),
            },
            &restore,
            &AgreeingAnchor,
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
            config_seen: RefCell::new(None),
        };
        let err = restore_checkpoint(
            &store,
            RestoreParams {
                checkpoint: ckpt.id,
                target_vm: "origin".into(),
            },
            &restore,
            &AgreeingAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("integrity") || err.to_string().contains("sha256"),
            "unexpected error: {err}"
        );
        // Restore seam must NOT have been called on a tampered checkpoint.
        assert!(restore.seen.borrow().is_none());
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
            runtime_source_policy: Some(mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay),
            runtime_overlay_version: Some("0.17.0".to_string()),
            tag: Some("gold".into()),
            created_unix: 7,
            quiesced: true,
            grants: None,
        };
        let meta = capture_fs_quick(&store, params).unwrap();
        let content_blob = store.content_dir(&meta.id).join("rootfs.ext4");
        assert_eq!(std::fs::read(&content_blob).unwrap(), b"fake-ext4-bytes");
        assert_eq!(meta.content.len(), 1);
        assert_eq!(meta.content[0].name, "rootfs.ext4");
        assert_eq!(meta.content[0].sha256.len(), 64);
        assert_eq!(meta.tag.as_deref(), Some("gold"));
        assert_eq!(
            meta.runtime_source_policy,
            Some(mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay)
        );
        assert_eq!(meta.runtime_overlay_version.as_deref(), Some("0.17.0"));
        assert_eq!(store.read_meta(&meta.id).unwrap(), meta);
    }

    fn fs_quick_meta(
        id: &str,
        vm: &str,
        parent: Option<CheckpointDigest>,
        rootfs_sha: &str,
    ) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, vm)
            .parent(parent)
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
        let b = fs_quick_meta("child", "vm", Some(a.meta_digest.clone()), "aaaa");
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

    // ── capture_vm_full: no machine-id sidecar + extra_content ────────────────

    /// A backend that does NOT write a machine-id sidecar (e.g. Firecracker)
    /// should produce a vm_full checkpoint WITHOUT a machine-id blob but WITH
    /// any blobs returned by `extra_content`.
    struct NoMachineIdControl {
        rootfs: PathBuf,
        extra: Vec<ContentBlob>,
    }
    impl VmFullControl for NoMachineIdControl {
        fn pause(&self) -> Result<()> {
            Ok(())
        }
        fn resume(&self) -> Result<()> {
            Ok(())
        }
        fn save_memory(&self, memory_path: &Path) -> Result<()> {
            std::fs::write(memory_path, b"mem").unwrap();
            // Intentionally does NOT write a .machine-id sidecar.
            Ok(())
        }
        fn rootfs_path(&self) -> Result<PathBuf> {
            Ok(self.rootfs.clone())
        }
        fn device_anchors(&self) -> Result<DeviceAnchors> {
            let dir = self.rootfs.parent().unwrap_or(Path::new("."));
            Ok(DeviceAnchors {
                rootfs: self.rootfs.clone(),
                rootfs_verity: None,
                config: None,
                secrets: None,
                vsock: dir.join("v.sock"),
            })
        }
        fn extra_content(&self, _content_dir: &Path) -> Result<Vec<ContentBlob>> {
            Ok(self.extra.clone())
        }
    }

    #[test]
    fn capture_vm_full_no_machine_id_blob_when_no_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = tmp.path().join("live.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        let ctl = NoMachineIdControl {
            rootfs,
            extra: vec![],
        };
        let meta = capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: CheckpointId::new("fc1"),
                vm_name: "fc-vm".into(),
                supervisor_config_digest: "d".into(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: None,
                tag: None,
                created_unix: 1,
                retain_paused: false,
                grants: None,
            },
            &ctl,
        )
        .unwrap();
        let names: Vec<&str> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(
            !names.contains(&"machine-id"),
            "no machine-id blob expected when backend writes no sidecar: {names:?}"
        );
        assert!(
            names.contains(&"rootfs.ext4"),
            "rootfs.ext4 must be present: {names:?}"
        );
        assert!(
            names.contains(&"memory.bin"),
            "memory.bin must be present: {names:?}"
        );
        // No supervisor-config.json when src is None.
        assert!(
            !names.contains(&SUPERVISOR_CONFIG_FILE_NAME),
            "no supervisor-config.json expected when src is None: {names:?}"
        );
        verify_content(&store, &meta).unwrap();
    }

    #[test]
    fn capture_vm_full_includes_extra_content_blobs() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let rootfs = tmp.path().join("live.ext4");
        std::fs::write(&rootfs, b"disk").unwrap();
        // Write a fake vmstate.bin that extra_content will return as a blob.
        let vmstate = tmp.path().join("vmstate.bin");
        std::fs::write(&vmstate, b"fake-vmstate").unwrap();
        let sha256 = mvm_core::crypto::image_verify::sha256_file(&vmstate).unwrap();
        let ctl = NoMachineIdControl {
            rootfs,
            extra: vec![ContentBlob {
                name: "vmstate.bin".into(),
                sha256: sha256.clone(),
            }],
        };
        // The extra content blob references a file in the content dir — write
        // the file there so verify_content passes.
        let id = CheckpointId::new("fc2");
        let content_dir = store.content_dir(&id);
        std::fs::create_dir_all(&content_dir).unwrap();
        std::fs::write(content_dir.join("vmstate.bin"), b"fake-vmstate").unwrap();

        let meta = capture_vm_full(
            &store,
            CaptureVmFullParams {
                id: id.clone(),
                vm_name: "fc-vm".into(),
                supervisor_config_digest: "d".into(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: None,
                tag: None,
                created_unix: 2,
                retain_paused: false,
                grants: None,
            },
            &ctl,
        )
        .unwrap();
        let names: Vec<&str> = meta.content.iter().map(|b| b.name.as_str()).collect();
        assert!(
            names.contains(&"vmstate.bin"),
            "vmstate.bin extra blob must be in manifest: {names:?}"
        );
        let vmstate_blob = meta
            .content
            .iter()
            .find(|b| b.name == "vmstate.bin")
            .unwrap();
        assert_eq!(
            vmstate_blob.sha256, sha256,
            "vmstate.bin sha256 must match the extra_content blob"
        );
    }

    // ── vm_full_origin ──────────────────────────────────────────────────────

    use mvm_core::checkpoint::{VmFullOrigin, vm_full_origin};

    /// A supervisor-config checkpoint with no recognizable machine-state blob
    /// was captured by a backend that has since been removed: nothing on this
    /// host can load it, so every consumer must refuse rather than guess.
    #[test]
    fn vm_full_origin_reports_retired_for_a_supervisor_config_only_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_vm_full_checkpoint(&store, tmp.path(), "supcfg-only");
        assert_eq!(vm_full_origin(&meta), Some(VmFullOrigin::Retired));
    }

    #[test]
    fn vm_full_origin_reports_firecracker_for_a_vmstate_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_fc_vm_full_checkpoint(&store, tmp.path(), "fc1");
        assert_eq!(vm_full_origin(&meta), Some(VmFullOrigin::Firecracker));
    }

    /// The HVF frame wins over a supervisor-config blob: an HVF checkpoint
    /// carries both, and the machine-state blob is what decides who can load it.
    #[test]
    fn vm_full_origin_reports_hvf_when_the_frame_blob_is_present() {
        let mut meta =
            CheckpointMeta::builder(CheckpointId::new("hvf1"), CheckpointClass::VmFull, "hvf-vm")
                .content(vec![
                    ContentBlob {
                        name: mvm_core::checkpoint::MEMORY_BLOB.into(),
                        sha256: "a".into(),
                    },
                    ContentBlob {
                        name: mvm_core::checkpoint::SUPERVISOR_CONFIG_BLOB.into(),
                        sha256: "b".into(),
                    },
                    ContentBlob {
                        name: mvm_core::checkpoint::HVF_FRAME_BLOB.into(),
                        sha256: "c".into(),
                    },
                ])
                .build();
        assert_eq!(vm_full_origin(&meta), Some(VmFullOrigin::Hvf));
        // Strip the frame and the same record reads as the retired backend's.
        meta.content
            .retain(|b| b.name != mvm_core::checkpoint::HVF_FRAME_BLOB);
        assert_eq!(vm_full_origin(&meta), Some(VmFullOrigin::Retired));
    }

    /// An fs_quick manifest names no machine state at all.
    #[test]
    fn vm_full_origin_is_none_without_any_machine_state_blob() {
        let meta =
            CheckpointMeta::builder(CheckpointId::new("fsq"), CheckpointClass::FsQuick, "vm")
                .content(vec![ContentBlob {
                    name: mvm_core::checkpoint::ROOTFS_BLOB.into(),
                    sha256: "a".into(),
                }])
                .build();
        assert_eq!(vm_full_origin(&meta), None);
    }

    #[test]
    fn fork_vm_full_rejects_parent_identity_collisions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint(&store, tmp.path(), "fc-identity-parent");

        let same_checkpoint = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: parent.id.clone(),
                child_vm_name: "new-child".into(),
                dest_dir: tmp.path().join("same-checkpoint"),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &|_: &RestoredChild<'_>| Ok(()),
            &AgreeingAnchor,
        )
        .unwrap_err();
        assert!(same_checkpoint.to_string().contains("child checkpoint id"));

        let same_vm = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("new-child-checkpoint"),
                child_vm_name: parent.vm_name.clone(),
                dest_dir: tmp.path().join("same-vm"),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &|_: &RestoredChild<'_>| Ok(()),
            &AgreeingAnchor,
        )
        .unwrap_err();
        assert!(same_vm.to_string().contains("child VM name"));
    }

    /// Every registered backend's marker counts, not a hand-kept subset. The
    /// probe reads one shared marker list, so this test drives it from the
    /// backend catalog instead: a backend that grows a pid file but never
    /// reaches that list goes red here rather than silently reading as stopped.
    /// That matters because this probe gates the refuse-to-fork-a-live-parent
    /// rule — an unrecognised marker lets a fork proceed against a running VM.
    /// A marker no registered backend owns is, conversely, not liveness.
    #[test]
    fn vm_is_running_covers_every_catalog_pid_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", tmp.path());
        let state = mvm_core::config::vm_state_dir("pid-check");
        std::fs::create_dir_all(&state).unwrap();

        let markers: Vec<&str> = crate::catalog::started_vm_probe_descriptors()
            .into_iter()
            .filter_map(|descriptor| descriptor.marker_file)
            .collect();
        assert!(
            markers.contains(&"hvf.pid") && markers.contains(&"fc.pid"),
            "the catalog must expose the HVF and Firecracker markers: {markers:?}"
        );
        for marker in &markers {
            std::fs::write(state.join(marker), std::process::id().to_string()).unwrap();
            assert!(vm_is_running("pid-check"), "{marker} must read as live");
            std::fs::remove_file(state.join(marker)).unwrap();
        }

        std::fs::write(state.join("retired.pid"), std::process::id().to_string()).unwrap();
        assert!(
            !vm_is_running("pid-check"),
            "a marker no registered backend owns is not liveness"
        );
    }

    #[test]
    fn fork_verity_binding_requires_sidecars_and_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let mut parent = seed_fc_vm_full_checkpoint(&store, tmp.path(), "fc-verity");
        parent.content.push(ContentBlob {
            name: "rootfs.verity".into(),
            sha256: "a".repeat(64),
        });
        parent.content.push(ContentBlob {
            name: "rootfs.roothash".into(),
            sha256: "b".repeat(64),
        });

        let child_dir = tmp.path().join("child");
        std::fs::create_dir_all(&child_dir).unwrap();
        let anchors = DeviceAnchors {
            rootfs: child_dir.join("rootfs.ext4"),
            rootfs_verity: Some(child_dir.join("rootfs.verity")),
            config: None,
            secrets: None,
            vsock: child_dir.join("runtime/v.sock"),
        };
        std::fs::write(
            child_dir.join("device-anchors.json"),
            serde_json::to_vec(&anchors).unwrap(),
        )
        .unwrap();

        let err = validate_fork_verity_binding(&parent, &child_dir).unwrap_err();
        assert!(err.to_string().contains("drop its dm-verity binding"));

        std::fs::write(child_dir.join("rootfs.verity"), b"verity").unwrap();
        std::fs::write(child_dir.join("rootfs.roothash"), b"roothash").unwrap();
        validate_fork_verity_binding(&parent, &child_dir).unwrap();
    }

    // ── fork_vm_full_fc ─────────────────────────────────────────────────────

    /// Seeds an FC-shaped vm_full checkpoint: {rootfs.ext4, memory.bin,
    /// vmstate.bin}, no supervisor-config.json, no machine-id.
    fn seed_fc_vm_full_checkpoint(store: &CheckpointStore, tmp: &Path, id: &str) -> CheckpointMeta {
        seed_fc_vm_full_checkpoint_with_grants(store, tmp, id, None)
    }

    fn seed_fc_vm_full_checkpoint_with_grants(
        store: &CheckpointStore,
        tmp: &Path,
        id: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> CheckpointMeta {
        let rootfs = tmp.join(format!("{id}-live.ext4"));
        std::fs::write(&rootfs, b"disk").unwrap();
        let checkpoint_id = CheckpointId::new(id);
        let content_dir = store.content_dir(&checkpoint_id);
        std::fs::create_dir_all(&content_dir).unwrap();
        let vmstate = content_dir.join("vmstate.bin");
        std::fs::write(&vmstate, b"fake-vmstate").unwrap();
        let sha256 = mvm_core::crypto::image_verify::sha256_file(&vmstate).unwrap();
        let ctl = NoMachineIdControl {
            rootfs,
            extra: vec![ContentBlob {
                name: "vmstate.bin".into(),
                sha256,
            }],
        };
        capture_vm_full(
            store,
            CaptureVmFullParams {
                id: checkpoint_id,
                vm_name: "fc-origin".into(),
                supervisor_config_digest: "d".into(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                supervisor_config_src: None,
                tag: None,
                created_unix: 1,
                retain_paused: false,
                grants,
            },
            &ctl,
        )
        .unwrap()
    }

    fn admitted_child_plan() -> (String, String) {
        admitted_child_plan_with_grants(None)
    }

    fn admitted_child_plan_with_grants(
        grants: Option<mvm_contract::grants::Grants>,
    ) -> (String, String) {
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("fc-childvm")
            .grants(grants)
            .build();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[91u8; 32]);
        let signed = mvm_core::plan::sign_plan(&plan, &signer, "test-signer");
        (
            serde_json::to_string(&signed).unwrap(),
            plan.tenant.0.to_string(),
        )
    }

    /// Records what the fork restore callback was handed, so a test can assert
    /// the child's identity and staged dir without a live hypervisor.
    #[derive(Default)]
    struct RecordedRestore {
        seen: RefCell<Option<(String, PathBuf)>>,
        cpu_grant: RefCell<Option<mvm_contract::grants::CpuGrant>>,
    }
    impl RecordedRestore {
        fn restore(&self) -> impl Fn(&RestoredChild<'_>) -> Result<()> + '_ {
            |child: &RestoredChild<'_>| {
                *self.seen.borrow_mut() =
                    Some((child.vm_name.to_string(), child.state_dir.to_path_buf()));
                *self.cpu_grant.borrow_mut() = child.cpu_grant;
                Ok(())
            }
        }
    }

    #[test]
    fn fork_vm_full_does_not_inherit_the_parent_session() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint(&store, tmp.path(), "fcv-session");
        let parent = bind_to_session(&store, &parent);
        assert!(parent.session.is_some());
        let (child_plan_json, child_tenant_id) = admitted_child_plan();

        let dest = tmp.path().join("childvm-state");
        let restorer = RecordedRestore::default();
        let child = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("fcf-session"),
                child_vm_name: "fc-childvm-session".into(),
                dest_dir: dest,
                created_unix: 2,
                child_plan_json: Some(child_plan_json),
                child_tenant_id: Some(child_tenant_id),
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
        .unwrap();

        // Same reasoning as fork_checkpoint: a fork is a new lineage, not a
        // continuation of the parent's session at generation+1, so the child
        // must not carry the parent's binding forward.
        assert!(
            child.session.is_none(),
            "forked child must not inherit the parent's session binding"
        );
    }

    #[test]
    fn fork_vm_full_clones_triple_and_records_lineage() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint(&store, tmp.path(), "fcv1");
        let (child_plan_json, child_tenant_id) = admitted_child_plan();

        let dest = tmp.path().join("childvm-state");
        let restorer = RecordedRestore::default();
        let child = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("fcf1"),
                child_vm_name: "fc-childvm".into(),
                dest_dir: dest.clone(),
                created_unix: 2,
                child_plan_json: Some(child_plan_json),
                child_tenant_id: Some(child_tenant_id),
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
        .unwrap();

        // The FC triple is cloned into the child's state dir; no supervisor
        // config or machine-id ever existed for this checkpoint.
        for name in ["rootfs.ext4", "memory.bin", "vmstate.bin"] {
            assert!(dest.join(name).exists(), "{name} not cloned");
        }
        assert!(!dest.join(SUPERVISOR_CONFIG_FILE_NAME).exists());
        assert!(!dest.join("machine-id").exists());

        assert_eq!(child.class, CheckpointClass::VmFull);
        assert_eq!(child.parent.as_ref().unwrap(), &parent.meta_digest);
        assert_eq!(child.vm_name, "fc-childvm");
        assert_eq!(child.content, parent.content);

        // The restorer was invoked with the child's name and staged dir.
        let (seen_name, seen_dir) = restorer.seen.borrow().clone().unwrap();
        assert_eq!(seen_name, "fc-childvm");
        assert_eq!(seen_dir, dest);
    }

    #[test]
    fn fork_vm_full_refuses_missing_child_admission() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint(&store, tmp.path(), "fcv-missing-plan");
        let restorer = RecordedRestore::default();
        let err = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id,
                child_id: CheckpointId::new("fc-missing-plan-child"),
                child_vm_name: "fc-missing-plan-child".into(),
                dest_dir: tmp.path().join("missing-plan-child-state"),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
        .unwrap_err();
        assert!(err.to_string().contains("requires an admitted child plan"));
        assert!(restorer.seen.borrow().is_none());
    }

    #[test]
    fn child_admission_rejects_malformed_tenant_mismatch_and_expiry() {
        let params = |child_plan_json, child_tenant_id| ForkParams {
            checkpoint: CheckpointId::new("parent"),
            child_id: CheckpointId::new("child"),
            child_vm_name: "child-vm".into(),
            dest_dir: PathBuf::from("/tmp/child-state"),
            created_unix: 2,
            child_plan_json,
            child_tenant_id,
        };

        let err = validate_child_fork_plan(
            &params(Some("not-json".to_string()), Some("local".to_string())),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("decoding the admitted child"));

        let (valid_json, _) = admitted_child_plan();
        let err = validate_child_fork_plan(
            &params(Some(valid_json), Some("wrong-tenant".to_string())),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match"));

        let expired = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("expired-child")
            .validity(
                Utc::now() - Duration::minutes(2),
                Utc::now() - Duration::minutes(1),
            )
            .build();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[92u8; 32]);
        let signed = mvm_core::plan::sign_plan(&expired, &signer, "test-signer");
        let err = validate_child_fork_plan(
            &params(
                Some(serde_json::to_string(&signed).unwrap()),
                Some("local".to_string()),
            ),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside its validity window"));
    }

    // ── restore may not launder a permission set ────────────────────────────

    fn share(millicores: u32) -> Option<mvm_contract::grants::CpuGrant> {
        Some(mvm_contract::grants::CpuGrant::Share { millicores })
    }

    fn destinations(hosts: &[(&str, u16)]) -> Option<mvm_contract::grants::EgressGrant> {
        Some(mvm_contract::grants::EgressGrant {
            allow: hosts
                .iter()
                .map(|(h, p)| mvm_core::network_policy::HostPort::new(*h, *p))
                .collect(),
        })
    }

    /// Fork a child carrying `child_grants` out of a parent captured under
    /// `parent_grants`. The whole restore path runs, so a refusal here is a
    /// refusal before any VMM starts.
    fn fork_child_under(
        tmp: &Path,
        id: &str,
        parent_grants: Option<mvm_contract::grants::Grants>,
        child_grants: Option<mvm_contract::grants::Grants>,
    ) -> Result<CheckpointMeta> {
        let store = CheckpointStore::at(tmp.join(format!("{id}-store")));
        let parent = seed_fc_vm_full_checkpoint_with_grants(&store, tmp, id, parent_grants);
        let (child_plan_json, child_tenant_id) = admitted_child_plan_with_grants(child_grants);
        let restorer = RecordedRestore::default();
        fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id,
                child_id: CheckpointId::new(format!("{id}-child")),
                child_vm_name: "fc-childvm".into(),
                dest_dir: tmp.join(format!("{id}-child-state")),
                created_unix: 2,
                child_plan_json: Some(child_plan_json),
                child_tenant_id: Some(child_tenant_id),
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
    }

    /// The subset check decides what a child may be *admitted* to; this decides
    /// what it actually runs under. Without the hand-off the check would govern
    /// only the lineage record, and a child admitted to 1 core would restore
    /// with no quota at all.
    #[test]
    fn fork_vm_full_hands_the_admitted_child_grant_to_the_restore() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint_with_grants(
            &store,
            tmp.path(),
            "bound",
            Some(mvm_contract::grants::Grants {
                cpu: share(4000),
                ..Default::default()
            }),
        );
        let (child_plan_json, child_tenant_id) =
            admitted_child_plan_with_grants(Some(mvm_contract::grants::Grants {
                cpu: share(1000),
                ..Default::default()
            }));
        let restorer = RecordedRestore::default();
        fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id,
                child_id: CheckpointId::new("bound-child"),
                child_vm_name: "fc-childvm".into(),
                dest_dir: tmp.path().join("bound-child-state"),
                created_unix: 2,
                parent_liveness: ForkParentLiveness::MayBeRunning,
                child_plan_json: Some(child_plan_json),
                child_tenant_id: Some(child_tenant_id),
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
        .expect("a narrowing child forks");

        // The child's own grant, not the parent's wider one: handing down the
        // parent's would bind every child to the widest set in its ancestry.
        assert_eq!(*restorer.cpu_grant.borrow(), share(1000));
    }

    /// A child whose plan grants nothing restores unbounded rather than
    /// inheriting a number nobody signed for it.
    #[test]
    fn fork_vm_full_hands_down_no_grant_when_the_child_plan_carries_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint_with_grants(
            &store,
            tmp.path(),
            "ungranted",
            // The parent grants no CPU bound either: an absent grant is
            // unbounded, so a child dropping a parent's bound would be a
            // widening and is refused a step earlier.
            None,
        );
        let (child_plan_json, child_tenant_id) = admitted_child_plan_with_grants(None);
        let restorer = RecordedRestore::default();
        fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id,
                child_id: CheckpointId::new("ungranted-child"),
                child_vm_name: "fc-childvm".into(),
                dest_dir: tmp.path().join("ungranted-child-state"),
                created_unix: 2,
                child_plan_json: Some(child_plan_json),
                child_tenant_id: Some(child_tenant_id),
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
        .expect("a child asking for nothing forks");

        assert_eq!(*restorer.cpu_grant.borrow(), None);
    }

    #[test]
    fn a_restored_child_may_narrow_every_dimension_of_its_parents_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let child = fork_child_under(
            tmp.path(),
            "narrow",
            Some(mvm_contract::grants::Grants {
                cpu: share(4000),
                wall_clock: Some(mvm_contract::grants::WallClockGrant::Secs {
                    secs: std::num::NonZeroU32::new(600).unwrap(),
                }),
                egress: destinations(&[("api.example.com", 443), ("pypi.org", 443)]),
            }),
            Some(mvm_contract::grants::Grants {
                cpu: share(1000),
                wall_clock: Some(mvm_contract::grants::WallClockGrant::Secs {
                    secs: std::num::NonZeroU32::new(60).unwrap(),
                }),
                egress: destinations(&[("api.example.com", 443)]),
            }),
        )
        .expect("a narrowing child is admitted");
        // The child records its OWN narrower set, so a grandchild is bounded by
        // what this restore actually got rather than by the grandparent's.
        assert_eq!(child.grants.as_ref().and_then(|g| g.cpu), share(1000));
    }

    #[test]
    fn a_restored_child_may_not_widen_its_parents_cpu_share() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_child_under(
            tmp.path(),
            "widen-cpu",
            Some(mvm_contract::grants::Grants {
                cpu: share(1000),
                ..Default::default()
            }),
            Some(mvm_contract::grants::Grants {
                cpu: share(4000),
                ..Default::default()
            }),
        )
        .expect_err("a widening child must be refused");
        assert!(
            err.to_string().contains("exceeds the parent's 1000"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_restored_child_may_not_widen_its_parents_wall_clock() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_child_under(
            tmp.path(),
            "widen-clock",
            Some(mvm_contract::grants::Grants {
                wall_clock: Some(mvm_contract::grants::WallClockGrant::Secs {
                    secs: std::num::NonZeroU32::new(60).unwrap(),
                }),
                ..Default::default()
            }),
            Some(mvm_contract::grants::Grants {
                wall_clock: Some(mvm_contract::grants::WallClockGrant::Unbounded),
                ..Default::default()
            }),
        )
        .expect_err("an unbounded child clock must be refused");
        assert!(
            err.to_string().contains("unbounded wall clock"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_restored_child_may_not_drop_a_cpu_bound_its_parent_carried() {
        // The laundering shape that looks most innocent: the child simply
        // declares nothing. Absent means unbounded, so this is the widest ask.
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_child_under(
            tmp.path(),
            "drop-cpu",
            Some(mvm_contract::grants::Grants {
                cpu: share(1000),
                ..Default::default()
            }),
            None,
        )
        .expect_err("dropping the parent's bound must be refused");
        assert!(
            err.to_string().contains("drops the parent's CPU bound"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_restored_child_may_not_swap_the_unit_of_its_parents_cpu_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_child_under(
            tmp.path(),
            "unit-swap",
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Fuel { instructions: 10 }),
                ..Default::default()
            }),
            Some(mvm_contract::grants::Grants {
                cpu: share(1),
                ..Default::default()
            }),
        )
        .expect_err("mismatched CPU units must be refused");
        assert!(
            err.to_string().contains("different units"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_restored_child_may_not_reach_a_destination_its_parent_could_not() {
        let tmp = tempfile::tempdir().unwrap();
        let err = fork_child_under(
            tmp.path(),
            "widen-egress",
            Some(mvm_contract::grants::Grants {
                egress: destinations(&[("api.example.com", 443)]),
                ..Default::default()
            }),
            Some(mvm_contract::grants::Grants {
                egress: destinations(&[("api.example.com", 443), ("evil.example.com", 443)]),
                ..Default::default()
            }),
        )
        .expect_err("an unadmitted destination must be refused");
        assert!(
            err.to_string().contains("evil.example.com:443"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_tampered_parent_grant_record_cannot_justify_a_wider_child() {
        // Widening the parent's sealed record on disk is the way around a
        // subset check that trusts it. The grant is inside the record's
        // content-address, so the edit is caught before the comparison runs.
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fc_vm_full_checkpoint_with_grants(
            &store,
            tmp.path(),
            "tampered",
            Some(mvm_contract::grants::Grants {
                cpu: share(1000),
                ..Default::default()
            }),
        );

        let meta_path = store.dir_for(&parent.id).join("meta.json");
        let mut raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
        raw["grants"]["cpu"]["millicores"] = serde_json::json!(64_000);
        std::fs::write(&meta_path, serde_json::to_vec(&raw).unwrap()).unwrap();
        // The stored content-address is untouched — only the grant moved.
        let reread = store.read_meta(&parent.id).unwrap();
        assert_eq!(reread.meta_digest, parent.meta_digest);
        assert_eq!(reread.grants.and_then(|g| g.cpu), share(64_000));

        let (child_plan_json, child_tenant_id) =
            admitted_child_plan_with_grants(Some(mvm_contract::grants::Grants {
                cpu: share(64_000),
                ..Default::default()
            }));
        let restorer = RecordedRestore::default();
        let err = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: parent.id,
                child_id: CheckpointId::new("tampered-child"),
                child_vm_name: "fc-childvm".into(),
                dest_dir: tmp.path().join("tampered-child-state"),
                created_unix: 2,
                child_plan_json: Some(child_plan_json),
                child_tenant_id: Some(child_tenant_id),
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
        .expect_err("a post-seal edit of the parent's grant must be refused");
        assert!(
            err.to_string().contains("meta_digest drift"),
            "unexpected error: {err}"
        );
        assert!(restorer.seen.borrow().is_none(), "no VMM may have started");
    }

    #[test]
    fn fork_vm_full_refuses_fs_quick() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let fsq = seed_fs_quick_checkpoint(&store, tmp.path(), "fcp1");
        let restorer = RecordedRestore::default();
        let err = fork_vm_full(
            &store,
            ForkParams {
                checkpoint: fsq.id.clone(),
                child_id: CheckpointId::new("fcf2"),
                child_vm_name: "fc-childvm2".into(),
                dest_dir: tmp.path().join("childvm2-state"),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &restorer.restore(),
            &AgreeingAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("fs_quick"),
            "unexpected error: {err}"
        );
        assert!(restorer.seen.borrow().is_none());
    }

    // ── hash-linked lineage: verify_lineage ─────────────────────────────────

    /// Seed a bare fs_quick meta hash-linked to `parent`, written to the store.
    /// Only metadata is written (no content blobs) — `verify_lineage` reads
    /// meta.json and recomputes digests; it never touches blob bytes.
    fn seed_linked_meta(
        store: &CheckpointStore,
        id: &str,
        parent: Option<CheckpointDigest>,
        rootfs_sha: &str,
    ) -> CheckpointMeta {
        let m = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .parent(parent)
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: rootfs_sha.into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build();
        store.write_meta(&m).unwrap();
        m
    }

    #[test]
    fn capture_writes_a_meta_digest_that_recomputes_equal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let meta = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        assert_eq!(meta.meta_digest, meta.compute_meta_digest());
        // A freshly captured genesis checkpoint is a valid one-node lineage.
        verify_lineage(&store, &meta.id, &AgreeingAnchor).unwrap();
    }

    #[test]
    fn fork_records_parent_meta_digest_as_hashlink() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let child = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("c1"),
                child_vm_name: "childvm".into(),
                dest_dir: tmp.path().join("childvm-state"),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &AgreeingAnchor,
        )
        .unwrap();
        assert_eq!(child.parent.as_ref().unwrap(), &parent.meta_digest);
    }

    #[test]
    fn verify_lineage_passes_for_genesis_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let root = seed_linked_meta(&store, "g0", None, "aa");
        assert!(root.parent.is_none());
        verify_lineage(&store, &root.id, &AgreeingAnchor).unwrap();
    }

    #[test]
    fn verify_lineage_walks_multiple_generations_to_genesis() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let g0 = seed_linked_meta(&store, "g0", None, "aa");
        let g1 = seed_linked_meta(&store, "g1", Some(g0.meta_digest.clone()), "bb");
        let g2 = seed_linked_meta(&store, "g2", Some(g1.meta_digest.clone()), "cc");
        verify_lineage(&store, &g2.id, &AgreeingAnchor).unwrap();
        // Each hop is a hash-link to the parent's content-address.
        assert_eq!(g2.parent.as_ref().unwrap(), &g1.meta_digest);
        assert_eq!(g1.parent.as_ref().unwrap(), &g0.meta_digest);
    }

    /// HEADLINE: editing an ancestor's recorded content sha in its meta.json —
    /// two hops up from the checkpoint under test — is invisible to the old
    /// name-based parent pointer but is caught here: the ancestor's stored
    /// meta_digest no longer matches a recomputation of its (now-edited) fields.
    #[test]
    fn verify_lineage_detects_an_edited_ancestor_content_sha() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let g0 = seed_linked_meta(&store, "g0", None, "aa");
        let g1 = seed_linked_meta(&store, "g1", Some(g0.meta_digest.clone()), "bb");
        let g2 = seed_linked_meta(&store, "g2", Some(g1.meta_digest.clone()), "cc");

        // Baseline: the intact chain verifies.
        verify_lineage(&store, &g2.id, &AgreeingAnchor).unwrap();

        // Tamper the ANCESTOR (g0): rewrite its recorded content sha, leaving
        // its stored meta_digest (and g1's hash-link to it) stale.
        let g0_meta_path = store.dir_for(&g0.id).join("meta.json");
        let mut tampered: CheckpointMeta =
            serde_json::from_slice(&std::fs::read(&g0_meta_path).unwrap()).unwrap();
        tampered.content[0].sha256 = "0".repeat(64);
        std::fs::write(&g0_meta_path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();

        let err = verify_lineage(&store, &g2.id, &AgreeingAnchor).unwrap_err();
        assert!(
            err.to_string().contains("meta_digest drift"),
            "expected a meta_digest drift error, got: {err}"
        );
    }

    #[test]
    fn verify_lineage_fails_closed_on_a_dangling_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        // A child hash-linked to a digest no stored checkpoint carries.
        let orphan_parent = CheckpointDigest::parse(format!("sha256:{}", "e".repeat(64))).unwrap();
        let child = seed_linked_meta(&store, "child", Some(orphan_parent), "cc");
        let err = verify_lineage(&store, &child.id, &AgreeingAnchor).unwrap_err();
        assert!(
            err.to_string().contains("lineage is broken"),
            "expected a dangling-parent error, got: {err}"
        );
    }

    /// A flipped blob byte does not touch meta.json, so `meta_digest` still
    /// recomputes equal — that tamper class is `verify_content`'s job (it
    /// re-hashes the bytes), while `verify_lineage` guards the metadata chain.
    #[test]
    fn content_byte_flip_fails_verify_content_though_meta_digest_recomputes() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let blob = store.content_dir(&parent.id).join("rootfs.ext4");
        std::fs::write(&blob, b"flipped-bytes").unwrap();
        assert!(verify_content(&store, &parent).is_err());
        assert_eq!(parent.meta_digest, parent.compute_meta_digest());
    }

    // ── chain-anchored verification (the signed-chain leg) ───────────────────

    #[test]
    fn verify_lineage_fails_when_chain_recorded_digest_disagrees() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let root = seed_linked_meta(&store, "g0", None, "aa");
        // The on-disk record is internally consistent (recompute == stored), but
        // the signed chain recorded a different content-address at creation — a
        // full local re-forge that only the signed chain can catch.
        let err =
            verify_lineage(&store, &root.id, &DisagreeingAnchor(unrelated_digest())).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the signed audit chain"),
            "expected a chain-mismatch error, got: {err}"
        );
    }

    #[test]
    fn verify_lineage_refuses_a_node_with_no_signed_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let root = seed_linked_meta(&store, "g0", None, "aa");
        let err = verify_lineage(&store, &root.id, &UnauditedAnchor).unwrap_err();
        assert!(
            err.to_string().contains("no signed audit entry"),
            "expected an un-audited-node error, got: {err}"
        );
    }

    #[test]
    fn fork_fails_closed_when_parent_disagrees_with_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let dest = tmp.path().join("childvm-state");
        // Parent bytes and stored digest agree, but the signed chain recorded a
        // different digest at creation → refuse to fork, before cloning a byte.
        let err = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("c1"),
                child_vm_name: "childvm".into(),
                dest_dir: dest.clone(),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &DisagreeingAnchor(unrelated_digest()),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the signed audit chain"),
            "expected a chain-mismatch error, got: {err}"
        );
        assert!(
            !dest.join("rootfs.ext4").exists(),
            "fork must fail closed before cloning a chain-inconsistent parent"
        );
        assert!(
            store.read_meta(&CheckpointId::new("c1")).is_err(),
            "no child checkpoint record must be written"
        );
    }

    #[test]
    fn fork_fails_closed_when_parent_has_no_signed_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("store"));
        let parent = seed_fs_quick_checkpoint(&store, tmp.path(), "p1");
        let dest = tmp.path().join("childvm-state");
        let err = fork_checkpoint(
            &store,
            ForkParams {
                checkpoint: parent.id.clone(),
                child_id: CheckpointId::new("c1"),
                child_vm_name: "childvm".into(),
                dest_dir: dest.clone(),
                created_unix: 2,
                child_plan_json: None,
                child_tenant_id: None,
            },
            &UnauditedAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("no signed audit entry"),
            "expected an un-audited-parent error, got: {err}"
        );
        assert!(!dest.join("rootfs.ext4").exists());
    }

    // SAFETY: serialized by HOME_TEST_LOCK.
    #[allow(unused)]
    fn placeholder_for_trailing_env_remove() {}
}
