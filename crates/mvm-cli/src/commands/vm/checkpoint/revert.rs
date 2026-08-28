//! `mvmctl machine revert|rewind|advance` — time-travel restore verbs.
//!
//! A restore here is **not** an in-place same-identity mutation. It launches a
//! *fresh, re-admitted* VM at a prior state, so the current security posture
//! (signed `ExecutionPlan`, current egress policy, sealed attenuation) is
//! re-derived at launch rather than inherited from the snapshot era:
//!
//! - **Checkpoint targets** reuse the fork path (`super::fork` with `--boot`):
//!   fork re-verifies the source against the signed audit chain, CoW-clones it
//!   into a new identity, and admits a fresh plan through
//!   `admit_plan_for_boot` before booting. A restore therefore never touches
//!   `restore_checkpoint` (which bypasses admission).
//! - **OCI image-node targets** re-run the node's digest-pinned reference
//!   (`<registry>/<repository>@<resolved_digest>`) through the normal admitted
//!   `machine run` path, which re-fetches the exact bytes and re-admits
//!   identically.
//! - **Flake image-node targets pin the stored revision.** Restoring a
//!   flake-built image resolves the recorded slot/revision directory directly,
//!   reconciles every committed artifact hash before boot, and then runs that
//!   exact source through the normal admitted path. It never rebuilds the flake
//!   or follows the slot's mutable `current` symlink.
//!
//! Every restore verifies its target against the signed audit chain up front and
//! fails closed on an un-audited, tampered, or dangling record — the same
//! `verify_lineage` / `verify_image_lineage` gate `machine checkpoint verify`
//! and `fork` use. A completed checkpoint restore emits a chain-signed
//! `checkpoint.restored` entry, and an image restore an `image.reverted` entry;
//! both carry the initiating verb (`revert` / `rewind` / `advance`) as their
//! `via` label.

use std::path::{Component, Path};

use anyhow::{Context, Result, bail};

use mvm_core::checkpoint::CheckpointMeta;
use mvm_core::image_lineage::{ImageBuildIdentity, ImageCanonicalId, ImageNode};
use mvm_runtime::checkpoint::{
    CheckpointStore, checkpoint_ancestry, checkpoint_children, verify_lineage,
};
use mvm_runtime::image_lineage::{
    ImageStore, image_ancestry, image_children, verify_image_lineage,
};
use mvm_runtime::lineage::VerifiedNode;

use super::SignedChainAnchor;
use super::timeline::{LineageKind, ResolvedTarget, resolve_target};
use crate::ui;

/// How a restore was initiated, recorded as the `via` label on the chain-signed
/// `checkpoint.restored` entry so a time-travel restore reads distinctly in the
/// audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevertVia {
    /// Restore to the resolved target itself.
    Revert,
    /// Restore to the target's parent (one step back).
    Rewind,
    /// Restore to a child of the target (one step forward).
    Advance,
}

impl RevertVia {
    fn as_str(self) -> &'static str {
        match self {
            RevertVia::Revert => "revert",
            RevertVia::Rewind => "rewind",
            RevertVia::Advance => "advance",
        }
    }
}

#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct RevertArgs {
    /// Checkpoint id, or a `sha256:<hex>` content-address naming a checkpoint or
    /// an image lineage node to restore.
    pub target: String,
    /// Disambiguate a `sha256:<hex>` digest present in BOTH the checkpoint and
    /// image stores. Not needed for a checkpoint id.
    #[arg(long, value_enum)]
    pub kind: Option<LineageKind>,
    /// Hypervisor backend for the restored checkpoint VM. Defaults to the same
    /// auto-detect order as `machine run`.
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
    /// Name for the restored VM (checkpoint restores only; auto-generated if
    /// omitted). Image restores auto-name through the run path.
    #[arg(long, value_parser = super::super::shared::clap_vm_name)]
    pub new_id: Option<String>,
    /// Emit the restore result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub(in crate::commands) struct AdvanceArgs {
    /// Checkpoint id or `sha256:<hex>` digest whose child to restore.
    pub target: String,
    /// The specific child to advance to, by its `sha256:<hex>` content-address.
    /// Required when the target has more than one child (a fork).
    #[arg(long)]
    pub to: Option<String>,
    /// Disambiguate a `sha256:<hex>` target present in BOTH stores.
    #[arg(long, value_enum)]
    pub kind: Option<LineageKind>,
    /// Hypervisor backend for the restored checkpoint VM.
    #[arg(long, default_value = "firecracker")]
    pub hypervisor: String,
    /// Name for the restored VM (checkpoint restores only).
    #[arg(long, value_parser = super::super::shared::clap_vm_name)]
    pub new_id: Option<String>,
    /// Emit the restore result as JSON.
    #[arg(long)]
    pub json: bool,
}

/// The result of a restore verb, so the `machine` dispatcher can complete the
/// image path (which re-runs through `run_dispatch`) without this module
/// depending on the run surface.
#[derive(Debug)]
pub(in crate::commands) enum RevertOutcome {
    /// A checkpoint restore ran to completion here: fork re-admitted + booted the
    /// restored VM and emitted the chain-signed `checkpoint.restored` entry.
    Done,
    /// An image-node restore: the caller must re-run the reconstructed reference
    /// through the normal admitted `machine run` path.
    RunImage(RevertRunImage),
}

/// The exact source selected for an image-node restore.
#[derive(Debug)]
pub(in crate::commands) enum RevertImageSource {
    /// A digest-pinned OCI reference.
    Oci(String),
    /// A content-addressed stored flake revision.
    Flake {
        slot_hash: String,
        revision_hash: String,
    },
}

impl RevertImageSource {
    fn audit_reference(&self) -> String {
        match self {
            Self::Oci(reference) => reference.clone(),
            Self::Flake {
                slot_hash,
                revision_hash,
            } => format!("flake:{slot_hash}@{revision_hash}"),
        }
    }
}

/// The source and run options for an image-node restore.
#[derive(Debug)]
pub(in crate::commands) struct RevertRunImage {
    pub source: RevertImageSource,
    pub hypervisor: Option<String>,
    pub json: bool,
}

/// Common restore knobs threaded from the verb args into the engine.
struct RestoreOpts<'a> {
    hypervisor: &'a str,
    new_id: Option<&'a str>,
    json: bool,
}

/// `machine revert <target>` — restore the resolved target itself.
pub(in crate::commands) fn run_revert(args: RevertArgs) -> Result<RevertOutcome> {
    let cstore = CheckpointStore::open();
    let istore = ImageStore::open();
    let resolved = resolve_target(&cstore, &istore, &args.target, args.kind)?;
    restore_resolved(
        &cstore,
        &istore,
        resolved,
        RevertVia::Revert,
        RestoreOpts {
            hypervisor: &args.hypervisor,
            new_id: args.new_id.as_deref(),
            json: args.json,
        },
    )
}

/// `machine rewind <target>` — restore the target's parent (one step back).
pub(in crate::commands) fn run_rewind(args: RevertArgs) -> Result<RevertOutcome> {
    let cstore = CheckpointStore::open();
    let istore = ImageStore::open();
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to resolve the rewind target")?;
    let resolved = resolve_target(&cstore, &istore, &args.target, args.kind)?;
    let parent = parent_of(&cstore, &istore, &anchor, resolved)?;
    restore_resolved(
        &cstore,
        &istore,
        parent,
        RevertVia::Rewind,
        RestoreOpts {
            hypervisor: &args.hypervisor,
            new_id: args.new_id.as_deref(),
            json: args.json,
        },
    )
}

/// `machine advance <target> [--to <child>]` — restore a child of the target
/// (one step forward). Forward is a tree, so a fork requires `--to`.
pub(in crate::commands) fn run_advance(args: AdvanceArgs) -> Result<RevertOutcome> {
    let cstore = CheckpointStore::open();
    let istore = ImageStore::open();
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to resolve the advance target")?;
    let resolved = resolve_target(&cstore, &istore, &args.target, args.kind)?;
    let child = child_of(&cstore, &istore, &anchor, resolved, args.to.as_deref())?;
    restore_resolved(
        &cstore,
        &istore,
        child,
        RevertVia::Advance,
        RestoreOpts {
            hypervisor: &args.hypervisor,
            new_id: args.new_id.as_deref(),
            json: args.json,
        },
    )
}

fn restore_resolved(
    cstore: &CheckpointStore,
    istore: &ImageStore,
    resolved: ResolvedTarget,
    via: RevertVia,
    opts: RestoreOpts<'_>,
) -> Result<RevertOutcome> {
    match resolved {
        ResolvedTarget::Checkpoint(meta) => {
            revert_checkpoint(cstore, meta, via, &opts)?;
            Ok(RevertOutcome::Done)
        }
        ResolvedTarget::Image(node) => revert_image(istore, node, via, &opts),
    }
}

/// Restore a checkpoint target by forking a fresh, re-admitted VM from it.
///
/// The full lineage is verified against the signed audit chain first (fail
/// closed on an un-audited, tampered, or dangling record) — a restore must
/// never build on a checkpoint edited after it was audited. The fork path then
/// re-admits (`admit_plan_for_boot`), preserving the current egress policy and
/// re-deriving the sealed attenuation, and boots the restored VM. Finally a
/// chain-signed `checkpoint.restored` entry binds the restore to the launched
/// plan, carrying the initiating verb as its `via` label.
fn revert_checkpoint(
    store: &CheckpointStore,
    target: CheckpointMeta,
    via: RevertVia,
    opts: &RestoreOpts<'_>,
) -> Result<()> {
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the restore target")?;
    verify_lineage(store, &target.id, &anchor).with_context(|| {
        format!(
            "refusing to restore checkpoint {:?}: its lineage does not verify against the \
             signed audit chain",
            target.id.as_str()
        )
    })?;

    let restored_vm_name = opts
        .new_id
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("revert-{}-{}", target.id.as_str(), super::now_unix()));

    // Reuse the fork path verbatim: it re-admits through `admit_plan_for_boot`,
    // re-derives the sealed attenuation, and boots. This is the anti-bypass
    // guarantee — a restore never reaches `restore_checkpoint`.
    super::fork(super::ForkCmdParams {
        id: target.id.as_str(),
        new_id: Some(restored_vm_name.clone()),
        boot: true,
        hypervisor: opts.hypervisor,
        cpus: None,
        memory: None,
        // A revert re-admits the checkpoint it targets; it declares no bindings
        // of its own, matching the pre-existing behaviour of this path.
        declared_secrets: &[],
        // A revert cannot silently attenuate capabilities. Operators restoring
        // a secret-bearing checkpoint use `machine restore`, whose explicit
        // declaration/drop flags describe the fresh child's capability.
        allow_secret_drop: false,
        json: opts.json,
    })
    .with_context(|| format!("restoring checkpoint {:?}", target.id.as_str()))?;

    // Bind the restore to the launched plan (persisted by the fork boot) so the
    // operation is tamper-evident in the chain, distinct from the fork's own
    // `checkpoint.forked` lineage entry.
    emit_revert_audit(&restored_vm_name, &target, via)?;

    if !opts.json {
        ui::success(&format!(
            "{} {} -> restored vm '{}' (re-admitted from checkpoint)",
            via.as_str(),
            target.id.as_str(),
            restored_vm_name
        ));
    }
    Ok(())
}

/// Restore an image-node target: verify it against the signed audit chain,
/// reconstruct its digest-pinned reference, emit a chain-signed `image.reverted`
/// marker, then hand the reference to the caller. The caller re-runs it through
/// the normal admitted `machine run` path, which re-fetches the exact bytes and
/// re-admits identically.
fn revert_image(
    store: &ImageStore,
    node: ImageNode,
    via: RevertVia,
    opts: &RestoreOpts<'_>,
) -> Result<RevertOutcome> {
    // `--new-id` names the restored VM, but an image restore auto-names its VM
    // through the run path — reject rather than silently drop it.
    if let Some(new_id) = opts.new_id {
        bail!(
            "--new-id {new_id:?} applies only to checkpoint restores; an image restore \
             auto-names its VM through the run path"
        );
    }

    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the restore target")?;
    verify_image_lineage(store, &node.node_digest, &anchor).with_context(|| {
        format!(
            "refusing to restore image node {}: its lineage does not verify against the \
             signed audit chain",
            node.node_digest
        )
    })?;

    let source = reconstruct_image_source(&node)?;
    let reference = source.audit_reference();

    // Distinctly audit the restore BEFORE handing off, so the chain records
    // "reverted to node X via Y" — not just an ordinary image run.
    emit_image_revert_audit(&node, via, &reference)?;

    Ok(RevertOutcome::RunImage(RevertRunImage {
        source,
        hypervisor: Some(opts.hypervisor.to_string()),
        json: opts.json,
    }))
}

/// Resolve the exact boot source recorded by an image node.
///
/// OCI nodes become digest-pinned references. Flake nodes resolve the stored
/// slot revision, reconcile every committed artifact hash, and become a
/// pinned template source. Neither branch follows a mutable tag or `current`.
fn reconstruct_image_source(node: &ImageNode) -> Result<RevertImageSource> {
    match &node.build_identity {
        ImageBuildIdentity::Oci {
            registry,
            repository,
        } => {
            let ImageCanonicalId::Oci { resolved_digest } = &node.image_identity.canonical else {
                bail!(
                    "image node {} names an OCI build identity but a non-OCI canonical id; \
                     refusing to reconstruct an ambiguous reference",
                    node.node_digest
                );
            };
            Ok(RevertImageSource::Oci(format!(
                "{registry}/{repository}@{resolved_digest}"
            )))
        }
        ImageBuildIdentity::Flake { slot_hash } => {
            let ImageCanonicalId::Flake { revision_hash } = &node.image_identity.canonical else {
                bail!(
                    "image node {} names a flake build identity but a non-flake canonical id; \
                     refusing to reconstruct an ambiguous source",
                    node.node_digest
                );
            };
            let (_, _, _, rootfs, _) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_for_slot_revision(
                    slot_hash,
                    revision_hash,
                )
                .with_context(|| {
                    format!("resolving stored flake revision {slot_hash}@{revision_hash}")
                })?;
            reconcile_flake_artifacts(
                node,
                Path::new(&rootfs).parent().ok_or_else(|| {
                    anyhow::anyhow!("stored flake rootfs has no revision directory")
                })?,
            )?;
            Ok(RevertImageSource::Flake {
                slot_hash: slot_hash.clone(),
                revision_hash: revision_hash.clone(),
            })
        }
    }
}

/// Reconcile the stored revision's bytes against the image node before the
/// admitted boot path sees them. The node must commit both boot artifacts and
/// may not name paths outside its revision directory.
fn reconcile_flake_artifacts(node: &ImageNode, revision_dir: &Path) -> Result<()> {
    let required = ["vmlinux", "rootfs.ext4"];
    for name in required {
        if !node
            .image_identity
            .artifacts
            .iter()
            .any(|artifact| artifact.name == name)
        {
            bail!(
                "image node {} does not commit required flake artifact {name:?}",
                node.node_digest
            );
        }
    }

    for artifact in &node.image_identity.artifacts {
        let path = revision_dir.join(safe_artifact_name(&artifact.name)?);
        let actual = mvm_core::crypto::image_verify::sha256_file(&path)
            .with_context(|| format!("hashing stored flake artifact {}", path.display()))?;
        if actual != artifact.sha256 {
            bail!(
                "stored flake artifact {:?} failed image-lineage reconciliation: expected {}, got {}",
                artifact.name,
                artifact.sha256,
                actual
            );
        }
    }
    Ok(())
}

fn safe_artifact_name(name: &str) -> Result<&str> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(name),
        _ => bail!("image-lineage artifact name {name:?} is not a plain file name"),
    }
}

/// Workload/intent labels for the host-side `image.reverted` audit-envelope plan.
const IMAGE_REVERT_WORKLOAD: &str = "image-revert";
const IMAGE_REVERT_INTENT: &str = "image:revert";

/// Emit the chain-signed `image.reverted` marker recording the restored node's
/// content-address, the initiating verb, and the reconstructed reference. Bound
/// to a lightweight host-side event plan (never admitted or booted) on the local
/// tenant, keyed to the node's content-address — mirroring how the build path
/// audits `image.created`. A missing signer degrades to a warning (best-effort,
/// as capture does); a present signer whose emit fails is fatal, so an
/// un-auditable restore refuses before it re-runs.
fn emit_image_revert_audit(node: &ImageNode, via: RevertVia, reference: &str) -> Result<()> {
    let signer = match crate::commands::vm::host_signer::load_or_init() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "host signer unavailable; image.reverted chain entry skipped");
            return Ok(());
        }
    };
    let emitter = crate::commands::vm::audit_chain::AuditEmitter::new(signer.signing)
        .map(|e| e.with_receipts())
        .context("refusing an unaudited image restore: audit emitter unavailable")?;
    // The node's content-address is always a valid 64-hex digest — bind the
    // event plan's image to it so synthesis can never reject a genuine node.
    let node_hex = node
        .node_digest
        .as_str()
        .strip_prefix(mvm_core::checkpoint::CheckpointDigest::PREFIX)
        .unwrap_or_else(|| node.node_digest.as_str());
    let plan = crate::commands::build::image_lineage::build_event_plan(
        IMAGE_REVERT_WORKLOAD,
        IMAGE_REVERT_INTENT,
        reference,
        node_hex,
    )
    .context("building the image.reverted audit-envelope plan")?;
    emitter
        .emit_image_reverted(&plan, node.node_digest.as_str(), via.as_str(), reference)
        .context("refusing an unaudited image restore")?;
    Ok(())
}

/// Resolve the parent of a restore target (the `rewind` step) via the C1
/// ancestry enumeration, so the parent hop is chain-verified. Fails closed when
/// the target is a genesis root, the ancestry is structurally broken, or the
/// parent hop itself did not verify — the selected node's own verdict is
/// enforced here, not left to a downstream re-verify.
fn parent_of(
    cstore: &CheckpointStore,
    istore: &ImageStore,
    anchor: &SignedChainAnchor,
    resolved: ResolvedTarget,
) -> Result<ResolvedTarget> {
    match resolved {
        ResolvedTarget::Checkpoint(meta) => {
            let ancestry = checkpoint_ancestry(cstore, &meta.id, anchor)?;
            if let Some(reason) = &ancestry.broken {
                bail!(
                    "cannot rewind: checkpoint {:?} lineage is broken: {reason}",
                    meta.id.as_str()
                );
            }
            // nodes[0] is the target; nodes[1] is its parent.
            let parent = ancestry.nodes.into_iter().nth(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot rewind: checkpoint {:?} is a genesis root with no parent",
                    meta.id.as_str()
                )
            })?;
            let record = verified_record(parent, "rewind")?;
            Ok(ResolvedTarget::Checkpoint(record))
        }
        ResolvedTarget::Image(node) => {
            let ancestry = image_ancestry(istore, &node.node_digest, anchor)?;
            if let Some(reason) = &ancestry.broken {
                bail!(
                    "cannot rewind: image node {} lineage is broken: {reason}",
                    node.node_digest
                );
            }
            let parent = ancestry.nodes.into_iter().nth(1).ok_or_else(|| {
                anyhow::anyhow!(
                    "cannot rewind: image node {} is a genesis root with no parent",
                    node.node_digest
                )
            })?;
            let record = verified_record(parent, "rewind")?;
            Ok(ResolvedTarget::Image(record))
        }
    }
}

/// Extract a verified node's record, failing closed if its per-hop verdict is
/// not `Verified`. `op` names the verb for the error (`rewind` / `advance`).
/// Safety here does not depend on the downstream restore re-verifying.
fn verified_record<R>(node: VerifiedNode<R>, op: &str) -> Result<R> {
    match node.status.error() {
        None => Ok(node.record),
        Some(reason) => bail!(
            "cannot {op}: the selected node did not verify against the signed audit chain: {reason}"
        ),
    }
}

/// Resolve a child of a restore target (the `advance` step) via the C1 children
/// enumeration. Forward is a tree, so a fork (more than one child) requires an
/// explicit `--to <child-digest>`.
fn child_of(
    cstore: &CheckpointStore,
    istore: &ImageStore,
    anchor: &SignedChainAnchor,
    resolved: ResolvedTarget,
    to: Option<&str>,
) -> Result<ResolvedTarget> {
    match resolved {
        ResolvedTarget::Checkpoint(meta) => {
            let children = checkpoint_children(cstore, &meta.meta_digest, anchor)?;
            let picked = pick_child(
                children
                    .into_iter()
                    .map(|c| (c.record.meta_digest.to_string(), c)),
                to,
                &format!("checkpoint {:?}", meta.id.as_str()),
            )?;
            Ok(ResolvedTarget::Checkpoint(verified_record(
                picked, "advance",
            )?))
        }
        ResolvedTarget::Image(node) => {
            let children = image_children(istore, &node.node_digest, anchor)?;
            let picked = pick_child(
                children
                    .into_iter()
                    .map(|c| (c.record.node_digest.to_string(), c)),
                to,
                &format!("image node {}", node.node_digest),
            )?;
            Ok(ResolvedTarget::Image(verified_record(picked, "advance")?))
        }
    }
}

/// Pick the single child to advance to, carrying its per-hop verdict for the
/// caller to enforce. No children → nothing to advance to; one child → that one
/// (or the one `--to` names); many children → `--to` must disambiguate the fork.
fn pick_child<R>(
    children: impl Iterator<Item = (String, VerifiedNode<R>)>,
    to: Option<&str>,
    target_label: &str,
) -> Result<VerifiedNode<R>> {
    let all: Vec<(String, VerifiedNode<R>)> = children.collect();
    if all.is_empty() {
        bail!("cannot advance: {target_label} has no children to advance to");
    }
    match to {
        Some(want) => all
            .into_iter()
            .find(|(digest, _)| digest == want)
            .map(|(_, node)| node)
            .ok_or_else(|| {
                anyhow::anyhow!("cannot advance: {target_label} has no child with digest {want:?}")
            }),
        None => {
            if all.len() > 1 {
                let digests: Vec<&str> = all.iter().map(|(d, _)| d.as_str()).collect();
                bail!(
                    "cannot advance: {target_label} has {} children (a fork); \
                     disambiguate with `--to <child-digest>`. Children: {}",
                    all.len(),
                    digests.join(", ")
                );
            }
            Ok(all.into_iter().next().expect("len == 1").1)
        }
    }
}

/// Emit the chain-signed `checkpoint.restored` entry for a completed restore,
/// bound to the plan the restored VM launched under (persisted by the fork
/// boot). Best-effort on a missing plan/signer (the VM already booted); a
/// present signer whose emit fails is fatal — an unaudited restore breaks the
/// chain.
fn emit_revert_audit(
    restored_vm_name: &str,
    target: &CheckpointMeta,
    via: RevertVia,
) -> Result<()> {
    let plan = match crate::commands::vm::plan_persist::read_plan(restored_vm_name) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, vm = restored_vm_name,
                "no persisted plan for restored VM; checkpoint.restored emitted without chain binding");
            return Ok(());
        }
    };
    let signer = match crate::commands::vm::host_signer::load_or_init() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "host signer unavailable; restore chain entry skipped");
            return Ok(());
        }
    };
    let emitter = crate::commands::vm::audit_chain::AuditEmitter::new(signer.signing)
        .map(|e| e.with_receipts())
        .context("refusing an unaudited restore: audit emitter unavailable")?;
    mvm_hostd::audit::bind::bind_checkpoint_restored(
        &emitter,
        &plan,
        target,
        restored_vm_name,
        via.as_str(),
    )
    .context("refusing an unaudited restore")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob};
    use mvm_core::image_lineage::{
        ImageBuildIdentity, ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance,
    };
    use mvm_core::manifest::{PersistedManifest, Provenance, slot_dir, slot_revision_dir};
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_hostd::audit::bind::bind_checkpoint_created;
    use mvm_hostd::audit::emitter::AuditEmitter;

    // ── seed helpers: a store record + its host-signed creation entry ─────────

    fn emitter() -> (AuditEmitter, mvm_core::plan::ExecutionPlan) {
        let signer = crate::commands::vm::host_signer::load_or_init().unwrap();
        let em = AuditEmitter::new(signer.signing).unwrap();
        let plan = PlanFixture::new()
            .tenant("local")
            .plan_id("plan-revert")
            .build();
        (em, plan)
    }

    fn seed_ckpt(
        store: &CheckpointStore,
        em: &AuditEmitter,
        plan: &mvm_core::plan::ExecutionPlan,
        id: &str,
        parent: Option<mvm_core::checkpoint::CheckpointDigest>,
    ) -> CheckpointMeta {
        let meta = CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
            .parent(parent)
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "h".into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build();
        store.write_meta(&meta).unwrap();
        bind_checkpoint_created(em, plan, &meta).unwrap();
        meta
    }

    fn image_of(
        slot: &str,
        revision: &str,
        parent: Option<mvm_core::checkpoint::CheckpointDigest>,
    ) -> ImageNode {
        ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: slot.into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: revision.into(),
                },
                artifacts: vec![ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: revision.into(),
                }],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .parent(parent)
        .created_unix(1)
        .build()
    }

    fn seed_flake_revision(slot_hash: &str, revision_hash: &str) -> ImageNode {
        let slot = std::path::PathBuf::from(slot_dir(slot_hash));
        std::fs::create_dir_all(&slot).unwrap();
        PersistedManifest {
            schema_version: 1,
            manifest_path: "/tmp/mvm.toml".into(),
            manifest_hash: slot_hash.into(),
            flake_ref: ".#app".into(),
            profile: "app".into(),
            vcpus: 2,
            mem_mib: 512,
            mem_initial_mib: None,
            data_disk_mib: 0,
            name: None,
            backend: "firecracker".into(),
            provenance: Provenance {
                toolchain_version: "test".into(),
                builder_image_digest: None,
                host_arch: "aarch64-darwin".into(),
                built_at: "2026-01-01T00:00:00Z".into(),
                ir_hash: None,
            },
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
        .write_to_slot(&slot)
        .unwrap();

        let revision_dir = std::path::PathBuf::from(slot_revision_dir(slot_hash, revision_hash));
        std::fs::create_dir_all(&revision_dir).unwrap();
        let rootfs = revision_dir.join("rootfs.ext4");
        let vmlinux = revision_dir.join("vmlinux");
        std::fs::write(&rootfs, b"rootfs-revision-1").unwrap();
        std::fs::write(&vmlinux, b"kernel-revision-1").unwrap();
        let rootfs_sha = mvm_core::crypto::image_verify::sha256_file(&rootfs).unwrap();
        let vmlinux_sha = mvm_core::crypto::image_verify::sha256_file(&vmlinux).unwrap();

        ImageNode::builder(
            ImageBuildIdentity::Flake {
                slot_hash: slot_hash.into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: revision_hash.into(),
                },
                artifacts: vec![
                    ContentBlob {
                        name: "rootfs.ext4".into(),
                        sha256: rootfs_sha,
                    },
                    ContentBlob {
                        name: "vmlinux".into(),
                        sha256: vmlinux_sha,
                    },
                ],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: Some("lock".into()),
            },
        )
        .created_unix(1)
        .build()
    }

    fn seed_image(
        store: &ImageStore,
        em: &AuditEmitter,
        plan: &mvm_core::plan::ExecutionPlan,
        node: &ImageNode,
    ) {
        store.save(node).unwrap();
        em.emit_image_created(plan, node).unwrap();
    }

    fn oci_node(digest_hex: &str) -> ImageNode {
        let resolved = format!("sha256:{}", digest_hex.repeat(64));
        ImageNode::builder(
            ImageBuildIdentity::Oci {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
            },
            ImageIdentity {
                canonical: ImageCanonicalId::Oci {
                    resolved_digest: resolved.clone(),
                },
                artifacts: vec![ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: digest_hex.into(),
                }],
            },
            ImageProvenance::Oci {
                resolved_digest: resolved,
                layer_digests: vec![],
            },
        )
        .created_unix(1)
        .build()
    }

    // ── reference reconstruction (pure) ──────────────────────────────────────

    #[test]
    fn oci_node_reconstructs_a_digest_pinned_reference() {
        let node = oci_node("a");
        let source = reconstruct_image_source(&node).unwrap();
        assert!(matches!(
            source,
            RevertImageSource::Oci(reference)
                if reference == format!("docker.io/library/alpine@sha256:{}", "a".repeat(64))
        ));
    }

    #[test]
    fn flake_node_reconstruction_requires_the_stored_revision() {
        let node = image_of("slot-a", "rev-1", None);
        let err = reconstruct_image_source(&node).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("flake"), "{msg}");
        assert!(msg.contains("manifest") || msg.contains("stored"), "{msg}");
    }

    // ── invariant 5: verify the target before restoring (fail closed) ─────────

    #[test]
    fn revert_refuses_an_unaudited_checkpoint_before_booting() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let store = CheckpointStore::open();
        // Written to the store but NEVER audited: no signed creation entry.
        let meta = CheckpointMeta::builder(
            CheckpointId::new("unaudited"),
            CheckpointClass::FsQuick,
            "vm",
        )
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "h".into(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        store.write_meta(&meta).unwrap();

        let err = run_revert(RevertArgs {
            target: "unaudited".into(),
            kind: None,
            hypervisor: "firecracker".into(),
            new_id: None,
            json: false,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no signed audit entry"),
            "revert must fail closed on an un-audited target: {msg}"
        );
    }

    #[test]
    fn revert_refuses_a_tampered_checkpoint_before_booting() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let store = CheckpointStore::open();
        let (em, plan) = emitter();
        let meta = seed_ckpt(&store, &em, &plan, "audited", None);

        // Tamper the sealed record after it was audited: recompute now drifts.
        let path = store.dir_for(&meta.id).join("meta.json");
        let mut tampered: CheckpointMeta =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        tampered.created_unix = 999;
        std::fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();

        let err = run_revert(RevertArgs {
            target: "audited".into(),
            kind: None,
            hypervisor: "firecracker".into(),
            new_id: None,
            json: false,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("drift") || msg.contains("does not match the signed audit chain"),
            "revert must fail closed on a tampered target: {msg}"
        );
    }

    #[test]
    fn revert_refuses_an_image_node_absent_from_the_signed_chain() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let istore = ImageStore::open();
        let node = oci_node("a");
        // Saved but NEVER audited.
        istore.save(&node).unwrap();

        let err = run_revert(RevertArgs {
            target: node.node_digest.as_str().to_string(),
            kind: None,
            hypervisor: "firecracker".into(),
            new_id: None,
            json: false,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no signed audit entry"),
            "image revert must fail closed on an un-audited node: {msg}"
        );
    }

    /// An audited OCI image node passes verification, reconstructs its
    /// digest-pinned reference, emits a chain-signed `image.reverted` marker, and
    /// returns a `RunImage` the dispatcher re-runs through the admitted run path —
    /// the image analog of "re-admit, don't bypass". `run_revert` never boots
    /// inline for an image target.
    #[test]
    fn revert_of_an_audited_oci_node_reconstructs_a_run_and_audits_the_revert() {
        use mvm_hostd::supervisor::verify_audit_chain;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let istore = ImageStore::open();
        let (em, plan) = emitter();
        let node = oci_node("a");
        seed_image(&istore, &em, &plan, &node);

        let outcome = run_revert(RevertArgs {
            target: node.node_digest.as_str().to_string(),
            kind: None,
            hypervisor: "firecracker".into(),
            new_id: None,
            json: false,
        })
        .unwrap();
        match outcome {
            RevertOutcome::RunImage(run) => {
                assert!(matches!(
                    run.source,
                    RevertImageSource::Oci(reference)
                        if reference
                            == format!(
                                "docker.io/library/alpine@sha256:{}",
                                "a".repeat(64)
                            )
                ));
            }
            RevertOutcome::Done => {
                panic!(
                    "an image restore must route through the admitted run path, not complete inline"
                )
            }
        }

        // The revert is distinctly audited BEFORE handoff: image.created (seed) +
        // image.reverted (revert), both chain-signed and verifiable.
        let signer = crate::commands::vm::host_signer::load_or_init().unwrap();
        let path = mvm_hostd::audit::emitter::default_audit_dir()
            .unwrap()
            .join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("image.reverted"), "{content}");
        assert!(content.contains(node.node_digest.as_str()));
        assert!(content.contains("\"via\""));
        assert!(content.contains("revert"));
        assert_eq!(verify_audit_chain(&path, &signer.verifying).unwrap(), 2);
    }

    #[test]
    fn flake_node_reconstruction_rejects_tampered_artifacts() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let node = seed_flake_revision("slot-a", "rev-1");
        let rootfs =
            std::path::PathBuf::from(slot_revision_dir("slot-a", "rev-1")).join("rootfs.ext4");
        std::fs::write(rootfs, b"tampered").unwrap();
        let err = reconstruct_image_source(&node).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("reconciliation"), "{msg}");
    }

    #[test]
    fn revert_of_an_audited_flake_node_selects_the_pinned_revision() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let istore = ImageStore::open();
        let (em, plan) = emitter();
        let node = seed_flake_revision("slot-a", "rev-1");
        seed_image(&istore, &em, &plan, &node);

        let outcome = run_revert(RevertArgs {
            target: node.node_digest.as_str().to_string(),
            kind: None,
            hypervisor: "firecracker".into(),
            new_id: None,
            json: false,
        })
        .unwrap();
        match outcome {
            RevertOutcome::RunImage(run) => assert!(matches!(
                run.source,
                RevertImageSource::Flake {
                    slot_hash,
                    revision_hash,
                } if slot_hash == "slot-a" && revision_hash == "rev-1"
            )),
            RevertOutcome::Done => panic!("flake image restore must use the admitted run path"),
        }
    }

    /// `--new-id` names the restored VM for a checkpoint restore; an image restore
    /// auto-names through the run path, so passing it is rejected, not dropped.
    #[test]
    fn image_revert_rejects_new_id() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let istore = ImageStore::open();
        let (em, plan) = emitter();
        let node = oci_node("a");
        seed_image(&istore, &em, &plan, &node);

        let err = run_revert(RevertArgs {
            target: node.node_digest.as_str().to_string(),
            kind: None,
            hypervisor: "firecracker".into(),
            new_id: Some("my-restored-vm".into()),
            json: false,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("--new-id"), "{msg}");
    }

    /// A rewind/advance target's own per-hop verdict is enforced here, not left
    /// to the downstream restore re-verify: a `Failed` hop is refused, a
    /// `Verified` hop yields its record.
    #[test]
    fn verified_record_gates_on_hop_status() {
        use mvm_runtime::lineage::{HopStatus, VerifiedNode};
        let meta = CheckpointMeta::builder(CheckpointId::new("n"), CheckpointClass::FsQuick, "vm")
            .content(vec![])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build();
        let verified = VerifiedNode {
            record: meta.clone(),
            status: HopStatus::Verified,
        };
        assert!(verified_record(verified, "rewind").is_ok());

        let failed = VerifiedNode {
            record: meta,
            status: HopStatus::Failed("meta_digest drift".into()),
        };
        let err = verified_record(failed, "advance").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("advance"), "names the op: {msg}");
        assert!(msg.contains("drift"), "preserves the reason: {msg}");
    }

    // ── cross-store ambiguity refused (shared resolver) ──────────────────────

    #[test]
    fn revert_refuses_a_cross_store_ambiguous_digest() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let cstore = CheckpointStore::open();
        let istore = ImageStore::open();

        // Plant the same digest string in both stores.
        let d = mvm_core::checkpoint::CheckpointDigest::parse(format!("sha256:{}", "c".repeat(64)))
            .unwrap();
        let mut meta =
            CheckpointMeta::builder(CheckpointId::new("collide"), CheckpointClass::FsQuick, "vm")
                .content(vec![])
                .supervisor_config_digest("d")
                .created_unix(1)
                .build();
        meta.meta_digest = d.clone();
        cstore.write_meta(&meta).unwrap();
        let mut node = image_of("slot-a", "rev-1", None);
        node.node_digest = d.clone();
        istore.save(&node).unwrap();

        let err = run_revert(RevertArgs {
            target: d.as_str().to_string(),
            kind: None,
            hypervisor: "firecracker".into(),
            new_id: None,
            json: false,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("BOTH"),
            "ambiguous digest must be refused: {msg}"
        );
        assert!(
            msg.contains("--kind"),
            "refusal must point at --kind: {msg}"
        );
    }

    // ── invariant 4: a completed restore emits a verifiable chain entry ───────

    #[test]
    fn emit_revert_audit_writes_a_verifiable_restored_entry() {
        use mvm_hostd::supervisor::verify_audit_chain;

        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        // The restored VM's plan is persisted by the fork boot; seed it here so
        // the audit binds to the launched identity.
        let restored_vm = "revert-target-child";
        let plan = PlanFixture::new()
            .tenant("local")
            .plan_id("plan-restored")
            .build();
        crate::commands::vm::plan_persist::write_plan(restored_vm, &plan).unwrap();

        let target = CheckpointMeta::builder(
            CheckpointId::new("target"),
            CheckpointClass::FsQuick,
            "origin",
        )
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "h".into(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();

        emit_revert_audit(restored_vm, &target, RevertVia::Rewind).unwrap();

        let signer = crate::commands::vm::host_signer::load_or_init().unwrap();
        let path = mvm_hostd::audit::emitter::default_audit_dir()
            .unwrap()
            .join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.restored"));
        assert!(content.contains("target"));
        assert!(content.contains(restored_vm));
        assert!(content.contains("rewind"), "the via label must be recorded");
        // The chain-signed entry verifies under the host key.
        assert_eq!(verify_audit_chain(&path, &signer.verifying).unwrap(), 1);
    }

    #[test]
    fn emit_revert_audit_is_best_effort_when_no_plan_is_persisted() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let target =
            CheckpointMeta::builder(CheckpointId::new("t"), CheckpointClass::FsQuick, "origin")
                .content(vec![])
                .supervisor_config_digest("d")
                .created_unix(1)
                .build();
        // No persisted plan for the restored VM → best-effort skip, not an error.
        emit_revert_audit("no-plan-vm", &target, RevertVia::Revert).unwrap();
    }

    // ── invariant 3: a sealed restore preserves the sealed posture ────────────

    #[test]
    fn sealed_restore_derives_the_attenuated_grant_and_refuses_console() {
        // A restore reuses the fork boot, which takes the attenuated ProdSafe
        // grant (no console/exec) from the shape of the run, and whose backend
        // records accessible=false — exactly as fork does.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake").unwrap();
        let sidecar = mvm_build::builder_vm::GuestSidecar {
            name: "sealed".to_string(),
            accessible: false,
            sealed: true,
            entrypoint_kind: "command".to_string(),
            entrypoint_argv: Vec::new(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "real".to_string(),
            rootless_entrypoint: true,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
            runtime_lean: true,
            image_tag: String::new(),
            source: String::new(),
            built_at: String::new(),
            protocol_version: 0,
            generator_rev: String::new(),
            libc: mvm_build::guest_libc::GuestLibc::Glibc,
        };
        sidecar.write_to_dir(tmp.path()).unwrap();

        // The restore qualifies for the attenuated grant the fork boot sets on
        // the restored VM's admitted plan. The image's sealed bit no longer
        // enters that decision — the shape of the run does — but the sidecar is
        // still written here because the console gate below reads the posture
        // the backend records from it.
        assert!(crate::commands::vm::agent_verbs::image_is_sealed(&rootfs));
        assert!(
            crate::commands::vm::agent_verbs::grant_eligible(false, false, false),
            "a restore must receive the attenuated ProdSafe grant"
        );

        // And a restored VM whose recorded runtime meta is sealed refuses the
        // interactive console gate (claim 15).
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", home.path());
        let state_dir = mvm_core::config::vm_state_dir("restored-sealed");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            state_dir.join("mode.json"),
            "{\"mode\":\"detached\",\"accessible\":false}\n",
        )
        .unwrap();
        let err = crate::commands::vm::console::enforce_accessible_gate("restored-sealed", false)
            .unwrap_err();
        assert!(
            err.to_string().contains("sealed"),
            "a restored sealed VM must refuse console: {err}"
        );
    }
}
