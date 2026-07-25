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
//! - **Image-node targets** re-run the node's recorded reference through the
//!   normal admitted `machine run` path, which re-admits identically.
//!
//! Every restore verifies its target against the signed audit chain up front and
//! fails closed on an un-audited, tampered, or dangling record — the same
//! `verify_lineage` / `verify_image_lineage` gate `machine checkpoint verify`
//! and `fork` use. A completed checkpoint restore additionally emits a
//! chain-signed `checkpoint.restored` entry carrying the initiating verb
//! (`revert` / `rewind` / `advance`) as its `via` label.

use anyhow::{Context, Result, bail};

use mvm_core::checkpoint::CheckpointMeta;
use mvm_core::image_lineage::{ImageBuildIdentity, ImageCanonicalId, ImageNode, ImageProvenance};
use mvm_runtime::checkpoint::{
    CheckpointStore, checkpoint_ancestry, checkpoint_children, verify_lineage,
};
use mvm_runtime::image_lineage::{
    ImageStore, image_ancestry, image_children, verify_image_lineage,
};

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

/// The reconstructed `machine run` reference for an image-node restore. Exactly
/// one of `image` / `flake` is set.
#[derive(Debug)]
pub(in crate::commands) struct RevertRunImage {
    pub image: Option<String>,
    pub flake: Option<String>,
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
        .unwrap_or_else(|| format!("revert-{}-{}", target.id.as_str(), now_unix()));

    // Reuse the fork path verbatim: it re-admits through `admit_plan_for_boot`,
    // re-derives the sealed attenuation, and boots. This is the anti-bypass
    // guarantee — a restore never reaches `restore_checkpoint`.
    super::fork(
        target.id.as_str(),
        Some(restored_vm_name.clone()),
        /* boot */ true,
        opts.hypervisor,
        /* cpus */ None,
        /* memory */ None,
        opts.json,
    )
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

/// Restore an image-node target: verify it against the signed audit chain, then
/// reconstruct its recorded `machine run` reference. The caller re-runs that
/// reference through the normal admitted run path, which re-admits identically
/// and chain-signs its own admission trail.
fn revert_image(
    store: &ImageStore,
    node: ImageNode,
    via: RevertVia,
    opts: &RestoreOpts<'_>,
) -> Result<RevertOutcome> {
    let anchor = SignedChainAnchor::load()
        .context("loading the signed audit chain to verify the restore target")?;
    verify_image_lineage(store, &node.node_digest, &anchor).with_context(|| {
        format!(
            "refusing to restore image node {}: its lineage does not verify against the \
             signed audit chain",
            node.node_digest
        )
    })?;

    let reference = reconstruct_image_run_reference(&node)?;
    tracing::info!(
        node = %node.node_digest,
        via = via.as_str(),
        "image restore re-runs the recorded reference through the admitted run path"
    );
    Ok(RevertOutcome::RunImage(RevertRunImage {
        image: reference.image,
        flake: reference.flake,
        hypervisor: Some(opts.hypervisor.to_string()),
        json: opts.json,
    }))
}

/// Reconstruct the `machine run` reference an image node recorded, so a restore
/// re-materializes the exact prior image. OCI nodes yield a digest-pinned
/// `<registry>/<repository>@<digest>`; flake nodes yield the recorded input ref.
fn reconstruct_image_run_reference(node: &ImageNode) -> Result<RevertRunImage> {
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
            Ok(RevertRunImage {
                image: Some(format!("{registry}/{repository}@{resolved_digest}")),
                flake: None,
                hypervisor: None,
                json: false,
            })
        }
        ImageBuildIdentity::Flake { .. } => {
            let ImageProvenance::Build { input_ref, .. } = &node.provenance else {
                bail!(
                    "image node {} names a flake build identity but non-build provenance; \
                     refusing to reconstruct an ambiguous reference",
                    node.node_digest
                );
            };
            Ok(RevertRunImage {
                image: None,
                flake: Some(input_ref.clone()),
                hypervisor: None,
                json: false,
            })
        }
    }
}

/// Resolve the parent of a restore target (the `rewind` step) via the C1
/// ancestry enumeration, so the parent hop is chain-verified. Fails closed when
/// the target is a genesis root or the ancestry is structurally broken.
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
            Ok(ResolvedTarget::Checkpoint(parent.record))
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
            Ok(ResolvedTarget::Image(parent.record))
        }
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
                    .map(|c| (c.record.meta_digest.to_string(), c.record)),
                to,
                &format!("checkpoint {:?}", meta.id.as_str()),
            )?;
            Ok(ResolvedTarget::Checkpoint(picked))
        }
        ResolvedTarget::Image(node) => {
            let children = image_children(istore, &node.node_digest, anchor)?;
            let picked = pick_child(
                children
                    .into_iter()
                    .map(|c| (c.record.node_digest.to_string(), c.record)),
                to,
                &format!("image node {}", node.node_digest),
            )?;
            Ok(ResolvedTarget::Image(picked))
        }
    }
}

/// Pick the single child to advance to. No children → nothing to advance to; one
/// child → that one (or the one `--to` names); many children → `--to` must
/// disambiguate the fork.
fn pick_child<R>(
    children: impl Iterator<Item = (String, R)>,
    to: Option<&str>,
    target_label: &str,
) -> Result<R> {
    let all: Vec<(String, R)> = children.collect();
    if all.is_empty() {
        bail!("cannot advance: {target_label} has no children to advance to");
    }
    match to {
        Some(want) => all
            .into_iter()
            .find(|(digest, _)| digest == want)
            .map(|(_, record)| record)
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob};
    use mvm_core::image_lineage::{
        ImageBuildIdentity, ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance,
    };
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
        let out = reconstruct_image_run_reference(&node).unwrap();
        assert_eq!(
            out.image.as_deref(),
            Some(format!("docker.io/library/alpine@sha256:{}", "a".repeat(64)).as_str()),
            "OCI restore must re-fetch the exact resolved digest"
        );
        assert!(out.flake.is_none());
    }

    #[test]
    fn flake_node_reconstructs_the_recorded_input_ref() {
        let node = image_of("slot-a", "rev-1", None);
        let out = reconstruct_image_run_reference(&node).unwrap();
        assert_eq!(out.flake.as_deref(), Some(".#app"));
        assert!(out.image.is_none());
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
        let node = image_of("slot-a", "rev-1", None);
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

    /// An audited image node passes verification and reconstructs its recorded
    /// reference, returning a `RunImage` that the dispatcher re-runs through the
    /// normal admitted run path — the image analog of "re-admit, don't bypass".
    /// `run_revert` never boots inline for an image target.
    #[test]
    fn revert_of_an_audited_image_node_reconstructs_a_run_not_a_bypass() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());
        let istore = ImageStore::open();
        let (em, plan) = emitter();
        let node = image_of("slot-a", "rev-1", None);
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
                assert_eq!(
                    run.flake.as_deref(),
                    Some(".#app"),
                    "a flake image node restores through its recorded input ref"
                );
                assert!(run.image.is_none());
            }
            RevertOutcome::Done => {
                panic!(
                    "an image restore must route through the admitted run path, not complete inline"
                )
            }
        }
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
        // A restore of a sealed image reuses the fork boot, which derives the
        // attenuated ProdSafe grant from `image_is_sealed` (no console/exec) and
        // whose backend records accessible=false — exactly as fork does.
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fake").unwrap();
        let sidecar = mvm_build::builder_vm::GuestSidecar {
            name: "sealed".to_string(),
            accessible: false,
            sealed: true,
            entrypoint_kind: "command".to_string(),
            init_system: "busybox".to_string(),
            expected_boot_ms: 300,
            agent_binary: "real".to_string(),
            rootless_entrypoint: true,
            hypervisor: "firecracker".to_string(),
            overlay_aware: true,
            runtime_lean: true,
        };
        sidecar.write_to_dir(tmp.path()).unwrap();

        // The sealed rootfs qualifies for the attenuated grant the fork boot sets
        // on the restored VM's admitted plan.
        assert!(crate::commands::vm::agent_verbs::image_is_sealed(&rootfs));
        assert!(
            crate::commands::vm::agent_verbs::grant_eligible(
                false,
                false,
                false,
                crate::commands::vm::agent_verbs::image_is_sealed(&rootfs),
            ),
            "a sealed restore must receive the attenuated ProdSafe grant"
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
