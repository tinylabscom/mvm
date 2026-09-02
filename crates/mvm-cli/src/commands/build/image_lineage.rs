//! Records an audited image-lineage node after a successful flake build.
//!
//! A build produces a compiled microVM image; this module content-addresses
//! that image into an [`ImageNode`], hash-links it onto the prior build of the
//! same slot identity, and binds its creation into the host-signed audit chain
//! before the build reports success.
//!
//! # Ordering and the trust invariant
//!
//! A node is committed to the store with an atomic write, then its creation is
//! chain-signed. If the emit fails, the just-saved node is rolled back, so the
//! signed chain never carries an entry for a node the store dropped (no phantom
//! entry). The invariant that actually protects trust is not "the store only
//! holds anchored nodes" but "a stored node is never *trusted* without its
//! signed chain entry": `verify_image_lineage` fails closed on any un-audited
//! node.
//!
//! A process crash between the save and the emit can leave a stored node
//! transiently un-audited. Verification rejects it; the next build self-heals
//! it. Because a *later* revision can chain onto a crash-orphaned predecessor,
//! the self-heal walks the tip's ancestry and completes the audit of every
//! un-audited ancestor before either no-oping (same revision) or chaining a new
//! child onto it — so a newly created node's full ancestry is always anchored
//! and lineage verification cannot fail closed on a stranded orphan.
//!
//! A node carries a non-load-bearing `audit_ref` back-pointer, stamped once its
//! creation is anchored, so the common path tells "already audited" from a cheap
//! field read; the full signed chain is loaded (lazily, once) only when a node
//! lacks the marker. The signed chain stays authoritative: a missing marker on
//! an actually-audited node is confirmed against it and backfilled, never
//! double-emitted.
//!
//! # Lineage is PROVENANCE, not AUTHORIZATION
//!
//! Nothing here (or downstream) consults a node to grant a build, an admission,
//! or a boot any trust. The recorded chain proves only *where a build came
//! from*; boot integrity stays with dm-verity and admission with the signed
//! bundle. The chain-shaping decision (genesis / child / idempotent no-op) keys
//! strictly on the build identity and the image's canonical revision — the
//! recorded provenance is never an input to it.

use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use mvm_core::checkpoint::{CheckpointDigest, ContentBlob};
use mvm_core::crypto::image_verify::sha256_file_cached;
use mvm_core::image_lineage::{
    ImageBuildIdentity, ImageCanonicalId, ImageIdentity, ImageNode, ImageProvenance,
};
use mvm_core::manifest::{PersistedManifest, slot_revision_dir};
use mvm_core::plan::{ExecutionPlan, SynthesisInput, synthesize_plan};
use mvm_core::template::TemplateRevision;
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::audit::host_keypair::load_or_init;
use mvm_runtime::image_lineage::{ImageChainAnchor, ImageStore};

use crate::commands::vm::checkpoint::SignedChainAnchor;
use crate::ui;

/// The audit-emit capability [`record_image_node`] depends on, narrowed to the
/// single `image.created` emit so a test can inject a failing emitter and
/// exercise the save-then-emit rollback. [`AuditEmitter`] is the production impl.
pub(in crate::commands) trait ImageCreatedEmitter {
    fn emit_image_created(&self, plan: &ExecutionPlan, node: &ImageNode) -> Result<()>;
}

impl ImageCreatedEmitter for AuditEmitter {
    fn emit_image_created(&self, plan: &ExecutionPlan, node: &ImageNode) -> Result<()> {
        AuditEmitter::emit_image_created(self, plan, node)
    }
}

/// Workload name stamped on the synthesized audit-envelope plan. A build is not
/// a workload run, so this is only the plan's identity label — never admitted.
const IMAGE_BUILD_WORKLOAD: &str = "image-build";

/// Intent stamped on the synthesized audit-envelope plan.
const IMAGE_BUILD_INTENT: &str = "image:build";

/// The content-addressable inputs for one image-lineage node, decoupled from
/// where they came from (a flake build, an OCI pull) so the record/audit core
/// is exercisable without a real build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct ImageNodeInputs {
    /// The version-chain key: builds sharing it line up on one chain.
    pub build_identity: ImageBuildIdentity,
    /// The compiled image's own canonical identity (flake revision hash / OCI
    /// resolved digest). The idempotency check keys on this.
    pub canonical: ImageCanonicalId,
    /// Content commitments to the produced artifact bytes.
    pub artifacts: Vec<ContentBlob>,
    /// The external base, recorded as a provenance attribute (never a walk edge
    /// and never a trust input).
    pub provenance: ImageProvenance,
}

/// Outcome of a node-record attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum ImageNodeOutcome {
    /// A new node was created, persisted, and audited; carries its digest.
    Created(CheckpointDigest),
    /// The slot's current tip already records this exact revision and is already
    /// anchored in the signed chain, so no new node and no new entry — an
    /// identical-revision rebuild is a no-op.
    AlreadyCurrent(CheckpointDigest),
    /// The tip already records this revision but carried no signed creation entry
    /// (a crash orphaned it between save and emit); its audit was completed by
    /// re-emitting `image.created`. Carries the healed node's digest.
    Healed(CheckpointDigest),
}

/// Create, persist, and audit an image-lineage node for a freshly built image.
///
/// Resolves the slot's current chain tip and either chains the new build as its
/// child, opens a genesis node when the slot has no prior build, or reconciles
/// an identical-revision rebuild. A genuinely ambiguous (forked) tip surfaces as
/// an error rather than a silent guess — the store's `head_for` fails closed on
/// a fork and that error is propagated.
///
/// Before either no-oping or chaining a child, the tip's ancestry is healed: any
/// un-audited ancestor (a crash orphan) has its `image.created` re-emitted, so a
/// newly created node's full ancestry is always anchored and lineage
/// verification cannot fail closed on a stranded orphan. A new node is committed
/// atomically and *then* chain-signed; an emit failure rolls it back so the
/// chain never references a node the store dropped. The healing check is
/// marker-first — a node's `audit_ref` back-pointer proves it is anchored
/// cheaply — and consults `anchor` (the same reader the verifier uses) only when
/// a marker is absent.
pub(in crate::commands) fn record_image_node(
    store: &ImageStore,
    emitter: &dyn ImageCreatedEmitter,
    plan: &ExecutionPlan,
    inputs: &ImageNodeInputs,
    created_unix: u64,
    anchor: &dyn ImageChainAnchor,
) -> Result<ImageNodeOutcome> {
    let head = store
        .head_for(&inputs.build_identity)
        .context("resolving the current image-lineage tip for this build identity")?;

    // Heal any un-audited ancestor before we no-op on the tip or chain a child
    // onto it, so the resulting tip's whole ancestry is anchored.
    let healed = match &head {
        Some(tip) => heal_unaudited_ancestry(store, emitter, plan, anchor, tip)?,
        None => false,
    };

    // The current tip already records this exact revision. We do not fork a
    // second tip for one identity; the ancestry heal above already completed any
    // orphaned audit. Provenance is deliberately not compared — it is recorded,
    // never a chain-shaping input.
    if let Some(tip) = head
        .as_ref()
        .filter(|tip| tip.image_identity.canonical == inputs.canonical)
    {
        return Ok(if healed {
            ImageNodeOutcome::Healed(tip.node_digest.clone())
        } else {
            ImageNodeOutcome::AlreadyCurrent(tip.node_digest.clone())
        });
    }

    let parent = head.map(|tip| tip.node_digest);
    create_image_node(store, emitter, plan, inputs, created_unix, parent)
}

/// Build, commit, then chain-sign a genuinely new node (genesis or child).
///
/// Save precedes emit so the store never holds a node the chain references but
/// cannot resolve; the save is atomic ([`ImageStore::save`]). If the emit fails
/// the just-saved node is rolled back, leaving nothing behind for a clean retry.
/// On success the node is stamped with its audit back-pointer so a later build
/// recognizes it as anchored without scanning the chain.
fn create_image_node(
    store: &ImageStore,
    emitter: &dyn ImageCreatedEmitter,
    plan: &ExecutionPlan,
    inputs: &ImageNodeInputs,
    created_unix: u64,
    parent: Option<CheckpointDigest>,
) -> Result<ImageNodeOutcome> {
    let node = ImageNode::builder(
        inputs.build_identity.clone(),
        ImageIdentity {
            canonical: inputs.canonical.clone(),
            artifacts: inputs.artifacts.clone(),
        },
        inputs.provenance.clone(),
    )
    .parent(parent)
    .created_unix(created_unix)
    .build();

    store
        .save(&node)
        .context("persisting the image-lineage node")?;
    if let Err(e) = emitter.emit_image_created(plan, &node) {
        // Roll the node back so the chain never references a node the store
        // dropped, and a retry re-creates it cleanly.
        if let Err(rollback_err) = store.remove(&node.node_digest) {
            tracing::warn!(
                node_digest = %node.node_digest,
                error = %rollback_err,
                "failed to roll back an un-audited image-lineage node after its audit emit \
                 failed; it will be rejected by lineage verification and healed on the next build"
            );
        }
        return Err(e).context("recording image.created in the signed audit chain");
    }
    mark_audited(store, &node, plan);
    Ok(ImageNodeOutcome::Created(node.node_digest))
}

/// Walk `tip`'s ancestry to genesis, completing the audit of every un-audited
/// node so a build never chains onto — or no-ops on — a chain with a stranded
/// orphan (which would make `verify_image_lineage` fail closed forever). Returns
/// whether any node was healed.
///
/// The walk terminates on exactly two things: an `audit_ref` marker we stamped,
/// or genesis. A marker is only ever set *after* healing a node's ancestry
/// (`create_image_node` heals the tip before emitting+marking a new node; this
/// walk marks each node it processes), so a marker means the whole chain below is
/// already anchored — the walk stops there without touching the signed chain.
///
/// An *unmarked* node is never trusted to end the walk: it was written by a flow
/// that did not heal its ancestry (a pre-marker record, or a crash between emit
/// and mark), so an orphan may still lurk beneath it. Its state is resolved
/// against the authoritative `anchor` and then the walk **continues** to the
/// parent: an already-audited node has its marker backfilled with no re-emit; a
/// genuine orphan has `image.created` re-emitted, then is marked. So the first
/// post-upgrade build walks to genesis once (one lazy anchor load, reused),
/// backfilling markers and healing any real orphans; later builds stop at the
/// first marked node.
///
/// A `seen` set refuses to revisit a digest, so a fabricated cross-identity cycle
/// fails closed rather than looping or re-emitting duplicates — even if a
/// persistently-failing `mark_audited` never sets the markers that would
/// otherwise end the walk (mirrors the lineage walkers' cycle guard).
fn heal_unaudited_ancestry(
    store: &ImageStore,
    emitter: &dyn ImageCreatedEmitter,
    plan: &ExecutionPlan,
    anchor: &dyn ImageChainAnchor,
    tip: &ImageNode,
) -> Result<bool> {
    let mut healed = false;
    let mut seen: HashSet<CheckpointDigest> = HashSet::new();
    let mut current = tip.clone();
    loop {
        // A revisit can only mean a cycle — a valid ancestry is a simple path.
        if !seen.insert(current.node_digest.clone()) {
            anyhow::bail!(
                "image-lineage ancestry of {} revisits {}: a cycle; refusing to heal",
                tip.node_digest,
                current.node_digest
            );
        }
        // A marker we stamped means this node's ancestry is already healed — stop.
        if current.audit_ref.is_some() {
            break;
        }
        if anchor.recorded_creation_digest(&current)?.is_some() {
            // Anchored but unmarked (a pre-marker record, or a crash between emit
            // and mark). Backfill the marker without re-emitting — but keep
            // walking: this node's writer did not heal its ancestry.
            mark_audited(store, &current, plan);
        } else {
            // A genuine orphan (saved, never emitted). The envelope binds to this
            // build's plan; the entry's identity labels come from the node itself.
            emitter
                .emit_image_created(plan, &current)
                .context("completing the audit of a crash-orphaned image-lineage ancestor")?;
            mark_audited(store, &current, plan);
            healed = true;
        }

        match &current.parent {
            Some(parent_digest) => {
                current = store
                    .read(parent_digest)
                    .context("reading an image-lineage ancestor to heal its audit")?;
            }
            None => break,
        }
    }
    Ok(healed)
}

/// Stamp a node's `audit_ref` back-pointer once its creation is anchored, so a
/// later build recognizes it as audited from a field read rather than a chain
/// scan. `audit_ref` is excluded from the content-address, so the re-save keeps
/// the same `node_digest` (and directory) — the record is unchanged for
/// verification. Best-effort: the marker is an optimization, and the signed
/// chain stays authoritative, so a re-save failure is logged, not fatal.
fn mark_audited(store: &ImageStore, node: &ImageNode, plan: &ExecutionPlan) {
    if node.audit_ref.is_some() {
        return;
    }
    let marked = ImageNode {
        audit_ref: Some(audit_ref_marker(plan)),
        ..node.clone()
    };
    if let Err(e) = store.save(&marked) {
        tracing::warn!(
            node_digest = %node.node_digest,
            error = %e,
            "failed to stamp an image-lineage node's audit marker; the next build will \
             re-confirm it against the signed chain"
        );
    }
}

/// The value stamped in `audit_ref`: the per-tenant chain file the node's
/// `image.created` entry lives in. Only its presence is load-bearing (the cheap
/// "audited" marker); the value is informational, so the chain filename suffices.
fn audit_ref_marker(plan: &ExecutionPlan) -> String {
    format!("{}.jsonl", plan.tenant.0)
}

/// A [`SignedChainAnchor`] loaded on first use and cached, so the hot build path
/// pays the full `~/.mvm/audit/` scan + verify only when a node lacks its cheap
/// `audit_ref` marker (the rare orphan / pre-marker case), never on a build whose
/// ancestry is fully marked.
struct LazySignedChainAnchor {
    inner: RefCell<Option<SignedChainAnchor>>,
}

impl LazySignedChainAnchor {
    fn new() -> Self {
        Self {
            inner: RefCell::new(None),
        }
    }
}

impl ImageChainAnchor for LazySignedChainAnchor {
    fn recorded_creation_digest(&self, node: &ImageNode) -> Result<Option<CheckpointDigest>> {
        if self.inner.borrow().is_none() {
            let loaded = load_signed_chain_anchor()?;
            *self.inner.borrow_mut() = Some(loaded);
        }
        self.inner
            .borrow()
            .as_ref()
            .expect("anchor was just loaded")
            .recorded_creation_digest(node)
    }
}

fn flake_build_identity(slot_hash: &str) -> ImageBuildIdentity {
    ImageBuildIdentity::Flake {
        slot_hash: slot_hash.to_string(),
    }
}

fn flake_canonical(revision_hash: &str) -> ImageCanonicalId {
    ImageCanonicalId::Flake {
        revision_hash: revision_hash.to_string(),
    }
}

fn oci_build_identity(registry: &str, repository: &str) -> ImageBuildIdentity {
    ImageBuildIdentity::Oci {
        registry: registry.to_string(),
        repository: repository.to_string(),
    }
}

fn oci_canonical(resolved_digest: &str) -> ImageCanonicalId {
    ImageCanonicalId::Oci {
        resolved_digest: resolved_digest.to_string(),
    }
}

/// Assemble the node inputs for a flake build from its slot hash, the produced
/// revision, and the on-disk artifact hashes.
fn flake_node_inputs(
    slot_hash: &str,
    revision: &TemplateRevision,
    rootfs_sha256: String,
    vmlinux_sha256: String,
) -> ImageNodeInputs {
    ImageNodeInputs {
        build_identity: flake_build_identity(slot_hash),
        canonical: flake_canonical(&revision.revision_hash),
        artifacts: vec![
            ContentBlob {
                name: revision.artifact_paths.rootfs.clone(),
                sha256: rootfs_sha256,
            },
            ContentBlob {
                name: revision.artifact_paths.vmlinux.clone(),
                sha256: vmlinux_sha256,
            },
        ],
        provenance: ImageProvenance::Build {
            input_ref: revision.flake_ref.clone(),
            lock_digest: Some(revision.flake_lock_hash.clone()),
        },
    }
}

/// Synthesize the audit-envelope plan a host-side image-lineage chain entry
/// (`image.created` / `image.reverted`) binds to. Such an event is not a
/// workload admission, so this plan is only the tenant / plan-id / image binding
/// the chain entry carries — it is never signed, admitted, or booted. Tenant is
/// the local host tenant (`DEFAULT_TENANT`); `workload` / `intent` label the
/// operation (build vs restore). `image_sha256` must be a 64-char lowercase hex
/// digest. Shared with the revert engine so both host-side markers use one
/// synthesis path.
pub(in crate::commands) fn build_event_plan(
    workload: &str,
    intent: &str,
    image_name: &str,
    image_sha256: &str,
) -> Result<ExecutionPlan> {
    let input = SynthesisInput {
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        network_mode: Default::default(),
        ingress: Vec::new(),
        vm_name: workload,
        tenant: None,
        backend_name: workload,
        image_name,
        image_sha256,
        image_cosign_bundle: None,
        intent: Some(intent),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: mvm_core::plan::SecretReleasePolicy::None,
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: 1,
        mem_mib: 64,
        disk_mib: 0,
        boot_timeout_secs: 1,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        caller_commitment: None,
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    };
    synthesize_plan(&input).context("synthesizing the image-lineage audit-envelope plan")
}

/// Record an audited image-lineage node for a completed flake build.
///
/// Surfaces any failure so the caller can fail the build rather than leave an
/// image un-audited — a build that produced an image but could not record its
/// lineage is a failure, not a silent skip.
///
/// The identical-revision fast path is checked *before* any artifact hashing:
/// this recorder backs `mvmctl machine run --flake`, which reruns on every
/// invocation, so re-hashing an unchanged multi-GB rootfs only to discover the
/// revision is already recorded would be a per-run regression. Artifact hashing
/// happens lazily, and only for a genuinely new revision.
pub(in crate::commands) fn record_flake_build_node(
    persisted: &PersistedManifest,
    revision: &TemplateRevision,
) -> Result<()> {
    let slot_hash = &persisted.manifest_hash;
    let build_identity = flake_build_identity(slot_hash);
    let canonical = flake_canonical(&revision.revision_hash);
    let store = ImageStore::open();

    match classify_tip(&store, &build_identity, &canonical)? {
        // Tip records this revision and is marked audited — the whole ancestry is
        // anchored, so this is a genuine no-op: no lock, no hash, no chain scan.
        TipDisposition::CurrentAndAudited(digest) => {
            report_already_current(&digest);
            return Ok(());
        }
        // Tip records this revision but is unmarked: reconcile (heal) without
        // re-hashing the rootfs.
        TipDisposition::CurrentButUnmarked => {
            return reconcile_over_signed_chain(
                &store,
                &build_identity,
                &canonical,
                &revision.flake_ref,
            );
        }
        // A genuinely new revision falls through to hash + record.
        TipDisposition::NewRevision => {}
    }

    // Genuinely new (or genesis): hash the installed artifacts now, using the
    // mtime+size sidecar cache so a later run of the same revision is cheap.
    let rev_dir = slot_revision_dir(slot_hash, &revision.revision_hash);
    let rootfs_path = Path::new(&rev_dir).join(&revision.artifact_paths.rootfs);
    let vmlinux_path = Path::new(&rev_dir).join(&revision.artifact_paths.vmlinux);
    let rootfs_sha256 = sha256_file_cached(&rootfs_path).with_context(|| {
        format!(
            "hashing {} for the image-lineage node",
            rootfs_path.display()
        )
    })?;
    let vmlinux_sha256 = sha256_file_cached(&vmlinux_path).with_context(|| {
        format!(
            "hashing {} for the image-lineage node",
            vmlinux_path.display()
        )
    })?;

    let inputs = flake_node_inputs(slot_hash, revision, rootfs_sha256.clone(), vmlinux_sha256);
    record_over_signed_chain(&store, &inputs, &revision.flake_ref, &rootfs_sha256)
}

/// How the current tip relates to the revision being recorded. Cheap: reads only
/// the stored node records (and their `audit_ref` markers), never hashing an
/// artifact and never scanning the signed chain — this is the guard the hot path
/// relies on to skip re-hashing an unchanged image. Propagates `head_for`'s fork
/// error, so an ambiguous tip surfaces before any work.
enum TipDisposition {
    /// The tip records this revision and carries its audit marker (so its whole
    /// ancestry is anchored). Carries the tip digest.
    CurrentAndAudited(CheckpointDigest),
    /// The tip records this revision but has no audit marker — reconcile it (heal
    /// an orphan, or backfill a pre-marker record) without re-hashing.
    CurrentButUnmarked,
    /// This revision is not the current tip — a new node must be created.
    NewRevision,
}

fn classify_tip(
    store: &ImageStore,
    build_identity: &ImageBuildIdentity,
    canonical: &ImageCanonicalId,
) -> Result<TipDisposition> {
    let head = store
        .head_for(build_identity)
        .context("resolving the current image-lineage tip for this build identity")?;
    Ok(match head {
        Some(tip) if &tip.image_identity.canonical == canonical => {
            if tip.audit_ref.is_some() {
                TipDisposition::CurrentAndAudited(tip.node_digest)
            } else {
                TipDisposition::CurrentButUnmarked
            }
        }
        _ => TipDisposition::NewRevision,
    })
}

/// Shared tail for a genuinely-new node: load the host signer, synthesize the
/// audit-envelope plan, and record the node under a per-identity advisory lock.
/// `image_name` / `image_sha256` bind the audit entry; `image_sha256` is the
/// rootfs digest for both callers.
///
/// The lock serializes the `head_for` → heal → save → emit critical section per
/// build identity, so two concurrent recorders of one identity (e.g. two
/// concurrent `machine run --flake` of one slot) cannot both read the same tip
/// and fork the chain. The signed-chain anchor is loaded lazily (and only inside
/// the lock), so a build whose ancestry is fully marked never pays the scan, and
/// `record_image_node`'s own reconcile guard is the backstop: a second writer
/// that finds the first's node as the tip reconciles (no-op or self-heal) rather
/// than forking.
fn record_over_signed_chain(
    store: &ImageStore,
    inputs: &ImageNodeInputs,
    image_name: &str,
    image_sha256: &str,
) -> Result<()> {
    let emitter = open_audit_emitter()?;
    // The plan binds the audit entry to the local tenant + the rootfs digest.
    let plan = build_event_plan(
        IMAGE_BUILD_WORKLOAD,
        IMAGE_BUILD_INTENT,
        image_name,
        image_sha256,
    )?;

    let outcome = with_identity_lock(store, &inputs.build_identity, || {
        let anchor = LazySignedChainAnchor::new();
        record_image_node(store, &emitter, &plan, inputs, now_unix(), &anchor)
    })?;
    report_outcome(&outcome);
    Ok(())
}

/// Shared tail for an already-recorded tip: reconcile its audit state under the
/// per-identity lock without re-hashing the rootfs. The tip is re-read under the
/// lock (it may have advanced since the caller's cheap pre-lock check); if it
/// still records `canonical` its ancestry is healed (any orphan's audit
/// completed, any pre-marker record backfilled), else there is nothing to do
/// here (a concurrent build advanced the chain past this revision).
fn reconcile_over_signed_chain(
    store: &ImageStore,
    build_identity: &ImageBuildIdentity,
    canonical: &ImageCanonicalId,
    image_name: &str,
) -> Result<()> {
    let emitter = open_audit_emitter()?;

    let outcome = with_identity_lock(store, build_identity, || {
        let anchor = LazySignedChainAnchor::new();
        let Some(tip) = store
            .head_for(build_identity)
            .context("resolving the current image-lineage tip for this build identity")?
            .filter(|tip| &tip.image_identity.canonical == canonical)
        else {
            return Ok(None);
        };
        // The plan is just the audit envelope; bind it to the stored rootfs digest.
        let image_sha256 = rootfs_digest(&tip.image_identity.artifacts)?.to_string();
        let plan = build_event_plan(
            IMAGE_BUILD_WORKLOAD,
            IMAGE_BUILD_INTENT,
            image_name,
            &image_sha256,
        )?;
        let healed = heal_unaudited_ancestry(store, &emitter, &plan, &anchor, &tip)?;
        Ok(Some(if healed {
            ImageNodeOutcome::Healed(tip.node_digest.clone())
        } else {
            ImageNodeOutcome::AlreadyCurrent(tip.node_digest.clone())
        }))
    })?;

    if let Some(outcome) = outcome {
        report_outcome(&outcome);
    }
    Ok(())
}

/// Open the host-signed audit emitter over the default audit dir.
fn open_audit_emitter() -> Result<AuditEmitter> {
    let signer =
        load_or_init().context("loading the host signer to audit the image-lineage node")?;
    AuditEmitter::new(signer.signing)
        .context("opening the signed audit chain for the image-lineage node")
}

/// Load the signed-chain anchor the verifier uses, to detect an orphaned tip.
fn load_signed_chain_anchor() -> Result<SignedChainAnchor> {
    SignedChainAnchor::load()
        .context("loading the signed audit chain to detect an orphaned image-lineage tip")
}

/// The rootfs digest an audit-envelope plan binds to: the first artifact's
/// sha256. Both node constructions put the rootfs first (flake: rootfs, kernel;
/// OCI: rootfs). Errors on an artifact-less node rather than fabricate a digest.
fn rootfs_digest(artifacts: &[ContentBlob]) -> Result<&str> {
    artifacts
        .first()
        .map(|blob| blob.sha256.as_str())
        .context("image-lineage node has no rootfs artifact to bind its audit envelope to")
}

fn report_outcome(outcome: &ImageNodeOutcome) {
    match outcome {
        ImageNodeOutcome::Created(digest) => {
            ui::info(&format!(
                "  Image lineage: recorded node {}",
                digest.as_str()
            ));
        }
        ImageNodeOutcome::Healed(digest) => {
            ui::info(&format!(
                "  Image lineage: completed audit for node {}",
                digest.as_str()
            ));
        }
        ImageNodeOutcome::AlreadyCurrent(digest) => report_already_current(digest),
    }
}

fn report_already_current(digest: &CheckpointDigest) {
    ui::info(&format!(
        "  Image lineage: already current ({})",
        digest.as_str()
    ));
}

/// Run `f` while holding the per-`build_identity` advisory lock, released when
/// the lock file drops. The lock lives beside the store it guards
/// (`<store-root>/.locks/<hash>.lock`); the `.locks` directory has no
/// `node.json`, so the store's node scan skips it.
fn with_identity_lock<T>(
    store: &ImageStore,
    build_identity: &ImageBuildIdentity,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let lock_path = identity_lock_path(store.root(), build_identity)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening image-lineage lock {}", lock_path.display()))?;
    flock_exclusive(&file)
        .with_context(|| format!("acquiring image-lineage lock {}", lock_path.display()))?;
    let result = f();
    // Hold the lock until after `f` returns; the kernel releases it on drop.
    drop(file);
    result
}

/// Lock-file path for a build identity, under `<store-root>/.locks/`. The name
/// is the SHA-256 of the identity's canonical JSON, so registry/repository
/// values that are not filename-safe still key a stable, collision-free file.
fn identity_lock_path(store_root: &Path, build_identity: &ImageBuildIdentity) -> Result<PathBuf> {
    let key = serde_json::to_vec(build_identity)
        .context("serializing build identity for its advisory-lock key")?;
    let name = hex::encode(Sha256::digest(&key));
    let dir = store_root.join(".locks");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating image-lineage lock dir {}", dir.display()))?;
    Ok(dir.join(format!("{name}.lock")))
}

/// Take an exclusive advisory lock on `file`, blocking until acquired. Released
/// when the file's descriptor is closed on drop.
fn flock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `file` owns the fd for the duration of the call; `LOCK_EX` blocks
    // until the advisory lock is granted, and the kernel releases it when the
    // descriptor is closed on drop.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The resolved identity of a freshly pulled OCI image, gathered at the pull
/// site. Grouped into one struct so the recorder takes a single argument rather
/// than a long positional list.
pub(in crate::commands) struct OciPullNode<'a> {
    /// Registry host the image was pulled from (the chain-key's first half).
    pub registry: &'a str,
    /// Repository path (the chain-key's second half).
    pub repository: &'a str,
    /// The manifest digest the reference resolved to (the canonical identity).
    pub resolved_digest: &'a str,
    /// The ordered layer digest set the manifest enumerated.
    pub layer_digests: Vec<String>,
    /// The fully-qualified reference, recorded as the audit entry's image name.
    pub canonical_reference: &'a str,
    /// The materialized rootfs whose bytes the node commits to.
    pub rootfs_path: &'a Path,
}

/// Assemble the node inputs for an OCI pull. The build identity is the
/// registry+repository (so successive pulls of one repo line up on a chain);
/// the canonical identity and provenance are the resolved manifest digest.
fn oci_node_inputs(
    registry: &str,
    repository: &str,
    resolved_digest: &str,
    layer_digests: Vec<String>,
    rootfs_sha256: String,
) -> ImageNodeInputs {
    ImageNodeInputs {
        build_identity: oci_build_identity(registry, repository),
        canonical: oci_canonical(resolved_digest),
        artifacts: vec![ContentBlob {
            name: "rootfs.ext4".to_string(),
            sha256: rootfs_sha256,
        }],
        provenance: ImageProvenance::Oci {
            resolved_digest: resolved_digest.to_string(),
            layer_digests,
        },
    }
}

/// Record an audited image-lineage node for a freshly pulled OCI image. Same
/// fail-closed posture as the flake path: an image that was pulled but could not
/// record its lineage is a failure to surface, not a silent skip. The
/// identical-digest fast path is checked before hashing the materialized rootfs.
pub(in crate::commands) fn record_oci_pull_node(node: &OciPullNode<'_>) -> Result<()> {
    let build_identity = oci_build_identity(node.registry, node.repository);
    let canonical = oci_canonical(node.resolved_digest);
    let store = ImageStore::open();

    match classify_tip(&store, &build_identity, &canonical)? {
        // Tip records this digest and is marked audited — a genuine no-op.
        TipDisposition::CurrentAndAudited(digest) => {
            report_already_current(&digest);
            return Ok(());
        }
        // Tip records this digest but is unmarked: reconcile (heal) without
        // re-hashing the materialized rootfs.
        TipDisposition::CurrentButUnmarked => {
            return reconcile_over_signed_chain(
                &store,
                &build_identity,
                &canonical,
                node.canonical_reference,
            );
        }
        TipDisposition::NewRevision => {}
    }

    let rootfs_sha256 = sha256_file_cached(node.rootfs_path).with_context(|| {
        format!(
            "hashing {} for the image-lineage node",
            node.rootfs_path.display()
        )
    })?;
    let inputs = oci_node_inputs(
        node.registry,
        node.repository,
        node.resolved_digest,
        node.layer_digests.clone(),
        rootfs_sha256.clone(),
    );
    record_over_signed_chain(&store, &inputs, node.canonical_reference, &rootfs_sha256)
}

/// Current wall-clock seconds since the Unix epoch, saturating at 0 for a clock
/// set before the epoch (never in practice). Stamped on the node's
/// `created_unix`, which is part of its content-address.
fn now_unix() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_core::manifest::{MANIFEST_SCHEMA_VERSION, Provenance};
    use mvm_core::pool::ArtifactPaths;
    use mvm_core::util::test_env::TestEnv;
    use mvm_hostd::supervisor::verify_audit_chain;
    use mvm_runtime::image_lineage::verify_image_lineage;
    use rand::Rng;

    /// A test anchor that agrees with every node's recomputed digest — models a
    /// signed chain that recorded every node's creation, isolating the store-side
    /// lineage walk from the real signed-chain reader (the MVM_HOME integration
    /// tests exercise that).
    struct AgreeingAnchor;
    impl ImageChainAnchor for AgreeingAnchor {
        fn recorded_creation_digest(&self, n: &ImageNode) -> Result<Option<CheckpointDigest>> {
            Ok(Some(n.compute_node_digest()))
        }
    }

    /// A test anchor that recorded *no* node — models a signed chain missing an
    /// `image.created` entry (a crash-orphaned node), so the reconcile path
    /// self-heals.
    struct UnauditedAnchor;
    impl ImageChainAnchor for UnauditedAnchor {
        fn recorded_creation_digest(&self, _n: &ImageNode) -> Result<Option<CheckpointDigest>> {
            Ok(None)
        }
    }

    /// A test anchor that recognizes exactly the node digests it was given —
    /// models a signed chain that recorded precisely those creations, so lineage
    /// verification fails closed on any node whose heal was missed.
    struct RecognizingAnchor(std::collections::HashSet<CheckpointDigest>);
    impl RecognizingAnchor {
        fn of(digests: &[&CheckpointDigest]) -> Self {
            Self(digests.iter().map(|d| (*d).clone()).collect())
        }
    }
    impl ImageChainAnchor for RecognizingAnchor {
        fn recorded_creation_digest(&self, n: &ImageNode) -> Result<Option<CheckpointDigest>> {
            Ok(self
                .0
                .contains(&n.node_digest)
                .then(|| n.node_digest.clone()))
        }
    }

    /// An emitter whose `image.created` always fails — exercises the
    /// save-then-emit rollback without a real audit chain.
    struct FailingEmitter;
    impl ImageCreatedEmitter for FailingEmitter {
        fn emit_image_created(&self, _plan: &ExecutionPlan, _node: &ImageNode) -> Result<()> {
            anyhow::bail!("injected audit-emit failure")
        }
    }

    /// Build an [`ImageNode`] from node inputs at a fixed timestamp, as the
    /// recorder would — for seeding crash-orphan fixtures directly into the store.
    fn node_for(inputs: &ImageNodeInputs, created_unix: u64) -> ImageNode {
        ImageNode::builder(
            inputs.build_identity.clone(),
            ImageIdentity {
                canonical: inputs.canonical.clone(),
                artifacts: inputs.artifacts.clone(),
            },
            inputs.provenance.clone(),
        )
        .created_unix(created_unix)
        .build()
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn fixture_plan() -> ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-image-build")
            .build()
    }

    fn blob(name: &str, sha: &str) -> ContentBlob {
        ContentBlob {
            name: name.into(),
            sha256: sha.into(),
        }
    }

    fn flake_inputs(revision: &str, provenance_ref: &str) -> ImageNodeInputs {
        ImageNodeInputs {
            build_identity: ImageBuildIdentity::Flake {
                slot_hash: "slot-a".into(),
            },
            canonical: ImageCanonicalId::Flake {
                revision_hash: revision.into(),
            },
            artifacts: vec![blob("rootfs.ext4", revision), blob("vmlinux", "kern")],
            provenance: ImageProvenance::Build {
                input_ref: provenance_ref.into(),
                lock_digest: Some("sha256:lock".into()),
            },
        }
    }

    /// `(store, emitter, verifying_key)` over two tempdirs, so a test can assert
    /// both store state and chain-signed validity without touching MVM_HOME.
    fn harness(store_dir: &Path, audit_dir: &Path) -> (ImageStore, AuditEmitter, VerifyingKey) {
        let (signing, verifying) = keypair();
        let store = ImageStore::at(store_dir);
        let emitter = AuditEmitter::with_dir(signing, audit_dir).unwrap();
        (store, emitter, verifying)
    }

    #[test]
    fn records_a_genesis_node_and_chain_signs_it() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();
        let inputs = flake_inputs("rev-1", ".#app");

        let outcome =
            record_image_node(&store, &emitter, &plan, &inputs, 100, &AgreeingAnchor).unwrap();
        let digest = match outcome {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };

        // The node is persisted, is genesis, and carries the inputs verbatim.
        let stored = store.by_digest(&digest).unwrap().expect("node persisted");
        assert!(stored.parent.is_none(), "genesis has no parent");
        assert_eq!(stored.build_identity, inputs.build_identity);
        assert_eq!(stored.image_identity.canonical, inputs.canonical);
        assert_eq!(stored.provenance, inputs.provenance);

        // Its creation is a single chain-signed audit entry that verifies clean.
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 1, "one image.created entry, chain-signed");
    }

    #[test]
    fn second_revision_chains_as_a_child_and_lineage_verifies() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();

        let genesis = record_image_node(
            &store,
            &emitter,
            &plan,
            &flake_inputs("rev-1", ".#app"),
            1,
            &AgreeingAnchor,
        )
        .unwrap();
        let child = record_image_node(
            &store,
            &emitter,
            &plan,
            &flake_inputs("rev-2", ".#app"),
            2,
            &AgreeingAnchor,
        )
        .unwrap();

        let (genesis_d, child_d) = match (&genesis, &child) {
            (ImageNodeOutcome::Created(g), ImageNodeOutcome::Created(c)) => (g.clone(), c.clone()),
            other => panic!("expected two Created outcomes, got {other:?}"),
        };

        // The child hash-links to the genesis; the tip is the child.
        let child_node = store.by_digest(&child_d).unwrap().unwrap();
        assert_eq!(child_node.parent.as_ref(), Some(&genesis_d));
        let identity = ImageBuildIdentity::Flake {
            slot_hash: "slot-a".into(),
        };
        assert_eq!(
            store.head_for(&identity).unwrap().unwrap().node_digest,
            child_d
        );

        // The full two-node version lineage verifies, and both creations are
        // chain-signed.
        verify_image_lineage(&store, &child_d, &AgreeingAnchor).unwrap();
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 2, "genesis + child, chain-signed");
    }

    #[test]
    fn identical_revision_rebuild_is_idempotent() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();
        let inputs = flake_inputs("rev-1", ".#app");

        let first =
            record_image_node(&store, &emitter, &plan, &inputs, 1, &AgreeingAnchor).unwrap();
        let first_d = match first {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };

        // Rebuilding the identical revision (already anchored, per AgreeingAnchor)
        // is a no-op: same digest, no fork, no new audit entry — even with a
        // different `created_unix`.
        let second =
            record_image_node(&store, &emitter, &plan, &inputs, 999, &AgreeingAnchor).unwrap();
        assert_eq!(
            second,
            ImageNodeOutcome::AlreadyCurrent(first_d.clone()),
            "identical revision must be AlreadyCurrent"
        );

        let identity = ImageBuildIdentity::Flake {
            slot_hash: "slot-a".into(),
        };
        // Still exactly one node for the identity and a single unambiguous tip.
        assert_eq!(store.list().unwrap().len(), 1, "no duplicate node created");
        assert_eq!(
            store.head_for(&identity).unwrap().unwrap().node_digest,
            first_d
        );
        // No second emit: the chain still carries exactly one entry.
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 1, "idempotent rebuild must not re-emit");
    }

    #[test]
    fn provenance_is_recorded_but_never_shapes_the_chain() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, _vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();

        // Genesis records provenance ".#app".
        let genesis_d = match record_image_node(
            &store,
            &emitter,
            &plan,
            &flake_inputs("rev-1", ".#app"),
            1,
            &AgreeingAnchor,
        )
        .unwrap()
        {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };

        // A rebuild of the SAME canonical revision but a DIFFERENT provenance
        // must still be idempotent — the create/idempotency decision keys on the
        // canonical revision only, never on provenance.
        let rebuilt = record_image_node(
            &store,
            &emitter,
            &plan,
            &flake_inputs("rev-1", ".#other"),
            2,
            &AgreeingAnchor,
        )
        .unwrap();
        assert_eq!(
            rebuilt,
            ImageNodeOutcome::AlreadyCurrent(genesis_d.clone()),
            "differing provenance must not create a second node"
        );

        // The stored node still records the ORIGINAL provenance verbatim.
        let stored = store.by_digest(&genesis_d).unwrap().unwrap();
        assert_eq!(
            stored.provenance,
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: Some("sha256:lock".into()),
            }
        );
    }

    #[test]
    fn an_ambiguous_forked_tip_surfaces_an_error() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, _vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();

        // Plant a genuine fork directly in the store: two sibling children of one
        // genesis, so the identity has two tips and no single head.
        let identity = ImageBuildIdentity::Flake {
            slot_hash: "slot-a".into(),
        };
        let g0 = ImageNode::builder(
            identity.clone(),
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: "rev-1".into(),
                },
                artifacts: vec![blob("rootfs.ext4", "rev-1")],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .created_unix(1)
        .build();
        store.save(&g0).unwrap();
        for rev in ["rev-2a", "rev-2b"] {
            let child = ImageNode::builder(
                identity.clone(),
                ImageIdentity {
                    canonical: ImageCanonicalId::Flake {
                        revision_hash: rev.into(),
                    },
                    artifacts: vec![blob("rootfs.ext4", rev)],
                },
                ImageProvenance::Build {
                    input_ref: ".#app".into(),
                    lock_digest: None,
                },
            )
            .parent(Some(g0.node_digest.clone()))
            .created_unix(2)
            .build();
            store.save(&child).unwrap();
        }

        // Recording a new build must refuse to guess a tip on the fork.
        let err = record_image_node(
            &store,
            &emitter,
            &plan,
            &flake_inputs("rev-3", ".#app"),
            3,
            &AgreeingAnchor,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("tip") || format!("{err:#}").contains("ambiguous"),
            "fork must surface, got: {err:#}"
        );
    }

    #[test]
    fn emit_failure_rolls_back_the_saved_node() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = ImageStore::at(store_dir.path());
        let plan = fixture_plan();
        let inputs = flake_inputs("rev-1", ".#app");

        // The node saves, then the emit fails. The error surfaces...
        let err = record_image_node(&store, &FailingEmitter, &plan, &inputs, 1, &AgreeingAnchor)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("image.created"),
            "the emit failure surfaces: {err:#}"
        );

        // ...and the just-saved node is rolled back, so the store keeps no
        // un-audited phantom and a retry starts from a clean genesis.
        assert!(
            store.list().unwrap().is_empty(),
            "the saved node must be rolled back when its audit emit fails"
        );
    }

    #[test]
    fn crash_orphaned_tip_self_heals_on_next_record() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();
        let inputs = flake_inputs("rev-1", ".#app");

        // Simulate a crash between save and emit: the node is in the store, but
        // no `image.created` anchors it in the chain.
        let orphan = ImageNode::builder(
            inputs.build_identity.clone(),
            ImageIdentity {
                canonical: inputs.canonical.clone(),
                artifacts: inputs.artifacts.clone(),
            },
            inputs.provenance.clone(),
        )
        .created_unix(7)
        .build();
        store.save(&orphan).unwrap();
        assert!(
            !audit_dir.path().join("local.jsonl").exists(),
            "the orphan starts un-audited"
        );

        // Recording the same revision detects the un-audited tip and re-emits,
        // rather than silently no-oping.
        let outcome =
            record_image_node(&store, &emitter, &plan, &inputs, 999, &UnauditedAnchor).unwrap();
        assert_eq!(
            outcome,
            ImageNodeOutcome::Healed(orphan.node_digest.clone()),
            "an orphaned tip must self-heal, not no-op"
        );

        // Exactly one node (no duplicate/fork) and now exactly one signed entry,
        // and the healed node verifies against a chain that records it.
        assert_eq!(store.list().unwrap().len(), 1, "no duplicate node");
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 1, "the orphan's audit was completed with one entry");
        verify_image_lineage(&store, &orphan.node_digest, &AgreeingAnchor).unwrap();

        // A further rebuild, now that the chain records it, is a plain no-op.
        let again =
            record_image_node(&store, &emitter, &plan, &inputs, 1000, &AgreeingAnchor).unwrap();
        assert_eq!(again, ImageNodeOutcome::AlreadyCurrent(orphan.node_digest));
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 1, "a healed tip is not re-emitted again");
    }

    /// The reviewer's regression: a DIFFERENT revision must heal a crash-orphaned
    /// ancestor before chaining onto it. Without the ancestry walk, `rev-2` would
    /// chain onto an un-audited `rev-1` and `verify_image_lineage(rev-2)` would
    /// fail closed forever.
    #[test]
    fn a_new_revision_heals_the_orphaned_ancestor_it_chains_onto() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();

        // Crash-orphan a genesis node for rev-1: saved, never emitted, unmarked.
        let orphan = node_for(&flake_inputs("rev-1", ".#app"), 1);
        store.save(&orphan).unwrap();

        // A different revision rev-2 records. The anchor recognizes only what was
        // emitted (nothing yet), so the orphaned ancestor must be healed first.
        let rev2 = flake_inputs("rev-2", ".#app");
        let outcome =
            record_image_node(&store, &emitter, &plan, &rev2, 2, &UnauditedAnchor).unwrap();
        let rev2_digest = match outcome {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };

        // rev-2 hash-links to the (now healed) rev-1.
        assert_eq!(
            store
                .by_digest(&rev2_digest)
                .unwrap()
                .unwrap()
                .parent
                .as_ref(),
            Some(&orphan.node_digest)
        );
        // The chain grew by exactly two — the healed ancestor + the new node —
        // with no duplicate emits, and the store holds exactly those two nodes.
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 2, "one ancestor heal + one create, no duplicates");
        assert_eq!(store.list().unwrap().len(), 2);
        // The full lineage now verifies against a chain that records every node.
        let recognized = RecognizingAnchor::of(&[&orphan.node_digest, &rev2_digest]);
        verify_image_lineage(&store, &rev2_digest, &recognized).unwrap();
    }

    /// The walk heals a *run* of orphaned ancestors from successive crashes, not
    /// just the immediate parent, and emits each exactly once.
    #[test]
    fn the_heal_walks_a_run_of_orphaned_ancestors() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();

        // Two stacked orphans: rev-1 (genesis) ← rev-2, both saved, none emitted.
        let g0 = node_for(&flake_inputs("rev-1", ".#app"), 1);
        let g1 = ImageNode::builder(
            g0.build_identity.clone(),
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: "rev-2".into(),
                },
                artifacts: vec![blob("rootfs.ext4", "rev-2")],
            },
            g0.provenance.clone(),
        )
        .parent(Some(g0.node_digest.clone()))
        .created_unix(2)
        .build();
        store.save(&g0).unwrap();
        store.save(&g1).unwrap();

        // A third revision chains on. Both orphaned ancestors must be healed.
        let rev3 = flake_inputs("rev-3", ".#app");
        let outcome =
            record_image_node(&store, &emitter, &plan, &rev3, 3, &UnauditedAnchor).unwrap();
        let rev3_digest = match outcome {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };

        // Three emits total (two heals + one create), no double-heal, three nodes.
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 3, "two ancestor heals + one create, each once");
        assert_eq!(store.list().unwrap().len(), 3);
        let recognized = RecognizingAnchor::of(&[&g0.node_digest, &g1.node_digest, &rev3_digest]);
        verify_image_lineage(&store, &rev3_digest, &recognized).unwrap();
    }

    /// An audited-but-unmarked node (as a pre-marker record would be) is confirmed
    /// against the signed chain and its marker backfilled — never re-emitted.
    #[test]
    fn an_audited_but_unmarked_tip_is_backfilled_not_re_emitted() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();
        let inputs = flake_inputs("rev-1", ".#app");

        // A node that was emitted but carries no audit marker on disk.
        let node = node_for(&inputs, 5);
        store.save(&node).unwrap();
        emitter.emit_image_created(&plan, &node).unwrap();
        assert!(node.audit_ref.is_none(), "seeded record has no marker");

        // Recording the same revision: the anchor confirms it is audited, so the
        // marker is backfilled with no second emit — a no-op, not a heal.
        let outcome =
            record_image_node(&store, &emitter, &plan, &inputs, 99, &AgreeingAnchor).unwrap();
        assert_eq!(
            outcome,
            ImageNodeOutcome::AlreadyCurrent(node.node_digest.clone()),
            "an already-audited tip is a no-op, not a heal"
        );
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(count, 1, "confirmed-audited node must not be re-emitted");
        assert!(
            store
                .by_digest(&node.node_digest)
                .unwrap()
                .unwrap()
                .audit_ref
                .is_some(),
            "the marker was backfilled"
        );
    }

    /// A fabricated ancestry cycle (only reachable by tampering — a real
    /// content-address cannot point at its own descendant) must fail closed
    /// rather than loop the heal or re-emit duplicates.
    #[test]
    fn heal_refuses_a_fabricated_ancestry_cycle() {
        let store_dir = tempfile::tempdir().unwrap();
        let audit_dir = tempfile::tempdir().unwrap();
        let (store, emitter, vk) = harness(store_dir.path(), audit_dir.path());
        let plan = fixture_plan();

        // A (genesis) and B (child of A), both unmarked.
        let a = node_for(&flake_inputs("rev-a", ".#app"), 1);
        store.save(&a).unwrap();
        let b = ImageNode::builder(
            a.build_identity.clone(),
            ImageIdentity {
                canonical: ImageCanonicalId::Flake {
                    revision_hash: "rev-b".into(),
                },
                artifacts: vec![blob("rootfs.ext4", "rev-b")],
            },
            a.provenance.clone(),
        )
        .parent(Some(a.node_digest.clone()))
        .created_unix(2)
        .build();
        store.save(&b).unwrap();

        // Rewrite A to point back at B, keeping A's digest (its directory name) so
        // the store's self-consistency check still admits it — an A↔B cycle.
        let cyclic_a = ImageNode {
            parent: Some(b.node_digest.clone()),
            ..a.clone()
        };
        std::fs::write(
            store.dir_for(&a.node_digest).join("node.json"),
            serde_json::to_vec_pretty(&cyclic_a).unwrap(),
        )
        .unwrap();

        // Healing from B walks B → A → B and must refuse the revisit.
        let err =
            heal_unaudited_ancestry(&store, &emitter, &plan, &UnauditedAnchor, &b).unwrap_err();
        assert!(
            format!("{err:#}").contains("cycle"),
            "a cycle must surface, got: {err:#}"
        );
        // Each node was emitted at most once before the bail — no duplicates.
        let count = verify_audit_chain(&audit_dir.path().join("local.jsonl"), &vk).unwrap();
        assert_eq!(
            count, 2,
            "B and A emitted once each, then the revisit bailed"
        );
    }

    #[test]
    fn flake_node_inputs_maps_slot_revision_and_artifacts() {
        let revision = TemplateRevision {
            schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
            revision_hash: "rev-xyz".into(),
            flake_ref: ".#worker".into(),
            flake_lock_hash: "lock-abc".into(),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".into(),
                rootfs: "rootfs.ext4".into(),
                fc_base_config: "fc-base.json".into(),
                initrd: None,
                sizes: None,
            },
            built_at: "2026-01-01T00:00:00Z".into(),
            profile: "worker".into(),
            vcpus: 2,
            mem_mib: 512,
            data_disk_mib: 0,
            snapshot: None,
            build_mode: Some("dev".into()),
        };
        let inputs = flake_node_inputs("slot-42", &revision, "rootsha".into(), "kernsha".into());

        assert_eq!(
            inputs.build_identity,
            ImageBuildIdentity::Flake {
                slot_hash: "slot-42".into()
            }
        );
        assert_eq!(
            inputs.canonical,
            ImageCanonicalId::Flake {
                revision_hash: "rev-xyz".into()
            }
        );
        assert_eq!(
            inputs.artifacts,
            vec![blob("rootfs.ext4", "rootsha"), blob("vmlinux", "kernsha")]
        );
        assert_eq!(
            inputs.provenance,
            ImageProvenance::Build {
                input_ref: ".#worker".into(),
                lock_digest: Some("lock-abc".into()),
            }
        );
    }

    #[test]
    fn oci_node_inputs_maps_registry_repository_and_layers() {
        let layers = vec![
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
        ];
        let digest = format!("sha256:{}", "d".repeat(64));
        let inputs = oci_node_inputs(
            "docker.io",
            "library/alpine",
            &digest,
            layers.clone(),
            "rootsha".into(),
        );

        assert_eq!(
            inputs.build_identity,
            ImageBuildIdentity::Oci {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
            }
        );
        assert_eq!(
            inputs.canonical,
            ImageCanonicalId::Oci {
                resolved_digest: digest.clone()
            }
        );
        assert_eq!(inputs.artifacts, vec![blob("rootfs.ext4", "rootsha")]);
        assert_eq!(
            inputs.provenance,
            ImageProvenance::Oci {
                resolved_digest: digest,
                layer_digests: layers,
            }
        );
    }

    #[test]
    fn build_event_plan_binds_local_tenant_and_rootfs_digest() {
        let sha = "a".repeat(64);
        let plan =
            build_event_plan(IMAGE_BUILD_WORKLOAD, IMAGE_BUILD_INTENT, ".#app", &sha).unwrap();
        assert_eq!(plan.tenant.0, "local");
        assert_eq!(plan.image.name, ".#app");
        assert_eq!(plan.image.sha256, sha);
        assert!(!plan.plan_id.0.is_empty(), "plan carries a content-address");
    }

    // ── recorder glue (MVM_HOME end-to-end) ──────────────────────────────────

    fn persisted_manifest(slot_hash: &str) -> PersistedManifest {
        PersistedManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            manifest_path: "/tmp/does-not-exist/mvm.toml".into(),
            manifest_hash: slot_hash.into(),
            flake_ref: ".#app".into(),
            profile: "minimal".into(),
            vcpus: 2,
            mem_mib: 512,
            mem_initial_mib: None,
            data_disk_mib: 0,
            name: None,
            backend: "mock".into(),
            provenance: Provenance::current(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn template_revision(revision_hash: &str) -> TemplateRevision {
        TemplateRevision {
            schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
            revision_hash: revision_hash.into(),
            flake_ref: ".#app".into(),
            flake_lock_hash: "lock-hash".into(),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".into(),
                rootfs: "rootfs.ext4".into(),
                fc_base_config: "fc-base.json".into(),
                initrd: None,
                sizes: None,
            },
            built_at: "2026-01-01T00:00:00Z".into(),
            profile: "minimal".into(),
            vcpus: 2,
            mem_mib: 512,
            data_disk_mib: 0,
            snapshot: None,
            build_mode: Some("dev".into()),
        }
    }

    /// Write fake rootfs + kernel artifacts into the slot's revision dir, as a
    /// real build would, so the recorder has files to hash.
    fn seed_slot_artifacts(slot_hash: &str, revision_hash: &str) {
        let rev_dir = slot_revision_dir(slot_hash, revision_hash);
        std::fs::create_dir_all(&rev_dir).unwrap();
        std::fs::write(Path::new(&rev_dir).join("rootfs.ext4"), b"rootfs-bytes").unwrap();
        std::fs::write(Path::new(&rev_dir).join("vmlinux"), b"kernel-bytes").unwrap();
    }

    fn local_audit_chain_len(home: &Path) -> usize {
        let vk = load_or_init().unwrap().verifying;
        let audit = home.join("audit").join("local.jsonl");
        verify_audit_chain(&audit, &vk).unwrap()
    }

    #[test]
    fn record_flake_build_node_creates_and_audits_a_node() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let slot_hash = "slot-under-test";
        let revision_hash = "rev-flake-1";
        seed_slot_artifacts(slot_hash, revision_hash);

        record_flake_build_node(
            &persisted_manifest(slot_hash),
            &template_revision(revision_hash),
        )
        .unwrap();

        // A genesis node is persisted under the slot identity, committing to both
        // the rootfs and the kernel.
        let store = ImageStore::open();
        let node = store
            .head_for(&flake_build_identity(slot_hash))
            .unwrap()
            .expect("node recorded");
        assert_eq!(
            node.image_identity.canonical,
            flake_canonical(revision_hash)
        );
        assert!(node.parent.is_none(), "first build is genesis");
        assert_eq!(node.image_identity.artifacts.len(), 2);

        // Its image.created entry is chain-signed and verifies.
        assert_eq!(local_audit_chain_len(tmp.path()), 1);
    }

    #[test]
    fn record_flake_build_node_identical_rebuild_skips_hashing() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let slot_hash = "slot-hot";
        let revision_hash = "rev-hot-1";
        seed_slot_artifacts(slot_hash, revision_hash);
        let persisted = persisted_manifest(slot_hash);
        let revision = template_revision(revision_hash);

        record_flake_build_node(&persisted, &revision).unwrap();

        // Delete the artifacts: a rerun that tried to hash them would fail. The
        // fast path must return AlreadyCurrent WITHOUT touching rootfs/kernel.
        let rev_dir = slot_revision_dir(slot_hash, revision_hash);
        std::fs::remove_file(Path::new(&rev_dir).join("rootfs.ext4")).unwrap();
        std::fs::remove_file(Path::new(&rev_dir).join("vmlinux")).unwrap();

        record_flake_build_node(&persisted, &revision)
            .expect("identical rebuild must not re-hash the now-absent artifacts");

        // Still exactly one node and one audit entry — no duplicate, no re-emit.
        assert_eq!(ImageStore::open().list().unwrap().len(), 1);
        assert_eq!(local_audit_chain_len(tmp.path()), 1);
    }

    #[test]
    fn record_flake_build_node_self_heals_a_crash_orphaned_tip() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let slot_hash = "slot-orphan";
        let revision_hash = "rev-orphan-1";
        seed_slot_artifacts(slot_hash, revision_hash);
        let persisted = persisted_manifest(slot_hash);
        let revision = template_revision(revision_hash);

        // Simulate a crash between save and emit: persist the node in the store
        // WITHOUT recording its `image.created`. The store holds an un-audited
        // orphan; no audit chain exists yet.
        let store = ImageStore::open();
        let rev_dir = slot_revision_dir(slot_hash, revision_hash);
        let rootfs_sha = sha256_file_cached(&Path::new(&rev_dir).join("rootfs.ext4")).unwrap();
        let vmlinux_sha = sha256_file_cached(&Path::new(&rev_dir).join("vmlinux")).unwrap();
        let inputs = flake_node_inputs(slot_hash, &revision, rootfs_sha, vmlinux_sha);
        let orphan = ImageNode::builder(
            inputs.build_identity.clone(),
            ImageIdentity {
                canonical: inputs.canonical.clone(),
                artifacts: inputs.artifacts.clone(),
            },
            inputs.provenance.clone(),
        )
        .created_unix(42)
        .build();
        store.save(&orphan).unwrap();
        assert!(
            !tmp.path().join("audit").join("local.jsonl").exists(),
            "the orphan starts un-audited"
        );

        // A rebuild of the SAME revision detects the un-audited tip and completes
        // its audit — without re-hashing (delete the artifacts to prove it).
        std::fs::remove_file(Path::new(&rev_dir).join("rootfs.ext4")).unwrap();
        std::fs::remove_file(Path::new(&rev_dir).join("vmlinux")).unwrap();
        record_flake_build_node(&persisted, &revision)
            .expect("self-heal must not re-hash the now-absent artifacts");

        // The orphan is now audited: one signed entry, still exactly one node, and
        // the node verifies against the real signed chain.
        assert_eq!(
            ImageStore::open().list().unwrap().len(),
            1,
            "no duplicate node"
        );
        assert_eq!(local_audit_chain_len(tmp.path()), 1, "orphan self-healed");
        let anchor = SignedChainAnchor::load().unwrap();
        verify_image_lineage(&store, &orphan.node_digest, &anchor).unwrap();
    }

    /// End-to-end regression against the real signed chain: a build of a DIFFERENT
    /// revision must heal a crash-orphaned ancestor before chaining onto it, so
    /// the new tip verifies. This is the reviewer's exact case, through the real
    /// flake entry point and the production `SignedChainAnchor`.
    #[test]
    fn record_flake_build_node_heals_an_orphaned_ancestor_across_revisions() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let slot_hash = "slot-cross";
        let store = ImageStore::open();

        // Crash-orphan a genesis node for rev-1: saved, never emitted, unmarked.
        let orphan = ImageNode::builder(
            flake_build_identity(slot_hash),
            ImageIdentity {
                canonical: flake_canonical("rev-1"),
                artifacts: vec![blob("rootfs.ext4", &"a".repeat(64))],
            },
            ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        )
        .created_unix(1)
        .build();
        store.save(&orphan).unwrap();
        assert!(!tmp.path().join("audit").join("local.jsonl").exists());

        // A different revision rev-2 builds and records. It must heal rev-1 first.
        let revision_hash = "rev-2";
        seed_slot_artifacts(slot_hash, revision_hash);
        record_flake_build_node(
            &persisted_manifest(slot_hash),
            &template_revision(revision_hash),
        )
        .unwrap();

        // rev-2 chained onto the (now healed) rev-1; the chain grew by exactly two
        // (heal + create); the whole lineage verifies against the real chain.
        let tip = store
            .head_for(&flake_build_identity(slot_hash))
            .unwrap()
            .expect("rev-2 recorded");
        assert_eq!(tip.parent.as_ref(), Some(&orphan.node_digest));
        assert_eq!(
            local_audit_chain_len(tmp.path()),
            2,
            "heal + create, no dupes"
        );
        assert_eq!(store.list().unwrap().len(), 2);
        let anchor = SignedChainAnchor::load().unwrap();
        verify_image_lineage(&store, &tip.node_digest, &anchor).unwrap();
    }

    /// The re-review's regression: a genuine orphan hidden *beneath* an
    /// emitted-but-unmarked ancestor. The heal must not stop at the unmarked
    /// ancestor (it was written by a flow that did not heal its own ancestry) —
    /// it must walk through to the deeper orphan. Exercised against the real
    /// signed chain: back it out and `verify_image_lineage(rev-3)` fails forever.
    #[test]
    fn record_image_node_heals_a_deep_orphan_beneath_an_unmarked_ancestor() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let slot_hash = "slot-deep";
        let store = ImageStore::open();
        let emitter = AuditEmitter::new(load_or_init().unwrap().signing).unwrap();
        let plan = fixture_plan();

        let node = |rev: &str, sha_seed: &str, parent: Option<CheckpointDigest>, ts: u64| {
            ImageNode::builder(
                flake_build_identity(slot_hash),
                ImageIdentity {
                    canonical: flake_canonical(rev),
                    artifacts: vec![blob("rootfs.ext4", &sha_seed.repeat(64))],
                },
                ImageProvenance::Build {
                    input_ref: ".#app".into(),
                    lock_digest: None,
                },
            )
            .parent(parent)
            .created_unix(ts)
            .build()
        };

        // rev-1: a genuine orphan (saved, never emitted, unmarked) — genesis.
        let rev1 = node("rev-1", "a", None, 1);
        store.save(&rev1).unwrap();
        // rev-2: emitted (raw) but never marked — the pre-marker / crash-after-emit
        // flow — child of rev-1.
        let rev2 = node("rev-2", "b", Some(rev1.node_digest.clone()), 2);
        store.save(&rev2).unwrap();
        emitter.emit_image_created(&plan, &rev2).unwrap();
        assert_eq!(
            local_audit_chain_len(tmp.path()),
            1,
            "only rev-2 is emitted pre-build"
        );

        // Build rev-3. The walk must backfill rev-2 (no re-emit) AND heal rev-1
        // beneath it, or the new tip fails lineage verification forever.
        let rev3 = ImageNodeInputs {
            build_identity: flake_build_identity(slot_hash),
            canonical: flake_canonical("rev-3"),
            artifacts: vec![blob("rootfs.ext4", &"c".repeat(64))],
            provenance: ImageProvenance::Build {
                input_ref: ".#app".into(),
                lock_digest: None,
            },
        };
        let outcome = record_image_node(
            &store,
            &emitter,
            &plan,
            &rev3,
            3,
            &SignedChainAnchor::load().unwrap(),
        )
        .unwrap();
        let rev3_digest = match outcome {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };

        // rev-1 healed + rev-3 created; rev-2 backfilled, NOT re-emitted → exactly
        // three entries, three nodes, and the whole lineage verifies.
        assert_eq!(
            local_audit_chain_len(tmp.path()),
            3,
            "rev-1 healed + rev-3 created; rev-2 not re-emitted"
        );
        assert_eq!(store.list().unwrap().len(), 3);
        assert_eq!(
            store
                .by_digest(&rev3_digest)
                .unwrap()
                .unwrap()
                .parent
                .as_ref(),
            Some(&rev2.node_digest)
        );
        let anchor = SignedChainAnchor::load().unwrap();
        verify_image_lineage(&store, &rev3_digest, &anchor).unwrap();
    }

    #[test]
    fn record_oci_pull_node_creates_and_audits_a_node() {
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let rootfs = tmp.path().join("oci-rootfs.ext4");
        std::fs::write(&rootfs, b"oci-rootfs-bytes").unwrap();
        let digest = format!("sha256:{}", "c".repeat(64));

        record_oci_pull_node(&OciPullNode {
            registry: "docker.io",
            repository: "library/alpine",
            resolved_digest: &digest,
            layer_digests: vec![format!("sha256:{}", "e".repeat(64))],
            canonical_reference: "docker.io/library/alpine@sha256:pinned",
            rootfs_path: &rootfs,
        })
        .unwrap();

        let store = ImageStore::open();
        let node = store
            .head_for(&oci_build_identity("docker.io", "library/alpine"))
            .unwrap()
            .expect("node recorded");
        assert_eq!(node.image_identity.canonical, oci_canonical(&digest));
        assert_eq!(local_audit_chain_len(tmp.path()), 1);
    }
}
