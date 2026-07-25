//! Records an audited image-lineage node after a successful flake build.
//!
//! A build produces a compiled microVM image; this module content-addresses
//! that image into an [`ImageNode`], hash-links it onto the prior build of the
//! same slot identity, and binds its creation into the host-signed audit chain
//! *before* the build reports success. The store never holds a node the audit
//! chain cannot anchor.
//!
//! # Lineage is PROVENANCE, not AUTHORIZATION
//!
//! Nothing here (or downstream) consults a node to grant a build, an admission,
//! or a boot any trust. The recorded chain proves only *where a build came
//! from*; boot integrity stays with dm-verity and admission with the signed
//! bundle. The chain-shaping decision (genesis / child / idempotent no-op) keys
//! strictly on the build identity and the image's canonical revision — the
//! recorded provenance is never an input to it.

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
use mvm_runtime::image_lineage::ImageStore;

use crate::ui;

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
    /// A new node was created, audited, and persisted; carries its digest.
    Created(CheckpointDigest),
    /// The slot's current tip already records this exact revision, so no new
    /// node was created — an identical-revision rebuild is a no-op.
    AlreadyCurrent(CheckpointDigest),
}

/// Create, audit, and persist an image-lineage node for a freshly built image.
///
/// Resolves the slot's current chain tip and either chains the new build as its
/// child, opens a genesis node when the slot has no prior build, or treats an
/// identical-revision rebuild as a no-op. A genuinely ambiguous (forked) tip
/// surfaces as an error rather than a silent guess — the store's `head_for`
/// fails closed on a fork and that error is propagated.
///
/// Creation is chain-signed into the audit log *before* the node is persisted:
/// an audit failure aborts with no unaudited node left behind, so a node in the
/// store is always backed by a signature the verifier can anchor.
pub(in crate::commands) fn record_image_node(
    store: &ImageStore,
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    inputs: &ImageNodeInputs,
    created_unix: u64,
) -> Result<ImageNodeOutcome> {
    let head = store
        .head_for(&inputs.build_identity)
        .context("resolving the current image-lineage tip for this build identity")?;

    let parent = match &head {
        // The current tip already records this exact revision. Rebuilding it is
        // a no-op: we do not fork a second tip for one identity, and we do not
        // re-emit. Provenance is deliberately not compared — it is recorded,
        // never a chain-shaping input.
        Some(tip) if tip.image_identity.canonical == inputs.canonical => {
            return Ok(ImageNodeOutcome::AlreadyCurrent(tip.node_digest.clone()));
        }
        Some(tip) => Some(tip.node_digest.clone()),
        None => None,
    };

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

    // Chain-sign the creation before persisting: the store must never hold a
    // node the signed chain cannot anchor.
    emitter
        .emit_image_created(plan, &node)
        .context("recording image.created in the signed audit chain")?;
    store
        .save(&node)
        .context("persisting the image-lineage node")?;

    Ok(ImageNodeOutcome::Created(node.node_digest))
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
        exec_timeout_secs: 0,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        audit_labels: Default::default(),
        agent_verbs: None,
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

    if let Some(digest) = tip_already_records(&store, &build_identity, &canonical)? {
        report_already_current(&digest);
        return Ok(());
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

/// The current tip's digest if it already records `canonical` for
/// `build_identity` (an identical-revision rebuild), else `None`. Cheap: reads
/// only the stored node records, never hashing an artifact — this is the guard
/// the hot path relies on to skip re-hashing an unchanged image. Propagates
/// `head_for`'s fork error, so an ambiguous tip surfaces before any work.
fn tip_already_records(
    store: &ImageStore,
    build_identity: &ImageBuildIdentity,
    canonical: &ImageCanonicalId,
) -> Result<Option<CheckpointDigest>> {
    let head = store
        .head_for(build_identity)
        .context("resolving the current image-lineage tip for this build identity")?;
    Ok(head
        .filter(|tip| &tip.image_identity.canonical == canonical)
        .map(|tip| tip.node_digest.clone()))
}

/// Shared tail of the flake and OCI recorders: load the host signer, synthesize
/// the audit-envelope plan, and record the node under a per-identity advisory
/// lock. `image_name` / `image_sha256` bind the audit entry; `image_sha256` is
/// the rootfs digest for both callers.
///
/// The lock serializes the `head_for` → emit → save critical section per build
/// identity, so two concurrent recorders of one identity (e.g. two concurrent
/// `machine run --flake` of one slot) cannot both read the same tip and fork the
/// chain. `record_image_node`'s own `AlreadyCurrent` guard is the backstop: the
/// second writer sees the first's node as the tip and no-ops rather than forks.
fn record_over_signed_chain(
    store: &ImageStore,
    inputs: &ImageNodeInputs,
    image_name: &str,
    image_sha256: &str,
) -> Result<()> {
    let signer =
        load_or_init().context("loading the host signer to audit the image-lineage node")?;
    let emitter = AuditEmitter::new(signer.signing)
        .context("opening the signed audit chain for the image-lineage node")?;
    // The plan binds the audit entry to the local tenant + the rootfs digest.
    let plan = build_event_plan(
        IMAGE_BUILD_WORKLOAD,
        IMAGE_BUILD_INTENT,
        image_name,
        image_sha256,
    )?;

    let outcome = with_identity_lock(store, &inputs.build_identity, || {
        record_image_node(store, &emitter, &plan, inputs, now_unix())
    })?;

    match outcome {
        ImageNodeOutcome::Created(digest) => {
            ui::info(&format!(
                "  Image lineage: recorded node {}",
                digest.as_str()
            ));
        }
        ImageNodeOutcome::AlreadyCurrent(digest) => report_already_current(&digest),
    }
    Ok(())
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

    if let Some(digest) = tip_already_records(&store, &build_identity, &canonical)? {
        report_already_current(&digest);
        return Ok(());
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
    use mvm_runtime::image_lineage::ImageChainAnchor;

    /// A test anchor that agrees with every node's recomputed digest — isolates
    /// the store-side lineage walk (parent links + digest recompute) from the
    /// signed-chain reader, which the MVM_HOME integration test exercises.
    struct AgreeingAnchor;
    impl ImageChainAnchor for AgreeingAnchor {
        fn recorded_creation_digest(&self, n: &ImageNode) -> Result<Option<CheckpointDigest>> {
            Ok(Some(n.compute_node_digest()))
        }
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
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

        let outcome = record_image_node(&store, &emitter, &plan, &inputs, 100).unwrap();
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

        let genesis =
            record_image_node(&store, &emitter, &plan, &flake_inputs("rev-1", ".#app"), 1).unwrap();
        let child =
            record_image_node(&store, &emitter, &plan, &flake_inputs("rev-2", ".#app"), 2).unwrap();

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
        mvm_runtime::image_lineage::verify_image_lineage(&store, &child_d, &AgreeingAnchor)
            .unwrap();
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

        let first = record_image_node(&store, &emitter, &plan, &inputs, 1).unwrap();
        let first_d = match first {
            ImageNodeOutcome::Created(d) => d,
            other => panic!("expected Created, got {other:?}"),
        };

        // Rebuilding the identical revision is a no-op: same digest, no fork, no
        // new audit entry — even with a different `created_unix`.
        let second = record_image_node(&store, &emitter, &plan, &inputs, 999).unwrap();
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
        let genesis_d =
            match record_image_node(&store, &emitter, &plan, &flake_inputs("rev-1", ".#app"), 1)
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
        let err = record_image_node(&store, &emitter, &plan, &flake_inputs("rev-3", ".#app"), 3)
            .unwrap_err();
        assert!(
            err.to_string().contains("tip") || format!("{err:#}").contains("ambiguous"),
            "fork must surface, got: {err:#}"
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
            role: String::new(),
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
            role: String::new(),
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
