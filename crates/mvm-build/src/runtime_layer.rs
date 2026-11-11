//! Stage a signed runtime pack's files without booting or invoking Nix.
//!
//! Layers are unpacked alone, not on top of the base. A later composer must
//! check path ownership and policy before incorporating this staged tree.

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use mvm_contract::pack_spec::PackTarget;
use mvm_contract::pack_spec_v2::{BuildMode, ComposablePackError, ComposablePackSpec};
use mvm_contract::pack_spec_v3::{ComposedGraph, GraphNode, SignedPackPin};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::base_compatibility::{
    DevelopmentBaseCompatibility, ProductionBaseCompatibility,
};
use mvm_core::image_set::{
    ArtifactFormat, ImageSetManifest, ImageTrustTier, LocalImageSetVerification,
    WorkloadImageProfile,
};
use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::application_component::VerifiedApplicationComponentInputs;
use mvm_core::registry_pack::component_layer::{ComponentLayerKind, VerifiedComponentLayerInputs};
use mvm_core::registry_pack::runtime_layer::{
    OfflineRuntimePolicyError, RuntimeLayerArchiveError, RuntimeLayerInputError,
    RuntimeLayerPolicyError, RuntimeLayerResolveError, VerifiedRuntimeLayerArchive,
    VerifiedRuntimeLayerInputs, VerifiedRuntimeLayerPolicies, require_offline_runtime_policies,
    require_offline_runtime_policy, resolve_requested_runtime_layers,
};
use mvm_core::registry_pack::{AuthenticatedRegistryManifest, PackPin};
use mvm_core::registry_pack_store::RegistryPackStoreError;
use mvm_fs::oci::unpack::{
    SetidPolicy, UnpackError, UnpackOptions, UnpackReport, XattrPolicy, unpack_layer,
};
use mvm_fs::ownership::OwnerTable;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_UNPACKED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ENTRIES: u64 = 200_000;
const MAX_LAYERS: usize = 64;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathKind {
    Directory,
    Leaf,
}

#[derive(Clone, Copy)]
enum TarRole {
    Base,
    Runtime,
    Application,
}

fn reserved_runtime_path(path: &Path) -> bool {
    ["etc/mvm", "mvm", "usr/lib/mvm", "dev", "proc", "sys", "run"]
        .iter()
        .any(|tree| path.starts_with(tree))
        || [
            "init",
            "etc/passwd",
            "etc/group",
            "etc/shadow",
            "etc/gshadow",
            "etc/hosts",
            "etc/resolv.conf",
            "sbin/mvm-setpriv",
        ]
        .iter()
        .any(|file| path == Path::new(file))
}

#[derive(Debug)]
struct TarInventory {
    paths: BTreeMap<PathBuf, PathKind>,
    directory_modes: BTreeMap<PathBuf, u32>,
    bytes: u64,
    entries: u64,
}

/// A private, complete layer tree with its ownership and path inventory.
#[derive(Debug)]
pub struct StagedRuntimeLayer {
    directory: tempfile::TempDir,
    report: UnpackReport,
}

impl StagedRuntimeLayer {
    /// Private directory containing only the unpacked layer's contents.
    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    /// Paths and original ownership the final composer must check and retain.
    pub fn report(&self) -> &UnpackReport {
        &self.report
    }
}

/// A private combined filesystem tree, not yet merged with a signed Linux base.
#[derive(Debug)]
pub struct ComposedRuntimeLayers {
    directory: tempfile::TempDir,
    ownership: OwnerTable,
    pins: Vec<PackPin>,
    claimed: BTreeMap<PathBuf, PathKind>,
    base_directory_modes: BTreeMap<PathBuf, u32>,
    remaining_bytes: u64,
    remaining_entries: u64,
}

/// A private base-plus-runtime tree tied to the signed image-set root.
#[derive(Debug)]
pub struct ComposedWorkloadRootfs {
    tree: ComposedRuntimeLayers,
    base_manifest_sha256: Sha256Hex,
    profile: WorkloadImageProfile,
    authored_spec_sha256: Option<Sha256Hex>,
    runtime_policies: Vec<VerifiedRuntimeLayerPolicies>,
}

/// Private base, runtimes and one application; still not an admitted VM.
#[derive(Debug)]
pub struct ComposedApplicationRootfs {
    tree: ComposedWorkloadRootfs,
    application_archive_sha256: Sha256Hex,
}

/// A private, authenticated ordered component tree; not a launch or export grant.
#[derive(Debug)]
pub struct ComposedComponentRootfs {
    tree: ComposedWorkloadRootfs,
    pins: Vec<PackPin>,
    tier: ImageTrustTier,
}

impl ComposedComponentRootfs {
    /// Trust tier of the selected base; a local base remains development-only.
    pub fn tier(&self) -> ImageTrustTier {
        self.tier
    }

    /// The staged tree, which remains private until separately sealed and admitted.
    pub fn root(&self) -> &Path {
        self.tree.root()
    }

    /// Original file owners to preserve during later image materialization.
    pub fn ownership(&self) -> &OwnerTable {
        self.tree.ownership()
    }

    /// Exact signed manifest pins in filesystem application order.
    pub fn pins(&self) -> &[PackPin] {
        &self.pins
    }
}

/// This lock has its own schema; it never changes the v1 Nix pack lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposableLockSchema {
    #[serde(rename = "mvm.composable-pack-lock/v1")]
    V1,
}

/// Pinned candidate inputs; a lock is not publisher trust or boot evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedComposableLock {
    schema: ComposableLockSchema,
    spec_sha256: Sha256Hex,
    source_tree_sha256: Sha256Hex,
    application_archive_sha256: Sha256Hex,
    base_manifest_sha256: Sha256Hex,
    runtime_pins: Vec<PackPin>,
    target: PackTarget,
    profile: WorkloadImageProfile,
    producer_revision: String,
    producer_version: String,
}

impl ResolvedComposableLock {
    /// Exact signed image-set root used to select the base filesystem.
    pub fn base_manifest_sha256(&self) -> &Sha256Hex {
        &self.base_manifest_sha256
    }

    /// Publisher-authenticated runtime manifests in composition order.
    pub fn runtime_pins(&self) -> &[PackPin] {
        &self.runtime_pins
    }

    /// Architecture selected by the authenticated source recipe.
    pub fn target(&self) -> PackTarget {
        self.target
    }

    /// Compare against freshly resolved inputs before a production build.
    ///
    /// # Errors
    ///
    /// Refuses any changed spec, source, base, runtime, archive or producer.
    pub fn verify_current(&self, current: &Self) -> Result<(), RuntimeLayerStageError> {
        if self != current {
            return Err(RuntimeLayerStageError::StaleLock);
        }
        Ok(())
    }

    /// Identity of filesystem bytes, excluding command and policy decisions.
    ///
    /// The base and runtime manifest pins bind their archive digests. The
    /// application archive digest binds every copied file. A new assembler
    /// revision changes the key even when its version number has not changed.
    pub fn filesystem_identity(&self) -> anyhow::Result<Sha256Hex> {
        let bytes = serde_json::to_vec(&(
            "mvm.composable-rootfs/v1",
            &self.base_manifest_sha256,
            &self.runtime_pins,
            &self.application_archive_sha256,
            self.target,
            self.profile,
            &self.producer_revision,
            &self.producer_version,
        ))?;
        Ok(Sha256Hex::from_bytes(&bytes))
    }
}

impl ComposedApplicationRootfs {
    /// The exact bytes of the application input consumed by the composer.
    pub fn application_archive_sha256(&self) -> &Sha256Hex {
        &self.application_archive_sha256
    }

    /// Signed policy documents retained with the runtime manifests.
    pub fn runtime_policies(&self) -> &[VerifiedRuntimeLayerPolicies] {
        &self.tree.runtime_policies
    }

    /// Guest tree with exactly one authored application copied under `/srv/app`.
    pub fn root(&self) -> &Path {
        self.tree.root()
    }

    /// Bind one authored spec to the selected input graph after composition.
    ///
    /// The caller must reverify the held source/archive and producer revision
    /// before and after materialization; this is not authority to sign or boot.
    ///
    /// # Errors
    ///
    /// Refuses non-authored trees, different specs and non-canonical revisions.
    pub fn resolved_lock(
        &self,
        spec: &ComposablePackSpec,
        source_tree_sha256: &Sha256Hex,
        producer_revision: &str,
    ) -> Result<ResolvedComposableLock, RuntimeLayerStageError> {
        spec.check_mode_request(BuildMode::Production)?;
        self.lock_for(spec, source_tree_sha256, producer_revision)
    }

    /// Bind a development build to the same immutable inputs without claiming
    /// production intent or a publisher signature.
    ///
    /// # Errors
    ///
    /// Refuses changed source, policy, layer or producer identities.
    pub fn development_lock(
        &self,
        spec: &ComposablePackSpec,
        source_tree_sha256: &Sha256Hex,
        producer_revision: &str,
    ) -> Result<ResolvedComposableLock, RuntimeLayerStageError> {
        spec.check_mode_request(BuildMode::Development)?;
        self.lock_for(spec, source_tree_sha256, producer_revision)
    }

    fn lock_for(
        &self,
        spec: &ComposablePackSpec,
        source_tree_sha256: &Sha256Hex,
        producer_revision: &str,
    ) -> Result<ResolvedComposableLock, RuntimeLayerStageError> {
        let spec_sha256 = Sha256Hex::from_bytes(&spec.canonical_json()?);
        if self.tree.authored_spec_sha256.as_ref() != Some(&spec_sha256)
            || producer_revision.len() != 40
            || !producer_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RuntimeLayerStageError::InconsistentLayers);
        }
        self.tree.reverify_runtime_policies()?;
        Ok(ResolvedComposableLock {
            schema: ComposableLockSchema::V1,
            spec_sha256,
            source_tree_sha256: source_tree_sha256.clone(),
            application_archive_sha256: self.application_archive_sha256.clone(),
            base_manifest_sha256: self.tree.base_manifest_sha256.clone(),
            runtime_pins: self.tree.runtime_pins().to_vec(),
            target: spec.target,
            profile: self.tree.profile,
            producer_revision: producer_revision.to_owned(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    /// Produce an ext4+verity candidate, not an archive or proof of health.
    ///
    /// # Errors
    ///
    /// Refuses a source tree that changed after staging or cannot be materialized.
    pub fn materialize_candidate(
        &self,
        output: &Path,
    ) -> Result<crate::rootfs::MaterializedExt4, RuntimeLayerStageError> {
        self.tree.materialize_candidate(output)
    }
}

impl ComposedWorkloadRootfs {
    fn reverify_runtime_policies(&self) -> Result<(), RuntimeLayerStageError> {
        if self.runtime_policies.len() != self.runtime_pins().len()
            || self
                .runtime_policies
                .iter()
                .zip(self.runtime_pins())
                .any(|(policy, pin)| {
                    policy.descriptor().reference() != pin.reference()
                        || policy.descriptor().manifest_sha256() != pin.manifest_sha256()
                })
        {
            return Err(RuntimeLayerStageError::InconsistentLayers);
        }
        for policy in &self.runtime_policies {
            require_offline_runtime_policies(policy)?;
        }
        Ok(())
    }

    /// Bytes ready for application composition, not yet a bootable image.
    pub fn root(&self) -> &Path {
        self.tree.root()
    }

    /// Original owners for deterministic image materialization.
    pub fn ownership(&self) -> &OwnerTable {
        self.tree.ownership()
    }

    /// Exact image-set root that authenticated the base composition source.
    pub fn base_manifest_sha256(&self) -> &Sha256Hex {
        &self.base_manifest_sha256
    }

    /// Runtime manifests whose bytes contributed to this tree.
    pub fn runtime_pins(&self) -> &[PackPin] {
        self.tree.pins()
    }

    /// Apply exactly one digest-bound application archive under `/srv/app`.
    ///
    /// Consumes the base tree, so an extraction error drops any partial result.
    /// A signed lock and exact health boot are still needed before export.
    ///
    /// # Errors
    ///
    /// Refuses changed bytes, forbidden paths, overlaps, special entries or
    /// unbounded payloads without producing a partially usable candidate.
    pub fn with_application_archive(
        mut self,
        archive_bytes: &[u8],
        expected: &Sha256Hex,
    ) -> Result<ComposedApplicationRootfs, RuntimeLayerStageError> {
        if archive_bytes.is_empty()
            || archive_bytes.len() > 2 * 1024 * 1024 * 1024
            || Sha256Hex::from_bytes(archive_bytes) != *expected
        {
            return Err(RuntimeLayerStageError::ApplicationDigest);
        }
        let mut tar = tempfile::tempfile()?;
        decompress_single_gzip(
            io::Cursor::new(archive_bytes),
            archive_bytes.len() as u64,
            &mut tar,
        )?;
        tar.seek(SeekFrom::Start(0))?;
        self.tree.apply_tar(&mut tar, TarRole::Application)?;
        Ok(ComposedApplicationRootfs {
            tree: self,
            application_archive_sha256: expected.clone(),
        })
    }

    /// Emit a verity-sealed candidate after restoring the signed base's directory modes.
    ///
    /// This does not attest a health boot or grant a workload entrypoint.
    ///
    /// # Errors
    ///
    /// Refuses missing or withdrawn runtime policy inputs, a changed tree or
    /// a directory that can no longer be restored.
    pub fn materialize_candidate(
        &self,
        output: &Path,
    ) -> Result<crate::rootfs::MaterializedExt4, RuntimeLayerStageError> {
        self.reverify_runtime_policies()?;
        self.tree.restore_base_directory_modes()?;
        let input = crate::rootfs::MaterializeExt4Input::new(
            self.root().to_path_buf(),
            output.to_path_buf(),
            0,
        )
        .with_owners(self.ownership().clone())
        .with_verity();
        let result = crate::rootfs::materialize_ext4_pure(&input)?;
        self.reverify_runtime_policies()?;
        Ok(result)
    }
}

impl ComposedRuntimeLayers {
    /// Private tree containing all selected runtime files.
    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    /// Original tar ownership to pass to the final rootfs materializer.
    pub fn ownership(&self) -> &OwnerTable {
        &self.ownership
    }

    /// Exact authenticated input pins in composition order.
    pub fn pins(&self) -> &[PackPin] {
        &self.pins
    }

    fn new(pins: Vec<PackPin>) -> io::Result<Self> {
        Ok(Self {
            directory: tempfile::tempdir()?,
            ownership: OwnerTable::new(),
            pins,
            claimed: BTreeMap::new(),
            base_directory_modes: BTreeMap::new(),
            remaining_bytes: MAX_UNPACKED_BYTES,
            remaining_entries: MAX_ENTRIES,
        })
    }

    fn add_tar<R: Read + Seek>(&mut self, reader: &mut R) -> Result<(), RuntimeLayerStageError> {
        self.apply_tar(reader, TarRole::Runtime)
    }

    fn add_base_tar<R: Read + Seek>(
        &mut self,
        reader: &mut R,
    ) -> Result<(), RuntimeLayerStageError> {
        self.apply_tar(reader, TarRole::Base)
    }

    fn apply_tar<R: Read + Seek>(
        &mut self,
        reader: &mut R,
        role: TarRole,
    ) -> Result<(), RuntimeLayerStageError> {
        let inventory = preflight(reader, role)?;
        if inventory.bytes > self.remaining_bytes || inventory.entries > self.remaining_entries {
            return Err(RuntimeLayerStageError::Unsupported(
                "combined runtime layers exceed their bound",
            ));
        }
        for (path, kind) in &inventory.paths {
            if let Some(previous) = self.claimed.get(path)
                && (*kind != PathKind::Directory || *previous != PathKind::Directory)
            {
                return Err(RuntimeLayerStageError::Collision(path.clone()));
            }
            if *kind == PathKind::Directory
                && let Some(mode) = inventory.directory_modes.get(path)
                && self.claimed.contains_key(path)
            {
                use std::os::unix::fs::PermissionsExt;
                let existing = std::fs::symlink_metadata(self.root().join(path))?;
                if !existing.is_dir() || existing.permissions().mode() & 0o7777 != *mode {
                    return Err(RuntimeLayerStageError::Collision(path.clone()));
                }
            }
        }
        let options = UnpackOptions::builder()
            .max_total_bytes(inventory.bytes)
            .max_entries(inventory.entries)
            .xattr_policy(XattrPolicy::DropAll)
            .setid_policy(SetidPolicy::RefuseUnsigned)
            .build();
        let report = unpack_layer(reader, self.directory.path(), &options, None)?;
        refuse_lossy_report(&report)?;
        let mut current_ownership = OwnerTable::new();
        current_ownership.absorb(&report.ownership);
        for (path, kind) in &inventory.paths {
            if *kind == PathKind::Directory && self.claimed.contains_key(path) {
                let guest_path = format!("/{}", path.display());
                if self.ownership.owner_of(&guest_path) != current_ownership.owner_of(&guest_path) {
                    return Err(RuntimeLayerStageError::Collision(path.clone()));
                }
            }
        }
        self.ownership.absorb(&report.ownership);
        if matches!(role, TarRole::Base) {
            self.base_directory_modes.extend(inventory.directory_modes);
        }
        self.claimed.extend(inventory.paths);
        self.remaining_bytes -= inventory.bytes;
        self.remaining_entries -= inventory.entries;
        Ok(())
    }

    fn restore_base_directory_modes(&self) -> Result<(), RuntimeLayerStageError> {
        use std::os::unix::fs::PermissionsExt;

        let mut directories: Vec<_> = self.base_directory_modes.iter().collect();
        directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        for (path, mode) in directories {
            let destination = self.root().join(path);
            if !std::fs::symlink_metadata(&destination)?.is_dir() {
                return Err(RuntimeLayerStageError::Collision(path.clone()));
            }
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(*mode))?;
        }
        Ok(())
    }
}

/// Why a runtime layer was refused before entering a bootable image.
#[derive(Debug, Error)]
pub enum RuntimeLayerStageError {
    #[error(transparent)]
    Archive(#[from] RuntimeLayerArchiveError),
    #[error(transparent)]
    Revocation(#[from] RegistryPackStoreError),
    #[error(transparent)]
    RuntimeInput(#[from] RuntimeLayerInputError),
    #[error(transparent)]
    Policy(#[from] RuntimeLayerPolicyError),
    #[error(transparent)]
    OfflinePolicy(#[from] OfflineRuntimePolicyError),
    #[error(transparent)]
    Unpack(#[from] UnpackError),
    #[error("runtime layer staging I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("runtime layer contains an unsupported tar entry: {0}")]
    Unsupported(&'static str),
    #[error("runtime layer overlaps another layer at {0}")]
    Collision(PathBuf),
    #[error("runtime layer order, architecture or dependency pin is inconsistent")]
    InconsistentLayers,
    #[error(transparent)]
    RequestedRuntime(#[from] RuntimeLayerResolveError),
    #[error(transparent)]
    AuthoredSpec(#[from] ComposablePackError),
    #[error(
        "host filesystem case-folds distinct guest paths; compose inside a case-sensitive Linux boundary"
    )]
    CaseFolding,
    #[error("base acquisition failed: {0}")]
    Base(#[from] anyhow::Error),
    #[error("signed base composition source has invalid contract or ownership")]
    BaseContract,
    #[error("application archive bytes do not match the resolved input digest")]
    ApplicationDigest,
    #[error("composable pack inputs differ from the frozen lock")]
    StaleLock,
    #[error("ordered component graph, signed inputs or selected base disagree")]
    ComponentGraph,
    #[error("component archive differs from its signed descriptor")]
    ComponentDigest,
    #[error("component base requirements are not satisfied: {0}")]
    ComponentBase(#[from] mvm_core::image_set::base_compatibility::BaseCompatibilityError),
    #[error("application component input failed: {0}")]
    ApplicationComponent(
        #[from] mvm_core::registry_pack::application_component::ApplicationComponentInputError,
    ),
    #[error("runtime/tool component input failed: {0}")]
    ComponentInput(#[from] mvm_core::registry_pack::component_layer::ComponentLayerInputError),
    #[error(transparent)]
    Materialize(#[from] crate::rootfs::RootfsError),
}

/// Select the base for an ordered component graph without upgrading local evidence.
pub enum ComponentGraphBase<'a> {
    /// A publisher-verified production image set and its signed compatibility.
    Production {
        images: &'a crate::published_image_set::PublishedImageSet,
        compatibility: &'a ProductionBaseCompatibility,
    },
    /// An unsigned local schema-3 set, with exact selected kernel and tar paths.
    Development {
        compatibility: &'a DevelopmentBaseCompatibility,
        evidence: &'a LocalImageSetVerification<'a>,
        manifest_bytes: &'a [u8],
        kernel: &'a Path,
        tar: &'a Path,
    },
}

/// Apply exact signed v3 components to a matching production or development base.
///
/// This does not select an entrypoint, resolve policy, seal an image or export
/// a bundle. The caller must supply separately verified base compatibility and
/// held component inputs. Local evidence remains development-only, and its
/// checkout identities must be freshly sampled for this call.
///
/// # Errors
///
/// Refuses missing/extra/drifted inputs, unsatisfied requirements, unordered
/// dependencies, revoked signatures, changed archives and path collisions.
pub fn compose_verified_component_graph(
    source: ComponentGraphBase<'_>,
    graph: &ComposedGraph,
    applications: &[VerifiedApplicationComponentInputs],
    components: &[VerifiedComponentLayerInputs],
) -> Result<ComposedComponentRootfs, RuntimeLayerStageError> {
    graph
        .validate()
        .map_err(|_| RuntimeLayerStageError::ComponentGraph)?;
    if graph.graph.len() > MAX_LAYERS || graph.graph.len() != applications.len() + components.len()
    {
        return Err(RuntimeLayerStageError::ComponentGraph);
    }
    let descriptor = match &source {
        ComponentGraphBase::Production { compatibility, .. } => compatibility.descriptor(),
        ComponentGraphBase::Development { compatibility, .. } => compatibility.descriptor(),
    };
    let arch = descriptor.arch();
    let mut base = match &source {
        ComponentGraphBase::Production { images, .. } => {
            if descriptor.image_set_manifest_sha256()
                != &Sha256Hex::from_bytes(images.manifest_bytes())
            {
                return Err(RuntimeLayerStageError::ComponentGraph);
            }
            compose_signed_workload_tree(images, arch, descriptor.profile(), &[])?
        }
        ComponentGraphBase::Development { .. } => compose_local_component_base(&source)?,
    };
    let mut pins = Vec::with_capacity(graph.graph.len());
    for node in &graph.graph {
        let requested = node.pin();
        let pin = graph_pin(requested)?;
        match node {
            GraphNode::Application { .. } => {
                let input = applications
                    .iter()
                    .find(|input| {
                        input.descriptor().manifest().reference == *pin.reference()
                            && Sha256Hex::from_bytes(input.descriptor().manifest_bytes())
                                == *pin.manifest_sha256()
                    })
                    .ok_or(RuntimeLayerStageError::ComponentGraph)?;
                let manifest = input.descriptor().manifest();
                if manifest.application_component.guest_arch != arch.to_string() {
                    return Err(RuntimeLayerStageError::ComponentGraph);
                }
                check_graph_requirements(
                    &source,
                    &manifest.application_component.requirements,
                    arch,
                )?;
                let archive = input.open_verified_archive()?;
                apply_component_archive(
                    &mut base.tree,
                    archive,
                    &manifest.application_component.archive.archive_sha256,
                    TarRole::Application,
                )?;
                input.reverify()?;
            }
            GraphNode::Runtime { .. } | GraphNode::Tool { .. } => {
                let input = components
                    .iter()
                    .find(|input| {
                        input.descriptor().manifest().reference() == pin.reference()
                            && input.descriptor().manifest_sha256() == pin.manifest_sha256()
                    })
                    .ok_or(RuntimeLayerStageError::ComponentGraph)?;
                let manifest = input.descriptor().manifest();
                let expected_kind = match node {
                    GraphNode::Runtime { .. } => ComponentLayerKind::Runtime,
                    GraphNode::Tool { .. } => ComponentLayerKind::Tool,
                    GraphNode::Application { .. } => unreachable!("matched component node"),
                };
                if manifest.kind() != expected_kind
                    || manifest.component().guest_arch != arch.to_string()
                    || !dependencies_before(&manifest.component().dependencies, &pins)
                {
                    return Err(RuntimeLayerStageError::ComponentGraph);
                }
                check_graph_requirements(&source, &manifest.component().requirements, arch)?;
                let archive = input.open_verified_archive()?;
                apply_component_archive(
                    &mut base.tree,
                    archive,
                    &manifest.component().archive.archive_sha256,
                    TarRole::Runtime,
                )?;
                input.reverify()?;
            }
        }
        pins.push(pin);
    }
    // A later signer must not infer trust merely from this staged tree.
    for input in applications {
        input.reverify()?;
    }
    for input in components {
        input.reverify()?;
    }
    let tier = match source {
        ComponentGraphBase::Production { images, .. } => {
            images.retained_publisher_proof()?;
            ImageTrustTier::VerifiedRelease
        }
        ComponentGraphBase::Development {
            compatibility,
            evidence,
            manifest_bytes,
            kernel,
            tar,
        } => {
            reverify_local_component_base(compatibility, evidence, manifest_bytes, kernel, tar)?;
            ImageTrustTier::LocalDev
        }
    };
    Ok(ComposedComponentRootfs {
        tree: base,
        pins,
        tier,
    })
}

fn reverify_local_component_base(
    compatibility: &DevelopmentBaseCompatibility,
    evidence: &LocalImageSetVerification<'_>,
    manifest_bytes: &[u8],
    kernel: &Path,
    tar: &Path,
) -> Result<(), RuntimeLayerStageError> {
    let current = compatibility.reverify(evidence)?;
    let (selected_kernel, selected_tar) = current.artifacts();
    if current.descriptor().image_set_manifest_sha256() != &Sha256Hex::from_bytes(manifest_bytes)
        || selected_kernel.path != kernel
        || selected_tar.path != tar
    {
        return Err(RuntimeLayerStageError::ComponentGraph);
    }
    Ok(())
}

fn compose_local_component_base(
    source: &ComponentGraphBase<'_>,
) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError> {
    let ComponentGraphBase::Development {
        compatibility,
        evidence,
        manifest_bytes,
        kernel,
        tar,
    } = source
    else {
        return Err(RuntimeLayerStageError::ComponentGraph);
    };
    reverify_local_component_base(compatibility, evidence, manifest_bytes, kernel, tar)?;
    compose_local_workload_tree(
        manifest_bytes,
        kernel,
        tar,
        compatibility.descriptor().arch(),
        compatibility.descriptor().profile(),
        &[],
    )
}

fn check_graph_requirements(
    source: &ComponentGraphBase<'_>,
    requirements: &mvm_core::registry_pack::application_component::ComponentRequirements,
    arch: GuestArch,
) -> Result<(), RuntimeLayerStageError> {
    match source {
        ComponentGraphBase::Production { compatibility, .. } => {
            compatibility.check_component_requirements(requirements, arch)?;
        }
        ComponentGraphBase::Development { compatibility, .. } => {
            compatibility.check_component_requirements(requirements, arch)?;
        }
    }
    Ok(())
}

fn graph_pin(requested: &SignedPackPin) -> Result<PackPin, RuntimeLayerStageError> {
    let reference = format!("{}@{}", requested.name, requested.version)
        .parse()
        .map_err(|_| RuntimeLayerStageError::ComponentGraph)?;
    let digest = Sha256Hex::new(&requested.manifest_sha256)
        .map_err(|_| RuntimeLayerStageError::ComponentGraph)?;
    PackPin::new(reference, digest).map_err(|_| RuntimeLayerStageError::ComponentGraph)
}

fn dependencies_before(dependencies: &[PackPin], preceding: &[PackPin]) -> bool {
    dependencies.iter().all(|pin| preceding.contains(pin))
}

fn apply_component_archive(
    tree: &mut ComposedRuntimeLayers,
    mut archive: std::fs::File,
    expected: &Sha256Hex,
    role: TarRole,
) -> Result<(), RuntimeLayerStageError> {
    let size = archive.metadata()?.len();
    if mvm_core::crypto::image_verify::sha256_reader(&mut archive)? != expected.as_str() {
        return Err(RuntimeLayerStageError::ComponentDigest);
    }
    archive.seek(SeekFrom::Start(0))?;
    let mut magic = [0; 2];
    archive.read_exact(&mut magic)?;
    archive.seek(SeekFrom::Start(0))?;
    if magic == [0x1f, 0x8b] {
        let mut tar = tempfile::tempfile()?;
        decompress_single_gzip(io::BufReader::new(archive), size, &mut tar)?;
        tar.seek(SeekFrom::Start(0))?;
        tree.apply_tar(&mut tar, role)?;
    } else {
        tree.apply_tar(&mut archive, role)?;
    }
    Ok(())
}

/// Verify revocation and snapshot custody around strict, bounded extraction.
///
/// # Errors
///
/// Refuses withdrawn trust, changed archive bytes or tar entries outside the
/// runtime-layer subset. This is not a complete composed rootfs or boot grant.
pub fn stage_runtime_layer(
    archive: &VerifiedRuntimeLayerArchive,
) -> Result<StagedRuntimeLayer, RuntimeLayerStageError> {
    archive.descriptor().check_current_revocations()?;
    let mut file = archive.open_verified()?;
    let stage = stage_tar(&mut file)?;
    archive.reverify()?;
    archive.descriptor().check_current_revocations()?;
    Ok(stage)
}

/// Compose authenticated runtime archives without Nix or a builder VM.
///
/// This prepares reusable filesystem input only. It cannot be booted, signed as
/// an application, or installed as a `.mvmpkg` without the signed base, an
/// application entrypoint, policy admission, verity and final bundle signing.
/// A directory may recur across layers, but no file or symlink may overlap.
///
/// # Errors
///
/// Refuses revoked or changed archives, unresolved dependencies, path
/// collisions, and any tar semantics not faithfully retained by extraction.
pub fn compose_runtime_layers(
    archives: &[&VerifiedRuntimeLayerArchive],
) -> Result<ComposedRuntimeLayers, RuntimeLayerStageError> {
    if archives.is_empty() || archives.len() > MAX_LAYERS {
        return Err(RuntimeLayerStageError::InconsistentLayers);
    }
    let arch = &archives[0].descriptor().manifest().runtime_layer.guest_arch;
    let pins = runtime_pins(archives, arch)?;
    let mut composed = ComposedRuntimeLayers::new(pins)?;
    add_runtime_archives(&mut composed, archives)?;
    Ok(composed)
}

/// Compose precisely the authenticated layers a v2 application requests.
///
/// The host selects the generic base profile; the author cannot choose a
/// kernel, grant, publisher or signing key. This is candidate filesystem
/// materialization, not production admission or an `.mvmpkg` exporter.
///
/// # Errors
///
/// Refuses an invalid spec, missing/extra/out-of-order layers, wrong target,
/// stale publisher proof, policy-file drift or archive drift before a candidate is returned.
pub fn compose_authored_candidate(
    spec: &ComposablePackSpec,
    images: &crate::published_image_set::PublishedImageSet,
    profile: WorkloadImageProfile,
    inputs: &[&VerifiedRuntimeLayerInputs],
) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError> {
    compose_authored_candidate_with(spec, inputs, |arch, archives| {
        compose_signed_workload_tree(images, arch, profile, archives)
    })
}

/// Compose an explicitly selected local-development base. The local manifest
/// must declare both input files; its ext4 artifact is not treated as the
/// composition tree or as evidence that it matches the tar.
pub fn compose_local_authored_candidate(
    spec: &ComposablePackSpec,
    manifest_bytes: &[u8],
    kernel: &Path,
    tar: &Path,
    profile: WorkloadImageProfile,
    inputs: &[&VerifiedRuntimeLayerInputs],
) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError> {
    compose_authored_candidate_with(spec, inputs, |arch, archives| {
        compose_local_workload_tree(manifest_bytes, kernel, tar, arch, profile, archives)
    })
}

fn compose_authored_candidate_with(
    spec: &ComposablePackSpec,
    inputs: &[&VerifiedRuntimeLayerInputs],
    select_base: impl FnOnce(
        GuestArch,
        &[&VerifiedRuntimeLayerArchive],
    ) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError>,
) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError> {
    spec.validate()?;
    for input in inputs {
        require_offline_runtime_policy(input)?;
    }
    let archives: Vec<&VerifiedRuntimeLayerArchive> =
        inputs.iter().map(|input| input.archive()).collect();
    let descriptors: Vec<_> = archives
        .iter()
        .map(|archive| archive.descriptor().clone())
        .collect();
    let order = resolve_requested_runtime_layers(spec, &descriptors)?;
    if order.len() != archives.len()
        || order.iter().zip(&archives).any(|(selected, archive)| {
            selected.reference() != archive.descriptor().reference()
                || selected.manifest_sha256() != archive.descriptor().manifest_sha256()
        })
    {
        return Err(RuntimeLayerStageError::InconsistentLayers);
    }
    let arch = match spec.target {
        PackTarget::X86_64Linux => GuestArch::X86_64,
        PackTarget::Aarch64Linux => GuestArch::Aarch64,
    };
    let mut composed = select_base(arch, &archives)?;
    for input in inputs {
        // add_runtime_archives already rehashes each archive before and after
        // extraction; the small signed policy bytes still need a final check.
        require_offline_runtime_policy(input)?;
    }
    composed.authored_spec_sha256 = Some(Sha256Hex::from_bytes(&spec.canonical_json()?));
    composed.runtime_policies = inputs
        .iter()
        .map(|input| input.policies().clone())
        .collect();
    Ok(composed)
}

/// Require a local schema-3 dev pair with its own declared tar, then use
/// exactly those bytes as the base and selected kernel for a dev-only build.
pub fn compose_local_workload_tree(
    manifest_bytes: &[u8],
    kernel: &Path,
    tar: &Path,
    arch: GuestArch,
    profile: WorkloadImageProfile,
    archives: &[&VerifiedRuntimeLayerArchive],
) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError> {
    if manifest_bytes.len() > mvm_core::plan::bundle::MAX_IMAGE_SET_MANIFEST_BYTES as usize {
        return Err(RuntimeLayerStageError::Unsupported(
            "local base manifest exceeds its bound",
        ));
    }
    let manifest: ImageSetManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| RuntimeLayerStageError::Unsupported("invalid local base manifest"))?;
    mvm_core::image_set::check_workload_protocol_compatibility(
        &manifest.compatibility,
        &crate::stage0_kernel::current_image_set_protocol_support(),
    )
    .map_err(|error| RuntimeLayerStageError::Base(error.into()))?;
    let (kernel_artifact, tar_artifact) =
        mvm_core::plan::bundle::select_local_development_source(&manifest, arch, profile)
            .map_err(|error| RuntimeLayerStageError::Base(error.into()))?;
    let ArtifactFormat::Kernel(declared_kernel_format) = kernel_artifact.format else {
        return Err(RuntimeLayerStageError::Unsupported(
            "local dev kernel format is invalid",
        ));
    };
    if kernel_artifact.size > 256 * 1024 * 1024 {
        return Err(RuntimeLayerStageError::Unsupported(
            "local base kernel exceeds the bundle capture bound",
        ));
    }
    if tar_artifact.size > 2 * 1024 * 1024 * 1024 {
        return Err(RuntimeLayerStageError::Unsupported(
            "local base tar exceeds its bound",
        ));
    }
    for (path, artifact) in [(kernel, kernel_artifact), (tar, tar_artifact)] {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file()
            || metadata.len() != artifact.size
            || mvm_core::crypto::image_verify::sha256_file(path)? != artifact.sha256.as_str()
        {
            return Err(RuntimeLayerStageError::Unsupported(
                "local base kernel or composition tar differs from its declared bytes",
            ));
        }
    }
    let mut head = vec![0; mvm_core::kernel_format::KernelFormat::SNIFF_LEN];
    std::io::Read::read_exact(&mut std::fs::File::open(kernel)?, &mut head)?;
    let actual_kernel_format = mvm_core::kernel_format::KernelFormat::sniff_magic(&head);
    let expected_machine = match arch {
        GuestArch::X86_64 => 62u16,
        GuestArch::Aarch64 => 183u16,
    };
    if actual_kernel_format != Some(declared_kernel_format)
        || (declared_kernel_format == mvm_core::kernel_format::KernelFormat::Elf
            && head.get(18..20) != Some(expected_machine.to_le_bytes().as_slice()))
    {
        return Err(RuntimeLayerStageError::Unsupported(
            "local kernel bytes do not match the declared format or architecture",
        ));
    }
    let pins = runtime_pins(archives, &arch.to_string())?;
    let mut decompressed = tempfile::tempfile()?;
    decompress_single_gzip(
        io::BufReader::new(std::fs::File::open(tar)?),
        tar_artifact.size,
        &mut decompressed,
    )?;
    if mvm_core::crypto::image_verify::sha256_file(tar)? != tar_artifact.sha256.as_str() {
        return Err(RuntimeLayerStageError::Unsupported(
            "local base tar changed while decompressing",
        ));
    }
    decompressed.seek(SeekFrom::Start(0))?;
    let mut composed = ComposedRuntimeLayers::new(pins)?;
    composed.add_base_tar(&mut decompressed)?;
    check_base_contract(&composed)?;
    add_runtime_archives(&mut composed, archives)?;
    Ok(ComposedWorkloadRootfs {
        tree: composed,
        base_manifest_sha256: Sha256Hex::from_bytes(manifest_bytes),
        profile,
        authored_spec_sha256: None,
        runtime_policies: Vec::new(),
    })
}

/// Combine a signed generic base and ordered runtime layers without Nix.
///
/// A verified image-set root selects the production tar; its compressed bytes
/// are fetched and digest-checked before bounded decompression. This remains
/// private build input: an application, policy, verity and final signed bundle
/// are still required before the VM can boot from a `.mvmpkg`.
///
/// # Errors
///
/// Refuses stale publisher proof, missing or modified base tar, wrong base
/// contract, archive drift or a runtime collision with base-owned paths.
pub fn compose_signed_workload_tree(
    images: &crate::published_image_set::PublishedImageSet,
    arch: GuestArch,
    profile: WorkloadImageProfile,
    archives: &[&VerifiedRuntimeLayerArchive],
) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError> {
    compose_signed_workload_tree_with(images, arch, profile, archives, |images| {
        images.retained_publisher_proof()?;
        Ok(())
    })
}

fn compose_signed_workload_tree_with(
    images: &crate::published_image_set::PublishedImageSet,
    arch: GuestArch,
    profile: WorkloadImageProfile,
    archives: &[&VerifiedRuntimeLayerArchive],
    check_proof: impl FnOnce(
        &crate::published_image_set::PublishedImageSet,
    ) -> Result<(), RuntimeLayerStageError>,
) -> Result<ComposedWorkloadRootfs, RuntimeLayerStageError> {
    let pins = runtime_pins(archives, &arch.to_string())?;
    let downloaded = tempfile::tempdir()?;
    let source = downloaded.path().join("base.tar.gz");
    let signed_digest = images.fetch_workload_composition_tar(arch, profile, &source)?;
    let mut decompressed = tempfile::tempfile()?;
    decompress_single_gzip(
        io::BufReader::new(std::fs::File::open(&source)?),
        std::fs::metadata(&source)?.len(),
        &mut decompressed,
    )?;
    if mvm_core::crypto::image_verify::sha256_file(&source)? != signed_digest.as_str() {
        return Err(RuntimeLayerStageError::Unsupported(
            "signed base tar changed during decompression",
        ));
    }
    decompressed.seek(SeekFrom::Start(0))?;
    let mut composed = ComposedRuntimeLayers::new(pins)?;
    composed.add_base_tar(&mut decompressed)?;
    check_base_contract(&composed)?;
    add_runtime_archives(&mut composed, archives)?;
    // Recheck signed publisher proof and revocations after assembling the tree.
    check_proof(images)?;
    Ok(ComposedWorkloadRootfs {
        tree: composed,
        base_manifest_sha256: Sha256Hex::from_bytes(images.manifest_bytes()),
        profile,
        authored_spec_sha256: None,
        runtime_policies: Vec::new(),
    })
}

fn decompress_single_gzip<R: io::BufRead + Seek>(
    source: R,
    compressed_len: u64,
    output: &mut std::fs::File,
) -> Result<(), RuntimeLayerStageError> {
    let mut decoder = flate2::bufread::GzDecoder::new(source);
    let bytes = io::copy(&mut decoder.by_ref().take(MAX_UNPACKED_BYTES + 1), output)?;
    if bytes > MAX_UNPACKED_BYTES {
        return Err(RuntimeLayerStageError::Unsupported(
            "decompressed tar exceeds its bound",
        ));
    }
    if decoder.into_inner().stream_position()? != compressed_len {
        return Err(RuntimeLayerStageError::Unsupported(
            "compressed tar has trailing gzip members or bytes",
        ));
    }
    Ok(())
}

fn check_base_contract(composed: &ComposedRuntimeLayers) -> Result<(), RuntimeLayerStageError> {
    use std::os::unix::fs::PermissionsExt;

    let marker = composed.root().join("etc/mvm/base-image-contract");
    let metadata = std::fs::symlink_metadata(&marker)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != 0o444
        || std::fs::read(&marker)? != b"1\n"
        || composed.ownership().owner_of("/home/mvm-worker") != mvm_fs::ext4::Owner::new(901, 901)
    {
        return Err(RuntimeLayerStageError::BaseContract);
    }
    Ok(())
}

fn runtime_pins(
    archives: &[&VerifiedRuntimeLayerArchive],
    arch: &str,
) -> Result<Vec<PackPin>, RuntimeLayerStageError> {
    if archives.len() > MAX_LAYERS {
        return Err(RuntimeLayerStageError::InconsistentLayers);
    }
    let mut pins: Vec<PackPin> = Vec::with_capacity(archives.len());
    for archive in archives {
        let descriptor = archive.descriptor();
        if descriptor.manifest().runtime_layer.guest_arch != arch
            || descriptor
                .manifest()
                .runtime_layer
                .dependencies
                .iter()
                .any(|dependency| !pins.contains(dependency))
            || pins.iter().any(|pin| {
                pin.reference().coordinate_string() == descriptor.reference().coordinate_string()
            })
        {
            return Err(RuntimeLayerStageError::InconsistentLayers);
        }
        pins.push(
            PackPin::new(
                descriptor.reference().clone(),
                descriptor.manifest_sha256().clone(),
            )
            .map_err(|_| RuntimeLayerStageError::InconsistentLayers)?,
        );
    }
    Ok(pins)
}

fn add_runtime_archives(
    composed: &mut ComposedRuntimeLayers,
    archives: &[&VerifiedRuntimeLayerArchive],
) -> Result<(), RuntimeLayerStageError> {
    for archive in archives {
        archive.descriptor().check_current_revocations()?;
        let mut file = archive.open_verified()?;
        composed.add_tar(&mut file)?;
        archive.reverify()?;
        archive.descriptor().check_current_revocations()?;
    }
    Ok(())
}

fn stage_tar<R: Read + Seek>(reader: &mut R) -> Result<StagedRuntimeLayer, RuntimeLayerStageError> {
    preflight(reader, TarRole::Runtime)?;
    let directory = tempfile::tempdir()?;
    let options = UnpackOptions::builder()
        .max_total_bytes(MAX_UNPACKED_BYTES)
        .max_entries(MAX_ENTRIES)
        .xattr_policy(XattrPolicy::DropAll)
        .setid_policy(SetidPolicy::RefuseUnsigned)
        .build();
    let report = unpack_layer(reader, directory.path(), &options, None)?;
    refuse_lossy_report(&report)?;
    Ok(StagedRuntimeLayer { directory, report })
}

fn refuse_lossy_report(report: &UnpackReport) -> Result<(), RuntimeLayerStageError> {
    if !report.deferred_nodes.is_empty() {
        return Err(RuntimeLayerStageError::CaseFolding);
    }
    if !report.refused.is_empty()
        || report.whiteouts_applied != 0
        || report.opaque_markers_applied != 0
        || report.device_nodes_written != 0
        || report.device_nodes_skipped != 0
        || report.setid_entries_preserved != 0
        || report.xattrs_dropped != 0
    {
        return Err(RuntimeLayerStageError::Unsupported(
            "unpack refused or could not faithfully represent a layer entry",
        ));
    }
    if report.files_written == 0 {
        return Err(RuntimeLayerStageError::Unsupported(
            "runtime layer contains no regular files",
        ));
    }
    Ok(())
}

/// Reject destructive or ambiguous tar semantics before any write, even to staging.
fn preflight<R: Read + Seek>(
    reader: &mut R,
    role: TarRole,
) -> Result<TarInventory, RuntimeLayerStageError> {
    let mut archive = tar::Archive::new(&mut *reader);
    let mut paths = HashSet::<PathBuf>::new();
    let mut inventory = BTreeMap::new();
    let mut directory_modes = BTreeMap::new();
    let mut total_bytes = 0_u64;
    let mut entries = 0_u64;
    for entry in archive.entries()? {
        let entry = entry?;
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(RuntimeLayerStageError::Unsupported("too many tar entries"));
        }
        total_bytes =
            total_bytes
                .checked_add(entry.size())
                .ok_or(RuntimeLayerStageError::Unsupported(
                    "tar byte count overflow",
                ))?;
        if total_bytes > MAX_UNPACKED_BYTES {
            return Err(RuntimeLayerStageError::Unsupported(
                "tar content exceeds its bound",
            ));
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir() || kind.is_symlink())
            || (matches!(role, TarRole::Application) && kind.is_symlink())
        {
            return Err(RuntimeLayerStageError::Unsupported("tar entry type"));
        }
        if kind.is_symlink()
            && entry
                .link_name_bytes()
                .is_none_or(|target| target.is_empty() || std::str::from_utf8(&target).is_err())
        {
            return Err(RuntimeLayerStageError::Unsupported(
                "non-UTF-8 or empty symlink target",
            ));
        }
        let mode = entry.header().mode()?;
        if mode & 0o6000 != 0 {
            return Err(RuntimeLayerStageError::Unsupported("setuid or setgid mode"));
        }
        let raw = entry.path_bytes();
        let path: PathBuf = entry
            .path()?
            .components()
            .filter(|component| *component != std::path::Component::CurDir)
            .collect();
        if path.as_os_str().is_empty()
            && kind.is_dir()
            && (raw.as_ref() == b"." || raw.as_ref() == b"./")
        {
            continue;
        }
        if raw.len() > MAX_PATH_BYTES
            || path.as_os_str().is_empty()
            || !path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
            || path.to_str().is_none()
        {
            return Err(RuntimeLayerStageError::Unsupported(
                "non-canonical tar path",
            ));
        }
        if raw
            .split(|byte| *byte == b'/')
            .any(|component| component.starts_with(b".wh."))
            || (matches!(role, TarRole::Runtime) && reserved_runtime_path(&path))
            || (matches!(role, TarRole::Application)
                && !(path == Path::new("srv") || path.starts_with("srv/app")))
            || (matches!(role, TarRole::Base)
                && ["init", "sbin/mvm-setpriv", "etc/mvm/entrypoint"]
                    .iter()
                    .any(|reserved| path == Path::new(reserved)))
        {
            return Err(RuntimeLayerStageError::Unsupported(
                "whiteout or host-owned guest path",
            ));
        }
        if !paths.insert(path.clone()) {
            return Err(RuntimeLayerStageError::Unsupported("duplicate tar path"));
        }
        if kind.is_dir() {
            directory_modes.insert(path.clone(), mode & 0o7777);
        }
        let kind = if kind.is_dir() {
            PathKind::Directory
        } else {
            PathKind::Leaf
        };
        if matches!(role, TarRole::Application)
            && (path == Path::new("srv") || path == Path::new("srv/app"))
            && kind != PathKind::Directory
        {
            return Err(RuntimeLayerStageError::Unsupported(
                "application root is not a directory",
            ));
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            if let Some(PathKind::Leaf) =
                inventory.insert(parent.to_path_buf(), PathKind::Directory)
            {
                return Err(RuntimeLayerStageError::Unsupported(
                    "non-directory tar parent",
                ));
            }
        }
        if inventory
            .insert(path, kind)
            .is_some_and(|prior| prior == PathKind::Leaf || kind == PathKind::Leaf)
        {
            return Err(RuntimeLayerStageError::Unsupported(
                "tar path replaces a leaf",
            ));
        }
        if inventory.len() > MAX_ENTRIES as usize {
            return Err(RuntimeLayerStageError::Unsupported(
                "too many tar paths including parent directories",
            ));
        }
    }
    let reader = archive.into_inner();
    let mut tail = [0u8; 8192];
    loop {
        let len = reader.read(&mut tail)?;
        if len == 0 {
            break;
        }
        if tail[..len].iter().any(|byte| *byte != 0) {
            return Err(RuntimeLayerStageError::Unsupported(
                "tar has nonzero data after its end marker",
            ));
        }
    }
    reader.seek(SeekFrom::Start(0))?;
    Ok(TarInventory {
        paths: inventory,
        directory_modes,
        bytes: total_bytes,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn archive(entries: &[(&str, &[u8], tar::EntryType, u32)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes, kind, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_mode(*mode);
            header.set_size(bytes.len() as u64);
            if kind.is_symlink() {
                header.set_link_name("bin").unwrap();
            }
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn base_tar(contract: &[u8], uid: u64) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes, kind, mode, owner) in [
            ("./", b"".as_slice(), tar::EntryType::Directory, 0o755, 0),
            (
                "etc/mvm/base-image-contract",
                contract,
                tar::EntryType::Regular,
                0o444,
                0,
            ),
            (
                "home/mvm-worker",
                b"".as_slice(),
                tar::EntryType::Directory,
                0o755,
                uid,
            ),
            (
                "usr/bin/sh",
                b"busybox".as_slice(),
                tar::EntryType::Regular,
                0o755,
                0,
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(mode);
            header.set_uid(owner);
            header.set_gid(owner);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, path, bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    #[test]
    fn a_runtime_tar_stages_without_a_builder_vm() {
        let tar = archive(&[("bin/python3", b"python", tar::EntryType::Regular, 0o755)]);
        let staged = stage_tar(&mut Cursor::new(tar)).unwrap();
        assert_eq!(
            std::fs::read(staged.root().join("bin/python3")).unwrap(),
            b"python"
        );
        assert_eq!(staged.report().files_written, 1);
        assert!(
            staged
                .report()
                .paths_written
                .contains(Path::new("bin/python3"))
        );
    }

    #[test]
    #[ignore = "requires MVM_TEST_PYTHON_LAYER_TAR from the pinned source signing smoke"]
    fn pinned_python_layer_passes_the_real_runtime_tar_preflight() {
        let path = std::env::var("MVM_TEST_PYTHON_LAYER_TAR")
            .expect("the signing smoke supplies its verified Python tar");
        let staged = stage_tar(&mut std::fs::File::open(path).unwrap()).unwrap();
        assert!(staged.root().join("usr/bin/python3").is_file());
        assert!(
            staged
                .root()
                .join("usr/lib/python3.13/encodings/__init__.py")
                .is_file()
        );
        assert!(staged.report().files_written >= 500);
    }

    #[test]
    fn every_tar_role_refuses_hidden_bytes_after_the_end_marker() {
        let mut tar = archive(&[(
            "srv/app/main.py",
            b"print('ok')",
            tar::EntryType::Regular,
            0o644,
        )]);
        tar.extend_from_slice(b"hidden bytes");
        for role in [TarRole::Base, TarRole::Runtime, TarRole::Application] {
            assert!(matches!(
                preflight(&mut Cursor::new(&tar), role),
                Err(RuntimeLayerStageError::Unsupported(
                    "tar has nonzero data after its end marker"
                ))
            ));
        }
    }

    #[test]
    fn base_and_application_gzip_refuse_a_second_member() {
        use std::io::Write as _;

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"first tar").unwrap();
        let first = gzip.finish().unwrap();
        let mut concatenated = first.clone();
        concatenated.extend_from_slice(&first);
        for bytes in [concatenated, [first, b"trailing".to_vec()].concat()] {
            assert!(matches!(
                decompress_single_gzip(
                    io::Cursor::new(&bytes),
                    bytes.len() as u64,
                    &mut tempfile::tempfile().unwrap()
                ),
                Err(RuntimeLayerStageError::Unsupported(
                    "compressed tar has trailing gzip members or bytes"
                ))
            ));
        }
    }

    #[test]
    fn component_archive_refuses_tamper_before_extraction() {
        use std::io::Write as _;

        let bytes = archive(&[("bin/tool", b"trusted", tar::EntryType::Regular, 0o755)]);
        let mut snapshot = tempfile::tempfile().unwrap();
        snapshot.write_all(&bytes).unwrap();
        snapshot.rewind().unwrap();
        let mut accepted = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        apply_component_archive(
            &mut accepted,
            snapshot.try_clone().unwrap(),
            &Sha256Hex::from_bytes(&bytes),
            TarRole::Runtime,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(accepted.root().join("bin/tool")).unwrap(),
            b"trusted"
        );
        snapshot.rewind().unwrap();
        let mut tree = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        let wrong = Sha256Hex::from_bytes(b"different signed archive");
        assert!(matches!(
            apply_component_archive(&mut tree, snapshot, &wrong, TarRole::Runtime),
            Err(RuntimeLayerStageError::ComponentDigest)
        ));
        assert!(!tree.root().join("bin/tool").exists());
    }

    #[test]
    fn component_accepts_digest_pinned_gzip_without_an_extension_rule() {
        use std::io::Write as _;

        let raw = archive(&[("bin/tool", b"compressed", tar::EntryType::Regular, 0o755)]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        let gzip = encoder.finish().unwrap();
        let mut snapshot = tempfile::tempfile().unwrap();
        snapshot.write_all(&gzip).unwrap();
        snapshot.rewind().unwrap();
        let mut tree = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        apply_component_archive(
            &mut tree,
            snapshot,
            &Sha256Hex::from_bytes(&gzip),
            TarRole::Runtime,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(tree.root().join("bin/tool")).unwrap(),
            b"compressed"
        );
    }

    #[test]
    fn component_dependencies_require_exact_preceding_manifest_pins() {
        let reference = "runtime/python@1.0.0".parse().unwrap();
        let pinned = PackPin::new(reference, Sha256Hex::from_bytes(b"trusted manifest")).unwrap();
        let drift = PackPin::new(
            pinned.reference().clone(),
            Sha256Hex::from_bytes(b"different manifest"),
        )
        .unwrap();
        assert!(!dependencies_before(std::slice::from_ref(&pinned), &[]));
        assert!(!dependencies_before(
            std::slice::from_ref(&pinned),
            &[drift]
        ));
        assert!(dependencies_before(
            std::slice::from_ref(&pinned),
            std::slice::from_ref(&pinned)
        ));
    }

    #[test]
    fn ordered_components_refuse_leaf_and_directory_mode_collisions() {
        let mut tree = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        let first = archive(&[
            ("usr", b"", tar::EntryType::Directory, 0o755),
            ("usr/bin/tool", b"first", tar::EntryType::Regular, 0o755),
        ]);
        tree.add_tar(&mut Cursor::new(first)).unwrap();
        let overlapping = archive(&[("usr/bin/tool", b"second", tar::EntryType::Regular, 0o755)]);
        assert!(matches!(
            tree.add_tar(&mut Cursor::new(overlapping)),
            Err(RuntimeLayerStageError::Collision(_))
        ));
        let changed_mode = archive(&[
            ("usr", b"", tar::EntryType::Directory, 0o777),
            ("usr/bin/other", b"other", tar::EntryType::Regular, 0o755),
        ]);
        assert!(matches!(
            tree.add_tar(&mut Cursor::new(changed_mode)),
            Err(RuntimeLayerStageError::Collision(_))
        ));
        assert_eq!(
            std::fs::read(tree.root().join("usr/bin/tool")).unwrap(),
            b"first"
        );
        assert!(!tree.root().join("usr/bin/other").exists());
    }

    #[test]
    fn runtime_tar_refuses_changes_to_earlier_layers_and_boot() {
        for path in [
            ".wh.bin",
            "bin/.wh.python3",
            "etc/mvm/entrypoint",
            "./etc/mvm/entrypoint",
            "etc/mvm/base-image-contract",
            "etc/resolv.conf",
            "etc/passwd",
            "mvm/runtime/agent",
            "usr/lib/mvm/wrappers/oci-entrypoint",
            "dev/null",
            "init",
            "./init",
        ] {
            let tar = archive(&[(path, b"data", tar::EntryType::Regular, 0o644)]);
            assert!(stage_tar(&mut Cursor::new(tar)).is_err(), "{path}");
        }
        let tar = archive(&[
            ("bin/python3", b"a", tar::EntryType::Regular, 0o755),
            ("bin/python3", b"b", tar::EntryType::Regular, 0o755),
        ]);
        assert!(stage_tar(&mut Cursor::new(tar)).is_err());
    }

    #[test]
    fn runtime_tar_refuses_device_setid_and_empty_payload() {
        for (kind, mode) in [
            (tar::EntryType::Char, 0o644),
            (tar::EntryType::Regular, 0o4755),
        ] {
            let tar = archive(&[("bin/tool", b"binary", kind, mode)]);
            assert!(stage_tar(&mut Cursor::new(tar)).is_err());
        }
        assert!(stage_tar(&mut Cursor::new(archive(&[]))).is_err());
    }

    #[test]
    fn independent_python_layers_compose_without_replacing_files() {
        let python = archive(&[
            ("usr", b"", tar::EntryType::Directory, 0o755),
            ("usr/bin/python3", b"python", tar::EntryType::Regular, 0o755),
        ]);
        let stdlib = archive(&[
            ("usr", b"", tar::EntryType::Directory, 0o755),
            (
                "usr/lib/python3.12/os.py",
                b"stdlib",
                tar::EntryType::Regular,
                0o644,
            ),
        ]);
        let mut composed = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        composed.add_tar(&mut Cursor::new(python)).unwrap();
        composed.add_tar(&mut Cursor::new(stdlib)).unwrap();
        assert_eq!(
            std::fs::read(composed.root().join("usr/bin/python3")).unwrap(),
            b"python"
        );
        assert_eq!(
            std::fs::read(composed.root().join("usr/lib/python3.12/os.py")).unwrap(),
            b"stdlib"
        );
        assert_eq!(
            composed.claimed.get(Path::new("usr")),
            Some(&PathKind::Directory)
        );
        let output = tempfile::tempdir().unwrap();
        let ext4 = output.path().join("rootfs.ext4");
        let input = crate::rootfs::MaterializeExt4Input::new(
            composed.root().to_path_buf(),
            ext4.clone(),
            0,
        )
        .with_owners(composed.ownership().clone())
        .with_verity();
        let materialized = crate::rootfs::materialize_ext4_pure(&input).unwrap();
        assert!(materialized.verity_root_hash.is_some());
        assert!(output.path().join("rootfs.verity").is_file());
        let image = mvm_fs::tree_diff::Ext4Tree::open(&ext4).unwrap();
        assert_eq!(
            image
                .read_regular_file_no_symlinks("usr/bin/python3", 16)
                .unwrap(),
            b"python"
        );
        assert_eq!(
            image
                .read_regular_file_no_symlinks("usr/lib/python3.12/os.py", 16)
                .unwrap(),
            b"stdlib"
        );
    }

    #[test]
    fn composition_refuses_overwrite_and_symlink_ancestor() {
        let python = archive(&[("usr/bin/python3", b"python", tar::EntryType::Regular, 0o755)]);
        let overwrite = archive(&[(
            "usr/bin/python3",
            b"surprise",
            tar::EntryType::Regular,
            0o755,
        )]);
        let mut composed = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        composed.add_tar(&mut Cursor::new(python)).unwrap();
        assert!(matches!(
            composed.add_tar(&mut Cursor::new(overwrite)),
            Err(RuntimeLayerStageError::Collision(path)) if path == Path::new("usr/bin/python3")
        ));
        assert_eq!(
            std::fs::read(composed.root().join("usr/bin/python3")).unwrap(),
            b"python"
        );
        let child = archive(&[(
            "opt/tools/runner",
            b"runner",
            tar::EntryType::Regular,
            0o755,
        )]);
        let mut composed = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        let first = archive(&[
            ("opt/tools", b"", tar::EntryType::Symlink, 0o777),
            ("bin/python", b"python", tar::EntryType::Regular, 0o755),
        ]);
        composed.add_tar(&mut Cursor::new(first)).unwrap();
        assert!(matches!(
            composed.add_tar(&mut Cursor::new(child)),
            Err(RuntimeLayerStageError::Collision(path)) if path == Path::new("opt/tools")
        ));
    }

    #[test]
    fn composition_has_one_aggregate_resource_budget() {
        let file = archive(&[("bin/python", b"python", tar::EntryType::Regular, 0o755)]);
        let mut composed = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        composed.remaining_entries = 0;
        assert!(matches!(
            composed.add_tar(&mut Cursor::new(file)),
            Err(RuntimeLayerStageError::Unsupported(
                "combined runtime layers exceed their bound"
            ))
        ));
        assert_eq!(std::fs::read_dir(composed.root()).unwrap().count(), 0);
    }

    #[test]
    fn base_tree_preserves_contract_and_refuses_runtime_replacement() {
        let mut composed = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        composed
            .add_base_tar(&mut Cursor::new(base_tar(b"1\n", 901)))
            .unwrap();
        check_base_contract(&composed).unwrap();
        let python = archive(&[("usr/bin/python3", b"python", tar::EntryType::Regular, 0o755)]);
        composed.add_tar(&mut Cursor::new(python)).unwrap();
        assert_eq!(
            std::fs::read(composed.root().join("usr/bin/sh")).unwrap(),
            b"busybox"
        );
        assert_eq!(
            std::fs::read(composed.root().join("usr/bin/python3")).unwrap(),
            b"python"
        );
        let replacement = archive(&[("usr/bin/sh", b"bad", tar::EntryType::Regular, 0o755)]);
        assert!(matches!(
            composed.add_tar(&mut Cursor::new(replacement)),
            Err(RuntimeLayerStageError::Collision(path)) if path == Path::new("usr/bin/sh")
        ));
        for (contract, uid) in [(b"2\n".as_slice(), 901), (b"1\n", 902)] {
            let mut composed = ComposedRuntimeLayers::new(Vec::new()).unwrap();
            composed
                .add_base_tar(&mut Cursor::new(base_tar(contract, uid)))
                .unwrap();
            assert!(matches!(
                check_base_contract(&composed),
                Err(RuntimeLayerStageError::BaseContract)
            ));
        }
    }

    #[test]
    fn local_composition_uses_only_the_declared_kernel_and_tar() {
        use crate::published_image_set::fixture::ImageSetFixture;
        use mvm_core::image_set::{
            BaseImageContract, BuilderBootAbi, GuestDeviceRequirement, ImageSetRole,
            MemberArtifact, MemberTarget,
        };

        let directory = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        let profile = WorkloadImageProfile::DefaultTenant;
        let kernel = directory.path().join("vmlinux");
        let tar = directory.path().join("rootfs.tar.gz");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &base_tar(b"1\n", 901)).unwrap();
        let tar_bytes = encoder.finish().unwrap();
        let mut kernel_bytes = vec![0u8; mvm_core::kernel_format::KernelFormat::SNIFF_LEN];
        match arch {
            GuestArch::X86_64 => {
                kernel_bytes[..4].copy_from_slice(b"\x7fELF");
                kernel_bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
            }
            GuestArch::Aarch64 => {
                kernel_bytes[56..60].copy_from_slice(&0x644D_5241u32.to_le_bytes());
            }
        }
        std::fs::write(&kernel, &kernel_bytes).unwrap();
        std::fs::write(&tar, &tar_bytes).unwrap();
        let mut manifest = ImageSetFixture::complete()
            .with_base_image_contract(Some(BaseImageContract::LINUX_LAYER))
            .publish(
                ImageSetRole::WorkloadKernel(profile),
                MemberTarget::Arch(arch),
                "local-vmlinux",
                kernel_bytes.clone(),
            )
            .publish(
                ImageSetRole::WorkloadRootfs(profile),
                MemberTarget::Arch(arch),
                "local-rootfs.ext4",
                b"unrelated ext4".to_vec(),
            )
            .into_manifest();
        manifest.members.retain(|member| {
            member.target == MemberTarget::Arch(arch)
                && matches!(
                    member.role,
                    ImageSetRole::WorkloadKernel(_) | ImageSetRole::WorkloadRootfs(_)
                )
        });
        manifest.schema_version = mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION;
        let release_producer = manifest.producer.clone();
        manifest.producer = serde_json::from_value(serde_json::json!({
            "local_checkouts": {
                "images": {
                    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "worktree": {"state": "clean"}
                }
            }
        }))
        .unwrap();
        manifest.mvm_source_commit = None;
        manifest.revocation_channel = None;
        manifest.compatibility.guest_agent_protocol = None;
        manifest.compatibility.builder_boot_abi = Some(BuilderBootAbi::NO_MVM_BINARY);
        for member in &mut manifest.members {
            member.pack_hash = None;
            member.sbom = None;
            match member.role {
                ImageSetRole::WorkloadKernel(_) => {
                    member.required_capabilities = vec![GuestDeviceRequirement::VirtioVsock];
                }
                ImageSetRole::WorkloadRootfs(_) => {
                    member.required_capabilities = vec![GuestDeviceRequirement::VirtioBlk];
                    member.artifacts.push(MemberArtifact {
                        name: mvm_core::image_set::ArtifactName::new("local-rootfs.tar.gz")
                            .unwrap(),
                        format: ArtifactFormat::TarGz,
                        sha256: Sha256Hex::from_bytes(&tar_bytes),
                        size: tar_bytes.len() as u64,
                    });
                }
                _ => unreachable!(),
            }
        }
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let composed =
            compose_local_workload_tree(&bytes, &kernel, &tar, arch, profile, &[]).unwrap();
        assert_eq!(
            std::fs::read(composed.root().join("usr/bin/sh")).unwrap(),
            b"busybox"
        );
        assert_eq!(
            composed.base_manifest_sha256(),
            &Sha256Hex::from_bytes(&bytes)
        );
        drop(composed);

        std::fs::write(&kernel, b"forged kernel").unwrap();
        assert!(compose_local_workload_tree(&bytes, &kernel, &tar, arch, profile, &[]).is_err());
        std::fs::write(&kernel, &kernel_bytes).unwrap();
        std::fs::write(&tar, b"unrelated ext4").unwrap();
        assert!(compose_local_workload_tree(&bytes, &kernel, &tar, arch, profile, &[]).is_err());
        std::fs::write(&tar, &tar_bytes).unwrap();
        manifest.compatibility.builder_boot_abi = Some(BuilderBootAbi::LEGACY);
        assert!(
            compose_local_workload_tree(
                &serde_json::to_vec(&manifest).unwrap(),
                &kernel,
                &tar,
                arch,
                profile,
                &[]
            )
            .is_err()
        );
        manifest.compatibility.builder_boot_abi = Some(BuilderBootAbi::NO_MVM_BINARY);
        manifest
            .members
            .iter_mut()
            .find(|member| member.role == ImageSetRole::WorkloadRootfs(profile))
            .unwrap()
            .artifacts
            .retain(|artifact| artifact.format != ArtifactFormat::TarGz);
        assert!(
            compose_local_workload_tree(
                &serde_json::to_vec(&manifest).unwrap(),
                &kernel,
                &tar,
                arch,
                profile,
                &[]
            )
            .is_err(),
            "an ext4 declaration is not a composition tree"
        );
        manifest.producer = release_producer;
        assert!(
            compose_local_workload_tree(
                &serde_json::to_vec(&manifest).unwrap(),
                &kernel,
                &tar,
                arch,
                profile,
                &[]
            )
            .is_err(),
            "a release claim cannot enter the local lane"
        );
    }

    #[test]
    fn component_graph_local_base_is_development_and_rejects_mismatches_and_tampering() {
        use crate::published_image_set::fixture::ImageSetFixture;
        use mvm_core::image_set::base_compatibility::verify_development_base_compatibility;
        use mvm_core::image_set::{
            BaseImageContract, BuilderBootAbi, GuestDeviceRequirement, ImageSetProducer,
            ImageSetRole, LocalCheckouts, MemberArtifact, MemberTarget,
        };
        use mvm_core::registry_pack::application_component::ComponentRequirements;

        let directory = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        let profile = WorkloadImageProfile::DefaultTenant;
        let mut kernel_bytes = vec![0; mvm_core::kernel_format::KernelFormat::SNIFF_LEN];
        match arch {
            GuestArch::X86_64 => {
                kernel_bytes[..4].copy_from_slice(b"\x7fELF");
                kernel_bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
            }
            GuestArch::Aarch64 => {
                kernel_bytes[56..60].copy_from_slice(&0x644D_5241u32.to_le_bytes());
            }
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &base_tar(b"1\n", 901)).unwrap();
        let tar_bytes = encoder.finish().unwrap();
        let kernel = directory.path().join("local-vmlinux");
        let tar = directory.path().join("local-rootfs.tar.gz");
        std::fs::write(&kernel, &kernel_bytes).unwrap();
        std::fs::write(&tar, &tar_bytes).unwrap();
        std::fs::write(directory.path().join("local-rootfs.ext4"), b"ext4").unwrap();
        let current: LocalCheckouts = serde_json::from_value(serde_json::json!({
            "images": {"commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "worktree": {"state": "clean"}}
        }))
        .unwrap();
        let mut manifest = ImageSetFixture::complete()
            .with_base_image_contract(Some(BaseImageContract::LINUX_LAYER))
            .publish(
                ImageSetRole::WorkloadKernel(profile),
                MemberTarget::Arch(arch),
                "local-vmlinux",
                kernel_bytes.clone(),
            )
            .publish(
                ImageSetRole::WorkloadRootfs(profile),
                MemberTarget::Arch(arch),
                "local-rootfs.ext4",
                b"ext4".to_vec(),
            )
            .into_manifest();
        manifest.members.retain(|member| {
            member.target == MemberTarget::Arch(arch)
                && (member.role == ImageSetRole::WorkloadKernel(profile)
                    || member.role == ImageSetRole::WorkloadRootfs(profile))
        });
        manifest.schema_version = mvm_core::image_set::IMAGE_SET_SCHEMA_VERSION;
        manifest.producer = ImageSetProducer::LocalCheckouts(current.clone());
        manifest.mvm_source_commit = None;
        manifest.revocation_channel = None;
        manifest.compatibility.guest_agent_protocol = None;
        manifest.compatibility.builder_boot_abi = Some(BuilderBootAbi::NO_MVM_BINARY);
        for member in &mut manifest.members {
            member.pack_hash = None;
            member.sbom = None;
            match member.role {
                ImageSetRole::WorkloadKernel(_) => {
                    member.required_capabilities = vec![GuestDeviceRequirement::VirtioVsock];
                }
                ImageSetRole::WorkloadRootfs(_) => {
                    member.required_capabilities = vec![GuestDeviceRequirement::VirtioBlk];
                    member.artifacts.push(MemberArtifact {
                        name: mvm_core::image_set::ArtifactName::new("local-rootfs.tar.gz")
                            .unwrap(),
                        format: ArtifactFormat::TarGz,
                        sha256: Sha256Hex::from_bytes(&tar_bytes),
                        size: tar_bytes.len() as u64,
                    });
                }
                _ => unreachable!(),
            }
        }
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let descriptor_bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "base-compatibility/v1",
            "image_set_manifest_sha256": Sha256Hex::from_bytes(&manifest_bytes),
            "arch": if arch == GuestArch::X86_64 { "x86_64" } else { "aarch64" },
            "profile": "default_tenant",
            "kernel": {"name": "local-vmlinux", "sha256": Sha256Hex::from_bytes(&kernel_bytes), "size": kernel_bytes.len()},
            "composition_tar": {"name": "local-rootfs.tar.gz", "sha256": Sha256Hex::from_bytes(&tar_bytes), "size": tar_bytes.len()},
            "base_image_contract": 1, "boot_protocol": "linux_direct", "filesystem_abi": 1,
            "kernel_version": "6.12.3",
            "libc_loaders": [{"libc": "musl", "path": if arch == GuestArch::X86_64 { "/lib/ld-musl-x86_64.so.1" } else { "/lib/ld-musl-aarch64.so.1" }}],
            "kernel_capabilities": ["virtio_vsock"]
        }))
        .unwrap();
        let evidence =
            LocalImageSetVerification::new(&manifest_bytes, directory.path(), &current, arch);
        let compatibility =
            verify_development_base_compatibility(&descriptor_bytes, &evidence, arch, profile)
                .unwrap();
        let source = ComponentGraphBase::Development {
            compatibility: &compatibility,
            evidence: &evidence,
            manifest_bytes: &manifest_bytes,
            kernel: &kernel,
            tar: &tar,
        };
        let base = compose_local_component_base(&source).unwrap();
        assert_eq!(
            std::fs::read(base.root().join("usr/bin/sh")).unwrap(),
            b"busybox"
        );
        assert_eq!(
            base.base_manifest_sha256(),
            &Sha256Hex::from_bytes(&manifest_bytes)
        );
        let requirements = ComponentRequirements {
            filesystem_abi: 1,
            libc: "musl".into(),
            loader: Some(
                if arch == GuestArch::X86_64 {
                    "/lib/ld-musl-x86_64.so.1"
                } else {
                    "/lib/ld-musl-aarch64.so.1"
                }
                .into(),
            ),
            minimum_kernel: "6.12.3".into(),
            required_capabilities: vec!["virtio_vsock".into()],
        };
        check_graph_requirements(&source, &requirements, arch).unwrap();
        let mut incompatible = requirements.clone();
        incompatible.minimum_kernel = "6.12.4".into();
        assert!(matches!(
            check_graph_requirements(&source, &incompatible, arch),
            Err(RuntimeLayerStageError::ComponentBase(_))
        ));

        let wrong_manifest = b"another image set";
        assert!(matches!(
            reverify_local_component_base(&compatibility, &evidence, wrong_manifest, &kernel, &tar),
            Err(RuntimeLayerStageError::ComponentGraph)
        ));
        let alternate_kernel = directory.path().join("alternate-vmlinux");
        std::fs::write(&alternate_kernel, &kernel_bytes).unwrap();
        assert!(matches!(
            reverify_local_component_base(
                &compatibility,
                &evidence,
                &manifest_bytes,
                &alternate_kernel,
                &tar
            ),
            Err(RuntimeLayerStageError::ComponentGraph)
        ));
        let alternate_tar = directory.path().join("alternate-rootfs.tar.gz");
        std::fs::write(&alternate_tar, &tar_bytes).unwrap();
        assert!(matches!(
            reverify_local_component_base(
                &compatibility,
                &evidence,
                &manifest_bytes,
                &kernel,
                &alternate_tar
            ),
            Err(RuntimeLayerStageError::ComponentGraph)
        ));
        let changed_checkout: LocalCheckouts = serde_json::from_value(serde_json::json!({
            "images": {"commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "worktree": {"state": "clean"}}
        }))
        .unwrap();
        let stale_evidence = LocalImageSetVerification::new(
            &manifest_bytes,
            directory.path(),
            &changed_checkout,
            arch,
        );
        assert!(matches!(
            reverify_local_component_base(
                &compatibility,
                &stale_evidence,
                &manifest_bytes,
                &kernel,
                &tar
            ),
            Err(RuntimeLayerStageError::ComponentBase(_))
        ));
        std::fs::write(&tar, b"tampered").unwrap();
        assert!(matches!(
            compose_local_component_base(&source),
            Err(RuntimeLayerStageError::ComponentBase(_))
        ));
    }

    #[test]
    fn one_application_is_sealed_into_the_composed_rootfs() {
        use std::io::Write as _;

        let make_gzip = |tar: Vec<u8>| {
            let mut gzip =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gzip.write_all(&tar).unwrap();
            gzip.finish().unwrap()
        };
        let mut base = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        base.add_base_tar(&mut Cursor::new(base_tar(b"1\n", 901)))
            .unwrap();
        let candidate = ComposedWorkloadRootfs {
            tree: base,
            base_manifest_sha256: Sha256Hex::from_bytes(b"test base"),
            profile: WorkloadImageProfile::DefaultTenant,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        };
        let app = make_gzip(archive(&[(
            "srv/app/main.py",
            b"print('ready')\n",
            tar::EntryType::Regular,
            0o644,
        )]));
        let digest = Sha256Hex::from_bytes(&app);
        let composed = candidate.with_application_archive(&app, &digest).unwrap();
        assert_eq!(composed.application_archive_sha256(), &digest);
        assert_eq!(
            std::fs::read(composed.root().join("srv/app/main.py")).unwrap(),
            b"print('ready')\n"
        );
        let out = tempfile::tempdir().unwrap();
        let image = out.path().join("rootfs.ext4");
        assert!(
            composed
                .materialize_candidate(&image)
                .unwrap()
                .verity_root_hash
                .is_some()
        );
        assert_eq!(
            mvm_fs::tree_diff::Ext4Tree::open(&image)
                .unwrap()
                .read_regular_file_no_symlinks("srv/app/main.py", 128)
                .unwrap(),
            b"print('ready')\n"
        );

        let missing_policy = ComposedWorkloadRootfs {
            tree: ComposedRuntimeLayers::new(vec![
                PackPin::new(
                    "runtime/example@1.0.0".parse().unwrap(),
                    Sha256Hex::from_bytes(b"signed runtime manifest"),
                )
                .unwrap(),
            ])
            .unwrap(),
            base_manifest_sha256: Sha256Hex::from_bytes(b"test base"),
            profile: WorkloadImageProfile::DefaultTenant,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        }
        .with_application_archive(&app, &digest)
        .unwrap();
        let refused = out.path().join("refused.ext4");
        assert!(matches!(
            missing_policy.materialize_candidate(&refused),
            Err(RuntimeLayerStageError::InconsistentLayers)
        ));
        assert!(
            !refused.exists(),
            "no image may be materialized without signed policy inputs"
        );

        let candidate = ComposedWorkloadRootfs {
            tree: ComposedRuntimeLayers::new(Vec::new()).unwrap(),
            base_manifest_sha256: Sha256Hex::from_bytes(b"test base"),
            profile: WorkloadImageProfile::DefaultTenant,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        };
        assert!(matches!(
            candidate.with_application_archive(&app, &Sha256Hex::from_bytes(b"wrong")),
            Err(RuntimeLayerStageError::ApplicationDigest)
        ));
        let candidate = ComposedWorkloadRootfs {
            tree: ComposedRuntimeLayers::new(Vec::new()).unwrap(),
            base_manifest_sha256: Sha256Hex::from_bytes(b"test base"),
            profile: WorkloadImageProfile::DefaultTenant,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        };
        let forbidden = make_gzip(archive(&[(
            "etc/mvm/entrypoint",
            b"bad",
            tar::EntryType::Regular,
            0o644,
        )]));
        assert!(matches!(
            candidate.with_application_archive(&forbidden, &Sha256Hex::from_bytes(&forbidden)),
            Err(RuntimeLayerStageError::Unsupported(_))
        ));
        let candidate = ComposedWorkloadRootfs {
            tree: ComposedRuntimeLayers::new(Vec::new()).unwrap(),
            base_manifest_sha256: Sha256Hex::from_bytes(b"test base"),
            profile: WorkloadImageProfile::DefaultTenant,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        };
        let symlink = make_gzip(archive(&[(
            "srv/app/entrypoint",
            b"",
            tar::EntryType::Symlink,
            0o777,
        )]));
        assert!(matches!(
            candidate.with_application_archive(&symlink, &Sha256Hex::from_bytes(&symlink)),
            Err(RuntimeLayerStageError::Unsupported(_))
        ));
        let candidate = ComposedWorkloadRootfs {
            tree: ComposedRuntimeLayers::new(Vec::new()).unwrap(),
            base_manifest_sha256: Sha256Hex::from_bytes(b"test base"),
            profile: WorkloadImageProfile::DefaultTenant,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        };
        let mut appended = app.clone();
        appended.extend_from_slice(b"unexamined archive bytes");
        assert!(matches!(
            candidate.with_application_archive(&appended, &Sha256Hex::from_bytes(&appended)),
            Err(RuntimeLayerStageError::Unsupported(
                "compressed tar has trailing gzip members or bytes"
            ))
        ));
    }

    #[test]
    fn signed_set_composition_fetches_and_checks_the_production_base() {
        use std::io::Write as _;

        use crate::published_image_set::{PublishedImageSet, fixture::ImageSetFixture};
        use mvm_core::image_set::{
            ArtifactFormat, BaseImageContract, ImageSetRole, MemberTarget, WorkloadImageProfile,
        };

        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let served = tempfile::tempdir().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&base_tar(b"1\n", 901)).unwrap();
        let real_tar = std::env::var_os("MVM_TEST_SIGNED_BASE_TAR").map(PathBuf::from);
        let compressed = match &real_tar {
            Some(path) => std::fs::read(path).unwrap(),
            None => encoder.finish().unwrap(),
        };
        let arch = if real_tar.is_some() {
            GuestArch::X86_64
        } else {
            GuestArch::Aarch64
        };
        let kernel = match std::env::var_os("MVM_TEST_SIGNED_BASE_KERNEL") {
            Some(path) if real_tar.is_some() => std::fs::read(path).unwrap(),
            None if real_tar.is_none() => b"kernel".to_vec(),
            _ => panic!("real composition tar and boot kernel must be supplied together"),
        };
        let target = MemberTarget::Arch(arch);
        let profile = WorkloadImageProfile::DefaultTenant;
        let root = ImageSetRole::WorkloadRootfs(profile);
        let base = format!("base-rootfs-{arch}");
        let fixture = ImageSetFixture::complete()
            .with_base_image_contract(Some(BaseImageContract::LINUX_LAYER))
            .publish(
                ImageSetRole::WorkloadKernel(profile),
                target,
                &format!("base-vmlinux-{arch}"),
                kernel,
            )
            .publish(root, target, &format!("{base}.ext4"), b"ext4".to_vec())
            .publish_extra(root, target, &format!("{base}.verity"), b"verity".to_vec())
            .with_artifact_format(&format!("{base}.verity"), ArtifactFormat::VerityHashTree)
            .publish_extra(root, target, &format!("{base}.roothash"), b"hash".to_vec())
            .with_artifact_format(&format!("{base}.roothash"), ArtifactFormat::VerityRootHash)
            .publish_extra(root, target, &format!("{base}.tar.gz"), compressed);
        let images = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();
        if let Some(directory) = std::env::var_os("MVM_TEST_SIGNED_BASE_DIR") {
            let directory = PathBuf::from(directory);
            let manifest = directory.join("image-set.json");
            let tar = directory.join("rootfs.tar.gz");
            if std::env::var_os("MVM_TEST_SIGNED_BASE_VERIFY").is_some() {
                let signed = std::fs::read(&manifest).unwrap();
                assert_eq!(signed, images.manifest_bytes(), "signed root changed");
                let bundle = std::fs::read(directory.join("image-set.bundle")).unwrap();
                let identity = std::env::var("MVM_TEST_SIGNED_BASE_IDENTITY").unwrap();
                mvm_core::crypto::image_verify::verify_signed_payload_under_any_identity(
                    &signed,
                    &bundle,
                    &[identity.as_str()],
                    "https://token.actions.githubusercontent.com",
                )
                .expect("test-only OIDC signature, never a production publisher");
                let fetched = tempfile::tempdir().unwrap();
                let digest = images
                    .fetch_workload_composition_tar(
                        arch,
                        profile,
                        &fetched.path().join("base.tar.gz"),
                    )
                    .unwrap();
                assert_eq!(Sha256Hex::from_bytes(&std::fs::read(&tar).unwrap()), digest);
                if let Some(kernel_path) = std::env::var_os("MVM_TEST_SIGNED_BASE_KERNEL") {
                    let kernel_member = images
                        .manifest()
                        .members
                        .iter()
                        .find(|member| {
                            member.role == ImageSetRole::WorkloadKernel(profile)
                                && member.target == target
                                && member.build_mode.is_none()
                        })
                        .unwrap();
                    let [kernel] = kernel_member.artifacts.as_slice() else {
                        panic!("synthetic signed root must name one boot kernel");
                    };
                    images
                        .fetch_artifact(kernel, &fetched.path().join("kernel"))
                        .unwrap();
                    assert_eq!(
                        Sha256Hex::from_bytes(&std::fs::read(kernel_path).unwrap()),
                        kernel.sha256
                    );
                }
            } else {
                std::fs::create_dir(&directory).unwrap();
                std::fs::write(&manifest, images.manifest_bytes()).unwrap();
                images
                    .fetch_workload_composition_tar(arch, profile, &tar)
                    .unwrap();
            }
        }
        let mut composed =
            compose_signed_workload_tree_with(&images, arch, profile, &[], |_| Ok(())).unwrap();
        if real_tar.is_none() {
            assert_eq!(
                std::fs::read(composed.root().join("usr/bin/sh")).unwrap(),
                b"busybox"
            );
        }
        assert_eq!(composed.ownership().owner_of("/home/mvm-worker").uid, 901);
        assert_eq!(
            composed.base_manifest_sha256(),
            &Sha256Hex::from_bytes(images.manifest_bytes())
        );
        assert!(composed.runtime_pins().is_empty());

        // Synthetic publisher fixture only: exercise actual v2 source -> tar ->
        // base composition -> verity bytes without claiming a signed boot.
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("main.py"), b"print('ready')\n").unwrap();
        let probe = project.path().join("probe.sh");
        std::fs::write(
            &probe,
            b"#!/usr/bin/sh\nIFS= read -r value < /srv/app/main.py\nprintf 'COMPOSED_GUEST_VALUE=%s\\n' \"$value\"\n",
        ).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let spec: ComposablePackSpec = serde_json::from_value(serde_json::json!({
            "schema": "mvm.pack-spec/v2",
            "identity": {"name": "agent/example", "version": "1.0.0"},
            "target": if arch == GuestArch::X86_64 { "x86_64-linux" } else { "aarch64-linux" },
            "source": {"kind": "local", "path": "."},
            "runtimes": [],
            "copy": [
                {"source": "main.py", "destination": "/srv/app/main.py"},
                {"source": "probe.sh", "destination": "/srv/app/probe.sh"}
            ],
            "entrypoint": ["/srv/app/probe.sh"],
            "resources": {"cpu_cores": 1, "memory_mb": 256},
            "production": {}
        }))
        .unwrap();
        composed.authored_spec_sha256 =
            Some(Sha256Hex::from_bytes(&spec.canonical_json().unwrap()));
        let prepared =
            mvm_sdk::pack::composable::prepare_composable_application(&spec, project.path())
                .unwrap();
        let digest = Sha256Hex::new(prepared.archive_sha256().to_owned()).unwrap();
        let application = composed
            .with_application_archive(prepared.archive_bytes(), &digest)
            .unwrap();
        prepared.reverify().unwrap();
        let source_sha256 = Sha256Hex::new(prepared.source_sha256().to_owned()).unwrap();
        let revision = "a".repeat(40);
        let unbound = ComposedWorkloadRootfs {
            tree: ComposedRuntimeLayers::new(Vec::new()).unwrap(),
            base_manifest_sha256: Sha256Hex::from_bytes(b"unbound"),
            profile,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        }
        .with_application_archive(prepared.archive_bytes(), &digest)
        .unwrap();
        assert!(matches!(
            unbound.resolved_lock(&spec, &source_sha256, &revision),
            Err(RuntimeLayerStageError::InconsistentLayers)
        ));
        let unbound_policy = ComposedWorkloadRootfs {
            tree: ComposedRuntimeLayers::new(vec![
                PackPin::new(
                    "runtime/python@1.0.0".parse().unwrap(),
                    Sha256Hex::from_bytes(b"runtime manifest"),
                )
                .unwrap(),
            ])
            .unwrap(),
            base_manifest_sha256: Sha256Hex::from_bytes(b"test base"),
            profile,
            authored_spec_sha256: Some(Sha256Hex::from_bytes(&spec.canonical_json().unwrap())),
            runtime_policies: Vec::new(),
        }
        .with_application_archive(prepared.archive_bytes(), &digest)
        .unwrap();
        assert!(matches!(
            unbound_policy.resolved_lock(&spec, &source_sha256, &revision),
            Err(RuntimeLayerStageError::InconsistentLayers)
        ));
        let lock = application
            .resolved_lock(&spec, &source_sha256, &revision)
            .unwrap();
        let locked_bytes = serde_json::to_vec(&lock).unwrap();
        let restored: ResolvedComposableLock = serde_json::from_slice(&locked_bytes).unwrap();
        restored.verify_current(&lock).unwrap();
        let filesystem = restored.filesystem_identity().unwrap();
        let mut command_only = lock.clone();
        command_only.spec_sha256 = Sha256Hex::from_bytes(b"another admitted command");
        assert_ne!(command_only, lock);
        assert_eq!(command_only.filesystem_identity().unwrap(), filesystem);
        let mut changed = lock.clone();
        changed.source_tree_sha256 = Sha256Hex::from_bytes(b"edited source");
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        changed = lock.clone();
        changed.base_manifest_sha256 = Sha256Hex::from_bytes(b"replaced base");
        assert_ne!(changed.filesystem_identity().unwrap(), filesystem);
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        changed = lock.clone();
        changed.application_archive_sha256 = Sha256Hex::from_bytes(b"changed application");
        assert_ne!(changed.filesystem_identity().unwrap(), filesystem);
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        changed = lock.clone();
        changed.producer_revision = "b".repeat(40);
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        changed = lock.clone();
        changed.runtime_pins.push(
            PackPin::new(
                "runtime/python@1.0.0".parse().unwrap(),
                Sha256Hex::from_bytes(b"another runtime manifest"),
            )
            .unwrap(),
        );
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        changed = lock.clone();
        changed.profile = WorkloadImageProfile::RootlessTenant;
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        let mut dev = spec.clone();
        dev.production = None;
        assert!(matches!(
            application.resolved_lock(&dev, &source_sha256, &revision),
            Err(RuntimeLayerStageError::AuthoredSpec(
                ComposablePackError::ProductionNotSelected
            ))
        ));
        assert!(
            application
                .development_lock(&dev, &source_sha256, &revision)
                .is_err(),
            "a dev lock still must bind the exact authored spec used for composition"
        );
        let mut changed_spec = spec.clone();
        changed_spec.entrypoint[0] = "/bin/other".into();
        assert!(matches!(
            application.resolved_lock(&changed_spec, &source_sha256, &revision),
            Err(RuntimeLayerStageError::InconsistentLayers)
        ));
        assert!(matches!(
            application.resolved_lock(&spec, &source_sha256, "unpinned"),
            Err(RuntimeLayerStageError::InconsistentLayers)
        ));
        let mut unknown: serde_json::Value = serde_json::from_slice(&locked_bytes).unwrap();
        unknown["network"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ResolvedComposableLock>(unknown).is_err());
        let mut unsupported: serde_json::Value = serde_json::from_slice(&locked_bytes).unwrap();
        unsupported["schema"] = serde_json::json!("mvm.composable-pack-lock/v0");
        assert!(serde_json::from_value::<ResolvedComposableLock>(unsupported).is_err());
        let out = tempfile::tempdir().unwrap();
        let image = out.path().join("rootfs.ext4");
        assert!(
            application
                .materialize_candidate(&image)
                .unwrap()
                .verity_root_hash
                .is_some()
        );
        assert_eq!(
            mvm_fs::tree_diff::Ext4Tree::open(&image)
                .unwrap()
                .read_regular_file_no_symlinks("srv/app/main.py", 128)
                .unwrap(),
            b"print('ready')\n"
        );
        if real_tar.is_some() && std::env::var_os("MVM_TEST_SIGNED_BASE_VERIFY").is_some() {
            let directory = PathBuf::from(std::env::var_os("MVM_TEST_SIGNED_BASE_DIR").unwrap());
            std::fs::copy(&image, directory.join("composed.ext4")).unwrap();
        }
        let mut development = application;
        development.tree.authored_spec_sha256 =
            Some(Sha256Hex::from_bytes(&dev.canonical_json().unwrap()));
        assert_eq!(
            development
                .development_lock(&dev, &source_sha256, &revision)
                .unwrap()
                .base_manifest_sha256(),
            lock.base_manifest_sha256()
        );
    }

    #[test]
    fn authored_candidate_requires_its_runtime_before_base_acquisition() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let served = tempfile::tempdir().unwrap();
        let images = crate::published_image_set::PublishedImageSet::acquire_from(
            crate::published_image_set::fixture::ImageSetFixture::complete()
                .serve_from(served.path()),
        )
        .unwrap();
        let spec: ComposablePackSpec = serde_json::from_value(serde_json::json!({
            "schema": "mvm.pack-spec/v2",
            "identity": {"name": "agent/example", "version": "1.0.0"},
            "target": "aarch64-linux",
            "source": {"kind": "local", "path": "."},
            "runtimes": ["runtime/python"],
            "copy": [{"source": "main.py", "destination": "/srv/app/main.py"}],
            "entrypoint": ["/usr/bin/python3", "/srv/app/main.py"],
            "resources": {"cpu_cores": 1, "memory_mb": 256}
        }))
        .unwrap();
        assert!(matches!(
            compose_authored_candidate(&spec, &images, WorkloadImageProfile::DefaultTenant, &[]),
            Err(RuntimeLayerStageError::RequestedRuntime(
                RuntimeLayerResolveError::Missing(_)
            ))
        ));
    }

    #[test]
    fn nix_generated_base_tar_materializes_with_verity_when_provided() {
        let Some(path) = std::env::var_os("MVM_TEST_COMPOSITION_TAR") else {
            return;
        };
        let decoder = flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap());
        let mut tar = tempfile::tempfile().unwrap();
        io::copy(&mut decoder.take(MAX_UNPACKED_BYTES + 1), &mut tar).unwrap();
        tar.seek(SeekFrom::Start(0)).unwrap();
        let mut composed = ComposedRuntimeLayers::new(Vec::new()).unwrap();
        let extracted = composed.add_base_tar(&mut tar);
        if std::env::var_os("MVM_TEST_EXPECT_CASEFOLD_REFUSAL").is_some() {
            assert!(matches!(
                extracted,
                Err(RuntimeLayerStageError::CaseFolding)
            ));
            return;
        }
        extracted.unwrap();
        check_base_contract(&composed).unwrap();
        let candidate = ComposedWorkloadRootfs {
            tree: composed,
            base_manifest_sha256: Sha256Hex::from_bytes(b"local test-only Nix base"),
            profile: WorkloadImageProfile::DefaultTenant,
            authored_spec_sha256: None,
            runtime_policies: Vec::new(),
        };
        let output = tempfile::tempdir().unwrap();
        let ext4 = output.path().join("rootfs.ext4");
        let materialized = candidate.materialize_candidate(&ext4).unwrap();
        assert!(materialized.verity_root_hash.is_some());
        let image = mvm_fs::tree_diff::Ext4Tree::open(&ext4).unwrap();
        assert_eq!(
            image
                .read_regular_file_no_symlinks("etc/mvm/base-image-contract", 2)
                .unwrap(),
            b"1\n"
        );
        if let Some(original) = std::env::var_os("MVM_TEST_COMPOSITION_ROOTFS") {
            let diff = mvm_fs::tree_diff::diff_images(
                Path::new(&original),
                &ext4,
                mvm_fs::tree_diff::DiffLimits::default(),
            )
            .unwrap();
            assert_eq!(
                diff.stats.changed(),
                0,
                "composition changed Nix base files or modes: {:?}",
                diff.files.iter().take(8).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn tar_inventory_refuses_path_expansion_and_non_directory_ancestors() {
        let oversized = format!("bin/{}", "x".repeat(MAX_PATH_BYTES));
        let tar = archive(&[(&oversized, b"x", tar::EntryType::Regular, 0o755)]);
        assert!(stage_tar(&mut Cursor::new(tar)).is_err());
        let tar = archive(&[
            ("usr/bin", b"file", tar::EntryType::Regular, 0o755),
            ("usr/bin/python3", b"python", tar::EntryType::Regular, 0o755),
        ]);
        assert!(stage_tar(&mut Cursor::new(tar)).is_err());
    }
}
