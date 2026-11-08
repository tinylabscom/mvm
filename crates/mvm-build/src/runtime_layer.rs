//! Stage a signed runtime pack's files without booting or invoking Nix.
//!
//! Layers are unpacked alone, not on top of the base. A later composer must
//! check path ownership and policy before incorporating this staged tree.

use std::collections::{BTreeMap, HashSet};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use mvm_contract::pack_spec::PackTarget;
use mvm_contract::pack_spec_v2::{BuildMode, ComposablePackError, ComposablePackSpec};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::WorkloadImageProfile;
use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::runtime_layer::{
    RuntimeLayerArchiveError, RuntimeLayerInputError, RuntimeLayerPolicyError,
    RuntimeLayerResolveError, VerifiedRuntimeLayerArchive, VerifiedRuntimeLayerInputs,
    VerifiedRuntimeLayerPolicies, resolve_requested_runtime_layers,
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
        let spec_sha256 = Sha256Hex::from_bytes(&spec.canonical_json()?);
        if self.tree.authored_spec_sha256.as_ref() != Some(&spec_sha256)
            || self.tree.runtime_policies.len() != self.tree.runtime_pins().len()
            || self
                .tree
                .runtime_policies
                .iter()
                .zip(self.tree.runtime_pins())
                .any(|(policy, pin)| policy.descriptor().manifest_sha256() != pin.manifest_sha256())
            || producer_revision.len() != 40
            || !producer_revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RuntimeLayerStageError::InconsistentLayers);
        }
        for policy in &self.tree.runtime_policies {
            policy.reverify()?;
        }
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
    /// Refuses a changed tree or a directory that can no longer be restored.
    pub fn materialize_candidate(
        &self,
        output: &Path,
    ) -> Result<crate::rootfs::MaterializedExt4, RuntimeLayerStageError> {
        self.tree.restore_base_directory_modes()?;
        let input = crate::rootfs::MaterializeExt4Input::new(
            self.root().to_path_buf(),
            output.to_path_buf(),
            0,
        )
        .with_owners(self.ownership().clone())
        .with_verity();
        Ok(crate::rootfs::materialize_ext4_pure(&input)?)
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
    #[error("signed base acquisition failed: {0}")]
    Base(#[from] anyhow::Error),
    #[error("signed base composition source has invalid contract or ownership")]
    BaseContract,
    #[error("application archive bytes do not match the resolved input digest")]
    ApplicationDigest,
    #[error("composable pack inputs differ from the frozen lock")]
    StaleLock,
    #[error(transparent)]
    Materialize(#[from] crate::rootfs::RootfsError),
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
    spec.validate()?;
    for input in inputs {
        input.policies().reverify()?;
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
    let mut composed = compose_signed_workload_tree(images, arch, profile, &archives)?;
    for input in inputs {
        // add_runtime_archives already rehashes each archive before and after
        // extraction; the small signed policy bytes still need a final check.
        input.policies().reverify()?;
    }
    composed.authored_spec_sha256 = Some(Sha256Hex::from_bytes(&spec.canonical_json()?));
    composed.runtime_policies = inputs
        .iter()
        .map(|input| input.policies().clone())
        .collect();
    Ok(composed)
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
        let compressed = encoder.finish().unwrap();
        let arch = GuestArch::Aarch64;
        let target = MemberTarget::Arch(arch);
        let profile = WorkloadImageProfile::DefaultTenant;
        let root = ImageSetRole::WorkloadRootfs(profile);
        let fixture = ImageSetFixture::complete()
            .with_base_image_contract(Some(BaseImageContract::LINUX_LAYER))
            .publish(
                ImageSetRole::WorkloadKernel(profile),
                target,
                "base-vmlinux-aarch64",
                b"kernel".to_vec(),
            )
            .publish(root, target, "base-rootfs-aarch64.ext4", b"ext4".to_vec())
            .publish_extra(
                root,
                target,
                "base-rootfs-aarch64.verity",
                b"verity".to_vec(),
            )
            .with_artifact_format("base-rootfs-aarch64.verity", ArtifactFormat::VerityHashTree)
            .publish_extra(
                root,
                target,
                "base-rootfs-aarch64.roothash",
                b"hash".to_vec(),
            )
            .with_artifact_format(
                "base-rootfs-aarch64.roothash",
                ArtifactFormat::VerityRootHash,
            )
            .publish_extra(root, target, "base-rootfs-aarch64.tar.gz", compressed);
        let images = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();
        let mut composed =
            compose_signed_workload_tree_with(&images, arch, profile, &[], |_| Ok(())).unwrap();
        assert_eq!(
            std::fs::read(composed.root().join("usr/bin/sh")).unwrap(),
            b"busybox"
        );
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
        let spec: ComposablePackSpec = serde_json::from_value(serde_json::json!({
            "schema": "mvm.pack-spec/v2",
            "identity": {"name": "agent/example", "version": "1.0.0"},
            "target": "aarch64-linux",
            "source": {"kind": "local", "path": "."},
            "runtimes": [],
            "copy": [{"source": "main.py", "destination": "/srv/app/main.py"}],
            "entrypoint": ["/usr/bin/sh", "/srv/app/main.py"],
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
        let mut changed = lock.clone();
        changed.source_tree_sha256 = Sha256Hex::from_bytes(b"edited source");
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        changed = lock.clone();
        changed.base_manifest_sha256 = Sha256Hex::from_bytes(b"replaced base");
        assert!(matches!(
            restored.verify_current(&changed),
            Err(RuntimeLayerStageError::StaleLock)
        ));
        changed = lock.clone();
        changed.application_archive_sha256 = Sha256Hex::from_bytes(b"changed application");
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
