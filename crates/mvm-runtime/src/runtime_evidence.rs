//! Bind authenticated guest-runtime snapshots to detached launch lifetimes.
//!
//! Persisted declarations are diagnostic records, not verification authority.
//! Backends currently cannot prove a generation-specific stop, so snapshots
//! are retained even after a successful stop rather than risking active reads.

use anyhow::{Context, Result, bail};
use mvm_build::guest_bins::assembly::RuntimeAssembly;
use mvm_build::guest_runtime::evidence::{
    RuntimeArtifactSelection, VerifiedRuntimeArtifacts, VerifiedRuntimeManifest,
    verify_runtime_release_proof,
};
use mvm_build::guest_runtime::source::{CheckedSourceRuntime, check_source_runtime};
use mvm_core::arch::GuestArch;
use mvm_core::plan::{RuntimeArtifactDigests, RuntimeIdentity};
use mvm_core::protocol::runtime_release::{
    CliRuntimeLaunchBinding, RuntimeBindingProvenance, RuntimeLaunchBinding,
};
use mvm_core::util::atomic_io::write_private_new;
use mvm_core::vm_backend::VmStartConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod namespace;
mod retire;
use namespace::{check_owner, private_directory, sync_dir, sync_file};
pub use retire::remove_retired_vm_evidence;

/// Guest RPC compatibility, distinct from the host instance-control protocol.
pub const MIN_GUEST_RPC_PROTOCOL_VERSION: u32 = mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION;
/// Current guest RPC version, not the host instance-control wire version.
pub const GUEST_RPC_PROTOCOL_VERSION: u32 = mvm_agentd::vsock::PROTOCOL_VERSION;

/// One launch's authenticated release archive and checked artifact selection.
///
/// This cannot be serialized or constructed from plan data. A separate launch
/// must verify its own release bytes, even inside a long-lived host process.
#[derive(Debug)]
pub struct VerifiedRuntimeSet {
    release: Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>,
    identity: RuntimeIdentity,
}

impl VerifiedRuntimeSet {
    /// The exact identity to compare with a signed plan and admission audit.
    pub fn identity(&self) -> &RuntimeIdentity {
        &self.identity
    }

    /// Borrow the verified archive through attachment and lifecycle custody.
    pub fn release(&self) -> &mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime {
        &self.release
    }

    /// Refuse a config that diverged from the selection this launch verified.
    pub fn verify_config(&self, config: &VmStartConfig) -> Result<()> {
        anyhow::ensure!(
            config.runtime_release_proof.as_ref() == Some(self.release.proof())
                && config.runtime_overlay_version.as_deref()
                    == Some(self.identity.version.as_str())
                && config.runtime_overlay_roothash.as_deref()
                    == Some(self.identity.declaration.overlay_roothash.as_str()),
            "runtime proof identity changed"
        );
        Ok(())
    }
}

/// Complete one release-runtime verification after overlay and initramfs attach.
/// No artifact path or serialized proof can mint the returned authority.
pub fn verify_release_runtime_set(
    config: &VmStartConfig,
    release: Arc<mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime>,
) -> Result<VerifiedRuntimeSet> {
    let identity = verified_release_identity(config, &release, MIN_GUEST_RPC_PROTOCOL_VERSION)?;
    Ok(VerifiedRuntimeSet { release, identity })
}

/// Authenticate an already selected release once when a caller did not attach
/// it from the ordinary versioned cache in this process.
pub fn verify_selected_release_runtime_set(
    config: &VmStartConfig,
) -> Result<Option<VerifiedRuntimeSet>> {
    let Some(proof) = &config.runtime_release_proof else {
        return Ok(None);
    };
    let release = mvm_build::guest_runtime::evidence::verify_release_runtime(
        proof.clone(),
        config
            .runtime_overlay_version
            .as_deref()
            .context("selected guest runtime has no version")?,
        GuestArch::host(),
    )?;
    verify_release_runtime_set(config, Arc::new(release)).map(Some)
}

/// Checked launch inputs retain their assurance tier through admission.
/// Source integrity is deliberately not signed release provenance.
#[derive(Debug)]
pub enum VerifiedLaunchRuntime {
    Release(Box<VerifiedRuntimeManifest>),
    Source(CheckedSourceRuntime),
    LegacyBundle(crate::legacy_bundle_runtime::VerifiedLegacyBundleRuntime),
    LegacyPortable(crate::legacy_portable_runtime::VerifiedLegacyPortableRuntime),
}

impl VerifiedLaunchRuntime {
    pub fn is_release(&self) -> bool {
        matches!(self, Self::Release(_))
    }

    pub fn declaration(&self, arch: GuestArch) -> Result<&RuntimeAssembly> {
        match self {
            Self::Release(runtime) => Ok(runtime.declaration(arch)?),
            Self::Source(runtime) => Ok(runtime.declaration(arch)?),
            Self::LegacyBundle(_) | Self::LegacyPortable(_) => {
                bail!("a legacy runtime has no CLI runtime assembly")
            }
        }
    }
}

enum CheckedLaunchRuntime<'a> {
    Release(&'a VerifiedRuntimeManifest),
    Source(&'a CheckedSourceRuntime),
    LegacyBundle(&'a crate::legacy_bundle_runtime::VerifiedLegacyBundleRuntime),
    LegacyPortable(&'a crate::legacy_portable_runtime::VerifiedLegacyPortableRuntime),
}

impl<'a> From<&'a VerifiedLaunchRuntime> for CheckedLaunchRuntime<'a> {
    fn from(runtime: &'a VerifiedLaunchRuntime) -> Self {
        match runtime {
            VerifiedLaunchRuntime::Release(release) => Self::Release(release),
            VerifiedLaunchRuntime::Source(source) => Self::Source(source),
            VerifiedLaunchRuntime::LegacyBundle(bundle) => Self::LegacyBundle(bundle),
            VerifiedLaunchRuntime::LegacyPortable(portable) => Self::LegacyPortable(portable),
        }
    }
}

impl CheckedLaunchRuntime<'_> {
    fn is_release(&self) -> bool {
        matches!(self, Self::Release(_))
    }

    fn snapshot_artifacts_in(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
        parent: &Path,
        shared: &Path,
    ) -> Result<VerifiedRuntimeArtifacts> {
        match self {
            Self::Release(runtime) => {
                Ok(runtime.snapshot_artifacts_shared_in(selection, parent, shared)?)
            }
            Self::Source(runtime) => {
                Ok(runtime.snapshot_artifacts_shared_in(selection, parent, shared)?)
            }
            Self::LegacyBundle(_) | Self::LegacyPortable(_) => {
                bail!("a legacy runtime has no CLI runtime assembly")
            }
        }
    }
}

fn checked_source(
    version: &str,
    arch: GuestArch,
    bound_home: Option<&Path>,
    expected_archive_sha256: Option<&str>,
) -> Result<CheckedSourceRuntime> {
    if !mvm_build::artifact_acquisition::compiled_channel().permits_automatic_builds() {
        bail!("selected runtime requires a signed release proof for this compiled channel");
    }
    let cache = match bound_home {
        Some(home) => namespace::source_cache_at(home)?,
        None => namespace::source_cache_root()?,
    };
    let checked = check_source_runtime(&cache, version, arch)?;
    if let Some(expected) = expected_archive_sha256
        && expected != checked.archive_sha256()
    {
        bail!("source runtime archive differs from the originally selected archive");
    }
    Ok(checked)
}

/// Bind a warm child's requested runtime to its authenticated parent record.
/// The caller must authenticate the parent checkpoint before invoking this.
pub fn verify_runtime_for_claim(
    parent: &crate::checkpoint::VerifiedRetainedRuntime,
    requested: Option<&VmStartConfig>,
) -> Result<()> {
    let Some(parent) = parent.binding() else {
        if let Some(config) = requested
            && requires_runtime_proof(config)?
        {
            bail!("warm parent has no authenticated runtime binding");
        }
        return Ok(());
    };
    let RuntimeLaunchBinding::CliAssembly(parent_assembly) = parent else {
        bail!("legacy bundle runtime does not support warm claims");
    };
    let config = requested.context("warm runtime claim requires its launch configuration")?;
    if config.runtime_overlay_version.as_deref() != Some(parent_assembly.version())
        || config.runtime_overlay_roothash.as_deref()
            != Some(parent_assembly.overlay_roothash.as_str())
    {
        bail!("warm child requested a different runtime version or verity root");
    }
    if config.runtime_release_proof.is_some() != parent_assembly.release_proof().is_some() {
        bail!("warm child cannot change its parent's runtime provenance tier");
    }
    if let RuntimeBindingProvenance::Source { archive_sha256, .. } = &parent_assembly.provenance {
        // The checked parent owns the retained runtime. A child may carry no
        // source-cache pin, but a pin it does carry must name that same archive.
        if config
            .source_runtime_archive_sha256
            .as_deref()
            .is_some_and(|requested| requested != archive_sha256)
        {
            bail!("warm child requested a different source archive");
        }
        return Ok(());
    }
    check_runtime_provenance(config)?;
    if let (Some(requested), Some(actual)) = (
        config.runtime_release_proof.as_ref(),
        parent_assembly.release_proof(),
    ) && requested.archive_sha256 != actual.archive_sha256
    {
        bail!("warm child requested a different release archive");
    }
    Ok(())
}

/// Reverify a retained generation without changing or recopying it. Release
/// provenance requires a signature; source provenance requires the compiled
/// contributor channel and current checked source cache.
///
/// Callers must separately authenticate the checkpoint and compare its actual
/// restored devices to this binding. This function grants neither checkpoint
/// authenticity nor permission to delete. The host account is trusted not to
/// chmod or replace its private generations; mvm never modifies them in place.
pub fn verify_runtime_binding(binding: &RuntimeLaunchBinding) -> Result<()> {
    verify_retained_runtime_identity(binding).map(|_| ())
}

/// Return a release identity only after checking its retained generation.
pub(crate) fn verify_retained_runtime_identity(
    binding: &RuntimeLaunchBinding,
) -> Result<Option<RuntimeIdentity>> {
    if matches!(binding, RuntimeLaunchBinding::LegacyPortable { .. }) {
        let mut config = VmStartConfig::default();
        binding.apply_to_config(&mut config);
        let verified = verify_retained_portable_runtime(&config)?;
        anyhow::ensure!(
            mvm_core::crypto::image_verify::sha256_file(Path::new(&config.rootfs_path))?
                == verified.rootfs_sha256(),
            "retained portable rootfs differs from signed bundle"
        );
        return Ok(None);
    }
    let RuntimeLaunchBinding::CliAssembly(binding) = binding else {
        let mut config = VmStartConfig::default();
        binding.apply_to_config(&mut config);
        verify_retained_legacy_runtime(&config)?;
        return Ok(None);
    };
    let root = validate_generation_paths(binding)?;
    if binding.arch() != GuestArch::host() {
        bail!("retained runtime has the wrong guest architecture");
    }
    let verified = match &binding.provenance {
        RuntimeBindingProvenance::Release { proof } => VerifiedLaunchRuntime::Release(Box::new(
            verify_runtime_release_proof(proof, binding.version(), GuestArch::host())?,
        )),
        RuntimeBindingProvenance::Source {
            version,
            arch,
            archive_sha256,
        } => VerifiedLaunchRuntime::Source(checked_source(
            version,
            *arch,
            Some(root.parent().context("runtime root has no home")?),
            Some(archive_sha256),
        )?),
    };
    let declaration = verified.declaration(GuestArch::host())?;
    if declaration.protocol_version < MIN_GUEST_RPC_PROTOCOL_VERSION
        || declaration.min_supported_protocol_version > GUEST_RPC_PROTOCOL_VERSION
        || declaration.overlay_roothash != binding.overlay_roothash
    {
        bail!("retained runtime declaration does not match the requested launch");
    }
    for (path, expected) in [
        (&binding.overlay_path, &declaration.overlay_sha256),
        (
            &binding.overlay_verity_path,
            &declaration.overlay_verity_sha256,
        ),
        (&binding.initramfs_path, &declaration.initramfs_sha256),
    ] {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() > 1024 * 1024 * 1024
            || mvm_core::private_fs::mode_bits(path, &metadata)? != 0o400
        {
            bail!("retained runtime artifact is not a private read-only regular file");
        }
        check_owner(&metadata)?;
        if mvm_core::crypto::verified_digest::sha256_open_file_verified(&file)? != *expected {
            bail!("retained runtime artifact differs from its checked declaration");
        }
    }
    let digests = RuntimeArtifactDigests {
        overlay_sha256: declaration.overlay_sha256.clone(),
        overlay_verity_sha256: declaration.overlay_verity_sha256.clone(),
        overlay_roothash: declaration.overlay_roothash.clone(),
        initramfs_sha256: declaration.initramfs_sha256.clone(),
    };
    let (RuntimeBindingProvenance::Release { proof }, VerifiedLaunchRuntime::Release(manifest)) =
        (&binding.provenance, &verified)
    else {
        return Ok(None);
    };
    Ok(Some(RuntimeIdentity {
        archive_sha256: proof.archive_sha256.clone(),
        version: proof.version.clone(),
        arch: proof.arch.to_string(),
        declaration: digests.clone(),
        selected: digests,
        signer_identity: manifest.signer().identity.clone(),
        signer_issuer: manifest.signer().issuer.clone(),
    }))
}

/// Checked-source runtime evidence for integration fixtures: a bound
/// `VmStartConfig` and its `RuntimeLaunchBinding` in the retained-generation
/// layout the launch-time lease produces, rooted under the current `MVM_HOME`.
///
/// The bytes come from the public source-cache fixture assembled by the
/// ordinary overlay/initramfs builders, and every consumer still runs the real
/// verifiers against them — this exists so a harness can supply the
/// authenticated runtime the launch and claim paths require instead of
/// launching without one. The fixture binaries are placeholder bytes and must
/// never execute.
#[cfg(any(test, feature = "test-support"))]
pub fn checked_source_runtime_fixture(
    vm_name: &str,
    rootfs: &Path,
) -> Result<(VmStartConfig, RuntimeLaunchBinding)> {
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let workspace = mvm_build::image_source::guest_runtime_source_checkout()
        .context("a checked-source fixture requires the developer checkout")?;
    let version = env!("CARGO_PKG_VERSION");
    let arch = GuestArch::host();
    let runtime = mvm_build::guest_runtime::test_support::write_source_cache_fixture(
        &cache, &workspace, version, arch,
    )?;
    let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        &cache, version, arch, &runtime,
    )?;
    let initramfs =
        mvm_build::initramfs::build_initramfs_from_guest_runtime(&cache, version, arch, &runtime)?;

    // The retained-generation layout `RuntimeLifecycleLease::bind` produces:
    // private ancestry and read-only artifacts, both of which
    // `verify_runtime_binding` demands.
    let root = namespace::root(true)?;
    private_directory(&root.join(vm_name))?;
    let generation = root.join(vm_name).join("runtime-fixture");
    private_directory(&generation)?;
    for (source, name) in [
        (&overlay.overlay_ext4, "overlay.ext4"),
        (&overlay.sidecar, "overlay.verity"),
        (&initramfs.image_path, "initramfs.cpio.gz"),
    ] {
        let dest = generation.join(name);
        std::fs::copy(source, &dest).with_context(|| format!("stage fixture {name}"))?;
        mvm_core::private_fs::set_mode(&dest, 0o400)?;
    }

    let binding = RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
        provenance: RuntimeBindingProvenance::Source {
            version: version.to_owned(),
            arch,
            archive_sha256: runtime.digest,
        },
        overlay_path: generation.join("overlay.ext4"),
        overlay_verity_path: generation.join("overlay.verity"),
        initramfs_path: generation.join("initramfs.cpio.gz"),
        overlay_roothash: overlay.roothash,
    });
    let mut config = VmStartConfig {
        name: vm_name.to_owned(),
        rootfs_path: rootfs.display().to_string(),
        ..Default::default()
    };
    binding.apply_to_config(&mut config);
    Ok((config, binding))
}

/// Bind a signed legacy fixture into the same retained generation used at boot.
/// The returned binding is still untrusted until a checkpoint authenticates it.
#[cfg(any(test, feature = "test-support"))]
pub fn retained_legacy_runtime_fixture(
    config: &VmStartConfig,
) -> Result<(VmStartConfig, RuntimeLaunchBinding)> {
    let lease = RuntimeLifecycleLease::acquire(&config.name)?;
    let bound = lease.bind(config)?;
    let proof = bound
        .legacy_bundle_runtime
        .clone()
        .context("legacy fixture has no retained proof")?;
    let binding = RuntimeLaunchBinding::LegacyBundle {
        proof,
        rootfs_path: PathBuf::from(&bound.rootfs_path),
        initramfs_path: bound.initrd_path.as_ref().map(PathBuf::from),
    };
    Ok((bound, binding))
}

pub(crate) fn verify_retained_legacy_runtime(
    config: &VmStartConfig,
) -> Result<crate::legacy_bundle_runtime::VerifiedLegacyBundleRuntime> {
    let proof = config
        .legacy_bundle_runtime
        .as_ref()
        .context("legacy bundle proof missing")?;
    let generation = proof
        .archive
        .parent()
        .context("legacy generation missing")?;
    validate_legacy_generation(&generation.join("initrd"))?;
    validate_retained_file(&proof.archive, &generation.join("bundle.mvmpkg"))?;
    if let Some(path) = config.initrd_path.as_deref() {
        anyhow::ensure!(
            Path::new(path) == generation.join("initrd"),
            "legacy artifacts mix generations"
        );
        validate_legacy_generation(Path::new(path))?;
        validate_retained_file(Path::new(path), &generation.join("initrd"))?;
    }
    crate::legacy_bundle_runtime::verify_retained(config, MIN_GUEST_RPC_PROTOCOL_VERSION)
}

pub(crate) fn verify_retained_portable_runtime(
    config: &VmStartConfig,
) -> Result<crate::legacy_portable_runtime::VerifiedLegacyPortableRuntime> {
    let proof = config
        .legacy_portable_runtime
        .as_ref()
        .context("portable proof missing")?;
    let generation = proof
        .archive
        .parent()
        .context("portable generation missing")?;
    let root = namespace::root(false)?;
    let relative = generation
        .strip_prefix(&root)
        .context("portable generation outside retained storage")?;
    let parts: Vec<_> = relative.components().collect();
    let [
        std::path::Component::Normal(vm),
        std::path::Component::Normal(name),
    ] = parts.as_slice()
    else {
        bail!("portable generation is not one VM's direct generation");
    };
    mvm_core::naming::validate_vm_name(vm.to_str().context("non-UTF-8 VM name")?)?;
    anyhow::ensure!(
        name.to_str()
            .is_some_and(|name| name.starts_with("portable-runtime-")),
        "invalid portable generation name"
    );
    for directory in [root.clone(), root.join(vm), generation.to_path_buf()] {
        let metadata = std::fs::symlink_metadata(&directory)?;
        anyhow::ensure!(
            metadata.file_type().is_dir()
                && mvm_core::private_fs::mode_bits(&directory, &metadata)? == 0o700,
            "portable generation ancestry is not private"
        );
        check_owner(&metadata)?;
    }
    for (selected, name) in [
        (Some(proof.archive.as_path()), "bundle.mvmpkg"),
        (
            config.runtime_overlay_path.as_deref().map(Path::new),
            "overlay.ext4",
        ),
        (
            config.runtime_overlay_verity_path.as_deref().map(Path::new),
            "overlay.verity",
        ),
        (
            config.initrd_path.as_deref().map(Path::new),
            "initramfs.cpio.gz",
        ),
        (config.kernel_path.as_deref().map(Path::new), "kernel"),
    ] {
        let path = selected.context("portable retained selection missing")?;
        anyhow::ensure!(
            path == generation.join(name),
            "portable artifacts mix generations"
        );
        let metadata = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.file_type().is_file()
                && mvm_core::private_fs::mode_bits(path, &metadata)? == 0o400,
            "portable retained artifact is not private read-only"
        );
        check_owner(&metadata)?;
    }
    let verified =
        crate::legacy_portable_runtime::verify_retained(config, MIN_GUEST_RPC_PROTOCOL_VERSION)?;
    anyhow::ensure!(
        mvm_core::crypto::image_verify::sha256_file(Path::new(
            config
                .kernel_path
                .as_deref()
                .context("portable kernel missing")?
        ))? == verified.kernel_sha256(),
        "retained portable kernel differs from signed bundle"
    );
    Ok(verified)
}

fn validate_legacy_generation(path: &Path) -> Result<()> {
    let root = namespace::root(false)?;
    let relative = path
        .strip_prefix(&root)
        .context("legacy initrd is outside retained storage")?;
    let parts: Vec<_> = relative.components().collect();
    let [
        std::path::Component::Normal(vm),
        std::path::Component::Normal(generation),
        std::path::Component::Normal(file),
    ] = parts.as_slice()
    else {
        bail!("legacy initrd is not in a direct retained generation");
    };
    mvm_core::naming::validate_vm_name(vm.to_str().context("non-UTF-8 VM name")?)?;
    if !generation
        .to_str()
        .is_some_and(|name| name.starts_with("legacy-runtime-"))
        || *file != "initrd"
    {
        bail!("legacy initrd has an invalid retained generation name");
    }
    for directory in [root.clone(), root.join(vm), root.join(vm).join(generation)] {
        let metadata = std::fs::symlink_metadata(&directory)?;
        if !metadata.file_type().is_dir()
            || mvm_core::private_fs::mode_bits(&directory, &metadata)? != 0o700
        {
            bail!("legacy runtime ancestry is not a private non-symlink directory");
        }
        check_owner(&metadata)?;
    }
    Ok(())
}

fn validate_retained_file(path: &Path, expected: &Path) -> Result<()> {
    anyhow::ensure!(
        path == expected,
        "runtime evidence must belong to its retained generation"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || mvm_core::private_fs::mode_bits(path, &metadata)? != 0o400
    {
        bail!("legacy initrd is not a private read-only regular file");
    }
    check_owner(&metadata)?;
    Ok(())
}

fn validate_generation_paths(binding: &CliRuntimeLaunchBinding) -> Result<PathBuf> {
    let generation = binding
        .initramfs_path
        .parent()
        .context("runtime generation has no parent")?;
    let root = namespace::root(false)?;
    let relative = generation
        .strip_prefix(&root)
        .context("runtime generation is outside retained runtime storage")?;
    let parts: Vec<_> = relative.components().collect();
    let [
        std::path::Component::Normal(vm),
        std::path::Component::Normal(generation_name),
    ] = parts.as_slice()
    else {
        bail!("runtime generation path is not one VM's direct generation");
    };
    mvm_core::naming::validate_vm_name(vm.to_str().context("non-UTF-8 VM name")?)?;
    if !generation_name
        .to_str()
        .is_some_and(|name| name.starts_with("runtime-"))
        || binding.overlay_path != generation.join("overlay.ext4")
        || binding.overlay_verity_path != generation.join("overlay.verity")
        || binding.initramfs_path != generation.join("initramfs.cpio.gz")
    {
        bail!("runtime artifacts must belong to one retained generation");
    }
    for directory in [root.clone(), root.join(vm), generation.to_path_buf()] {
        let metadata = std::fs::symlink_metadata(&directory)?;
        if !metadata.file_type().is_dir()
            || mvm_core::private_fs::mode_bits(&directory, &metadata)? != 0o700
        {
            bail!("runtime generation ancestry is not a private non-symlink directory");
        }
        check_owner(&metadata)?;
    }
    if let Some(proof) = binding.release_proof() {
        for (path, name) in [
            (&proof.archive, "archive"),
            (&proof.checksum, "checksum"),
            (&proof.signature_bundle, "archive.signature"),
        ] {
            validate_retained_file(path, &generation.join(name))?;
        }
        let signature = mvm_build::guest_runtime::evidence::checksum_bundle_path(&proof.checksum);
        match std::fs::symlink_metadata(&signature) {
            Ok(_) => validate_retained_file(&signature, &generation.join("checksum.bundle"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(root)
}

/// Authenticate release declarations or independently check contributor source
/// integrity, retaining that distinction in the result. Never trust a caller's
/// tier flag. Artifact bytes are snapshotted separately at the launch boundary.
pub fn verify_runtime_for_launch(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<Option<VerifiedLaunchRuntime>> {
    verify_runtime_for_launch_at(config, minimum_protocol, None)
}

/// Release-only preflight over the actual selected launch bytes. The returned
/// owner authenticates the archive, not execution or ownership of the selected
/// payloads. Launch must still bind the same configuration through its normal
/// lifecycle, which snapshots and retains those bytes before backend effects.
pub fn verify_release_runtime_for_launch(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<VerifiedRuntimeManifest> {
    check_runtime_provenance(config)?;
    if config.unsigned_runtime_development
        || config.source_runtime_archive_sha256.is_some()
        || config.legacy_bundle_runtime.is_some()
        || config.legacy_portable_runtime.is_some()
        || config.bundle_boot_assets.is_some()
    {
        bail!("CLI release runtime cannot include source, developer, or legacy provenance");
    }
    if config.runtime_release_proof.is_none() {
        bail!("CLI release runtime proof is required");
    }
    let Some(VerifiedLaunchRuntime::Release(release)) =
        verify_runtime_for_launch(config, minimum_protocol)?
    else {
        bail!("selected runtime is not a CLI release");
    };
    release.verify_selected_artifacts(&runtime_selection(config, minimum_protocol)?)?;
    Ok(*release)
}

/// Derive a signed-plan identity only after checking the selected artifacts
/// against the archive snapshot that was authenticated for this launch.
pub fn verified_release_identity(
    config: &VmStartConfig,
    release: &mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime,
    minimum_protocol: u32,
) -> Result<RuntimeIdentity> {
    check_runtime_provenance(config)?;
    let proof = config
        .runtime_release_proof
        .as_ref()
        .context("CLI release runtime proof is required")?;
    anyhow::ensure!(
        proof == release.proof()
            && config.runtime_overlay_version.as_deref() == Some(proof.version.as_str())
            && proof.arch == GuestArch::host(),
        "runtime proof identity changed"
    );
    let selection = runtime_selection(config, minimum_protocol)?;
    let declaration = release.manifest().declaration(selection.arch)?;
    declaration.validate(selection.arch)?;
    anyhow::ensure!(
        declaration.protocol_version >= minimum_protocol
            && declaration.min_supported_protocol_version <= GUEST_RPC_PROTOCOL_VERSION,
        "checked guest runtime protocol is incompatible with this launch"
    );
    release.manifest().verify_selected_artifacts(&selection)?;
    let digests = RuntimeArtifactDigests {
        overlay_sha256: declaration.overlay_sha256.clone(),
        overlay_verity_sha256: declaration.overlay_verity_sha256.clone(),
        overlay_roothash: declaration.overlay_roothash.clone(),
        initramfs_sha256: declaration.initramfs_sha256.clone(),
    };
    Ok(RuntimeIdentity {
        archive_sha256: proof.archive_sha256.clone(),
        version: proof.version.clone(),
        arch: proof.arch.to_string(),
        declaration: digests.clone(),
        selected: digests,
        signer_identity: release.signer().identity.clone(),
        signer_issuer: release.signer().issuer.clone(),
    })
}

#[tracing::instrument(skip_all)]
fn verify_runtime_for_launch_at(
    config: &VmStartConfig,
    minimum_protocol: u32,
    bound_home: Option<&Path>,
) -> Result<Option<VerifiedLaunchRuntime>> {
    check_runtime_provenance(config)?;
    if config.legacy_portable_runtime.is_some() {
        return Ok(Some(VerifiedLaunchRuntime::LegacyPortable(
            crate::legacy_portable_runtime::verify(config, minimum_protocol)?,
        )));
    }
    anyhow::ensure!(
        config.bundle_boot_assets.is_none(),
        "bundle boot-assets pin has no portable runtime proof"
    );
    anyhow::ensure!(
        !(config.legacy_bundle_runtime.is_some() && has_external_runtime(config)),
        "conflicting baked and external runtime evidence"
    );
    if !has_external_runtime(config) && config.legacy_bundle_runtime.is_some() {
        return Ok(Some(VerifiedLaunchRuntime::LegacyBundle(
            crate::legacy_bundle_runtime::verify(config, minimum_protocol)?,
        )));
    }
    if !requires_runtime_proof(config)? {
        return Ok(None);
    }
    let version = config
        .runtime_overlay_version
        .as_deref()
        .context("selected guest runtime has no version")?;
    let selection = runtime_selection(config, minimum_protocol)?;
    // Ends the span before the check, so the lap below times the check alone.
    mvm_core::launch_trace::lap("runtime_evidence.provenance_and_selection");
    let verified = match config.runtime_release_proof.as_ref() {
        Some(proof) => VerifiedLaunchRuntime::Release(Box::new(verify_runtime_release_proof(
            proof,
            version,
            GuestArch::host(),
        )?)),
        None => VerifiedLaunchRuntime::Source(checked_source(
            version,
            GuestArch::host(),
            bound_home,
            config.source_runtime_archive_sha256.as_deref(),
        )?),
    };
    mvm_core::launch_trace::lap(if config.runtime_release_proof.is_some() {
        "runtime_evidence.release_proof_verify"
    } else {
        "runtime_evidence.source_runtime_check"
    });
    let declaration = verified.declaration(GuestArch::host())?;
    if declaration.protocol_version < minimum_protocol
        || declaration.min_supported_protocol_version > mvm_agentd::vsock::PROTOCOL_VERSION
    {
        bail!("checked guest runtime protocol is incompatible with this launch");
    }
    if selection.overlay_roothash != declaration.overlay_roothash {
        bail!("selected guest runtime root differs from its checked declaration");
    }
    Ok(Some(verified))
}

fn check_runtime_provenance(config: &VmStartConfig) -> Result<()> {
    let proof_classes = [
        config.runtime_release_proof.is_some(),
        config.legacy_bundle_runtime.is_some(),
        config.legacy_portable_runtime.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    anyhow::ensure!(proof_classes <= 1, "conflicting runtime proof classes");
    anyhow::ensure!(
        proof_classes == 0
            || (!config.unsigned_runtime_development
                && config.source_runtime_archive_sha256.is_none()),
        "runtime proof cannot include source or developer provenance"
    );
    Ok(())
}

fn has_external_runtime(config: &VmStartConfig) -> bool {
    config.runtime_release_proof.is_some()
        || config.source_runtime_archive_sha256.is_some()
        || config.runtime_overlay_path.is_some()
        || config.runtime_overlay_verity_path.is_some()
        || config.runtime_overlay_roothash.is_some()
        || config.runtime_overlay_version.is_some()
        || config.unsigned_runtime_development
}

fn requires_runtime_proof(config: &VmStartConfig) -> Result<bool> {
    if has_external_runtime(config)
        || config.initrd_path.is_some()
        || config.legacy_bundle_runtime.is_some()
        || config.legacy_portable_runtime.is_some()
    {
        return Ok(true);
    }
    let Some(parent) = Path::new(&config.rootfs_path).parent() else {
        return Ok(false);
    };
    let metadata = mvm_build::builder_vm::GuestSidecar::read_from_dir(parent)
        .context("read guest metadata at runtime proof boundary")?;
    Ok(metadata.is_some_and(|meta| meta.overlay_aware && meta.protocol_version == 0))
}

fn runtime_selection(
    config: &VmStartConfig,
    minimum_protocol: u32,
) -> Result<RuntimeArtifactSelection<'_>> {
    Ok(RuntimeArtifactSelection {
        arch: GuestArch::host(),
        overlay: Path::new(
            config
                .runtime_overlay_path
                .as_deref()
                .context("missing runtime overlay")?,
        ),
        overlay_verity: Path::new(
            config
                .runtime_overlay_verity_path
                .as_deref()
                .context("missing runtime verity")?,
        ),
        overlay_roothash: config
            .runtime_overlay_roothash
            .as_deref()
            .context("missing runtime verity root")?,
        initramfs: Path::new(
            config
                .initrd_path
                .as_deref()
                .context("missing runtime initramfs")?,
        ),
        minimum_protocol,
        host_protocol: GUEST_RPC_PROTOCOL_VERSION,
    })
}

/// Directory under the runtime-evidence root holding artifact bytes shared by
/// content. The underscore keeps it outside the VM-name space.
pub const SHARED_CONTENT_DIR: &str = "shared_content";

/// A narrow lock distinct from the outer instance restore lock. Its directory
/// is outside VM state, so PID-based orphan reconciliation cannot erase bytes.
pub(crate) struct RuntimeLifecycleLease {
    directory: PathBuf,
    /// Whether `acquire` created `directory` and left its entry in the
    /// namespace root unsynced. `bind` syncs it after the generation it
    /// publishes, so one round makes both durable before the spawn.
    entry_unsynced: bool,
    _lock: std::fs::File,
}

impl RuntimeLifecycleLease {
    pub(crate) fn canonical_kernel_record(&self) -> PathBuf {
        self.directory.join("canonical-kernel.json")
    }

    /// Content store the generations of every VM link their artifact bytes
    /// from, so a launch keeps a per-VM record but not a per-VM copy. Named so
    /// no VM name can collide with it, and never deleted: it holds one copy per
    /// distinct runtime.
    fn shared_content(&self) -> Result<PathBuf> {
        let root = self
            .directory
            .parent()
            .context("runtime lifecycle namespace has no root")?;
        let shared = root.join(SHARED_CONTENT_DIR);
        private_directory(&shared)?;
        Ok(shared)
    }

    fn bundle_use_record(&self) -> PathBuf {
        self.directory.join("bundle-use.sha256")
    }

    #[tracing::instrument(name = "runtime_lifecycle.retain_installed_bundle", skip_all)]
    fn retain_installed_bundle(&self, config: &VmStartConfig) -> Result<()> {
        let registry = mvm_core::plan::bundle::BundleRegistry::default_path()?;
        let Ok(relative) = Path::new(&config.rootfs_path).strip_prefix(registry.root()) else {
            return Ok(());
        };
        let Some(sha) = relative
            .components()
            .next()
            .and_then(|part| part.as_os_str().to_str())
        else {
            bail!("installed bundle rootfs has no address");
        };
        anyhow::ensure!(
            mvm_core::manifest::is_slot_hash_dirname(sha),
            "invalid installed bundle rootfs address"
        );
        let record = self.bundle_use_record();
        anyhow::ensure!(
            std::fs::symlink_metadata(&record)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
            "an unresolved bundle use already owns this VM name"
        );
        registry.retain_for_vm(sha, &config.name)?;
        write_private_new(&record, sha.as_bytes())?;
        sync_file(&record)?;
        sync_dir(&self.directory)?;
        Ok(())
    }

    /// Only a backend's confirmed terminal stop may call this method.
    pub(crate) fn release_installed_bundle_after_stop(&self, vm: &str) -> Result<()> {
        use std::io::Read;

        let record = self.bundle_use_record();
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = match options.open(&record) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            file.metadata()?.is_file() && file.metadata()?.len() == 64,
            "bundle use record is not a fixed-size regular file"
        );
        let mut bytes = Vec::new();
        file.take(65).read_to_end(&mut bytes)?;
        let sha = std::str::from_utf8(&bytes)?;
        anyhow::ensure!(
            mvm_core::manifest::is_slot_hash_dirname(sha),
            "bundle use record has an invalid address"
        );
        mvm_core::plan::bundle::BundleRegistry::default_path()?.release_after_stop(sha, vm)?;
        std::fs::remove_file(&record)?;
        sync_dir(&self.directory)?;
        Ok(())
    }

    pub(crate) fn acquire(vm_name: &str) -> Result<Self> {
        mvm_core::naming::validate_vm_name(vm_name)?;
        let root = namespace::root(true)?;
        let directory = root.join(vm_name);
        let entry_unsynced = namespace::private_directory_unsynced(&directory)?;
        let lock = namespace::lock(&directory)?;
        Ok(Self {
            directory,
            entry_unsynced,
            _lock: lock,
        })
    }

    /// Publish a fresh immutable generation before any backend side effect.
    /// Once persisted, neither an error return nor dropping the VM handle
    /// removes the artifacts.
    #[tracing::instrument(name = "runtime_lifecycle.bind", skip_all)]
    pub(crate) fn bind(&self, config: &VmStartConfig) -> Result<VmStartConfig> {
        self.retain_installed_bundle(config)?;
        let minimum_protocol = mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION;
        let home = self
            .directory
            .parent()
            .and_then(Path::parent)
            .context("runtime lifecycle namespace has no home")?;
        let verified = verify_runtime_for_launch_at(config, minimum_protocol, Some(home))?;
        self.bind_checked(config, verified.as_ref())
    }

    /// Bind an already authenticated selection without repeating release
    /// signature verification. The selection still has to match this config;
    /// copying and hashing the selected artifacts remains the custody point.
    pub(crate) fn bind_checked(
        &self,
        config: &VmStartConfig,
        verified: Option<&VerifiedLaunchRuntime>,
    ) -> Result<VmStartConfig> {
        self.bind_checked_ref(config, verified.map(CheckedLaunchRuntime::from))
    }

    /// Borrow a launch's signed archive through the custody boundary without
    /// reopening its mutable source path or repeating signature verification.
    pub(crate) fn bind_verified_release(
        &self,
        config: &VmStartConfig,
        release: &mvm_build::guest_runtime::evidence::VerifiedReleaseRuntime,
    ) -> Result<VmStartConfig> {
        self.retain_installed_bundle(config)?;
        anyhow::ensure!(
            config.runtime_release_proof.as_ref() == Some(release.proof()),
            "runtime proof identity changed"
        );
        self.bind_checked_ref(
            config,
            Some(CheckedLaunchRuntime::Release(release.manifest())),
        )
    }

    /// Every bind ends here, so a lease this process created is durable before
    /// any bound config reaches a backend.
    fn bind_checked_ref(
        &self,
        config: &VmStartConfig,
        verified: Option<CheckedLaunchRuntime<'_>>,
    ) -> Result<VmStartConfig> {
        let bound = self.publish_generation(config, verified)?;
        if self.entry_unsynced {
            sync_dir(
                self.directory
                    .parent()
                    .context("runtime lifecycle namespace has no root")?,
            )?;
        }
        Ok(bound)
    }

    fn publish_generation(
        &self,
        config: &VmStartConfig,
        verified: Option<CheckedLaunchRuntime<'_>>,
    ) -> Result<VmStartConfig> {
        let minimum_protocol = mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION;
        let Some(verified) = verified else {
            anyhow::ensure!(
                !requires_runtime_proof(config)?,
                "selected guest runtime has no verified launch evidence"
            );
            return Ok(config.clone());
        };
        check_runtime_provenance(config)?;
        if let CheckedLaunchRuntime::Release(release) = &verified {
            let proof = config
                .runtime_release_proof
                .as_ref()
                .context("release proof missing")?;
            anyhow::ensure!(
                proof.archive_sha256 == release.archive_sha256()
                    && proof.version == config.runtime_overlay_version.as_deref().unwrap_or("")
                    && proof.arch == GuestArch::host(),
                "runtime proof does not match the selected version and guest architecture"
            );
            let declaration = release.declaration(GuestArch::host())?;
            anyhow::ensure!(
                declaration.protocol_version >= minimum_protocol
                    && declaration.min_supported_protocol_version <= GUEST_RPC_PROTOCOL_VERSION,
                "checked guest runtime protocol is incompatible with this launch"
            );
        } else {
            anyhow::ensure!(
                config.runtime_release_proof.is_none(),
                "release runtime cannot use non-release verification evidence"
            );
        }
        if let CheckedLaunchRuntime::Source(source) = &verified {
            anyhow::ensure!(
                config
                    .source_runtime_archive_sha256
                    .as_deref()
                    .is_none_or(|digest| digest == source.archive_sha256())
                    && source.declaration(GuestArch::host())?.arch == GuestArch::host(),
                "source runtime archive differs from the originally selected archive"
            );
        }
        if let CheckedLaunchRuntime::LegacyBundle(legacy) = &verified {
            let mut bound = legacy.snapshot_in(config, &self.directory)?;
            bound.source_runtime_archive_sha256 = None;
            self.report_retained_best_effort();
            return Ok(bound);
        }
        if let CheckedLaunchRuntime::LegacyPortable(portable) = &verified {
            let bound = portable.snapshot_in(config, &self.directory)?;
            self.report_retained_best_effort();
            return Ok(bound);
        }
        let selection = runtime_selection(config, minimum_protocol)?;
        let shared = self.shared_content()?;
        let artifacts = verified.snapshot_artifacts_in(&selection, &self.directory, &shared)?;
        let mut bound = config.clone();
        if let CheckedLaunchRuntime::Release(release) = &verified {
            bound.runtime_release_proof = Some(
                release.retain_release_proof_in(
                    config
                        .runtime_release_proof
                        .as_ref()
                        .context("release proof missing")?,
                    artifacts.directory_path(),
                    Some(&shared),
                )?,
            );
        }
        bound.unsigned_runtime_development = !verified.is_release();
        bound.source_runtime_archive_sha256 = match &verified {
            CheckedLaunchRuntime::Source(source) => Some(source.archive_sha256().to_owned()),
            CheckedLaunchRuntime::Release(_)
            | CheckedLaunchRuntime::LegacyBundle(_)
            | CheckedLaunchRuntime::LegacyPortable(_) => None,
        };
        bound.runtime_overlay_path = Some(artifacts.overlay_path().display().to_string());
        bound.runtime_overlay_verity_path =
            Some(artifacts.overlay_verity_path().display().to_string());
        bound.initrd_path = Some(artifacts.initramfs_path().display().to_string());
        let binding = artifacts.directory_path().join("launch.json");
        let record = serde_json::json!({
            "vm_name": config.name,
            "provenance": if verified.is_release() { "release" } else { "source" },
            "archive_sha256": artifacts.archive_sha256(),
            "overlay_roothash": artifacts.declaration().overlay_roothash,
            "overlay": bound.runtime_overlay_path,
            "overlay_verity": bound.runtime_overlay_verity_path,
            "initramfs": bound.initrd_path,
            "status": "retained-before-spawn",
        });
        write_private_new(&binding, &serde_json::to_vec(&record)?)?;
        sync_file(&binding)?;
        sync_dir(artifacts.directory_path())?;
        let artifacts = artifacts.persist()?;
        tracing::warn!(
            path = %artifacts.directory_path().display(),
            "retaining runtime generation before spawn; deletion requires independently confirmed absence of all VM readers"
        );
        self.report_retained_best_effort();
        Ok(bound)
    }

    pub(crate) fn report_retained_best_effort(&self) {
        if let Err(error) = self.report_retained() {
            tracing::warn!(
                path = %self.directory.display(),
                %error,
                "could not measure retained runtime generations; no artifacts were deleted"
            );
        }
    }

    #[tracing::instrument(name = "runtime_lifecycle.report_retained", skip_all)]
    pub(crate) fn report_retained(&self) -> Result<()> {
        let mut generations = 0_u64;
        let mut bytes = 0_u64;
        for entry in std::fs::read_dir(&self.directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            generations += 1;
            for artifact in std::fs::read_dir(entry.path())? {
                let artifact = artifact?;
                if artifact.file_type()?.is_file() {
                    bytes = bytes.saturating_add(artifact.metadata()?.len());
                }
            }
        }
        if generations != 0 {
            tracing::warn!(
                path = %self.directory.display(),
                retained_generations = generations,
                retained_bytes = bytes,
                "guest runtime snapshots retained: automatic cleanup requires exact-generation stop proof; remove only after independently confirming no VM can read these generations"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_source_fixture_binds_a_reverifiable_runtime() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fixture rootfs").unwrap();

        let (config, binding) = checked_source_runtime_fixture("fixture-vm", &rootfs).unwrap();
        let checked = verify_runtime_for_launch(&config, MIN_GUEST_RPC_PROTOCOL_VERSION)
            .unwrap()
            .expect("the fixture config carries external runtime evidence");
        assert!(!checked.is_release(), "fixture bytes are source provenance");
        verify_runtime_binding(&binding).unwrap();

        // A swapped retained artifact fails the same re-verification.
        let RuntimeLaunchBinding::CliAssembly(assembly) = &binding else {
            panic!("source fixture binding");
        };
        let overlay = assembly.overlay_path.clone();
        mvm_core::private_fs::set_mode(&overlay, 0o600).unwrap();
        std::fs::write(&overlay, b"swapped").unwrap();
        assert!(verify_runtime_binding(&binding).is_err());
    }

    /// A new lease's directory entry is made durable once, at the end of
    /// `bind`, after the generation it publishes: still before any spawn, but
    /// in the same round as the generation rather than one of its own.
    #[test]
    fn a_new_lease_entry_is_synced_once_after_the_generation_it_publishes() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fixture rootfs").unwrap();
        let (fixture, _) = checked_source_runtime_fixture("fixture-vm", &rootfs).unwrap();
        // An earlier launch on this host already created the shared content
        // store, whose own first creation syncs the root once.
        RuntimeLifecycleLease::acquire("earlier-launch")
            .unwrap()
            .bind(&VmStartConfig {
                name: "earlier-launch".into(),
                ..fixture.clone()
            })
            .unwrap();
        let root = namespace::root(false).unwrap();
        namespace::durable_steps::take();

        let lease = RuntimeLifecycleLease::acquire("durable-lease").unwrap();
        assert_eq!(
            namespace::durable_steps::take(),
            Vec::<PathBuf>::new(),
            "acquiring a new lease leaves its entry for bind to sync"
        );
        let bound = lease
            .bind(&VmStartConfig {
                name: "durable-lease".into(),
                ..fixture
            })
            .unwrap();

        let steps = namespace::durable_steps::take();
        let record = Path::new(bound.initrd_path.as_deref().unwrap()).with_file_name("launch.json");
        let record_synced = steps
            .iter()
            .position(|path| path == &record)
            .expect("the launch record is synced");
        assert_eq!(
            steps.iter().filter(|path| **path == root).count(),
            1,
            "the namespace root is synced exactly once: {steps:?}"
        );
        assert_eq!(
            steps.last(),
            Some(&root),
            "the lease entry is synced last, after the launch record at {record_synced}: {steps:?}"
        );
    }

    /// A bind that publishes no generation still makes a new lease durable
    /// before it returns, so no path to a spawn skips the sync.
    #[test]
    fn a_bind_without_runtime_evidence_still_syncs_a_new_lease_entry() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fixture rootfs").unwrap();
        let config = VmStartConfig {
            name: "plain-lease".into(),
            rootfs_path: rootfs.display().to_string(),
            ..Default::default()
        };

        let lease = RuntimeLifecycleLease::acquire("plain-lease").unwrap();
        let root = namespace::root(false).unwrap();
        namespace::durable_steps::take();
        lease.bind(&config).unwrap();

        assert_eq!(namespace::durable_steps::take(), vec![root]);
    }

    /// Re-acquiring a lease whose entry already exists syncs nothing new.
    #[test]
    fn an_existing_lease_entry_is_not_synced_again() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fixture rootfs").unwrap();
        let config = VmStartConfig {
            name: "existing-lease".into(),
            rootfs_path: rootfs.display().to_string(),
            ..Default::default()
        };
        drop(RuntimeLifecycleLease::acquire("existing-lease").unwrap());
        namespace::durable_steps::take();

        let lease = RuntimeLifecycleLease::acquire("existing-lease").unwrap();
        lease.bind(&config).unwrap();

        assert_eq!(namespace::durable_steps::take(), Vec::<PathBuf>::new());
    }

    #[test]
    #[cfg(unix)]
    fn launches_share_one_copy_of_the_runtime_and_still_reverify() {
        use std::os::unix::fs::MetadataExt;
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let rootfs = home.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"fixture rootfs").unwrap();
        let (config, _) = checked_source_runtime_fixture("fixture-vm", &rootfs).unwrap();

        let bind = |name: &str| {
            let lease = RuntimeLifecycleLease::acquire(name).unwrap();
            let named = VmStartConfig {
                name: name.into(),
                ..config.clone()
            };
            lease.bind(&named).unwrap()
        };
        let first = bind("share-a");
        let second = bind("share-b");
        let inode =
            |path: &Option<String>| std::fs::metadata(path.as_deref().unwrap()).unwrap().ino();
        assert_ne!(first.runtime_overlay_path, second.runtime_overlay_path);
        assert_eq!(
            inode(&first.runtime_overlay_path),
            inode(&second.runtime_overlay_path)
        );
        assert_eq!(inode(&first.initrd_path), inode(&second.initrd_path));
        let shared = namespace::root(false).unwrap().join(SHARED_CONTENT_DIR);
        assert_eq!(std::fs::read_dir(shared).unwrap().count(), 3);
        for bound in [&first, &second] {
            verify_runtime_for_launch(bound, MIN_GUEST_RPC_PROTOCOL_VERSION)
                .unwrap()
                .expect("a bound launch carries runtime evidence");
        }
    }

    #[test]
    fn bundle_use_is_durable_before_start_and_requires_explicit_release() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let registry = mvm_core::plan::bundle::BundleRegistry::default_path().unwrap();
        let sha = "a".repeat(64);
        let rootfs = registry.install_dir(&sha).join("artifacts/rootfs.ext4");
        mvm_core::config::create_private_dir(rootfs.parent().unwrap()).unwrap();
        std::fs::write(&rootfs, b"fixture rootfs").unwrap();
        let config = VmStartConfig {
            name: "bundle-use-unit".into(),
            rootfs_path: rootfs.display().to_string(),
            ..Default::default()
        };

        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        lease.bind(&config).unwrap();
        let claim = registry.root().join(format!(".{sha}.uses/{}", config.name));
        assert!(claim.is_file());
        assert!(lease.bundle_use_record().is_file());
        assert!(
            lease.bind(&config).is_err(),
            "an unresolved VM cannot be reused"
        );
        drop(lease);
        assert!(claim.is_file(), "a crash cannot release the bundle by Drop");

        // The real caller invokes release only after the original backend
        // confirmed exit; this unit checks the durable-record mechanics.
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        lease
            .release_installed_bundle_after_stop(&config.name)
            .unwrap();
        assert!(!claim.exists());
        assert!(!lease.bundle_use_record().exists());
        assert!(rootfs.exists(), "an older install is not eviction-eligible");
    }

    #[test]
    fn generic_preflight_refuses_mixed_provenance_before_proof_or_snapshot_effects() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let portable =
            crate::legacy_portable_runtime::fixtures::signed_legacy_portable_runtime_fixture(
                home.path(),
            );
        let proof = portable.legacy_portable_runtime.as_ref().unwrap();
        let baked = mvm_core::vm_backend::LegacyBundleRuntimeProof {
            archive: proof.archive.clone(),
            pin: proof.pin.clone(),
        };
        let release = mvm_core::protocol::runtime_release::RuntimeReleaseProof {
            archive: home.path().join("missing-release"),
            checksum: home.path().join("missing-checksum"),
            signature_bundle: home.path().join("missing-signature"),
            archive_sha256: "a".repeat(64),
            version: "99.2.3".into(),
            arch: GuestArch::host(),
        };
        for mask in 1_u8..8 {
            let mut config = VmStartConfig::default();
            if mask & 1 != 0 {
                config.runtime_release_proof = Some(release.clone());
            }
            if mask & 2 != 0 {
                config.legacy_bundle_runtime = Some(baked.clone());
            }
            if mask & 4 != 0 {
                config.legacy_portable_runtime = Some(proof.clone());
            }
            for source in [false, true] {
                let mut mixed = config.clone();
                if source {
                    mixed.source_runtime_archive_sha256 = Some("b".repeat(64));
                } else {
                    mixed.unsigned_runtime_development = true;
                }
                let before = format!("{mixed:?}");
                let error = verify_runtime_for_launch(&mixed, 2).unwrap_err();
                assert!(
                    error.to_string().contains(if mask.count_ones() > 1 {
                        "conflicting runtime proof classes"
                    } else {
                        "runtime proof cannot include source or developer provenance"
                    }),
                    "{error:#}"
                );
                assert_eq!(format!("{mixed:?}"), before);
            }
            if mask.count_ones() > 1 {
                assert!(
                    verify_runtime_for_launch(&config, 2)
                        .unwrap_err()
                        .to_string()
                        .contains("conflicting runtime proof classes")
                );
            }
        }
        assert!(verify_runtime_for_launch(&portable, 2).is_ok());
        let source = VmStartConfig {
            unsigned_runtime_development: true,
            source_runtime_archive_sha256: Some("a".repeat(64)),
            ..Default::default()
        };
        assert!(check_runtime_provenance(&source).is_ok());
    }

    #[test]
    fn release_only_preflight_rejects_missing_or_developer_provenance() {
        for config in [
            VmStartConfig::default(),
            VmStartConfig {
                runtime_overlay_version: Some("1.2.3".into()),
                ..Default::default()
            },
        ] {
            assert!(
                verify_release_runtime_for_launch(&config, 2)
                    .unwrap_err()
                    .to_string()
                    .contains("CLI release runtime proof is required")
            );
        }
        for config in [
            VmStartConfig {
                unsigned_runtime_development: true,
                ..Default::default()
            },
            VmStartConfig {
                source_runtime_archive_sha256: Some("a".repeat(64)),
                ..Default::default()
            },
        ] {
            assert!(
                verify_release_runtime_for_launch(&config, 2)
                    .unwrap_err()
                    .to_string()
                    .contains("cannot include source, developer, or legacy provenance")
            );
        }
    }

    #[test]
    fn source_binding_pins_checked_archive_and_refuses_changed_selection() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let cache = home.path().join("cache");
        let workspace = mvm_build::image_source::guest_runtime_source_checkout().unwrap();
        let version = env!("CARGO_PKG_VERSION");
        let arch = GuestArch::host();
        let runtime = mvm_build::guest_runtime::test_support::write_source_cache_fixture(
            &cache, &workspace, version, arch,
        )
        .unwrap();
        let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
            &cache, version, arch, &runtime,
        )
        .unwrap();
        let initramfs = mvm_build::initramfs::build_initramfs_from_guest_runtime(
            &cache, version, arch, &runtime,
        )
        .unwrap();
        let mut config = VmStartConfig {
            name: "source-pin".into(),
            runtime_overlay_version: Some(version.into()),
            runtime_overlay_path: Some(overlay.overlay_ext4.display().to_string()),
            runtime_overlay_verity_path: Some(overlay.sidecar.display().to_string()),
            runtime_overlay_roothash: Some(overlay.roothash),
            initrd_path: Some(initramfs.image_path.display().to_string()),
            source_runtime_archive_sha256: Some("0".repeat(64)),
            ..Default::default()
        };
        let lease = RuntimeLifecycleLease::acquire(&config.name).unwrap();
        assert!(
            lease
                .bind_checked(&config, None)
                .unwrap_err()
                .to_string()
                .contains("no verified launch evidence"),
            "a selected runtime may not bypass the binding verifier"
        );
        let checked = VerifiedLaunchRuntime::Source(
            checked_source(version, arch, Some(home.path()), None).unwrap(),
        );
        assert!(
            lease
                .bind_checked(&config, Some(&checked))
                .unwrap_err()
                .to_string()
                .contains("originally selected archive"),
            "checked evidence from another selection cannot authorize binding"
        );
        assert!(
            lease
                .bind(&config)
                .unwrap_err()
                .to_string()
                .contains("originally selected archive")
        );
        assert!(
            std::fs::read_dir(&lease.directory)
                .unwrap()
                .all(|entry| !entry.unwrap().file_type().unwrap().is_dir()),
            "a mismatched original selection must fail before snapshotting"
        );
        // Direct callers without an earlier selection gain only the digest of
        // the independently checked archive, after all artifact hashes pass.
        config.source_runtime_archive_sha256 = None;
        let bound = lease.bind(&config).unwrap();
        assert_eq!(
            bound.source_runtime_archive_sha256.as_deref(),
            Some(runtime.digest.as_str())
        );
        let mut explicitly_checked_source = config.clone();
        explicitly_checked_source.source_runtime_archive_sha256 = Some(runtime.digest.clone());
        explicitly_checked_source.unsigned_runtime_development = true;
        assert!(verify_runtime_for_launch(&explicitly_checked_source, 2).is_ok());
        let binding = CliRuntimeLaunchBinding {
            provenance: RuntimeBindingProvenance::Source {
                version: version.into(),
                arch,
                archive_sha256: runtime.digest.clone(),
            },
            overlay_path: bound.runtime_overlay_path.as_ref().unwrap().into(),
            overlay_verity_path: bound.runtime_overlay_verity_path.as_ref().unwrap().into(),
            initramfs_path: bound.initrd_path.as_ref().unwrap().into(),
            overlay_roothash: bound.runtime_overlay_roothash.clone().unwrap(),
        };
        let retained = crate::checkpoint::runtime_binding::verify_retained_binding_for_test(Some(
            &RuntimeLaunchBinding::CliAssembly(binding.clone()),
        ))
        .unwrap();
        config.source_runtime_archive_sha256 = Some(runtime.digest.clone());
        verify_runtime_for_claim(&retained, Some(&config)).unwrap();
        let mut changed = binding;
        let RuntimeBindingProvenance::Source { archive_sha256, .. } = &mut changed.provenance
        else {
            unreachable!()
        };
        *archive_sha256 = "0".repeat(64);
        let changed = RuntimeLaunchBinding::CliAssembly(changed);
        assert!(verify_runtime_binding(&changed).is_err());
        assert!(
            crate::checkpoint::runtime_binding::verify_retained_binding_for_test(Some(&changed))
                .is_err()
        );
        // A claim compares the child request with the checked parent; it does
        // not rerun the source-cache verifier as a second "parent" proof.
        std::fs::rename(&cache, home.path().join("cache-removed")).unwrap();
        verify_runtime_for_claim(&retained, Some(&config)).unwrap();
        let mut wrong_archive = config.clone();
        wrong_archive.source_runtime_archive_sha256 = Some("0".repeat(64));
        assert!(
            verify_runtime_for_claim(&retained, Some(&wrong_archive))
                .unwrap_err()
                .to_string()
                .contains("warm child requested a different source archive")
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_binding_refuses_mixed_generations_external_paths_and_symlink_ancestry() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let lease = RuntimeLifecycleLease::acquire("retained-test").unwrap();
        let generation = lease.directory.join("runtime-one");
        private_directory(&generation).unwrap();
        for name in ["archive", "checksum", "archive.signature"] {
            let path = generation.join(name);
            write_private_new(&path, b"not authenticated evidence").unwrap();
            mvm_core::private_fs::set_mode(&path, 0o400).unwrap();
        }
        let binding = CliRuntimeLaunchBinding {
            provenance: RuntimeBindingProvenance::Release {
                proof: mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                    archive: generation.join("archive"),
                    checksum: generation.join("checksum"),
                    signature_bundle: generation.join("archive.signature"),
                    archive_sha256: "a".repeat(64),
                    version: "1.2.3".into(),
                    arch: GuestArch::host(),
                },
            },
            overlay_path: generation.join("overlay.ext4"),
            overlay_verity_path: generation.join("overlay.verity"),
            initramfs_path: generation.join("initramfs.cpio.gz"),
            overlay_roothash: "a".repeat(64),
        };
        validate_generation_paths(&binding).unwrap();
        for selected in ["archive", "checksum", "signature"] {
            let mut external = binding.clone();
            let RuntimeBindingProvenance::Release { proof } = &mut external.provenance else {
                unreachable!();
            };
            match selected {
                "archive" => proof.archive = home.path().join("ambient-archive"),
                "checksum" => proof.checksum = home.path().join("ambient-checksum"),
                "signature" => proof.signature_bundle = home.path().join("ambient-signature"),
                _ => unreachable!(),
            }
            assert!(validate_generation_paths(&external).is_err());
        }
        // A valid-looking path never grants authority to unverified bytes.
        assert!(
            verify_runtime_binding(&RuntimeLaunchBinding::CliAssembly(binding.clone())).is_err()
        );
        let mixed = CliRuntimeLaunchBinding {
            overlay_path: lease.directory.join("runtime-two/overlay.ext4"),
            ..binding.clone()
        };
        assert!(validate_generation_paths(&mixed).is_err());
        let external = CliRuntimeLaunchBinding {
            initramfs_path: home.path().join("cache/initramfs.cpio.gz"),
            ..binding.clone()
        };
        assert!(validate_generation_paths(&external).is_err());
        let real = lease.directory.join("runtime-real");
        std::fs::rename(&generation, &real).unwrap();
        std::os::unix::fs::symlink(&real, &generation).unwrap();
        assert!(validate_generation_paths(&binding).is_err());
    }

    #[test]
    fn every_partial_runtime_selection_and_forged_flag_is_rejected() {
        for config in [
            VmStartConfig {
                runtime_overlay_path: Some("/runtime/overlay".into()),
                ..Default::default()
            },
            VmStartConfig {
                unsigned_runtime_development: true,
                ..Default::default()
            },
            VmStartConfig {
                initrd_path: Some("/runtime/initramfs".into()),
                ..Default::default()
            },
            VmStartConfig {
                runtime_overlay_verity_path: Some("/runtime/verity".into()),
                ..Default::default()
            },
            VmStartConfig {
                runtime_overlay_roothash: Some("a".repeat(64)),
                ..Default::default()
            },
            VmStartConfig {
                runtime_overlay_version: Some("1.2.3".into()),
                ..Default::default()
            },
        ] {
            assert!(verify_runtime_for_launch(&config, 2).is_err());
        }
    }

    #[test]
    fn incomplete_selection_and_wrong_architecture_fail_before_reading_archive() {
        let other_arch = match GuestArch::host() {
            GuestArch::X86_64 => GuestArch::Aarch64,
            GuestArch::Aarch64 => GuestArch::X86_64,
        };
        let proof = mvm_core::protocol::runtime_release::RuntimeReleaseProof {
            archive: "/missing/archive".into(),
            checksum: "/missing/checksum".into(),
            signature_bundle: "/missing/signature".into(),
            archive_sha256: "a".repeat(64),
            version: "1.2.3".into(),
            arch: other_arch,
        };
        let mut config = VmStartConfig {
            runtime_release_proof: Some(proof),
            runtime_overlay_version: Some("1.2.3".into()),
            ..Default::default()
        };
        assert!(
            verify_runtime_for_launch(&config, 2)
                .unwrap_err()
                .to_string()
                .contains("missing runtime overlay")
        );
        config.runtime_overlay_path = Some("/missing/overlay".into());
        config.runtime_overlay_verity_path = Some("/missing/verity".into());
        config.runtime_overlay_roothash = Some("a".repeat(64));
        config.initrd_path = Some("/missing/initramfs".into());
        config.unsigned_runtime_development = true;
        assert!(
            verify_runtime_for_launch(&config, 2)
                .unwrap_err()
                .to_string()
                .contains("runtime proof cannot include source or developer provenance")
        );
        config.unsigned_runtime_development = false;
        assert!(
            verify_runtime_for_launch(&config, 2)
                .unwrap_err()
                .to_string()
                .contains("guest architecture")
        );
    }

    #[test]
    fn legacy_image_agnostic_launch_needs_no_runtime_proof() {
        assert!(
            verify_runtime_for_launch(&VmStartConfig::default(), 2)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_runtime_root_refuses_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(private_directory(&link).is_err());
    }
}
