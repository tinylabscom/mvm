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
use mvm_core::protocol::runtime_release::{
    CliRuntimeLaunchBinding, RuntimeBindingProvenance, RuntimeLaunchBinding,
};
use mvm_core::util::atomic_io::{sync_dir, sync_file, write_private_new};
use mvm_core::vm_backend::VmStartConfig;
use std::path::{Path, PathBuf};

mod namespace;
use namespace::{check_owner, private_directory};

/// Guest RPC compatibility, distinct from the host instance-control protocol.
pub const MIN_GUEST_RPC_PROTOCOL_VERSION: u32 = mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION;
/// Current guest RPC version, not the host instance-control wire version.
pub const GUEST_RPC_PROTOCOL_VERSION: u32 = mvm_agentd::vsock::PROTOCOL_VERSION;

/// Checked launch inputs retain their assurance tier through admission.
/// Source integrity is deliberately not signed release provenance.
#[derive(Debug)]
pub enum VerifiedLaunchRuntime {
    Release(VerifiedRuntimeManifest),
    Source(CheckedSourceRuntime),
    LegacyBundle(crate::legacy_bundle_runtime::VerifiedLegacyBundleRuntime),
}

impl VerifiedLaunchRuntime {
    pub fn is_release(&self) -> bool {
        matches!(self, Self::Release(_))
    }

    pub fn declaration(&self, arch: GuestArch) -> Result<&RuntimeAssembly> {
        match self {
            Self::Release(runtime) => Ok(runtime.declaration(arch)?),
            Self::Source(runtime) => Ok(runtime.declaration(arch)?),
            Self::LegacyBundle(_) => bail!("a baked runtime has no external runtime assembly"),
        }
    }

    fn snapshot_artifacts_in(
        &self,
        selection: &RuntimeArtifactSelection<'_>,
        parent: &Path,
    ) -> Result<VerifiedRuntimeArtifacts> {
        match self {
            Self::Release(runtime) => Ok(runtime.snapshot_artifacts_in(selection, parent)?),
            Self::Source(runtime) => Ok(runtime.snapshot_artifacts_in(selection, parent)?),
            Self::LegacyBundle(_) => bail!("a baked runtime has no external runtime assembly"),
        }
    }
}

fn checked_source(
    version: &str,
    arch: GuestArch,
    bound_home: Option<&Path>,
) -> Result<CheckedSourceRuntime> {
    if !mvm_build::artifact_acquisition::compiled_channel().permits_automatic_builds() {
        bail!("selected runtime requires a signed release proof for this compiled channel");
    }
    let cache = match bound_home {
        Some(home) => namespace::source_cache_at(home)?,
        None => namespace::source_cache_root()?,
    };
    Ok(check_source_runtime(&cache, version, arch)?)
}

/// Bind a warm child's requested runtime to its authenticated parent record.
/// The caller must authenticate the parent checkpoint before invoking this.
pub fn verify_runtime_for_claim(
    parent: Option<&RuntimeLaunchBinding>,
    requested: Option<&VmStartConfig>,
) -> Result<()> {
    let Some(parent) = parent else {
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
    let checked = verify_runtime_for_launch(config, MIN_GUEST_RPC_PROTOCOL_VERSION)?
        .context("warm child omitted its runtime evidence")?;
    if checked.is_release() != parent_assembly.release_proof().is_some() {
        bail!("warm child cannot change its parent's runtime provenance tier");
    }
    if let (Some(requested), Some(actual)) = (
        config.runtime_release_proof.as_ref(),
        parent_assembly.release_proof(),
    ) && requested.archive_sha256 != actual.archive_sha256
    {
        bail!("warm child requested a different release archive");
    }
    verify_runtime_binding(parent)
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
    let RuntimeLaunchBinding::CliAssembly(binding) = binding else {
        let mut config = VmStartConfig::default();
        binding.apply_to_config(&mut config);
        verify_retained_legacy_runtime(&config)?;
        return Ok(());
    };
    let root = validate_generation_paths(binding)?;
    if binding.arch() != GuestArch::host() {
        bail!("retained runtime has the wrong guest architecture");
    }
    let verified = match &binding.provenance {
        RuntimeBindingProvenance::Release { proof } => VerifiedLaunchRuntime::Release(
            verify_runtime_release_proof(proof, binding.version(), GuestArch::host())?,
        ),
        RuntimeBindingProvenance::Source { version, arch } => {
            VerifiedLaunchRuntime::Source(checked_source(
                version,
                *arch,
                Some(root.parent().context("runtime root has no home")?),
            )?)
        }
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
        if mvm_core::crypto::image_verify::sha256_reader(file)? != *expected {
            bail!("retained runtime artifact differs from its checked declaration");
        }
    }
    Ok(())
}

pub(crate) fn verify_retained_legacy_runtime(
    config: &VmStartConfig,
) -> Result<crate::legacy_bundle_runtime::VerifiedLegacyBundleRuntime> {
    if let Some(path) = config.initrd_path.as_deref() {
        validate_legacy_generation(Path::new(path))?;
    }
    crate::legacy_bundle_runtime::verify_retained(config, MIN_GUEST_RPC_PROTOCOL_VERSION)
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

fn verify_runtime_for_launch_at(
    config: &VmStartConfig,
    minimum_protocol: u32,
    bound_home: Option<&Path>,
) -> Result<Option<VerifiedLaunchRuntime>> {
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
    let verified = match config.runtime_release_proof.as_ref() {
        Some(proof) => VerifiedLaunchRuntime::Release(verify_runtime_release_proof(
            proof,
            version,
            GuestArch::host(),
        )?),
        None => {
            VerifiedLaunchRuntime::Source(checked_source(version, GuestArch::host(), bound_home)?)
        }
    };
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

fn has_external_runtime(config: &VmStartConfig) -> bool {
    config.runtime_release_proof.is_some()
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

/// A narrow lock distinct from the outer instance restore lock. Its directory
/// is outside VM state, so PID-based orphan reconciliation cannot erase bytes.
pub(crate) struct RuntimeLifecycleLease {
    directory: PathBuf,
    _lock: std::fs::File,
}

impl RuntimeLifecycleLease {
    pub(crate) fn acquire(vm_name: &str) -> Result<Self> {
        mvm_core::naming::validate_vm_name(vm_name)?;
        let root = namespace::root(true)?;
        let directory = root.join(vm_name);
        private_directory(&directory)?;
        let lock = namespace::lock(&directory)?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    /// Publish a fresh immutable generation before any backend side effect.
    /// Once persisted, neither an error return nor dropping the VM handle
    /// removes the artifacts.
    pub(crate) fn bind(&self, config: &VmStartConfig) -> Result<VmStartConfig> {
        let minimum_protocol = mvm_agentd::vsock::MIN_SUPPORTED_PROTOCOL_VERSION;
        let home = self
            .directory
            .parent()
            .and_then(Path::parent)
            .context("runtime lifecycle namespace has no home")?;
        let Some(verified) = verify_runtime_for_launch_at(config, minimum_protocol, Some(home))?
        else {
            return Ok(config.clone());
        };
        if let VerifiedLaunchRuntime::LegacyBundle(legacy) = &verified {
            let bound = legacy.snapshot_in(config, &self.directory)?;
            self.report_retained_best_effort();
            return Ok(bound);
        }
        let selection = runtime_selection(config, minimum_protocol)?;
        let artifacts = verified.snapshot_artifacts_in(&selection, &self.directory)?;
        let mut bound = config.clone();
        bound.unsigned_runtime_development = !verified.is_release();
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
        let binding = CliRuntimeLaunchBinding {
            provenance: RuntimeBindingProvenance::Release {
                proof: mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                    archive: "/missing/archive".into(),
                    checksum: "/missing/checksum".into(),
                    signature_bundle: "/missing/signature".into(),
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
