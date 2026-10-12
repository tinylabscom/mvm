//! Offline runtime selection from a signed, installed bundle.
//!
//! Schema 5 uses retained release proofs and prepared bytes without reassembly,
//! runtime-cache lookup or downloads. Schema 4 preserves the original explicit
//! image-set runtime selection; it is never reinterpreted as a CLI runtime.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{BackendImageSupport, ImageSetMember};
use mvm_core::plan::FsTrustStore;
use mvm_core::plan::bundle::{
    ArtifactRole, BundleRegistry, VerifiedEmbeddedImageSet, select_boot_asset_members,
    verify_bundle_file,
};
use mvm_core::vm_backend::{BackendKind, BundleBootAssetsPin, VmStartConfig};

/// Locate a registry-owned bundle. This path is only a hint; never proof.
pub fn installed_archive_for_rootfs(rootfs: &Path) -> Result<Option<PathBuf>> {
    let registry = BundleRegistry::default_path()?;
    let Ok(relative) = rootfs.strip_prefix(registry.root()) else {
        return Ok(None);
    };
    let Some(sha) = relative
        .components()
        .next()
        .and_then(|c| c.as_os_str().to_str())
    else {
        return Ok(None);
    };
    ensure!(
        mvm_core::manifest::is_slot_hash_dirname(sha),
        "invalid installed bundle identity"
    );
    Ok(Some(registry.archive_path(sha)))
}

/// False means an ordinary source or a legacy bundle without boot assets.
pub fn attach_if_installed_bundle(config: &mut VmStartConfig, backend: &str) -> Result<bool> {
    let mut selected = config.clone();
    let attached = attach_installed_bundle(&mut selected, backend)?;
    // A rejected proof must not erase or partially replace any caller selection.
    // Nonportable signed bundles still commit their workload verity on Ok(false).
    *config = selected;
    Ok(attached)
}

fn attach_installed_bundle(config: &mut VmStartConfig, backend: &str) -> Result<bool> {
    let Some(archive) = installed_archive_for_rootfs(Path::new(&config.rootfs_path))? else {
        return Ok(false);
    };
    let registry = BundleRegistry::default_path()?;
    let trust = FsTrustStore::default_path()?;
    let verified = verify_bundle_file(&archive, &trust).context("verifying bundle boot assets")?;
    ensure!(
        registry.archive_path(&verified.bundle_sha256) == archive,
        "installed bundle archive identity changed"
    );
    let installed = registry
        .find(&verified.bundle_sha256)?
        .context("installed bundle is missing")?;
    ensure!(
        installed.manifest == verified.manifest,
        "installed bundle manifest changed"
    );
    attach_workload_verity(config, &installed)?;
    let Some(boot) = &verified.boot_assets else {
        return Ok(false);
    };
    ensure!(
        config.legacy_bundle_runtime.is_none() && !config.unsigned_runtime_development,
        "portable bundle conflicts with baked or unsigned runtime selection"
    );
    if boot.cli_runtime.is_some() {
        ensure!(
            config.legacy_portable_runtime.is_none() && config.bundle_boot_assets.is_none(),
            "CLI portable bundle conflicts with legacy portable runtime selection"
        );
    } else {
        ensure!(
            config.runtime_release_proof.is_none(),
            "legacy portable bundle conflicts with CLI release runtime selection"
        );
    }
    ensure!(
        boot.arch == GuestArch::host(),
        "bundle boot-assets architecture differs from host"
    );
    let kind = BackendKind::from_label(backend).context("unknown bundle boot backend")?;
    let support = BackendImageSupport::for_backend(kind)
        .context("backend cannot consume bundle boot assets")?;
    mvm_core::plan::bundle::check_boot_assets_for_backend(
        boot,
        &support,
        &mvm_build::stage0_kernel::current_image_set_protocol_support(),
    )?;
    if let Some(runtime) = &boot.cli_runtime {
        attach_cli_runtime(config, &installed, runtime)?;
        return Ok(true);
    }
    let initrd = verified
        .manifest
        .find_by_role(&ArtifactRole::Initrd)
        .context("bundle boot assets require a signed initrd")?;
    let set = mvm_build::published_image_set::SetMemberCache::for_root(
        boot.image_set.manifest_sha256.clone(),
    );
    let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
    let staging = tempfile::tempdir()?;
    let [overlay_member, initramfs_member] =
        select_boot_asset_members(&boot.image_set.manifest, boot.arch)?;
    let overlay_archive = authenticated_copy(
        overlay_member,
        &boot.image_set,
        &installed.root,
        staging.path(),
    )?;
    let initramfs_archive = authenticated_copy(
        initramfs_member,
        &boot.image_set,
        &installed.root,
        staging.path(),
    )?;
    mvm_build::runtime_overlay::install_image_set_runtime_overlay_archive(
        &overlay_archive,
        &set,
        boot.image_set.manifest_sha256.as_str(),
        boot.arch,
        &cache,
    )?;
    mvm_build::initramfs::install_image_set_initramfs_archive(
        &initramfs_archive,
        &set,
        boot.arch,
        &cache,
    )?;
    let overlay =
        mvm_build::runtime_overlay::resolve_image_set_runtime_overlay(&cache, &set, boot.arch)?;
    let ramdisk = mvm_build::initramfs::resolve_image_set_initramfs(&cache, &set, boot.arch)?;
    let initrd_sha256 = mvm_core::crypto::image_verify::sha256_file(&ramdisk.image_path)?;
    ensure!(
        std::fs::metadata(&ramdisk.image_path)?.len() == initrd.size_bytes
            && initrd_sha256 == initrd.sha256,
        "bundle member initrd differs from the signed boot initrd"
    );
    let boot_pin = BundleBootAssetsPin {
        manifest_sha256: boot.image_set.manifest_sha256.clone(),
        arch: boot.arch,
        initrd_sha256: mvm_core::packs::Sha256Hex::new(initrd_sha256)?,
    };
    if let Some(existing) = &config.bundle_boot_assets {
        ensure!(
            existing.manifest_sha256 == boot_pin.manifest_sha256
                && existing.arch == boot_pin.arch
                && existing.initrd_sha256 == boot_pin.initrd_sha256,
            "legacy portable boot pin conflicts with the signed bundle"
        );
    }
    let portable_proof = mvm_core::vm_backend::LegacyPortableRuntimeProof {
        archive,
        pin: verified.plan_artifact(),
        manifest_sha256: boot.image_set.manifest_sha256.as_str().to_owned(),
        arch: boot.arch,
    };
    if let Some(existing) = &config.legacy_portable_runtime {
        ensure!(
            existing.archive == portable_proof.archive
                && existing.pin == portable_proof.pin
                && existing.manifest_sha256 == portable_proof.manifest_sha256
                && existing.arch == portable_proof.arch,
            "legacy portable runtime proof conflicts with the signed bundle"
        );
    }
    config.runtime_overlay_path = Some(overlay.overlay_ext4.display().to_string());
    config.runtime_overlay_verity_path = Some(overlay.sidecar.display().to_string());
    config.runtime_overlay_roothash = Some(overlay.roothash);
    config.runtime_overlay_version = Some(overlay.version);
    config.initrd_path = Some(ramdisk.image_path.display().to_string());
    config.bundle_boot_assets = Some(boot_pin);
    config.runtime_release_proof = None;
    config.unsigned_runtime_development = false;
    config.legacy_bundle_runtime = None;
    config.legacy_portable_runtime = Some(portable_proof);
    Ok(true)
}

fn attach_cli_runtime(
    config: &mut VmStartConfig,
    installed: &mvm_core::plan::bundle::InstalledBundle,
    runtime: &mvm_core::plan::bundle::EmbeddedCliBootAssets,
) -> Result<()> {
    use mvm_build::guest_runtime::evidence::{
        RuntimeArtifactSelection, verify_runtime_release_proof,
    };
    use mvm_core::protocol::runtime_release::{
        CliRuntimeLaunchBinding, RuntimeBindingProvenance, RuntimeLaunchBinding,
        RuntimeReleaseProof,
    };
    let artifact = |name: &str| -> Result<PathBuf> {
        verify_installed_artifact(
            &installed.root,
            installed
                .manifest
                .find_by_name(name)
                .context("CLI runtime artifact missing")?,
        )
    };
    let archive = installed
        .manifest
        .find_by_name(&runtime.archive_artifact)
        .context("CLI runtime archive declaration missing")?;
    let proof = RuntimeReleaseProof {
        archive: artifact(&runtime.archive_artifact)?,
        checksum: artifact(&runtime.checksum_artifact)?,
        signature_bundle: artifact(&runtime.signature_bundle_artifact)?,
        archive_sha256: archive.sha256.clone(),
        version: runtime.version.clone(),
        arch: GuestArch::host(),
    };
    if let Some(existing) = &config.runtime_release_proof {
        ensure!(
            existing == &proof,
            "CLI portable runtime proof conflicts with the signed bundle"
        );
    }
    // Retain the complete published quartet. The archive bundle is the
    // authentication authority; every retained input is also bundle-bound.
    let checksum_bundle = artifact(&runtime.checksum_signature_bundle_artifact)?;
    ensure!(
        checksum_bundle
            == mvm_build::guest_runtime::evidence::checksum_bundle_path(&proof.checksum),
        "retained checksum signature bundle is not paired with its checksum"
    );
    let overlay_path = artifact(&runtime.overlay_artifact)?;
    let overlay_verity_path = artifact(&runtime.overlay_verity_artifact)?;
    let initramfs_path = artifact(&runtime.initramfs_artifact)?;
    let verified = verify_runtime_release_proof(&proof, &runtime.version, proof.arch)?;
    let declaration = verified.declaration(proof.arch)?;
    ensure!(
        declaration.protocol_version == runtime.protocol_version
            && declaration.min_supported_protocol_version == runtime.min_supported_protocol_version
            && declaration.overlay_roothash == runtime.overlay_roothash,
        "bundle runtime protocol or verity declaration differs from signed release"
    );
    // Check exact prepared bytes through the existing authenticated verifier.
    // The launch boundary takes its own owned snapshots before backend reads;
    // these retained installed paths and proof are inputs, not authority.
    let _checked = verified.snapshot_artifacts(&RuntimeArtifactSelection {
        arch: proof.arch,
        overlay: &overlay_path,
        overlay_verity: &overlay_verity_path,
        overlay_roothash: &runtime.overlay_roothash,
        initramfs: &initramfs_path,
        minimum_protocol: mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
        host_protocol: mvm_runtime::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
    })?;
    RuntimeLaunchBinding::CliAssembly(CliRuntimeLaunchBinding {
        provenance: RuntimeBindingProvenance::Release { proof },
        overlay_path,
        overlay_verity_path,
        initramfs_path,
        overlay_roothash: runtime.overlay_roothash.clone(),
    })
    .apply_to_config(config);
    config.bundle_boot_assets = None;
    config.legacy_portable_runtime = None;
    Ok(())
}

fn attach_workload_verity(
    config: &mut VmStartConfig,
    installed: &mvm_core::plan::bundle::InstalledBundle,
) -> Result<()> {
    let rootfs = installed
        .manifest
        .find_by_role(&ArtifactRole::Rootfs)
        .context("bundle rootfs missing")?;
    ensure!(
        Path::new(&config.rootfs_path) == installed.root.join(&rootfs.path),
        "boot rootfs differs from bundle"
    );
    let kernel = installed
        .manifest
        .find_by_role(&ArtifactRole::Kernel)
        .context("bundle kernel missing")?;
    ensure!(
        config.kernel_path.as_deref().map(Path::new)
            == Some(installed.root.join(&kernel.path).as_path()),
        "boot kernel differs from bundle"
    );
    for artifact in [rootfs, kernel] {
        verify_installed_artifact(&installed.root, artifact)?;
    }
    let binding = installed
        .manifest
        .verity
        .as_ref()
        .map(|verity| {
            let artifact = installed
                .manifest
                .find_by_name(&verity.sidecar_artifact)
                .context("bundle verity artifact missing")?;
            ensure!(
                artifact.role == ArtifactRole::VerityHashSidecar,
                "bundle verity artifact has the wrong role"
            );
            let path = verify_installed_artifact(&installed.root, artifact)?;
            Ok::<_, anyhow::Error>((path.display().to_string(), verity.roothash.clone()))
        })
        .transpose()?;
    // An authenticated bundle declaration supersedes any ambient sibling pair.
    (config.verity_path, config.roothash) = match binding {
        Some((path, hash)) => (Some(path), Some(hash)),
        None => (None, None),
    };
    Ok(())
}

fn verify_installed_artifact(
    root: &Path,
    artifact: &mvm_core::plan::bundle::BundleArtifact,
) -> Result<PathBuf> {
    let path = root.join(&artifact.path);
    ensure!(
        std::fs::symlink_metadata(&path)?.file_type().is_file(),
        "installed bundle artifact is not a regular file: {}",
        artifact.path
    );
    let size = std::fs::metadata(&path)
        .with_context(|| format!("reading installed bundle artifact {}", artifact.path))?
        .len();
    ensure!(
        size == artifact.size_bytes,
        "installed bundle artifact size changed: {}",
        artifact.path
    );
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(&path)? == artifact.sha256,
        "installed bundle artifact digest changed: {}",
        artifact.path
    );
    Ok(path)
}

fn authenticated_copy(
    member: &ImageSetMember,
    image_set: &VerifiedEmbeddedImageSet,
    installed_root: &Path,
    staging: &Path,
) -> Result<PathBuf> {
    ensure!(
        member.artifacts.len() == 1,
        "bundle runtime member must contain one archive"
    );
    let artifact = &member.artifacts[0];
    let path = image_set
        .artifact_paths
        .get(artifact.name.as_str())
        .context("bundle runtime archive missing")?;
    let authenticated = staging.join(artifact.name.as_str());
    // Parse only a private copy, authenticated after copying so a changing
    // installed archive cannot replace the bytes between verification and use.
    let size = std::fs::copy(installed_root.join(path), &authenticated)
        .with_context(|| format!("copying installed bundle runtime archive {path}"))?;
    ensure!(
        size == artifact.size,
        "bundle runtime archive size changed: {path}"
    );
    ensure!(
        mvm_core::crypto::image_verify::sha256_file(&authenticated)? == artifact.sha256.as_str(),
        "bundle runtime archive digest changed: {path}"
    );
    Ok(authenticated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use mvm_build::boot_asset_fixture;
    use mvm_build::published_image_set::fixture::ImageSetFixture;
    use mvm_bundler::{
        BootAssetsInputs, BundleExportInputs, BundleSigner, export_bundle_with_signer,
    };
    use mvm_core::image_set::{ImageSetVersion, MemberTarget};
    use mvm_core::packs::Sha256Hex;
    use mvm_core::util::test_env::TestEnv;

    struct Publisher(SigningKey);

    impl BundleSigner for Publisher {
        fn publisher_id(&self) -> String {
            "offline-runtime-test".into()
        }
        fn verifying_key(&self) -> VerifyingKey {
            self.0.verifying_key()
        }
        fn sign(&self, bytes: &[u8]) -> Result<[u8; 64]> {
            Ok(self.0.sign(bytes).to_bytes())
        }
    }

    #[test]
    fn checksum_bundle_pairing_uses_the_release_verifier_rule() {
        for (checksum, bundle) in [
            (
                "artifacts/runtime.sha256",
                "artifacts/runtime.sha256.bundle",
            ),
            ("artifacts/proof.txt", "artifacts/proof.txt.bundle"),
        ] {
            assert_eq!(
                mvm_build::guest_runtime::evidence::checksum_bundle_path(Path::new(checksum)),
                PathBuf::from(bundle)
            );
        }
    }

    #[test]
    fn signed_schema5_bundle_does_not_authorize_unsigned_or_tampered_runtime_inputs() {
        use mvm_bundler::CliBootAssetsInputs;
        use mvm_core::image_set::{
            BaseImageContract, BuilderBootAbi, IMAGE_SET_SCHEMA_VERSION, ImageSetRole,
            WorkloadImageProfile,
        };
        use mvm_core::plan::bundle::EmbeddedCliBootAssets;

        let home = tempfile::tempdir().unwrap();
        let producer = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.set("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:1/unreachable");
        let arch = GuestArch::host();
        let kernel_bytes = b"portable Linux kernel";
        let mut linux = ImageSetFixture::complete()
            .publish(
                ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
                MemberTarget::Arch(arch),
                "portable-kernel",
                kernel_bytes.to_vec(),
            )
            .into_manifest();
        linux.schema_version = IMAGE_SET_SCHEMA_VERSION;
        linux.mvm_source_commit = None;
        linux.compatibility.guest_agent_protocol = None;
        linux.compatibility.base_image_contract = Some(BaseImageContract::LINUX_LAYER);
        linux.compatibility.builder_boot_abi = Some(BuilderBootAbi::NO_MVM_BINARY);
        linux.members.retain(|member| !member.role.is_retired());
        let manifest_bytes = serde_json::to_vec_pretty(&linux).unwrap();
        let pin = Sha256Hex::from_bytes(&manifest_bytes);
        let kernel = producer.path().join("kernel");
        let rootfs = producer.path().join("rootfs.ext4");
        let archive = producer.path().join("bundle.mvmpkg");
        std::fs::write(&kernel, kernel_bytes).unwrap();
        std::fs::write(&rootfs, b"portable workload").unwrap();
        std::fs::write(producer.path().join("mvm-meta.json"), b"{}").unwrap();
        let runtime = EmbeddedCliBootAssets {
            manifest_artifact: "boot-image-set.json".into(),
            version: "99.2.3".into(),
            arch: arch.to_string(),
            archive_artifact: "runtime.tar.gz".into(),
            checksum_artifact: "runtime.sha256".into(),
            signature_bundle_artifact: "runtime.bundle".into(),
            checksum_signature_bundle_artifact: "runtime.sha256.bundle".into(),
            overlay_artifact: "overlay.ext4".into(),
            overlay_verity_artifact: "overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: "a".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 2,
        };
        let paths: Vec<_> = [
            "runtime.tar.gz",
            "runtime.sha256",
            "runtime.bundle",
            "runtime.sha256.bundle",
            "overlay.ext4",
            "overlay.verity",
            "initrd",
        ]
        .into_iter()
        .map(|name| {
            let path = producer.path().join(name);
            std::fs::write(&path, format!("unsigned:{name}")).unwrap();
            (name, path)
        })
        .collect();
        let files: Vec<_> = paths
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect();
        let arch_label = arch.to_string();
        let publisher = Publisher(SigningKey::from_bytes(&[13; 32]));
        let mut inputs = BundleExportInputs::new(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            &arch_label,
            &archive,
        )
        .initrd(paths.last().unwrap().1.to_str().unwrap());
        inputs.cli_boot_assets = Some(CliBootAssetsInputs {
            manifest_bytes: &manifest_bytes,
            manifest_sha256: &pin,
            runtime: &runtime,
            artifacts: &files,
        });
        export_bundle_with_signer(&inputs, &publisher).unwrap();
        let trust = FsTrustStore::default_path().unwrap();
        std::fs::create_dir_all(trust.root()).unwrap();
        std::fs::write(
            trust.root().join(format!("{}.pub", publisher.key_id().0)),
            publisher.verifying_key().as_bytes(),
        )
        .unwrap();
        let registry = BundleRegistry::default_path().unwrap();
        let installed = registry.install_file(&archive, &trust, false).unwrap();
        let config = VmStartConfig {
            rootfs_path: installed
                .path_for_role(&ArtifactRole::Rootfs)
                .unwrap()
                .display()
                .to_string(),
            kernel_path: Some(
                installed
                    .path_for_role(&ArtifactRole::Kernel)
                    .unwrap()
                    .display()
                    .to_string(),
            ),
            ..VmStartConfig::default()
        };
        let mut attempted = config.clone();
        attempted.verity_path = Some("/untrusted/workload-verity".into());
        attempted.roothash = Some("d".repeat(64));
        let before = serde_json::to_value(&attempted).unwrap();
        assert!(attach_if_installed_bundle(&mut attempted, "qemu").is_err());
        assert_eq!(serde_json::to_value(&attempted).unwrap(), before);
        assert!(attempted.runtime_release_proof.is_none());
        assert!(attempted.runtime_overlay_path.is_none());
        let mut mixed = config.clone();
        mixed.legacy_portable_runtime = Some(mvm_core::vm_backend::LegacyPortableRuntimeProof {
            archive: registry.archive_path(&installed.sha256),
            pin: verify_bundle_file(&archive, &trust)
                .unwrap()
                .plan_artifact(),
            manifest_sha256: pin.as_str().to_owned(),
            arch,
        });
        let error = attach_if_installed_bundle(&mut mixed, "qemu").unwrap_err();
        assert!(
            error.to_string().contains("conflicts with legacy portable"),
            "{error}"
        );
        assert!(mixed.legacy_portable_runtime.is_some());
        assert!(mixed.runtime_release_proof.is_none());
        let mut conflicting = config.clone();
        conflicting.runtime_release_proof =
            Some(mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                archive: installed.path_for_name(&runtime.archive_artifact).unwrap(),
                checksum: installed.path_for_name(&runtime.checksum_artifact).unwrap(),
                signature_bundle: installed
                    .path_for_name(&runtime.signature_bundle_artifact)
                    .unwrap(),
                archive_sha256: "a".repeat(64),
                version: "different-explicit-version".into(),
                arch,
            });
        let requested = conflicting.runtime_release_proof.clone();
        let error = attach_if_installed_bundle(&mut conflicting, "qemu").unwrap_err();
        assert!(error.to_string().contains("proof conflicts"), "{error}");
        assert_eq!(conflicting.runtime_release_proof, requested);
        assert!(conflicting.runtime_overlay_path.is_none());

        // Replacing a checksum's extension must not select another sidecar or
        // make the release verifier silently treat the fourth proof as absent.
        let mut renamed_runtime = runtime.clone();
        renamed_runtime.checksum_artifact = "proof.txt".into();
        renamed_runtime.checksum_signature_bundle_artifact = "proof.sha256.bundle".into();
        let renamed_files: Vec<_> = files
            .iter()
            .map(|(name, path)| {
                let name = if *name == runtime.checksum_artifact {
                    renamed_runtime.checksum_artifact.as_str()
                } else if *name == runtime.checksum_signature_bundle_artifact {
                    renamed_runtime.checksum_signature_bundle_artifact.as_str()
                } else {
                    *name
                };
                (name, *path)
            })
            .collect();
        let renamed_archive = producer.path().join("renamed.mvmpkg");
        let mut renamed_inputs = inputs.clone();
        renamed_inputs.out = &renamed_archive;
        renamed_inputs.cli_boot_assets.as_mut().unwrap().runtime = &renamed_runtime;
        renamed_inputs.cli_boot_assets.as_mut().unwrap().artifacts = &renamed_files;
        export_bundle_with_signer(&renamed_inputs, &publisher).unwrap();
        let renamed = registry
            .install_file(&renamed_archive, &trust, false)
            .unwrap();
        let mut renamed_config = VmStartConfig {
            rootfs_path: renamed
                .path_for_role(&ArtifactRole::Rootfs)
                .unwrap()
                .display()
                .to_string(),
            kernel_path: Some(
                renamed
                    .path_for_role(&ArtifactRole::Kernel)
                    .unwrap()
                    .display()
                    .to_string(),
            ),
            verity_path: Some("/untrusted/workload-verity".into()),
            roothash: Some("d".repeat(64)),
            ..VmStartConfig::default()
        };
        let before = serde_json::to_value(&renamed_config).unwrap();
        let error = attach_if_installed_bundle(&mut renamed_config, "qemu").unwrap_err();
        assert!(
            error.to_string().contains("not paired with its checksum"),
            "{error}"
        );
        assert_eq!(serde_json::to_value(&renamed_config).unwrap(), before);
        for name in [
            &runtime.archive_artifact,
            &runtime.checksum_artifact,
            &runtime.signature_bundle_artifact,
            &runtime.checksum_signature_bundle_artifact,
            &runtime.overlay_artifact,
            &runtime.overlay_verity_artifact,
            &runtime.initramfs_artifact,
        ] {
            let path = installed.path_for_name(name).unwrap();
            let original = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"changed").unwrap();
            let mut attempted = config.clone();
            let error = attach_if_installed_bundle(&mut attempted, "qemu").unwrap_err();
            assert!(error.to_string().contains("changed"), "{name}: {error}");
            assert!(attempted.runtime_release_proof.is_none());
            std::fs::write(&path, &original).unwrap();
        }
        let fourth = installed
            .path_for_name(&runtime.checksum_signature_bundle_artifact)
            .unwrap();
        let fourth_bytes = std::fs::read(&fourth).unwrap();
        std::fs::remove_file(&fourth).unwrap();
        let mut missing_fourth = config.clone();
        missing_fourth.verity_path = Some("/untrusted/workload-verity".into());
        missing_fourth.roothash = Some("d".repeat(64));
        let before = serde_json::to_value(&missing_fourth).unwrap();
        assert!(attach_if_installed_bundle(&mut missing_fourth, "qemu").is_err());
        assert_eq!(serde_json::to_value(&missing_fourth).unwrap(), before);
        std::fs::write(&fourth, fourth_bytes).unwrap();
        let proof_path = installed
            .path_for_name(&runtime.signature_bundle_artifact)
            .unwrap();
        std::fs::remove_file(proof_path).unwrap();
        assert!(attach_if_installed_bundle(&mut config.clone(), "qemu").is_err());
    }

    #[test]
    fn signed_boot_assets_attach_offline_and_refuse_missing_or_corrupt_members() {
        let home = tempfile::tempdir().unwrap();
        let producer = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.set("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:1/unreachable");
        let arch = GuestArch::host();
        let version = "99.2.3";
        let overlay_bytes = boot_asset_fixture::runtime_overlay_archive_bytes(
            arch,
            &boot_asset_fixture::valid_overlay_ext4_bytes(),
            b"synthetic-verity-sidecar",
            format!("{}\n", "a".repeat(64)).as_bytes(),
            version.as_bytes(),
        );
        let (initrd_bytes, hash, size) = boot_asset_fixture::initramfs_fixture(b"synthetic cpio");
        let initramfs_bytes = boot_asset_fixture::initramfs_archive_bytes(
            &initrd_bytes,
            hash.as_bytes(),
            size.as_bytes(),
            version.as_bytes(),
        );
        let mut manifest = ImageSetFixture::complete()
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_OVERLAY_ROLE,
                MemberTarget::Arch(arch),
                "overlay.tar.gz",
                overlay_bytes.clone(),
            )
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_INITRAMFS_ROLE,
                MemberTarget::Arch(arch),
                "initramfs.tar.gz",
                initramfs_bytes.clone(),
            )
            .into_manifest();
        // Deliberately not the running CLI's locked root or release.
        manifest.set_version = ImageSetVersion::new(version).unwrap();
        if let mvm_core::image_set::ImageSetProducer::Release(release) = &mut manifest.producer {
            release.release_tag =
                mvm_core::image_set::ReleaseTag::new(format!("v{version}")).unwrap();
        }
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let root = Sha256Hex::from_bytes(&manifest_bytes);
        assert_ne!(
            root,
            mvm_core::image_set::image_train_lock()
                .image_set
                .manifest_sha256
        );
        let kernel = producer.path().join("kernel");
        let rootfs = producer.path().join("rootfs.ext4");
        let initrd = producer.path().join("initrd");
        let overlay = producer.path().join("overlay.tar.gz");
        let initramfs = producer.path().join("initramfs.tar.gz");
        let archive = producer.path().join("bundle.mvmpkg");
        std::fs::write(&kernel, b"synthetic kernel").unwrap();
        std::fs::write(&rootfs, b"synthetic rootfs").unwrap();
        std::fs::write(&initrd, &initrd_bytes).unwrap();
        std::fs::write(&overlay, overlay_bytes).unwrap();
        std::fs::write(&initramfs, initramfs_bytes).unwrap();
        std::fs::write(producer.path().join("mvm-meta.json"), b"{}").unwrap();
        let publisher = Publisher(SigningKey::from_bytes(&rand::random()));
        let arch_label = arch.to_string();
        let workload_hash = "b".repeat(64);
        let mut inputs = BundleExportInputs::new(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            &arch_label,
            &archive,
        )
        .initrd(initrd.to_str().unwrap())
        .verity(b"workload merkle tree", &workload_hash);
        inputs.boot_assets = Some(BootAssetsInputs {
            manifest_bytes: &manifest_bytes,
            manifest_sha256: &root,
            runtime_overlay: &overlay,
            initramfs: &initramfs,
        });
        export_bundle_with_signer(&inputs, &publisher).unwrap();
        let trust = FsTrustStore::default_path().unwrap();
        std::fs::create_dir_all(trust.root()).unwrap();
        std::fs::write(
            trust.root().join(format!("{}.pub", publisher.key_id().0)),
            publisher.verifying_key().as_bytes(),
        )
        .unwrap();
        let registry = BundleRegistry::default_path().unwrap();
        let installed = registry.install_file(&archive, &trust, false).unwrap();
        assert_eq!(installed.manifest.schema_version, 4);
        let verified = verify_bundle_file(&archive, &trust).unwrap();
        let boot = verified.boot_assets.unwrap();
        let config = VmStartConfig {
            rootfs_path: installed
                .root
                .join(
                    &installed
                        .manifest
                        .find_by_role(&ArtifactRole::Rootfs)
                        .unwrap()
                        .path,
                )
                .display()
                .to_string(),
            kernel_path: Some(
                installed
                    .root
                    .join(
                        &installed
                            .manifest
                            .find_by_role(&ArtifactRole::Kernel)
                            .unwrap()
                            .path,
                    )
                    .display()
                    .to_string(),
            ),
            ..Default::default()
        };
        assert!(!Path::new(&mvm_core::config::mvm_cache_dir()).exists());
        let mut attached = config.clone();
        assert!(attach_if_installed_bundle(&mut attached, "qemu").unwrap());
        let portable_proof = attached.legacy_portable_runtime.as_ref().unwrap();
        assert_eq!(
            portable_proof.archive,
            registry.archive_path(&installed.sha256)
        );
        assert_eq!(
            portable_proof.pin,
            verify_bundle_file(&archive, &trust)
                .unwrap()
                .plan_artifact()
        );
        assert_eq!(
            portable_proof.manifest_sha256,
            boot.image_set.manifest_sha256.as_str()
        );
        assert_eq!(portable_proof.arch, arch);
        assert!(attached.legacy_bundle_runtime.is_none());
        assert!(attached.runtime_release_proof.is_none());
        assert!(!attached.unsigned_runtime_development);
        assert!(attached.runtime_overlay_path.is_some());
        assert!(attached.runtime_overlay_verity_path.is_some());
        assert_eq!(attached.runtime_overlay_version.as_deref(), Some(version));
        let mut mixed = attached.clone();
        mixed.verity_path = Some("/untrusted/workload-verity".into());
        mixed.roothash = Some("d".repeat(64));
        mixed.runtime_release_proof =
            Some(mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                archive: producer.path().join("unrelated-release"),
                checksum: producer.path().join("unrelated-checksum"),
                signature_bundle: producer.path().join("unrelated-signature"),
                archive_sha256: "c".repeat(64),
                version: version.into(),
                arch,
            });
        let requested = mixed.runtime_release_proof.clone();
        let before = serde_json::to_value(&mixed).unwrap();
        let error = attach_if_installed_bundle(&mut mixed, "qemu").unwrap_err();
        assert!(
            error.to_string().contains("conflicts with CLI release"),
            "{error}"
        );
        assert_eq!(mixed.runtime_release_proof, requested);
        assert_eq!(serde_json::to_value(&mixed).unwrap(), before);
        assert!(mixed.legacy_portable_runtime.is_some());
        assert_eq!(mixed.runtime_overlay_path, attached.runtime_overlay_path);
        let mut unsigned = attached.clone();
        unsigned.unsigned_runtime_development = true;
        assert!(attach_if_installed_bundle(&mut unsigned, "qemu").is_err());
        assert!(unsigned.unsigned_runtime_development);
        let mut changed_identity = attached.clone();
        changed_identity
            .legacy_portable_runtime
            .as_mut()
            .unwrap()
            .manifest_sha256 = "c".repeat(64);
        let error = attach_if_installed_bundle(&mut changed_identity, "qemu").unwrap_err();
        assert!(error.to_string().contains("proof conflicts"), "{error}");
        assert_eq!(
            changed_identity
                .legacy_portable_runtime
                .as_ref()
                .unwrap()
                .manifest_sha256,
            "c".repeat(64)
        );
        assert_eq!(
            changed_identity.runtime_overlay_path,
            attached.runtime_overlay_path
        );
        assert_eq!(attached.roothash.as_deref(), Some(workload_hash.as_str()));
        let verity_path = PathBuf::from(attached.verity_path.as_ref().unwrap());
        assert!(!verity_path.with_extension("roothash").exists());
        assert_eq!(
            verity_path,
            installed.root.join(
                &installed
                    .manifest
                    .find_by_role(&ArtifactRole::VerityHashSidecar)
                    .unwrap()
                    .path
            )
        );
        let mut ambient = config.clone();
        ambient.verity_path = Some("/untrusted/tree".into());
        ambient.roothash = Some("c".repeat(64));
        assert!(attach_if_installed_bundle(&mut ambient, "qemu").unwrap());
        assert_eq!(ambient.verity_path, attached.verity_path);
        assert_eq!(ambient.roothash, attached.roothash);
        let mut wrong_kernel = config.clone();
        wrong_kernel.kernel_path = Some("/untrusted/kernel".into());
        assert!(
            attach_if_installed_bundle(&mut wrong_kernel, "qemu")
                .unwrap_err()
                .to_string()
                .contains("boot kernel differs")
        );
        let mut wrong_rootfs = config.clone();
        wrong_rootfs.rootfs_path = installed.root.join("other.ext4").display().to_string();
        assert!(
            attach_if_installed_bundle(&mut wrong_rootfs, "qemu")
                .unwrap_err()
                .to_string()
                .contains("boot rootfs differs")
        );
        for artifact in [
            ArtifactRole::Rootfs,
            ArtifactRole::Kernel,
            ArtifactRole::VerityHashSidecar,
        ] {
            let path = installed
                .root
                .join(&installed.manifest.find_by_role(&artifact).unwrap().path);
            let original = std::fs::read(&path).unwrap();
            for corruption in [None, Some(vec![0; original.len()]), Some(vec![0])] {
                if let Some(bytes) = corruption {
                    std::fs::write(&path, bytes).unwrap();
                } else {
                    std::fs::remove_file(&path).unwrap();
                }
                let error = attach_if_installed_bundle(&mut config.clone(), "qemu").unwrap_err();
                assert!(format!("{error:#}").contains("installed bundle artifact"));
                std::fs::write(&path, &original).unwrap();
            }
        }
        let pin = attached.bundle_boot_assets.as_ref().unwrap();
        assert_eq!(pin.manifest_sha256, root);
        assert_eq!(pin.initrd_sha256, Sha256Hex::from_bytes(&initrd_bytes));
        assert_eq!(
            mvm_core::crypto::image_verify::sha256_file(Path::new(
                attached.initrd_path.as_ref().unwrap()
            ))
            .unwrap(),
            installed
                .manifest
                .find_by_role(&ArtifactRole::Initrd)
                .unwrap()
                .sha256,
        );
        assert_eq!(attached.runtime_overlay_version.as_deref(), Some(version));
        assert!(
            attached
                .runtime_overlay_path
                .as_ref()
                .unwrap()
                .contains(root.as_str())
        );
        for path in boot.image_set.artifact_paths.values() {
            let installed_member = installed.root.join(path);
            let original = std::fs::read(&installed_member).unwrap();
            for missing in [true, false] {
                if missing {
                    std::fs::remove_file(&installed_member).unwrap();
                } else {
                    let mut corrupt = original.clone();
                    corrupt[0] ^= 1;
                    std::fs::write(&installed_member, corrupt).unwrap();
                }
                let mut refused = config.clone();
                let error = super::super::runtime_source::attach_runtime_overlay_if_cached_version(
                    &mut refused,
                    "qemu",
                    None,
                    None,
                )
                .unwrap_err();
                let message = format!("{error:#}");
                assert!(
                    message.contains(if missing {
                        "copying installed"
                    } else {
                        "digest changed"
                    }),
                    "{message}"
                );
                assert!(refused.bundle_boot_assets.is_none());
                assert!(refused.runtime_overlay_path.is_none());
                assert!(refused.initrd_path.is_none());
                std::fs::write(&installed_member, &original).unwrap();
            }
        }

        // Legacy bundles still leave runtime selection to their original path.
        inputs.boot_assets = None;
        export_bundle_with_signer(&inputs, &publisher).unwrap();
        let legacy = registry.install_file(&archive, &trust, false).unwrap();
        let mut legacy_config = VmStartConfig {
            rootfs_path: legacy
                .root
                .join(
                    &legacy
                        .manifest
                        .find_by_role(&ArtifactRole::Rootfs)
                        .unwrap()
                        .path,
                )
                .display()
                .to_string(),
            kernel_path: Some(
                legacy
                    .root
                    .join(
                        &legacy
                            .manifest
                            .find_by_role(&ArtifactRole::Kernel)
                            .unwrap()
                            .path,
                    )
                    .display()
                    .to_string(),
            ),
            ..Default::default()
        };
        assert!(!attach_if_installed_bundle(&mut legacy_config, "qemu").unwrap());
        assert_eq!(
            legacy_config.roothash.as_deref(),
            Some(workload_hash.as_str())
        );
        assert!(legacy_config.runtime_overlay_path.is_none());
        assert!(legacy_config.initrd_path.is_none());
        assert!(legacy_config.bundle_boot_assets.is_none());

        inputs.verity_bytes = None;
        inputs.roothash = None;
        export_bundle_with_signer(&inputs, &publisher).unwrap();
        let unsealed = registry.install_file(&archive, &trust, false).unwrap();
        let rootfs = unsealed.root.join(
            &unsealed
                .manifest
                .find_by_role(&ArtifactRole::Rootfs)
                .unwrap()
                .path,
        );
        let stray_tree = rootfs.with_extension("verity");
        std::fs::write(&stray_tree, b"ambient tree").unwrap();
        std::fs::write(rootfs.with_extension("roothash"), &workload_hash).unwrap();
        let mut unsealed_config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            kernel_path: Some(
                unsealed
                    .root
                    .join(
                        &unsealed
                            .manifest
                            .find_by_role(&ArtifactRole::Kernel)
                            .unwrap()
                            .path,
                    )
                    .display()
                    .to_string(),
            ),
            verity_path: Some(stray_tree.display().to_string()),
            roothash: Some(workload_hash),
            ..Default::default()
        };
        assert!(!attach_if_installed_bundle(&mut unsealed_config, "qemu").unwrap());
        assert!(unsealed_config.verity_path.is_none());
        assert!(unsealed_config.roothash.is_none());
    }

    #[test]
    fn ordinary_sources_keep_their_verity_binding() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut config = VmStartConfig {
            rootfs_path: home.path().join("rootfs.ext4").display().to_string(),
            verity_path: Some("/source/rootfs.verity".into()),
            roothash: Some("a".repeat(64)),
            ..Default::default()
        };
        assert!(!attach_if_installed_bundle(&mut config, "qemu").unwrap());
        assert_eq!(config.verity_path.as_deref(), Some("/source/rootfs.verity"));
        assert_eq!(config.roothash, Some("a".repeat(64)));
    }

    #[test]
    fn missing_bundle_never_falls_back_to_a_source_build_or_download() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.set("MVM_UPDATE_DOWNLOAD_URL", "http://127.0.0.1:1/unreachable");
        let mut config = VmStartConfig {
            rootfs_path: home
                .path()
                .join("bundles")
                .join("a".repeat(64))
                .join("artifacts/rootfs.ext4")
                .display()
                .to_string(),
            ..Default::default()
        };
        let error = super::super::runtime_source::attach_runtime_overlay_if_cached_version(
            &mut config,
            "firecracker",
            None,
            None,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("verifying bundle boot assets"));
        assert!(config.runtime_overlay_path.is_none());
        assert!(config.initrd_path.is_none());
        assert!(!home.path().join("cache").exists());
    }

    #[test]
    fn a_cache_pin_alone_cannot_authorize_runtime_assets() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let mut config = VmStartConfig {
            rootfs_path: home.path().join("rootfs.ext4").display().to_string(),
            bundle_boot_assets: Some(BundleBootAssetsPin {
                manifest_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"set"),
                arch: GuestArch::host(),
                initrd_sha256: mvm_core::packs::Sha256Hex::from_bytes(b"initrd"),
            }),
            ..Default::default()
        };
        let error = super::super::runtime_source::attach_runtime_overlay_if_cached_version(
            &mut config,
            "firecracker",
            None,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refusing runtime fallback"));
        assert!(config.runtime_overlay_path.is_none());
    }
}
