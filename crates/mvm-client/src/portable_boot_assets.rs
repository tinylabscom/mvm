//! Original Linux image-set assets paired with the signed CLI guest runtime.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_build::guest_runtime::evidence::{
    RuntimeArtifactSelection, VerifiedRuntimeArtifacts, verify_runtime_release_proof,
};
use mvm_build::oci_runtime_inject::MvmRuntimeBinaries;
use mvm_build::published_image_set::{PublishedImageSet, RetainedPublisherProof};
use mvm_core::arch::GuestArch;
use mvm_core::crypto::image_verify::sha256_file;
use mvm_core::plan::bundle::EmbeddedCliBootAssets;
use mvm_core::protocol::runtime_release::RuntimeReleaseProof;

/// Producer-owned release boot closure. Construction uses only the existing
/// authenticated Linux and CLI-release paths; it cannot hold a Source runtime.
/// Consumers never acquire this object to fill an incomplete package.
///
/// ```compile_fail
/// let _: mvm_client::portable_boot_assets::PreparedPortableBootAssets =
///     serde_json::from_str("{}").unwrap();
/// ```
pub struct PreparedPortableBootAssets {
    _directory: tempfile::TempDir,
    pub(crate) kernel: PathBuf,
    pub(crate) runtime_overlay: PathBuf,
    pub(crate) runtime_overlay_verity: PathBuf,
    pub(crate) initrd: PathBuf,
    pub(crate) binaries: MvmRuntimeBinaries,
    pub(crate) release_proof: RuntimeReleaseProof,
    pub(crate) checksum_signature_bundle: PathBuf,
    pub(crate) runtime: EmbeddedCliBootAssets,
    _prepared: VerifiedRuntimeArtifacts,
    publisher: RetainedPublisherProof,
    home: PathBuf,
    bindings: Vec<(PathBuf, String, u64)>,
}

impl PreparedPortableBootAssets {
    pub fn acquire(arch: GuestArch) -> Result<Self> {
        let image_set = PublishedImageSet::acquire_workload()?;
        let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let runtime = mvm_build::guest_runtime::resolve_or_download_guest_runtime_quartet(
            &cache,
            env!("CARGO_PKG_VERSION"),
            arch,
        )?;
        let proof = runtime
            .release_proof
            .context("portable creation requires a signed CLI runtime release")?;
        Self::from_set(image_set, arch, &proof)
    }

    fn from_set(
        image_set: PublishedImageSet,
        arch: GuestArch,
        source_proof: &RuntimeReleaseProof,
    ) -> Result<Self> {
        anyhow::ensure!(
            source_proof.version == env!("CARGO_PKG_VERSION") && source_proof.arch == arch,
            "portable runtime proof differs from the selected CLI version or architecture"
        );
        verify_runtime_release_proof(source_proof, &source_proof.version, arch).with_context(
            || {
                format!(
                    "authenticate selected runtime archive {}",
                    source_proof.archive.display()
                )
            },
        )?;
        let publisher = image_set.retained_publisher_proof()?;
        let home = mvm_core::config::mvm_home_strict()?;
        let directory = tempfile::tempdir().context("stage portable release boot assets")?;
        mvm_core::config::create_private_dir(directory.path())?;
        let root = directory.path();
        let kernel_member =
            mvm_core::plan::bundle::select_cli_boot_kernel(image_set.manifest(), arch)?;
        let kernel_artifact = single_artifact(kernel_member)?;
        let kernel = root.join("vmlinux");
        image_set.fetch_artifact(kernel_artifact, &kernel)?;
        let archive = root.join("guest-runtime.tar.gz");
        let checksum = root.join("guest-runtime.sha256");
        let signature_bundle = root.join("guest-runtime.bundle");
        let checksum_signature_bundle = root.join("guest-runtime.sha256.bundle");
        let source_checksum_bundle =
            mvm_build::guest_runtime::evidence::checksum_bundle_path(&source_proof.checksum);
        for (source, target) in [
            (&source_proof.archive, &archive),
            (&source_proof.checksum, &checksum),
            (&source_proof.signature_bundle, &signature_bundle),
            (&source_checksum_bundle, &checksum_signature_bundle),
        ] {
            std::fs::copy(source, target).with_context(|| {
                format!("retain signed runtime release input {}", source.display())
            })?;
        }
        let release_proof = RuntimeReleaseProof {
            archive,
            checksum,
            signature_bundle,
            ..source_proof.clone()
        };
        let verified = verify_runtime_release_proof(&release_proof, &source_proof.version, arch)?;
        let cache = root.join("runtime-cache");
        let guest_runtime = mvm_build::guest_runtime::install_signed_guest_runtime_archive(
            &cache,
            &release_proof.archive,
            &release_proof.checksum,
            &release_proof.signature_bundle,
            &release_proof.version,
            arch,
        )?;
        let overlay = mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
            &cache,
            &release_proof.version,
            arch,
            &guest_runtime,
        )?;
        let initramfs = mvm_build::initramfs::build_initramfs_from_guest_runtime(
            &cache,
            &release_proof.version,
            arch,
            &guest_runtime,
        )?;
        let prepared = verified.snapshot_artifacts(&RuntimeArtifactSelection {
            arch,
            overlay: &overlay.overlay_ext4,
            overlay_verity: &overlay.sidecar,
            overlay_roothash: &overlay.roothash,
            initramfs: &initramfs.image_path,
            minimum_protocol: mvm_runtime::runtime_evidence::MIN_GUEST_RPC_PROTOCOL_VERSION,
            host_protocol: mvm_runtime::runtime_evidence::GUEST_RPC_PROTOCOL_VERSION,
        })?;
        let runtime_overlay = prepared.overlay_path();
        let runtime_overlay_verity = prepared.overlay_verity_path();
        let initrd = prepared.initramfs_path();
        let declaration = prepared.declaration();
        let runtime = EmbeddedCliBootAssets {
            manifest_artifact: "boot-image-set.json".into(),
            version: release_proof.version.clone(),
            arch: arch.to_string(),
            archive_artifact: "guest-runtime.tar.gz".into(),
            checksum_artifact: "guest-runtime.sha256".into(),
            signature_bundle_artifact: "guest-runtime.bundle".into(),
            checksum_signature_bundle_artifact: "guest-runtime.sha256.bundle".into(),
            overlay_artifact: "runtime-overlay.ext4".into(),
            overlay_verity_artifact: "runtime-overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: declaration.overlay_roothash.clone(),
            protocol_version: declaration.protocol_version,
            min_supported_protocol_version: declaration.min_supported_protocol_version,
        };
        let bin = guest_runtime.root.join(arch.to_string()).join("bin");
        let binaries = MvmRuntimeBinaries {
            agent: bin.join("mvm-guest-agent"),
            netinit: bin.join("mvm-guest-netinit"),
            egress_client: bin.join("mvm-egress-client"),
            entrypoint_runner: bin.join("mvm-oci-entrypoint"),
        };
        let mut bindings = vec![(
            kernel.clone(),
            kernel_artifact.sha256.as_str().to_owned(),
            kernel_artifact.size,
        )];
        for path in [
            &runtime_overlay,
            &runtime_overlay_verity,
            &initrd,
            &release_proof.archive,
            &release_proof.checksum,
            &release_proof.signature_bundle,
            &checksum_signature_bundle,
        ]
        .into_iter()
        .map(PathBuf::as_path)
        .chain(binaries.artifacts().into_iter().map(|(_, path)| path))
        {
            bindings.push((
                path.to_owned(),
                sha256_file(path)?,
                std::fs::metadata(path)?.len(),
            ));
        }
        Ok(Self {
            _directory: directory,
            kernel,
            runtime_overlay,
            runtime_overlay_verity,
            initrd,
            binaries,
            release_proof,
            checksum_signature_bundle,
            runtime,
            _prepared: prepared,
            publisher,
            home,
            bindings,
        })
    }

    pub fn verify_integrity(&self) -> Result<()> {
        anyhow::ensure!(
            mvm_core::config::mvm_home_strict()? == self.home,
            "portable producer closure belongs to another home"
        );
        let current = mvm_core::image_set_revocation::ImageSetRevocationStore::in_mvm_home()
            .load(chrono::Utc::now())?;
        anyhow::ensure!(
            current.checkpoint() == self.publisher.revocations().verified().checkpoint(),
            "portable publisher policy advanced; capture a fresh closure"
        );
        let request = mvm_core::image_set::ImageSetVerification::new(
            self.publisher.root().manifest_bytes(),
            self.publisher.root().signature_bundle(),
            &mvm_core::image_set::image_train_lock().image_set,
            Path::new(""),
        )
        .with_revocations(&current);
        mvm_core::image_set::verify_image_set_root(&request)?;
        verify_bindings(&self.bindings)
    }

    pub fn initramfs_path(&self) -> &Path {
        &self.initrd
    }

    /// Private producer input directories, for retention diagnostics only.
    /// Their existence is not launch, health, or cleanup evidence.
    pub fn retention_paths(&self) -> [&Path; 2] {
        [self._directory.path(), self._prepared.directory_path()]
    }

    /// Check the built slot rather than silently replacing its selected kernel.
    pub fn verify_build_kernel(&self, kernel: &Path) -> Result<()> {
        self.verify_integrity()?;
        verify_kernel_selection(kernel, &self.bindings[0].1)?;
        Ok(())
    }

    /// Bind producer health to this closure, with no host-runtime fallback.
    /// Runtime lifecycle custody still snapshots these exact files before boot.
    pub fn apply_for_health(&self, config: &mut mvm_core::vm_backend::VmStartConfig) -> Result<()> {
        self.verify_build_kernel(Path::new(
            config
                .kernel_path
                .as_deref()
                .context("health kernel missing")?,
        ))?;
        refuse_health_runtime_mix(config)?;
        config.kernel_read_sha256 = Some(self.bindings[0].1.clone());
        config.initrd_path = Some(utf8(&self.initrd)?.into());
        config.runtime_overlay_path = Some(utf8(&self.runtime_overlay)?.into());
        config.runtime_overlay_verity_path = Some(utf8(&self.runtime_overlay_verity)?.into());
        config.runtime_overlay_roothash = Some(self.runtime.overlay_roothash.clone());
        config.runtime_overlay_version = Some(self.release_proof.version.clone());
        config.runtime_release_proof = Some(self.release_proof.clone());
        Ok(())
    }

    /// Check the actual post-admission health config before backend effects.
    pub fn verify_health_config(&self, config: &mvm_core::vm_backend::VmStartConfig) -> Result<()> {
        self.verify_build_kernel(Path::new(
            config
                .kernel_path
                .as_deref()
                .context("health kernel missing")?,
        ))?;
        anyhow::ensure!(
            config.kernel_read_sha256.as_deref() == Some(self.bindings[0].1.as_str())
                && config.initrd_path.as_deref() == self.initrd.to_str()
                && config.runtime_overlay_path.as_deref() == self.runtime_overlay.to_str()
                && config.runtime_overlay_verity_path.as_deref()
                    == self.runtime_overlay_verity.to_str()
                && config.runtime_overlay_roothash.as_deref()
                    == Some(self.runtime.overlay_roothash.as_str())
                && config.runtime_overlay_version.as_deref()
                    == Some(self.release_proof.version.as_str())
                && config.runtime_release_proof.as_ref() == Some(&self.release_proof)
                && !config.unsigned_runtime_development
                && config.source_runtime_archive_sha256.is_none()
                && config.legacy_bundle_runtime.is_none()
                && config.legacy_portable_runtime.is_none(),
            "final health configuration substituted the retained release boot closure"
        );
        Ok(())
    }

    /// Seal the very closure selected for producer health. The signer is not
    /// consulted until proof, artifact and selection checks have succeeded.
    pub fn export(
        &self,
        inputs: &mvm_bundler::BundleExportInputs<'_>,
        signer: &dyn mvm_bundler::BundleSigner,
    ) -> Result<mvm_bundler::ExportedBundle> {
        self.stage(inputs, signer)?.publish()
    }

    /// Seal the same verified closure into an owned, unpublished archive.
    ///
    /// The returned guard owns its sealed bytes until publication or explicit
    /// abort. It is not registry admission or authority to run a workload.
    pub fn stage(
        &self,
        inputs: &mvm_bundler::BundleExportInputs<'_>,
        signer: &dyn mvm_bundler::BundleSigner,
    ) -> Result<mvm_bundler::StagedBundle> {
        self.verify_build_kernel(Path::new(inputs.vmlinux))?;
        verify_export_selection(inputs, &self.runtime.arch, &sha256_file(&self.initrd)?)?;
        let files = [
            (
                self.runtime.archive_artifact.as_str(),
                self.release_proof.archive.as_path(),
            ),
            (
                self.runtime.checksum_artifact.as_str(),
                self.release_proof.checksum.as_path(),
            ),
            (
                self.runtime.signature_bundle_artifact.as_str(),
                self.release_proof.signature_bundle.as_path(),
            ),
            (
                self.runtime.checksum_signature_bundle_artifact.as_str(),
                self.checksum_signature_bundle.as_path(),
            ),
            (
                self.runtime.overlay_artifact.as_str(),
                self.runtime_overlay.as_path(),
            ),
            (
                self.runtime.overlay_verity_artifact.as_str(),
                self.runtime_overlay_verity.as_path(),
            ),
            (
                self.runtime.initramfs_artifact.as_str(),
                self.initrd.as_path(),
            ),
        ];
        let mut selected = inputs.clone();
        selected.cli_boot_assets = Some(mvm_bundler::CliBootAssetsInputs {
            manifest_bytes: self.publisher.root().manifest_bytes(),
            manifest_sha256: self.publisher.root().root().manifest_sha256(),
            runtime: &self.runtime,
            artifacts: &files,
        });
        selected.canonical_linux_proof = Some(mvm_bundler::CanonicalLinuxProofInputs {
            root: self.publisher.root(),
            revocations: self.publisher.revocations(),
        });
        let output = mvm_bundler::stage_bundle_with_signer(&selected, signer)?;
        if let Err(error) = self.verify_integrity() {
            return Err(output.abort(error));
        }
        Ok(output)
    }
}

fn verify_bindings(bindings: &[(PathBuf, String, u64)]) -> Result<()> {
    for (path, expected, size) in bindings {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file()
            || metadata.len() != *size
            || sha256_file(path)? != *expected
        {
            bail!("authenticated boot asset changed: {}", path.display());
        }
    }
    Ok(())
}

fn verify_kernel_selection(kernel: &Path, expected: &str) -> Result<()> {
    anyhow::ensure!(
        sha256_file(kernel)? == expected,
        "built kernel differs from the canonical Linux kernel selected for export"
    );
    Ok(())
}

fn refuse_health_runtime_mix(config: &mvm_core::vm_backend::VmStartConfig) -> Result<()> {
    anyhow::ensure!(
        config.runtime_overlay_path.is_none()
            && config.runtime_overlay_verity_path.is_none()
            && config.runtime_overlay_roothash.is_none()
            && config.runtime_overlay_version.is_none()
            && config.runtime_release_proof.is_none()
            && config.source_runtime_archive_sha256.is_none()
            && config.legacy_bundle_runtime.is_none()
            && config.legacy_portable_runtime.is_none()
            && config.canonical_kernel.is_none()
            && config.kernel_read_sha256.is_none()
            && config.bundle_boot_assets.is_none()
            && !config.unsigned_runtime_development,
        "cannot mix a producer closure with another selected runtime"
    );
    Ok(())
}

fn verify_export_selection(
    inputs: &mvm_bundler::BundleExportInputs<'_>,
    arch: &str,
    initrd: &str,
) -> Result<()> {
    anyhow::ensure!(
        inputs.boot_assets.is_none()
            && inputs.cli_boot_assets.is_none()
            && inputs.canonical_linux_proof.is_none(),
        "cannot mix portable export closures"
    );
    anyhow::ensure!(
        inputs.arch_label == arch
            && inputs
                .initrd
                .map(|p| sha256_file(Path::new(p)))
                .transpose()?
                .as_deref()
                == Some(initrd),
        "export omitted or substituted the health-selected architecture or initramfs"
    );
    Ok(())
}

fn single_artifact(
    member: &mvm_core::image_set::ImageSetMember,
) -> Result<&mvm_core::image_set::MemberArtifact> {
    let [artifact] = member.artifacts.as_slice() else {
        bail!(
            "portable OCI boot requires one artifact for image-set role {:?}",
            member.role
        );
    };
    Ok(artifact)
}

pub(crate) fn utf8(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("artifact path {} is not valid UTF-8", path.display()))
}

#[cfg(all(test, unix))]
#[path = "portable_boot_assets_diagnostic.rs"]
mod diagnostic;

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::boot_asset_fixture;
    use mvm_build::published_image_set::fixture::ImageSetFixture;
    use mvm_core::image_set::{ImageSetRole, MemberTarget, WorkloadImageProfile};
    use mvm_core::util::test_env::TestEnv;

    #[test]
    #[ignore = "requires genuine signed runtime, published Linux proofs, and an existing sealed workload"]
    fn signed_release_exports_real_canonical_workload() {
        let required = |name| PathBuf::from(std::env::var_os(name).expect(name));
        let archive = required("MVM_TEST_SIGNED_RUNTIME_ARCHIVE");
        let rootfs = required("MVM_TEST_CANONICAL_ROOTFS");
        let output = required("MVM_TEST_CANONICAL_OUTPUT");
        let environment = std::env::var_os("MVM_TEST_CANONICAL_ENVIRONMENT").map(|path| {
            let descriptor: mvm_core::plan::EnvironmentDescriptor =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            descriptor.validate().unwrap();
            let metadata: serde_json::Value = serde_json::from_slice(
                &std::fs::read(mvm_bundler::guest_sidecar_path(utf8(&rootfs).unwrap()).unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(&descriptor.entrypoint.argv).unwrap(),
                metadata["entrypointArgv"],
                "signed environment must retain the built entrypoint"
            );
            assert!(descriptor.volumes.is_empty() && descriptor.services.is_empty());
            descriptor
        });
        let proof = RuntimeReleaseProof {
            checksum: archive.with_extension("gz.sha256"),
            signature_bundle: archive.with_extension("gz.bundle"),
            archive_sha256: sha256_file(&archive).unwrap(),
            archive,
            version: std::env::var("MVM_TEST_SIGNED_RUNTIME_VERSION")
                .expect("MVM_TEST_SIGNED_RUNTIME_VERSION"),
            arch: GuestArch::host(),
        };
        let assets = PreparedPortableBootAssets::from_set(
            PublishedImageSet::acquire_workload().unwrap(),
            GuestArch::host(),
            &proof,
        )
        .unwrap();
        // Export the original sealed bytes in place. In particular, retain the
        // raw signed root hash beside the rootfs; never reseal this image.
        let directory = rootfs.parent().unwrap();
        let verity = std::fs::read(directory.join("rootfs.verity")).unwrap();
        let roothash = std::fs::read_to_string(directory.join("rootfs.roothash")).unwrap();
        std::fs::create_dir(&output).expect("output must be a fresh directory");
        mvm_core::config::create_private_dir(&output).unwrap();
        let bundle = output.join("workload.mvmpkg");
        let mut inputs = mvm_bundler::BundleExportInputs::new(
            utf8(&assets.kernel).unwrap(),
            utf8(&rootfs).unwrap(),
            assets.runtime.arch.as_str(),
            &bundle,
        )
        .initrd(utf8(&assets.initrd).unwrap())
        .verity(&verity, roothash.trim())
        .resources(2, 1024)
        .label("signed-runtime-lifecycle-witness");
        if let Some(environment) = environment {
            let resources = environment.resources.as_ref().expect("declared resources");
            let pack = environment.pack.as_ref().expect("package identity");
            inputs = inputs
                .resources(u32::from(resources.cpu_cores), resources.memory_mb)
                .label(format!("{}@{}", pack.name, pack.version))
                .posture(
                    mvm_bundler::PostureInputs::new(mvm_core::security::AgentProfile::SealedProd)
                        .allows_egress(true),
                )
                .environment(environment);
        }
        assets
            .stage(&inputs, &crate::bundle::HostBundleSigner::load().unwrap())
            .unwrap()
            .publish()
            .unwrap();
        println!("canonical portable export: {}", bundle.display());
    }

    #[test]
    fn health_selection_refuses_mixed_runtime_without_modifying_config() {
        let directory = tempfile::tempdir().unwrap();
        let kernel = directory.path().join("kernel");
        std::fs::write(&kernel, b"checked kernel").unwrap();
        let expected = sha256_file(&kernel).unwrap();
        verify_kernel_selection(&kernel, &expected).unwrap();
        let config = mvm_core::vm_backend::VmStartConfig {
            kernel_path: Some(kernel.display().to_string()),
            runtime_overlay_version: Some("another selection".into()),
            ..Default::default()
        };
        let before = format!("{config:?}");
        assert!(refuse_health_runtime_mix(&config).is_err());
        assert_eq!(format!("{config:?}"), before);
        std::fs::write(&kernel, b"substituted").unwrap();
        assert!(verify_kernel_selection(&kernel, &expected).is_err());
    }

    #[test]
    fn export_selection_refuses_omission_substitution_and_mixed_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let kernel = directory.path().join("kernel");
        let rootfs = directory.path().join("rootfs");
        let initrd = directory.path().join("initrd");
        let out = directory.path().join("out");
        std::fs::write(&initrd, b"health initrd").unwrap();
        let expected = sha256_file(&initrd).unwrap();
        let mut inputs = mvm_bundler::BundleExportInputs::new(
            kernel.to_str().unwrap(),
            rootfs.to_str().unwrap(),
            "aarch64",
            &out,
        );
        assert!(verify_export_selection(&inputs, "aarch64", &expected).is_err());
        inputs.initrd = Some(initrd.to_str().unwrap());
        // Selection matching only, not construction of an authenticated closure.
        verify_export_selection(&inputs, "aarch64", &expected).unwrap();
        assert!(verify_export_selection(&inputs, "x86_64", &expected).is_err());
        let pin = mvm_core::packs::Sha256Hex::from_bytes(b"root");
        inputs.boot_assets = Some(mvm_bundler::BootAssetsInputs {
            manifest_bytes: b"root",
            manifest_sha256: &pin,
            runtime_overlay: &kernel,
            initramfs: &initrd,
        });
        assert!(verify_export_selection(&inputs, "aarch64", &expected).is_err());
        inputs.boot_assets = None;
        std::fs::write(&initrd, b"changed after health").unwrap();
        assert!(verify_export_selection(&inputs, "aarch64", &expected).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn retained_file_selection_refuses_same_size_mutation_and_nonregular_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("retained");
        std::fs::write(&path, b"abc").unwrap();
        let bindings = vec![(path.clone(), sha256_file(&path).unwrap(), 3)];
        verify_bindings(&bindings).unwrap();
        std::fs::write(&path, b"xyz").unwrap();
        assert!(verify_bindings(&bindings).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(verify_bindings(&bindings).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_dir(&path).unwrap();
            let other = directory.path().join("same-bytes");
            std::fs::write(&other, b"abc").unwrap();
            std::os::unix::fs::symlink(&other, &path).unwrap();
            assert!(verify_bindings(&bindings).is_err());
        }
    }

    #[test]
    fn pinned_linux_assets_do_not_substitute_for_a_missing_runtime_release_proof() {
        let mut env = TestEnv::new();
        // The fixture pins exact local bytes but does not ship a Sigstore proof.
        env.set("MVM_SKIP_COSIGN_VERIFY", "1");
        let served = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        let target = MemberTarget::Arch(arch);
        let overlay = boot_asset_fixture::runtime_overlay_archive_bytes(
            arch,
            &boot_asset_fixture::valid_overlay_ext4_bytes(),
            b"synthetic verity",
            "a".repeat(64).as_bytes(),
            b"0.14.0",
        );
        let (image, hash, size) = boot_asset_fixture::initramfs_fixture(b"synthetic cpio");
        let initramfs = boot_asset_fixture::initramfs_archive_bytes(
            &image,
            hash.as_bytes(),
            size.as_bytes(),
            b"0.14.0",
        );
        let fixture = ImageSetFixture::complete()
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_OVERLAY_ROLE,
                target,
                "overlay.tar.gz",
                overlay,
            )
            .publish(
                mvm_core::plan::bundle::BOOT_ASSET_INITRAMFS_ROLE,
                target,
                "initramfs.tar.gz",
                initramfs,
            )
            .publish(
                ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant),
                target,
                "vmlinux",
                b"synthetic kernel".to_vec(),
            );
        let set = PublishedImageSet::acquire_from(fixture.serve_from(served.path())).unwrap();
        let proof = RuntimeReleaseProof {
            archive: served.path().join("missing-runtime.tar.gz"),
            checksum: served.path().join("missing-runtime.sha256"),
            signature_bundle: served.path().join("missing-runtime.bundle"),
            archive_sha256: "a".repeat(64),
            version: env!("CARGO_PKG_VERSION").into(),
            arch,
        };
        let error = PreparedPortableBootAssets::from_set(set, arch, &proof)
            .err()
            .expect("missing release proof must fail");
        assert!(format!("{error:#}").contains("missing-runtime"));
    }
}
