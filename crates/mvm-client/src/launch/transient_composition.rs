//! Invocation-private custody of a verified local composition.
//!
//! This directory is not the installed bundle registry. It exists only while
//! the caller retains this value, and does not enroll a publisher key.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use mvm_core::plan::bundle::{
    ArtifactRole, BundleMember, BundleOrigin, BundleRegistry, FsTrustStore, InstalledBundle,
    LocalBundleTrustStore, bundle_origin, key_id_from_pubkey, verify_bundle_file,
};

/// Exact signed bytes staged for one Dev boot, without installing a bundle.
#[derive(Debug)]
pub struct TransientComposition {
    directory: Option<tempfile::TempDir>,
    installed: InstalledBundle,
    archive: PathBuf,
    archive_sha256: String,
    host_key_id: mvm_core::plan::KeyId,
    created: Instant,
    process_id: u32,
    consumed: bool,
}

impl TransientComposition {
    /// Verify a host-signed composition and materialize it in a private directory.
    ///
    /// # Errors
    /// Refuses changed, foreign-signed, non-composed or non-regular input.
    pub fn stage(source: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(source)?;
        ensure!(
            metadata.file_type().is_file(),
            "composition source is not a regular file"
        );
        mvm_core::private_fs::require_current_owner(&metadata)?;
        let host = mvm_hostd::audit::host_keypair::load_or_init()?;
        let host_key_id = key_id_from_pubkey(&host.verifying);
        let release = mvm_core::registry_pack::application_bundle::trust_for_installed_archive(
            FsTrustStore::default_path()?,
            source,
        );
        let trust = LocalBundleTrustStore::new(release, host_key_id.clone(), host.verifying);
        let source_verified = verify_bundle_file(source, &trust)
            .context("verifying the local composition before private staging")?;
        ensure!(
            bundle_origin(&source_verified.manifest, &host_key_id, trust.release())
                == BundleOrigin::LocalBuild
                && source_verified.manifest.schema_version >= 8
                && source_verified
                    .manifest
                    .members
                    .iter()
                    .any(|member| matches!(member, BundleMember::LocalComposition(_))),
            "transient boot requires this host's signed local composition"
        );

        let directory = tempfile::tempdir().context("creating private composition staging")?;
        let registry = BundleRegistry::new(directory.path().join("bundles"));
        let installed = registry
            .install_file(source, &trust, false)
            .context("materializing verified composition privately")?;
        ensure!(
            installed.sha256 == source_verified.bundle_sha256
                && installed.manifest == source_verified.manifest,
            "composition changed during private staging"
        );
        let archive = registry.archive_path(&installed.sha256);
        let staged = Self {
            directory: Some(directory),
            archive,
            archive_sha256: installed.sha256.clone(),
            installed,
            host_key_id,
            created: Instant::now(),
            process_id: std::process::id(),
            consumed: false,
        };
        staged.reverify()?;
        Ok(staged)
    }

    /// Consume the staged source once, after rechecking the original signed bytes.
    ///
    /// # Errors
    /// Refuses expiry, replay, changed artifacts or a different process.
    pub fn consume(&mut self) -> Result<TransientBoot<'_>> {
        ensure!(!self.consumed, "transient composition already consumed");
        ensure!(
            self.process_id == std::process::id()
                && self.created.elapsed() < Duration::from_secs(120),
            "transient composition expired or changed processes"
        );
        self.reverify()?;
        self.consumed = true;
        Ok(TransientBoot {
            staged: self,
            admitted: Cell::new(false),
        })
    }

    /// Keep private evidence when an admitted VM may still need recovery.
    pub fn retain_on_error(&mut self) -> Option<PathBuf> {
        self.directory.take().map(tempfile::TempDir::keep)
    }

    fn reverify(&self) -> Result<()> {
        let directory = self
            .directory
            .as_ref()
            .context("transient composition custody was already released")?;
        ensure!(
            self.process_id == std::process::id(),
            "transient composition moved to another process"
        );
        let metadata = std::fs::symlink_metadata(directory.path())?;
        ensure!(
            metadata.file_type().is_dir(),
            "transient composition directory changed type"
        );
        mvm_core::private_fs::require_current_owner(&metadata)?;
        ensure!(
            self.installed.root.starts_with(directory.path()),
            "transient composition escaped its private directory"
        );
        let host = mvm_hostd::audit::host_keypair::load_or_init()?;
        let host_key_id = key_id_from_pubkey(&host.verifying);
        ensure!(
            host_key_id == self.host_key_id,
            "transient host signer changed"
        );
        let release = mvm_core::registry_pack::application_bundle::trust_for_installed_archive(
            FsTrustStore::default_path()?,
            &self.archive,
        );
        let trust = LocalBundleTrustStore::new(release, self.host_key_id.clone(), host.verifying);
        let verified = verify_bundle_file(&self.archive, &trust)?;
        ensure!(
            verified.bundle_sha256 == self.archive_sha256
                && verified.manifest == self.installed.manifest
                && bundle_origin(&verified.manifest, &self.host_key_id, trust.release())
                    == BundleOrigin::LocalBuild,
            "transient archive changed"
        );
        let registry = BundleRegistry::new(directory.path().join("bundles"));
        ensure!(
            registry
                .verified_manifest(&self.archive_sha256, &trust)?
                .as_ref()
                == Some(&self.installed.manifest),
            "transient materialized manifest differs from the archive"
        );
        for artifact in &verified.manifest.artifacts {
            let path = self.installed.root.join(&artifact.path);
            ensure!(
                std::fs::symlink_metadata(&path)?.file_type().is_file()
                    && std::fs::metadata(&path)?.len() == artifact.size_bytes
                    && mvm_core::crypto::image_verify::sha256_file(&path)? == artifact.sha256,
                "transient boot artifact differs from the signed archive"
            );
        }
        Ok(())
    }
}

/// A one-use, process-local Dev boot source. No installed-bundle address exists.
#[derive(Debug)]
pub struct TransientBoot<'a> {
    staged: &'a TransientComposition,
    admitted: Cell<bool>,
}

impl TransientBoot<'_> {
    /// Spend the sole admission attempt for this invocation.
    ///
    /// # Errors
    /// Refuses replay or a token used after its process-local window.
    pub(crate) fn admit_once(&self) -> Result<()> {
        ensure!(
            self.staged.process_id == std::process::id()
                && self.staged.created.elapsed() < Duration::from_secs(120),
            "transient composition admission expired"
        );
        ensure!(
            !self.admitted.replace(true),
            "transient composition was already admitted"
        );
        Ok(())
    }

    /// Recheck the held archive and materialized files before handing them to boot.
    ///
    /// # Errors
    /// Refuses a changed private archive or boot artifact.
    pub fn reverify(&self) -> Result<()> {
        self.staged.reverify()
    }

    /// The verified private archive for this admission only.
    pub fn archive(&self) -> &Path {
        &self.staged.archive
    }

    /// The signed manifest, held beside the private bytes.
    pub fn manifest(&self) -> &mvm_core::plan::bundle::BundleManifest {
        &self.staged.installed.manifest
    }

    /// The content address of the exact signed archive.
    pub fn sha256(&self) -> &str {
        &self.staged.archive_sha256
    }

    /// The invocation-private materialization root.
    pub(crate) fn registry_root(&self) -> &Path {
        self.staged
            .directory
            .as_ref()
            .expect("live transient boot retains private directory")
            .path()
    }

    /// Whether this invocation reached admitted-plan construction.
    pub fn was_admitted(&self) -> bool {
        self.admitted.get()
    }

    /// The exact materialized kernel.
    pub fn kernel(&self) -> Result<PathBuf> {
        self.staged
            .installed
            .path_for_role(&ArtifactRole::Kernel)
            .context("composition has no signed kernel")
    }

    /// The exact materialized root filesystem.
    pub fn rootfs(&self) -> Result<PathBuf> {
        self.staged
            .installed
            .path_for_role(&ArtifactRole::Rootfs)
            .context("composition has no signed rootfs")
    }

    /// The signed initramfs, when the composition embeds one.
    pub fn initrd(&self) -> Option<PathBuf> {
        self.staged.installed.path_for_role(&ArtifactRole::Initrd)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mvm_contract::plan::bundle::{
        EmbeddedCliBootAssets, LocalComposition, LocalDevelopmentBaseProof,
    };
    use mvm_core::arch::GuestArch;
    use mvm_core::util::test_env::TestEnv;

    pub(crate) fn signed_local_composition(home: &Path) -> (PathBuf, Vec<u8>) {
        use mvm_core::plan::bundle::{
            ArtifactRole, BundleArtifact, BundleManifest, VerityInfo, write_bundle,
        };
        let signer = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
        let arch = GuestArch::host().to_string();
        let kernel = b"kernel bytes";
        let tar = b"composition tar bytes";
        let tar_path = home.join("base.tar.gz");
        std::fs::write(&tar_path, tar).unwrap();
        let tar_path = std::fs::canonicalize(tar_path).unwrap();
        let mut linux = serde_json::to_value(
            mvm_build::published_image_set::fixture::ImageSetFixture::complete().into_manifest(),
        )
        .unwrap();
        linux["schema_version"] = 3.into();
        linux["set_version"] = "0.0.0-local".into();
        linux["producer"] = serde_json::json!({
            "local_checkouts": {
                "images": { "commit": "a".repeat(40), "worktree": { "state": "clean" } }
            }
        });
        linux.as_object_mut().unwrap().remove("mvm_source_commit");
        linux.as_object_mut().unwrap().remove("revocation_channel");
        linux["compatibility"]
            .as_object_mut()
            .unwrap()
            .remove("guest_agent_protocol");
        linux["compatibility"]["builder_boot_abi"] = 2.into();
        linux["compatibility"]["base_image_contract"] = 1.into();
        linux["members"] = serde_json::json!([
            {
                "role": {"workload_kernel": "default_tenant"},
                "target": {"arch": arch},
                "boot_protocol": "linux_direct",
                "artifacts": [{
                    "name": "vmlinux",
                    "format": {"kernel": if arch == "x86_64" { "elf" } else { "image" }},
                    "sha256": mvm_core::plan::bundle::sha256_hex(kernel),
                    "size": kernel.len()
                }],
                "required_capabilities": ["virtio_vsock"]
            },
            {
                "role": {"workload_rootfs": "default_tenant"},
                "target": {"arch": arch},
                "artifacts": [
                    {
                        "name": "rootfs.ext4",
                        "format": "ext4",
                        "sha256": mvm_core::plan::bundle::sha256_hex(b"rootfs"),
                        "size": 6
                    },
                    {
                        "name": "rootfs.verity",
                        "format": "verity_hash_tree",
                        "sha256": mvm_core::plan::bundle::sha256_hex(b"verity"),
                        "size": 6
                    },
                    {
                        "name": "rootfs.roothash",
                        "format": "verity_root_hash",
                        "sha256": mvm_core::plan::bundle::sha256_hex("a".repeat(64).as_bytes()),
                        "size": 64
                    },
                    {
                        "name": "rootfs.tar.gz",
                        "format": "tar_gz",
                        "sha256": mvm_core::plan::bundle::sha256_hex(tar),
                        "size": tar.len()
                    }
                ],
                "required_capabilities": ["virtio_blk", "dm_verity"]
            }
        ]);
        let linux = serde_json::to_vec(&linux).unwrap();
        let lock = serde_json::to_vec(&serde_json::json!({
            "schema": "mvm.composable-pack-lock/v1",
            "spec_sha256": mvm_core::plan::bundle::sha256_hex(b"spec"),
            "source_tree_sha256": mvm_core::plan::bundle::sha256_hex(b"source"),
            "application_archive_sha256": mvm_core::plan::bundle::sha256_hex(b"app"),
            "base_manifest_sha256": mvm_core::plan::bundle::sha256_hex(&linux),
            "runtime_pins": [],
            "target": if arch == "x86_64" { "x86_64-linux" } else { "aarch64-linux" },
            "profile": "default_tenant",
            "producer_revision": "a".repeat(40),
            "producer_version": "0.27.0"
        }))
        .unwrap();
        let boot = EmbeddedCliBootAssets {
            manifest_artifact: "boot-image-set.json".into(),
            version: "0.27.0".into(),
            arch: arch.clone(),
            archive_artifact: "guest-runtime.tar.gz".into(),
            checksum_artifact: "guest-runtime.sha256".into(),
            signature_bundle_artifact: "guest-runtime.bundle".into(),
            checksum_signature_bundle_artifact: "guest-runtime.sha256.bundle".into(),
            overlay_artifact: "runtime-overlay.ext4".into(),
            overlay_verity_artifact: "runtime-overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: "a".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 2,
            pr_test_pull_request: None,
        };
        let items: Vec<(&str, ArtifactRole, Vec<u8>)> = vec![
            ("vmlinux", ArtifactRole::Kernel, kernel.to_vec()),
            ("rootfs.ext4", ArtifactRole::Rootfs, b"rootfs".to_vec()),
            (
                "rootfs.verity",
                ArtifactRole::VerityHashSidecar,
                b"verity".to_vec(),
            ),
            (
                "rootfs.roothash",
                ArtifactRole::Other,
                "a".repeat(64).into_bytes(),
            ),
            ("boot-image-set.json", ArtifactRole::Other, linux),
            ("composition-lock.json", ArtifactRole::Other, lock),
            (
                "guest-runtime.tar.gz",
                ArtifactRole::Other,
                b"runtime".to_vec(),
            ),
            (
                "guest-runtime.sha256",
                ArtifactRole::Other,
                b"checksum".to_vec(),
            ),
            (
                "guest-runtime.bundle",
                ArtifactRole::Other,
                b"signature".to_vec(),
            ),
            (
                "guest-runtime.sha256.bundle",
                ArtifactRole::Other,
                b"signature".to_vec(),
            ),
            (
                "runtime-overlay.ext4",
                ArtifactRole::Other,
                b"overlay".to_vec(),
            ),
            (
                "runtime-overlay.verity",
                ArtifactRole::Other,
                b"verity".to_vec(),
            ),
            ("initrd", ArtifactRole::Initrd, b"initrd".to_vec()),
        ];
        let mut manifest = BundleManifest {
            schema_version: 9,
            publisher: "local".into(),
            key_id: key_id_from_pubkey(&signer.verifying),
            arch,
            kernel_version: None,
            profile: Some("dev".into()),
            workload_label: None,
            created_at: "2026-11-11T00:00:00Z".into(),
            labels: Default::default(),
            artifacts: items
                .iter()
                .map(|(name, role, bytes)| BundleArtifact {
                    name: (*name).into(),
                    role: role.clone(),
                    path: format!("artifacts/{name}"),
                    sha256: mvm_core::plan::bundle::sha256_hex(bytes),
                    size_bytes: bytes.len() as u64,
                })
                .collect(),
            members: vec![
                BundleMember::EmbeddedCliBootAssets(boot),
                BundleMember::LocalDevelopmentBaseProof(LocalDevelopmentBaseProof {
                    manifest_artifact: "boot-image-set.json".into(),
                    composition_tar_sha256: mvm_core::plan::bundle::sha256_hex(tar),
                    composition_tar_size: tar.len() as u64,
                    composition_tar_path: tar_path.to_str().unwrap().into(),
                }),
                BundleMember::LocalComposition(LocalComposition {
                    lock_artifact: "composition-lock.json".into(),
                    layers: Vec::new(),
                }),
            ],
            verity: Some(VerityInfo {
                roothash: "a".repeat(64),
                sidecar_artifact: "rootfs.verity".into(),
            }),
            resources: None,
        };
        mvm_core::plan::bundle::mark_local_build(&mut manifest);
        let bytes = write_bundle(
            &manifest,
            &signer.signing,
            items
                .into_iter()
                .map(|(name, _, bytes)| (format!("artifacts/{name}"), bytes))
                .collect(),
        )
        .unwrap();
        let path = home.join("composition.mvmpkg");
        std::fs::write(&path, &bytes).unwrap();
        (path, bytes)
    }

    #[test]
    fn unverified_source_never_creates_an_installed_bundle_entry() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let source = home.path().join("composed.mvmpkg");
        std::fs::write(&source, b"unsigned source").unwrap();

        assert!(TransientComposition::stage(&source).is_err());
        assert!(!BundleRegistry::default_path().unwrap().root().exists());
    }

    #[test]
    fn admitted_transient_source_cannot_be_replayed_or_used_after_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = mvm_core::plan::bundle::BundleManifest {
            schema_version: 8,
            publisher: "test".into(),
            key_id: mvm_core::plan::KeyId("0".repeat(32)),
            arch: mvm_core::arch::GuestArch::host().to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            labels: Default::default(),
            artifacts: Vec::new(),
            members: Vec::new(),
            verity: None,
            resources: None,
        };
        let staged = TransientComposition {
            installed: InstalledBundle {
                sha256: "0".repeat(64),
                root: directory.path().join("bundles"),
                manifest,
            },
            archive: directory.path().join("unused"),
            archive_sha256: "0".repeat(64),
            host_key_id: mvm_core::plan::KeyId("0".repeat(32)),
            created: Instant::now(),
            process_id: std::process::id(),
            consumed: true,
            directory: Some(directory),
        };
        let boot = TransientBoot {
            staged: &staged,
            admitted: Cell::new(false),
        };
        boot.admit_once().unwrap();
        assert!(boot.admit_once().is_err());

        let expired = TransientComposition {
            created: Instant::now() - Duration::from_secs(121),
            ..staged
        };
        let boot = TransientBoot {
            staged: &expired,
            admitted: Cell::new(false),
        };
        assert!(boot.admit_once().is_err());
    }

    #[test]
    fn signed_composition_stages_privately_and_rechecks_selected_bytes() {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        let (archive, _) = signed_local_composition(home.path());
        let mut staged = TransientComposition::stage(&archive).unwrap();
        assert!(!BundleRegistry::default_path().unwrap().root().exists());
        {
            let source = staged.consume().unwrap();
            source.reverify().unwrap();
            assert_eq!(std::fs::read(source.rootfs().unwrap()).unwrap(), b"rootfs");
            assert!(
                crate::launch::manifest_ref::resolve_manifest_arg(source.sha256()).is_err(),
                "private composition has no reusable installed-bundle address"
            );
        }
        assert!(staged.consume().is_err());
    }
}
