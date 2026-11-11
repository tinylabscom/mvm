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
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

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
}
