//! Binding a boot to the bundle its plan pins.
//!
//! Verifying a pinned archive proves the archive is what the publisher signed.
//! It says nothing about the files the boot reads: an installed bundle boots
//! from the copies `BundleRegistry::install` extracted beside the archive, and
//! those are ordinary files under `~/.mvm/bundles/<sha256>/` that can change
//! after install. A plan that pins bundle B while booting a root filesystem B
//! never contained would record a provenance the boot does not have.
//!
//! So once the archive has verified, the boot is held to its signed manifest:
//! the root filesystem and kernel admission hashed must be the ones the
//! manifest lists, and when the bundle is installed, every extracted artifact
//! and the extracted manifest the boot resolver reads must still match it.

use std::path::Path;

use anyhow::{Result, bail};
use mvm_core::plan::bundle::{ArtifactRole, BundleManifest, BundleRegistry};

/// The audit class a boot refused by this check is recorded under.
pub(super) const BUNDLE_VERIFY_CLASS: &str = "bundle-verify";

/// What admission verified about the bundle a plan pins, kept until the boot's
/// own digests are known.
#[derive(Debug)]
pub(super) struct PinnedBundle<'a> {
    /// The archive admission read and verified.
    pub archive: &'a Path,
    /// The archive's sha256, as signed into the plan.
    pub sha256: String,
    /// The manifest whose signature verified against the trust store.
    pub signed: BundleManifest,
}

/// The digests admission computed for what this boot will actually read.
#[derive(Debug, Clone, Copy)]
pub(super) struct BootDigests<'a> {
    pub rootfs_sha256: &'a str,
    pub kernel_sha256: Option<&'a str>,
}

impl PinnedBundle<'_> {
    /// Refuse a boot that does not run the bundle its plan pins.
    pub(super) fn check_boot(&self, boot: BootDigests<'_>) -> Result<()> {
        self.require_member(ArtifactRole::Rootfs, "root filesystem", boot.rootfs_sha256)?;
        if let Some(kernel) = boot.kernel_sha256 {
            self.require_member(ArtifactRole::Kernel, "kernel", kernel)?;
        }
        self.check_installed_copy()
    }

    fn require_member(&self, role: ArtifactRole, what: &str, actual: &str) -> Result<()> {
        let Some(expected) = self.signed.find_by_role(&role) else {
            bail!(
                "the plan pins bundle {} but boots a {what} the bundle does not carry",
                self.sha256
            );
        };
        if expected.sha256 != actual {
            bail!(
                "the {what} this boot reads (sha256 {actual}) is not the one bundle {} signed \
                 ({}); the bundle's files changed after it was installed",
                self.sha256,
                expected.sha256
            );
        }
        Ok(())
    }

    /// Check the extraction beside the archive, when there is one.
    ///
    /// The registry keeps `<sha256>.mvmpkg` and `<sha256>/` side by side, so an
    /// archive with no extraction beside it was never installed and the boot
    /// cannot be reading one; the role check above still binds what it does
    /// read. Digests go through the same size-and-mtime cache admission already
    /// uses for the root filesystem, so a launch after the first re-reads none
    /// of the artifacts.
    fn check_installed_copy(&self) -> Result<()> {
        let Some(registry_root) = self.archive.parent() else {
            return Ok(());
        };
        let Some(installed) = BundleRegistry::new(registry_root).find(&self.sha256)? else {
            return Ok(());
        };
        if installed.manifest != self.signed {
            bail!(
                "the installed manifest of bundle {} at {} differs from the one its publisher \
                 signed; reinstall the bundle",
                self.sha256,
                installed.root.display()
            );
        }
        for artifact in &self.signed.artifacts {
            let path = installed.root.join(&artifact.path);
            let actual =
                mvm_core::crypto::image_verify::sha256_file_cached(&path).map_err(|e| {
                    anyhow::anyhow!(
                        "reading installed artifact {} of bundle {}: {e}",
                        path.display(),
                        self.sha256
                    )
                })?;
            if actual != artifact.sha256 {
                bail!(
                    "installed artifact {} of bundle {} has sha256 {actual}, but the bundle \
                     signed {}; reinstall the bundle",
                    path.display(),
                    self.sha256,
                    artifact.sha256
                );
            }
        }
        Ok(())
    }
}
