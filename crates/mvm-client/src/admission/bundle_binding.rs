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
//!
//! A forked or restored child boots its parent's captured disk rather than the
//! bundle's own root filesystem, but it continues a workload that started from
//! the bundle. It inherits the parent's pin: the same archive is re-verified,
//! it must still be the bundle the parent's plan named, and the installed copy
//! is held to the signed manifest exactly as for a direct boot.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_core::plan::ExecutionPlan;
use mvm_core::plan::bundle::{ArtifactRole, BundleManifest, BundleRegistry};

/// The audit class a boot refused by this check is recorded under.
pub(super) const BUNDLE_VERIFY_CLASS: &str = "bundle-verify";

/// The bundle archive a boot is pinned to, and how the boot relates to it.
#[derive(Debug, Clone, Copy)]
pub struct BundlePin<'a> {
    archive: &'a Path,
    lineage: BundleLineage<'a>,
}

#[derive(Debug, Clone, Copy)]
enum BundleLineage<'a> {
    /// The boot reads the bundle's own root filesystem and kernel.
    Boots,
    /// The boot continues a parent that booted the bundle with this sha256.
    Inherited { bundle_sha256: &'a str },
}

impl<'a> BundlePin<'a> {
    /// A boot that reads its root filesystem and kernel out of the bundle at
    /// `archive`. Both must be the ones the bundle signed.
    pub fn boots(archive: &'a Path) -> Self {
        Self {
            archive,
            lineage: BundleLineage::Boots,
        }
    }

    /// The archive this pin reads.
    pub fn archive(&self) -> &'a Path {
        self.archive
    }
}

/// The bundle a parent's admitted plan names, for a child forked or restored
/// from that parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritedBundle {
    archive: PathBuf,
    bundle_sha256: String,
}

impl InheritedBundle {
    /// The bundle `parent` was admitted under, or `None` when its plan pins
    /// none.
    ///
    /// The archive path is returned whether or not anything is still there:
    /// a bundle uninstalled since the parent booted is admission's refusal to
    /// make, so the child cannot quietly boot unpinned.
    pub fn from_parent_plan(parent: &ExecutionPlan) -> Result<Option<Self>> {
        let Some(pin) = &parent.bundle else {
            return Ok(None);
        };
        if !mvm_core::manifest::is_slot_hash_dirname(&pin.bundle_sha256) {
            bail!(
                "the parent's plan pins bundle {:?}, which is not a sha256",
                pin.bundle_sha256
            );
        }
        let registry = BundleRegistry::default_path()
            .context("resolving the bundle registry for the parent's pinned bundle")?;
        Ok(Some(Self {
            archive: registry.archive_path(&pin.bundle_sha256),
            bundle_sha256: pin.bundle_sha256.clone(),
        }))
    }

    /// The bundle the VM `parent_vm` was admitted under, read from the plan
    /// its boot persisted.
    ///
    /// A parent with no persisted plan has nothing to inherit. A plan that is
    /// present but cannot be read is refused rather than read as "no bundle",
    /// because that answer would admit the child unpinned.
    pub fn of_parent_vm(parent_vm: &str) -> Result<Option<Self>> {
        let path = mvm_hostd::audit::plan_persist::plan_path(parent_vm)?;
        if !path.exists() {
            return Ok(None);
        }
        let plan = mvm_hostd::audit::plan_persist::read_plan_at(&path).with_context(|| {
            format!(
                "reading {parent_vm}'s admitted plan to learn which bundle its child inherits; \
                 refusing to admit a child whose bundle cannot be determined"
            )
        })?;
        Self::from_parent_plan(&plan)
    }

    /// The pin a child of this bundle is admitted with.
    pub fn pin(&self) -> BundlePin<'_> {
        BundlePin {
            archive: &self.archive,
            lineage: BundleLineage::Inherited {
                bundle_sha256: &self.bundle_sha256,
            },
        }
    }
}

/// What admission verified about the bundle a plan pins, kept until the boot's
/// own digests are known.
#[derive(Debug)]
pub(super) struct PinnedBundle<'a> {
    /// The pin admission was handed.
    pub pin: BundlePin<'a>,
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
        match self.pin.lineage {
            BundleLineage::Boots => {
                self.require_member(ArtifactRole::Rootfs, "root filesystem", boot.rootfs_sha256)?;
                if let Some(kernel) = boot.kernel_sha256 {
                    self.require_member(ArtifactRole::Kernel, "kernel", kernel)?;
                }
            }
            // The child's disk is the parent's captured state, not a bundle
            // member, so there is no member to compare it with. What binds it
            // is that the archive is still the one its parent was admitted
            // under.
            BundleLineage::Inherited { bundle_sha256 } => {
                if self.sha256 != bundle_sha256 {
                    bail!(
                        "the parent was admitted under bundle {bundle_sha256}, but the archive \
                         at {} is now bundle {}; the bundle changed after the parent booted",
                        self.pin.archive.display(),
                        self.sha256
                    );
                }
            }
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
        let Some(registry_root) = self.pin.archive.parent() else {
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
