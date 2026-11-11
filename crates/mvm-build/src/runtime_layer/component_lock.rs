//! Filesystem-only identity and measured materialization of a verified component graph.

use std::path::Path;

use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageTrustTier, WorkloadImageProfile};
use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::PackPin;
use mvm_core::registry_pack::application_component::VerifiedApplicationComponentInputs;
use mvm_core::registry_pack::component_layer::VerifiedComponentLayerInputs;
use serde::{Deserialize, Serialize};

use super::{
    ComponentGraphBase, ComposedComponentRootfs, RuntimeLayerStageError,
    reverify_local_component_base, valid_producer_revision,
};

/// Exact archive bytes declared by one signed graph component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentArchivePin {
    pub sha256: Sha256Hex,
    pub size: u64,
}

/// Filesystem-only v3 graph evidence, not a policy, command or signing grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentFilesystemLockSchema {
    #[serde(rename = "mvm.composed-filesystem-lock/v1")]
    V1,
}

/// Exact inputs and measured output of a private composed filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedComponentFilesystemLock {
    schema: ComponentFilesystemLockSchema,
    base_manifest_sha256: Sha256Hex,
    base_descriptor_sha256: Sha256Hex,
    pub(super) base_tier: ImageTrustTier,
    arch: GuestArch,
    profile: WorkloadImageProfile,
    pub(super) components: Vec<(PackPin, ComponentArchivePin)>,
    pub(super) producer_revision: String,
    producer_version: String,
    ext4_sha256: Sha256Hex,
    pub(super) verity_sha256: Sha256Hex,
    verity_root_hash: Sha256Hex,
}

impl ResolvedComponentFilesystemLock {
    /// Hash the exact filesystem inputs, excluding output bytes and launch decisions.
    ///
    /// # Errors
    ///
    /// Returns a serialization error if a lock field cannot be encoded.
    pub fn filesystem_identity(&self) -> anyhow::Result<Sha256Hex> {
        let archives: Vec<&ComponentArchivePin> =
            self.components.iter().map(|(_, archive)| archive).collect();
        let bytes = serde_json::to_vec(&(
            "mvm.composed-filesystem/v1",
            &self.base_manifest_sha256,
            &self.base_descriptor_sha256,
            self.base_tier,
            self.arch,
            self.profile,
            archives,
            &self.producer_revision,
            &self.producer_version,
        ))?;
        Ok(Sha256Hex::from_bytes(&bytes))
    }

    /// The base trust tier cannot be promoted by a composed filesystem lock.
    pub fn tier(&self) -> ImageTrustTier {
        self.base_tier
    }

    /// Digest of the exact written ext4 image.
    pub fn ext4_sha256(&self) -> &Sha256Hex {
        &self.ext4_sha256
    }

    /// Digest of the exact written dm-verity hash-tree sidecar.
    pub fn verity_sha256(&self) -> &Sha256Hex {
        &self.verity_sha256
    }

    /// Measured dm-verity root hash, not a health or boot witness.
    pub fn verity_root_hash(&self) -> &Sha256Hex {
        &self.verity_root_hash
    }

    /// Compare freshly resolved input and output pins before consuming this lock again.
    ///
    /// # Errors
    ///
    /// Refuses a different graph, assembler, base or materialized result.
    pub fn verify_current(&self, current: &Self) -> Result<(), RuntimeLayerStageError> {
        if self != current {
            return Err(RuntimeLayerStageError::StaleLock);
        }
        Ok(())
    }

    /// Rehash the materialized image and sidecars against this filesystem lock.
    ///
    /// # Errors
    ///
    /// Refuses changed ext4, verity or root-hash bytes.
    pub fn verify_materialized_bytes(
        &self,
        image: &crate::rootfs::MaterializedExt4,
    ) -> Result<(), RuntimeLayerStageError> {
        let (ext4, verity, root) = measure_materialized_component(image)?;
        if ext4 != self.ext4_sha256 || verity != self.verity_sha256 || root != self.verity_root_hash
        {
            return Err(RuntimeLayerStageError::StaleLock);
        }
        Ok(())
    }
}

/// Private image and its filesystem-only lock; neither grants launch or export.
#[derive(Debug)]
pub struct MaterializedComponentRootfs {
    pub image: crate::rootfs::MaterializedExt4,
    pub lock: ResolvedComponentFilesystemLock,
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
    pub fn ownership(&self) -> &mvm_fs::ownership::OwnerTable {
        self.tree.ownership()
    }

    /// Exact signed manifest pins in filesystem application order.
    pub fn pins(&self) -> &[PackPin] {
        &self.pins
    }

    /// Write ext4 and verity using the existing composer, binding measured bytes.
    ///
    /// The caller retains the same verified base and component inputs. Neither
    /// this filesystem-only lock nor the image selects policy or a launch command.
    /// `producer_revision` must be the caller's compiled `MVM_SOURCE_COMMIT`,
    /// never an authored value. A production export must separately reverify
    /// the signed base descriptor with its held image-set verification request;
    /// `PublishedImageSet` alone cannot reconstruct that request here.
    ///
    /// # Errors
    ///
    /// Refuses changed producer, base, component or output bytes.
    pub fn materialize_candidate(
        &self,
        output: &Path,
        producer_revision: &str,
        base: ComponentGraphBase<'_>,
        applications: &[VerifiedApplicationComponentInputs],
        components: &[VerifiedComponentLayerInputs],
    ) -> Result<MaterializedComponentRootfs, RuntimeLayerStageError> {
        if !valid_producer_revision(producer_revision) {
            return Err(RuntimeLayerStageError::ComponentGraph);
        }
        self.reverify_base(&base)?;
        self.reverify_components(applications, components)?;
        let image = self.tree.materialize_candidate(output)?;
        self.reverify_base(&base)?;
        self.reverify_components(applications, components)?;
        let (ext4_sha256, verity_sha256, verity_root_hash) =
            measure_materialized_component(&image)?;
        let lock = ResolvedComponentFilesystemLock {
            schema: ComponentFilesystemLockSchema::V1,
            base_manifest_sha256: self.tree.base_manifest_sha256.clone(),
            base_descriptor_sha256: self.base_descriptor_sha256.clone(),
            base_tier: self.tier,
            arch: self.arch,
            profile: self.tree.profile,
            components: self
                .pins
                .iter()
                .cloned()
                .zip(self.archives.iter().cloned())
                .collect(),
            producer_revision: producer_revision.to_owned(),
            producer_version: env!("CARGO_PKG_VERSION").into(),
            ext4_sha256,
            verity_sha256,
            verity_root_hash,
        };
        Ok(MaterializedComponentRootfs { image, lock })
    }

    fn reverify_base(&self, base: &ComponentGraphBase<'_>) -> Result<(), RuntimeLayerStageError> {
        let (descriptor, tier, manifest_sha256) = match base {
            ComponentGraphBase::Production {
                images,
                compatibility,
            } => {
                images.retained_publisher_proof()?;
                (
                    compatibility.descriptor(),
                    ImageTrustTier::VerifiedRelease,
                    Sha256Hex::from_bytes(images.manifest_bytes()),
                )
            }
            ComponentGraphBase::Development {
                compatibility,
                evidence,
                manifest_bytes,
                kernel,
                tar,
            } => {
                reverify_local_component_base(
                    compatibility,
                    evidence,
                    manifest_bytes,
                    kernel,
                    tar,
                )?;
                (
                    compatibility.descriptor(),
                    ImageTrustTier::LocalDev,
                    Sha256Hex::from_bytes(manifest_bytes),
                )
            }
        };
        let descriptor_sha256 = match base {
            ComponentGraphBase::Production { compatibility, .. } => {
                Sha256Hex::from_bytes(compatibility.descriptor_bytes())
            }
            ComponentGraphBase::Development { compatibility, .. } => {
                Sha256Hex::from_bytes(compatibility.descriptor_bytes())
            }
        };
        if self.tier != tier
            || self.arch != descriptor.arch()
            || self.tree.profile != descriptor.profile()
            || self.tree.base_manifest_sha256 != manifest_sha256
            || self.base_descriptor_sha256 != descriptor_sha256
            || descriptor.image_set_manifest_sha256() != &manifest_sha256
        {
            return Err(RuntimeLayerStageError::ComponentGraph);
        }
        Ok(())
    }

    fn reverify_components(
        &self,
        applications: &[VerifiedApplicationComponentInputs],
        components: &[VerifiedComponentLayerInputs],
    ) -> Result<(), RuntimeLayerStageError> {
        if self.pins.len() != self.archives.len()
            || self.pins.len() != applications.len() + components.len()
        {
            return Err(RuntimeLayerStageError::ComponentGraph);
        }
        for (pin, archive) in self.pins.iter().zip(&self.archives) {
            if let Some(input) = applications
                .iter()
                .find(|input| &input.descriptor().manifest().reference == pin.reference())
            {
                let descriptor = input.descriptor();
                let actual = &descriptor.manifest().application_component.archive;
                if &Sha256Hex::from_bytes(descriptor.manifest_bytes()) != pin.manifest_sha256()
                    || actual.archive_sha256 != archive.sha256
                    || actual.archive_size != archive.size
                {
                    return Err(RuntimeLayerStageError::ComponentGraph);
                }
                input.reverify()?;
            } else if let Some(input) = components
                .iter()
                .find(|input| input.descriptor().manifest().reference() == pin.reference())
            {
                let descriptor = input.descriptor();
                let actual = &descriptor.manifest().component().archive;
                if descriptor.manifest_sha256() != pin.manifest_sha256()
                    || actual.archive_sha256 != archive.sha256
                    || actual.archive_size != archive.size
                {
                    return Err(RuntimeLayerStageError::ComponentGraph);
                }
                input.reverify()?;
            } else {
                return Err(RuntimeLayerStageError::ComponentGraph);
            }
        }
        Ok(())
    }
}

fn measure_materialized_component(
    image: &crate::rootfs::MaterializedExt4,
) -> Result<(Sha256Hex, Sha256Hex, Sha256Hex), RuntimeLayerStageError> {
    let root = image
        .verity_root_hash
        .as_deref()
        .ok_or(RuntimeLayerStageError::ComponentGraph)?;
    let verity_root_hash =
        Sha256Hex::new(root).map_err(|_| RuntimeLayerStageError::ComponentGraph)?;
    let parent = image
        .path
        .parent()
        .ok_or(RuntimeLayerStageError::ComponentGraph)?;
    if std::fs::read(parent.join("rootfs.roothash"))? != format!("{root}\n").as_bytes() {
        return Err(RuntimeLayerStageError::ComponentGraph);
    }
    let ext4_sha256 = Sha256Hex::new(&mvm_core::crypto::image_verify::sha256_file(&image.path)?)
        .map_err(|_| RuntimeLayerStageError::ComponentGraph)?;
    let verity_sha256 = Sha256Hex::new(&mvm_core::crypto::image_verify::sha256_file(
        &parent.join("rootfs.verity"),
    )?)
    .map_err(|_| RuntimeLayerStageError::ComponentGraph)?;
    Ok((ext4_sha256, verity_sha256, verity_root_hash))
}
