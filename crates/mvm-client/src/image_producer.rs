//! Build-system adapters produce the same template revision for pack health and export.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_build::oci_runtime_inject::ImageRuntimeConfig;
use mvm_build::pipeline::{BuildMode, frozen::FrozenInputs};
use mvm_build::yocto::YoctoInput;
use mvm_core::manifest::PersistedManifest;
use mvm_core::template::TemplateRevision;
use mvm_runtime::vm::template::lifecycle::{
    ImageBuildSources, build_frozen_manifest, template_build_from_image,
};

use crate::portable_boot_assets::PreparedPortableBootAssets;

/// Build or import one image into a revisioned slot for the common health/signing path.
pub trait WorkloadImageProducer {
    /// Return the revision selected by the slot after the producer succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when the source cannot be built or the resulting slot is incomplete.
    fn build_slot(&self, slot: &PersistedManifest) -> Result<TemplateRevision>;
}

/// Frozen Nix flake producer; evaluation and compilation stay inside the builder VM.
pub struct FrozenNixImage<'a> {
    inputs: &'a FrozenInputs,
    mode: BuildMode,
}

impl<'a> FrozenNixImage<'a> {
    /// Borrow a source snapshot already checked against its pack lock.
    pub fn new(inputs: &'a FrozenInputs, mode: BuildMode) -> Self {
        Self { inputs, mode }
    }
}

impl WorkloadImageProducer for FrozenNixImage<'_> {
    fn build_slot(&self, slot: &PersistedManifest) -> Result<TemplateRevision> {
        build_frozen_manifest(slot, self.inputs, self.mode)
    }
}

/// A pinned Yocto rootfs imported with exactly the runtime and kernel the pack will ship.
pub struct YoctoImage<'a> {
    input: &'a YoctoInput,
    output: &'a Path,
    entrypoint: &'a ImageRuntimeConfig,
    boot: &'a PreparedPortableBootAssets,
}

impl<'a> YoctoImage<'a> {
    /// Borrow the retained input archive, private output path and verified boot closure.
    pub fn new(
        input: &'a YoctoInput,
        output: &'a Path,
        entrypoint: &'a ImageRuntimeConfig,
        boot: &'a PreparedPortableBootAssets,
    ) -> Self {
        Self {
            input,
            output,
            entrypoint,
            boot,
        }
    }
}

impl WorkloadImageProducer for YoctoImage<'_> {
    fn build_slot(&self, slot: &PersistedManifest) -> Result<TemplateRevision> {
        self.boot.verify_integrity()?;
        self.input
            .materialize(
                &mvm_core::config::oci_cache_dir(),
                self.output,
                self.entrypoint,
                self.boot.guest_binaries(),
            )
            .context("materialize the retained Yocto image")?;
        self.boot.verify_integrity()?;
        template_build_from_image(
            slot,
            &ImageBuildSources {
                rootfs: self.output.to_path_buf(),
                kernel: self.boot.kernel_path().to_path_buf(),
                image_ref: format!(
                    "yocto:{}@sha256:{}",
                    self.input.machine(),
                    self.input.archive_digest()
                ),
            },
            BuildMode::Prod,
        )
        .context("install the Yocto image in a private health-check slot")
    }
}
