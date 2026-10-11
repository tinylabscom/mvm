//! Materialize OCI content once, then sign a portable package on the caller.
//!
//! Acquisition uses the ordinary OCI fetch/unpack/materialization pipeline.
//! Runtime assets come from the existing authenticated image-set pin. Neither
//! the OCI materializer nor the builder receives the caller's signing key.

mod assets;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_build::builder_vm::GuestSidecar;
use mvm_core::arch::GuestArch;
use mvm_core::crypto::image_verify::sha256_file;
use mvm_core::plan::types::{BuildProvenance, InputKind};
use mvm_core::security::AgentProfile;
use mvm_fs::oci::ImageReference;

use crate::bundle::{
    BundleExportInputs, BundleSigner, DebugOutput, PostureInputs, export_bundle_with_signer,
};
use crate::local::oci::{OciMaterialization, OciMaterializeRequest, materialize_oci_image};
use assets::{BootAssets, utf8};

/// OCI input and host-side package destination.
#[derive(Debug, Clone)]
pub struct OciBundleRequest {
    image_ref: String,
    arch: GuestArch,
    production: bool,
    bundle_out: PathBuf,
    label: Option<String>,
    debug_out: Option<DebugOutput>,
}

impl OciBundleRequest {
    /// Defaults to this host's architecture and a development workload.
    pub fn new(image_ref: impl Into<String>, bundle_out: impl Into<PathBuf>) -> Self {
        Self {
            image_ref: image_ref.into(),
            arch: GuestArch::host(),
            production: false,
            bundle_out: bundle_out.into(),
            label: None,
            debug_out: None,
        }
    }

    pub fn arch(mut self, arch: GuestArch) -> Self {
        self.arch = arch;
        self
    }

    /// Require an immutable input and a genuinely verity-sealed workload.
    pub fn production(mut self, production: bool) -> Self {
        self.production = production;
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn debug_out(mut self, output: DebugOutput) -> Self {
        self.debug_out = Some(output);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.arch != GuestArch::host() {
            bail!(
                "OCI packaging supports this host architecture ({}), requested {}",
                GuestArch::host(),
                self.arch
            );
        }
        let reference: ImageReference = self.image_ref.parse()?;
        if self.production && reference.digest.is_none() {
            bail!("production OCI packaging requires a digest-qualified reference");
        }
        Ok(())
    }
}

/// Owns the verified input and boot assets until signing finishes.
///
/// It cannot be constructed from arbitrary rootfs paths or caller-written
/// provenance. Dropping it removes its private intermediate artifacts.
pub struct MaterializedOciBundle {
    request: OciBundleRequest,
    materialization: OciMaterialization,
    assets: BootAssets,
}

impl MaterializedOciBundle {
    pub fn resolved_digest(&self) -> &str {
        self.materialization.resolved_manifest_digest()
    }

    pub fn arch(&self) -> GuestArch {
        self.materialization.arch()
    }

    pub fn rootfs_sha256(&self) -> &str {
        self.materialization.rootfs_sha256()
    }

    pub fn sidecar_sha256(&self) -> &str {
        self.materialization.sidecar_sha256()
    }
}

/// Inspectable identity of the signed, durable output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciBundleResult {
    pub bundle_path: PathBuf,
    pub resolved_digest: String,
    pub bundle_sha256: String,
    pub signer_key_id: String,
    pub arch: GuestArch,
}

/// Acquire the pinned runtime and materialize OCI without access to a signer.
pub async fn materialize_oci_bundle(request: &OciBundleRequest) -> Result<MaterializedOciBundle> {
    request.validate()?;
    let arch = request.arch;
    let assets = tokio::task::spawn_blocking(move || BootAssets::acquire(arch))
        .await
        .context("acquiring OCI package boot assets")??;
    assets.verify_integrity()?;
    let materialization = materialize_oci_image(
        OciMaterializeRequest::new(&request.image_ref, arch, &assets.binaries)
            .sealed(request.production),
    )
    .await
    .with_context(|| format!("materializing OCI image {}", request.image_ref))?;
    assets.verify_integrity()?;
    Ok(MaterializedOciBundle {
        request: request.clone(),
        materialization,
        assets,
    })
}

/// Materialize once, validate the boot contract, and sign on the trusted caller.
pub async fn materialize_and_export_oci_bundle(
    request: &OciBundleRequest,
    signer: &dyn BundleSigner,
) -> Result<OciBundleResult> {
    let materialized = materialize_oci_bundle(request).await?;
    export_materialized_oci_bundle(&materialized, signer)
}

/// Export a retained materialization without pulling or unpacking it again.
pub fn export_materialized_oci_bundle(
    materialized: &MaterializedOciBundle,
    signer: &dyn BundleSigner,
) -> Result<OciBundleResult> {
    let MaterializedOciBundle {
        request,
        materialization,
        assets,
    } = materialized;
    request.validate()?;
    materialization.verify_integrity()?;
    assets.verify_integrity()?;
    let rootfs = materialization.rootfs_path();
    let directory = rootfs.parent().context("OCI rootfs has no parent")?;
    let sidecar = GuestSidecar::read_from_dir(directory)?
        .context("OCI rootfs has no mvm-meta.json sidecar")?;
    validate_sidecar(&sidecar, request.production)?;
    if materialization.arch() != request.arch || materialization.sealed() != request.production {
        bail!("OCI materialization does not match the package architecture or posture");
    }
    let verity = read_verity(directory, request.production)?;
    let arch = request.arch.to_string();
    let set = assets.image_set.member_cache();
    let mut inputs = BundleExportInputs::new(
        utf8(&assets.kernel)?,
        utf8(rootfs)?,
        &arch,
        &request.bundle_out,
    )
    .initrd(utf8(&assets.initrd)?)
    .profile(if request.production { "prod" } else { "dev" })
    .posture(PostureInputs::new(if request.production {
        AgentProfile::SealedProd
    } else {
        AgentProfile::Dev
    }))
    .provenance(BuildProvenance {
        input_kind: InputKind::Oci,
        input_ref: materialization.canonical_reference().to_owned(),
        lock_digest: Some(materialization.resolved_manifest_digest().to_owned()),
        builder_id: None,
        artifacts: Default::default(),
    });
    inputs.boot_assets = Some(mvm_bundler::BootAssetsInputs {
        manifest_bytes: assets.image_set.manifest_bytes(),
        manifest_sha256: set.root(),
        runtime_overlay: &assets.runtime_overlay,
        initramfs: &assets.initramfs_archive,
    });
    if let Some((bytes, roothash)) = &verity {
        inputs = inputs.verity(bytes, roothash);
    }
    if let Some(label) = &request.label {
        inputs = inputs.label(label);
    }
    if let Some(debug) = &request.debug_out {
        inputs = inputs.debug_out(debug.clone());
    }
    let exported = export_bundle_with_signer(&inputs, signer)?;
    materialization.verify_integrity()?;
    assets.verify_integrity()?;
    Ok(OciBundleResult {
        bundle_sha256: sha256_file(&exported.path)?,
        bundle_path: exported.path,
        resolved_digest: materialized.resolved_digest().to_owned(),
        signer_key_id: exported.key_id.0,
        arch: request.arch,
    })
}

fn validate_sidecar(sidecar: &GuestSidecar, production: bool) -> Result<()> {
    if !sidecar.is_oci_materialized()
        || !sidecar.overlay_aware
        || !sidecar.runtime_lean
        || sidecar.entrypoint_argv.first().is_none_or(String::is_empty)
        || sidecar.sealed != production
    {
        bail!("OCI sidecar has an incomplete or incompatible boot contract");
    }
    Ok(())
}

fn read_verity(directory: &Path, production: bool) -> Result<Option<(Vec<u8>, String)>> {
    let tree = directory.join("rootfs.verity");
    let hash = directory.join("rootfs.roothash");
    match (tree.try_exists()?, hash.try_exists()?) {
        (false, false) if !production => Ok(None),
        (true, true) => {
            let bytes = std::fs::read(tree)?;
            let hash = std::fs::read_to_string(hash)?.trim().to_owned();
            if bytes.is_empty()
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                bail!("OCI materialization has invalid verity metadata");
            }
            Ok(Some((bytes, hash)))
        }
        _ => bail!("OCI materialization requires a complete verity tree and root hash"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_requires_an_immutable_reference_before_acquisition() {
        assert!(
            OciBundleRequest::new("alpine:3.20", "a.mvmpkg")
                .validate()
                .is_ok()
        );
        assert!(
            OciBundleRequest::new("alpine:3.20", "a.mvmpkg")
                .production(true)
                .validate()
                .is_err()
        );
        assert!(
            OciBundleRequest::new(format!("alpine@sha256:{}", "ab".repeat(32)), "a.mvmpkg")
                .production(true)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn foreign_architecture_is_refused_before_acquisition() {
        let foreign = match GuestArch::host() {
            GuestArch::Aarch64 => GuestArch::X86_64,
            GuestArch::X86_64 => GuestArch::Aarch64,
        };
        assert!(
            OciBundleRequest::new("alpine", "a.mvmpkg")
                .arch(foreign)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn partial_or_missing_production_verity_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_verity(dir.path(), false).unwrap().is_none());
        assert!(read_verity(dir.path(), true).is_err());
        std::fs::write(dir.path().join("rootfs.verity"), b"tree").unwrap();
        assert!(read_verity(dir.path(), false).is_err());
        std::fs::write(dir.path().join("rootfs.roothash"), "ab".repeat(32)).unwrap();
        assert!(read_verity(dir.path(), true).unwrap().is_some());
        std::fs::write(dir.path().join("rootfs.roothash"), "invalid").unwrap();
        assert!(read_verity(dir.path(), true).is_err());
    }

    #[test]
    fn sidecar_requires_oci_runtime_entrypoint_and_matching_posture() {
        let mut sidecar = GuestSidecar::for_oci_run("alpine", false, true)
            .with_entrypoint_argv(vec!["/bin/true".into()]);
        validate_sidecar(&sidecar, false).unwrap();
        assert!(validate_sidecar(&sidecar, true).is_err());
        sidecar.entrypoint_argv.clear();
        assert!(validate_sidecar(&sidecar, false).is_err());
        sidecar.entrypoint_argv.push("/bin/true".into());
        sidecar.runtime_lean = false;
        assert!(validate_sidecar(&sidecar, false).is_err());
    }
}
