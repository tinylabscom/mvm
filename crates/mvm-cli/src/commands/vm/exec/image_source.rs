//! The image a launch boots from: the OCI image named by `--image`, or the
//! verified runtime pack or bundled default microVM a bare launch falls back to.

use anyhow::Result;

use super::super::super::env::builder_vm::{
    assert_workload_kernel_supports_verity, ensure_default_microvm_image, prepare_workload_kernel,
};
use super::OciProvenanceSink;
use crate::ui;

/// Resolve the [`crate::exec::ImageSource`] a launch boots from: the OCI image
/// named by `--image`, or — when none was named — the same verified runtime pack
/// or bundled default microVM a bare `machine run` falls back to.
///
/// Shared by the run path and by `pool warm`, because a warm parent must boot
/// the same rootfs a claim will be matched against: the pool keys on that
/// rootfs's digest, so resolving the image a second way is how the pool fills
/// with parents nothing claims. `provenance` is `None` for the warm path — a
/// factory parent is admitted under no workload plan, so there is no plan for
/// the claim-14 provenance entry to bind to.
pub(in crate::commands) fn resolve_launch_image_source(
    image_ref: Option<&str>,
    prod: bool,
    provenance: Option<&OciProvenanceSink>,
) -> Result<crate::exec::ImageSource> {
    let Some(reference) = image_ref else {
        return resolve_default_image_source(prod);
    };
    let oci_cache_root = super::super::super::image::oci_cache_root();
    // A prod run refuses a mutable OCI tag before ANY work — the
    // digest-pin policy refusal must be what the user sees, not an
    // incidental missing-kernel error from the local resolution
    // below. The pull path re-checks it, so this only reorders the
    // refusal ahead of the workload-kernel resolution.
    super::super::super::image::ensure_prod_digest_pin(reference, prod)?;
    // Resolve the workload kernel BEFORE the pull. An `--image` run
    // boots the materialized OCI rootfs (with its injected agent), so
    // it needs only a workload kernel — a cached workload/default-image
    // kernel, a local build (source checkout), or the published
    // download — rather than building/downloading a whole default image
    // whose rootfs we'd discard. Resolving it first makes a missing or
    // cold-cache kernel fail fast with an actionable error instead of
    // surfacing only after a full pull + rootfs materialization. The
    // rootfs boots verity-sealed, so the kernel must carry dm-verity;
    // the builder kernel (which drops it) is never a stand-in.
    let kernel_path = prepare_workload_kernel()?;
    // Enforce that invariant host-side: a kernel with no dm-verity
    // support would panic the guest in early init opening
    // /dev/mapper/control, with no host signal. Fail fast instead.
    assert_workload_kernel_supports_verity(&kernel_path)?;
    prepare_launch_pieces_for_image()?;
    prepare_oci_runtime_for_image(&oci_cache_root)?;
    let cached = super::super::super::image::acquire_run_image(&oci_cache_root, reference, prod)?;
    ui::info(&format!(
        "Using OCI image {} ({})",
        cached.reference, cached.resolved_digest
    ));
    // Hand the provenance to the real admission rather than
    // minting a plan here to hang it on. This used to synthesize a
    // throwaway `ExecutionPlan` and emit `plan.admitted` for it,
    // so one launch wrote two `plan.admitted` entries with
    // different plan ids — and the first authorized nothing, since
    // no VM ever booted under it. A reader of the chain could not
    // tell which of the two was the admission that mattered.
    if let Some(sink) = provenance {
        *sink.borrow_mut() = Some(cached.provenance.audit_labels());
    }
    if cached.pulled {
        let auth_source = cached.auth_source.as_deref().unwrap_or("unknown");
        mvm_core::audit_emit!(
            ImageFetch,
            "source=run_image reference={} digest={} prod={} layers={} trust_policy={} verification_status={} auth_source={}",
            cached.reference,
            cached.resolved_digest,
            prod,
            cached.provenance.layer_digests.len(),
            cached.provenance.trust_policy,
            cached.provenance.verification_status,
            auth_source
        );
    }
    Ok(crate::exec::ImageSource::Prebuilt {
        kernel_path,
        rootfs_path: cached.rootfs_path.display().to_string(),
        initrd_path: None,
        label: format!("oci:{}", cached.resolved_digest),
        unpacked_oci_root: cached
            .unpacked_root
            .as_ref()
            .map(|tree| tree.display().to_string()),
    })
}

fn prepare_launch_pieces_for_image() -> Result<()> {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host().to_string();
    let overlay =
        mvm_fs::overlay::RuntimeOverlayResolver::new(cache_root.clone(), version.to_string());
    let initramfs = mvm_fs::initramfs::InitramfsResolver::new(
        mvm_build::runtime_pieces::initramfs_cache_root(&cache_root),
        version,
    );
    let overlay_dir = overlay.layout(&arch).artifact_dir;
    let initramfs_dir = mvm_build::runtime_pieces::initramfs_cache_root(&cache_root)
        .join(version)
        .join(&arch);
    // A present but invalid cache entry is evidence of tampering or a failed
    // installation, not permission to replace it with another artifact.
    let overlay_ready = if overlay_dir.exists() {
        overlay.resolve(&arch)?;
        true
    } else {
        false
    };
    let initramfs_ready = if initramfs_dir.exists() {
        initramfs.resolve(&arch)?;
        true
    } else {
        false
    };
    if overlay_ready && initramfs_ready {
        return Ok(());
    }
    ui::info("Preparing runtime overlay and initramfs for first launch...");
    match oci_runtime_source(
        mvm_build::artifact_acquisition::compiled_channel(),
        mvm_client::launch::runtime_overlay::runtime_overlay_acquire_mode(),
    ) {
        OciRuntimeSource::Checkout => {
            super::super::super::env::bootstrap::prepare_source_launch_pieces()
        }
        OciRuntimeSource::Release => {
            crate::release_guest_runtime::prepare_launch_pieces_for_running_binary(&cache_root)
        }
    }
}

fn prepare_oci_runtime_for_image(oci_cache_root: &std::path::Path) -> Result<()> {
    use mvm_client::launch::runtime_overlay::{
        require_prepared_oci_guest_runtime, runtime_overlay_acquire_mode,
    };

    if require_prepared_oci_guest_runtime(oci_cache_root).is_ok() {
        return Ok(());
    }
    ui::info("Preparing OCI guest runtime for first image run (cached for future runs)...");
    match oci_runtime_source(
        mvm_build::artifact_acquisition::compiled_channel(),
        runtime_overlay_acquire_mode(),
    ) {
        OciRuntimeSource::Checkout => {
            mvm_client::launch::runtime_overlay::prepare_oci_guest_runtime(oci_cache_root)
        }
        OciRuntimeSource::Release => {
            crate::release_guest_runtime::prepare_oci_for_running_binary(oci_cache_root)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OciRuntimeSource {
    Checkout,
    Release,
}

fn oci_runtime_source(
    channel: mvm_build::artifact_acquisition::DistributionChannel,
    mode: mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode,
) -> OciRuntimeSource {
    use mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode;
    match (channel, mode) {
        (_, RuntimeOverlayAcquireMode::BuildFromSourceCheckout)
        | (
            mvm_build::artifact_acquisition::DistributionChannel::Source,
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
        ) => OciRuntimeSource::Checkout,
        (
            mvm_build::artifact_acquisition::DistributionChannel::Release,
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
        ) => OciRuntimeSource::Release,
    }
}

/// The image a launch boots when the caller named none: a verified runtime pack
/// if one is cached for this host, else the bundled default microVM built in the
/// builder VM.
fn resolve_default_image_source(prod: bool) -> Result<crate::exec::ImageSource> {
    if let Some(src) = super::super::runtime_pack::try_runtime_pack_image_source(prod) {
        let label = match &src {
            crate::exec::ImageSource::Prebuilt { label, .. } => label.clone(),
            crate::exec::ImageSource::Template(name) => name.clone(),
            crate::exec::ImageSource::PinnedTemplate {
                slot_hash,
                revision_hash,
            } => format!("{slot_hash}@{revision_hash}"),
            crate::exec::ImageSource::WasmModule { label, .. } => label.clone(),
            crate::exec::ImageSource::RegistryPack { pin } => {
                format!("pack:{}", pin.reference())
            }
        };
        ui::info(&format!(
            "Instant boot from verified runtime pack ({label}); skipping the build."
        ));
        return Ok(src);
    }
    let reason = super::super::runtime_pack::runtime_pack_diagnosis()
        .ok()
        .and_then(|d| super::super::runtime_pack::not_instant_reason(&d))
        .unwrap_or_else(|| "no verified runtime pack is cached for this host".to_string());
    ui::info(&format!(
        "{reason}; building the bundled default microVM in the builder VM."
    ));
    let (kernel_path, rootfs_path) =
        ensure_default_microvm_image(mvm_build::pipeline::BuildMode::Dev)?;
    Ok(crate::exec::ImageSource::Prebuilt {
        kernel_path,
        rootfs_path,
        initrd_path: None,
        label: "default-microvm".to_string(),
        unpacked_oci_root: None,
    })
}

#[cfg(test)]
mod oci_runtime_tests {
    use super::*;
    use mvm_build::artifact_acquisition::DistributionChannel;
    use mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode;

    #[test]
    fn image_run_prepares_from_the_running_binarys_own_source() {
        assert_eq!(
            oci_runtime_source(
                DistributionChannel::Release,
                RuntimeOverlayAcquireMode::DownloadPublishedArtifact
            ),
            OciRuntimeSource::Release
        );
        assert_eq!(
            oci_runtime_source(
                DistributionChannel::Source,
                RuntimeOverlayAcquireMode::DownloadPublishedArtifact
            ),
            OciRuntimeSource::Checkout
        );
        assert_eq!(
            oci_runtime_source(
                DistributionChannel::Release,
                RuntimeOverlayAcquireMode::BuildFromSourceCheckout
            ),
            OciRuntimeSource::Checkout
        );
    }
}
