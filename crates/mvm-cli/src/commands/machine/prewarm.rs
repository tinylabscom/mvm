//! Concrete source resolution for asynchronous warm-artifact jobs.
//!
//! OCI trust policy and template-slot lookup belong to the CLI source
//! boundary. The runtime worker owns durable jobs, staging, and publication.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::arch::GuestArch;
use mvm_core::config;
use mvm_core::vm_backend::WarmPrewarmSource;
use mvm_runtime::{
    WarmArtifactBuildPlan, WarmArtifactKey, WarmArtifactPlanResolver, WarmArtifactStore,
    WarmArtifactWorker, WarmGoldenVmFactory, WarmGoldenVmReadinessVerifier,
};

/// Resolve a host-path-free prewarm source into concrete boot inputs. The
/// runtime worker still re-checks regular-file status and content digests
/// before publication.
pub fn resolve_warm_artifact_plan(
    source: &WarmPrewarmSource,
    _key: &WarmArtifactKey,
) -> Result<WarmArtifactBuildPlan> {
    source.validate().map_err(anyhow::Error::msg)?;
    let arch = GuestArch::host();
    let cache_root = PathBuf::from(config::mvm_cache_dir());
    match source {
        WarmPrewarmSource::OciImage { reference } => {
            let image = super::super::image::resolve_or_pull_run_image(
                &super::super::image::oci_cache_root(),
                reference,
                false,
            )
            .with_context(|| format!("resolve prewarm OCI image {reference:?}"))?;
            let kernel_path = super::super::env::builder_vm::ensure_workload_kernel()
                .context("resolve prewarm workload kernel")?;
            Ok(WarmArtifactBuildPlan {
                rootfs_path: image.rootfs_path,
                kernel_path: PathBuf::from(kernel_path),
                arch,
                cache_root,
            })
        }
        WarmPrewarmSource::Template { template_id } => {
            let (_, kernel, _initramfs, rootfs, _) =
                mvm_runtime::vm::template::lifecycle::template_artifacts_for_slot(template_id)
                    .with_context(|| format!("resolve prewarm template {template_id:?}"))?;
            Ok(WarmArtifactBuildPlan {
                rootfs_path: PathBuf::from(rootfs),
                kernel_path: PathBuf::from(kernel),
                arch,
                cache_root,
            })
        }
    }
}

/// Construct the runtime worker with the CLI's source resolver. The caller
/// must provide a backend-specific authenticated golden-VM readiness verifier.
pub fn warm_artifact_worker(
    store: WarmArtifactStore,
    verify_readiness: WarmGoldenVmReadinessVerifier,
) -> WarmArtifactWorker {
    let resolver: WarmArtifactPlanResolver = Arc::new(resolve_warm_artifact_plan);
    WarmArtifactWorker::new(store, resolver, verify_readiness)
}

/// Construct the worker with the shared authenticated readiness verifier. The
/// factory remains backend-specific because only the selected VMM can assemble
/// and boot its disposable golden VM.
pub fn warm_artifact_worker_with_factory(
    store: WarmArtifactStore,
    factory: WarmGoldenVmFactory,
) -> WarmArtifactWorker {
    let resolver: WarmArtifactPlanResolver = Arc::new(resolve_warm_artifact_plan);
    WarmArtifactWorker::with_authenticated_readiness(store, resolver, factory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_source_is_rejected_before_source_resolution() {
        let key = WarmArtifactKey {
            backend: "hvf".into(),
            backend_version: "v1".into(),
            guest_agent_sha256: "a".repeat(64),
            kernel_sha256: "b".repeat(64),
            initramfs_sha256: "c".repeat(64),
            rootfs_sha256: "d".repeat(64),
            runtime_overlay_sha256: Some("e".repeat(64)),
        };
        let source = WarmPrewarmSource::OciImage {
            reference: " ".into(),
        };
        let error = resolve_warm_artifact_plan(&source, &key)
            .expect_err("invalid source must fail before image resolution");
        assert!(error.to_string().contains("source identifier is empty"));
    }
}
