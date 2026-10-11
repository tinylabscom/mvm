//! Explicit OCI image preparation and verified cache-only launch resolution.
//!
//! These are privileged local administration operations, not host ABI methods.
//! Preparation is the only acquisition boundary. Resolution rechecks the
//! current production policy and host-authenticated verification receipt,
//! and refuses stale or incomplete artifacts rather than repairing them.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};

mod base_image;
mod cache;
mod ingest;
mod materialize;
mod oci_types;
mod pull_core;
mod signature_legacy;
mod signature_registry;
mod source;
mod trust;
mod trust_policy;

pub use cache::{inspect_image, list_rows, remove_image};
pub use oci_types::{
    CachedOciImage, CachedOciLayer, ImageListRow, InspectOutput, OciProvenance, RemoveOutcome,
    ResolvedOciRunImage,
};
pub use pull_core::{
    ensure_prod_digest_pin, ensure_prod_registry_allowed, require_prod_digest_pin,
};
pub use source::ImageSource;
pub use trust::{OciRegistryAuthDecision, registry_auth_for, registry_auth_from_lookup};

#[derive(Debug, Clone)]
pub struct PrepareImageRequest {
    pub cache_root: PathBuf,
    pub reference: String,
    pub prod: bool,
}

#[derive(Debug, Clone)]
pub struct ResolveImageRequest {
    pub cache_root: PathBuf,
    pub reference: String,
    pub prod: bool,
}

#[derive(Debug, Clone)]
pub struct PreparationReport {
    pub reference: String,
    pub resolved_digest: String,
    pub rootfs_path: PathBuf,
    pub provenance: OciProvenance,
    pub auth_source: String,
    pub local: bool,
}

/// Observable transfer counters, independent of any terminal or renderer.
/// Zero total means the operation is outside the layer-transfer phase.
#[derive(Debug, Clone, Default)]
pub struct TransferProgress {
    received: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
}

impl TransferProgress {
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.received.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
        )
    }
}

/// Acquire and publish an image. A stdin source requires a caller-owned
/// reader; the service never accesses process stdin or terminal state.
pub fn prepare_image(
    request: &PrepareImageRequest,
    stdin: Option<&mut dyn Read>,
) -> Result<PreparationReport> {
    prepare_image_with_progress(request, stdin, &TransferProgress::default())
}

pub fn prepare_image_with_progress(
    request: &PrepareImageRequest,
    stdin: Option<&mut dyn Read>,
    progress: &TransferProgress,
) -> Result<PreparationReport> {
    let PrepareImageRequest {
        cache_root,
        reference,
        prod,
    } = request;
    let source = ImageSource::classify(reference)?;
    // Refuse unsupported local production inputs before preparing the runtime.
    if *prod && !matches!(source, ImageSource::Registry(_)) {
        bail!(
            "production image preparation requires a digest-pinned registry reference with cosign; local sources are dev-only"
        );
    }
    if matches!(source, ImageSource::Stdin) && stdin.is_none() {
        bail!("stdin image preparation requires an archive reader");
    }
    // Explicit preparation owns best-effort housekeeping for every frontend.
    // Cache-only resolution never enters this path.
    crate::maintenance::cache::sweep_orphaned_vm_helpers_on_startup();
    let report = match source {
        ImageSource::Registry(_) => {
            let (image, trust, auth_source) =
                pull_core::pull_image_with_progress(cache_root, reference, *prod, progress)?;
            PreparationReport {
                provenance: image.provenance("image_pull", reference, &trust),
                rootfs_path: cache::safe_cache_path(
                    cache_root,
                    image
                        .rootfs_path
                        .as_deref()
                        .context("prepared image has no rootfs")?,
                )?,
                reference: image.reference,
                resolved_digest: image.resolved_digest,
                auth_source,
                local: false,
            }
        }
        source => {
            crate::launch::runtime_overlay::prepare_oci_guest_runtime(cache_root)?;
            let resolved = match source {
                ImageSource::OciArchive(path) => {
                    ingest::ingest_local_archive(cache_root, &path, reference, *prod)?
                }
                ImageSource::RootfsDir(path) => {
                    ingest::ingest_rootfs_dir(cache_root, &path, reference, *prod)?
                }
                ImageSource::Stdin => ingest::ingest_stdin_archive(
                    cache_root,
                    reference,
                    *prod,
                    stdin.context("stdin image preparation requires an archive reader")?,
                )?,
                ImageSource::Registry(_) => unreachable!(),
            };
            pull_core::publish_local_preparation(cache_root, reference, &resolved)?;
            PreparationReport {
                reference: resolved.reference,
                resolved_digest: resolved.resolved_digest,
                rootfs_path: resolved.rootfs_path,
                provenance: resolved.provenance,
                auth_source: "local".to_owned(),
                local: true,
            }
        }
    };
    mvm_core::audit_emit!(
        ImageFetch,
        "source=image_pull reference={} digest={} prod={} layers={} trust_policy={} verification_status={} auth_source={}",
        report.reference,
        report.resolved_digest,
        prod,
        report.provenance.layer_digests.len(),
        report.provenance.trust_policy,
        report.provenance.verification_status,
        report.auth_source
    );
    Ok(report)
}

/// Verify prepared state only. Never downloads, invokes cosign, builds the
/// guest runtime, ingests local bytes, or rematerializes a rootfs.
pub fn resolve_prepared_image(request: &ResolveImageRequest) -> Result<ResolvedOciRunImage> {
    pull_core::resolve_or_pull_run_image(&request.cache_root, &request.reference, request.prod)
}

pub fn oci_cache_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir()).join("oci")
}

/// Compatibility entry for native launch consumers; identical cache-only
/// semantics to [`resolve_prepared_image`].
pub fn resolve_or_pull_run_image(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    resolve_prepared_image(&ResolveImageRequest {
        cache_root: cache_root.to_owned(),
        reference: reference.to_owned(),
        prod,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_prepare_refuses_local_prod_and_missing_stdin_before_acquisition() {
        let cache = tempfile::tempdir().unwrap();
        for reference in ["rootfs-dir:/missing", "oci-archive:/missing", "-"] {
            let error = prepare_image(
                &PrepareImageRequest {
                    cache_root: cache.path().to_owned(),
                    reference: reference.to_owned(),
                    prod: true,
                },
                None,
            )
            .unwrap_err();
            assert!(error.to_string().contains("local sources are dev-only"));
        }
        let error = prepare_image(
            &PrepareImageRequest {
                cache_root: cache.path().to_owned(),
                reference: "-".to_owned(),
                prod: false,
            },
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires an archive reader"));
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
    }

    #[test]
    fn public_resolve_refuses_a_cold_cache_without_creating_state() {
        let cache = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(cache.path());
        env.set("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE", "download");
        let error = resolve_prepared_image(&ResolveImageRequest {
            cache_root: cache.path().to_owned(),
            reference: "127.0.0.1:1/missing:latest".to_owned(),
            prod: false,
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("not prepared"), "{error:#}");
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
    }
}
