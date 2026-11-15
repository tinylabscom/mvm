//! Canonical OCI preparation and cache resolution.
//!
//! Acquisition is explicit. Prepared resolution never invokes acquisition
//! hooks, a materializer, or an online signature verifier. Cache records stay
//! private and are evidence to validate, not authorization supplied by a caller.

mod base_image;
mod cache;
mod ingest;
#[cfg(test)]
mod legacy_machine_spec;
mod materialize;
mod oci_types;
pub(crate) mod prepared;
mod pull_core;
mod recent;
mod source;
mod trust;
mod trust_policy;

use anyhow::{Result, bail};
use std::path::Path;

use mvm_fs::oci::{ImageReference, RegistryAuthConfig};
use oci_types::CosignIdentity;

pub use oci_types::{OciProvenance, ResolvedOciRunImage};
pub use source::ImageSource;
pub use trust::OciRegistryAuthDecision;

/// Non-authoritative effects attached by the explicit acquisition caller.
/// Neither hook can supply trust, image bytes, or a materializer.
pub struct AcquisitionHooks {
    pub before_materialize: fn(),
    pub record_pull: fn(&OciPullRecord<'_>) -> Result<()>,
}

impl AcquisitionHooks {
    fn refuse() -> Self {
        Self {
            before_materialize: || panic!("prepared-only resolution reached acquisition"),
            record_pull: |_| bail!("prepared-only resolution reached lineage publication"),
        }
    }

    #[cfg(test)]
    fn test() -> Self {
        Self {
            before_materialize: || {},
            record_pull: |_| Ok(()),
        }
    }
}

/// Identity the existing CLI image-lineage owner records after acquisition.
pub struct OciPullRecord<'a> {
    pub registry: &'a str,
    pub repository: &'a str,
    pub resolved_digest: &'a str,
    pub layer_digests: Vec<String>,
    pub canonical_reference: &'a str,
    pub rootfs_path: &'a Path,
}

pub fn validate_preparation(reference: &str, prod: bool) -> Result<()> {
    pull_core::ensure_prod_digest_pin(reference, prod)?;
    pull_core::ensure_prod_registry_reference_policy(reference, prod)
}

pub fn ensure_prod_digest_pin(reference: &str, prod: bool) -> Result<()> {
    pull_core::ensure_prod_digest_pin(reference, prod)
}

pub fn require_prod_digest_pin(
    reference: &ImageReference,
    prod: bool,
    surface: &str,
) -> Result<()> {
    pull_core::require_prod_digest_pin(reference, prod, surface)
}

pub fn ensure_prod_registry_allowed(reference: &ImageReference, prod: bool) -> Result<()> {
    pull_core::ensure_prod_registry_allowed(reference, prod)
}

/// Resolve an already prepared source. Missing preparation is never repaired.
pub fn resolve_prepared(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    pull_core::resolve_or_pull_run_image(cache_root, reference, prod)
}

/// Explicit acquisition/materialization, retaining the existing CLI semantics.
pub fn acquire(
    cache_root: &Path,
    reference: &str,
    prod: bool,
    hooks: &AcquisitionHooks,
) -> Result<ResolvedOciRunImage> {
    pull_core::acquire_run_image_using(cache_root, reference, prod, hooks)
}

/// Prepare one source through the existing registry or local ingest owner.
pub fn pull(
    cache_root: &Path,
    reference: &str,
    prod: bool,
    hooks: &AcquisitionHooks,
) -> Result<ResolvedOciRunImage> {
    validate_preparation(reference, prod)?;
    match ImageSource::classify(reference)? {
        ImageSource::Registry(_) => {
            let (image, trust, auth_source) =
                pull_core::pull_image_with_trust(cache_root, reference, prod, hooks)?;
            let rootfs_path = cache::safe_cache_path(
                cache_root,
                image
                    .rootfs_path
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("pull produced no rootfs"))?,
            )?;
            Ok(ResolvedOciRunImage {
                provenance: image.provenance("image_pull", reference, &trust),
                reference: image.reference,
                resolved_digest: image.resolved_digest,
                rootfs_path,
                unpacked_root: None,
                pulled: true,
                auth_source: Some(auth_source),
            })
        }
        source => {
            crate::launch::runtime_overlay::prepare_oci_guest_runtime(cache_root)?;
            let resolved = match source {
                ImageSource::OciArchive(path) => {
                    ingest::ingest_local_archive(cache_root, &path, reference, prod)?
                }
                ImageSource::Stdin => ingest::ingest_stdin_archive(cache_root, reference, prod)?,
                ImageSource::RootfsDir(path) => {
                    ingest::ingest_rootfs_dir(cache_root, &path, reference, prod)?
                }
                ImageSource::Registry(_) => unreachable!("registry handled above"),
            };
            pull_core::publish_local_preparation(cache_root, reference, &resolved)?;
            Ok(resolved)
        }
    }
}

pub fn recent_image_references(cache_root: &Path) -> Result<Vec<String>> {
    recent::recent_image_references(cache_root)
}

pub fn registry_auth_for(reference: &ImageReference) -> Result<OciRegistryAuthDecision> {
    trust::registry_auth_for(reference)
}

pub fn registry_auth_from_lookup(
    reference: &ImageReference,
    lookup: impl FnMut(&str) -> Option<String>,
) -> Result<OciRegistryAuthDecision> {
    trust::registry_auth_from_lookup(reference, lookup)
}

pub fn list_json(cache_root: &Path, registry: Option<&str>) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(cache::list_rows(
        cache_root, registry,
    )?)?)
}

pub fn render_list(cache_root: &Path, registry: Option<&str>) -> Result<()> {
    cache::render_list(&cache::list_rows(cache_root, registry)?);
    Ok(())
}

pub fn inspect_json(cache_root: &Path, reference: &str) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(cache::inspect_image(
        cache_root, reference,
    )?)?)
}

pub fn render_inspect(cache_root: &Path, reference: &str) -> Result<()> {
    cache::render_inspect(&cache::inspect_image(cache_root, reference)?);
    Ok(())
}

pub fn inspect_digest_reference(cache_root: &Path, reference: &str) -> Result<String> {
    cache::inspect_image(cache_root, reference)?
        .image
        .digest_reference()
}

#[derive(Debug)]
pub struct RemovedImage {
    pub reference: String,
    pub removed_files: usize,
    pub freed_bytes: u64,
}

pub fn remove_image(cache_root: &Path, reference: &str) -> Result<RemovedImage> {
    let outcome = cache::remove_image(cache_root, reference)?;
    Ok(RemovedImage {
        reference: outcome.reference,
        removed_files: outcome.removed_files,
        freed_bytes: outcome.freed_bytes,
    })
}

/// Compact binary-size formatting shared with CLI cache presentation.
pub fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
