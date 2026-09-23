//! Resolve an `--image` reference to a bootable rootfs: serve a fresh cache
//! hit, self-heal a stale or partially-missing one, or fall through to a
//! registry pull. This is the run-path entry every OCI source funnels
//! through once it's been classified as a registry reference.

use std::collections::HashSet;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde_json::Value;

use mvm_fs::oci::{
    ImageReference, LayerDescriptor, LayerFetchOptions, OciLayerFetcher, OciManifestFetcher,
    UnpackOptions, UnpackReport, current_linux_platform, unpack_layer_with_prior_paths,
};

use super::cache::{find_image, layer_blob_path, load_index, read_verified_cache_file};
use super::cache::{safe_cache_path, sha256_hex, unpacked_dir_if_present};
use super::materialize::{
    RuntimeMaterializer, cached_rootfs_is_current, ensure_rootfs_verity_sidecars,
    inject_runtime_and_materialize, oci_entrypoint_from_cache_path, oci_runtime_tag,
    prepare_rootfs_only_tree, rematerialize_cached_image,
};
use super::oci_types::{CachedOciImage, CachedOciLayer, OciTrustDecision, ResolvedOciRunImage};
use super::source;
use super::trust::CosignCommandVerifier;
use super::trust_policy::trust_decision_for_cached_image;
use super::trust_policy::{enforce_oci_trust_policy_with, enforce_registry_allowlist};
use super::trust_policy::{ensure_signature_policy_is_configured, load_oci_registry_policy};

/// Refuse a mutable (non-digest-pinned) registry reference under `--prod`
/// before any network fetch or local resource resolution. Local sources
/// (OCI archive / stdin / rootfs dir) carry their own provenance and are
/// exempt. A pure reference-string check with no I/O, so it also gates the
/// run path ahead of workload-kernel resolution — not only the pull itself.
pub(in crate::commands) fn ensure_prod_digest_pin(reference: &str, prod: bool) -> Result<()> {
    if !prod {
        return Ok(());
    }
    if let source::ImageSource::Registry(_) = source::ImageSource::classify(reference)? {
        let image_ref: ImageReference = reference.parse()?;
        require_prod_digest_pin(&image_ref, true, "mvmctl run --image")?;
    }
    Ok(())
}

/// The digest-pin rule every `--prod` registry fetch shares: a tag can be
/// moved to other bytes after the fact, a digest cannot. `surface` names the
/// command in the refusal.
pub(in crate::commands) fn require_prod_digest_pin(
    image_ref: &ImageReference,
    prod: bool,
    surface: &str,
) -> Result<()> {
    if prod && !image_ref.is_digest_pinned() {
        bail!(
            "{surface} --prod requires a digest-pinned reference; {} names a tag",
            image_ref.canonical()
        );
    }
    Ok(())
}

pub(in crate::commands) fn resolve_or_pull_run_image(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    ensure_prod_digest_pin(reference, prod)?;
    ensure_prod_registry_reference_policy(reference, prod)?;
    mvm_client::launch::runtime_overlay::prepare_oci_guest_runtime(cache_root)?;
    resolve_or_pull_run_image_with(
        cache_root,
        reference,
        prod,
        super::materialize::inject_runtime_and_materialize,
        &CosignCommandVerifier,
    )
}

/// Reap helper processes a previous run orphaned, immediately before this run
/// may spawn a builder VM of its own.
///
/// Rootfs materialization falls back to a builder VM when the in-process ext4
/// writer cannot faithfully emit a tree, and that is the only way this path
/// adds a helper. Called at the branches that can reach a materializer rather
/// than on entry: a run that resolves entirely from the cache spawns nothing,
/// and the sweep needs a host process-table snapshot whose cost the prepared
/// launch path should not pay for cleanup it cannot cause.
fn sweep_before_builder_vm() {
    crate::commands::env::builder_vm::sweep_orphaned_vm_helpers_before_spawn();
}

pub(super) fn resolve_or_pull_run_image_with(
    cache_root: &Path,
    reference: &str,
    prod: bool,
    materialize: RuntimeMaterializer,
    verifier: &dyn super::trust::CosignVerifier,
) -> Result<ResolvedOciRunImage> {
    // Local sources route to their own ingest; a registry reference falls
    // through to the cache-or-pull path below.
    match source::ImageSource::classify(reference)? {
        source::ImageSource::OciArchive(path) => {
            return super::ingest::ingest_local_archive(cache_root, &path, reference, prod);
        }
        source::ImageSource::Stdin => {
            return super::ingest::ingest_stdin_archive(cache_root, reference, prod);
        }
        source::ImageSource::RootfsDir(path) => {
            return super::ingest::ingest_rootfs_dir(cache_root, &path, reference, prod);
        }
        source::ImageSource::Registry(_) => {}
    }
    ensure_prod_digest_pin(reference, prod)?;
    let image_ref: ImageReference = reference.parse()?;
    let canonical = image_ref.canonical();
    let runtime_tag = oci_runtime_tag(cache_root);
    let cached_entry = load_index(cache_root)
        .ok()
        .and_then(|index| find_image(&index, &canonical).cloned());
    // Trust first. Nothing is materialized, and no provenance mark is signed,
    // for a production run of an image the policy has not verified: a refusal
    // after the fact would leave a signed, sealed image in the cache.
    let cached_trust = cached_entry
        .as_ref()
        .map(|cached| trust_decision_for_cached_image(&image_ref, cached, prod, verifier))
        .transpose()?;
    let (image, pulled, trust, auth_source_from_pull) = match (cached_entry, cached_trust) {
        (Some(cached), Some(trust)) if cached_rootfs_is_current(&cached, &runtime_tag, prod) => {
            (cached, false, trust, None)
        }
        (Some(cached), Some(trust)) => {
            sweep_before_builder_vm();
            match rematerialize_cached_image(cache_root, cached, &runtime_tag, materialize, prod)? {
                Some(repaired) => (repaired, false, trust, None),
                None => {
                    sweep_before_builder_vm();
                    let (cached, trust, auth_source) =
                        pull_image_ref(cache_root, image_ref.clone(), reference, prod)?;
                    (cached, true, trust, Some(auth_source))
                }
            }
        }
        _ => {
            sweep_before_builder_vm();
            let (cached, trust, auth_source) =
                pull_image_ref(cache_root, image_ref.clone(), reference, prod)?;
            (cached, true, trust, Some(auth_source))
        }
    };
    let Some(rootfs_relative) = image.rootfs_path.as_deref() else {
        bail!(
            "cached OCI image {} has no materialized rootfs; run `mvmctl image pull {}` first",
            image.reference,
            image.reference
        );
    };
    let rootfs_path = safe_cache_path(cache_root, rootfs_relative)?;
    let mut rematerialized_from = None;
    if !super::materialize::reusable_rootfs(&rootfs_path, prod)? {
        // Self-heal a cache whose index still records a materialized rootfs but
        // whose sealed block-root artifacts have since drifted. That covers a
        // vanished `rootfs.ext4` (interrupted prune / manual delete) and older
        // ext4-only cache entries that predate the current verity-backed OCI
        // materializer. If the unpacked layer tree survives, re-run the same
        // seal `image pull` performs — network-free, from the cached layers —
        // rather than failing the run. Only when the unpacked tree is gone too
        // is this a genuine cache loss the user must re-pull.
        // A tree whose recorded owners are missing or unreadable counts as
        // gone: rebuilding from it would boot every file owned by root.
        match super::cache::read_cached_unpack(cache_root, &image.resolved_digest)? {
            Some(cached) => {
                let unpacked_root = cached.root;
                sweep_before_builder_vm();
                let signer;
                let evidence = if prod {
                    signer = crate::commands::vm::host_signer::load_or_init()
                        .context("load host signing key for the provenance mark")?;
                    Some(
                        mvm_build::provenance_mark::SealEvidence::builder(&signer.signing)
                            .with_image_ref(&image.reference)
                            .with_image_digest(&image.resolved_digest)
                            .build(),
                    )
                } else {
                    None
                };
                materialize(super::materialize::MaterializeCall {
                    cache_root,
                    unpacked_root: &unpacked_root,
                    rootfs_abs: &rootfs_path,
                    image_label: &image.reference,
                    entrypoint: oci_entrypoint_from_cache_path(
                        cache_root,
                        image.config_path.as_deref(),
                    )?
                    .as_ref(),
                    sealed: prod,
                    deferred_nodes: cached.deferred_nodes,
                    owners: cached.owners,
                    evidence,
                })
                .with_context(|| {
                    format!(
                        "re-materializing cached OCI rootfs artifacts for {} from {}",
                        image.reference,
                        unpacked_root.display()
                    )
                })?;
                rematerialized_from = Some(unpacked_root);
            }
            None => bail!(
                "cached OCI image {} is missing sealed rootfs artifacts beside {} and its unpacked \
                 layers are gone; run `mvmctl image pull {}` to re-fetch",
                image.reference,
                rootfs_path.display(),
                image.reference
            ),
        }
    }
    ensure_rootfs_verity_sidecars(
        &rootfs_path,
        &image.reference,
        rematerialized_from.as_deref(),
    )?;
    super::materialize::refuse_unsealed_prod_rootfs(&rootfs_path, prod)?;
    let unpacked_root = unpacked_dir_if_present(cache_root, &image.resolved_digest)
        .map(|raw| prepare_rootfs_only_tree(cache_root, &raw, &image.resolved_digest))
        .transpose()?;
    Ok(ResolvedOciRunImage {
        provenance: image.provenance("run_image", reference, &trust),
        reference: image.reference,
        resolved_digest: image.resolved_digest,
        rootfs_path,
        unpacked_root,
        pulled,
        auth_source: auth_source_from_pull,
    })
}

pub(super) fn pull_image_with_trust(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<(CachedOciImage, OciTrustDecision, String)> {
    pull_image_with_trust_with_prepare(
        cache_root,
        reference,
        prod,
        mvm_client::launch::runtime_overlay::prepare_oci_guest_runtime,
    )
}

fn pull_image_with_trust_with_prepare(
    cache_root: &Path,
    reference: &str,
    prod: bool,
    prepare_guest_runtime: impl FnOnce(&Path) -> Result<()>,
) -> Result<(CachedOciImage, OciTrustDecision, String)> {
    let image_ref: ImageReference = reference.parse()?;
    require_prod_digest_pin(&image_ref, prod, "mvmctl image pull")?;
    ensure_prod_registry_policy(&image_ref, prod)?;
    prepare_guest_runtime(cache_root)?;
    pull_image_ref(cache_root, image_ref, reference, prod)
}

fn ensure_prod_registry_reference_policy(reference: &str, prod: bool) -> Result<()> {
    if !prod {
        return Ok(());
    }
    if let source::ImageSource::Registry(_) = source::ImageSource::classify(reference)? {
        let image_ref: ImageReference = reference.parse()?;
        ensure_prod_registry_policy(&image_ref, true)?;
    }
    Ok(())
}

/// Under `--prod`, refuse a registry the OCI registry policy does not allow.
/// Needs only the policy's allowlist, so it applies to callers whose content
/// is signed some other way.
pub(in crate::commands) fn ensure_prod_registry_allowed(
    image_ref: &ImageReference,
    prod: bool,
) -> Result<()> {
    if !prod {
        return Ok(());
    }
    let policy = super::trust_policy::load_oci_registry_allowlist()?;
    enforce_registry_allowlist(image_ref, &policy)
}

/// Under `--prod`, load the OCI registry policy, refuse a registry it does not
/// allow, and require the cosign signature section an image pull verifies.
fn ensure_prod_registry_policy(image_ref: &ImageReference, prod: bool) -> Result<()> {
    if !prod {
        return Ok(());
    }
    let policy = load_oci_registry_policy()?;
    enforce_registry_allowlist(image_ref, &policy)?;
    ensure_signature_policy_is_configured(&policy)
}

#[tracing::instrument(skip_all, fields(reference = supplied_reference, prod))]
fn pull_image_ref(
    cache_root: &Path,
    image_ref: ImageReference,
    supplied_reference: &str,
    prod: bool,
) -> Result<(CachedOciImage, OciTrustDecision, String)> {
    // Reaching here means the cache did not answer and bytes are coming off a
    // registry. A launch measurement that hides an acquisition is not a launch
    // measurement, so it is recorded where the fetch actually happens.
    mvm_core::launch_trace::record_image_pull();
    let prod_policy = if prod {
        let policy = load_oci_registry_policy()?;
        enforce_registry_allowlist(&image_ref, &policy)?;
        ensure_signature_policy_is_configured(&policy)?;
        Some(policy)
    } else {
        None
    };
    let registry_auth = super::trust::registry_auth_for(&image_ref)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build Tokio runtime for OCI pull")?;

    let manifest_fetcher = OciManifestFetcher::with_auth(registry_auth.auth);
    let manifest = runtime
        .block_on(
            manifest_fetcher.fetch_linux_platform_manifest(&image_ref, &current_linux_platform()),
        )
        .context("fetch OCI image manifest")?;
    let layers = manifest.layers().context("parse OCI image layers")?;
    if layers.is_empty() {
        bail!(
            "OCI image manifest has no layers: {}",
            image_ref.canonical()
        );
    }

    let trust = match &prod_policy {
        Some(policy) => enforce_oci_trust_policy_with(
            &image_ref,
            &manifest.digest,
            policy,
            &CosignCommandVerifier,
        )?,
        None => OciTrustDecision::dev_digest_only(&image_ref),
    };

    let manifest_hex = sha256_hex(&manifest.digest)?;
    let manifest_path = format!("manifests/{manifest_hex}.json");
    super::cache::write_cache_file(cache_root, &manifest_path, &manifest.bytes)?;

    let config_path = write_config_blob(
        cache_root,
        &runtime,
        &manifest_fetcher,
        &image_ref,
        &manifest.bytes,
    )?;
    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(&manifest_fetcher, LayerFetchOptions::default());
    let unpacked_root = cache_root.join("unpacked").join(&manifest_hex);
    // Another run of this image may be injecting into or copying from the
    // tree this is about to remove. Released before materializing, which
    // takes it again itself.
    let tree_lock = mvm_build::run_image::lock_unpacked_tree(&unpacked_root)?;
    if unpacked_root.exists() {
        fs::remove_dir_all(&unpacked_root)
            .with_context(|| format!("remove stale unpacked root {}", unpacked_root.display()))?;
    }
    fs::create_dir_all(&unpacked_root)
        .with_context(|| format!("create {}", unpacked_root.display()))?;

    let mut cached_layers = Vec::with_capacity(layers.len());
    let mut prior_layer_paths = std::collections::HashSet::new();
    let mut deferred_nodes = Vec::new();
    let mut owners = mvm_fs::ownership::OwnerTable::new();
    for layer in &layers {
        let report = fetch_or_unpack_layer(
            cache_root,
            &runtime,
            &layer_fetcher,
            &image_ref,
            layer,
            &unpacked_root,
            &prior_layer_paths,
        )
        .with_context(|| format!("layer {}", layer.digest))?;
        owners.absorb(&report.ownership);
        prior_layer_paths.extend(report.paths_written);
        deferred_nodes.extend(report.deferred_nodes);
        cached_layers.push(CachedOciLayer {
            digest: layer.digest.clone(),
            size_bytes: layer.size,
            path: Some(layer_blob_path(&layer.digest)?),
        });
    }

    let runtime_tag = oci_runtime_tag(cache_root);
    let rootfs_path = super::materialize::oci_rootfs_rel(&manifest.digest, &runtime_tag, prod)?;
    let rootfs_abs = cache_root.join(&rootfs_path);
    super::cache::write_deferred_nodes(cache_root, &manifest.digest, &deferred_nodes)?;
    super::cache::write_layer_owners(cache_root, &manifest.digest, &owners)?;
    // The config blob written above is the image's own declaration of `Env`,
    // `WorkingDir` and `Entrypoint`/`Cmd`. Materializing without it discards
    // all three: the guest then falls back to `workload_env::DEFAULT_PATH`, so
    // an image's own tools are off `PATH` even though the binaries are in the
    // rootfs. The cache-hit path beside this one has always passed it; this
    // one computed `config_path` forty lines earlier and dropped it.
    drop(tree_lock);
    let entrypoint = oci_entrypoint_from_cache_path(cache_root, config_path.as_deref())?;
    let canonical_label = image_ref.canonical();
    materialize_pulled_rootfs(
        PulledRootfs {
            cache_root,
            unpacked_root: &unpacked_root,
            rootfs_abs: &rootfs_abs,
            canonical_reference: &canonical_label,
            resolved_digest: &manifest.digest,
            entrypoint: entrypoint.as_ref(),
            prod,
            deferred_nodes,
            owners,
        },
        inject_runtime_and_materialize,
    )?;

    let provenance = super::oci_types::OciProvenance {
        schema_version: 1,
        source: "image_pull".to_string(),
        supplied_reference: supplied_reference.to_string(),
        canonical_reference: image_ref.canonical(),
        registry: image_ref.registry.clone(),
        repository: image_ref.repository.clone(),
        tag: image_ref.tag.clone(),
        resolved_digest: manifest.digest.clone(),
        layer_digests: cached_layers
            .iter()
            .map(|layer| layer.digest.clone())
            .collect(),
        trust_policy: trust.trust_policy.clone(),
        verification_status: trust.verification_status.clone(),
    };
    let claims_path = format!("claims/{}.provenance.json", manifest_hex);
    super::cache::write_cache_file(
        cache_root,
        &claims_path,
        &serde_json::to_vec_pretty(&provenance).context("serialize OCI provenance")?,
    )?;

    // Record the pulled image as an audited version-lineage node before it is
    // registered in the cache index — the same fail-closed posture as the flake
    // build path (lineage is provenance, never authorization).
    let canonical_reference = image_ref.canonical();
    crate::commands::build::image_lineage::record_oci_pull_node(
        &crate::commands::build::image_lineage::OciPullNode {
            registry: &image_ref.registry,
            repository: &image_ref.repository,
            resolved_digest: &manifest.digest,
            layer_digests: cached_layers.iter().map(|l| l.digest.clone()).collect(),
            canonical_reference: &canonical_reference,
            rootfs_path: &rootfs_abs,
        },
    )?;

    let cached = CachedOciImage {
        reference: image_ref.canonical(),
        registry: image_ref.registry.clone(),
        repository: image_ref.repository.clone(),
        tag: image_ref.tag.clone(),
        resolved_digest: manifest.digest.clone(),
        fetched_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        manifest_path,
        config_path,
        rootfs_path: Some(rootfs_path),
        runtime_tag: Some(runtime_tag),
        claims_path: Some(claims_path),
        layers: cached_layers,
    };
    super::cache::upsert_cached_image(cache_root, cached.clone())?;
    Ok((cached, trust, registry_auth.source))
}

/// Everything a fresh pull hands to the materializer.
struct PulledRootfs<'a> {
    cache_root: &'a Path,
    unpacked_root: &'a Path,
    rootfs_abs: &'a Path,
    canonical_reference: &'a str,
    resolved_digest: &'a str,
    entrypoint: Option<&'a mvm_build::oci_runtime_inject::ImageRuntimeConfig>,
    prod: bool,
    deferred_nodes: Vec<mvm_fs::ext4::Node>,
    owners: mvm_fs::ownership::OwnerTable,
}

/// Materialize a freshly pulled image as the variant the run asked for.
///
/// A production pull is sealed and carries a signed provenance mark. The
/// caller reaches here only after the trust policy has verified the image.
/// This used to materialize the dev variant whatever the flag said, and a
/// `--prod` run on a cold cache then booted it.
fn materialize_pulled_rootfs(
    pulled: PulledRootfs<'_>,
    materialize: RuntimeMaterializer,
) -> Result<()> {
    let signer = pulled
        .prod
        .then(crate::commands::vm::host_signer::load_or_init)
        .transpose()
        .context("load host signing key for the provenance mark")?;
    let evidence = signer.as_ref().map(|signer| {
        mvm_build::provenance_mark::SealEvidence::builder(&signer.signing)
            .with_image_ref(pulled.canonical_reference)
            .with_image_digest(pulled.resolved_digest)
            .build()
    });
    materialize(super::materialize::MaterializeCall {
        cache_root: pulled.cache_root,
        unpacked_root: pulled.unpacked_root,
        rootfs_abs: pulled.rootfs_abs,
        image_label: pulled.canonical_reference,
        entrypoint: pulled.entrypoint,
        sealed: pulled.prod,
        deferred_nodes: pulled.deferred_nodes,
        owners: pulled.owners,
        evidence,
    })
}

fn write_config_blob(
    cache_root: &Path,
    runtime: &tokio::runtime::Runtime,
    manifest_fetcher: &OciManifestFetcher,
    image_ref: &ImageReference,
    manifest_bytes: &[u8],
) -> Result<Option<String>> {
    let Some(config) = manifest_config_descriptor(manifest_bytes)? else {
        return Ok(None);
    };
    let config_path = format!("configs/{}.json", sha256_hex(&config.digest)?);
    if let Some(bytes) = read_verified_cache_file(cache_root, &config_path, &config.digest)?
        && serde_json::from_slice::<Value>(&bytes).is_ok()
    {
        return Ok(Some(config_path));
    }

    let fetcher =
        OciLayerFetcher::from_manifest_fetcher(manifest_fetcher, LayerFetchOptions::default());
    let mut bytes = Vec::new();
    runtime
        .block_on(fetcher.fetch_layer(image_ref, &config, &mut bytes))
        .context("fetch OCI image config blob")?;
    super::cache::write_cache_file(cache_root, &config_path, &bytes)?;
    Ok(Some(config_path))
}

fn manifest_config_descriptor(manifest_bytes: &[u8]) -> Result<Option<LayerDescriptor>> {
    let value: Value = serde_json::from_slice(manifest_bytes).context("parse manifest JSON")?;
    let Some(config) = value.get("config").and_then(Value::as_object) else {
        return Ok(None);
    };
    let digest = config
        .get("digest")
        .and_then(Value::as_str)
        .context("manifest config missing digest")?
        .to_string();
    let media_type = config
        .get("mediaType")
        .and_then(Value::as_str)
        .unwrap_or("application/vnd.oci.image.config.v1+json")
        .to_string();
    let size = config.get("size").and_then(Value::as_u64).unwrap_or(0);
    Ok(Some(LayerDescriptor {
        digest,
        size,
        media_type,
    }))
}

#[tracing::instrument(skip_all, fields(digest = %layer.digest, size = layer.size))]
fn fetch_or_unpack_layer(
    cache_root: &Path,
    runtime: &tokio::runtime::Runtime,
    fetcher: &OciLayerFetcher,
    image_ref: &ImageReference,
    layer: &LayerDescriptor,
    unpacked_root: &Path,
    prior_layer_paths: &HashSet<PathBuf>,
) -> Result<UnpackReport> {
    let path = layer_blob_path(&layer.digest)?;
    let cache_abs = safe_cache_path(cache_root, &path)?;

    if cache_abs.exists() {
        match runtime.block_on(mvm_fs::oci::layer::verify_and_unpack_layer_file(
            layer,
            &cache_abs,
            unpacked_root,
            &UnpackOptions::default(),
            prior_layer_paths,
        )) {
            Ok(report) => return Ok(report),
            Err(mvm_fs::oci::OciError::DigestMismatch { .. }) => {
                // Corrupt cache: evict it and fall through to a fresh fetch.
                let _ = std::fs::remove_file(&cache_abs);
            }
            Err(e) => return Err(e.into()),
        }
    }

    runtime
        .block_on(fetcher.fetch_and_unpack_layer(
            image_ref,
            layer,
            &cache_abs,
            unpacked_root,
            &UnpackOptions::default(),
            prior_layer_paths,
        ))
        .with_context(|| format!("fetch and unpack layer {}", layer.digest))
}

pub(super) fn unpack_layer_bytes(
    layer: &LayerDescriptor,
    bytes: &[u8],
    unpacked_root: &Path,
    prior_layer_paths: &HashSet<PathBuf>,
) -> Result<UnpackReport> {
    let report = if is_gzip_layer(&layer.media_type) {
        unpack_layer_with_prior_paths(
            GzDecoder::new(Cursor::new(bytes)),
            unpacked_root,
            &UnpackOptions::default(),
            prior_layer_paths,
        )
    } else {
        unpack_layer_with_prior_paths(
            Cursor::new(bytes),
            unpacked_root,
            &UnpackOptions::default(),
            prior_layer_paths,
        )
    }?;
    if !report.refused.is_empty() {
        bail!("layer unpack refused entries: {:?}", report.refused);
    }
    Ok(report)
}

fn is_gzip_layer(media_type: &str) -> bool {
    media_type.ends_with("+gzip")
        || media_type.ends_with(".gzip")
        || media_type.contains("tar.gzip")
}

#[cfg(test)]
mod tests {
    use super::super::oci_types::OciCacheIndex;
    use super::*;

    fn sample_image(reference: &str, digest: &str, layer_path: &str) -> CachedOciImage {
        CachedOciImage {
            reference: reference.to_string(),
            registry: "docker.io".to_string(),
            repository: "library/alpine".to_string(),
            tag: Some("3.20".to_string()),
            resolved_digest: digest.to_string(),
            fetched_at: "2026-05-18T00:00:00Z".to_string(),
            manifest_path: "manifests/alpine.json".to_string(),
            config_path: Some("configs/alpine.json".to_string()),
            rootfs_path: None,
            runtime_tag: None,
            claims_path: Some("claims/alpine.json".to_string()),
            layers: vec![CachedOciLayer {
                digest: "sha256:layer".to_string(),
                size_bytes: 4,
                path: Some(layer_path.to_string()),
            }],
        }
    }

    fn write_index(cache_root: &Path, index: &OciCacheIndex) {
        fs::create_dir_all(cache_root).expect("create cache root");
        fs::write(
            cache_root.join(super::super::oci_types::INDEX_FILE),
            serde_json::to_vec_pretty(index).expect("serialize index"),
        )
        .expect("write index");
    }

    fn write_file(cache_root: &Path, relative: &str, body: &[u8]) {
        let path = cache_root.join(relative);
        fs::create_dir_all(path.parent().expect("relative has parent")).expect("create parent");
        fs::write(path, body).expect("write cache file");
    }

    fn write_minimal_config(cache_root: &Path) {
        write_file(cache_root, "configs/alpine.json", br#"{"config":{}}"#);
    }

    fn create_unpacked_root(cache_root: &Path, digest: &str) -> std::path::PathBuf {
        let unpacked = cache_root
            .join("unpacked")
            .join(sha256_hex(digest).unwrap());
        fs::create_dir_all(&unpacked).expect("create unpacked root");
        fs::write(unpacked.join("layer-file"), b"from-layer").expect("write unpacked file");
        crate::commands::image::cache::write_layer_owners(
            cache_root,
            digest,
            &mvm_fs::ownership::OwnerTable::new(),
        )
        .expect("record layer owners");
        unpacked
    }

    /// Where a dev run expects this image's rootfs, for the runtime currently
    /// seeded under `cache_root`.
    fn dev_rootfs_rel(cache_root: &Path, digest: &str) -> String {
        super::super::materialize::oci_rootfs_rel(digest, &oci_runtime_tag(cache_root), false)
            .expect("rootfs path")
    }

    fn seed_guest_runtime_cache(cache_root: &Path) {
        use mvm_build::guest_agent_build::{GuestAgentLayout, guest_binary_source};
        use mvm_core::arch::GuestArch;

        // Seed the key the resolver actually reads, not the one this fixture
        // assumed. In a source checkout the resolver keys on a fingerprint of
        // the guest sources, so a version-keyed seed misses — silently,
        // because a miss is not an error, it is a real cross-compile of the
        // guest agent. That is what made these tests take fifty-five seconds
        // each while appearing to work from a seeded cache.
        let source = guest_binary_source().expect("resolve the guest-binary cache key");
        let guest_layout =
            GuestAgentLayout::under(cache_root, source.cache_key(), GuestArch::host());
        std::fs::create_dir_all(&guest_layout.dir).expect("create guest cache dir");
        for path in [
            &guest_layout.agent,
            &guest_layout.netinit,
            &guest_layout.egress_client,
            &guest_layout.entrypoint_runner,
        ] {
            std::fs::write(path, b"#!/bin/sh\nexit 0\n").expect("seed guest runtime cache");
        }
    }

    fn fake_runtime_materialize(
        call: super::super::materialize::MaterializeCall<'_>,
    ) -> Result<()> {
        assert!(call.unpacked_root.is_dir(), "unpacked root must exist");
        let parent = call.rootfs_abs.parent().expect("rootfs has parent");
        fs::create_dir_all(parent)?;
        fs::write(
            call.rootfs_abs,
            format!("materialized:{}", call.image_label),
        )?;
        fs::write(parent.join("rootfs.verity"), b"fake-verity")?;
        fs::write(parent.join("rootfs.roothash"), b"abc\n")?;
        // A fn pointer can't capture, so the deferred set the materializer
        // was handed is recorded on disk for the caller to assert on.
        fs::write(
            parent.join("deferred-seen.json"),
            serde_json::to_vec(&call.deferred_nodes)?,
        )?;
        fs::write(
            parent.join("owners-seen.json"),
            serde_json::to_vec(&call.owners)?,
        )?;
        fs::write(
            parent.join("seal-seen.json"),
            serde_json::to_vec(&serde_json::json!({
                "sealed": call.sealed,
                "evidence": call.evidence.is_some(),
            }))?,
        )?;
        // The sidecar the real materializer writes, with the variant it built.
        mvm_build::builder_vm::GuestSidecar::for_oci_run(call.image_label, call.sealed, true)
            .write_to_dir(parent)?;
        Ok(())
    }

    /// A materializer that records a dev sidecar whatever it was asked for:
    /// the shape of an image the reuse check or the final gate must refuse
    /// for a `--prod` run.
    fn unsealed_materialize(call: super::super::materialize::MaterializeCall<'_>) -> Result<()> {
        fake_runtime_materialize(super::super::materialize::MaterializeCall {
            sealed: false,
            evidence: None,
            ..call
        })
    }

    /// Accepts every signature, and counts how often it was asked.
    struct AcceptingVerifier(std::cell::Cell<u32>);

    impl super::super::trust::CosignVerifier for AcceptingVerifier {
        fn verify(
            &self,
            _reference: &str,
            _identity: &super::super::oci_types::CosignIdentity,
        ) -> Result<(), super::super::trust::CosignVerifyError> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    struct RejectingVerifier;

    impl super::super::trust::CosignVerifier for RejectingVerifier {
        fn verify(
            &self,
            _reference: &str,
            _identity: &super::super::oci_types::CosignIdentity,
        ) -> Result<(), super::super::trust::CosignVerifyError> {
            Err(super::super::trust::CosignVerifyError::MissingSignature(
                "no matching signatures".to_string(),
            ))
        }
    }

    const PINNED: &str = "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PINNED_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A scratch mvm home with a production OCI policy, a seeded guest
    /// runtime, and an index entry plus unpacked tree for [`PINNED`] — every
    /// input a `--prod` resolve reads, none of them the developer's.
    struct ProdFixture {
        _env: mvm_core::util::test_env::TestEnv,
        _home: tempfile::TempDir,
        cache: std::path::PathBuf,
    }

    fn prod_fixture() -> ProdFixture {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let policy = home.path().join("oci-policy.toml");
        fs::write(
            &policy,
            r#"
allowed_registries = ["docker.io"]
require_signatures = true

[[cosign]]
certificate_identity = "https://github.com/example/images/.github/workflows/release.yml@refs/tags/v1"
certificate_oidc_issuer = "https://token.actions.githubusercontent.com"
"#,
        )
        .expect("write policy");
        env.set("MVM_OCI_POLICY", &policy);
        let cache = home.path().join("cache/oci");
        seed_guest_runtime_cache(&cache);
        let mut image = sample_image(PINNED, PINNED_DIGEST, "blobs/a");
        image.config_path = None;
        write_index(
            &cache,
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        create_unpacked_root(&cache, PINNED_DIGEST);
        ProdFixture {
            _env: env,
            _home: home,
            cache,
        }
    }

    fn sidecar_sealed(rootfs: &Path) -> bool {
        crate::commands::vm::agent_verbs::image_is_sealed(rootfs)
    }

    fn resolve(
        fixture: &ProdFixture,
        prod: bool,
        materialize: RuntimeMaterializer,
    ) -> Result<ResolvedOciRunImage> {
        resolve_or_pull_run_image_with(
            &fixture.cache,
            PINNED,
            prod,
            materialize,
            &AcceptingVerifier(std::cell::Cell::new(0)),
        )
    }

    /// The reported bug: a dev run cached its image first, and a `--prod` run
    /// of the same image reused it — unsealed, so the boot picked the dev
    /// agent profile. The prod run now builds its own sealed image beside it.
    #[test]
    fn a_prod_run_after_a_dev_run_gets_its_own_sealed_image() {
        let fixture = prod_fixture();
        let dev = resolve(&fixture, false, fake_runtime_materialize).expect("dev resolves");
        assert!(!sidecar_sealed(&dev.rootfs_path));

        let prod = resolve(&fixture, true, fake_runtime_materialize).expect("prod resolves");

        assert_ne!(
            prod.rootfs_path, dev.rootfs_path,
            "the variants never share a file"
        );
        assert!(sidecar_sealed(&prod.rootfs_path));
        let seen: serde_json::Value = serde_json::from_slice(
            &fs::read(prod.rootfs_path.parent().unwrap().join("seal-seen.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(seen["sealed"], true);
        assert_eq!(seen["evidence"], true, "a sealed image carries its mark");
        assert!(
            !sidecar_sealed(&dev.rootfs_path),
            "the dev image is untouched"
        );
    }

    /// And the other way round: a dev run after a prod run does not reuse the
    /// sealed image; it gets a dev one.
    #[test]
    fn a_dev_run_after_a_prod_run_gets_its_own_dev_image() {
        let fixture = prod_fixture();
        let prod = resolve(&fixture, true, fake_runtime_materialize).expect("prod resolves");
        assert!(sidecar_sealed(&prod.rootfs_path));

        let dev = resolve(&fixture, false, fake_runtime_materialize).expect("dev resolves");

        assert_ne!(dev.rootfs_path, prod.rootfs_path);
        assert!(!sidecar_sealed(&dev.rootfs_path));
        assert!(sidecar_sealed(&prod.rootfs_path));
    }

    /// A file at the sealed path whose sidecar says otherwise — an interrupted
    /// or older build — is rebuilt, not trusted.
    #[test]
    fn a_prod_run_rebuilds_an_unsealed_image_at_the_sealed_path() {
        let fixture = prod_fixture();
        let rel = super::super::materialize::oci_rootfs_rel(
            PINNED_DIGEST,
            &oci_runtime_tag(&fixture.cache),
            true,
        )
        .unwrap();
        let rootfs = fixture.cache.join(&rel);
        fs::create_dir_all(rootfs.parent().unwrap()).unwrap();
        for (name, body) in [
            ("rootfs.ext4", "dev bytes"),
            ("rootfs.verity", "v"),
            ("rootfs.roothash", "h\n"),
        ] {
            fs::write(rootfs.parent().unwrap().join(name), body).unwrap();
        }
        mvm_build::builder_vm::GuestSidecar::for_oci_run(PINNED, false, true)
            .write_to_dir(rootfs.parent().unwrap())
            .unwrap();
        let mut index = load_index(&fixture.cache).unwrap();
        index.images[0].rootfs_path = Some(rel.clone());
        index.images[0].runtime_tag = Some(oci_runtime_tag(&fixture.cache));
        crate::commands::image::cache::save_index(&fixture.cache, &index).unwrap();

        let prod = resolve(&fixture, true, fake_runtime_materialize).expect("prod resolves");

        assert_eq!(prod.rootfs_path, rootfs);
        assert!(sidecar_sealed(&rootfs));
        assert_ne!(fs::read_to_string(&rootfs).unwrap(), "dev bytes");
    }

    /// Whatever the cache or a materializer did, a `--prod` resolve never
    /// hands back an image whose sidecar is not sealed.
    #[test]
    fn a_prod_run_is_refused_an_image_that_is_not_sealed() {
        let fixture = prod_fixture();
        let err = resolve(&fixture, true, unsealed_materialize)
            .expect_err("an unsealed image must not reach a production boot");
        assert!(
            format!("{err:#}").contains("does not record a sealed image"),
            "{err:#}"
        );
    }

    /// The trust check runs before anything is built or signed: an image the
    /// policy refuses leaves no sealed, signed image in the cache.
    #[test]
    fn a_prod_run_the_trust_policy_refuses_materializes_nothing() {
        let fixture = prod_fixture();
        let err = resolve_or_pull_run_image_with(
            &fixture.cache,
            PINNED,
            true,
            fake_runtime_materialize,
            &RejectingVerifier,
        )
        .expect_err("an unverified image must be refused");
        assert!(
            format!("{err:#}").contains("cosign verification failed"),
            "{err:#}"
        );
        let sealed_dir = fixture
            .cache
            .join(
                super::super::materialize::oci_rootfs_rel(
                    PINNED_DIGEST,
                    &oci_runtime_tag(&fixture.cache),
                    true,
                )
                .unwrap(),
            )
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(
            !sealed_dir.exists(),
            "nothing was materialized for the refused run"
        );
    }

    /// A fresh `--prod` pull materializes the sealed variant with its mark;
    /// it used to hard-code the dev variant.
    #[test]
    fn a_fresh_prod_pull_materializes_the_sealed_variant() {
        let fixture = prod_fixture();
        let rootfs_abs = fixture.cache.join("rootfs/pulled-sealed/rootfs.ext4");
        let unpacked = fixture
            .cache
            .join("unpacked")
            .join(sha256_hex(PINNED_DIGEST).unwrap());
        materialize_pulled_rootfs(
            PulledRootfs {
                cache_root: &fixture.cache,
                unpacked_root: &unpacked,
                rootfs_abs: &rootfs_abs,
                canonical_reference: PINNED,
                resolved_digest: PINNED_DIGEST,
                entrypoint: None,
                prod: true,
                deferred_nodes: Vec::new(),
                owners: mvm_fs::ownership::OwnerTable::new(),
            },
            fake_runtime_materialize,
        )
        .expect("prod pull materializes");

        assert!(sidecar_sealed(&rootfs_abs));
        let seen: serde_json::Value = serde_json::from_slice(
            &fs::read(rootfs_abs.parent().unwrap().join("seal-seen.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(seen["evidence"], true);
    }

    #[test]
    fn prod_pull_requires_digest_pin_before_network() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let err = pull_image_with_trust(tmp.path(), "docker.io/library/alpine:3.20", true)
            .expect_err("mutable prod pull must fail before registry access");
        assert!(
            err.to_string()
                .contains("requires a digest-pinned reference"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prod_pull_requires_registry_policy_before_guest_runtime_preparation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        env.remove("MVM_OCI_POLICY");
        let cache_root = tmp.path().join("cache/oci");
        let pinned = concat!(
            "docker.io/library/alpine@sha256:",
            "1111111111111111111111111111111111111111111111111111111111111111"
        );

        let err = pull_image_with_trust_with_prepare(&cache_root, pinned, true, |_| {
            bail!("guest runtime preparation ran before production policy admission")
        })
        .expect_err("missing production policy must fail before artifact preparation");

        assert!(
            err.to_string().contains("requires an OCI registry policy"),
            "unexpected error: {err}"
        );
    }

    /// The other half of the digest-pin rule, and the half nothing asserted.
    ///
    /// `prod && !pinned` has two operands, so a test that only drives
    /// `prod=true, pinned=false` pins one cell of a four-cell truth table.
    /// Flipping the `&&` to `||` still refuses the mutable prod pull above —
    /// it just *also* refuses everything else, and no test noticed.
    ///
    /// A digest-pinned prod pull must get past this check. It will still fail,
    /// because the test has no registry, but it must fail for a reason that is
    /// not the pin rule.
    #[test]
    fn a_digest_pinned_prod_pull_is_not_refused_by_the_pin_rule() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        // A closed local port: the pull fails on connect in milliseconds
        // instead of reaching a real registry. Which check rejected it is the
        // only thing under test, so the registry never needs to answer — and a
        // unit test that pulls from the internet is a flake waiting to happen.
        let pinned = concat!(
            "127.0.0.1:1/library/alpine@sha256:",
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let err = pull_image_with_trust(tmp.path(), pinned, true)
            .expect_err("no registry is listening on this port");
        assert!(
            !err.to_string()
                .contains("requires a digest-pinned reference"),
            "a digest-pinned reference must clear the pin rule; got: {err}"
        );
    }

    /// The dev cell of the same truth table. A mutable tag outside `--prod` is
    /// the ordinary case, and `||` would refuse it.
    #[test]
    fn a_mutable_tag_outside_prod_is_not_refused_by_the_pin_rule() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let err = pull_image_with_trust(tmp.path(), "127.0.0.1:1/library/alpine:3.20", false)
            .expect_err("no registry is listening on this port");
        assert!(
            !err.to_string()
                .contains("requires a digest-pinned reference"),
            "the pin rule applies only under --prod; got: {err}"
        );
    }

    #[test]
    fn prod_run_image_requires_digest_pin_before_network() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let err = resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", true)
            .expect_err("mutable prod run image must fail before registry access");
        assert!(
            err.to_string()
                .contains("requires a digest-pinned reference"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_run_image_uses_cached_rootfs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some(dev_rootfs_rel(tmp.path(), digest));
        image.runtime_tag = Some(oci_runtime_tag(tmp.path()));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        let rel = dev_rootfs_rel(tmp.path(), digest);
        let dir = Path::new(&rel).parent().expect("rootfs dir");
        write_file(tmp.path(), &rel, b"rootfs");
        write_file(
            tmp.path(),
            &dir.join("rootfs.verity").to_string_lossy(),
            b"verity",
        );
        write_file(
            tmp.path(),
            &dir.join("rootfs.roothash").to_string_lossy(),
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        );
        mvm_build::builder_vm::GuestSidecar::for_oci_run("alpine", false, true)
            .write_to_dir(&tmp.path().join(dir))
            .expect("publish the sidecar that marks the set complete");

        let resolved =
            resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", false)
                .expect("cached rootfs resolves");

        assert_eq!(resolved.reference, "docker.io/library/alpine:3.20");
        assert_eq!(resolved.resolved_digest, digest);
        assert!(resolved.rootfs_path.ends_with(&rel));
        assert!(!resolved.pulled);
        assert_eq!(resolved.provenance.source, "run_image");
        assert_eq!(
            resolved.provenance.supplied_reference,
            "docker.io/library/alpine:3.20"
        );
        assert_eq!(resolved.provenance.registry, "docker.io");
        assert_eq!(
            resolved.provenance.layer_digests,
            vec!["sha256:layer".to_string()]
        );
    }

    #[test]
    fn resolve_run_image_rematerializes_stale_record_without_rootfs_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        create_unpacked_root(tmp.path(), digest);

        let resolved = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
            &super::super::trust::CosignCommandVerifier,
        )
        .expect("stale cached image should be repaired from unpacked layers");

        let runtime_tag = oci_runtime_tag(tmp.path());
        let expected = dev_rootfs_rel(tmp.path(), digest);
        assert_eq!(resolved.rootfs_path, tmp.path().join(&expected));
        assert!(!resolved.pulled);
        assert_eq!(
            fs::read_to_string(&resolved.rootfs_path).expect("read repaired rootfs"),
            "materialized:docker.io/library/alpine:3.20"
        );
        let index = load_index(tmp.path()).expect("load repaired index");
        let repaired = find_image(&index, "docker.io/library/alpine:3.20")
            .expect("repaired image still indexed");
        assert_eq!(repaired.rootfs_path.as_deref(), Some(expected.as_str()));
        assert_eq!(repaired.runtime_tag.as_deref(), Some(runtime_tag.as_str()));
    }

    #[test]
    fn resolve_run_image_rematerializes_missing_current_rootfs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some(dev_rootfs_rel(tmp.path(), digest));
        image.runtime_tag = Some(oci_runtime_tag(tmp.path()));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        create_unpacked_root(tmp.path(), digest);

        let resolved = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
            &super::super::trust::CosignCommandVerifier,
        )
        .expect("missing current rootfs should be repaired from unpacked layers");

        assert_eq!(
            resolved.rootfs_path,
            tmp.path().join(dev_rootfs_rel(tmp.path(), digest))
        );
        assert!(!resolved.pulled);
        assert_eq!(
            fs::read_to_string(&resolved.rootfs_path).expect("read repaired rootfs"),
            "materialized:docker.io/library/alpine:3.20"
        );
    }

    #[test]
    fn self_heal_restores_the_deferred_nodes_the_pull_recorded() {
        // The self-heal path rebuilds an ext4 from a surviving unpacked
        // tree with no layer tarballs in hand. On a case-folding host that
        // tree is missing every path the host could not hold, so the
        // rebuild has to read them back from the sidecar — otherwise the
        // repaired image is quietly less complete than the one it replaced.
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some(dev_rootfs_rel(tmp.path(), digest));
        image.runtime_tag = Some(oci_runtime_tag(tmp.path()));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        create_unpacked_root(tmp.path(), digest);

        let deferred = vec![mvm_fs::ext4::Node::Symlink {
            path: "/usr/share/man/man7/pam.7.gz".to_string(),
            target: "PAM.7.gz".to_string(),
            owner: mvm_fs::ext4::Owner::ROOT,
        }];
        crate::commands::image::cache::write_deferred_nodes(tmp.path(), digest, &deferred)
            .expect("record deferred nodes");

        let resolved = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
            &super::super::trust::CosignCommandVerifier,
        )
        .expect("repair from unpacked layers");

        let seen: Vec<mvm_fs::ext4::Node> = serde_json::from_slice(
            &fs::read(
                resolved
                    .rootfs_path
                    .parent()
                    .expect("rootfs has parent")
                    .join("deferred-seen.json"),
            )
            .expect("materializer recorded what it was handed"),
        )
        .expect("parse recorded deferred nodes");
        assert_eq!(seen, deferred);
    }

    #[test]
    fn self_heal_restores_the_layer_owners_the_pull_recorded() {
        // The unpacked tree is owned by whoever ran the pull, so the owners
        // the layers declared exist only in the sidecar. A rebuild that
        // skipped it would boot a service's data directory owned by root.
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some(dev_rootfs_rel(tmp.path(), digest));
        image.runtime_tag = Some(oci_runtime_tag(tmp.path()));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        let unpacked = create_unpacked_root(tmp.path(), digest);

        let mut header = tar::Header::new_gnu();
        header.set_path("var/lib/svc/").unwrap();
        header.set_size(0);
        header.set_mode(0o750);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_uid(999);
        header.set_gid(999);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, std::io::empty()).unwrap();
        let report = mvm_fs::oci::unpack::unpack_layer(
            builder.into_inner().unwrap().as_slice(),
            &unpacked,
            &UnpackOptions::default(),
        )
        .expect("unpack");
        let mut owners = mvm_fs::ownership::OwnerTable::new();
        owners.absorb(&report.ownership);
        crate::commands::image::cache::write_layer_owners(tmp.path(), digest, &owners)
            .expect("record layer owners");

        let resolved = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
            &super::super::trust::CosignCommandVerifier,
        )
        .expect("repair from unpacked layers");

        let seen: mvm_fs::ownership::OwnerTable = serde_json::from_slice(
            &fs::read(
                resolved
                    .rootfs_path
                    .parent()
                    .expect("rootfs has parent")
                    .join("owners-seen.json"),
            )
            .expect("materializer recorded what it was handed"),
        )
        .expect("parse recorded owners");
        assert_eq!(seen, owners);
        assert_eq!(
            seen.owner_of("/var/lib/svc"),
            mvm_fs::ext4::Owner::new(999, 999)
        );
    }

    #[test]
    fn a_missing_rootfs_over_a_tree_with_no_recorded_owners_asks_for_repull() {
        let tmp = tempfile::tempdir().expect("tempdir");
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:8888888888888888888888888888888888888888888888888888888888888888";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some(dev_rootfs_rel(tmp.path(), digest));
        image.runtime_tag = Some(oci_runtime_tag(tmp.path()));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        create_unpacked_root(tmp.path(), digest);
        fs::remove_file(
            tmp.path()
                .join("unpacked")
                .join(format!("{}.owners.json", sha256_hex(digest).unwrap())),
        )
        .expect("drop the owner sidecar");

        let err = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
            &super::super::trust::CosignCommandVerifier,
        )
        .expect_err("a tree with no recorded owners must not rebuild the image");
        assert!(
            format!("{err:#}").contains("mvmctl image pull"),
            "error should tell the user to re-pull: {err:#}"
        );
    }

    #[test]
    fn resolve_run_image_missing_rootfs_without_unpacked_layers_asks_for_repull() {
        // The index records a materialized rootfs whose ext4 has vanished AND
        // whose unpacked layer tree is also gone — genuine cache loss. The run
        // fails with an actionable re-pull instruction, not the old bare
        // "rootfs is missing" bail.
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some(dev_rootfs_rel(tmp.path(), digest));
        image.runtime_tag = Some(oci_runtime_tag(tmp.path()));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        // Deliberately write neither the rootfs.ext4 nor the unpacked tree.

        let err = resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", false)
            .expect_err("missing rootfs with no unpacked layers must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("mvmctl image pull"),
            "error should tell the user to re-pull: {msg}"
        );
        assert!(
            msg.contains("unpacked"),
            "error should explain the unpacked layers are gone: {msg}"
        );
    }

    #[cfg(feature = "pure-mkfs")]
    #[test]
    fn resolve_run_image_reseals_cached_rootfs_when_verity_sidecars_are_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Seed before reading the tag: the runtime tag is derived from the
        // guest artifacts, so a tag taken before seeding is the cold-cache
        // placeholder and would not match the one the resolve path computes.
        seed_guest_runtime_cache(tmp.path());
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some(dev_rootfs_rel(tmp.path(), digest));
        image.runtime_tag = Some(oci_runtime_tag(tmp.path()));
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        let rel = dev_rootfs_rel(tmp.path(), digest);
        write_file(tmp.path(), &rel, b"stale-rootfs");
        let unpacked = tmp
            .path()
            .join("unpacked")
            .join(sha256_hex(digest).expect("hex digest key"));
        std::fs::create_dir_all(unpacked.join("etc")).expect("create unpacked tree");
        std::fs::write(unpacked.join("etc/hostname"), b"box\n").expect("write unpacked file");
        crate::commands::image::cache::write_layer_owners(
            tmp.path(),
            digest,
            &mvm_fs::ownership::OwnerTable::new(),
        )
        .expect("record layer owners");

        let resolved =
            resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", false)
                .expect("stale verity-free cached rootfs must be re-sealed");

        assert!(resolved.rootfs_path.ends_with(&rel));
        assert!(resolved.rootfs_path.is_file());
        assert!(
            resolved
                .rootfs_path
                .parent()
                .unwrap()
                .join("rootfs.verity")
                .is_file()
        );
        assert!(
            resolved
                .rootfs_path
                .parent()
                .unwrap()
                .join("rootfs.roothash")
                .is_file()
        );
    }

    #[test]
    fn manifest_config_descriptor_extracts_config_blob() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest,
                "size": 17,
            },
            "layers": [],
        });
        let descriptor =
            manifest_config_descriptor(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        let descriptor = descriptor.expect("config descriptor");
        assert_eq!(descriptor.digest, digest);
        assert_eq!(descriptor.size, 17);
    }

    /// Which layers are gzip-compressed decides how each one is unpacked,
    /// and nothing asserted it — a constant in either direction survived,
    /// as did collapsing the three-way disjunction.
    ///
    /// Both directions matter: pinned to `true` every uncompressed layer
    /// is fed through a gzip reader, pinned to `false` every compressed
    /// one is unpacked as raw tar. Either way the rootfs the provenance
    /// record describes is not the rootfs that boots.
    #[test]
    fn gzip_layers_are_recognised_by_media_type() {
        // Each disjunct on its own, so none can be dropped unnoticed.
        assert!(is_gzip_layer("application/vnd.oci.image.layer.v1.tar+gzip"));
        assert!(is_gzip_layer("application/vnd.example.layer.gzip"));
        assert!(is_gzip_layer("application/vnd.example.tar.gzip.v2"));

        // Uncompressed and unrelated media types are not gzip.
        assert!(!is_gzip_layer("application/vnd.oci.image.layer.v1.tar"));
        assert!(!is_gzip_layer(
            "application/vnd.docker.image.rootfs.diff.tar"
        ));
        assert!(!is_gzip_layer("application/vnd.oci.image.config.v1+json"));
        assert!(!is_gzip_layer("application/vnd.example.layer+zstd"));
        assert!(!is_gzip_layer(""));
    }
}
