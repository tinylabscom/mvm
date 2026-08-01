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
    ImageReference, LayerDescriptor, LayerFetchOptions, LinuxPlatform, OciLayerFetcher,
    OciManifestFetcher, UnpackOptions, UnpackReport, unpack_layer_with_prior_paths,
};

use super::cache::{find_image, layer_blob_path, load_index, read_verified_cache_file, save_index};
use super::cache::{safe_cache_path, sha256_hex, unpacked_dir_if_present, upsert_image};
use super::materialize::{
    RuntimeMaterializer, cached_rootfs_is_current, ensure_rootfs_verity_sidecars,
    inject_runtime_and_materialize, oci_entrypoint_from_cache_path, oci_runtime_tag,
    prepare_rootfs_only_tree, rematerialize_cached_image, rootfs_verity_sidecars_present,
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
        if !image_ref.is_digest_pinned() {
            bail!("mvmctl run --image --prod requires a digest-pinned reference");
        }
    }
    Ok(())
}

pub(in crate::commands) fn resolve_or_pull_run_image(
    cache_root: &Path,
    reference: &str,
    prod: bool,
) -> Result<ResolvedOciRunImage> {
    resolve_or_pull_run_image_with(
        cache_root,
        reference,
        prod,
        super::materialize::inject_runtime_and_materialize,
    )
}

pub(super) fn resolve_or_pull_run_image_with(
    cache_root: &Path,
    reference: &str,
    prod: bool,
    materialize: RuntimeMaterializer,
) -> Result<ResolvedOciRunImage> {
    // Rootfs materialization can fall back to a builder VM when the in-process
    // ext4 writer cannot faithfully emit a tree. `mvmctl image pull` reaps
    // previous helper processes at startup; the run-image path is the other
    // place a builder VM can spawn, so give it the same sweep before we might add one.
    crate::commands::env::builder_vm::sweep_orphaned_vm_helpers_on_startup();

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
    let runtime_tag = oci_runtime_tag();
    let (image, pulled, trust_from_pull, auth_source_from_pull) = match load_index(cache_root)
        .ok()
        .and_then(|index| find_image(&index, &canonical).cloned())
    {
        Some(cached) if cached_rootfs_is_current(&cached, &runtime_tag) => {
            (cached, false, None, None)
        }
        Some(cached) => {
            match rematerialize_cached_image(cache_root, cached, &runtime_tag, materialize, prod)? {
                Some(repaired) => (repaired, false, None, None),
                None => {
                    let (cached, trust, auth_source) =
                        pull_image_ref(cache_root, image_ref.clone(), reference, prod)?;
                    (cached, true, Some(trust), Some(auth_source))
                }
            }
        }
        _ => {
            let (cached, trust, auth_source) =
                pull_image_ref(cache_root, image_ref.clone(), reference, prod)?;
            (cached, true, Some(trust), Some(auth_source))
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
    if !rootfs_path.is_file() || !rootfs_verity_sidecars_present(&rootfs_path) {
        // Self-heal a cache whose index still records a materialized rootfs but
        // whose sealed block-root artifacts have since drifted. That covers a
        // vanished `rootfs.ext4` (interrupted prune / manual delete) and older
        // ext4-only cache entries that predate the current verity-backed OCI
        // materializer. If the unpacked layer tree survives, re-run the same
        // seal `image pull` performs — network-free, from the cached layers —
        // rather than failing the run. Only when the unpacked tree is gone too
        // is this a genuine cache loss the user must re-pull.
        match unpacked_dir_if_present(cache_root, &image.resolved_digest) {
            Some(unpacked_root) => {
                materialize(
                    cache_root,
                    &unpacked_root,
                    &rootfs_path,
                    &image.reference,
                    oci_entrypoint_from_cache_path(cache_root, image.config_path.as_deref())?
                        .as_ref(),
                    prod,
                    super::cache::read_deferred_nodes(cache_root, &image.resolved_digest)?,
                )
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
    let trust = match trust_from_pull {
        Some(trust) => trust,
        None => trust_decision_for_cached_image(&image_ref, &image, prod, &CosignCommandVerifier)?,
    };
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
    let image_ref: ImageReference = reference.parse()?;
    if prod && !image_ref.is_digest_pinned() {
        bail!("mvmctl image pull --prod requires a digest-pinned reference");
    }
    pull_image_ref(cache_root, image_ref, reference, prod)
}

fn pull_image_ref(
    cache_root: &Path,
    image_ref: ImageReference,
    supplied_reference: &str,
    prod: bool,
) -> Result<(CachedOciImage, OciTrustDecision, String)> {
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
            manifest_fetcher
                .fetch_linux_platform_manifest(&image_ref, &LinuxPlatform::for_current_arch()),
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
    if unpacked_root.exists() {
        fs::remove_dir_all(&unpacked_root)
            .with_context(|| format!("remove stale unpacked root {}", unpacked_root.display()))?;
    }
    fs::create_dir_all(&unpacked_root)
        .with_context(|| format!("create {}", unpacked_root.display()))?;

    let mut cached_layers = Vec::with_capacity(layers.len());
    let mut prior_layer_paths = std::collections::HashSet::new();
    let mut deferred_nodes = Vec::new();
    for layer in &layers {
        let compressed =
            fetch_or_read_layer(cache_root, &runtime, &layer_fetcher, &image_ref, layer)
                .with_context(|| format!("fetch layer {}", layer.digest))?;
        let report = unpack_layer_bytes(layer, &compressed, &unpacked_root, &prior_layer_paths)
            .with_context(|| format!("unpack layer {}", layer.digest))?;
        prior_layer_paths.extend(report.paths_written);
        deferred_nodes.extend(report.deferred_nodes);
        cached_layers.push(CachedOciLayer {
            digest: layer.digest.clone(),
            size_bytes: layer.size,
            path: Some(layer_blob_path(&layer.digest)?),
        });
    }

    let runtime_tag = oci_runtime_tag();
    let rootfs_path = format!("rootfs/{manifest_hex}-{runtime_tag}/rootfs.ext4");
    let rootfs_abs = cache_root.join(&rootfs_path);
    super::cache::write_deferred_nodes(cache_root, &manifest.digest, &deferred_nodes)?;
    inject_runtime_and_materialize(
        cache_root,
        &unpacked_root,
        &rootfs_abs,
        &image_ref.canonical(),
        None,
        false,
        deferred_nodes,
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

    let mut index = load_index(cache_root)?;
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
    upsert_image(&mut index, cached.clone());
    save_index(cache_root, &index)?;
    Ok((cached, trust, registry_auth.source))
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

fn fetch_or_read_layer(
    cache_root: &Path,
    runtime: &tokio::runtime::Runtime,
    fetcher: &OciLayerFetcher,
    image_ref: &ImageReference,
    layer: &LayerDescriptor,
) -> Result<Vec<u8>> {
    let path = layer_blob_path(&layer.digest)?;
    if let Some(bytes) = read_verified_cache_file(cache_root, &path, &layer.digest)? {
        return Ok(bytes);
    }
    let mut bytes = Vec::new();
    runtime.block_on(fetcher.fetch_layer(image_ref, layer, &mut bytes))?;
    super::cache::write_cache_file(cache_root, &path, &bytes)?;
    Ok(bytes)
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
    use mvm_build::oci_runtime_inject::OciEntrypointConfig;

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
        unpacked
    }

    fn seed_guest_runtime_cache(cache_root: &Path) {
        use mvm_build::guest_agent_build::GuestAgentLayout;
        use mvm_core::arch::GuestArch;

        let guest_layout =
            GuestAgentLayout::under(cache_root, env!("CARGO_PKG_VERSION"), GuestArch::host());
        std::fs::create_dir_all(&guest_layout.dir).expect("create guest cache dir");
        for path in [
            &guest_layout.oci_init,
            &guest_layout.agent,
            &guest_layout.netinit,
            &guest_layout.egress_client,
            &guest_layout.entrypoint_runner,
            &guest_layout.verity_init,
        ] {
            std::fs::write(path, b"#!/bin/sh\nexit 0\n").expect("seed guest runtime cache");
        }
    }

    fn fake_runtime_materialize(
        _cache_root: &Path,
        unpacked_root: &Path,
        rootfs_abs: &Path,
        image_label: &str,
        _entrypoint: Option<&OciEntrypointConfig>,
        _sealed: bool,
        deferred_nodes: Vec<mvm_fs::ext4::Node>,
    ) -> Result<()> {
        assert!(unpacked_root.is_dir(), "unpacked root must exist");
        let parent = rootfs_abs.parent().expect("rootfs has parent");
        fs::create_dir_all(parent)?;
        fs::write(rootfs_abs, format!("materialized:{image_label}"))?;
        fs::write(parent.join("rootfs.verity"), b"fake-verity")?;
        fs::write(parent.join("rootfs.roothash"), b"abc\n")?;
        // A fn pointer can't capture, so the deferred set the materializer
        // was handed is recorded on disk for the caller to assert on.
        fs::write(
            parent.join("deferred-seen.json"),
            serde_json::to_vec(&deferred_nodes)?,
        )?;
        Ok(())
    }

    #[test]
    fn prod_pull_requires_digest_pin_before_network() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = pull_image_with_trust(tmp.path(), "docker.io/library/alpine:3.20", true)
            .expect_err("mutable prod pull must fail before registry access");
        assert!(
            err.to_string()
                .contains("requires a digest-pinned reference"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prod_run_image_requires_digest_pin_before_network() {
        let tmp = tempfile::tempdir().expect("tempdir");
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
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some("rootfs/alpine/rootfs.ext4".to_string());
        image.runtime_tag = Some(oci_runtime_tag());
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_file(tmp.path(), "rootfs/alpine/rootfs.ext4", b"rootfs");
        write_file(tmp.path(), "rootfs/alpine/rootfs.verity", b"verity");
        write_file(
            tmp.path(),
            "rootfs/alpine/rootfs.roothash",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        );

        let resolved =
            resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", false)
                .expect("cached rootfs resolves");

        assert_eq!(resolved.reference, "docker.io/library/alpine:3.20");
        assert_eq!(resolved.resolved_digest, digest);
        assert!(resolved.rootfs_path.ends_with("rootfs/alpine/rootfs.ext4"));
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
        seed_guest_runtime_cache(tmp.path());

        let resolved = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
        )
        .expect("stale cached image should be repaired from unpacked layers");

        let runtime_tag = oci_runtime_tag();
        let expected = format!(
            "rootfs/{}-{runtime_tag}/rootfs.ext4",
            sha256_hex(digest).unwrap()
        );
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
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some("rootfs/alpine/rootfs.ext4".to_string());
        image.runtime_tag = Some(oci_runtime_tag());
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        create_unpacked_root(tmp.path(), digest);
        seed_guest_runtime_cache(tmp.path());

        let resolved = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
        )
        .expect("missing current rootfs should be repaired from unpacked layers");

        assert_eq!(
            resolved.rootfs_path,
            tmp.path().join("rootfs/alpine/rootfs.ext4")
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
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some("rootfs/alpine-deferred/rootfs.ext4".to_string());
        image.runtime_tag = Some(oci_runtime_tag());
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        create_unpacked_root(tmp.path(), digest);
        seed_guest_runtime_cache(tmp.path());

        let deferred = vec![mvm_fs::ext4::Node::Symlink {
            path: "/usr/share/man/man7/pam.7.gz".to_string(),
            target: "PAM.7.gz".to_string(),
        }];
        crate::commands::image::cache::write_deferred_nodes(tmp.path(), digest, &deferred)
            .expect("record deferred nodes");

        let resolved = resolve_or_pull_run_image_with(
            tmp.path(),
            "docker.io/library/alpine:3.20",
            false,
            fake_runtime_materialize,
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
    fn resolve_run_image_missing_rootfs_without_unpacked_layers_asks_for_repull() {
        // The index records a materialized rootfs whose ext4 has vanished AND
        // whose unpacked layer tree is also gone — genuine cache loss. The run
        // fails with an actionable re-pull instruction, not the old bare
        // "rootfs is missing" bail.
        let tmp = tempfile::tempdir().expect("tempdir");
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some("rootfs/alpine/rootfs.ext4".to_string());
        image.runtime_tag = Some(oci_runtime_tag());
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
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut image = sample_image("docker.io/library/alpine:3.20", digest, "blobs/a");
        image.rootfs_path = Some("rootfs/alpine/rootfs.ext4".to_string());
        image.runtime_tag = Some(oci_runtime_tag());
        write_index(
            tmp.path(),
            &OciCacheIndex {
                schema_version: 1,
                images: vec![image],
            },
        );
        write_minimal_config(tmp.path());
        write_file(tmp.path(), "rootfs/alpine/rootfs.ext4", b"stale-rootfs");
        let unpacked = tmp
            .path()
            .join("unpacked")
            .join(sha256_hex(digest).expect("hex digest key"));
        std::fs::create_dir_all(unpacked.join("etc")).expect("create unpacked tree");
        std::fs::write(unpacked.join("etc/hostname"), b"box\n").expect("write unpacked file");
        seed_guest_runtime_cache(tmp.path());

        let resolved =
            resolve_or_pull_run_image(tmp.path(), "docker.io/library/alpine:3.20", false)
                .expect("stale verity-free cached rootfs must be re-sealed");

        assert!(resolved.rootfs_path.ends_with("rootfs/alpine/rootfs.ext4"));
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
}
