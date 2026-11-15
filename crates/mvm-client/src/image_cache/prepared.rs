use std::path::{Component, Path, PathBuf};

use mvm_core::prepared_image::{
    PreparedImageError, PreparedImageErrorKind as Kind, PreparedImageTrust, PreparedOciSelection,
};
use mvm_fs::oci::{ImageReference, current_linux_platform};

use super::{cache, materialize, oci_types, pull_core, source::ImageSource};

/// Resolution context, separate from resource and permission profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedImageContext {
    /// Explicit backend; the launch must use exactly this backend.
    pub backend: String,
}

pub(crate) struct ValidatedPrepared {
    pub selection: PreparedOciSelection,
    pub image: oci_types::ResolvedOciRunImage,
    // Serialize cooperating cache publishers/pruners through admission.
    _output: mvm_core::util::atomic_io::FileLock,
}

fn refusal(reference: &str, kind: Kind, detail: impl std::fmt::Display) -> PreparedImageError {
    PreparedImageError {
        kind,
        reference: reference.to_string(),
        detail: detail.to_string(),
    }
}

/// Inspect prepared bytes without acquisition or machine lifecycle effects.
pub fn select(
    reference: &str,
    context: &PreparedImageContext,
) -> Result<PreparedOciSelection, PreparedImageError> {
    resolve(reference, context).map(|resolved| resolved.selection)
}

pub(crate) fn revalidate(
    expected: &PreparedOciSelection,
    backend: &str,
    profile: &str,
) -> Result<ValidatedPrepared, PreparedImageError> {
    validate_profile(profile, &expected.canonical_reference)?;
    require_backend(expected, backend, backend)?;
    let actual = resolve(
        &expected.canonical_reference,
        &PreparedImageContext {
            backend: backend.to_string(),
        },
    )?;
    if actual.selection != *expected {
        return Err(refusal(
            &expected.canonical_reference,
            Kind::SelectionChanged,
            "prepared selection changed; inspect and explicitly select the current preparation",
        ));
    }
    Ok(actual)
}

pub(crate) fn require_backend(
    expected: &PreparedOciSelection,
    requested: &str,
    actual: &str,
) -> Result<(), PreparedImageError> {
    if expected.backend != requested || requested != actual {
        return Err(refusal(
            &expected.canonical_reference,
            Kind::UnsupportedMode,
            "prepared selection, requested backend and actual driver must match without fallback",
        ));
    }
    Ok(())
}

pub(crate) fn validate_profile(profile: &str, reference: &str) -> Result<(), PreparedImageError> {
    if crate::profile::RunProfile::from_name(profile).is_none() {
        return Err(refusal(
            reference,
            Kind::UnsupportedMode,
            "prepared OCI reuse supports development artifacts and existing resource profiles only",
        ));
    }
    Ok(())
}

pub(crate) fn cached_kernel(
    selection: &PreparedOciSelection,
    backend: &str,
) -> Result<Option<String>, PreparedImageError> {
    crate::launch::machine_start::cached_workload_kernel(backend)
        .map_err(|error| refusal(&selection.canonical_reference, Kind::MissingKernel, error))
}

fn resolve(
    reference: &str,
    context: &PreparedImageContext,
) -> Result<ValidatedPrepared, PreparedImageError> {
    resolve_with_observer(reference, context, || {})
}

fn resolve_with_observer(
    reference: &str,
    context: &PreparedImageContext,
    after_metadata_validation: impl FnOnce(),
) -> Result<ValidatedPrepared, PreparedImageError> {
    if !matches!(
        ImageSource::classify(reference),
        Ok(ImageSource::Registry(_))
    ) || reference.starts_with('/')
        || reference.starts_with('.')
        || reference.starts_with("path:")
    {
        return Err(refusal(
            reference,
            Kind::UnsupportedMode,
            "only registry OCI references support prepared selection",
        ));
    }
    let image_ref: ImageReference = reference
        .parse()
        .map_err(|error| refusal(reference, Kind::UnsupportedMode, error))?;
    if !matches!(
        context.backend.as_str(),
        "firecracker" | "libkrun" | "hvf" | "apple-container" | "qemu"
    ) {
        return Err(refusal(
            reference,
            Kind::UnsupportedMode,
            "backend does not support prepared OCI reuse",
        ));
    }
    let cache_root = mvm_core::config::oci_cache_dir();
    if cache_root.join(oci_types::INDEX_FILE).exists() {
        regular_cache_file(&cache_root, oci_types::INDEX_FILE)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    }
    let index = cache::load_index(&cache_root)
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    let image = cache::find_image(&index, &image_ref.canonical()).ok_or_else(|| {
        refusal(
            reference,
            Kind::NotPrepared,
            "run `mvmctl image pull` explicitly first",
        )
    })?;
    for relative in [
        &image.manifest_path,
        image.config_path.as_deref().unwrap_or(""),
    ] {
        regular_cache_file(&cache_root, relative)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    }
    let manifest =
        cache::read_verified_cache_file(&cache_root, &image.manifest_path, &image.resolved_digest)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?
            .ok_or_else(|| {
                refusal(
                    reference,
                    Kind::CorruptPreparation,
                    "prepared manifest disappeared",
                )
            })?;
    let manifest: mvm_contract::oci::manifest_types::ImageManifest =
        serde_json::from_slice(&manifest)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    let layer_digests: Vec<String> = manifest
        .layers
        .iter()
        .map(|layer| layer.digest.clone())
        .collect();
    if layer_digests
        != image
            .layers
            .iter()
            .map(|layer| layer.digest.clone())
            .collect::<Vec<_>>()
    {
        return Err(refusal(
            reference,
            Kind::CorruptPreparation,
            "cached layer provenance disagrees with the digest-bound manifest",
        ));
    }
    let config_path = image.config_path.as_deref().ok_or_else(|| {
        refusal(
            reference,
            Kind::CorruptPreparation,
            "missing digest-bound OCI configuration",
        )
    })?;
    let config = cache::read_verified_cache_file(&cache_root, config_path, &manifest.config.digest)
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?
        .ok_or_else(|| {
            refusal(
                reference,
                Kind::CorruptPreparation,
                "prepared config disappeared",
            )
        })?;
    mvm_fs::oci::config::OciImageConfig::parse(&config)
        .and_then(|config| config.validate_platform(&current_linux_platform()))
        .map_err(|error| refusal(reference, Kind::PlatformMismatch, error))?;
    crate::launch::runtime_overlay::require_prepared_oci_guest_runtime(&cache_root)
        .map_err(|error| refusal(reference, Kind::RuntimeUnavailable, error))?;
    let runtime_identity = mvm_build::run_image::resolve_guest_runtime_identity(&cache_root)
        .map_err(|error| refusal(reference, Kind::RuntimeUnavailable, error))?;
    require_identified_runtime(reference, &runtime_identity)?;
    let runtime_tag = materialize::oci_runtime_tag(&cache_root);
    let current = materialize::cached_rootfs_is_current(image, &runtime_tag, false);
    let rootfs_relative = materialize::oci_rootfs_rel(&image.resolved_digest, &runtime_tag, false)
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    let rootfs = cache_root.join(&rootfs_relative);
    if !rootfs.exists() {
        return Err(refusal(
            reference,
            if current {
                Kind::CorruptPreparation
            } else {
                Kind::RuntimeMismatch
            },
            "no complete development rootfs prepared for this guest runtime; run `mvmctl image pull` explicitly",
        ));
    }
    for path in [
        &rootfs,
        &rootfs.with_extension("verity"),
        &rootfs.with_extension("roothash"),
        &rootfs
            .parent()
            .ok_or_else(|| refusal(reference, Kind::CorruptPreparation, "rootfs has no parent"))?
            .join(mvm_build::builder_vm::SIDECAR_FILENAME),
    ] {
        let relative = path
            .strip_prefix(&cache_root)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
        regular_cache_file(&cache_root, &relative.to_string_lossy())
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    }
    let verified_digest = image.resolved_digest.clone();
    let verified_reference = image.reference.clone();
    after_metadata_validation();
    let image =
        pull_core::resolve_or_pull_run_image(&cache_root, reference, false).map_err(|error| {
            refusal(
                reference,
                if current {
                    Kind::CorruptPreparation
                } else {
                    Kind::RuntimeMismatch
                },
                error,
            )
        })?;
    if image.resolved_digest != verified_digest
        || image.reference != verified_reference
        || image.rootfs_path != rootfs
        || image.provenance.layer_digests != layer_digests
    {
        return Err(refusal(
            reference,
            Kind::SelectionChanged,
            "prepared cache identity changed during resolution; select again explicitly",
        ));
    }
    let relative = image
        .rootfs_path
        .strip_prefix(&cache_root)
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    regular_cache_file(&cache_root, &relative.to_string_lossy())
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    let output = mvm_build::run_image::lock_rootfs_output(&image.rootfs_path)
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    if !mvm_build::run_image::published_build_matches(&image.rootfs_path, false) {
        return Err(refusal(
            reference,
            Kind::CorruptPreparation,
            "prepared development publication is incomplete or has the wrong variant",
        ));
    }
    let parent = image.rootfs_path.parent().ok_or_else(|| {
        refusal(
            reference,
            Kind::CorruptPreparation,
            "prepared rootfs has no parent",
        )
    })?;
    let hash = |name: &str| -> Result<String, PreparedImageError> {
        let path = parent.join(name);
        let relative = path
            .strip_prefix(&cache_root)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
        regular_cache_file(&cache_root, &relative.to_string_lossy())
            .and_then(|path| mvm_core::crypto::image_verify::sha256_file(&path).map_err(Into::into))
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))
    };
    let roothash = std::fs::read_to_string(parent.join("rootfs.roothash"))
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    let roothash = roothash.trim();
    if roothash.len() != 64 || !roothash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refusal(
            reference,
            Kind::CorruptPreparation,
            "malformed prepared verity root hash",
        ));
    }
    regular_cache_file(
        &cache_root,
        &parent
            .join(mvm_build::builder_vm::SIDECAR_FILENAME)
            .strip_prefix(&cache_root)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?
            .to_string_lossy(),
    )
    .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?;
    let mut sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(parent)
        .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?
        .ok_or_else(|| {
            refusal(
                reference,
                Kind::CorruptPreparation,
                "prepared sidecar disappeared",
            )
        })?;
    sidecar.built_at.clear();
    use sha2::Digest;
    let sidecar_sha256 = hex::encode(sha2::Sha256::digest(
        serde_jcs::to_vec(&sidecar)
            .map_err(|error| refusal(reference, Kind::CorruptPreparation, error))?,
    ));
    let platform = current_linux_platform();
    let platform = match platform.variant {
        Some(variant) => format!("linux/{}/{variant}", platform.architecture),
        None => format!("linux/{}", platform.architecture),
    };
    let selection = PreparedOciSelection {
        canonical_reference: image_ref.canonical(),
        manifest_digest: image.resolved_digest.clone(),
        rootfs_sha256: hash("rootfs.ext4")?,
        verity_sha256: hash("rootfs.verity")?,
        roothash: roothash.to_string(),
        guest_sidecar_sha256: sidecar_sha256,
        runtime_identity,
        platform,
        backend: context.backend.clone(),
        layer_digests,
        trust: PreparedImageTrust::DevelopmentDigestOnly,
    };
    Ok(ValidatedPrepared {
        selection,
        image,
        _output: output,
    })
}

fn require_identified_runtime(reference: &str, identity: &str) -> Result<(), PreparedImageError> {
    if identity.is_empty() || identity.starts_with("pending-") || identity == "unidentified" {
        return Err(refusal(
            reference,
            Kind::RuntimeUnavailable,
            "prepared guest runtime has no measured identity; run `mvmctl bootstrap` explicitly",
        ));
    }
    Ok(())
}

fn regular_cache_file(root: &Path, relative: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(!relative.is_empty(), "empty prepared cache path");
    let path = cache::safe_cache_path(root, relative)?;
    let mut cursor = root.to_path_buf();
    for component in Path::new(relative).components() {
        anyhow::ensure!(
            matches!(component, Component::Normal(_)),
            "non-canonical prepared cache path"
        );
        cursor.push(component);
        let metadata = std::fs::symlink_metadata(&cursor)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "prepared cache path contains a symlink"
        );
    }
    anyhow::ensure!(
        std::fs::symlink_metadata(&path)?.file_type().is_file(),
        "prepared artifact is not a regular file"
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::super::oci_types::{CachedOciImage, CachedOciLayer, OciCacheIndex};
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use sha2::{Digest, Sha256};
    use std::fs;

    const REFERENCE: &str = "docker.io/library/alpine:3.20";

    struct Fixture {
        _env: TestEnv,
        _home: tempfile::TempDir,
        cache: PathBuf,
        rootfs: PathBuf,
        context: PreparedImageContext,
    }

    fn write(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    }

    fn fixture() -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.remove("MVM_DIRECT_BOOT");
        let cache = mvm_core::config::oci_cache_dir();
        super::super::pull_core::tests::seed_guest_runtime_cache(&cache);
        let config = serde_json::to_vec(&serde_json::json!({
            "os": "linux", "architecture": current_linux_platform().architecture, "config": {},
        }))
        .unwrap();
        let config_digest = digest(&config);
        let layer_digest = format!("sha256:{}", "a".repeat(64));
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config.len(),
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest,
                "size": 4096,
            }],
        }))
        .unwrap();
        let manifest_digest = digest(&manifest);
        write(&cache, "manifests/fixture.json", &manifest);
        write(&cache, "configs/fixture.json", &config);
        let runtime_tag = materialize::oci_runtime_tag(&cache);
        let relative = materialize::oci_rootfs_rel(&manifest_digest, &runtime_tag, false).unwrap();
        let unpacked = cache
            .join("unpacked")
            .join(cache::sha256_hex(&manifest_digest).unwrap());
        fs::create_dir_all(&unpacked).unwrap();
        cache::write_layer_owners(
            &cache,
            &manifest_digest,
            &mvm_fs::ownership::OwnerTable::new(),
        )
        .unwrap();
        cache::write_deferred_nodes(&cache, &manifest_digest, &[]).unwrap();
        fs::create_dir_all(materialize::prepared_virtiofs_root(
            &cache,
            &manifest_digest,
            &runtime_tag,
        ))
        .unwrap();
        write(
            &cache,
            &relative,
            b"synthetic prepared fixture, not a boot witness",
        );
        let rootfs = cache.join(&relative);
        let parent = rootfs.parent().unwrap();
        fs::write(parent.join("rootfs.verity"), b"synthetic-verity").unwrap();
        fs::write(
            parent.join("rootfs.roothash"),
            format!("{}\n", "0".repeat(64)),
        )
        .unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run(REFERENCE, false, true)
            .write_to_dir(parent)
            .unwrap();
        cache::save_index(
            &cache,
            &OciCacheIndex {
                schema_version: 1,
                images: vec![CachedOciImage {
                    reference: REFERENCE.into(),
                    registry: "docker.io".into(),
                    repository: "library/alpine".into(),
                    tag: Some("3.20".into()),
                    resolved_digest: manifest_digest,
                    fetched_at: "2026-05-18T00:00:00Z".into(),
                    manifest_path: "manifests/fixture.json".into(),
                    config_path: Some("configs/fixture.json".into()),
                    rootfs_path: Some(relative),
                    runtime_tag: Some(runtime_tag),
                    claims_path: None,
                    verification_receipt_path: None,
                    layers: vec![CachedOciLayer {
                        digest: layer_digest,
                        size_bytes: 4096,
                        path: None,
                    }],
                }],
            },
        )
        .unwrap();
        Fixture {
            _env: env,
            _home: home,
            cache,
            rootfs,
            context: PreparedImageContext {
                backend: crate::auto_selected_backend_name(),
            },
        }
    }

    #[test]
    fn cli_and_client_share_manifest_runtime_and_development_provenance() {
        let fixture = fixture();
        let cli = crate::image_cache::resolve_prepared(&fixture.cache, REFERENCE, false).unwrap();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        assert_eq!(selected.canonical_reference, cli.reference);
        assert_eq!(selected.manifest_digest, cli.resolved_digest);
        assert_eq!(selected.layer_digests, cli.provenance.layer_digests);
        assert_eq!(
            selected.rootfs_sha256,
            mvm_core::crypto::image_verify::sha256_file(&cli.rootfs_path).unwrap()
        );
        assert_ne!(
            selected.manifest_digest,
            format!("sha256:{}", selected.rootfs_sha256)
        );
        assert_eq!(selected.trust, PreparedImageTrust::DevelopmentDigestOnly);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(selected.platform, "linux/arm64/v8");
        #[cfg(target_arch = "x86_64")]
        assert_eq!(selected.platform, "linux/amd64");
        assert_eq!(
            selected.audit_labels()["oci_verification_status"],
            cli.provenance.verification_status
        );
        let restored: PreparedOciSelection =
            serde_json::from_slice(&serde_json::to_vec(&selected).unwrap()).unwrap();
        assert_eq!(selected, restored);
        revalidate(&restored, &fixture.context.backend, "standard").unwrap();
    }

    #[test]
    fn existing_variant_adoption_is_bookkeeping_not_acquisition() {
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let mut index = cache::load_index(&fixture.cache).unwrap();
        index.images[0].runtime_tag = Some("another-runtime".into());
        index.images[0].rootfs_path = Some("rootfs/another-runtime/rootfs.ext4".into());
        cache::save_index(&fixture.cache, &index).unwrap();
        assert_eq!(select(REFERENCE, &fixture.context).unwrap(), selected);
        assert_eq!(
            cache::load_index(&fixture.cache).unwrap().images[0]
                .rootfs_path
                .as_deref(),
            Some(
                fixture
                    .rootfs
                    .strip_prefix(&fixture.cache)
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
    }

    #[test]
    fn selection_drift_refuses_bytes_sidecars_and_backend_changes() {
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        fs::write(&fixture.rootfs, b"changed fixture bytes").unwrap();
        assert_eq!(
            revalidate(&selected, &fixture.context.backend, "standard")
                .err()
                .unwrap()
                .kind,
            Kind::SelectionChanged
        );
        assert_eq!(
            revalidate(&selected, "wasm", "standard")
                .err()
                .unwrap()
                .kind,
            Kind::UnsupportedMode
        );
        assert_eq!(
            revalidate(&selected, &fixture.context.backend, "prod")
                .err()
                .unwrap()
                .kind,
            Kind::UnsupportedMode
        );
    }

    #[test]
    fn missing_runtime_and_kernel_have_independent_typed_remedies() {
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let error = cached_kernel(&selected, &fixture.context.backend).unwrap_err();
        assert_eq!(error.kind, Kind::MissingKernel);
        assert_eq!(
            error.remedy(),
            mvm_core::prepared_image::PreparedImageRemedy::Bootstrap
        );
        let source = mvm_build::guest_agent_build::guest_binary_source().unwrap();
        for key in std::collections::BTreeSet::from([source.cache_key(), env!("CARGO_PKG_VERSION")])
        {
            let layout = mvm_build::guest_agent_build::GuestAgentLayout::under(
                &fixture.cache,
                key,
                mvm_core::arch::GuestArch::host(),
            );
            fs::remove_file(layout.agent).unwrap();
        }
        assert_eq!(
            select(REFERENCE, &fixture.context).unwrap_err().kind,
            Kind::RuntimeUnavailable
        );
    }

    #[test]
    fn malformed_metadata_paths_and_incomplete_publication_refuse_without_repair() {
        let fixture = fixture();
        let original = cache::load_index(&fixture.cache).unwrap();
        for path in ["../outside.json", "/outside.json", ""] {
            let mut index = original.clone();
            index.images[0].manifest_path = path.into();
            cache::save_index(&fixture.cache, &index).unwrap();
            assert_eq!(
                select(REFERENCE, &fixture.context).unwrap_err().kind,
                Kind::CorruptPreparation
            );
        }
        cache::save_index(&fixture.cache, &original).unwrap();
        let sidecar = fixture
            .rootfs
            .parent()
            .unwrap()
            .join(mvm_build::builder_vm::SIDECAR_FILENAME);
        fs::remove_file(&sidecar).unwrap();
        assert_eq!(
            select(REFERENCE, &fixture.context).unwrap_err().kind,
            Kind::CorruptPreparation
        );
        assert!(!sidecar.exists());
    }

    #[test]
    fn tampered_digest_bound_metadata_is_not_a_prepared_selection() {
        let fixture = fixture();
        fs::write(fixture.cache.join("configs/fixture.json"), b"tampered").unwrap();
        assert_eq!(
            select(REFERENCE, &fixture.context).unwrap_err().kind,
            Kind::CorruptPreparation
        );
    }

    #[test]
    fn persisted_selection_has_no_legacy_fallback_and_rejects_ambiguity() {
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let request = crate::LaunchRequest::builder_for(
            crate::LifecycleMode::Persistent,
            crate::LaunchSource::PreparedImage {
                selection: selected.clone(),
            },
        )
        .name("prepared-fixture")
        .build()
        .unwrap();
        let spec = crate::launch::persisted_spec_from_request(&request, "prepared-fixture");
        let bytes = serde_json::to_vec(&spec).unwrap();
        let restored: mvm_runtime::machine::persist::MachineSpec =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.prepared_image, Some(selected));
        assert!(restored.image.is_none());
        assert!(restored.manifest.is_none());
        let legacy_error =
            serde_json::from_slice::<super::super::legacy_machine_spec::MachineSpec>(&bytes)
                .unwrap_err();
        assert!(
            legacy_error
                .to_string()
                .contains("unknown field `prepared_image`")
        );
        mvm_runtime::machine::persist::save_machine_spec(&spec, false).unwrap();
        assert_eq!(
            mvm_runtime::machine::persist::load_machine_spec(&spec.name).unwrap(),
            spec
        );
        for field in ["image", "manifest", "deployment", "registry_pack_image"] {
            let mut ambiguous = serde_json::to_value(&spec).unwrap();
            ambiguous[field] = if field == "registry_pack_image" {
                serde_json::to_value(
                    mvm_core::registry_pack::PackPin::new(
                        "runtime/python@1.1.0".parse().unwrap(),
                        mvm_core::packs::Sha256Hex::from_bytes(b"manifest"),
                    )
                    .unwrap(),
                )
                .unwrap()
            } else {
                "alpine:latest".into()
            };
            assert!(
                serde_json::from_value::<mvm_runtime::machine::persist::MachineSpec>(ambiguous)
                    .is_err()
            );
        }
        let mut ambiguous = serde_json::to_value(&spec).unwrap();
        ambiguous["runtime_pack"] = true.into();
        assert!(
            serde_json::from_value::<mvm_runtime::machine::persist::MachineSpec>(ambiguous)
                .is_err()
        );
        assert!(!mvm_runtime::machine::persist::machine_config_matches(
            &spec,
            &{
                let mut changed = spec.clone();
                changed.prepared_image.as_mut().unwrap().rootfs_sha256 = "0".repeat(64);
                changed
            }
        ));
    }

    #[test]
    fn ordinary_specs_omit_the_new_field_and_keep_the_old_reader_behavior() {
        let request = crate::LaunchRequest::builder(
            crate::LifecycleMode::Persistent,
            crate::RootfsSource::Oci {
                image_ref: REFERENCE.into(),
            },
        )
        .name("ordinary-fixture")
        .build()
        .unwrap();
        let spec = crate::launch::persisted_spec_from_request(&request, "ordinary-fixture");
        let value = serde_json::to_value(&spec).unwrap();
        assert!(value.get("prepared_image").is_none());
        let legacy: super::super::legacy_machine_spec::MachineSpec =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&legacy).unwrap(), value);
        let new: mvm_runtime::machine::persist::MachineSpec =
            serde_json::from_value(value.clone()).unwrap();
        assert!(new.prepared_image.is_none());
        assert_eq!(serde_json::to_value(new).unwrap(), value);
        let mut ordinary_ambiguous = value;
        ordinary_ambiguous["deployment"] = "/existing/deployment".into();
        assert!(
            serde_json::from_value::<mvm_runtime::machine::persist::MachineSpec>(
                ordinary_ambiguous
            )
            .is_ok()
        );
    }

    #[test]
    fn concurrent_index_replacement_cannot_select_unverified_platform_bytes() {
        let fixture = fixture();
        let mut replacement = cache::load_index(&fixture.cache).unwrap();
        let wrong_arch = if current_linux_platform().architecture == "arm64" {
            "amd64"
        } else {
            "arm64"
        };
        let config = serde_json::to_vec(&serde_json::json!({
            "os": "linux", "architecture": wrong_arch, "config": {},
        }))
        .unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(fixture.cache.join("manifests/fixture.json")).unwrap(),
        )
        .unwrap();
        manifest["config"]["digest"] = digest(&config).into();
        manifest["config"]["size"] = config.len().into();
        let manifest = serde_json::to_vec(&manifest).unwrap();
        let replacement_digest = digest(&manifest);
        write(&fixture.cache, "configs/replacement.json", &config);
        write(&fixture.cache, "manifests/replacement.json", &manifest);
        let rootfs = materialize::oci_rootfs_rel(
            &replacement_digest,
            &materialize::oci_runtime_tag(&fixture.cache),
            false,
        )
        .unwrap();
        write(
            &fixture.cache,
            &rootfs,
            b"unverified replacement platform bytes",
        );
        let parent = fixture.cache.join(&rootfs).parent().unwrap().to_path_buf();
        fs::write(parent.join("rootfs.verity"), b"replacement-verity").unwrap();
        fs::write(parent.join("rootfs.roothash"), "0".repeat(64)).unwrap();
        mvm_build::builder_vm::GuestSidecar::for_oci_run(REFERENCE, false, true)
            .write_to_dir(&parent)
            .unwrap();
        replacement.images[0].resolved_digest = replacement_digest;
        replacement.images[0].manifest_path = "manifests/replacement.json".into();
        replacement.images[0].config_path = Some("configs/replacement.json".into());
        replacement.images[0].rootfs_path = Some(rootfs);
        let result = resolve_with_observer(REFERENCE, &fixture.context, || {
            cache::save_index(&fixture.cache, &replacement).unwrap();
        });
        assert!(
            result.is_err(),
            "selected replacement bytes after validating a different manifest"
        );
        assert_eq!(result.err().unwrap().kind, Kind::SelectionChanged);
        assert_eq!(
            select(REFERENCE, &fixture.context).unwrap_err().kind,
            Kind::PlatformMismatch
        );
    }

    #[test]
    fn unverified_layer_claims_are_not_promoted_from_the_index() {
        let fixture = fixture();
        let mut index = cache::load_index(&fixture.cache).unwrap();
        index.images[0].layers[0].digest = format!("sha256:{}", "f".repeat(64));
        cache::save_index(&fixture.cache, &index).unwrap();
        assert_eq!(
            select(REFERENCE, &fixture.context).unwrap_err().kind,
            Kind::CorruptPreparation
        );
    }

    #[test]
    fn incidental_timestamps_are_not_selection_identity() {
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let parent = fixture.rootfs.parent().unwrap();
        let mut sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(parent)
            .unwrap()
            .unwrap();
        sidecar.built_at = "2026-05-19T00:00:00Z".into();
        sidecar.write_to_dir(parent).unwrap();
        let mut index = cache::load_index(&fixture.cache).unwrap();
        index.images[0].fetched_at = "2026-05-19T00:00:00Z".into();
        cache::save_index(&fixture.cache, &index).unwrap();
        assert_eq!(select(REFERENCE, &fixture.context).unwrap(), selected);
    }

    #[test]
    fn stale_runtime_is_not_repaired_from_complete_cached_layers() {
        let fixture = fixture();
        let mut index = cache::load_index(&fixture.cache).unwrap();
        index.images[0].runtime_tag = Some("stale-runtime".into());
        cache::save_index(&fixture.cache, &index).unwrap();
        fs::remove_file(&fixture.rootfs).unwrap();
        let before = fs::read(fixture.cache.join(oci_types::INDEX_FILE)).unwrap();
        assert_eq!(
            select(REFERENCE, &fixture.context).unwrap_err().kind,
            Kind::RuntimeMismatch
        );
        assert!(!fixture.rootfs.exists());
        assert_eq!(
            fs::read(fixture.cache.join(oci_types::INDEX_FILE)).unwrap(),
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_preparation_metadata_is_refused() {
        let fixture = fixture();
        let manifest = fixture.cache.join("manifests/fixture.json");
        let outside = fixture._home.path().join("outside-manifest.json");
        fs::rename(&manifest, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, &manifest).unwrap();
        assert_eq!(
            select(REFERENCE, &fixture.context).unwrap_err().kind,
            Kind::CorruptPreparation
        );
    }

    #[test]
    fn changed_prepared_sidecars_are_not_silently_reselected() {
        for name in [
            "rootfs.verity",
            "rootfs.roothash",
            mvm_build::builder_vm::SIDECAR_FILENAME,
        ] {
            let fixture = fixture();
            let selected = select(REFERENCE, &fixture.context).unwrap();
            let parent = fixture.rootfs.parent().unwrap();
            if name == mvm_build::builder_vm::SIDECAR_FILENAME {
                let mut sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(parent)
                    .unwrap()
                    .unwrap();
                sidecar.accessible = !sidecar.accessible;
                sidecar.write_to_dir(parent).unwrap();
            } else {
                fs::write(parent.join(name), "a".repeat(64)).unwrap();
            }
            assert_eq!(
                revalidate(&selected, &fixture.context.backend, "standard")
                    .err()
                    .unwrap()
                    .kind,
                Kind::SelectionChanged
            );
        }
    }

    #[test]
    fn persistent_start_revalidates_without_using_acquisition_host_hooks() {
        use crate::launch::machine_start::{
            BootImage, MachineStartParams, StartHost, start_machine_spec,
        };
        struct RefusingHost;
        impl StartHost for RefusingHost {
            fn workload_kernel(&self, _: &str) -> anyhow::Result<Option<String>> {
                panic!("prepared start must not ask a host to acquire a kernel")
            }
            fn resolve_image(&self, _: &str) -> anyhow::Result<BootImage> {
                panic!("prepared start must not use legacy image acquisition")
            }
            fn prepare_volumes(
                &self,
                _: &str,
                _: &[String],
            ) -> anyhow::Result<crate::volume::LaunchPreparation> {
                panic!("missing preparation must refuse before leases")
            }
        }
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let request = crate::LaunchRequest::builder_for(
            crate::LifecycleMode::Persistent,
            crate::LaunchSource::PreparedImage {
                selection: selected,
            },
        )
        .name("prepared-start")
        .build()
        .unwrap();
        let spec = crate::launch::persisted_spec_from_request(&request, "prepared-start");
        mvm_runtime::machine::persist::save_machine_spec(&spec, false).unwrap();
        let loaded = mvm_runtime::machine::persist::load_machine_spec("prepared-start").unwrap();
        let params = || MachineStartParams {
            hypervisor: &fixture.context.backend,
            has_ad_hoc_argv: false,
            mailbox: None,
        };
        let error = start_machine_spec(&loaded, &RefusingHost, params()).unwrap_err();
        assert_eq!(
            error.downcast_ref::<PreparedImageError>().unwrap().kind,
            Kind::MissingKernel
        );
        fs::write(&fixture.rootfs, b"changed since persistent selection").unwrap();
        let error = start_machine_spec(&loaded, &RefusingHost, params()).unwrap_err();
        assert_eq!(
            error.downcast_ref::<PreparedImageError>().unwrap().kind,
            Kind::SelectionChanged
        );
        assert!(
            mvm_runtime::machine::persist::load_machine_spec("prepared-start")
                .unwrap()
                .prepared_image
                .is_some()
        );
    }

    #[test]
    fn runtime_cache_sentinels_are_not_measured_runtime_identity() {
        for identity in ["", "pending-source-key", "unidentified"] {
            let error = require_identified_runtime(REFERENCE, identity).unwrap_err();
            assert_eq!(error.kind, Kind::RuntimeUnavailable);
            assert_eq!(
                error.remedy(),
                mvm_core::prepared_image::PreparedImageRemedy::Bootstrap
            );
        }
        require_identified_runtime(REFERENCE, &"0".repeat(64)).unwrap();
    }

    #[test]
    fn legacy_default_alias_cannot_change_a_prepared_backend_identity() {
        let mut fixture = fixture();
        fixture._env.set("MVM_HYPERVISOR", "qemu");
        let mut selected = select(REFERENCE, &fixture.context).unwrap();
        selected.backend = "firecracker".into();
        let effective = crate::launch::machine_start::resolve_effective_hypervisor("firecracker");
        assert_eq!(effective, "qemu");
        assert_eq!(
            require_backend(&selected, "firecracker", &effective)
                .unwrap_err()
                .kind,
            Kind::UnsupportedMode
        );
        assert_eq!(
            revalidate(&selected, &effective, "standard")
                .err()
                .unwrap()
                .kind,
            Kind::UnsupportedMode
        );
    }

    #[test]
    fn persistent_start_checks_the_actual_driver_before_preparation_hooks() {
        use crate::launch::machine_start::{
            BootImage, MachineStartParams, StartHost, start_machine_spec,
        };
        struct DifferentDriver<'a>(&'a str);
        impl StartHost for DifferentDriver<'_> {
            fn backend(&self, _: &str) -> mvm_runtime::AnyBackend {
                mvm_runtime::AnyBackend::from_hypervisor(self.0)
            }
            fn workload_kernel(&self, _: &str) -> anyhow::Result<Option<String>> {
                panic!("backend mismatch must refuse before a host kernel request")
            }
            fn resolve_image(&self, _: &str) -> anyhow::Result<BootImage> {
                panic!("backend mismatch must refuse before image acquisition")
            }
            fn prepare_volumes(
                &self,
                _: &str,
                _: &[String],
            ) -> anyhow::Result<crate::volume::LaunchPreparation> {
                panic!("backend mismatch must refuse before volume leases")
            }
        }
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let request = crate::LaunchRequest::builder_for(
            crate::LifecycleMode::Persistent,
            crate::LaunchSource::PreparedImage {
                selection: selected,
            },
        )
        .name("different-driver")
        .build()
        .unwrap();
        let spec = crate::launch::persisted_spec_from_request(&request, "different-driver");
        let other = if fixture.context.backend == "qemu" {
            "firecracker"
        } else {
            "qemu"
        };
        let error = start_machine_spec(
            &spec,
            &DifferentDriver(other),
            MachineStartParams {
                hypervisor: &fixture.context.backend,
                has_ad_hoc_argv: false,
                mailbox: None,
            },
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<PreparedImageError>().unwrap().kind,
            Kind::UnsupportedMode
        );
    }

    #[test]
    fn one_prepared_admission_binds_actual_bytes_and_refuses_subsequent_drift() {
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let validated = revalidate(&selected, &fixture.context.backend, "standard").unwrap();
        let ledger = crate::admission::InMemoryNonceLedger::new();
        let keys = fixture._home.path().join("test-keys");
        let audit = fixture._home.path().join("test-audit");
        let params = || {
            let mut params =
                crate::admission::admit_plan_tests::pinning_params(&fixture.rootfs, &ledger);
            params.backend_name = &fixture.context.backend;
            params.restrict_agent_verbs = false;
            params.keys_dir = Some(&keys);
            params.audit_dir = Some(&audit);
            params
        };
        let context =
            crate::admission::admit_prepared_plan_for_boot(params(), Vec::new(), &validated, None)
                .unwrap();
        assert_eq!(context.admitted.plan().image.sha256, selected.rootfs_sha256);
        assert_eq!(
            context.admitted.plan().audit_labels["oci_resolved_digest"],
            selected.manifest_digest
        );
        let chain = fs::read_to_string(audit.join("local.jsonl")).unwrap();
        assert_eq!(
            chain
                .lines()
                .filter(|line| line.contains("plan.admitted"))
                .count(),
            1
        );
        fs::write(&fixture.rootfs, b"drift before signing").unwrap();
        let error =
            crate::admission::admit_prepared_plan_for_boot(params(), Vec::new(), &validated, None)
                .unwrap_err();
        assert_eq!(
            error.downcast_ref::<PreparedImageError>().unwrap().kind,
            Kind::SelectionChanged
        );
        assert_eq!(
            fs::read_to_string(audit.join("local.jsonl")).unwrap(),
            chain
        );
    }

    #[test]
    fn prepared_admission_refuses_release_proof_without_verified_launch_evidence() {
        let fixture = fixture();
        let selected = select(REFERENCE, &fixture.context).unwrap();
        let validated = revalidate(&selected, &fixture.context.backend, "standard").unwrap();
        let ledger = crate::admission::InMemoryNonceLedger::new();
        let keys = fixture._home.path().join("test-keys");
        let audit = fixture._home.path().join("test-audit");
        let config = mvm_core::vm_backend::VmStartConfig {
            runtime_release_proof: Some(mvm_core::protocol::runtime_release::RuntimeReleaseProof {
                archive: fixture._home.path().join("unverified.tar.gz"),
                checksum: fixture._home.path().join("unverified.tar.gz.sha256"),
                signature_bundle: fixture._home.path().join("unverified.tar.gz.bundle"),
                archive_sha256: "a".repeat(64),
                version: env!("CARGO_PKG_VERSION").into(),
                arch: mvm_core::arch::GuestArch::host(),
            }),
            ..Default::default()
        };
        let mut params =
            crate::admission::admit_plan_tests::pinning_params(&fixture.rootfs, &ledger);
        params.backend_name = &fixture.context.backend;
        params.restrict_agent_verbs = false;
        params.keys_dir = Some(&keys);
        params.audit_dir = Some(&audit);
        params.runtime_config = Some(&config);

        let error =
            crate::admission::admit_prepared_plan_for_boot(params, Vec::new(), &validated, None)
                .unwrap_err();

        assert!(
            format!("{error:#}").contains("release runtime requires verified launch evidence"),
            "{error:#}"
        );
        assert!(!audit.join("local.jsonl").exists());
    }
}
