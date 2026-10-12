//! A fresh, privately owned OCI materialization and its content bindings.

use super::{
    TreeMaterializeOptions, UnpackedLayers, backend_err, materialize_tree, unpack_one_layer,
};
use mvm_build::oci_runtime_inject::{ImageRuntimeConfig, MvmRuntimeBinaries};
use mvm_core::arch::GuestArch;
use mvm_core::client::Result;
use mvm_fs::oci::{
    FetchedManifest, ImageReference, LayerDescriptor, LayerFetchOptions, OciLayerFetcher,
    OciManifestFetcher, current_linux_platform,
};
use std::path::{Path, PathBuf};

pub(super) struct PulledImage {
    pub(super) layers: UnpackedLayers,
    pub(super) config: mvm_build::oci_runtime_inject::ImageRuntimeConfig,
    digest: String,
    canonical_reference: String,
}

// Config is small JSON metadata, not a filesystem layer. Match the manifest
// reader's 4 MiB ceiling without granting it the layer fetcher's 2 GiB budget.
const MAX_OCI_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// Pull a public OCI registry reference and unpack every layer into `dest`,
/// reusing mvm-oci's fetch + hardened unpacker (gzip is decoded here, at the
/// crate boundary, keeping mvm-oci decompressor-free by design).
pub(super) async fn pull_image_to_dir(
    image_ref: &ImageReference,
    dest: &Path,
) -> Result<PulledImage> {
    let manifest_fetcher = OciManifestFetcher::new();
    pull_image_to_dir_with_fetcher(image_ref, dest, &manifest_fetcher).await
}

async fn pull_image_to_dir_with_fetcher(
    image_ref: &ImageReference,
    dest: &Path,
    manifest_fetcher: &OciManifestFetcher,
) -> Result<PulledImage> {
    let reference = image_ref.canonical();
    let manifest = manifest_fetcher
        .fetch_linux_platform_manifest(image_ref, &current_linux_platform())
        .await
        .map_err(|e| backend_err(format!("fetch manifest for {reference}: {e}")))?;
    let layers = manifest
        .layers()
        .map_err(|e| backend_err(format!("parse layers for {reference}: {e}")))?;
    if layers.is_empty() {
        return Err(backend_err(format!("OCI image {reference} has no layers")));
    }
    let layer_fetcher =
        OciLayerFetcher::from_manifest_fetcher(manifest_fetcher, LayerFetchOptions::default());
    let canonical_reference = digest_reference(image_ref, &manifest)?;
    let image: mvm_contract::oci::manifest_types::ImageManifest =
        serde_json::from_slice(&manifest.bytes).map_err(backend_err)?;
    let config_descriptor = LayerDescriptor {
        digest: image.config.digest,
        size: u64::try_from(image.config.size).map_err(backend_err)?,
        media_type: image.config.media_type,
    };
    let config_fetcher = OciLayerFetcher::from_manifest_fetcher(
        manifest_fetcher,
        LayerFetchOptions::builder()
            .max_size(MAX_OCI_CONFIG_BYTES)
            .build(),
    );
    let mut config_bytes = Vec::new();
    config_fetcher
        .fetch_layer(image_ref, &config_descriptor, &mut config_bytes)
        .await
        .map_err(|e| backend_err(format!("fetch OCI config: {e}")))?;
    let config = mvm_fs::oci::config::OciImageConfig::parse(&config_bytes).map_err(backend_err)?;
    config
        .validate_platform(&current_linux_platform())
        .map_err(backend_err)?;
    let config = mvm_build::oci_runtime_inject::ImageRuntimeConfig {
        argv: config.argv,
        env: config.env,
        working_dir: config.working_dir,
    };
    let mut prior_layer_paths = std::collections::HashSet::new();
    let mut unpacked = UnpackedLayers::default();
    for layer in &layers {
        let mut bytes = Vec::new();
        layer_fetcher
            .fetch_layer(image_ref, layer, &mut bytes)
            .await
            .map_err(|e| backend_err(format!("fetch layer {}: {e}", layer.digest)))?;
        let report = unpack_one_layer(layer, &bytes, dest, &prior_layer_paths)?;
        unpacked.owners.absorb(&report.ownership);
        prior_layer_paths.extend(report.paths_written);
        unpacked.deferred_nodes.extend(report.deferred_nodes);
    }
    Ok(PulledImage {
        layers: unpacked,
        config,
        digest: manifest.digest,
        canonical_reference,
    })
}

/// Keeps the output directory alive through bundle export. There is no public
/// constructor or deserializer: metadata can only come from verified acquisition.
/// Unique outputs avoid collisions with concurrent runs and cache publishers.
/// This is not a sandbox against other code running with the same host identity.
#[derive(Debug)]
pub struct OciMaterialization {
    directory: tempfile::TempDir,
    digest: String,
    canonical_reference: String,
    arch: GuestArch,
    sealed: bool,
    files: Vec<BoundFile>,
}

#[derive(Debug)]
struct BoundFile {
    path: PathBuf,
    sha256: String,
}

impl BoundFile {
    fn read(path: PathBuf) -> Result<Self> {
        let sha256 = hash_regular_file(&path)?;
        Ok(Self { path, sha256 })
    }

    fn verify(&self) -> Result<()> {
        if hash_regular_file(&self.path)? != self.sha256 {
            return Err(backend_err("OCI materialization changed before export"));
        }
        Ok(())
    }
}

fn hash_regular_file(path: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path).map_err(backend_err)?;
    if !metadata.file_type().is_file() {
        return Err(backend_err(
            "OCI materialization artifact is not a regular file",
        ));
    }
    mvm_core::crypto::image_verify::sha256_file(path).map_err(backend_err)
}

impl OciMaterialization {
    pub fn resolved_manifest_digest(&self) -> &str {
        &self.digest
    }

    pub fn canonical_reference(&self) -> &str {
        &self.canonical_reference
    }

    pub fn arch(&self) -> GuestArch {
        self.arch
    }

    pub fn sealed(&self) -> bool {
        self.sealed
    }

    pub fn rootfs_path(&self) -> &Path {
        &self.files[0].path
    }

    pub fn rootfs_sha256(&self) -> &str {
        &self.files[0].sha256
    }

    pub fn sidecar_sha256(&self) -> &str {
        &self.files[1].sha256
    }

    /// Check every bound artifact before and after consuming it for export.
    /// The private directory prevents cooperating materializers from replacing
    /// these files; hashes additionally detect accidental mutation by consumers.
    pub fn verify_integrity(&self) -> Result<()> {
        if !self.directory.path().is_dir() {
            return Err(backend_err("OCI materialization directory disappeared"));
        }
        for file in &self.files {
            file.verify()?;
        }
        Ok(())
    }
}

/// Packaging requires a runtime acquired from the package's pinned image set;
/// it must never silently substitute this checkout's current runtime.
pub(crate) struct OciMaterializeRequest<'a> {
    image_ref: &'a str,
    arch: GuestArch,
    sealed: bool,
    runtime_binaries: &'a MvmRuntimeBinaries,
}

impl<'a> OciMaterializeRequest<'a> {
    pub(crate) fn new(
        image_ref: &'a str,
        arch: GuestArch,
        runtime_binaries: &'a MvmRuntimeBinaries,
    ) -> Self {
        Self {
            image_ref,
            arch,
            sealed: false,
            runtime_binaries,
        }
    }

    pub(crate) fn sealed(mut self, sealed: bool) -> Self {
        self.sealed = sealed;
        self
    }

    fn tree_options<'b>(&'b self, config: &'b ImageRuntimeConfig) -> TreeMaterializeOptions<'b> {
        TreeMaterializeOptions {
            config: Some(config),
            sealed: self.sealed,
            runtime_binaries: Some(self.runtime_binaries),
            policy: mvm_build::run_image::RootfsMaterializationPolicy::InProcessOnly,
        }
    }
}

/// Acquire and materialize for packaging; unlike direct OCI runs a package must
/// declare an executable argv. Both variants retain the in-process verity seal.
pub(crate) async fn materialize_oci_image(
    request: OciMaterializeRequest<'_>,
) -> Result<OciMaterialization> {
    let OciMaterializeRequest {
        image_ref,
        arch,
        sealed,
        ..
    } = request;
    require_runtime_arch(arch)?;
    let reference: ImageReference = image_ref.parse().map_err(backend_err)?;
    let unpacked = tempfile::tempdir().map_err(backend_err)?;
    let pulled = pull_image_to_dir(&reference, unpacked.path()).await?;
    require_entrypoint(&pulled.config.argv)?;
    let directory = tempfile::tempdir().map_err(backend_err)?;
    let rootfs = directory.path().join("rootfs.ext4");
    materialize_tree(
        unpacked.path(),
        &rootfs,
        &pulled.canonical_reference,
        pulled.layers,
        request.tree_options(&pulled.config),
    )?;
    if sealed && !mvm_build::run_image::published_build_matches(&rootfs, true) {
        return Err(backend_err(
            "sealed OCI materialization has incomplete verity artifacts",
        ));
    }
    let files = bind_files(directory.path(), sealed)?;
    Ok(OciMaterialization {
        directory,
        digest: pulled.digest,
        canonical_reference: pulled.canonical_reference,
        arch,
        sealed,
        files,
    })
}

fn bind_files(directory: &Path, sealed: bool) -> Result<Vec<BoundFile>> {
    let mut files = vec![
        BoundFile::read(directory.join("rootfs.ext4"))?,
        BoundFile::read(directory.join(mvm_core::guest_sidecar::SIDECAR_FILENAME))?,
    ];
    for name in ["rootfs.verity", "rootfs.roothash"] {
        let path = directory.join(name);
        if sealed || path.try_exists().map_err(backend_err)? {
            files.push(BoundFile::read(path)?);
        }
    }
    Ok(files)
}

fn require_runtime_arch(arch: GuestArch) -> Result<()> {
    if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) || arch != GuestArch::host() {
        return Err(backend_err(format!(
            "OCI runtime injection supports only this host architecture ({}), requested {arch}",
            GuestArch::host()
        )));
    }
    Ok(())
}

fn require_entrypoint(argv: &[String]) -> Result<()> {
    if argv.first().is_none_or(|executable| executable.is_empty())
        || argv.iter().any(|argument| argument.contains('\0'))
    {
        return Err(backend_err(
            "OCI packaging requires a nonempty executable argv without NUL bytes",
        ));
    }
    Ok(())
}

pub(super) fn digest_reference(
    reference: &ImageReference,
    manifest: &FetchedManifest,
) -> Result<String> {
    mvm_fs::oci::verify_sha256_digest(&manifest.bytes, &manifest.digest).map_err(backend_err)?;
    let pinned = ImageReference {
        tag: None,
        digest: Some(manifest.digest.clone()),
        ..reference.clone()
    };
    Ok(pinned.canonical())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn packages_require_in_process_materialization_for_dev_and_prod() {
        let bins = MvmRuntimeBinaries {
            agent: "/pinned/agent".into(),
            netinit: "/pinned/netinit".into(),
            egress_client: "/pinned/egress".into(),
            entrypoint_runner: "/pinned/entrypoint".into(),
        };
        let config = ImageRuntimeConfig::default();
        for sealed in [false, true] {
            let request =
                OciMaterializeRequest::new("app:1", GuestArch::host(), &bins).sealed(sealed);
            let options = request.tree_options(&config);
            assert_eq!(
                options.policy,
                mvm_build::run_image::RootfsMaterializationPolicy::InProcessOnly
            );
            assert_eq!(options.sealed, sealed);
            assert_eq!(options.runtime_binaries, Some(&bins));
        }
    }

    fn config_registry(
        config: &[u8],
        declared_size: u64,
    ) -> (
        mvm_fs::oci::test_registry::MemoryRegistry,
        ImageReference,
        OciManifestFetcher,
        String,
    ) {
        use mvm_fs::oci::{ClientConfig, ClientProtocol, RegistryAuthConfig};
        let registry = mvm_fs::oci::test_registry::MemoryRegistry::start();
        let digest = registry.insert_blob(config);
        let layer = tar::Builder::new(Vec::new()).into_inner().unwrap();
        let layer_digest = registry.insert_blob(&layer);
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest, "size": declared_size
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest, "size": layer.len()
            }]
        });
        registry.insert_manifest(
            "test/image",
            "latest",
            "application/vnd.oci.image.manifest.v1+json",
            &serde_json::to_vec(&manifest).unwrap(),
        );
        let reference = format!("{}/test/image:latest", registry.host())
            .parse()
            .unwrap();
        let fetcher = OciManifestFetcher::with_config_and_auth(
            ClientConfig {
                protocol: ClientProtocol::Http,
            },
            RegistryAuthConfig::Anonymous,
        );
        (registry, reference, fetcher, digest)
    }

    #[tokio::test]
    async fn oci_config_descriptor_over_cap_never_requests_body() {
        let (registry, reference, fetcher, digest) =
            config_registry(b"{}", MAX_OCI_CONFIG_BYTES + 1);
        let dest = tempfile::tempdir().unwrap();
        let error = pull_image_to_dir_with_fetcher(&reference, dest.path(), &fetcher)
            .await
            .err()
            .expect("descriptor must fail");
        assert!(error.to_string().contains("exceeds"), "{error}");
        assert!(
            !registry
                .requests()
                .iter()
                .any(|request| request.path.ends_with(&digest))
        );
    }

    #[tokio::test]
    async fn oci_config_lying_small_descriptor_cannot_exceed_stream_cap() {
        let bytes = vec![b' '; MAX_OCI_CONFIG_BYTES as usize + 1];
        let (registry, reference, fetcher, digest) = config_registry(&bytes, 1);
        let dest = tempfile::tempdir().unwrap();
        let error = pull_image_to_dir_with_fetcher(&reference, dest.path(), &fetcher)
            .await
            .err()
            .expect("body must fail");
        assert!(error.to_string().contains("exceeds"), "{error}");
        assert!(
            registry
                .requests()
                .iter()
                .any(|request| request.path.ends_with(&digest))
        );
        assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn oci_config_digest_platform_and_runtime_metadata_are_verified() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "os": "linux", "architecture": current_linux_platform().architecture,
            "config": { "Entrypoint": ["/app"], "Cmd": ["serve"], "Env": ["A=B"], "WorkingDir": "/work" }
        })).unwrap();
        let (registry, reference, fetcher, digest) = config_registry(&bytes, bytes.len() as u64);
        let dest = tempfile::tempdir().unwrap();
        let image = pull_image_to_dir_with_fetcher(&reference, dest.path(), &fetcher)
            .await
            .unwrap();
        assert_eq!(image.config.argv, ["/app", "serve"]);
        assert_eq!(image.config.env, ["A=B"]);
        assert_eq!(image.config.working_dir.as_deref(), Some("/work"));
        registry.serve_blob_as(&digest, b"tampered");
        assert!(
            pull_image_to_dir_with_fetcher(&reference, dest.path(), &fetcher)
                .await
                .is_err()
        );

        let wrong = br#"{"os":"windows","architecture":"wrong"}"#;
        let (_registry, reference, fetcher, _) = config_registry(wrong, wrong.len() as u64);
        let error = pull_image_to_dir_with_fetcher(&reference, dest.path(), &fetcher)
            .await
            .err()
            .expect("wrong platform must fail");
        assert!(error.to_string().contains("platform"), "{error}");
    }

    #[test]
    fn selected_manifest_identity_is_content_bound_and_drops_mutable_tag() {
        let reference: ImageReference = "alpine:latest".parse().unwrap();
        let bytes = b"selected manifest".to_vec();
        let mut manifest = FetchedManifest {
            reference: reference.clone(),
            digest: format!("sha256:{}", hex::encode(Sha256::digest(&bytes))),
            bytes,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
        };
        assert_eq!(
            digest_reference(&reference, &manifest).unwrap(),
            format!("docker.io/library/alpine@{}", manifest.digest)
        );
        manifest.bytes.push(0);
        assert!(digest_reference(&reference, &manifest).is_err());
    }

    #[test]
    fn packaging_requires_command_and_host_runtime() {
        assert!(require_entrypoint(&["/bin/app".into(), "--serve".into()]).is_ok());
        for argv in [
            vec![],
            vec!["".into()],
            vec!["/bin/app".into(), "x\0y".into()],
        ] {
            assert!(require_entrypoint(&argv).is_err());
        }
        assert!(require_runtime_arch(GuestArch::host()).is_ok());
        let foreign = match GuestArch::host() {
            GuestArch::Aarch64 => GuestArch::X86_64,
            GuestArch::X86_64 => GuestArch::Aarch64,
        };
        assert!(require_runtime_arch(foreign).is_err());
    }

    #[tokio::test]
    async fn acquisition_verifies_config_content_and_platform_before_unpacking() {
        use mvm_fs::oci::{
            ClientConfig, ClientProtocol, OciManifestFetcher, current_linux_platform,
            test_registry::MemoryRegistry,
        };
        let registry = MemoryRegistry::start();
        let config = serde_json::to_vec(&serde_json::json!({
            "os": "linux",
            "architecture": current_linux_platform().architecture,
            "config": {"Entrypoint": ["/app"], "Cmd": ["--serve"], "Env": ["A=B"]}
        }))
        .unwrap();
        let config_digest = registry.insert_blob(&config);
        let layer = vec![0; 1024];
        let layer_digest = registry.insert_blob(&layer);
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer_digest, "size": layer.len()}]
        })).unwrap();
        registry.insert_manifest(
            "test/app",
            "latest",
            "application/vnd.oci.image.manifest.v1+json",
            &manifest,
        );
        let reference: ImageReference = format!("{}/test/app:latest", registry.host())
            .parse()
            .unwrap();
        let fetcher = OciManifestFetcher::with_config(ClientConfig {
            protocol: ClientProtocol::Http,
        });
        let output = tempfile::tempdir().unwrap();
        let pulled = pull_image_to_dir_with_fetcher(&reference, output.path(), &fetcher)
            .await
            .unwrap();
        assert_eq!(pulled.config.argv, ["/app", "--serve"]);
        assert_eq!(pulled.config.env, ["A=B"]);
        assert_eq!(
            pulled.digest,
            format!("sha256:{}", hex::encode(Sha256::digest(&manifest)))
        );
        registry.serve_blob_as(&config_digest, b"tampered config");
        assert!(
            pull_image_to_dir_with_fetcher(&reference, output.path(), &fetcher)
                .await
                .is_err()
        );

        let wrong_config = br#"{"os":"windows","architecture":"amd64","config":{"Cmd":["/app"]}}"#;
        let wrong_digest = registry.insert_blob(wrong_config);
        let mut wrong_manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        wrong_manifest["config"]["digest"] = wrong_digest.into();
        wrong_manifest["config"]["size"] = wrong_config.len().into();
        registry.insert_manifest(
            "test/app",
            "latest",
            "application/vnd.oci.image.manifest.v1+json",
            &serde_json::to_vec(&wrong_manifest).unwrap(),
        );
        let error = pull_image_to_dir_with_fetcher(&reference, output.path(), &fetcher)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("config platform"));
    }

    #[test]
    fn receipt_detects_mutation_of_every_artifact_and_owns_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_path_buf();
        for name in [
            "rootfs.ext4",
            mvm_core::guest_sidecar::SIDECAR_FILENAME,
            "rootfs.verity",
            "rootfs.roothash",
        ] {
            std::fs::write(path.join(name), name).unwrap();
        }
        let receipt = OciMaterialization {
            files: bind_files(&path, true).unwrap(),
            directory,
            digest: "test-only".into(),
            canonical_reference: "test-only".into(),
            arch: GuestArch::host(),
            sealed: true,
        };
        receipt.verify_integrity().unwrap();
        for file in &receipt.files {
            let original = std::fs::read(&file.path).unwrap();
            std::fs::write(&file.path, b"tampered").unwrap();
            assert!(receipt.verify_integrity().is_err());
            std::fs::write(&file.path, original).unwrap();
        }
        std::fs::remove_file(path.join("rootfs.verity")).unwrap();
        assert!(receipt.verify_integrity().is_err());
        assert!(bind_files(&path, true).is_err());
        drop(receipt);
        assert!(!path.exists());
    }
}
