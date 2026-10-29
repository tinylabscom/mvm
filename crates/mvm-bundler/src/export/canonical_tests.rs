//! Linux/feed crypto is genuine; CLI runtime payloads here are structural
//! fixtures, not runtime authentication or native admission.
use super::*;
use crate::{CanonicalLinuxProofInputs, CliBootAssetsInputs};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    BaseImageContractRange, BuilderBootAbiRange, HostProtocolSupport, ImageSetManifest,
    ImageSetVerification, RetainedImageSetRootProof, cache_image_set_root, image_train_lock,
    read_cached_image_set_root_proof,
};
use mvm_core::image_set_revocation::{ImageSetRevocationStore, RetainedImageSetRevocationProof};
use mvm_core::packs::Sha256Hex;
use mvm_core::plan::bundle::{EmbeddedCliBootAssets, TrustStore, key_id_from_pubkey};
use std::cell::Cell;

#[path = "../../../mvm-core/src/image_set/fixtures/published_root.rs"]
mod published;
const FEED: &[u8] = include_bytes!(
    "../../../mvm-core/tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json"
);
const SIGNATURE: &[u8] = include_bytes!(
    "../../../mvm-core/tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json.bundle"
);
fn clock() -> chrono::DateTime<Utc> {
    "2026-10-15T12:00:00Z".parse().unwrap()
}

struct Publisher {
    key: SigningKey,
    calls: Cell<usize>,
}
impl Publisher {
    fn touch(&self) {
        self.calls.set(self.calls.get() + 1);
    }
}
impl BundleSigner for Publisher {
    fn publisher_id(&self) -> String {
        self.touch();
        "structural-test-only".into()
    }
    fn verifying_key(&self) -> VerifyingKey {
        self.touch();
        self.key.verifying_key()
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64]> {
        self.touch();
        Ok(self.key.sign(bytes).to_bytes())
    }
}
impl TrustStore for Publisher {
    fn lookup(&self, key: &KeyId) -> Option<VerifyingKey> {
        (key == &key_id_from_pubkey(&self.key.verifying_key())).then(|| self.key.verifying_key())
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    root: RetainedImageSetRootProof,
    feed: RetainedImageSetRevocationProof,
    kernel: PathBuf,
    rootfs: PathBuf,
    out: PathBuf,
    paths: Vec<(&'static str, PathBuf)>,
    runtime: EmbeddedCliBootAssets,
}
impl Fixture {
    fn new(kernel: &[u8]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = ImageSetRevocationStore::new(directory.path().join("feed"));
        store.update(FEED, SIGNATURE, clock()).unwrap();
        let feed = store.capture_applied_proof(clock()).unwrap();
        let train = image_train_lock();
        let host = HostProtocolSupport {
            base_image_contract: BaseImageContractRange::SUPPORTED,
            builder_cache_contract: train.compatibility.builder_cache_contract,
            builder_boot_abi: BuilderBootAbiRange::WITH_PAYLOAD,
        };
        let cache = directory.path().join("roots");
        cache_image_set_root(
            &cache,
            &ImageSetVerification::new(
                published::MANIFEST,
                published::BUNDLE,
                &train.image_set,
                Path::new(""),
            )
            .with_host_protocols(&host)
            .with_revocations(feed.verified()),
        )
        .unwrap();
        let root = read_cached_image_set_root_proof(
            &cache,
            &train.image_set,
            &host,
            Some(feed.verified()),
        )
        .unwrap();
        let kernel_path = directory.path().join("kernel");
        let rootfs = directory.path().join("rootfs.ext4");
        let out = directory.path().join("out.mvmpkg");
        std::fs::write(&kernel_path, kernel).unwrap();
        std::fs::write(&rootfs, b"structural rootfs").unwrap();
        std::fs::write(directory.path().join(SIDECAR_FILENAME), b"{}").unwrap();
        let paths = [
            "runtime.tar.gz",
            "runtime.sha256",
            "runtime.bundle",
            "runtime.sha256.bundle",
            "overlay",
            "overlay.verity",
            "initrd",
        ]
        .into_iter()
        .map(|name| {
            let path = directory.path().join(name);
            std::fs::write(&path, format!("synthetic {name}")).unwrap();
            (name, path)
        })
        .collect();
        let runtime = EmbeddedCliBootAssets {
            manifest_artifact: BOOT_MANIFEST_NAME.into(),
            version: "0.24.0".into(),
            arch: GuestArch::host().to_string(),
            archive_artifact: "runtime.tar.gz".into(),
            checksum_artifact: "runtime.sha256".into(),
            signature_bundle_artifact: "runtime.bundle".into(),
            checksum_signature_bundle_artifact: "runtime.sha256.bundle".into(),
            overlay_artifact: "overlay".into(),
            overlay_verity_artifact: "overlay.verity".into(),
            initramfs_artifact: "initrd".into(),
            overlay_roothash: "a".repeat(64),
            protocol_version: 2,
            min_supported_protocol_version: 2,
        };
        Self {
            directory,
            root,
            feed,
            kernel: kernel_path,
            rootfs,
            out,
            paths,
            runtime,
        }
    }
    fn files(&self) -> Vec<(&str, &Path)> {
        self.paths.iter().map(|(n, p)| (*n, p.as_path())).collect()
    }
    fn inputs(&self) -> BundleExportInputs<'_> {
        BundleExportInputs::new(
            self.kernel.to_str().unwrap(),
            self.rootfs.to_str().unwrap(),
            &self.runtime.arch,
            &self.out,
        )
        .initrd(self.paths.last().unwrap().1.to_str().unwrap())
    }
    fn proof(&self) -> CanonicalLinuxProofInputs<'_> {
        CanonicalLinuxProofInputs {
            root: &self.root,
            revocations: &self.feed,
        }
    }
    fn signer(&self) -> Publisher {
        Publisher {
            key: SigningKey::from_bytes(&[79; 32]),
            calls: Cell::new(0),
        }
    }
}

#[test]
fn raw_root_hash_export_signs_exact_bytes_and_manifest_agreement() {
    // Archive-byte evidence only, not a canonical-kernel launch.
    let f = Fixture::new(b"kernel");
    let signer = f.signer();
    let hash = "a".repeat(64);
    let inputs = f.inputs().verity(b"synthetic verity", &hash);
    let exported = export_bundle_at(&inputs, &signer, clock()).unwrap();
    let bytes = std::fs::read(&exported.path).unwrap();
    let verified = mvm_core::plan::bundle::read_and_verify_bundle(&bytes, &signer).unwrap();
    let member = verified.manifest.find_by_name("rootfs.roothash").unwrap();
    let expected = format!("{hash}\n").into_bytes();
    assert_eq!(member.role, ArtifactRole::Other);
    assert_eq!(member.path, "artifacts/rootfs.roothash");
    assert_eq!(member.size_bytes, 65);
    assert_eq!(member.sha256, sha256_hex(&expected));
    assert_eq!(verified.artifacts[&member.path], expected);
    assert_eq!(verified.manifest.verity.as_ref().unwrap().roothash, hash);
    assert_eq!(exported.size_bytes, bytes.len() as u64);
}

#[test]
fn raw_root_hash_encoding_refuses_noncanonical_values_before_signing() {
    let f = Fixture::new(b"kernel");
    for invalid in [
        "A".repeat(64),
        "g".repeat(64),
        "a".repeat(63),
        format!("{}\n", "a".repeat(64)),
        format!(" {}", "a".repeat(64)),
    ] {
        let signer = f.signer();
        let inputs = f.inputs().verity(b"synthetic verity", &invalid);
        assert!(export_bundle_at(&inputs, &signer, clock()).is_err());
        assert_eq!(signer.calls.get(), 0);
        assert!(!f.out.exists());
    }
}

#[test]
fn raw_root_hash_export_preserves_no_clobber_and_explicit_abort() {
    let f = Fixture::new(b"kernel");
    let signer = f.signer();
    let hash = "a".repeat(64);
    let inputs = f.inputs().verity(b"synthetic verity", &hash);
    let staged = stage_bundle_at(&inputs, &signer, clock()).unwrap();
    std::fs::write(&f.out, b"preexisting destination").unwrap();
    assert!(staged.publish().is_err());
    assert_eq!(std::fs::read(&f.out).unwrap(), b"preexisting destination");
    std::fs::remove_file(&f.out).unwrap();
    let before: std::collections::BTreeSet<_> = std::fs::read_dir(f.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let staged = stage_bundle_at(&inputs, &signer, clock()).unwrap();
    let error = staged.abort(anyhow::anyhow!("post-seal producer refusal"));
    assert!(format!("{error:#}").contains("post-seal producer refusal"));
    assert!(!f.out.exists());
    let after: std::collections::BTreeSet<_> = std::fs::read_dir(f.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
}

#[test]
fn raw_root_hash_reserved_member_refuses_duplicate_names_and_paths() {
    let raw = format!("{}\n", "a".repeat(64)).into_bytes();
    let mut contents = BundleContents::default();
    contents
        .push("rootfs.roothash", ArtifactRole::Other, raw.clone())
        .unwrap();
    assert!(
        contents
            .push("rootfs.roothash", ArtifactRole::Other, raw.clone())
            .is_err()
    );
    let mut contents = BundleContents::default();
    contents.artifacts.push(BundleArtifact {
        name: "path-alias".into(),
        role: ArtifactRole::Other,
        path: "artifacts/rootfs.roothash".into(),
        sha256: sha256_hex(&raw),
        size_bytes: 65,
    });
    assert!(
        contents
            .push_verity(Some(b"synthetic verity"), Some(&"a".repeat(64)))
            .is_err()
    );
}

#[test]
fn omitted_or_mixed_closure_refuses_before_any_signer_call() {
    let f = Fixture::new(b"kernel");
    let signer = f.signer();
    let files = f.files();
    let mut inputs = f.inputs();
    inputs.canonical_linux_proof = Some(f.proof());
    assert!(export_bundle_at(&inputs, &signer, clock()).is_err());
    inputs.cli_boot_assets = Some(CliBootAssetsInputs {
        manifest_bytes: published::MANIFEST,
        manifest_sha256: f.root.root().manifest_sha256(),
        runtime: &f.runtime,
        artifacts: &files,
    });
    inputs.boot_assets = Some(crate::BootAssetsInputs {
        manifest_bytes: published::MANIFEST,
        manifest_sha256: f.root.root().manifest_sha256(),
        runtime_overlay: &f.paths[4].1,
        initramfs: &f.paths[6].1,
    });
    assert!(export_bundle_at(&inputs, &signer, clock()).is_err());
    assert_eq!(signer.calls.get(), 0);
    assert!(!f.out.exists());
}

#[test]
fn coherent_kernel_and_linux_manifest_substitution_refuses_before_signing() {
    let kernel = b"application replacement";
    let f = Fixture::new(kernel);
    let mut manifest: ImageSetManifest = serde_json::from_slice(published::MANIFEST).unwrap();
    let selected = manifest
        .members
        .iter_mut()
        .find(|m| {
            m.role
                == mvm_core::image_set::ImageSetRole::WorkloadKernel(
                    mvm_core::image_set::WorkloadImageProfile::DefaultTenant,
                )
                && m.target.admits(GuestArch::host())
                && m.build_mode.is_none()
        })
        .unwrap();
    selected.artifacts[0].sha256 = Sha256Hex::from_bytes(kernel);
    selected.artifacts[0].size = kernel.len() as u64;
    let bytes = serde_json::to_vec(&manifest).unwrap();
    let digest = Sha256Hex::from_bytes(&bytes);
    let files = f.files();
    let mut inputs = f.inputs();
    inputs.cli_boot_assets = Some(CliBootAssetsInputs {
        manifest_bytes: &bytes,
        manifest_sha256: &digest,
        runtime: &f.runtime,
        artifacts: &files,
    });
    inputs.canonical_linux_proof = Some(f.proof());
    let signer = f.signer();
    let error = export_bundle_at(&inputs, &signer, clock()).unwrap_err();
    assert!(
        format!("{error:#}").contains("differs from the selected Linux"),
        "{error:#}"
    );
    assert_eq!(signer.calls.get(), 0);
    assert!(!f.out.exists());
}

#[test]
fn expired_retained_feed_adds_no_payload() {
    let f = Fixture::new(b"kernel");
    let files = f.files();
    let boot = CliBootAssetsInputs {
        manifest_bytes: published::MANIFEST,
        manifest_sha256: f.root.root().manifest_sha256(),
        runtime: &f.runtime,
        artifacts: &files,
    };
    let mut contents = BundleContents::default();
    assert!(
        contents
            .push_canonical_linux_proof(&f.proof(), &boot, "2026-12-01T00:00:00Z".parse().unwrap())
            .is_err()
    );
    assert!(contents.artifacts.is_empty());
    assert!(contents.payload.is_empty());
}

#[test]
#[ignore = "requires pinned public kernel in MVM_TEST_CANONICAL_KERNEL; no runtime or native proof"]
fn originals_survive_canonical_export_and_signature_verification() {
    let kernel = std::fs::read(std::env::var_os("MVM_TEST_CANONICAL_KERNEL").unwrap()).unwrap();
    let f = Fixture::new(&kernel);
    let files = f.files();
    let mut inputs = f.inputs();
    inputs.cli_boot_assets = Some(CliBootAssetsInputs {
        manifest_bytes: published::MANIFEST,
        manifest_sha256: f.root.root().manifest_sha256(),
        runtime: &f.runtime,
        artifacts: &files,
    });
    inputs.canonical_linux_proof = Some(f.proof());
    let signer = f.signer();
    export_bundle_at(&inputs, &signer, clock()).unwrap();
    let bytes = std::fs::read(&f.out).unwrap();
    let verified = mvm_core::plan::bundle::read_and_verify_bundle(&bytes, &signer).unwrap();
    assert_eq!(verified.manifest.schema_version, 7);
    for (name, expected) in [
        (BOOT_MANIFEST_NAME, published::MANIFEST),
        (LINUX_SIGNATURE_NAME, published::BUNDLE),
        (REVOCATIONS_NAME, FEED),
        (REVOCATIONS_SIGNATURE_NAME, SIGNATURE),
    ] {
        let artifact = verified.manifest.find_by_name(name).unwrap();
        assert_eq!(artifact.sha256, sha256_hex(expected));
        assert_eq!(verified.artifacts[&artifact.path], expected);
    }
    assert!(f.directory.path().exists());
}
