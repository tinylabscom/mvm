//! Offline publisher proof for an accepted image-set root, never member bytes.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{ImageSetVerification, VerifiedImageSetRoot, verify_image_set_root};
use crate::image_set::{HostProtocolSupport, ImageLock, ImageSetRequirement};
use crate::packs::PackRevocationChecker;
use crate::util::atomic_io::{atomic_write_new, is_already_exists};

const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
// JSON string escaping can expand each byte to six bytes.
const MAX_PROOF_BYTES: usize = 6 * (MAX_MANIFEST_BYTES + MAX_BUNDLE_BYTES) + 128;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootProof {
    manifest: String,
    signature_bundle: String,
}

impl RootProof {
    fn check_size(&self) -> Result<()> {
        ensure!(
            !self.manifest.is_empty() && self.manifest.len() <= MAX_MANIFEST_BYTES,
            "image-set proof manifest is empty or exceeds its size limit"
        );
        ensure!(
            !self.signature_bundle.is_empty() && self.signature_bundle.len() <= MAX_BUNDLE_BYTES,
            "image-set proof signature bundle is empty or exceeds its size limit"
        );
        Ok(())
    }
}

/// Where publisher proofs for accepted image-set roots live. These are not the
/// bundle-authenticated embedded-image cache or the unsigned member records.
pub fn image_set_root_proof_cache() -> PathBuf {
    PathBuf::from(crate::config::mvm_cache_dir()).join("image-set-proofs")
}

fn proof_path(cache: &Path, lock: &ImageLock) -> PathBuf {
    cache.join(format!("{}.json", lock.manifest_sha256.as_str()))
}

/// Authenticate and atomically publish the exact manifest/signature pair.
///
/// An existing entry is never replaced, including a partial or corrupt entry.
/// Readers must reverify under their current lock and admission policy.
pub fn cache_image_set_root(cache: &Path, request: &ImageSetVerification<'_>) -> Result<()> {
    ensure!(
        request.manifest_bytes.len() <= MAX_MANIFEST_BYTES
            && request.signature_bundle.len() <= MAX_BUNDLE_BYTES,
        "image-set publisher proof exceeds its size limit"
    );
    let proof = RootProof {
        manifest: std::str::from_utf8(request.manifest_bytes)?.to_owned(),
        signature_bundle: std::str::from_utf8(request.signature_bundle)?.to_owned(),
    };
    proof.check_size()?;
    verify_image_set_root(request).context("authenticate image-set root before caching")?;
    let bytes = serde_json::to_vec(&proof)?;
    let path = proof_path(cache, request.lock);
    match atomic_write_new(&path, &bytes) {
        Ok(()) => Ok(()),
        Err(error) if is_already_exists(&error) => {
            let existing = read_proof(&path)?;
            let existing_request = ImageSetVerification {
                manifest_bytes: existing.manifest.as_bytes(),
                signature_bundle: existing.signature_bundle.as_bytes(),
                ..*request
            };
            verify_image_set_root(&existing_request)
                .context("existing image-set publisher proof failed re-verification")?;
            Ok(())
        }
        Err(error) => Err(error).context("publish image-set publisher proof"),
    }
}

/// Read a prepared proof with no network or developer fallback.
///
/// The current lock, complete publication, host protocols, and any supplied
/// revocation policy are rechecked. This authenticates only the root: callers
/// still have to select and hash every member artifact they will boot.
pub fn read_cached_image_set_root(
    cache: &Path,
    lock: &ImageLock,
    host: &HostProtocolSupport,
    revocations: Option<&dyn PackRevocationChecker>,
) -> Result<VerifiedImageSetRoot> {
    let path = proof_path(cache, lock);
    let proof = read_proof(&path).with_context(|| {
        format!(
            "accepted image-set publisher proof is missing or unusable at {}; prepare the accepted published image set before offline boot",
            path.display()
        )
    })?;
    let requirement = ImageSetRequirement::current_train();
    let mut request = ImageSetVerification::new(
        proof.manifest.as_bytes(),
        proof.signature_bundle.as_bytes(),
        lock,
        cache,
    )
    .require(&requirement)
    .with_host_protocols(host);
    if let Some(revocations) = revocations {
        request = request.with_revocations(revocations);
    }
    verify_image_set_root(&request).context("reverify cached image-set publisher proof")
}

fn read_proof(path: &Path) -> Result<RootProof> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "image-set publisher proof is not a regular file"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "image-set publisher proof is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_PROOF_BYTES as u64,
        "image-set publisher proof exceeds its size limit"
    );
    let mut bytes = Vec::new();
    file.take(MAX_PROOF_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_PROOF_BYTES,
        "image-set publisher proof grew beyond its size limit"
    );
    let proof: RootProof = serde_json::from_slice(&bytes)?;
    proof.check_size()?;
    Ok(proof)
}

#[cfg(all(test, feature = "manifest-verify"))]
#[path = "fixtures/published_root.rs"]
mod published_root;

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads only vendored public release files. No network is used by the
    /// test or cache APIs; this witnesses root authentication, not member boot.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn published_root_roundtrips_offline_and_reverifies_collisions() {
        use crate::image_set::{
            ArtifactName, BuilderBootAbiRange, ProtocolRange, ReleaseTag, RepositorySlug,
            SigningIdentity, TagRef, WorkflowPath,
        };
        use crate::packs::Sha256Hex;

        let manifest = published_root::MANIFEST;
        let bundle = published_root::BUNDLE;
        assert_eq!(manifest.len(), 17_784);
        assert_eq!(bundle.len(), 10_455);
        assert_eq!(
            Sha256Hex::from_bytes(manifest).as_str(),
            "5033520a59514f5d206d76d13db8c9b7e5841f068c83dd8585ef141879a1bb24"
        );
        assert_eq!(
            Sha256Hex::from_bytes(bundle).as_str(),
            "15962832c1e665f7e9cfa3fca9179f01db908201805fd773cfd8eca66d542ac8"
        );
        let tag = ReleaseTag::new("image-set/v0.2.4").unwrap();
        let lock = ImageLock {
            schema_version: crate::image_set::IMAGE_LOCK_SCHEMA_VERSION,
            repository: RepositorySlug::new("tinylabscom/mvm-images").unwrap(),
            release_tag: tag.clone(),
            manifest_asset: ArtifactName::new("image-set.json").unwrap(),
            manifest_sha256: Sha256Hex::new(
                "5033520a59514f5d206d76d13db8c9b7e5841f068c83dd8585ef141879a1bb24",
            )
            .unwrap(),
            signing_identity: SigningIdentity {
                workflow: WorkflowPath::new(".github/workflows/release.yml").unwrap(),
                tag_ref: TagRef::for_tag(&tag),
            },
        };
        let host = HostProtocolSupport {
            guest_agent_protocol: ProtocolRange::new(2, 2).unwrap(),
            builder_cache_contract: 5,
            builder_boot_abi: BuilderBootAbiRange::WITH_PAYLOAD,
        };
        let cache = tempfile::tempdir().unwrap();
        let requirement = ImageSetRequirement::current_train();
        let request = ImageSetVerification::new(manifest, bundle, &lock, cache.path())
            .require(&requirement)
            .with_host_protocols(&host);
        cache_image_set_root(cache.path(), &request).unwrap();
        let root = read_cached_image_set_root(cache.path(), &lock, &host, None).unwrap();
        assert_eq!(root.manifest_sha256(), &lock.manifest_sha256);
        cache_image_set_root(cache.path(), &request).expect("an authentic collision re-verifies");

        let path = proof_path(cache.path(), &lock);
        let original = std::fs::read(&path).unwrap();
        let mut poisoned: RootProof = serde_json::from_slice(&original).unwrap();
        poisoned.signature_bundle = "{}".into();
        let poison = serde_json::to_vec(&poisoned).unwrap();
        std::fs::write(&path, &poison).unwrap();
        assert!(read_cached_image_set_root(cache.path(), &lock, &host, None).is_err());
        assert!(cache_image_set_root(cache.path(), &request).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            poison,
            "poison is not overwritten"
        );

        poisoned = serde_json::from_slice(&original).unwrap();
        poisoned.manifest.push(' ');
        std::fs::write(&path, serde_json::to_vec(&poisoned).unwrap()).unwrap();
        assert!(read_cached_image_set_root(cache.path(), &lock, &host, None).is_err());
        assert!(cache_image_set_root(cache.path(), &request).is_err());

        std::fs::write(&path, &original).unwrap();
        let mut wrong_signer = lock.clone();
        wrong_signer.signing_identity.workflow =
            WorkflowPath::new(".github/workflows/wrong.yml").unwrap();
        assert!(read_cached_image_set_root(cache.path(), &wrong_signer, &host, None).is_err());
        let mut moved_lock = lock.clone();
        moved_lock.manifest_sha256 = Sha256Hex::from_bytes(b"another accepted root");
        assert!(read_cached_image_set_root(cache.path(), &moved_lock, &host, None).is_err());
    }

    #[test]
    fn public_cache_boundaries_refuse_unsigned_or_wrong_root_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let train = crate::image_set::image_train_lock();
        let host = HostProtocolSupport {
            guest_agent_protocol: train.compatibility.guest_agent_protocol,
            builder_cache_contract: train.compatibility.builder_cache_contract,
            builder_boot_abi: crate::image_set::BuilderBootAbiRange::WITH_PAYLOAD,
        };
        assert!(read_cached_image_set_root(dir.path(), &train.image_set, &host, None).is_err());
        let bytes = b"{}";
        let request = ImageSetVerification::new(bytes, bytes, &train.image_set, dir.path());
        assert!(cache_image_set_root(dir.path(), &request).is_err());
        assert!(!proof_path(dir.path(), &train.image_set).exists());

        let proof = RootProof {
            manifest: "{}".into(),
            signature_bundle: "{}".into(),
        };
        std::fs::write(
            proof_path(dir.path(), &train.image_set),
            serde_json::to_vec(&proof).unwrap(),
        )
        .unwrap();
        let error = read_cached_image_set_root(dir.path(), &train.image_set, &host, None)
            .expect_err("the path's digest does not establish authenticity");
        assert!(error.chain().any(|e| e.to_string().contains("digest")));
    }

    #[test]
    fn proof_preserves_exact_signed_bytes_in_one_atomic_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof");
        let proof = RootProof {
            manifest: " {\"x\":1}\n".into(),
            signature_bundle: "{\"signature\":\"abc\"}\n".into(),
        };
        atomic_write_new(&path, &serde_json::to_vec(&proof).unwrap()).unwrap();
        let read = read_proof(&path).unwrap();
        assert_eq!(read.manifest, proof.manifest);
        assert_eq!(read.signature_bundle, proof.signature_bundle);
        assert!(atomic_write_new(&path, b"replacement").is_err());
        assert_eq!(read_proof(&path).unwrap().manifest, proof.manifest);
    }

    #[test]
    fn proof_reader_refuses_missing_partial_empty_and_oversized_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof");
        assert!(read_proof(&path).is_err());
        for bytes in [
            b"{".to_vec(),
            br#"{"manifest":"{}"}"#.to_vec(),
            br#"{"manifest":"","signature_bundle":"{}"}"#.to_vec(),
            serde_json::to_vec(&RootProof {
                manifest: "x".repeat(MAX_MANIFEST_BYTES + 1),
                signature_bundle: "{}".into(),
            })
            .unwrap(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(read_proof(&path).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn proof_reader_refuses_symlinks_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proof");
        std::os::unix::fs::symlink(dir.path().join("missing"), &path).unwrap();
        assert!(read_proof(&path).is_err());
        assert!(read_proof(dir.path()).is_err());
    }
}
