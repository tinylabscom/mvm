//! Offline publisher proof for an accepted image-set root, never member bytes.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{ConsumerProtocols, ImageSetVerification, VerifiedImageSetRoot, verify_image_set_root};
use crate::image_set::{HostProtocolSupport, ImageLock, ImageSetRequirement};
use crate::packs::PackRevocationChecker;
use crate::util::atomic_io::{FileLock, atomic_write_durable, atomic_write_new, is_already_exists};

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

/// Owns the original bytes authenticated by one root-cache read.
///
/// This is root evidence, not selected-kernel custody or launch permission.
/// Exporters can retain these exact bytes instead of re-reading a mutable
/// cache path or reserializing the parsed manifest. Consumers must reverify
/// them against their own compiled lock and current revocation policy.
/// Construction and deserialization are deliberately not public.
///
/// ```compile_fail
/// let _: mvm_core::image_set::RetainedImageSetRootProof =
///     serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug)]
pub struct RetainedImageSetRootProof {
    root: VerifiedImageSetRoot,
    manifest: Vec<u8>,
    signature_bundle: Vec<u8>,
}

impl RetainedImageSetRootProof {
    pub fn root(&self) -> &VerifiedImageSetRoot {
        &self.root
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
    }

    pub fn signature_bundle(&self) -> &[u8] {
        &self.signature_bundle
    }
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
/// An existing entry that still authenticates is kept; a missing entry is
/// created no-clobber. A partial or corrupt entry no longer blocks
/// acquisition: the already-authenticated incoming proof replaces it under a
/// per-entry lock, so one damaged file cannot fail later valid acquisitions
/// until an operator removes it. Only authenticated content is ever written —
/// an incoming proof is verified before any collision handling — and the read
/// path never repairs: readers must reverify under their current lock and
/// admission policy.
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
            if cached_proof_authentic(&path, request) {
                return Ok(());
            }
            repair_image_set_root_proof(&path, request, &bytes)
        }
        Err(error) => Err(error).context("publish image-set publisher proof"),
    }
}

/// Reverify the cached entry under the caller's current lock, requirement,
/// host protocols, and revocation policy. `false` means missing, unreadable,
/// or inauthentic — anything short of a confirmed-authentic entry.
fn cached_proof_authentic(path: &Path, request: &ImageSetVerification<'_>) -> bool {
    let Ok(existing) = read_proof(path) else {
        return false;
    };
    let existing_request = ImageSetVerification {
        manifest_bytes: existing.manifest.as_bytes(),
        signature_bundle: existing.signature_bundle.as_bytes(),
        ..*request
    };
    verify_image_set_root(&existing_request).is_ok()
}

/// Replace a corrupt entry with an already-authenticated proof, serialized
/// against other cooperating writers. The entry is rechecked under the lock
/// so a concurrent repair is not clobbered, and the final on-disk content is
/// reverified before success is reported; the lock only serializes callers of
/// this API, so that closing check is what keeps a non-cooperating writer
/// from turning a reported success into a poisoned cache.
fn repair_image_set_root_proof(
    path: &Path,
    request: &ImageSetVerification<'_>,
    authenticated: &[u8],
) -> Result<()> {
    let _guard =
        FileLock::acquire(path).context("lock image-set publisher proof for cache repair")?;
    if cached_proof_authentic(path, request) {
        return Ok(());
    }
    atomic_write_durable(path, authenticated).context("repair image-set publisher proof")?;
    ensure!(
        cached_proof_authentic(path, request),
        "repaired image-set publisher proof failed re-verification"
    );
    Ok(())
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
    Ok(read_cached_image_set_root_proof(cache, lock, host, revocations)?.root)
}

/// Reverify a bounded, no-follow cache read and retain its original proof.
///
/// Applies the same root, completeness, protocol and supplied revocation
/// checks as [`read_cached_image_set_root`]. `None` does not establish current
/// revocation evidence; a workflow requiring it must supply its actual
/// admission policy. Neither entry point authenticates kernel member bytes.
pub fn read_cached_image_set_root_proof(
    cache: &Path,
    lock: &ImageLock,
    host: &HostProtocolSupport,
    revocations: Option<&dyn PackRevocationChecker>,
) -> Result<RetainedImageSetRootProof> {
    read_cached_root_proof(cache, lock, ConsumerProtocols::AllImages(host), revocations)
}

/// Read a workload-only root with the same checks as
/// [`read_cached_workload_image_set_root_proof`]. Member selection and byte
/// verification remain the caller's obligation.
pub fn read_cached_workload_image_set_root(
    cache: &Path,
    lock: &ImageLock,
    host: &HostProtocolSupport,
    revocations: Option<&dyn PackRevocationChecker>,
) -> Result<VerifiedImageSetRoot> {
    Ok(read_cached_workload_image_set_root_proof(cache, lock, host, revocations)?.root)
}

/// Reverify the complete signed root for a workload-only consumer.
///
/// Preserves all trust, lock, completeness and supplied revocation checks, but
/// does not require builder cache or payload support. Callers must select and
/// verify consumed members for their backend and architecture; this proof does
/// not authorize builder execution.
pub fn read_cached_workload_image_set_root_proof(
    cache: &Path,
    lock: &ImageLock,
    host: &HostProtocolSupport,
    revocations: Option<&dyn PackRevocationChecker>,
) -> Result<RetainedImageSetRootProof> {
    read_cached_root_proof(cache, lock, ConsumerProtocols::Workload(host), revocations)
}

fn read_cached_root_proof(
    cache: &Path,
    lock: &ImageLock,
    protocols: ConsumerProtocols<'_>,
    revocations: Option<&dyn PackRevocationChecker>,
) -> Result<RetainedImageSetRootProof> {
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
    .require(&requirement);
    request = match protocols {
        ConsumerProtocols::AllImages(host) => request.with_host_protocols(host),
        ConsumerProtocols::Workload(host) => request.with_workload_protocols(host),
    };
    if let Some(revocations) = revocations {
        request = request.with_revocations(revocations);
    }
    let root =
        verify_image_set_root(&request).context("reverify cached image-set publisher proof")?;
    Ok(RetainedImageSetRootProof {
        root,
        manifest: proof.manifest.into_bytes(),
        signature_bundle: proof.signature_bundle.into_bytes(),
    })
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
pub(crate) mod published_root;

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned set was published while the image repository still built
    /// the guest runtime, so it lists an overlay, two sidecars and an
    /// initramfs per architecture. A CLI that no longer requires them must
    /// still read that signed set: every one parses as a retired role, the set
    /// is complete without them, and the Linux layer selects as before.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn the_pinned_set_still_listing_the_guest_runtime_parses_complete_with_it_retired() {
        use crate::arch::GuestArch;
        use crate::image_set::{
            BackendImageSupport, ImageSetManifest, ImageSetRole, RetiredGuestRuntimeRole,
            WorkloadImageProfile, require_complete, select_workload_image, validate_structure,
        };
        use crate::vm_backend::BackendKind;
        use mvm_contract::guest_libc::GuestLibc;

        let manifest: ImageSetManifest = serde_json::from_slice(published_root::MANIFEST).unwrap();
        validate_structure(&manifest).unwrap();
        require_complete(&manifest, &ImageSetRequirement::current_train()).unwrap();
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            for retired in [
                RetiredGuestRuntimeRole::RuntimeOverlay,
                RetiredGuestRuntimeRole::SdkSidecar(GuestLibc::Glibc),
                RetiredGuestRuntimeRole::SdkSidecar(GuestLibc::Musl),
                RetiredGuestRuntimeRole::Initramfs,
            ] {
                assert!(
                    manifest.members.iter().any(|member| member.role
                        == ImageSetRole::RetiredGuestRuntime(retired)
                        && member.target.admits(arch)),
                    "{retired} for {arch}"
                );
            }
            let support = BackendImageSupport::for_backend(BackendKind::Firecracker).unwrap();
            let workload = select_workload_image(
                &manifest,
                WorkloadImageProfile::DefaultTenant,
                arch,
                &support,
            )
            .unwrap();
            assert!(!workload.kernel.role.is_retired() && !workload.rootfs.role.is_retired());
        }
        // The signed bytes re-serialize to an equal manifest, so nothing about
        // reading the retired members loses what the root digest covers.
        let again: ImageSetManifest =
            serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();
        assert_eq!(again, manifest);
    }

    /// Reads only vendored public release files. No network is used by the
    /// test or cache APIs; this witnesses root authentication, not member boot.
    #[cfg(feature = "manifest-verify")]
    #[test]
    fn published_root_roundtrips_offline_and_reverifies_collisions() {
        use crate::image_set::{
            ArtifactName, BuilderBootAbiRange, ReleaseTag, RepositorySlug, SigningIdentity, TagRef,
            WorkflowPath,
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
            base_image_contract: crate::image_set::BaseImageContractRange::SUPPORTED,
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
        let retained = read_cached_image_set_root_proof(cache.path(), &lock, &host, None).unwrap();
        assert_eq!(retained.root(), &root);
        assert_eq!(retained.manifest_bytes(), manifest);
        assert_eq!(retained.signature_bundle(), bundle);
        let workload_host = HostProtocolSupport {
            builder_boot_abi: BuilderBootAbiRange::LEGACY_ONLY,
            ..host
        };
        assert!(matches!(
            verify_image_set_root(&request.with_host_protocols(&workload_host)),
            Err(crate::image_set::ImageSetError::BuilderBootAbiUnsupported { .. })
        ));
        let workload_request = request.with_workload_protocols(&workload_host);
        let workload_root = verify_image_set_root(&workload_request).unwrap();
        let support =
            crate::image_set::BackendImageSupport::for_backend(crate::vm_backend::BackendKind::Hvf)
                .unwrap();
        crate::image_set::select_workload_image(
            workload_root.manifest(),
            crate::image_set::WorkloadImageProfile::DefaultTenant,
            crate::arch::GuestArch::Aarch64,
            &support,
        )
        .unwrap();
        assert!(
            crate::image_set::select_workload_image(
                workload_root.manifest(),
                crate::image_set::WorkloadImageProfile::DefaultTenant,
                crate::arch::GuestArch::X86_64,
                &support,
            )
            .is_err()
        );
        let wrong_base_host = HostProtocolSupport {
            base_image_contract: crate::image_set::BaseImageContractRange::new(
                crate::image_set::BaseImageContract::new(99),
                crate::image_set::BaseImageContract::new(99),
            )
            .unwrap(),
            ..workload_host
        };
        assert!(verify_image_set_root(&request.with_workload_protocols(&wrong_base_host)).is_err());
        let workload_cached =
            read_cached_workload_image_set_root_proof(cache.path(), &lock, &workload_host, None)
                .unwrap();
        assert_eq!(workload_cached.root(), &root);
        assert_eq!(
            read_cached_workload_image_set_root(cache.path(), &lock, &workload_host, None).unwrap(),
            root
        );
        assert!(
            read_cached_workload_image_set_root_proof(cache.path(), &lock, &wrong_base_host, None)
                .is_err()
        );
        assert!(
            read_cached_image_set_root_proof(cache.path(), &lock, &workload_host, None,).is_err()
        );
        let unrelated_cache_host = HostProtocolSupport {
            builder_cache_contract: 999,
            ..workload_host
        };
        assert!(
            read_cached_workload_image_set_root_proof(
                cache.path(),
                &lock,
                &unrelated_cache_host,
                None,
            )
            .is_ok()
        );
        struct Revoked;
        impl PackRevocationChecker for Revoked {
            fn status(
                &self,
                _: &crate::plan::KeyId,
                _: &crate::packs::Sha256Hex,
            ) -> crate::packs::RevocationStatus {
                crate::packs::RevocationStatus::Revoked {
                    reason: "test withdrawal".into(),
                }
            }
        }
        assert!(
            read_cached_image_set_root_proof(cache.path(), &lock, &host, Some(&Revoked)).is_err()
        );
        assert!(
            read_cached_workload_image_set_root_proof(
                cache.path(),
                &lock,
                &workload_host,
                Some(&Revoked),
            )
            .is_err()
        );
        assert!(verify_image_set_root(&workload_request.with_revocations(&Revoked)).is_err());
        cache_image_set_root(cache.path(), &request).expect("an authentic collision re-verifies");

        let path = proof_path(cache.path(), &lock);
        let original = std::fs::read(&path).unwrap();
        let mut poisoned: RootProof = serde_json::from_slice(&original).unwrap();
        poisoned.signature_bundle = "{}".into();
        let poison = serde_json::to_vec(&poisoned).unwrap();
        std::fs::write(&path, &poison).unwrap();
        assert!(read_cached_image_set_root(cache.path(), &lock, &host, None).is_err());
        assert!(read_cached_image_set_root_proof(cache.path(), &lock, &host, None).is_err());
        assert!(
            read_cached_workload_image_set_root_proof(cache.path(), &lock, &workload_host, None,)
                .is_err()
        );
        // An already captured proof owns the exact authenticated originals,
        // not a path to the subsequently poisoned cache entry.
        assert_eq!(retained.manifest_bytes(), manifest);
        assert_eq!(retained.signature_bundle(), bundle);
        let bad = ImageSetVerification::new(b"{}", b"{}", &lock, cache.path());
        assert!(cache_image_set_root(cache.path(), &bad).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            poison,
            "an unauthenticated incoming proof never replaces an entry"
        );
        cache_image_set_root(cache.path(), &request).expect("an authentic collision repairs");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        read_cached_image_set_root(cache.path(), &lock, &host, None)
            .expect("the repaired entry reverifies offline");

        poisoned = serde_json::from_slice(&original).unwrap();
        poisoned.manifest.push(' ');
        std::fs::write(&path, serde_json::to_vec(&poisoned).unwrap()).unwrap();
        assert!(read_cached_image_set_root(cache.path(), &lock, &host, None).is_err());
        cache_image_set_root(cache.path(), &request).expect("a tampered manifest is repaired");
        assert_eq!(std::fs::read(&path).unwrap(), original);

        std::fs::write(&path, &original).unwrap();
        let mut wrong_signer = lock.clone();
        wrong_signer.signing_identity.workflow =
            WorkflowPath::new(".github/workflows/wrong.yml").unwrap();
        assert!(read_cached_image_set_root(cache.path(), &wrong_signer, &host, None).is_err());
        assert!(
            read_cached_workload_image_set_root_proof(
                cache.path(),
                &wrong_signer,
                &workload_host,
                None,
            )
            .is_err()
        );
        let mut moved_lock = lock.clone();
        moved_lock.manifest_sha256 = Sha256Hex::from_bytes(b"another accepted root");
        assert!(read_cached_image_set_root(cache.path(), &moved_lock, &host, None).is_err());
        assert!(
            read_cached_workload_image_set_root_proof(
                cache.path(),
                &moved_lock,
                &workload_host,
                None,
            )
            .is_err()
        );
    }

    #[cfg(feature = "host-state")]
    #[test]
    fn public_cache_boundaries_refuse_unsigned_or_wrong_root_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let train = crate::image_set::image_train_lock();
        let host = HostProtocolSupport {
            base_image_contract: crate::image_set::BaseImageContractRange::SUPPORTED,
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

    #[cfg(all(feature = "manifest-verify", feature = "host-state"))]
    #[test]
    fn application_resigning_cannot_authorize_replaced_kernel_and_linux_json() {
        use crate::image_set::{ImageSetManifest, ImageSetRole, WorkloadImageProfile};
        use crate::plan::bundle::{
            ArtifactRole, BundleArtifact, BundleManifest, KeyId, TrustStore, key_id_from_pubkey,
            read_and_verify_bundle, sha256_hex, write_bundle,
        };
        use ed25519_dalek::{SigningKey, VerifyingKey};

        let kernel = b"replacement kernel controlled by an application publisher".to_vec();
        let mut linux: ImageSetManifest = serde_json::from_slice(published_root::MANIFEST).unwrap();
        let member = linux
            .members
            .iter_mut()
            .find(|member| {
                member.role == ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant)
                    && member.target.admits(crate::arch::GuestArch::host())
            })
            .unwrap();
        member.artifacts[0].sha256 = crate::packs::Sha256Hex::from_bytes(&kernel);
        member.artifacts[0].size = kernel.len() as u64;
        crate::image_set::validate_structure(&linux).unwrap();
        let changed_json = serde_json::to_vec(&linux).unwrap();
        let app_key = SigningKey::from_bytes(&[53; 32]);
        struct AppTrust(VerifyingKey);
        impl TrustStore for AppTrust {
            fn lookup(&self, id: &KeyId) -> Option<VerifyingKey> {
                (id == &key_id_from_pubkey(&self.0)).then_some(self.0)
            }
        }
        let payload = vec![
            ("artifacts/vmlinux".to_owned(), kernel),
            ("artifacts/linux.json".to_owned(), changed_json.clone()),
            (
                "artifacts/linux.bundle".to_owned(),
                published_root::BUNDLE.to_vec(),
            ),
        ];
        let manifest = BundleManifest {
            schema_version: 3,
            publisher: "application-only".into(),
            key_id: key_id_from_pubkey(&app_key.verifying_key()),
            arch: crate::arch::GuestArch::host().to_string(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-10-16T00:00:00Z".into(),
            labels: Default::default(),
            members: Vec::new(),
            verity: None,
            resources: None,
            artifacts: payload
                .iter()
                .map(|(path, bytes)| BundleArtifact {
                    name: path.strip_prefix("artifacts/").unwrap().to_owned(),
                    role: if path.ends_with("/vmlinux") {
                        ArtifactRole::Kernel
                    } else {
                        ArtifactRole::Other
                    },
                    path: path.clone(),
                    sha256: sha256_hex(bytes),
                    size_bytes: bytes.len() as u64,
                })
                .collect(),
        };
        let archive = write_bundle(&manifest, &app_key, payload).unwrap();
        let app = read_and_verify_bundle(&archive, &AppTrust(app_key.verifying_key())).unwrap();
        // Outer signature and all replaced artifact digests really verify.
        // They do not replace the independent, compiled Linux publisher pin.
        assert_eq!(app.artifacts["artifacts/linux.json"], changed_json);
        let cache = tempfile::tempdir().unwrap();
        let train = crate::image_set::image_train_lock();
        let forged = RootProof {
            manifest: String::from_utf8(app.artifacts["artifacts/linux.json"].clone()).unwrap(),
            signature_bundle: String::from_utf8(app.artifacts["artifacts/linux.bundle"].clone())
                .unwrap(),
        };
        std::fs::write(
            proof_path(cache.path(), &train.image_set),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        let host = HostProtocolSupport {
            base_image_contract: crate::image_set::BaseImageContractRange::SUPPORTED,
            builder_cache_contract: train.compatibility.builder_cache_contract,
            builder_boot_abi: crate::image_set::BuilderBootAbiRange::WITH_PAYLOAD,
        };
        let error = read_cached_image_set_root_proof(cache.path(), &train.image_set, &host, None)
            .expect_err("application signing must not replace canonical Linux authority");
        assert!(
            error
                .chain()
                .any(|error| error.to_string().contains("digest"))
        );
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
