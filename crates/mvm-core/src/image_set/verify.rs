//! Verify one published image set against the lock that pins it.
//!
//! Everything here is offline: the manifest bytes, the detached signature over
//! them, and the member artifacts are all already on disk. Nothing is fetched,
//! so a verification outcome never depends on what a network answered.
//!
//! The stage order is the point of the module. Manifest bytes are untrusted
//! until they are proven to be the bytes the lock pins *and* the bytes the
//! release workflow signed, so:
//!
//! 1. the raw bytes are hashed and compared to the lock's pinned digest, before
//!    anything parses them — which refuses tampering and replay of an older,
//!    validly signed set in the same step;
//! 2. the detached signature over those same raw bytes is checked against the
//!    identity the lock names;
//! 3. only then is the JSON parsed;
//! 4. the parsed manifest is checked for internal consistency and against the
//!    lock's own fields;
//! 5. every member artifact is checked on disk, by size and by digest;
//! 6. the set digest and every member pack hash are checked for revocation.
//!
//! A caller that wants the earlier stages without the later ones does not get
//! one: the entry point runs all of them, and the optional inputs only add
//! checks.

use std::io;
use std::path::{Path, PathBuf};

use super::validate::{check_lock_schema_version, check_manifest_digest};
use super::{
    ArtifactName, HostProtocolSupport, ImageLock, ImageSetError, ImageSetManifest, ImageSetMember,
    ImageSetRequirement, ImageSetRole, MemberArtifact, MemberTarget, check_against_lock,
    check_protocol_compatibility, require_complete, validate_structure,
};
use crate::crypto::image_verify::{sha256_file, verify_signed_payload_under_any_identity};
use crate::packs::{KeylessTrust, PackRevocationChecker, RevocationStatus, Sha256Hex};
use crate::plan::bundle::{KeyId, key_id_from_identity};

/// One image set to verify, and the optional policy inputs that add checks.
///
/// A params struct because four of the inputs are borrowed byte slices and
/// paths that would transpose silently, and because the optional three are what
/// a call site most wants to read at a glance.
#[derive(Clone, Copy)]
pub struct ImageSetVerification<'a> {
    /// The manifest exactly as published. Hashed before it is parsed.
    manifest_bytes: &'a [u8],
    /// The detached cosign bundle published beside the manifest.
    signature_bundle: &'a [u8],
    lock: &'a ImageLock,
    /// Directory holding the member artifacts, each under its declared name.
    artifact_dir: &'a Path,
    requirement: Option<&'a ImageSetRequirement>,
    host_protocols: Option<&'a HostProtocolSupport>,
    revocations: Option<&'a dyn PackRevocationChecker>,
}

impl<'a> ImageSetVerification<'a> {
    pub fn new(
        manifest_bytes: &'a [u8],
        signature_bundle: &'a [u8],
        lock: &'a ImageLock,
        artifact_dir: &'a Path,
    ) -> Self {
        Self {
            manifest_bytes,
            signature_bundle,
            lock,
            artifact_dir,
            requirement: None,
            host_protocols: None,
            revocations: None,
        }
    }

    /// Also refuse a set missing any member `requirement` names.
    #[must_use]
    pub fn require(mut self, requirement: &'a ImageSetRequirement) -> Self {
        self.requirement = Some(requirement);
        self
    }

    /// Also refuse a set declaring protocols this host cannot speak.
    #[must_use]
    pub fn with_host_protocols(mut self, host: &'a HostProtocolSupport) -> Self {
        self.host_protocols = Some(host);
        self
    }

    /// Also refuse a set, or a member, that `revocations` reports revoked.
    #[must_use]
    pub fn with_revocations(mut self, revocations: &'a dyn PackRevocationChecker) -> Self {
        self.revocations = Some(revocations);
        self
    }
}

/// What a verification established, for a caller that now wants to use the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedImageSet {
    pub manifest: ImageSetManifest,
    /// Digest of the bytes that were signed, and the key revocation is keyed on.
    pub manifest_sha256: Sha256Hex,
    /// Derived from the lock's signing identity, so it names who the set was
    /// accepted from rather than who it claims to be from.
    pub signer_key_id: KeyId,
    pub artifacts: Vec<VerifiedArtifact>,
}

/// One artifact found on disk with the digest and size its member declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub role: ImageSetRole,
    pub target: MemberTarget,
    pub name: ArtifactName,
    /// Where the bytes were read, so a caller boots the file that was checked
    /// rather than resolving the name a second time.
    pub path: PathBuf,
    pub sha256: Sha256Hex,
    pub size: u64,
}

/// Verify `request`'s image set, refusing at the first stage that fails.
pub fn verify_image_set(
    request: &ImageSetVerification<'_>,
) -> Result<VerifiedImageSet, ImageSetError> {
    verify_checked(request, check_keyless_signature)
}

/// How the detached signature over the manifest bytes is checked.
///
/// A parameter of [`verify_checked`] rather than a fixed call so the stages
/// after it stay reachable from a test: a cosign bundle cannot be minted
/// without the release workflow's signing identity, so a test that had to
/// satisfy the real check could never exercise the parse, lock, artifact or
/// revocation stages at all. It is deliberately not part of the public surface
/// — [`verify_image_set`] is the only entry point, and it always checks.
type SignatureChecker = fn(&[u8], &[u8], &KeylessTrust) -> Result<(), ImageSetError>;

pub(super) fn verify_checked(
    request: &ImageSetVerification<'_>,
    check_signature: SignatureChecker,
) -> Result<VerifiedImageSet, ImageSetError> {
    let lock = request.lock;
    check_lock_schema_version(lock)?;

    let manifest_sha256 = Sha256Hex::from_bytes(request.manifest_bytes);
    check_manifest_digest(&manifest_sha256, lock)?;
    check_signature(
        request.manifest_bytes,
        request.signature_bundle,
        &lock.keyless_trust(),
    )?;

    let manifest = parse_manifest(request.manifest_bytes)?;
    validate_structure(&manifest)?;
    check_against_lock(&manifest, &manifest_sha256, lock)?;
    if let Some(requirement) = request.requirement {
        require_complete(&manifest, requirement)?;
    }
    if let Some(host) = request.host_protocols {
        check_protocol_compatibility(&manifest, host)?;
    }

    let artifacts = verify_artifacts(&manifest, request.artifact_dir)?;
    let signer_key_id = locked_signer_key_id(lock);
    if let Some(revocations) = request.revocations {
        check_revocations(&manifest, &manifest_sha256, &signer_key_id, revocations)?;
    }

    Ok(VerifiedImageSet {
        manifest,
        manifest_sha256,
        signer_key_id,
        artifacts,
    })
}

/// Accept the manifest only if one of the lock's identities signed these exact
/// bytes under the release issuer.
fn check_keyless_signature(
    manifest_bytes: &[u8],
    signature_bundle: &[u8],
    trust: &KeylessTrust,
) -> Result<(), ImageSetError> {
    let identities: Vec<&str> = trust
        .accepted_identities
        .iter()
        .map(String::as_str)
        .collect();
    verify_signed_payload_under_any_identity(
        manifest_bytes,
        signature_bundle,
        &identities,
        &trust.issuer,
    )
    .map_err(|error| ImageSetError::SignatureInvalid {
        identity: identities.join(", "),
        reason: error.to_string(),
    })
}

fn parse_manifest(bytes: &[u8]) -> Result<ImageSetManifest, ImageSetError> {
    serde_json::from_slice(bytes).map_err(|error| ImageSetError::UnparseableManifest {
        reason: error.to_string(),
    })
}

/// The identity a revocation entry must key on to speak about this set. Taken
/// from the lock rather than the manifest, so revocation follows who the set
/// was accepted from.
fn locked_signer_key_id(lock: &ImageLock) -> KeyId {
    key_id_from_identity(&lock.signing_identity.certificate_identity(&lock.repository))
}

fn verify_artifacts(
    manifest: &ImageSetManifest,
    dir: &Path,
) -> Result<Vec<VerifiedArtifact>, ImageSetError> {
    let mut verified = Vec::new();
    for member in &manifest.members {
        for artifact in &member.artifacts {
            verified.push(verify_member_artifact(member, artifact, dir)?);
        }
    }
    Ok(verified)
}

/// Check one artifact's bytes. Size is compared first: it is a stat rather than
/// a read of the whole file, so a truncated multi-hundred-megabyte rootfs is
/// refused without hashing it.
fn verify_member_artifact(
    member: &ImageSetMember,
    artifact: &MemberArtifact,
    dir: &Path,
) -> Result<VerifiedArtifact, ImageSetError> {
    let path = dir.join(artifact.name.as_str());
    let size = artifact_size(member, artifact, &path)?;
    if size != artifact.size {
        return Err(ImageSetError::ArtifactSizeMismatch {
            role: member.role,
            target: member.target,
            name: artifact.name.clone(),
            declared: artifact.size,
            actual: size,
        });
    }
    let sha256 = artifact_digest(member, artifact, &path)?;
    if sha256 != artifact.sha256 {
        return Err(ImageSetError::ArtifactDigestMismatch {
            role: member.role,
            target: member.target,
            name: artifact.name.clone(),
            declared: artifact.sha256.clone(),
            actual: sha256,
        });
    }
    Ok(VerifiedArtifact {
        role: member.role,
        target: member.target,
        name: artifact.name.clone(),
        path,
        sha256,
        size,
    })
}

fn artifact_size(
    member: &ImageSetMember,
    artifact: &MemberArtifact,
    path: &Path,
) -> Result<u64, ImageSetError> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) => Err(read_failure(member, artifact, path, &error)),
    }
}

/// Hashed with `sha256_file` rather than `crypto::image_verify::verify_artifact`
/// because that helper deletes the file on mismatch; an image set is verified
/// out of a shared cache a concurrent run may also be reading.
fn artifact_digest(
    member: &ImageSetMember,
    artifact: &MemberArtifact,
    path: &Path,
) -> Result<Sha256Hex, ImageSetError> {
    let hex = sha256_file(path).map_err(|error| read_failure(member, artifact, path, &error))?;
    Sha256Hex::new(hex).map_err(|error| ImageSetError::ArtifactUnreadable {
        role: member.role,
        target: member.target,
        name: artifact.name.clone(),
        reason: error.to_string(),
    })
}

/// An absent file is its own refusal: it is the ordinary "this set was never
/// fully downloaded" case, and reporting it as an unreadable file would send an
/// operator looking for a permissions problem.
fn read_failure(
    member: &ImageSetMember,
    artifact: &MemberArtifact,
    path: &Path,
    error: &io::Error,
) -> ImageSetError {
    if error.kind() == io::ErrorKind::NotFound {
        ImageSetError::ArtifactMissing {
            role: member.role,
            target: member.target,
            name: artifact.name.clone(),
            path: path.display().to_string(),
        }
    } else {
        ImageSetError::ArtifactUnreadable {
            role: member.role,
            target: member.target,
            name: artifact.name.clone(),
            reason: error.to_string(),
        }
    }
}

/// The set digest is checked before the members: an entry revoking the signer
/// wholesale means the whole set is withdrawn, and reporting that as one
/// member's problem would understate it.
fn check_revocations(
    manifest: &ImageSetManifest,
    manifest_sha256: &Sha256Hex,
    signer_key_id: &KeyId,
    revocations: &dyn PackRevocationChecker,
) -> Result<(), ImageSetError> {
    if let RevocationStatus::Revoked { reason } = revocations.status(signer_key_id, manifest_sha256)
    {
        return Err(ImageSetError::SetRevoked {
            manifest_sha256: manifest_sha256.clone(),
            reason,
        });
    }
    for member in &manifest.members {
        if let RevocationStatus::Revoked { reason } =
            revocations.status(signer_key_id, &member.pack_hash)
        {
            return Err(ImageSetError::MemberRevoked {
                role: member.role,
                target: member.target,
                pack_hash: member.pack_hash.clone(),
                reason,
            });
        }
    }
    Ok(())
}
