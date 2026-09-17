//! Pure checks a set must pass before any of its bytes are fetched or booted.
//!
//! Each check answers one question and is independent of the others, so a
//! caller composes them in the order its flow needs. None performs I/O.

use std::cmp::Ordering;
use std::fmt;

use mvm_contract::guest_libc::GuestLibc;

use super::identity::ProtocolRange;
use super::{
    ArtifactFormat, BootProtocol, GuestDeviceRequirement, IMAGE_LOCK_SCHEMA_VERSION,
    IMAGE_SET_SCHEMA_VERSION, ImageLock, ImageSetError, ImageSetManifest, ImageSetMember,
    ImageSetRole, MemberTarget,
};
use crate::arch::GuestArch;
use crate::packs::Sha256Hex;

/// Check the manifest is internally consistent: supported schema, members that
/// are unique and well-formed, a tag that names the set version, lineage that
/// points backwards, and pinned Nix inputs.
pub fn validate_structure(manifest: &ImageSetManifest) -> Result<(), ImageSetError> {
    check_schema_version(manifest)?;
    check_members(&manifest.members)?;
    check_release_tag_version(manifest)?;
    check_supersedes(manifest)?;
    check_nix_inputs(manifest)
}

fn check_schema_version(manifest: &ImageSetManifest) -> Result<(), ImageSetError> {
    if manifest.schema_version == IMAGE_SET_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ImageSetError::UnsupportedSchemaVersion {
            found: manifest.schema_version,
            supported: IMAGE_SET_SCHEMA_VERSION,
        })
    }
}

fn check_members(members: &[ImageSetMember]) -> Result<(), ImageSetError> {
    if members.is_empty() {
        return Err(ImageSetError::NoMembers);
    }
    for (index, member) in members.iter().enumerate() {
        check_member(member)?;
        let repeated = members[..index]
            .iter()
            .any(|earlier| earlier.role == member.role && earlier.target == member.target);
        if repeated {
            return Err(ImageSetError::DuplicateMember {
                role: member.role,
                target: member.target,
            });
        }
    }
    Ok(())
}

fn check_member(member: &ImageSetMember) -> Result<(), ImageSetError> {
    check_target_for_role(member)?;
    check_sidecar_libc(member)?;
    check_artifacts(member)?;
    check_boot_protocol_presence(member)
}

fn check_target_for_role(member: &ImageSetMember) -> Result<(), ImageSetError> {
    let independent = member.target == MemberTarget::ArchIndependent;
    if independent == member.role.is_arch_independent() {
        Ok(())
    } else {
        Err(ImageSetError::TargetNotAllowedForRole {
            role: member.role,
            target: member.target,
        })
    }
}

/// `GuestLibc::Unknown` is a detection outcome, not a variant anyone can build
/// a sidecar for, so a member claiming it is refused.
fn check_sidecar_libc(member: &ImageSetMember) -> Result<(), ImageSetError> {
    if member.role == ImageSetRole::SdkSidecar(GuestLibc::Unknown) {
        Err(ImageSetError::UnknownSidecarLibc {
            target: member.target,
        })
    } else {
        Ok(())
    }
}

fn check_artifacts(member: &ImageSetMember) -> Result<(), ImageSetError> {
    if member.artifacts.is_empty() {
        return Err(ImageSetError::MemberHasNoArtifacts {
            role: member.role,
            target: member.target,
        });
    }
    for (index, artifact) in member.artifacts.iter().enumerate() {
        if member.artifacts[..index]
            .iter()
            .any(|earlier| earlier.name == artifact.name)
        {
            return Err(ImageSetError::DuplicateArtifactName {
                role: member.role,
                target: member.target,
                name: artifact.name.clone(),
            });
        }
        if artifact.size == 0 {
            return Err(ImageSetError::ZeroSizeArtifact {
                role: member.role,
                target: member.target,
                name: artifact.name.clone(),
            });
        }
    }
    Ok(())
}

fn check_boot_protocol_presence(member: &ImageSetMember) -> Result<(), ImageSetError> {
    match (member.role.is_bootable(), member.boot_protocol) {
        (true, None) => Err(ImageSetError::MissingBootProtocol {
            role: member.role,
            target: member.target,
        }),
        (false, Some(protocol)) => Err(ImageSetError::UnexpectedBootProtocol {
            role: member.role,
            target: member.target,
            protocol,
        }),
        _ => Ok(()),
    }
}

fn check_release_tag_version(manifest: &ImageSetManifest) -> Result<(), ImageSetError> {
    let release_tag = &manifest.producer.release_tag;
    if release_tag.version() == &manifest.set_version {
        Ok(())
    } else {
        Err(ImageSetError::ReleaseTagVersionMismatch {
            set_version: Box::new(manifest.set_version.clone()),
            release_tag: Box::new(release_tag.clone()),
        })
    }
}

fn check_supersedes(manifest: &ImageSetManifest) -> Result<(), ImageSetError> {
    let Some(supersedes) = &manifest.supersedes else {
        return Ok(());
    };
    match supersedes.set_version.cmp_precedence(&manifest.set_version) {
        Ordering::Less => Ok(()),
        Ordering::Equal | Ordering::Greater => Err(ImageSetError::SupersedesNotOlder {
            set_version: Box::new(manifest.set_version.clone()),
            superseded: Box::new(supersedes.set_version.clone()),
        }),
    }
}

fn check_nix_inputs(manifest: &ImageSetManifest) -> Result<(), ImageSetError> {
    if manifest.nix_inputs.flake_locks.is_empty() {
        Err(ImageSetError::MissingNixLock)
    } else {
        Ok(())
    }
}

/// One `(role, target)` pair a complete set must contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredMember {
    pub role: ImageSetRole,
    pub target: MemberTarget,
}

impl fmt::Display for RequiredMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.role, self.target)
    }
}

/// The members a set must contain to be accepted at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSetRequirement {
    members: Vec<RequiredMember>,
}

/// Every role published once per guest architecture.
const ARCH_BOUND_ROLES: [ImageSetRole; 7] = [
    ImageSetRole::BuilderVm,
    ImageSetRole::WorkloadKernel,
    ImageSetRole::WorkloadRootfs,
    ImageSetRole::RuntimeOverlay,
    ImageSetRole::SdkSidecar(GuestLibc::Glibc),
    ImageSetRole::SdkSidecar(GuestLibc::Musl),
    ImageSetRole::Stage0BootstrapKernel,
];

impl ImageSetRequirement {
    pub fn new(members: Vec<RequiredMember>) -> Self {
        Self { members }
    }

    /// Today's release train: every arch-bound role on both guest
    /// architectures, plus the one architecture-independent smoke pack.
    pub fn current_train() -> Self {
        let arch_bound = [GuestArch::X86_64, GuestArch::Aarch64]
            .into_iter()
            .flat_map(|arch| {
                ARCH_BOUND_ROLES
                    .into_iter()
                    .map(move |role| RequiredMember {
                        role,
                        target: MemberTarget::Arch(arch),
                    })
            });
        let independent = RequiredMember {
            role: ImageSetRole::QemuWasmSmokePack,
            target: MemberTarget::ArchIndependent,
        };
        Self::new(arch_bound.chain([independent]).collect())
    }

    pub fn members(&self) -> &[RequiredMember] {
        &self.members
    }
}

/// Refuse a partial set, naming every missing member rather than the first, so
/// one failed publish reports its whole gap at once.
pub fn require_complete(
    manifest: &ImageSetManifest,
    requirement: &ImageSetRequirement,
) -> Result<(), ImageSetError> {
    let missing: Vec<RequiredMember> = requirement
        .members()
        .iter()
        .filter(|required| {
            !manifest
                .members
                .iter()
                .any(|member| member.role == required.role && member.target == required.target)
        })
        .copied()
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ImageSetError::Incomplete { missing })
    }
}

/// The protocol versions this host speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostProtocolSupport {
    pub guest_agent_protocol: ProtocolRange,
    pub builder_cache_contract: u32,
}

/// Refuse a set whose declared protocols this host cannot speak.
pub fn check_protocol_compatibility(
    manifest: &ImageSetManifest,
    host: &HostProtocolSupport,
) -> Result<(), ImageSetError> {
    let declared = &manifest.compatibility;
    if !declared
        .guest_agent_protocol
        .overlaps(host.guest_agent_protocol)
    {
        return Err(ImageSetError::GuestAgentProtocolDisjoint {
            set: declared.guest_agent_protocol,
            host: host.guest_agent_protocol,
        });
    }
    if declared.builder_cache_contract != host.builder_cache_contract {
        return Err(ImageSetError::BuilderCacheContractMismatch {
            set: declared.builder_cache_contract,
            host: host.builder_cache_contract,
        });
    }
    Ok(())
}

/// What one backend can boot, declared in guest terms so selection never
/// depends on which host OS the backend happens to run on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendImageSupport {
    pub guest_arches: Vec<GuestArch>,
    pub boot_protocols: Vec<BootProtocol>,
    pub artifact_formats: Vec<ArtifactFormat>,
    pub device_capabilities: Vec<GuestDeviceRequirement>,
}

/// Pick the member playing `role` for an `arch` guest, refusing it unless the
/// backend satisfies every part of its contract.
pub fn select_member<'a>(
    manifest: &'a ImageSetManifest,
    role: ImageSetRole,
    arch: GuestArch,
    backend: &BackendImageSupport,
) -> Result<&'a ImageSetMember, ImageSetError> {
    if !backend.guest_arches.contains(&arch) {
        return Err(ImageSetError::ArchitectureUnsupportedByBackend { arch });
    }
    let member = find_member(manifest, role, arch)?;
    check_backend_boot_protocol(member, backend)?;
    check_backend_artifact_formats(member, backend)?;
    check_backend_device_capabilities(member, backend)?;
    Ok(member)
}

fn find_member(
    manifest: &ImageSetManifest,
    role: ImageSetRole,
    arch: GuestArch,
) -> Result<&ImageSetMember, ImageSetError> {
    let mut with_role = manifest
        .members
        .iter()
        .filter(|member| member.role == role)
        .peekable();
    if with_role.peek().is_none() {
        return Err(ImageSetError::MemberNotFound { role });
    }
    let mut available = Vec::new();
    for member in with_role {
        if member.target.admits(arch) {
            return Ok(member);
        }
        available.push(member.target);
    }
    Err(ImageSetError::WrongArchitecture {
        role,
        requested: arch,
        available,
    })
}

fn check_backend_boot_protocol(
    member: &ImageSetMember,
    backend: &BackendImageSupport,
) -> Result<(), ImageSetError> {
    match member.boot_protocol {
        Some(protocol) if !backend.boot_protocols.contains(&protocol) => {
            Err(ImageSetError::UnsupportedBootProtocol {
                role: member.role,
                protocol,
            })
        }
        _ => Ok(()),
    }
}

fn check_backend_artifact_formats(
    member: &ImageSetMember,
    backend: &BackendImageSupport,
) -> Result<(), ImageSetError> {
    match member
        .artifacts
        .iter()
        .find(|artifact| !backend.artifact_formats.contains(&artifact.format))
    {
        Some(artifact) => Err(ImageSetError::UnsupportedArtifactFormat {
            role: member.role,
            artifact: artifact.name.clone(),
            format: artifact.format,
        }),
        None => Ok(()),
    }
}

fn check_backend_device_capabilities(
    member: &ImageSetMember,
    backend: &BackendImageSupport,
) -> Result<(), ImageSetError> {
    match member
        .required_capabilities
        .iter()
        .find(|capability| !backend.device_capabilities.contains(capability))
    {
        Some(capability) => Err(ImageSetError::MissingDeviceCapability {
            role: member.role,
            capability: *capability,
        }),
        None => Ok(()),
    }
}

/// Refuse a manifest the lock does not pin.
///
/// The digest comparison is what stops tampering and replay: a structurally
/// valid older set, or any set from elsewhere, hashes differently. The identity
/// comparisons after it catch a lock whose own fields disagree with the bytes
/// it pins, which a digest match alone would wave through.
pub fn check_against_lock(
    manifest: &ImageSetManifest,
    manifest_sha256: &Sha256Hex,
    lock: &ImageLock,
) -> Result<(), ImageSetError> {
    check_lock_schema_version(lock)?;
    check_manifest_digest(manifest_sha256, lock)?;
    check_producer_matches_lock(manifest, lock)?;
    check_signing_ref(lock)?;
    check_set_version_matches_lock(manifest, lock)
}

fn check_lock_schema_version(lock: &ImageLock) -> Result<(), ImageSetError> {
    if lock.schema_version == IMAGE_LOCK_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ImageSetError::UnsupportedLockSchemaVersion {
            found: lock.schema_version,
            supported: IMAGE_LOCK_SCHEMA_VERSION,
        })
    }
}

fn check_manifest_digest(actual: &Sha256Hex, lock: &ImageLock) -> Result<(), ImageSetError> {
    if actual == &lock.manifest_sha256 {
        Ok(())
    } else {
        Err(ImageSetError::ManifestDigestMismatch {
            pinned: lock.manifest_sha256.clone(),
            actual: actual.clone(),
        })
    }
}

fn check_producer_matches_lock(
    manifest: &ImageSetManifest,
    lock: &ImageLock,
) -> Result<(), ImageSetError> {
    let producer = &manifest.producer;
    if producer.repository != lock.repository {
        return Err(ImageSetError::RepositoryMismatch {
            pinned: lock.repository.clone(),
            produced: producer.repository.clone(),
        });
    }
    if producer.workflow != lock.signing_identity.workflow {
        return Err(ImageSetError::WorkflowMismatch {
            pinned: lock.signing_identity.workflow.clone(),
            produced: producer.workflow.clone(),
        });
    }
    if producer.release_tag != lock.release_tag {
        return Err(ImageSetError::ReleaseTagMismatch {
            pinned: Box::new(lock.release_tag.clone()),
            produced: Box::new(producer.release_tag.clone()),
        });
    }
    Ok(())
}

fn check_signing_ref(lock: &ImageLock) -> Result<(), ImageSetError> {
    let tag_ref = &lock.signing_identity.tag_ref;
    if tag_ref.tag() == &lock.release_tag {
        Ok(())
    } else {
        Err(ImageSetError::SigningRefMismatch {
            tag_ref: Box::new(tag_ref.clone()),
            release_tag: Box::new(lock.release_tag.clone()),
        })
    }
}

fn check_set_version_matches_lock(
    manifest: &ImageSetManifest,
    lock: &ImageLock,
) -> Result<(), ImageSetError> {
    let tag_version = lock.release_tag.version();
    if tag_version == &manifest.set_version {
        Ok(())
    } else {
        Err(ImageSetError::SetVersionMismatch {
            set_version: Box::new(manifest.set_version.clone()),
            tag_version: Box::new(tag_version.clone()),
        })
    }
}
