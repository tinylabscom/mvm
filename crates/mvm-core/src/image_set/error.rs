//! Why an image set was refused.

use thiserror::Error;

use super::identity::{
    ArtifactName, ImageSetVersion, ProtocolRange, ReleaseTag, RepositorySlug, TagRef, WorkflowPath,
};
use super::validate::RequiredMember;
use super::{ArtifactFormat, BootProtocol, GuestDeviceRequirement, ImageSetRole, MemberTarget};
use crate::arch::GuestArch;
use crate::packs::Sha256Hex;

/// Every refusal names what differs, so an operator can tell a stale lock from
/// a tampered manifest from a backend that simply cannot run the set.
///
/// Versions, tags and refs are boxed: they carry their parsed form beside the
/// raw string, and holding two inline would make every `Result` this module
/// returns several times larger than its success value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImageSetError {
    #[error("image set schema version {found} is not supported (expected {supported})")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    #[error("image set has no members")]
    NoMembers,
    #[error("image set lists {role}/{target} more than once")]
    DuplicateMember {
        role: ImageSetRole,
        target: MemberTarget,
    },
    #[error("member {role}/{target} lists artifact {name} more than once")]
    DuplicateArtifactName {
        role: ImageSetRole,
        target: MemberTarget,
        name: ArtifactName,
    },
    #[error("member {role}/{target} has no artifacts")]
    MemberHasNoArtifacts {
        role: ImageSetRole,
        target: MemberTarget,
    },
    #[error("member {role}/{target} declares artifact {name} with size zero")]
    ZeroSizeArtifact {
        role: ImageSetRole,
        target: MemberTarget,
        name: ArtifactName,
    },
    #[error("bootable member {role}/{target} declares no boot protocol")]
    MissingBootProtocol {
        role: ImageSetRole,
        target: MemberTarget,
    },
    #[error("member {role}/{target} is not bootable but declares boot protocol {protocol:?}")]
    UnexpectedBootProtocol {
        role: ImageSetRole,
        target: MemberTarget,
        protocol: BootProtocol,
    },
    #[error("role {role} cannot be published with target {target}")]
    TargetNotAllowedForRole {
        role: ImageSetRole,
        target: MemberTarget,
    },
    #[error("SDK sidecar for {target} names no known C library")]
    UnknownSidecarLibc { target: MemberTarget },
    #[error("set version {set_version} does not match release tag {release_tag}")]
    ReleaseTagVersionMismatch {
        set_version: Box<ImageSetVersion>,
        release_tag: Box<ReleaseTag>,
    },
    #[error("set version {set_version} claims to supersede {superseded}, which is not older")]
    SupersedesNotOlder {
        set_version: Box<ImageSetVersion>,
        superseded: Box<ImageSetVersion>,
    },
    #[error("image set pins no Nix flake lock")]
    MissingNixLock,
    #[error("image set is incomplete; missing {}", join(.missing))]
    Incomplete { missing: Vec<RequiredMember> },
    #[error("guest-agent protocol {set} declared by the set does not overlap host support {host}")]
    GuestAgentProtocolDisjoint {
        set: ProtocolRange,
        host: ProtocolRange,
    },
    #[error("builder cache contract {set} declared by the set is not the host's {host}")]
    BuilderCacheContractMismatch { set: u32, host: u32 },
    #[error("backend cannot run {arch} guests")]
    ArchitectureUnsupportedByBackend { arch: GuestArch },
    #[error("image set has no {role} for {requested}; it has {}", join(.available))]
    WrongArchitecture {
        role: ImageSetRole,
        requested: GuestArch,
        available: Vec<MemberTarget>,
    },
    #[error("image set has no {role} member")]
    MemberNotFound { role: ImageSetRole },
    #[error("backend does not support boot protocol {protocol:?} required by {role}")]
    UnsupportedBootProtocol {
        role: ImageSetRole,
        protocol: BootProtocol,
    },
    #[error("backend cannot load artifact {artifact} of {role}: format {format:?}")]
    UnsupportedArtifactFormat {
        role: ImageSetRole,
        artifact: ArtifactName,
        format: ArtifactFormat,
    },
    #[error("backend lacks guest device {capability:?} required by {role}")]
    MissingDeviceCapability {
        role: ImageSetRole,
        capability: GuestDeviceRequirement,
    },
    #[error("image lock schema version {found} is not supported (expected {supported})")]
    UnsupportedLockSchemaVersion { found: u32, supported: u32 },
    #[error("manifest digest {} is not the locked {}", .actual.as_str(), .pinned.as_str())]
    ManifestDigestMismatch {
        pinned: Sha256Hex,
        actual: Sha256Hex,
    },
    #[error("manifest was produced by {produced}, lock pins {pinned}")]
    RepositoryMismatch {
        pinned: RepositorySlug,
        produced: RepositorySlug,
    },
    #[error("manifest was produced by workflow {produced}, lock pins {pinned}")]
    WorkflowMismatch {
        pinned: WorkflowPath,
        produced: WorkflowPath,
    },
    #[error("manifest was released as {produced}, lock pins {pinned}")]
    ReleaseTagMismatch {
        pinned: Box<ReleaseTag>,
        produced: Box<ReleaseTag>,
    },
    #[error("lock signing ref {tag_ref} does not name the locked tag {release_tag}")]
    SigningRefMismatch {
        tag_ref: Box<TagRef>,
        release_tag: Box<ReleaseTag>,
    },
    #[error("set version {set_version} does not match locked tag version {tag_version}")]
    SetVersionMismatch {
        set_version: Box<ImageSetVersion>,
        tag_version: Box<ImageSetVersion>,
    },
}

fn join<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
