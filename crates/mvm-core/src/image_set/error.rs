//! Why an image set was refused.

use thiserror::Error;

use super::checkout::RepoIdentity;
use super::identity::{
    ArtifactName, GitCommit, ImageSetVersion, ProtocolRange, ReleaseTag, RepositorySlug, TagRef,
    WorkflowPath,
};
use super::validate::RequiredMember;
use super::{
    ArtifactFormat, BootProtocol, BuilderBootAbi, BuilderBootAbiRange, GuestDeviceRequirement,
    ImageSetRole, MemberTarget,
};
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
    #[error("released image set has no {field}")]
    ReleaseFieldMissing { field: &'static str },
    #[error("member {role}/{target} of a released image set has no {field}")]
    ReleaseMemberFieldMissing {
        role: ImageSetRole,
        target: MemberTarget,
        field: &'static str,
    },
    #[error("locally built image set carries {field}, which only a release has")]
    LocalFieldPresent { field: &'static str },
    #[error(
        "member {role}/{target} of a locally built image set carries {field}, which only a release has"
    )]
    LocalMemberFieldPresent {
        role: ImageSetRole,
        target: MemberTarget,
        field: &'static str,
    },
    #[error(
        "locally built image set declares mvm source {declared}, but its mvm checkout is at {recorded}"
    )]
    LocalMvmCommitMismatch {
        declared: GitCommit,
        recorded: GitCommit,
    },
    #[error(
        "image set was built from local checkouts, not published by a release, and cannot be \
         verified as one"
    )]
    NotARelease,
    #[error(
        "image set read as a local build names the release producer {repository} \
         ({workflow}); a locally built set is never a release"
    )]
    LocalSetClaimsRelease {
        repository: RepositorySlug,
        workflow: WorkflowPath,
    },
    #[error(
        "the {checkout} checkout is now {current}, but the image set was built from {recorded}; \
         rebuild it"
    )]
    StaleLocalSet {
        checkout: &'static str,
        recorded: Box<RepoIdentity>,
        current: Box<RepoIdentity>,
    },
    #[error("image set is incomplete; missing {}", join(.missing))]
    Incomplete { missing: Vec<RequiredMember> },
    #[error("guest-agent protocol {set} declared by the set does not overlap host support {host}")]
    GuestAgentProtocolDisjoint {
        set: ProtocolRange,
        host: ProtocolRange,
    },
    #[error("builder cache contract {set} declared by the set is not the host's {host}")]
    BuilderCacheContractMismatch { set: u32, host: u32 },
    #[error(
        "builder boot ABI {set} declared by the set is not one this mvmctl boots ({host}); \
         update mvmctl, or use an image set built for it"
    )]
    BuilderBootAbiUnsupported {
        set: BuilderBootAbi,
        host: BuilderBootAbiRange,
    },
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
    #[error("no signature over the image set manifest verifies under {identity}: {reason}")]
    SignatureInvalid { identity: String, reason: String },
    #[error("signed image set manifest is not a manifest this build understands: {reason}")]
    UnparseableManifest { reason: String },
    #[error("member {role}/{target} artifact {name} is not at {path}")]
    ArtifactMissing {
        role: ImageSetRole,
        target: MemberTarget,
        name: ArtifactName,
        path: String,
    },
    #[error("member {role}/{target} artifact {name} at {path} is not a regular file")]
    ArtifactNotRegularFile {
        role: ImageSetRole,
        target: MemberTarget,
        name: ArtifactName,
        path: String,
    },
    #[error("member {role}/{target} artifact {name} cannot be read: {reason}")]
    ArtifactUnreadable {
        role: ImageSetRole,
        target: MemberTarget,
        name: ArtifactName,
        reason: String,
    },
    #[error(
        "member {role}/{target} artifact {name} is {actual} bytes, not the declared {declared}"
    )]
    ArtifactSizeMismatch {
        role: ImageSetRole,
        target: MemberTarget,
        name: ArtifactName,
        declared: u64,
        actual: u64,
    },
    #[error(
        "member {role}/{target} artifact {name} hashes to {}, not the declared {}",
        .actual.as_str(),
        .declared.as_str()
    )]
    ArtifactDigestMismatch {
        role: ImageSetRole,
        target: MemberTarget,
        name: ArtifactName,
        declared: Sha256Hex,
        actual: Sha256Hex,
    },
    #[error("member {role}/{target} pack {} is revoked: {reason}", .pack_hash.as_str())]
    MemberRevoked {
        role: ImageSetRole,
        target: MemberTarget,
        pack_hash: Sha256Hex,
        reason: String,
    },
    #[error("image set {} is revoked: {reason}", .manifest_sha256.as_str())]
    SetRevoked {
        manifest_sha256: Sha256Hex,
        reason: String,
    },
}

/// The verification stage a refusal belongs to.
///
/// [`super::verify_image_set`] runs its stages in a fixed order and stops at the
/// first that fails, so the stage alone tells an operator how far a set got:
/// a signature refusal means the bytes were the pinned ones, and an artifact
/// refusal means the manifest itself was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSetStage {
    /// The lock cannot be used at all.
    Lock,
    /// The manifest bytes are not the ones the lock pins.
    ManifestDigest,
    /// No accepted identity signed the manifest bytes.
    Signature,
    /// The signed bytes are not a manifest this build understands.
    Parse,
    /// The manifest is internally inconsistent.
    Structure,
    /// The manifest's producer is not the kind this path accepts: a local set
    /// offered as a release, or a release offered as a local set.
    Provenance,
    /// A locally built set whose checkouts have changed since it was built.
    Freshness,
    /// The manifest names a different producer, tag or version than the lock.
    LockMatch,
    /// A member the caller requires is absent.
    Completeness,
    /// The set declares protocols the host cannot speak.
    ProtocolCompatibility,
    /// An artifact on disk is missing or differs from its declaration.
    Artifacts,
    /// The set or one of its members is revoked.
    Revocation,
    /// A backend cannot run any member the set offers for a role.
    Selection,
}

impl ImageSetStage {
    /// A stable, lowercase name for scripts and machine-readable output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::ManifestDigest => "manifest-digest",
            Self::Signature => "signature",
            Self::Parse => "parse",
            Self::Structure => "structure",
            Self::Provenance => "provenance",
            Self::Freshness => "freshness",
            Self::LockMatch => "lock-match",
            Self::Completeness => "completeness",
            Self::ProtocolCompatibility => "protocol-compatibility",
            Self::Artifacts => "artifacts",
            Self::Revocation => "revocation",
            Self::Selection => "selection",
        }
    }
}

impl std::fmt::Display for ImageSetStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl ImageSetError {
    /// Which stage refused. Exhaustive rather than defaulted, so a new refusal
    /// cannot be added without deciding where it belongs.
    pub fn stage(&self) -> ImageSetStage {
        match self {
            Self::UnsupportedLockSchemaVersion { .. } => ImageSetStage::Lock,
            Self::ManifestDigestMismatch { .. } => ImageSetStage::ManifestDigest,
            Self::SignatureInvalid { .. } => ImageSetStage::Signature,
            Self::UnparseableManifest { .. } => ImageSetStage::Parse,
            Self::UnsupportedSchemaVersion { .. }
            | Self::NoMembers
            | Self::DuplicateMember { .. }
            | Self::DuplicateArtifactName { .. }
            | Self::MemberHasNoArtifacts { .. }
            | Self::ZeroSizeArtifact { .. }
            | Self::MissingBootProtocol { .. }
            | Self::UnexpectedBootProtocol { .. }
            | Self::TargetNotAllowedForRole { .. }
            | Self::UnknownSidecarLibc { .. }
            | Self::ReleaseTagVersionMismatch { .. }
            | Self::SupersedesNotOlder { .. }
            | Self::MissingNixLock
            | Self::ReleaseFieldMissing { .. }
            | Self::ReleaseMemberFieldMissing { .. }
            | Self::LocalFieldPresent { .. }
            | Self::LocalMemberFieldPresent { .. }
            | Self::LocalMvmCommitMismatch { .. } => ImageSetStage::Structure,
            Self::NotARelease | Self::LocalSetClaimsRelease { .. } => ImageSetStage::Provenance,
            Self::StaleLocalSet { .. } => ImageSetStage::Freshness,
            Self::RepositoryMismatch { .. }
            | Self::WorkflowMismatch { .. }
            | Self::ReleaseTagMismatch { .. }
            | Self::SigningRefMismatch { .. }
            | Self::SetVersionMismatch { .. } => ImageSetStage::LockMatch,
            Self::Incomplete { .. } => ImageSetStage::Completeness,
            Self::GuestAgentProtocolDisjoint { .. }
            | Self::BuilderCacheContractMismatch { .. }
            | Self::BuilderBootAbiUnsupported { .. } => ImageSetStage::ProtocolCompatibility,
            Self::ArtifactMissing { .. }
            | Self::ArtifactNotRegularFile { .. }
            | Self::ArtifactUnreadable { .. }
            | Self::ArtifactSizeMismatch { .. }
            | Self::ArtifactDigestMismatch { .. } => ImageSetStage::Artifacts,
            Self::MemberRevoked { .. } | Self::SetRevoked { .. } => ImageSetStage::Revocation,
            Self::ArchitectureUnsupportedByBackend { .. }
            | Self::WrongArchitecture { .. }
            | Self::MemberNotFound { .. }
            | Self::UnsupportedBootProtocol { .. }
            | Self::UnsupportedArtifactFormat { .. }
            | Self::MissingDeviceCapability { .. } => ImageSetStage::Selection,
        }
    }
}

fn join<T: std::fmt::Display>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
