//! The image set: one atomic release of every guest image `mvm` boots.
//!
//! A set is a manifest indexing member packs. Each member names the role it
//! plays, the guest architecture it targets, how it boots, which artifact
//! formats it ships and which guest devices it needs, and pins its
//! [`crate::packs::PackManifest`] by content hash. The members are the guest's
//! contract rather than the host's: nothing here is named after a host OS, so
//! any backend that satisfies a member's contract can select it.
//!
//! This module holds the types, the pure checks, and the checked-in
//! [`ImageTrainLock`] over the pins that exist today. Signature verification
//! and fetching live with their callers.

use std::fmt;

use chrono::{DateTime, Utc};
use mvm_contract::guest_libc::GuestLibc;
use serde::{Deserialize, Serialize};

use crate::arch::GuestArch;
use crate::kernel_format::KernelFormat;
use crate::packs::{FlakeLockIdentity, SbomReference, Sha256Hex, SourceRevisionIdentity};

mod error;
mod identity;
mod lock;
mod train_lock;
mod validate;
mod verify;

pub use error::{ImageSetError, ImageSetStage};
pub use identity::{
    ArtifactName, GitCommit, ImageSetIdentityError, ImageSetVersion, ProtocolRange, ReleaseTag,
    RepositorySlug, RevocationChannel, TagRef, WorkflowPath,
};
pub use lock::{IMAGE_LOCK_SCHEMA_VERSION, ImageLock, SigningIdentity};
pub use train_lock::{
    BootImagePin, IMAGE_TRAIN_LOCK_SCHEMA_VERSION, ImageTrainLock, ImageTrainLockError,
    PinnedArtifact, Stage0KernelPin, image_train_lock,
};
pub use validate::{
    BackendImageSupport, HostProtocolSupport, ImageSetRequirement, RequiredMember,
    check_against_lock, check_protocol_compatibility, require_complete, select_member,
    validate_structure,
};
pub use verify::{ImageSetVerification, VerifiedArtifact, VerifiedImageSet, verify_image_set};

pub const IMAGE_SET_SCHEMA_VERSION: u32 = 1;

/// The root object of one published image set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetManifest {
    pub schema_version: u32,
    pub set_version: ImageSetVersion,
    pub issued_at: DateTime<Utc>,
    pub producer: ImageSetProducer,
    /// The `mvm` commit whose guest and builder binaries are embedded in the
    /// images. Recorded apart from the producer commit because the image
    /// repository checks `mvm` out at an exact commit rather than tracking it.
    pub mvm_source_commit: GitCommit,
    pub compatibility: ImageSetCompatibility,
    pub nix_inputs: NixInputs,
    pub revocation_channel: RevocationChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<Supersedes>,
    pub members: Vec<ImageSetMember>,
}

/// Who built the set, and from what. The repository, workflow and tag are also
/// what a lock pins, so a set cannot claim one producer and be locked as
/// another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetProducer {
    pub repository: RepositorySlug,
    pub workflow: WorkflowPath,
    pub release_tag: ReleaseTag,
    pub source_commit: GitCommit,
}

/// What a host must support to use the set, declared so an incompatible set is
/// refused before acquisition rather than discovered at the guest handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetCompatibility {
    pub guest_agent_protocol: ProtocolRange,
    /// The builder image cache layout. Exact rather than a range: a builder
    /// image laid out under a different contract is unusable, not degraded.
    pub builder_cache_contract: u32,
}

/// The Nix inputs every member was built from, using the pack model's input
/// identities so a set and its member packs describe inputs the same way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NixInputs {
    pub flake_locks: Vec<FlakeLockIdentity>,
    pub source_revisions: Vec<SourceRevisionIdentity>,
}

/// The set this one replaces. Metadata only: it records lineage and is never
/// followed, so it cannot redirect a consumer to other bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Supersedes {
    pub set_version: ImageSetVersion,
    pub manifest_sha256: Sha256Hex,
}

/// One pack in the set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetMember {
    pub role: ImageSetRole,
    pub target: MemberTarget,
    /// Present exactly for roles that boot; see [`ImageSetRole::is_bootable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_protocol: Option<BootProtocol>,
    pub artifacts: Vec<MemberArtifact>,
    pub required_capabilities: Vec<GuestDeviceRequirement>,
    /// Content hash of the member's `PackManifest`.
    pub pack_hash: Sha256Hex,
    pub sbom: SbomReference,
}

/// The part a member plays in the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSetRole {
    BuilderVm,
    WorkloadKernel,
    WorkloadRootfs,
    RuntimeOverlay,
    /// One sidecar per C library, since a guest can only load the variant
    /// linked against the libc it carries.
    SdkSidecar(GuestLibc),
    Stage0BootstrapKernel,
    QemuWasmSmokePack,
}

impl ImageSetRole {
    /// Roles a backend boots directly, and which therefore declare a boot
    /// protocol.
    pub fn is_bootable(self) -> bool {
        matches!(
            self,
            Self::BuilderVm | Self::WorkloadKernel | Self::Stage0BootstrapKernel
        )
    }

    /// Roles published once for every architecture. The smoke pack runs its
    /// emulator in a browser, so its bytes do not depend on the guest arch a
    /// host would boot.
    pub fn is_arch_independent(self) -> bool {
        matches!(self, Self::QemuWasmSmokePack)
    }
}

impl fmt::Display for ImageSetRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuilderVm => f.write_str("builder_vm"),
            Self::WorkloadKernel => f.write_str("workload_kernel"),
            Self::WorkloadRootfs => f.write_str("workload_rootfs"),
            Self::RuntimeOverlay => f.write_str("runtime_overlay"),
            Self::SdkSidecar(libc) => write!(f, "sdk_sidecar_{libc}"),
            Self::Stage0BootstrapKernel => f.write_str("stage0_bootstrap_kernel"),
            Self::QemuWasmSmokePack => f.write_str("qemu_wasm_smoke_pack"),
        }
    }
}

/// The guest architecture a member runs as, or an explicit statement that it
/// has none. Explicit so an arch-bound role can never be accepted for every
/// architecture by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberTarget {
    Arch(GuestArch),
    ArchIndependent,
}

impl MemberTarget {
    /// Whether a member with this target can serve a guest of `arch`.
    pub fn admits(self, arch: GuestArch) -> bool {
        match self {
            Self::Arch(target) => target == arch,
            Self::ArchIndependent => true,
        }
    }
}

impl fmt::Display for MemberTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arch(arch) => write!(f, "{arch}"),
            Self::ArchIndependent => f.write_str("arch_independent"),
        }
    }
}

/// How a backend transfers control to a bootable member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootProtocol {
    /// The VMM loads the Linux kernel image itself and jumps to it, with no
    /// firmware or bootloader in between.
    LinuxDirect,
}

/// One file of a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberArtifact {
    pub name: ArtifactName,
    pub format: ArtifactFormat,
    pub sha256: Sha256Hex,
    pub size: u64,
}

/// The on-disk format of an artifact, which is what decides whether a backend
/// can load it. Kernel images reuse the backend-neutral [`KernelFormat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Kernel(KernelFormat),
    Ext4,
    VerityHashTree,
    VerityRootHash,
    TarGz,
    Text,
    Json,
}

/// A guest-visible device or kernel facility a member cannot run without.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestDeviceRequirement {
    VirtioVsock,
    VirtioBlk,
    DmVerity,
}

#[cfg(test)]
mod tests;
