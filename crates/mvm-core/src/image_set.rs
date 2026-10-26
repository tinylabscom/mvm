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

mod base_contract;
mod boot_abi;
mod checkout;
mod error;
mod identity;
mod local;
mod lock;
// The compiled-in image-train lock pins what this binary may boot; the pin
// is read by host downloaders and the canonical-kernel path, never in-guest.
#[cfg(feature = "host-state")]
mod train_lock;
mod trust_tier;
mod validate;
mod verify;

pub use base_contract::{BASE_IMAGE_CONTRACT_MARKER, BaseImageContract, BaseImageContractRange};
pub use boot_abi::{BuilderBootAbi, BuilderBootAbiRange};
pub use checkout::{LocalCheckouts, RepoIdentity, WorktreeState};
pub use error::{ImageSetError, ImageSetStage};
pub use identity::{
    ArtifactName, GitCommit, ImageSetIdentityError, ImageSetVersion, ProtocolRange, ReleaseTag,
    RepositorySlug, RevocationChannel, TagRef, WorkflowPath,
};
pub use local::{
    LOCAL_SET_MANIFEST_NAME, LocalImageSet, LocalImageSetVerification, MvmCheckoutRule,
    verify_local_image_set,
};
pub use lock::{IMAGE_LOCK_SCHEMA_VERSION, ImageLock, SigningIdentity};
#[cfg(feature = "host-state")]
pub(crate) use train_lock::image_train_lock_sha256;
#[cfg(feature = "host-state")]
pub use train_lock::{
    BootImagePin, IMAGE_TRAIN_LOCK_SCHEMA_VERSION, ImageTrainLock, ImageTrainLockError,
    LegacyImageTrain, PinnedArtifact, Stage0KernelPin, image_train_lock,
};
pub use trust_tier::ImageTrustTier;
pub use validate::{
    BackendImageSupport, HostProtocolSupport, ImageSetRequirement, RequiredMember,
    WorkloadImageSelection, check_against_lock, check_declared_protocol_compatibility,
    check_protocol_compatibility, require_complete, select_member, select_workload_image,
    validate_structure,
};
pub use verify::{
    ImageSetVerification, RetainedImageSetRootProof, VerifiedArtifact, VerifiedImageSet,
    VerifiedImageSetRoot, VerifiedSelectedArtifacts, cache_image_set_root,
    image_set_root_proof_cache, read_cached_image_set_root, read_cached_image_set_root_proof,
    verify_image_set, verify_image_set_artifacts, verify_image_set_root,
};

#[cfg(all(test, feature = "manifest-verify"))]
pub(crate) use verify::published_root;

pub const IMAGE_SET_SCHEMA_VERSION: u32 = 3;
pub const LEGACY_IMAGE_SET_SCHEMA_VERSION: u32 = 2;

/// The root object of one image set: a published release, or a set built
/// locally from two checkouts. Both are read by the same parser and checked by
/// the same structural rules; [`ImageSetProducer`] is what tells them apart,
/// and the fields only a release can carry are absent from a local set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetManifest {
    pub schema_version: u32,
    pub set_version: ImageSetVersion,
    pub issued_at: DateTime<Utc>,
    pub producer: ImageSetProducer,
    /// Legacy schema 2 runtime-source provenance. Required in that schema and
    /// absent in schema 3: the Linux-only image producer reads no mvm source.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub mvm_source_commit: Option<GitCommit>,
    pub compatibility: ImageSetCompatibility,
    pub nix_inputs: NixInputs,
    /// Where revocations of a released set are published. Required of a
    /// release and refused on a local set, which no one publishes or revokes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_channel: Option<RevocationChannel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<Supersedes>,
    pub members: Vec<ImageSetMember>,
}

/// Who built the set, and from what.
///
/// A release names the repository, workflow and tag it was published from —
/// which are also what a lock pins, so a set cannot claim one producer and be
/// locked as another. A local set names only the two checkouts it was built
/// from. The two shapes share no field, so a manifest is exactly one of them:
/// one naming both, or neither, does not parse.
///
/// On the wire a release producer is the flat object it has always been, and a
/// local one is `{"local_checkouts": {...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawProducer", into = "RawProducer")]
pub enum ImageSetProducer {
    Release(ReleaseProducer),
    LocalCheckouts(LocalCheckouts),
}

impl ImageSetProducer {
    /// The release this set claims to be, if it claims one.
    #[must_use]
    pub fn release(&self) -> Option<&ReleaseProducer> {
        match self {
            Self::Release(release) => Some(release),
            Self::LocalCheckouts(_) => None,
        }
    }

    /// The checkouts this set was built from, if it was built locally.
    #[must_use]
    pub fn local_checkouts(&self) -> Option<&LocalCheckouts> {
        match self {
            Self::Release(_) => None,
            Self::LocalCheckouts(local) => Some(local),
        }
    }
}

/// The release workflow run that published a set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseProducer {
    pub repository: RepositorySlug,
    pub workflow: WorkflowPath,
    pub release_tag: ReleaseTag,
    pub source_commit: GitCommit,
}

/// The wire form of [`ImageSetProducer`]: every field either shape can carry,
/// so an object mixing the two is caught by name rather than parsed as
/// whichever shape it happens to satisfy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProducer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repository: Option<RepositorySlug>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workflow: Option<WorkflowPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release_tag: Option<ReleaseTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_commit: Option<GitCommit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_checkouts: Option<LocalCheckouts>,
}

impl TryFrom<RawProducer> for ImageSetProducer {
    type Error = String;

    fn try_from(raw: RawProducer) -> Result<Self, Self::Error> {
        let RawProducer {
            repository,
            workflow,
            release_tag,
            source_commit,
            local_checkouts,
        } = raw;
        let release_fields = [
            ("repository", repository.is_some()),
            ("workflow", workflow.is_some()),
            ("release_tag", release_tag.is_some()),
            ("source_commit", source_commit.is_some()),
        ];
        if let Some(local) = local_checkouts {
            let named: Vec<&str> = release_fields
                .iter()
                .filter(|(_, present)| *present)
                .map(|(name, _)| *name)
                .collect();
            if !named.is_empty() {
                return Err(format!(
                    "a producer naming local_checkouts cannot also name a release ({})",
                    named.join(", ")
                ));
            }
            return Ok(Self::LocalCheckouts(local));
        }
        match (repository, workflow, release_tag, source_commit) {
            (Some(repository), Some(workflow), Some(release_tag), Some(source_commit)) => {
                Ok(Self::Release(ReleaseProducer {
                    repository,
                    workflow,
                    release_tag,
                    source_commit,
                }))
            }
            _ => {
                let missing: Vec<&str> = release_fields
                    .iter()
                    .filter(|(_, present)| !*present)
                    .map(|(name, _)| *name)
                    .collect();
                Err(format!(
                    "producer names neither local_checkouts nor a complete release \
                     (missing {})",
                    missing.join(", ")
                ))
            }
        }
    }
}

impl From<ImageSetProducer> for RawProducer {
    fn from(producer: ImageSetProducer) -> Self {
        match producer {
            ImageSetProducer::Release(release) => Self {
                repository: Some(release.repository),
                workflow: Some(release.workflow),
                release_tag: Some(release.release_tag),
                source_commit: Some(release.source_commit),
                local_checkouts: None,
            },
            ImageSetProducer::LocalCheckouts(local) => Self {
                repository: None,
                workflow: None,
                release_tag: None,
                source_commit: None,
                local_checkouts: Some(local),
            },
        }
    }
}

/// What a host must support to use the set, declared so an incompatible set is
/// refused before acquisition rather than discovered at the guest handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetCompatibility {
    /// Retired: the guest-agent protocol range a set recorded while it shipped
    /// the guest agent. The agent now ships with `mvmctl`, which speaks its own
    /// protocol, so nothing reads this. It stays parseable because every set up
    /// to `image-set/v0.2.4` declares it, and the signed bytes must round-trip.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub guest_agent_protocol: Option<ProtocolRange>,
    /// The builder image cache layout. Exact rather than a range: a builder
    /// image laid out under a different contract is unusable, not degraded.
    pub builder_cache_contract: u32,
    /// What the set's builder image promises the `mvmctl` that boots it; see
    /// [`BuilderBootAbi`]. A release published before the field existed omits
    /// it and means the legacy ABI 0. A locally built set must declare it:
    /// its emitter always writes it, so one without it predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_boot_abi: Option<BuilderBootAbi>,
    /// What the set's workload base root filesystems promise the guest runtime
    /// `mvmctl` boots them with; see [`BaseImageContract`]. A set published
    /// before the field existed omits it, which means the legacy contract 0.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub base_image_contract: Option<BaseImageContract>,
}

// Absent and null are different: a present declaration must be well formed,
// never a null that erases a contradictory field.
fn deserialize_present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

impl ImageSetCompatibility {
    /// The base-image contract the set declares, reading an absent field as
    /// the legacy contract every set published before the field carried.
    #[must_use]
    pub fn base_image_contract_or_legacy(&self) -> BaseImageContract {
        self.base_image_contract
            .unwrap_or(BaseImageContract::LEGACY)
    }

    /// Whether two declarations promise the same thing. The retired
    /// guest-agent range is left out: the checked-in lock no longer copies it,
    /// and nothing decides on it.
    #[must_use]
    pub fn same_contract(&self, other: &Self) -> bool {
        self.builder_cache_contract == other.builder_cache_contract
            && self.builder_boot_abi == other.builder_boot_abi
            && self.base_image_contract == other.base_image_contract
    }

    /// The builder boot ABI the set's builder image declares, reading an
    /// absent field as the legacy ABI a release published before the field
    /// meant. A local set without it is refused before this is asked.
    #[must_use]
    pub fn builder_boot_abi_or_legacy(&self) -> BuilderBootAbi {
        self.builder_boot_abi.unwrap_or(BuilderBootAbi::LEGACY)
    }
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

/// Which build of its role a member carries.
///
/// Absent means the production build. Only workload bases publish a dev
/// variant — the accessible, unsealed build a developer shell or the
/// documented-surface e2e boots — so the enum carries just that one value
/// until another role grows a second build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MemberBuildMode {
    /// The accessible, unsealed dev variant of a workload base image.
    Dev,
}

impl fmt::Display for MemberBuildMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dev => f.write_str("dev"),
        }
    }
}

/// One pack in the set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetMember {
    pub role: ImageSetRole,
    pub target: MemberTarget,
    /// Which build of the role this member carries; absent is the production
    /// build. Distinguishes the dev and prod variants of one workload base so
    /// both can publish in one atomic set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_mode: Option<MemberBuildMode>,
    /// Fingerprint of the sources a guest-runtime member was built from.
    /// Published on the SDK sidecar members of sets that still carry them
    /// (see [`RetiredGuestRuntimeRole`]), and parsed so those sets stay
    /// readable. Nothing reads it: the guest runtime ships with the CLI, so no
    /// image-set member is adopted in place of a build any more.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub source_fingerprint: Option<Sha256Hex>,
    /// Present exactly for roles that boot; see [`ImageSetRole::is_bootable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_protocol: Option<BootProtocol>,
    pub artifacts: Vec<MemberArtifact>,
    pub required_capabilities: Vec<GuestDeviceRequirement>,
    /// Content hash of the member's signed `PackManifest`. Required of a
    /// release; a local build has no signed pack, and a local set carrying one
    /// is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_hash: Option<Sha256Hex>,
    /// The member's published SBOM. Required of a release and refused on a
    /// local set, for the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom: Option<SbomReference>,
}

/// Generic workload base-image posture selected by a workload capability
/// declaration. Profiles name reusable security/capability floors, never a
/// host backend or a product-specific workload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadImageProfile {
    /// Smallest sealed workload base for one admitted workload.
    #[default]
    DefaultTenant,
    /// Sealed base with the generic namespace, cgroup and filesystem floor
    /// needed by an unprivileged in-guest container stack or supervisor.
    RootlessTenant,
}

impl fmt::Display for WorkloadImageProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultTenant => f.write_str("default_tenant"),
            Self::RootlessTenant => f.write_str("rootless_tenant"),
        }
    }
}

/// The part a member plays in the set.
///
/// Every role but one is part of the Linux layer: kernels, base root
/// filesystems, the builder image, the Stage 0 seed and the browser smoke
/// pack. The guest runtime — the runtime overlay, the universal initramfs and
/// the SDK sidecars — ships with each `mvmctl` release instead, so a set that
/// still publishes those members parses them as [`Self::RetiredGuestRuntime`]:
/// they are never required, and a launch never attaches one. Only a portable
/// bundle's boot assets still select them, through the set the bundle embeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSetRole {
    BuilderVm,
    WorkloadKernel(WorkloadImageProfile),
    WorkloadRootfs(WorkloadImageProfile),
    Stage0BootstrapKernel,
    QemuWasmSmokePack,
    /// A guest-runtime member of a set published before the guest runtime
    /// moved to the CLI release. Untagged, so it keeps the wire spelling those
    /// sets signed (`"runtime_overlay"`, `{"sdk_sidecar": "glibc"}`,
    /// `"initramfs"`) and the set's root digest still covers the same bytes.
    #[serde(untagged)]
    RetiredGuestRuntime(RetiredGuestRuntimeRole),
}

/// A guest-runtime role an older image set publishes. Accepted so a release
/// binary keeps reading such a set until the image repository stops
/// publishing these members; nothing in a launch reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetiredGuestRuntimeRole {
    RuntimeOverlay,
    SdkSidecar(GuestLibc),
    Initramfs,
}

impl fmt::Display for RetiredGuestRuntimeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeOverlay => f.write_str("runtime_overlay"),
            Self::SdkSidecar(libc) => write!(f, "sdk_sidecar_{libc}"),
            Self::Initramfs => f.write_str("initramfs"),
        }
    }
}

impl ImageSetRole {
    /// Roles a backend boots directly, and which therefore declare a boot
    /// protocol.
    pub fn is_bootable(self) -> bool {
        matches!(
            self,
            Self::BuilderVm | Self::WorkloadKernel(_) | Self::Stage0BootstrapKernel
        )
    }

    /// Roles published once for every architecture. The smoke pack runs its
    /// emulator in a browser, so its bytes do not depend on the guest arch a
    /// host would boot.
    pub fn is_arch_independent(self) -> bool {
        matches!(self, Self::QemuWasmSmokePack)
    }

    /// Whether this is a guest-runtime role a set may still carry and every
    /// consumer ignores.
    pub fn is_retired(self) -> bool {
        matches!(self, Self::RetiredGuestRuntime(_))
    }
}

impl fmt::Display for ImageSetRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuilderVm => f.write_str("builder_vm"),
            Self::WorkloadKernel(profile) => write!(f, "{profile}_workload_kernel"),
            Self::WorkloadRootfs(profile) => write!(f, "{profile}_workload_rootfs"),
            Self::Stage0BootstrapKernel => f.write_str("stage0_bootstrap_kernel"),
            Self::QemuWasmSmokePack => f.write_str("qemu_wasm_smoke_pack"),
            Self::RetiredGuestRuntime(role) => role.fmt(f),
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
