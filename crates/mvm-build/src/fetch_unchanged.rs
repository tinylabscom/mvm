//! Which arm prepares an image that a source checkout otherwise pair-builds
//! from an `mvm-images` checkout: the SDK sidecars and the dev default image.
//!
//! [`FETCH_UNCHANGED_ENV`] selects it, and it is off by default:
//!
//! | value    | arm                                                          |
//! |----------|--------------------------------------------------------------|
//! | unset    | build locally — the contributor default, unchanged           |
//! | `1`      | adopt the pinned set's members only when they were built     |
//! |          | from exactly this tree's sources; build locally otherwise    |
//! | `pinned` | adopt the pinned set's members whatever sources they were    |
//! |          | built from; never build                                      |
//!
//! `1` is fetch-when-unchanged. The image-set schema carries a member's
//! `source_fingerprint` and dev build variants, so a tree whose fingerprint
//! matches the published sidecars can adopt those verified bytes instead of
//! rebuilding them — and the same predicate covers the dev image, whose inputs
//! over-approximate to the host-services C ABI on purpose (a broader guest
//! change rebuilds; that is the accepted v1 behavior). A mismatch or an absent
//! field never fails: it names the reason and the caller builds locally, which
//! is the safe direction.
//!
//! `pinned` is for a lane that has to test what a user of this CLI gets: the
//! pinned set, not a pair build of the tree. It skips the fingerprint equality
//! and nothing else. The root is still digest-pinned, signature-verified and
//! refused when its compatibility declaration excludes this CLI; every member
//! is still size- and digest-checked against it. Because it asked for those
//! members by name, a refusal is final: it never falls back to a local build,
//! which would test something other than what was asked for.
//!
//! Both arms report which one ran and why in one line, including how this
//! tree's fingerprint compares with the set's when it was adopted anyway.

use std::fmt;
use std::path::Path;

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ImageSetRole, MemberBuildMode, MemberTarget, ReleaseTag, WorkloadImageProfile,
};
use thiserror::Error;

use crate::guest_agent_build;
use crate::published_image_set::PublishedImageSet;

/// The opt-in knob. Production resolvers never read it; the documented-surface
/// e2e sets it to adopt published members instead of pair-building them.
pub const FETCH_UNCHANGED_ENV: &str = "MVM_FETCH_UNCHANGED_IMAGES";

/// Hex digits of a source fingerprint shown in a report line.
const FINGERPRINT_PREFIX_LEN: usize = 12;

/// What the caller asked for through [`FETCH_UNCHANGED_ENV`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchMode {
    /// Build locally from the selected image checkout.
    Off,
    /// Adopt the pinned members only when this tree's fingerprint matches.
    WhenUnchanged,
    /// Adopt the pinned members whatever their source fingerprint.
    Pinned,
}

impl FetchMode {
    /// The mode the environment selects.
    #[must_use]
    pub fn from_env() -> Self {
        std::env::var(FETCH_UNCHANGED_ENV)
            .map(|value| Self::parse(&value))
            .unwrap_or(Self::Off)
    }

    /// Parse one value: trimmed and case-insensitive. An unrecognised value
    /// warns and selects [`Self::Off`] — the same fall-through `MVM_BOOT_IMAGE`
    /// and the builder backend selection use. Off is the arm that adopts
    /// nothing, so a typo can never adopt bytes nobody asked for.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "0" => Self::Off,
            "1" => Self::WhenUnchanged,
            "pinned" => Self::Pinned,
            other => {
                tracing::warn!(
                    value = %other,
                    "{FETCH_UNCHANGED_ENV} value not recognised (expected `1` or `pinned`); building locally"
                );
                Self::Off
            }
        }
    }

    /// The token this mode is spelled with, for report lines.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Off => "unset",
            Self::WhenUnchanged => "1",
            Self::Pinned => "pinned",
        }
    }
}

/// Which members of the set an image-preparation verb installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinnedMembers {
    /// Both libc variants of the SDK sidecar.
    SdkSidecars,
    /// The dev (writable) default-tenant kernel and rootfs.
    DevDefaultImage,
}

impl PinnedMembers {
    /// Whether the set publishes every member this verb installs for `arch`.
    #[must_use]
    pub fn published_in(self, set: &PublishedImageSet, arch: GuestArch) -> bool {
        match self {
            Self::SdkSidecars => set_publishes_sidecars(set, arch),
            Self::DevDefaultImage => set_publishes_dev_members(set, arch),
        }
    }
}

impl fmt::Display for PinnedMembers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SdkSidecars => "SDK sidecars",
            Self::DevDefaultImage => "dev default image",
        })
    }
}

/// How this tree's cdylib source fingerprint compares with the one the set's
/// sidecar members declare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceComparison {
    /// Both sidecar members declare this tree's fingerprint.
    Matches,
    /// The set declares a different fingerprint.
    Differs { tree: String, set: String },
    /// The set's sidecar members declare no fingerprint (an older set).
    SetDeclaresNone,
    /// This tree's fingerprint could not be computed.
    TreeUnknown(String),
}

impl SourceComparison {
    /// Compare `tree` with what `set` declares for `arch`.
    #[must_use]
    pub fn of(set: &PublishedImageSet, arch: GuestArch, tree: &Result<String, String>) -> Self {
        let tree = match tree {
            Ok(tree) => tree,
            Err(reason) => return Self::TreeUnknown(reason.clone()),
        };
        if set_sidecars_match_tree(set, arch, tree) {
            return Self::Matches;
        }
        match declared_sidecar_fingerprint(set, arch) {
            Some(declared) => Self::Differs {
                tree: tree.clone(),
                set: declared,
            },
            None => Self::SetDeclaresNone,
        }
    }
}

impl fmt::Display for SourceComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Matches => f.write_str("this tree's cdylib source fingerprint matches the set's"),
            Self::Differs { tree, set } => write!(
                f,
                "this tree's cdylib source fingerprint {} differs from the set's {}",
                short(tree),
                short(set)
            ),
            Self::SetDeclaresNone => {
                f.write_str("the set's sidecar members declare no source fingerprint")
            }
            Self::TreeUnknown(reason) => write!(
                f,
                "this tree's cdylib source fingerprint could not be computed ({reason})"
            ),
        }
    }
}

fn short(fingerprint: &str) -> String {
    let prefix: String = fingerprint.chars().take(FINGERPRINT_PREFIX_LEN).collect();
    if prefix.len() < fingerprint.len() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

/// The arm one image-preparation verb takes.
pub enum Arm {
    /// Install the members of this verified set.
    Adopt {
        set: Box<PublishedImageSet>,
        comparison: SourceComparison,
    },
    /// Build locally from the selected image checkout.
    BuildLocally { reason: String },
}

/// What one verb asks of [`choose_arm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmRequest {
    pub mode: FetchMode,
    pub members: PinnedMembers,
    pub arch: GuestArch,
}

impl ArmRequest {
    /// The request for `members` on this host, under the environment's mode.
    #[must_use]
    pub fn for_host(members: PinnedMembers) -> Self {
        Self {
            mode: FetchMode::from_env(),
            members,
            arch: GuestArch::host(),
        }
    }
}

impl Arm {
    /// The one line that says which arm ran for `request`, and why.
    #[must_use]
    pub fn report(&self, request: ArmRequest) -> String {
        let knob = format!("{FETCH_UNCHANGED_ENV}={}", request.mode.token());
        match self {
            Self::Adopt { set, comparison } => format!(
                "{}: adopting the members of the pinned image set {} ({knob}); {comparison}",
                request.members,
                set.release_tag(),
            ),
            Self::BuildLocally { reason } => format!(
                "{}: pair-building from the selected image checkout ({knob}): {reason}",
                request.members
            ),
        }
    }
}

/// [`FETCH_UNCHANGED_ENV`]`=pinned` asked for the pinned set's members, and
/// they cannot be delivered. Never answered by a local build.
#[derive(Debug, Error)]
pub enum PinnedSetRefused {
    /// The set itself was refused: unreachable, not the locked root, not
    /// signed by its publisher, incomplete, or declaring a compatibility this
    /// CLI does not have.
    #[error(
        "{FETCH_UNCHANGED_ENV}=pinned adopts the {members} from the pinned image set and never \
         builds them in its place, but the set was refused: {reason}"
    )]
    SetRefused {
        members: PinnedMembers,
        reason: String,
    },
    /// The set is sound but does not publish these members.
    #[error(
        "{FETCH_UNCHANGED_ENV}=pinned adopts the {members} from the pinned image set, but \
         {release_tag} publishes no {members} for {arch}; nothing is built in their place"
    )]
    MembersMissing {
        members: PinnedMembers,
        release_tag: ReleaseTag,
        arch: GuestArch,
    },
}

/// Choose the arm for `request`. `tree` is this tree's cdylib source
/// fingerprint (or why it is unknown); `acquire` delivers the verified set.
/// Only [`FetchMode::Pinned`] can fail: the other modes answer every problem
/// with [`Arm::BuildLocally`] and its reason.
pub fn choose_arm(
    request: ArmRequest,
    tree: Result<String, String>,
    acquire: impl FnOnce() -> anyhow::Result<PublishedImageSet>,
) -> Result<Arm, PinnedSetRefused> {
    match request.mode {
        FetchMode::Off => Ok(Arm::BuildLocally {
            reason: format!("{FETCH_UNCHANGED_ENV} is not set"),
        }),
        FetchMode::WhenUnchanged => Ok(when_unchanged(request, tree, acquire)),
        FetchMode::Pinned => pinned(request, tree, acquire),
    }
}

/// [`choose_arm`] against this build's locked set and this tree's sources.
pub fn resolve_arm(request: ArmRequest) -> Result<Arm, PinnedSetRefused> {
    let tree = match guest_agent_build::detect_source_workspace() {
        Some(workspace) => tree_sdk_fingerprint(&workspace).map_err(|e| e.to_string()),
        None => Err("no source workspace to fingerprint".to_string()),
    };
    choose_arm(request, tree, PublishedImageSet::acquire)
}

fn when_unchanged(
    request: ArmRequest,
    tree: Result<String, String>,
    acquire: impl FnOnce() -> anyhow::Result<PublishedImageSet>,
) -> Arm {
    let build_locally = |reason: String| Arm::BuildLocally { reason };
    if let Err(reason) = &tree {
        return build_locally(format!(
            "cannot fingerprint the tree's cdylib sources ({reason})"
        ));
    }
    let set = match acquire() {
        Ok(set) => set,
        Err(e) => return build_locally(format!("cannot acquire the pinned image set ({e:#})")),
    };
    if !request.members.published_in(&set, request.arch) {
        return build_locally(format!(
            "{} publishes no {} for {}",
            set.release_tag(),
            request.members,
            request.arch
        ));
    }
    match SourceComparison::of(&set, request.arch, &tree) {
        SourceComparison::Matches => Arm::Adopt {
            set: Box::new(set),
            comparison: SourceComparison::Matches,
        },
        other => build_locally(other.to_string()),
    }
}

fn pinned(
    request: ArmRequest,
    tree: Result<String, String>,
    acquire: impl FnOnce() -> anyhow::Result<PublishedImageSet>,
) -> Result<Arm, PinnedSetRefused> {
    let set = acquire().map_err(|e| PinnedSetRefused::SetRefused {
        members: request.members,
        reason: format!("{e:#}"),
    })?;
    if !request.members.published_in(&set, request.arch) {
        return Err(PinnedSetRefused::MembersMissing {
            members: request.members,
            release_tag: set.release_tag().clone(),
            arch: request.arch,
        });
    }
    let comparison = SourceComparison::of(&set, request.arch, &tree);
    Ok(Arm::Adopt {
        set: Box::new(set),
        comparison,
    })
}

/// This tree's cdylib source fingerprint — the same function the producer ran
/// at the pinned commit.
pub fn tree_sdk_fingerprint(
    workspace_root: &Path,
) -> Result<String, guest_agent_build::GuestAgentBuildError> {
    guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)
}

/// The production (not `build_mode: dev`) sidecar members for `arch`.
fn production_sidecars(
    set: &PublishedImageSet,
    arch: GuestArch,
) -> impl Iterator<Item = &mvm_core::image_set::ImageSetMember> {
    set.manifest().members.iter().filter(move |member| {
        matches!(member.role, ImageSetRole::SdkSidecar(_))
            && member.target == MemberTarget::Arch(arch)
            && member.build_mode.is_none()
    })
}

fn set_publishes_sidecars(set: &PublishedImageSet, arch: GuestArch) -> bool {
    [GuestLibc::Glibc, GuestLibc::Musl].iter().all(|libc| {
        production_sidecars(set, arch).any(|member| member.role == ImageSetRole::SdkSidecar(*libc))
    })
}

/// The set publishes the dev variant of the default tenant for `arch`: a dev
/// kernel and a dev rootfs member.
fn set_publishes_dev_members(set: &PublishedImageSet, arch: GuestArch) -> bool {
    let dev = set
        .manifest()
        .members
        .iter()
        .filter(|member| {
            member.build_mode == Some(MemberBuildMode::Dev)
                && member.target == MemberTarget::Arch(arch)
                && matches!(
                    member.role,
                    ImageSetRole::WorkloadKernel(WorkloadImageProfile::DefaultTenant)
                        | ImageSetRole::WorkloadRootfs(WorkloadImageProfile::DefaultTenant)
                )
        })
        .count();
    dev == 2
}

/// The first fingerprint a production sidecar for `arch` declares, if any.
fn declared_sidecar_fingerprint(set: &PublishedImageSet, arch: GuestArch) -> Option<String> {
    production_sidecars(set, arch)
        .find_map(|member| member.source_fingerprint.as_ref())
        .map(|fp| fp.as_str().to_string())
}

/// Both SDK sidecar members of the set (glibc and musl, this architecture,
/// production build) declare `source_fingerprint` equal to `fingerprint`.
pub fn set_sidecars_match_tree(
    set: &PublishedImageSet,
    arch: GuestArch,
    fingerprint: &str,
) -> bool {
    [GuestLibc::Glibc, GuestLibc::Musl].iter().all(|libc| {
        production_sidecars(set, arch).any(|member| {
            member.role == ImageSetRole::SdkSidecar(*libc)
                && member
                    .source_fingerprint
                    .as_ref()
                    .is_some_and(|fp| fp.as_str() == fingerprint)
        })
    })
}

/// The set publishes the dev variant of the default tenant for `arch`, and —
/// by the accepted v1 over-approximation — the sidecars' source fingerprint
/// equals this tree's, which is the predicate the sidecar arm uses.
pub fn set_dev_members_match_tree(
    set: &PublishedImageSet,
    arch: GuestArch,
    fingerprint: &str,
) -> bool {
    set_publishes_dev_members(set, arch) && set_sidecars_match_tree(set, arch, fingerprint)
}

/// Fetch both sidecars from an already-acquired, verified set into
/// `cache_root` — the same install the release-channel download arm performs.
pub fn fetch_sidecars_from_set(
    set: &PublishedImageSet,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<(), crate::sdk_sidecar::SdkSidecarBuildError> {
    for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
        crate::sdk_sidecar::download_sdk_sidecar_from(set, arch, libc, cache_root)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
