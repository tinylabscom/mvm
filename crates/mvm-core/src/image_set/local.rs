//! Read a locally built image set: the same manifest a release publishes, from
//! two working trees instead of a release workflow.
//!
//! Nothing here verifies a signature, and nothing here can produce the
//! release tier. A local set is parsed by the release parser and held to the
//! release's structural rules, then accepted only if:
//!
//! 1. its producer is the two checkouts it was built from, never a release —
//!    a local file naming a release workflow is refused, not trusted;
//! 2. those checkouts are still what the caller finds on disk now, so a set
//!    built before an edit or a checkout of another commit is refused as stale;
//! 3. every member targets the requested guest architecture, and every role
//!    the caller needs is present;
//! 4. every artifact is a regular file inside the set's directory with the
//!    digest and size the manifest declares.
//!
//! What comes out is a [`LocalImageSet`], whose tier is always
//! [`ImageTrustTier::LocalDev`].

use std::path::Path;

use super::verify::{parse_manifest, verify_artifacts};
use super::{
    HostProtocolSupport, ImageSetError, ImageSetManifest, ImageSetProducer, ImageSetRequirement,
    ImageSetRole, ImageTrustTier, LocalCheckouts, MemberTarget, RepoIdentity, RequiredMember,
    VerifiedArtifact, check_protocol_compatibility, require_complete, validate_structure,
};
use crate::arch::GuestArch;
use crate::packs::Sha256Hex;

/// The name a locally built set's manifest has inside its directory.
pub const LOCAL_SET_MANIFEST_NAME: &str = "image-set.json";

/// One locally built set to read, and what the caller needs of it.
#[derive(Clone, Copy)]
pub struct LocalImageSetVerification<'a> {
    manifest_bytes: &'a [u8],
    /// Directory holding the member artifacts, each under its declared name.
    artifact_dir: &'a Path,
    /// The two checkouts as they are now, read by the caller immediately
    /// before this call.
    current: &'a LocalCheckouts,
    arch: GuestArch,
    roles: &'a [ImageSetRole],
    host_protocols: Option<&'a HostProtocolSupport>,
}

impl<'a> LocalImageSetVerification<'a> {
    pub fn new(
        manifest_bytes: &'a [u8],
        artifact_dir: &'a Path,
        current: &'a LocalCheckouts,
        arch: GuestArch,
    ) -> Self {
        Self {
            manifest_bytes,
            artifact_dir,
            current,
            arch,
            roles: &[],
            host_protocols: None,
        }
    }

    /// Also refuse a set that lacks any of `roles` for the requested
    /// architecture.
    #[must_use]
    pub fn require_roles(mut self, roles: &'a [ImageSetRole]) -> Self {
        self.roles = roles;
        self
    }

    /// Also refuse a set declaring protocols this host cannot speak.
    #[must_use]
    pub fn with_host_protocols(mut self, host: &'a HostProtocolSupport) -> Self {
        self.host_protocols = Some(host);
        self
    }
}

/// A locally built set that passed every check, for a caller that now wants to
/// use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalImageSet {
    pub manifest: ImageSetManifest,
    /// Digest of the manifest bytes that were read, to key a cache entry on.
    pub manifest_sha256: Sha256Hex,
    /// The checkouts the set was built from, which were also the checkouts on
    /// disk when it was read.
    pub checkouts: LocalCheckouts,
    pub artifacts: Vec<VerifiedArtifact>,
}

impl LocalImageSet {
    /// Always [`ImageTrustTier::LocalDev`]. There is no path from a local set
    /// to the release tier, whatever its manifest says.
    #[must_use]
    pub fn tier(&self) -> ImageTrustTier {
        ImageTrustTier::LocalDev
    }
}

/// Read `request`'s locally built set, refusing at the first check that fails.
pub fn verify_local_image_set(
    request: &LocalImageSetVerification<'_>,
) -> Result<LocalImageSet, ImageSetError> {
    let manifest_sha256 = Sha256Hex::from_bytes(request.manifest_bytes);
    let manifest = parse_manifest(request.manifest_bytes)?;
    validate_structure(&manifest)?;
    let recorded = require_local(&manifest)?.clone();
    check_fresh(&recorded, request.current)?;
    check_architecture(&manifest, request.arch)?;
    require_complete(
        &manifest,
        &ImageSetRequirement::new(required_members(request.roles, request.arch)),
    )?;
    if let Some(host) = request.host_protocols {
        check_protocol_compatibility(&manifest, host)?;
    }
    let artifacts = verify_artifacts(&manifest, request.artifact_dir)?;
    Ok(LocalImageSet {
        manifest,
        manifest_sha256,
        checkouts: recorded,
        artifacts,
    })
}

/// A set read from a local build must say it is one. A release producer in a
/// file nobody signed is a claim with nothing behind it.
fn require_local(manifest: &ImageSetManifest) -> Result<&LocalCheckouts, ImageSetError> {
    match &manifest.producer {
        ImageSetProducer::LocalCheckouts(local) => Ok(local),
        ImageSetProducer::Release(release) => Err(ImageSetError::LocalSetClaimsRelease {
            repository: release.repository.clone(),
            workflow: release.workflow.clone(),
        }),
    }
}

/// The image checkout is compared first: it is the one the contributor named,
/// so a stale set is most usefully reported against it.
fn check_fresh(recorded: &LocalCheckouts, current: &LocalCheckouts) -> Result<(), ImageSetError> {
    check_checkout_fresh("mvm-images", &recorded.images, &current.images)?;
    check_checkout_fresh("mvm", &recorded.mvm, &current.mvm)
}

fn check_checkout_fresh(
    checkout: &'static str,
    recorded: &RepoIdentity,
    current: &RepoIdentity,
) -> Result<(), ImageSetError> {
    if recorded == current {
        Ok(())
    } else {
        Err(ImageSetError::StaleLocalSet {
            checkout,
            recorded: Box::new(recorded.clone()),
            current: Box::new(current.clone()),
        })
    }
}

/// A local set is built for one guest architecture. Every member must serve
/// it; one built for another is a set for a different machine, not a partial
/// match.
fn check_architecture(manifest: &ImageSetManifest, arch: GuestArch) -> Result<(), ImageSetError> {
    match manifest
        .members
        .iter()
        .find(|member| !member.target.admits(arch))
    {
        Some(foreign) => Err(ImageSetError::WrongArchitecture {
            role: foreign.role,
            requested: arch,
            available: manifest
                .members
                .iter()
                .filter(|member| member.role == foreign.role)
                .map(|member| member.target)
                .collect(),
        }),
        None => Ok(()),
    }
}

fn required_members(roles: &[ImageSetRole], arch: GuestArch) -> Vec<RequiredMember> {
    roles
        .iter()
        .map(|&role| RequiredMember {
            role,
            target: if role.is_arch_independent() {
                MemberTarget::ArchIndependent
            } else {
                MemberTarget::Arch(arch)
            },
        })
        .collect()
}
