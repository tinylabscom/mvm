//! The lock that pins `mvm` to exactly one image set.

use serde::{Deserialize, Serialize};

use super::identity::{ArtifactName, ReleaseTag, RepositorySlug, TagRef, WorkflowPath};
use crate::packs::{KeylessTrust, Sha256Hex};
use crate::release_trust::RELEASE_OIDC_ISSUER;

pub const IMAGE_LOCK_SCHEMA_VERSION: u32 = 1;

/// Everything needed to accept one set and refuse every other: where it was
/// published, the manifest's digest, and who must have signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageLock {
    pub schema_version: u32,
    pub repository: RepositorySlug,
    pub release_tag: ReleaseTag,
    pub manifest_asset: ArtifactName,
    pub manifest_sha256: Sha256Hex,
    pub signing_identity: SigningIdentity,
}

/// The workflow and ref a keyless signing certificate must name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningIdentity {
    pub workflow: WorkflowPath,
    pub tag_ref: TagRef,
}

impl SigningIdentity {
    /// The certificate identity GitHub Actions issues for this workflow at this
    /// ref, in the same shape `release_trust` pins for the release trains.
    /// The host is part of the identity, so moving hosting is a trust-root
    /// change rather than a configuration one.
    pub fn certificate_identity(&self, repository: &RepositorySlug) -> String {
        format!(
            "https://github.com/{repository}/{}@{}",
            self.workflow, self.tag_ref
        )
    }
}

impl ImageLock {
    /// The keyless trust root a signature over the locked manifest must satisfy.
    pub fn keyless_trust(&self) -> KeylessTrust {
        KeylessTrust {
            accepted_identities: vec![self.signing_identity.certificate_identity(&self.repository)],
            issuer: RELEASE_OIDC_ISSUER.to_string(),
        }
    }
}
