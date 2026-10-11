//! The signed revocation list for published image sets.
//!
//! mvm-images publishes this list from its own `revocations.yml` workflow, one
//! `revocation-list/v<N>` tag per publication, as the `revocations.json` and
//! `revocations.json.bundle` assets of its `revocations` release. The wire
//! format is [`PackRevocationList`], keyed on the image-set signer's key id and,
//! optionally, one member's pack hash.
//!
//! Three properties are checked here that the format alone does not give:
//!
//! - **Authority.** The signer must be exactly that workflow at a
//!   `revocation-list/v<N>` tag ([`image_set_revocation_publication`]). The
//!   authority is compiled in. It is never read from an image-set manifest's
//!   `revocation_channel`, and it is not the registry-pack revocation feed or
//!   this repository's pack revocation list.
//! - **Freshness.** The list must be inside its own validity window, and that
//!   window may not exceed [`MAX_IMAGE_SET_REVOCATION_VALIDITY`], so a signed
//!   list cannot be minted to stay current indefinitely.
//! - **Monotonicity.** The list carries no sequence number, so the checkpoint
//!   orders publications by the authenticated tag number `N` *and* by
//!   `issued_at`, and pins the exact document digest. Neither may go back, and
//!   a second document at the same `N` or the same `issued_at` is refused as
//!   equivocation. Re-presenting the exact accepted bytes is idempotent.
//!
//! A verified list is only as current as the moment it was loaded; a caller
//! re-loads it for each admission rather than holding one across a long run.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::image_verify::VerifiedSigner;
use crate::image_set::{
    ArtifactName, ImageSetError, ImageSetVerification, VerifiedImageSet, VerifiedSelectedArtifacts,
    verify_image_set, verify_image_set_artifacts,
};
use crate::pack_revocation::{PACK_REVOCATION_SCHEMA_VERSION, PackRevocationList};
use crate::packs::{PackRevocationChecker, RevocationStatus, Sha256Hex};
use crate::plan::bundle::KeyId;
use crate::release_trust::{RELEASE_OIDC_ISSUER, image_set_revocation_publication};

mod store;

pub use store::{
    ImageSetRevocationStore, ImageSetRevocationStoreError, load_image_set_revocations,
    update_image_set_revocations,
};

/// Where mvm-images publishes the list and its bundle. Informational: the
/// authority is the signer identity, not the location the bytes came from.
pub const IMAGE_SET_REVOCATION_CHANNEL: &str =
    "https://github.com/tinylabscom/mvm-images/releases/download/revocations/revocations.json";

/// Longest validity window a list may claim. The producer renews on a 45-day
/// window; anything longer than this is refused rather than trusted for longer.
pub const MAX_IMAGE_SET_REVOCATION_VALIDITY: Duration = Duration::days(62);

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

/// How far the image-set revocation feed has advanced on this host.
///
/// Persist it apart from the feed and pass it to the next verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSetRevocationCheckpoint {
    /// `N` of the `revocation-list/v<N>` tag the signing certificate names.
    pub publication: u64,
    /// The accepted list's own `issued_at`.
    pub issued_at: DateTime<Utc>,
    /// SHA-256 of the exact signed document bytes.
    pub sha256: Sha256Hex,
}

impl ImageSetRevocationCheckpoint {
    /// Refuse `self` as a successor of `previous` when it goes back or
    /// contradicts it. The same bytes are always acceptable again.
    fn check_successor_of(
        &self,
        previous: &ImageSetRevocationCheckpoint,
    ) -> Result<(), ImageSetRevocationError> {
        if self.publication < previous.publication || self.issued_at < previous.issued_at {
            return Err(ImageSetRevocationError::Rollback {
                previous_publication: previous.publication,
                previous_issued_at: previous.issued_at,
                received_publication: self.publication,
                received_issued_at: self.issued_at,
            });
        }
        if self.sha256 != previous.sha256
            && (self.publication == previous.publication || self.issued_at == previous.issued_at)
        {
            return Err(ImageSetRevocationError::Equivocation {
                publication: self.publication,
                issued_at: self.issued_at,
            });
        }
        Ok(())
    }

    /// Strictly later than `earlier` under the same order
    /// [`Self::check_successor_of`] enforces.
    pub(crate) fn supersedes(&self, earlier: &Self) -> bool {
        self != earlier && self.check_successor_of(earlier).is_ok()
    }
}

/// A list whose exact bytes passed authority, freshness and checkpoint checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedImageSetRevocations {
    list: PackRevocationList,
    checkpoint: ImageSetRevocationCheckpoint,
    signer_identity: String,
}

impl VerifiedImageSetRevocations {
    /// Checkpoint to persist after accepting this list.
    pub fn checkpoint(&self) -> &ImageSetRevocationCheckpoint {
        &self.checkpoint
    }

    /// The certificate identity that signed this list.
    pub fn signer_identity(&self) -> &str {
        &self.signer_identity
    }

    /// The end of the list's validity window.
    pub fn not_after(&self) -> DateTime<Utc> {
        self.list.not_after
    }

    /// How many entries the list carries.
    pub fn entry_count(&self) -> usize {
        self.list.revocations.len()
    }
}

impl PackRevocationChecker for VerifiedImageSetRevocations {
    fn status(&self, key_id: &KeyId, pack_hash: &Sha256Hex) -> RevocationStatus {
        self.list.status(key_id, pack_hash)
    }
}

/// Why an image-set revocation list cannot be trusted.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ImageSetRevocationError {
    #[error("image-set revocation list or its bundle exceeds the 1 MiB limit")]
    TooLarge,
    #[error("image-set revocation list signature is invalid: {0}")]
    SignatureInvalid(String),
    #[error(
        "image-set revocation list was signed by {identity} (issuer {issuer}), which is not \
         the mvm-images revocation workflow at a revocation-list/v<N> tag"
    )]
    UntrustedSigner { identity: String, issuer: String },
    #[error("image-set revocation list is not valid JSON: {0}")]
    Parse(String),
    #[error("image-set revocation list schema {found} is not supported (expected {supported})")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("image-set revocation list has issued_at at or after not_after")]
    InvalidValidityWindow,
    #[error(
        "image-set revocation list claims a validity window longer than {} days",
        MAX_IMAGE_SET_REVOCATION_VALIDITY.num_days()
    )]
    ValidityTooLong,
    #[error("image-set revocation list was issued at {issued_at}, after the current time {now}")]
    IssuedInFuture {
        issued_at: DateTime<Utc>,
        now: DateTime<Utc>,
    },
    #[error(
        "image-set revocation list expired at {not_after} (now {now}); fetch and apply the \
         current list from {IMAGE_SET_REVOCATION_CHANNEL}"
    )]
    Expired {
        not_after: DateTime<Utc>,
        now: DateTime<Utc>,
    },
    #[error(
        "image-set revocation list rolled back from publication {previous_publication} issued \
         {previous_issued_at} to publication {received_publication} issued {received_issued_at}"
    )]
    Rollback {
        previous_publication: u64,
        previous_issued_at: DateTime<Utc>,
        received_publication: u64,
        received_issued_at: DateTime<Utc>,
    },
    #[error(
        "image-set revocation publication {publication} issued {issued_at} conflicts with a \
         different list already accepted at that publication or time"
    )]
    Equivocation {
        publication: u64,
        issued_at: DateTime<Utc>,
    },
}

/// Authenticate and check one fetched list against the durable checkpoint.
///
/// The signature is verified over the raw bytes before they are parsed. A
/// missing `previous` is only correct for the very first list a host accepts.
pub fn verify_image_set_revocations(
    document: &[u8],
    bundle: &[u8],
    now: DateTime<Utc>,
    previous: Option<&ImageSetRevocationCheckpoint>,
) -> Result<VerifiedImageSetRevocations, ImageSetRevocationError> {
    verify_image_set_revocations_with(document, bundle, now, previous, verify_keyless_signer)
}

fn verify_keyless_signer(document: &[u8], bundle: &[u8]) -> Result<VerifiedSigner, String> {
    crate::crypto::image_verify::verify_signed_payload_signer(document, bundle, RELEASE_OIDC_ISSUER)
        .map_err(|error| error.to_string())
}

pub(crate) fn verify_image_set_revocations_with<F>(
    document: &[u8],
    bundle: &[u8],
    now: DateTime<Utc>,
    previous: Option<&ImageSetRevocationCheckpoint>,
    verify_signer: F,
) -> Result<VerifiedImageSetRevocations, ImageSetRevocationError>
where
    F: FnOnce(&[u8], &[u8]) -> Result<VerifiedSigner, String>,
{
    if document.len() > MAX_DOCUMENT_BYTES || bundle.len() > MAX_BUNDLE_BYTES {
        return Err(ImageSetRevocationError::TooLarge);
    }
    let signer =
        verify_signer(document, bundle).map_err(ImageSetRevocationError::SignatureInvalid)?;
    let publication = authorized_publication(&signer)?;
    let list: PackRevocationList = serde_json::from_slice(document)
        .map_err(|error| ImageSetRevocationError::Parse(error.to_string()))?;
    check_list(&list, now)?;
    let checkpoint = ImageSetRevocationCheckpoint {
        publication,
        issued_at: list.issued_at,
        sha256: Sha256Hex::from_bytes(document),
    };
    if let Some(previous) = previous {
        checkpoint.check_successor_of(previous)?;
    }
    Ok(VerifiedImageSetRevocations {
        list,
        checkpoint,
        signer_identity: signer.identity,
    })
}

fn authorized_publication(signer: &VerifiedSigner) -> Result<u64, ImageSetRevocationError> {
    let publication = (signer.issuer == RELEASE_OIDC_ISSUER)
        .then(|| image_set_revocation_publication(&signer.identity))
        .flatten();
    publication.ok_or_else(|| ImageSetRevocationError::UntrustedSigner {
        identity: signer.identity.clone(),
        issuer: signer.issuer.clone(),
    })
}

fn check_list(
    list: &PackRevocationList,
    now: DateTime<Utc>,
) -> Result<(), ImageSetRevocationError> {
    if list.schema_version != PACK_REVOCATION_SCHEMA_VERSION {
        return Err(ImageSetRevocationError::UnsupportedSchema {
            found: list.schema_version,
            supported: PACK_REVOCATION_SCHEMA_VERSION,
        });
    }
    if list.issued_at >= list.not_after {
        return Err(ImageSetRevocationError::InvalidValidityWindow);
    }
    if list.not_after - list.issued_at > MAX_IMAGE_SET_REVOCATION_VALIDITY {
        return Err(ImageSetRevocationError::ValidityTooLong);
    }
    if list.issued_at > now {
        return Err(ImageSetRevocationError::IssuedInFuture {
            issued_at: list.issued_at,
            now,
        });
    }
    if list.not_after <= now {
        return Err(ImageSetRevocationError::Expired {
            not_after: list.not_after,
            now,
        });
    }
    Ok(())
}

/// Verify a whole image set under a revocation list that has already been
/// loaded for this admission. The list is required, so there is no path
/// through here that admits a set with no revocation check at all.
pub fn verify_image_set_under_revocations(
    request: ImageSetVerification<'_>,
    revocations: &VerifiedImageSetRevocations,
) -> Result<VerifiedImageSet, ImageSetError> {
    verify_image_set(&request.with_revocations(revocations))
}

/// [`verify_image_set_under_revocations`] for a caller that boots only the
/// named artifacts. Set and member revocation are checked exactly as for the
/// whole set.
pub fn verify_image_set_artifacts_under_revocations(
    request: ImageSetVerification<'_>,
    selected: &[ArtifactName],
    revocations: &VerifiedImageSetRevocations,
) -> Result<VerifiedSelectedArtifacts, ImageSetError> {
    verify_image_set_artifacts(&request.with_revocations(revocations), selected)
}

#[cfg(test)]
mod tests;
