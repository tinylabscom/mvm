//! The prepared, on-disk copy of the image-set revocation list.
//!
//! An operator or a refresh job applies a fetched list with
//! [`ImageSetRevocationStore::update`]; admission reads it back with
//! [`ImageSetRevocationStore::load`], which re-authenticates the cached bytes
//! and their checkpoint on every call. Nothing here touches the network, and a
//! missing, partial, expired or modified cache is an error, never an empty list.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{
    IMAGE_SET_REVOCATION_CHANNEL, ImageSetRevocationCheckpoint, ImageSetRevocationError,
    VerifiedImageSetRevocations, verify_image_set_revocations_with, verify_keyless_signer,
};
use crate::crypto::image_verify::VerifiedSigner;
use crate::packs::Sha256Hex;
use crate::signed_feed_store::{FeedCheckpoint, FeedStoreFault, SignedFeedStore};

/// Why the prepared image-set revocation list cannot be used.
#[derive(Debug, Error)]
pub enum ImageSetRevocationStoreError {
    #[error(
        "no image-set revocation list has been applied on this host; download revocations.json \
         and revocations.json.bundle from {IMAGE_SET_REVOCATION_CHANNEL} and apply them with \
         `mvmctl image revocations update`"
    )]
    Missing,
    #[error(
        "the image-set revocation cache is incomplete: its checkpoint and its stored list \
         disagree, or one of the two files is missing. After an interrupted update, re-apply \
         a signed list at least as new as the recorded checkpoint with `mvmctl image \
         revocations update`. A missing checkpoint cannot be repaired that way; clearing the \
         cache by hand also discards this host's rollback protection"
    )]
    Incomplete,
    #[error("the image-set revocation cache is corrupt or was modified")]
    Corrupt,
    #[error("the image-set revocation cache exceeds its size limit")]
    TooLarge,
    #[error("{0}")]
    Verification(#[from] ImageSetRevocationError),
    #[error("image-set revocation storage failed: {0}")]
    Storage(String),
}

impl From<FeedStoreFault> for ImageSetRevocationStoreError {
    fn from(fault: FeedStoreFault) -> Self {
        match fault {
            FeedStoreFault::Missing => Self::Missing,
            FeedStoreFault::Incomplete => Self::Incomplete,
            FeedStoreFault::Corrupt => Self::Corrupt,
            FeedStoreFault::TooLarge => Self::TooLarge,
            FeedStoreFault::Storage(reason) => Self::Storage(reason),
        }
    }
}

impl FeedCheckpoint for ImageSetRevocationCheckpoint {
    fn document_sha256(&self) -> &Sha256Hex {
        &self.sha256
    }

    fn is_well_formed(&self) -> bool {
        self.publication != 0
    }

    fn supersedes(&self, earlier: &Self) -> bool {
        ImageSetRevocationCheckpoint::supersedes(self, earlier)
    }
}

type SignerCheck = fn(&[u8], &[u8]) -> Result<VerifiedSigner, String>;

/// The owner-only directory holding the applied list and its checkpoint.
#[derive(Debug, Clone)]
pub struct ImageSetRevocationStore {
    feed: SignedFeedStore,
    verify_signer: SignerCheck,
}

impl ImageSetRevocationStore {
    /// The standard location under `MVM_HOME`.
    pub fn in_mvm_home() -> Self {
        Self::new(crate::config::image_set_revocation_store_dir())
    }

    /// An explicit directory, for an isolated home.
    pub fn new(root: PathBuf) -> Self {
        Self {
            feed: SignedFeedStore::new(root),
            verify_signer: verify_keyless_signer,
        }
    }

    /// Authenticate a fetched list against the persisted checkpoint, then
    /// persist it. A rolled-back, equivocating, stale or wrongly signed list
    /// leaves the cache untouched.
    pub fn update(
        &self,
        document: &[u8],
        bundle: &[u8],
        now: DateTime<Utc>,
    ) -> Result<ImageSetRevocationCheckpoint, ImageSetRevocationStoreError> {
        self.feed
            .update_with(document, bundle, |bytes, signature, previous| {
                verify_image_set_revocations_with(
                    bytes,
                    signature,
                    now,
                    previous,
                    self.verify_signer,
                )
                .map(|verified| verified.checkpoint().clone())
                .map_err(ImageSetRevocationStoreError::Verification)
            })
    }

    /// Re-authenticate the applied list for use at `now`.
    pub fn load(
        &self,
        now: DateTime<Utc>,
    ) -> Result<VerifiedImageSetRevocations, ImageSetRevocationStoreError> {
        self.feed.load_with(|bytes, signature, checkpoint| {
            let verified =
                verify_image_set_revocations_with(bytes, signature, now, None, self.verify_signer)?;
            if verified.checkpoint() != checkpoint {
                return Err(ImageSetRevocationStoreError::Corrupt);
            }
            Ok(verified)
        })
    }

    #[cfg(test)]
    pub(super) fn with_signer_check(mut self, verify_signer: SignerCheck) -> Self {
        self.verify_signer = verify_signer;
        self
    }

    #[cfg(test)]
    pub(super) fn state_path(&self) -> PathBuf {
        self.feed.state_path()
    }

    #[cfg(test)]
    pub(super) fn checkpoint_path(&self) -> PathBuf {
        self.feed.checkpoint_path()
    }
}

/// Apply a fetched list to the host's store now, and record the advance in
/// the local audit log.
pub fn update_image_set_revocations(
    document: &[u8],
    bundle: &[u8],
) -> Result<ImageSetRevocationCheckpoint, ImageSetRevocationStoreError> {
    let checkpoint = ImageSetRevocationStore::in_mvm_home().update(document, bundle, Utc::now())?;
    crate::policy::audit::event(crate::policy::audit::LocalAuditKind::ImageSetRevocationUpdate)
        .detail(format!(
            "publication={} issued_at={} sha256={}",
            checkpoint.publication,
            checkpoint.issued_at.to_rfc3339(),
            checkpoint.sha256.as_str()
        ))
        .emit();
    Ok(checkpoint)
}

/// Load the host's applied image-set revocation list for an admission now.
pub fn load_image_set_revocations()
-> Result<VerifiedImageSetRevocations, ImageSetRevocationStoreError> {
    ImageSetRevocationStore::in_mvm_home().load(Utc::now())
}
