//! Authenticated revocation policy for offline built-pack admission.
//!
//! Loads the image-set revocation authority using the existing signed-feed
//! verifier, enforcing freshness checks and durable rollback checkpoints.
//! A missing or stale revocation list causes offline admission to fail
//! closed — a host with no applied list cannot admit a built pack.
//!
//! The revocation policy is content-addressed by the authenticated
//! document digest, so the same bytes can be re-verified across offline
//! boots without network access.

use anyhow::Result;
use chrono::{DateTime, Utc};

use mvm_core::image_set_revocation::{
    ImageSetRevocationStore, ImageSetRevocationStoreError, VerifiedImageSetRevocations,
};
use mvm_core::packs::{PackRevocationChecker, RevocationStatus, Sha256Hex};
use mvm_core::plan::bundle::KeyId;

/// A revocation checker that loads the authenticated image-set revocation
/// list from the local store, enforcing freshness at load time.
///
/// The owner approved using the mvm-images `revocations.yml` workflow:
/// the applied list is signed by that workflow's keyless identity, and
/// a fresh list must have been applied before any offline admission.
#[derive(Debug)]
pub struct OfflineRevocationPolicy {
    verified: VerifiedImageSetRevocations,
}

impl OfflineRevocationPolicy {
    /// Load and re-authenticate the applied revocation list at `now`.
    ///
    /// Fails if no list has been applied, if the applied list is stale
    /// (past its `not_after` window), or if the cache has been tampered
    /// with. The durable rollback checkpoint prevents accepting a list
    /// older than one already seen.
    pub fn load_at(
        store: &ImageSetRevocationStore,
        now: DateTime<Utc>,
    ) -> Result<Self, ImageSetRevocationStoreError> {
        let verified = store.load(now)?;
        Ok(Self { verified })
    }

    /// Load from the host's default MVM_HOME store.
    pub fn load_from_host() -> Result<Self, ImageSetRevocationStoreError> {
        let store = ImageSetRevocationStore::in_mvm_home();
        Self::load_at(&store, Utc::now())
    }

    /// The authenticated signer identity of the loaded list.
    pub fn signer_identity(&self) -> &str {
        self.verified.signer_identity()
    }

    /// The end of the loaded list's validity window.
    pub fn not_after(&self) -> DateTime<Utc> {
        self.verified.not_after()
    }

    /// How many entries the loaded list carries.
    pub fn entry_count(&self) -> usize {
        self.verified.entry_count()
    }
}

impl PackRevocationChecker for OfflineRevocationPolicy {
    fn status(&self, key_id: &KeyId, pack_hash: &Sha256Hex) -> RevocationStatus {
        self.verified.status(key_id, pack_hash)
    }
}

/// Load an authenticated revocation policy for offline built-pack admission.
///
/// This is the entry point for the offline admission path: it loads the
/// applied image-set revocation list, re-authenticates it against the
/// durable checkpoint, and returns a `PackRevocationChecker` that can be
/// passed to pack verification.
///
/// The caller is responsible for having applied a signed list via
/// `mvmctl image revocations update` before any offline admission.
pub fn load_offline_revocation_policy() -> Result<OfflineRevocationPolicy> {
    OfflineRevocationPolicy::load_from_host().map_err(|e| match e {
        ImageSetRevocationStoreError::Missing => anyhow::anyhow!(
            "offline built-pack admission requires an applied image-set revocation list; \
             download and apply one with `mvmctl image revocations update`"
        ),
        ImageSetRevocationStoreError::Verification(ref inner) => anyhow::anyhow!(
            "the applied image-set revocation list failed re-authentication for offline \
             admission: {inner}; fetch and apply a fresh list with \
             `mvmctl image revocations update`"
        ),
        other => anyhow::anyhow!("loading revocation policy for offline admission: {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_store_gives_clear_message() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = ImageSetRevocationStore::new(tmp.path().join("nonexistent"));
        let err = OfflineRevocationPolicy::load_at(&store, Utc::now())
            .expect_err("should fail on missing store");
        assert!(
            matches!(err, ImageSetRevocationStoreError::Missing),
            "got: {err}"
        );
    }
}
