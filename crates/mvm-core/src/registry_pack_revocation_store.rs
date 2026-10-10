//! Durable, fail-closed local cache for signed registry-pack revocations.
//!
//! The file mechanics and crash ordering live in
//! [`crate::signed_feed_store`]; this module binds them to the registry-pack
//! checkpoint, verifier and directory. The checkpoint is persisted before the
//! signed bytes, so a crash between those writes can make the cache unusable
//! until a verified refresh, but cannot make an older feed appear current.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::packs::{KeylessTrust, Sha256Hex};
use crate::registry_pack_revocation::{
    RegistryPackRevocationCheckpoint, RegistryPackRevocationError, VerifiedRegistryPackRevocations,
    verify_registry_pack_revocations,
};
use crate::signed_feed_store::{FeedCheckpoint, FeedStoreFault, SignedFeedStore};

#[derive(Debug, Error)]
pub enum RegistryPackRevocationStoreError {
    #[error("registry-pack revocation cache is missing; a signed feed must be fetched")]
    Missing,
    #[error("registry-pack revocation cache is incomplete; a verified refresh is required")]
    Incomplete,
    #[error("registry-pack revocation cache is corrupt or was modified")]
    Corrupt,
    #[error("registry-pack revocation cache exceeds its size limit")]
    TooLarge,
    #[error("registry-pack revocation signature, freshness, or checkpoint check failed: {0}")]
    Verification(#[from] RegistryPackRevocationError),
    #[error("registry-pack revocation storage failed: {0}")]
    Storage(String),
}

impl From<FeedStoreFault> for RegistryPackRevocationStoreError {
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

impl FeedCheckpoint for RegistryPackRevocationCheckpoint {
    fn document_sha256(&self) -> &Sha256Hex {
        &self.sha256
    }

    fn is_well_formed(&self) -> bool {
        self.sequence != 0
    }

    fn supersedes(&self, earlier: &Self) -> bool {
        self.sequence > earlier.sequence
    }
}

/// A caller supplies fetched bytes; this type performs no network access.
#[derive(Debug, Clone)]
pub struct RegistryPackRevocationStore {
    feed: SignedFeedStore,
}

impl RegistryPackRevocationStore {
    /// Use the standard owner-only location under `MVM_HOME`.
    pub fn in_mvm_home() -> Self {
        Self::new(crate::config::registry_pack_revocation_store_dir())
    }

    /// Use an explicit directory, primarily for isolated test homes.
    pub fn new(root: PathBuf) -> Self {
        Self {
            feed: SignedFeedStore::new(root),
        }
    }

    /// Authenticate and durably cache a fetched feed before it can be used.
    ///
    /// A verified refresh can repair a crash after checkpoint persistence.
    /// It cannot silently reset a present checkpoint or accept an older feed.
    pub fn update(
        &self,
        document: &[u8],
        bundle: &[u8],
        release_trust: &KeylessTrust,
        now: DateTime<Utc>,
    ) -> Result<RegistryPackRevocationCheckpoint, RegistryPackRevocationStoreError> {
        self.update_with(document, bundle, now, |bytes, signature, at, previous| {
            verify_registry_pack_revocations(bytes, signature, release_trust, at, previous)
                .map(|verified| verified.checkpoint().clone())
        })
    }

    /// Re-authenticate cached bytes on every use, including expiry and the
    /// independent durable checkpoint. A missing cache is never an empty list.
    pub fn load(
        &self,
        release_trust: &KeylessTrust,
        now: DateTime<Utc>,
    ) -> Result<VerifiedRegistryPackRevocations, RegistryPackRevocationStoreError> {
        self.load_with(now, |bytes, signature, at, checkpoint| {
            let verified =
                verify_registry_pack_revocations(bytes, signature, release_trust, at, None)?;
            if verified.checkpoint() != checkpoint {
                return Err(RegistryPackRevocationStoreError::Corrupt);
            }
            Ok(verified)
        })
    }

    fn update_with<F>(
        &self,
        document: &[u8],
        bundle: &[u8],
        now: DateTime<Utc>,
        verify: F,
    ) -> Result<RegistryPackRevocationCheckpoint, RegistryPackRevocationStoreError>
    where
        F: FnOnce(
            &[u8],
            &[u8],
            DateTime<Utc>,
            Option<&RegistryPackRevocationCheckpoint>,
        ) -> Result<RegistryPackRevocationCheckpoint, RegistryPackRevocationError>,
    {
        self.feed
            .update_with(document, bundle, |bytes, signature, previous| {
                verify(bytes, signature, now, previous)
                    .map_err(RegistryPackRevocationStoreError::Verification)
            })
    }

    fn load_with<T, F>(
        &self,
        now: DateTime<Utc>,
        verify: F,
    ) -> Result<T, RegistryPackRevocationStoreError>
    where
        F: FnOnce(
            &[u8],
            &[u8],
            DateTime<Utc>,
            &RegistryPackRevocationCheckpoint,
        ) -> Result<T, RegistryPackRevocationStoreError>,
    {
        self.feed
            .load_with(|bytes, signature, checkpoint| verify(bytes, signature, now, checkpoint))
    }

    #[cfg(test)]
    fn state_path(&self) -> PathBuf {
        self.feed.state_path()
    }

    #[cfg(test)]
    fn checkpoint_path(&self) -> PathBuf {
        self.feed.checkpoint_path()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine as _;
    use chrono::TimeZone;

    use super::*;
    use crate::util::atomic_io::write_private;

    type StoredFeed = crate::signed_feed_store::StoredFeed<RegistryPackRevocationCheckpoint>;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, day, 0, 0, 0)
            .single()
            .expect("valid test date")
    }

    fn document(sequence: u64, changed: bool) -> Vec<u8> {
        let revoked_identities = if changed {
            vec!["changed identity"]
        } else {
            Vec::new()
        };
        serde_json::json!({
            "schema_version": 1,
            "sequence": sequence,
            "issued_at": at(6),
            "not_after": at(8),
            "revoked_identities": revoked_identities,
            "revoked_manifests": []
        })
        .to_string()
        .into_bytes()
    }

    fn signed(
        bytes: &[u8],
        signature: &[u8],
        now: DateTime<Utc>,
        previous: Option<&RegistryPackRevocationCheckpoint>,
    ) -> Result<RegistryPackRevocationCheckpoint, RegistryPackRevocationError> {
        if signature != b"signed" {
            return Err(RegistryPackRevocationError::SignatureInvalid(
                "test signature rejected".to_string(),
            ));
        }
        let json: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| RegistryPackRevocationError::Parse(error.to_string()))?;
        let sequence = json["sequence"]
            .as_u64()
            .ok_or(RegistryPackRevocationError::InvalidSequence)?;
        let expiry: DateTime<Utc> = serde_json::from_value(json["not_after"].clone())
            .map_err(|error| RegistryPackRevocationError::Parse(error.to_string()))?;
        if now >= expiry {
            return Err(RegistryPackRevocationError::Expired);
        }
        let checkpoint = RegistryPackRevocationCheckpoint {
            sequence,
            sha256: Sha256Hex::from_bytes(bytes),
        };
        if let Some(previous) = previous {
            if sequence < previous.sequence {
                return Err(RegistryPackRevocationError::Rollback {
                    previous: previous.sequence,
                    received: sequence,
                });
            }
            if sequence == previous.sequence && checkpoint.sha256 != previous.sha256 {
                return Err(RegistryPackRevocationError::Equivocation { sequence });
            }
        }
        Ok(checkpoint)
    }

    fn load_test(
        store: &RegistryPackRevocationStore,
        now: DateTime<Utc>,
    ) -> Result<RegistryPackRevocationCheckpoint, RegistryPackRevocationStoreError> {
        store.load_with(now, |bytes, bundle, at, checkpoint| {
            let verified = signed(bytes, bundle, at, None)?;
            if &verified != checkpoint {
                return Err(RegistryPackRevocationStoreError::Corrupt);
            }
            Ok(verified)
        })
    }

    #[test]
    fn update_and_load_reverify_signed_bytes_and_private_modes() {
        let temp = tempfile::tempdir().expect("test dir");
        let store = RegistryPackRevocationStore::new(temp.path().join("revocations"));
        assert!(matches!(
            load_test(&store, at(7)),
            Err(RegistryPackRevocationStoreError::Missing)
        ));
        let bytes = document(1, false);
        let checkpoint = store
            .update_with(&bytes, b"signed", at(7), signed)
            .expect("verified update");
        assert_eq!(load_test(&store, at(7)).expect("load"), checkpoint);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for path in [store.checkpoint_path(), store.state_path()] {
                let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
    }

    #[test]
    fn tamper_and_expiry_fail_closed() {
        let temp = tempfile::tempdir().expect("test dir");
        let store = RegistryPackRevocationStore::new(temp.path().join("revocations"));
        let bytes = document(1, false);
        store
            .update_with(&bytes, b"signed", at(7), signed)
            .expect("update");
        assert!(matches!(
            load_test(&store, at(8)),
            Err(RegistryPackRevocationStoreError::Verification(
                RegistryPackRevocationError::Expired
            ))
        ));
        let mut state: StoredFeed =
            serde_json::from_slice(&fs::read(store.state_path()).expect("read")).expect("parse");
        state.bundle_base64 = base64::engine::general_purpose::STANDARD.encode(b"tampered");
        fs::write(
            store.state_path(),
            serde_json::to_vec(&state).expect("serialize"),
        )
        .expect("tamper");
        assert!(matches!(
            load_test(&store, at(7)),
            Err(RegistryPackRevocationStoreError::Corrupt)
        ));
    }

    #[test]
    fn rollback_and_equivocation_refused_before_persist() {
        let temp = tempfile::tempdir().expect("test dir");
        let store = RegistryPackRevocationStore::new(temp.path().join("revocations"));
        store
            .update_with(&document(2, false), b"signed", at(7), signed)
            .expect("first");
        let before = fs::read(store.state_path()).expect("read state");
        assert!(matches!(
            store.update_with(&document(1, false), b"signed", at(7), signed),
            Err(RegistryPackRevocationStoreError::Verification(
                RegistryPackRevocationError::Rollback { .. }
            ))
        ));
        assert!(matches!(
            store.update_with(&document(2, true), b"signed", at(7), signed),
            Err(RegistryPackRevocationStoreError::Verification(
                RegistryPackRevocationError::Equivocation { .. }
            ))
        ));
        assert_eq!(fs::read(store.state_path()).expect("read state"), before);
    }

    #[test]
    fn partial_checkpoint_write_fails_load_but_verified_refresh_repairs_it() {
        let temp = tempfile::tempdir().expect("test dir");
        let store = RegistryPackRevocationStore::new(temp.path().join("revocations"));
        store
            .update_with(&document(1, false), b"signed", at(7), signed)
            .expect("first");
        let second = document(2, false);
        let checkpoint = signed(&second, b"signed", at(7), None).expect("verified");
        write_private(
            &store.checkpoint_path(),
            &serde_json::to_vec(&checkpoint).expect("serialize"),
        )
        .expect("simulate checkpoint-first crash");
        assert!(matches!(
            load_test(&store, at(7)),
            Err(RegistryPackRevocationStoreError::Incomplete)
        ));
        store
            .update_with(&second, b"signed", at(7), signed)
            .expect("verified recovery");
        assert_eq!(
            load_test(&store, at(7)).expect("recovered feed"),
            checkpoint
        );
    }

    #[test]
    fn missing_half_and_bad_signature_are_refused() {
        let temp = tempfile::tempdir().expect("test dir");
        let store = RegistryPackRevocationStore::new(temp.path().join("revocations"));
        assert!(matches!(
            store.update_with(&document(1, false), b"bad", at(7), signed),
            Err(RegistryPackRevocationStoreError::Verification(
                RegistryPackRevocationError::SignatureInvalid(_)
            ))
        ));
        assert!(matches!(
            load_test(&store, at(7)),
            Err(RegistryPackRevocationStoreError::Missing)
        ));
        write_private(&store.checkpoint_path(), b"{}").expect("write partial checkpoint");
        assert!(matches!(
            load_test(&store, at(7)),
            Err(RegistryPackRevocationStoreError::Incomplete)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_store_directory_is_refused() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("test dir");
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("target dir");
        let root = temp.path().join("revocations");
        symlink(&target, &root).expect("symlink");
        let store = RegistryPackRevocationStore::new(root);
        assert!(matches!(
            load_test(&store, at(7)),
            Err(RegistryPackRevocationStoreError::Corrupt)
        ));
    }
}
