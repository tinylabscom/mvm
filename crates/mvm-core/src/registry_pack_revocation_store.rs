//! Durable, fail-closed local cache for signed registry-pack revocations.
//!
//! The checkpoint is persisted before the signed bytes. A crash between those
//! writes can make the cache unusable until a verified refresh, but cannot make
//! an older feed appear current. The owner-only directory protects this local
//! checkpoint from other accounts; it is not a hardware rollback counter.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::packs::{KeylessTrust, Sha256Hex};
use crate::registry_pack_revocation::{
    RegistryPackRevocationCheckpoint, RegistryPackRevocationError, VerifiedRegistryPackRevocations,
    verify_registry_pack_revocations,
};
use crate::util::atomic_io::{FileLock, write_private};

const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_STATE_BYTES: usize = 3 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 1024;

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFeed {
    document_base64: String,
    bundle_base64: String,
    bundle_sha256: Sha256Hex,
    checkpoint: RegistryPackRevocationCheckpoint,
}

struct FeedBytes {
    document: Vec<u8>,
    bundle: Vec<u8>,
    checkpoint: RegistryPackRevocationCheckpoint,
}

/// A caller supplies fetched bytes; this type performs no network access.
#[derive(Debug, Clone)]
pub struct RegistryPackRevocationStore {
    root: PathBuf,
}

impl RegistryPackRevocationStore {
    /// Use the standard owner-only location under `MVM_HOME`.
    pub fn in_mvm_home() -> Self {
        Self::new(crate::config::registry_pack_revocation_store_dir())
    }

    /// Use an explicit directory, primarily for isolated test homes.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
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
        check_sizes(document, bundle)?;
        self.ensure_root()?;
        let _lock = self.lock()?;
        let previous = self.read_checkpoint_for_update()?;
        let checkpoint = verify(document, bundle, now, previous.as_ref())?;
        if checkpoint.sha256 != Sha256Hex::from_bytes(document) {
            return Err(RegistryPackRevocationStoreError::Corrupt);
        }
        let stored = StoredFeed {
            document_base64: base64::engine::general_purpose::STANDARD.encode(document),
            bundle_base64: base64::engine::general_purpose::STANDARD.encode(bundle),
            bundle_sha256: Sha256Hex::from_bytes(bundle),
            checkpoint: checkpoint.clone(),
        };
        let checkpoint_bytes = serde_json::to_vec(&checkpoint)
            .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))?;
        let state_bytes = serde_json::to_vec(&stored)
            .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))?;
        if state_bytes.len() > MAX_STATE_BYTES {
            return Err(RegistryPackRevocationStoreError::TooLarge);
        }
        write_private(&self.checkpoint_path(), &checkpoint_bytes)
            .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))?;
        write_private(&self.state_path(), &state_bytes)
            .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))?;
        Ok(checkpoint)
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
        self.ensure_root()?;
        let _lock = self.lock()?;
        let feed = self
            .read_state()?
            .ok_or(RegistryPackRevocationStoreError::Missing)?;
        verify(&feed.document, &feed.bundle, now, &feed.checkpoint)
    }

    fn ensure_root(&self) -> Result<(), RegistryPackRevocationStoreError> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(RegistryPackRevocationStoreError::Corrupt);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RegistryPackRevocationStoreError::Storage(error.to_string()));
            }
        }
        crate::config::create_private_dir(&self.root)
            .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))
    }

    fn lock(&self) -> Result<FileLock, RegistryPackRevocationStoreError> {
        FileLock::acquire(&self.state_path())
            .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("feed.json")
    }

    fn checkpoint_path(&self) -> PathBuf {
        self.root.join("checkpoint.json")
    }

    fn read_state(&self) -> Result<Option<FeedBytes>, RegistryPackRevocationStoreError> {
        let checkpoint = read_limited(&self.checkpoint_path(), MAX_CHECKPOINT_BYTES)?;
        let state = read_limited(&self.state_path(), MAX_STATE_BYTES)?;
        let (Some(checkpoint), Some(state)) = (checkpoint, state) else {
            return if !self.checkpoint_path().exists() && !self.state_path().exists() {
                Ok(None)
            } else {
                Err(RegistryPackRevocationStoreError::Incomplete)
            };
        };
        let checkpoint = parse_checkpoint(&checkpoint)?;
        let feed = decode_state(&state)?;
        if feed.checkpoint != checkpoint {
            return Err(RegistryPackRevocationStoreError::Incomplete);
        }
        Ok(Some(feed))
    }

    fn read_checkpoint_for_update(
        &self,
    ) -> Result<Option<RegistryPackRevocationCheckpoint>, RegistryPackRevocationStoreError> {
        let checkpoint = read_limited(&self.checkpoint_path(), MAX_CHECKPOINT_BYTES)?;
        let state = read_limited(&self.state_path(), MAX_STATE_BYTES)?;
        match (checkpoint, state) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(RegistryPackRevocationStoreError::Incomplete),
            (Some(checkpoint), state) => {
                let checkpoint = parse_checkpoint(&checkpoint)?;
                if let Some(state) = state {
                    let feed = decode_state(&state)?;
                    if feed.checkpoint.sequence > checkpoint.sequence
                        || (feed.checkpoint.sequence == checkpoint.sequence
                            && feed.checkpoint != checkpoint)
                    {
                        return Err(RegistryPackRevocationStoreError::Incomplete);
                    }
                }
                Ok(Some(checkpoint))
            }
        }
    }
}

fn parse_checkpoint(
    bytes: &[u8],
) -> Result<RegistryPackRevocationCheckpoint, RegistryPackRevocationStoreError> {
    let checkpoint: RegistryPackRevocationCheckpoint =
        serde_json::from_slice(bytes).map_err(|_| RegistryPackRevocationStoreError::Corrupt)?;
    if checkpoint.sequence == 0 {
        return Err(RegistryPackRevocationStoreError::Corrupt);
    }
    Ok(checkpoint)
}

fn decode_state(bytes: &[u8]) -> Result<FeedBytes, RegistryPackRevocationStoreError> {
    let stored: StoredFeed =
        serde_json::from_slice(bytes).map_err(|_| RegistryPackRevocationStoreError::Corrupt)?;
    if stored.checkpoint.sequence == 0 {
        return Err(RegistryPackRevocationStoreError::Corrupt);
    }
    let document = decode_limited(&stored.document_base64, MAX_DOCUMENT_BYTES)?;
    let bundle = decode_limited(&stored.bundle_base64, MAX_BUNDLE_BYTES)?;
    if Sha256Hex::from_bytes(&document) != stored.checkpoint.sha256
        || Sha256Hex::from_bytes(&bundle) != stored.bundle_sha256
    {
        return Err(RegistryPackRevocationStoreError::Corrupt);
    }
    Ok(FeedBytes {
        document,
        bundle,
        checkpoint: stored.checkpoint,
    })
}

fn check_sizes(document: &[u8], bundle: &[u8]) -> Result<(), RegistryPackRevocationStoreError> {
    if document.len() > MAX_DOCUMENT_BYTES || bundle.len() > MAX_BUNDLE_BYTES {
        return Err(RegistryPackRevocationStoreError::TooLarge);
    }
    Ok(())
}

fn decode_limited(
    encoded: &str,
    limit: usize,
) -> Result<Vec<u8>, RegistryPackRevocationStoreError> {
    if encoded.len() > limit.div_ceil(3) * 4 + 4 {
        return Err(RegistryPackRevocationStoreError::TooLarge);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| RegistryPackRevocationStoreError::Corrupt)?;
    if bytes.len() > limit {
        return Err(RegistryPackRevocationStoreError::TooLarge);
    }
    Ok(bytes)
}

fn read_limited(
    path: &Path,
    limit: usize,
) -> Result<Option<Vec<u8>>, RegistryPackRevocationStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RegistryPackRevocationStoreError::Storage(error.to_string())),
    };
    if !metadata.file_type().is_file() {
        return Err(RegistryPackRevocationStoreError::Corrupt);
    }
    let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if size > limit {
        return Err(RegistryPackRevocationStoreError::TooLarge);
    }
    let mut file = fs::File::open(path)
        .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RegistryPackRevocationStoreError::Storage(error.to_string()))?;
    if bytes.len() > limit {
        return Err(RegistryPackRevocationStoreError::TooLarge);
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

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
