//! Durable one-shot consumption for protected cold-HVF owner grants.
//!
//! Initialization belongs to the trusted installer. A missing or corrupt
//! journal never becomes an empty authority namespace.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use mvm_core::{atomic_io, crypto::hvf_owner_grant::VerifiedOwnerGrant};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const VERSION: u32 = 1;
const MAX_RECORDS: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;

/// Durable one-shot disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum GrantDisposition {
    Consumed {
        request_digest: [u8; 32],
        consumed_at_secs: u64,
        expires_at_secs: u64,
    },
    Revoked {
        revoked_at_secs: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRecord {
    grant_id: [u8; 32],
    disposition: GrantDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantJournal {
    version: u32,
    provider_id: [u8; 32],
    last_observed_secs: u64,
    records: Vec<GrantRecord>,
}

/// Non-wire proof that exact provider authority was durably consumed.
#[derive(Debug)]
pub struct ConsumedOwnerGrant {
    grant_id: [u8; 32],
    request_digest: [u8; 32],
    expires_at_secs: u64,
}

impl ConsumedOwnerGrant {
    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }

    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    #[must_use]
    pub fn expires_at_secs(&self) -> u64 {
        self.expires_at_secs
    }
}

/// Reconciliation view after an uncertain publication outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerGrantDisposition {
    Consumed,
    Revoked,
}

/// Protected grant-store failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OwnerGrantStoreError {
    #[error("protected HVF owner grant journal is missing")]
    Missing,
    #[error("protected HVF owner grant journal is corrupt")]
    Corrupt,
    #[error("HVF owner grant has already been consumed")]
    AlreadyConsumed,
    #[error("HVF owner grant was revoked")]
    Revoked,
    #[error("HVF owner grant is expired")]
    Expired,
    #[error("HVF owner grant clock regressed after verification")]
    ClockRegression,
    #[error("HVF owner grant journal capacity is exhausted")]
    Exhausted,
    #[error("HVF owner grant disposition conflicts with retained state")]
    Conflict,
    #[error("HVF owner grant storage failed")]
    Storage(#[source] anyhow::Error),
    #[error("HVF owner grant commit outcome is unknown")]
    CommitUnknown {
        grant_id: [u8; 32],
        #[source]
        source: io::Error,
    },
}

type Commit = dyn Fn(&Path, &[u8]) -> io::Result<()> + Send + Sync;

/// Trusted time source owned by the protected provider.
pub trait OwnerGrantClock: Send + Sync {
    /// Current Unix seconds.
    ///
    /// # Errors
    /// Returns an error when the provider cannot establish security time.
    fn now_secs(&self) -> io::Result<u64>;
}

/// Host wall clock under the trusted-provider deployment boundary.
#[derive(Debug)]
pub struct SystemOwnerGrantClock;

impl OwnerGrantClock for SystemOwnerGrantClock {
    fn now_secs(&self) -> io::Result<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(io::Error::other)
    }
}

/// One explicitly initialized provider-owned journal.
#[derive(Clone)]
pub struct OwnerGrantStore {
    path: PathBuf,
    provider_id: [u8; 32],
    clock: Arc<dyn OwnerGrantClock>,
    commit: Arc<Commit>,
}

impl std::fmt::Debug for OwnerGrantStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerGrantStore")
            .field("path", &self.path)
            .field("provider_id", &self.provider_id)
            .finish_non_exhaustive()
    }
}

impl OwnerGrantStore {
    /// Commissioned provider identity bound to this journal handle.
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    /// Initialize an empty namespace exactly once.
    ///
    /// The trusted installer must create, validate and protect the complete
    /// parent ancestry under the separately commissioned provider UID. This
    /// file-level API does not establish that deployment boundary.
    ///
    /// # Errors
    /// Refuses an existing namespace or unavailable file-level storage.
    pub fn initialize(
        path: impl AsRef<Path>,
        provider_id: [u8; 32],
        clock: Arc<dyn OwnerGrantClock>,
    ) -> Result<Self, OwnerGrantStoreError> {
        if provider_id == [0; 32] {
            return Err(OwnerGrantStoreError::Conflict);
        }
        let store = Self::at(path, provider_id, clock);
        let _lock = store.lock()?;
        let now_secs = store.now_secs()?;
        let bytes = serialize(&GrantJournal {
            version: VERSION,
            provider_id,
            last_observed_secs: now_secs,
            records: Vec::new(),
        })?;
        match atomic_io::write_private_new(&store.path, &bytes)
            .map_err(|error| OwnerGrantStoreError::Storage(error.into()))?
        {
            atomic_io::NewFile::Created => Ok(store),
            atomic_io::NewFile::AlreadyPresent => Err(OwnerGrantStoreError::Conflict),
        }
    }

    /// Open an existing namespace without creating missing state.
    ///
    /// # Errors
    /// Refuses missing, corrupt, oversized or unavailable file-level storage.
    pub fn open(
        path: impl AsRef<Path>,
        provider_id: [u8; 32],
        clock: Arc<dyn OwnerGrantClock>,
    ) -> Result<Self, OwnerGrantStoreError> {
        let store = Self::at(path, provider_id, clock);
        let _lock = store.lock()?;
        store.read()?;
        Ok(store)
    }

    fn at(path: impl AsRef<Path>, provider_id: [u8; 32], clock: Arc<dyn OwnerGrantClock>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            provider_id,
            clock,
            commit: Arc::new(|path, bytes| {
                atomic_io::write_private(path, bytes).map_err(io::Error::other)
            }),
        }
    }

    /// Durably consume exact verified authority before native effects.
    ///
    /// A publication error requires reopening and observing retained state.
    /// A present disposition is never retryable. A proven absent disposition
    /// means publication did not occur and no consumed capability was returned.
    ///
    /// # Errors
    /// Refuses expiry, replay, revocation, conflicts, capacity and uncertain
    /// storage publication.
    pub fn consume(
        &self,
        grant: VerifiedOwnerGrant,
    ) -> Result<ConsumedOwnerGrant, OwnerGrantStoreError> {
        if grant.provider_id() != self.provider_id {
            return Err(OwnerGrantStoreError::Conflict);
        }
        let grant_id = grant.grant_id();
        let _lock = self.lock()?;
        let mut journal = self.read()?;
        let now_secs = self.observe_time(&mut journal, grant_id, 0)?;
        if now_secs < grant.verified_at_secs() {
            return Err(OwnerGrantStoreError::ClockRegression);
        }
        if now_secs >= grant.expires_at_secs() {
            return Err(OwnerGrantStoreError::Expired);
        }
        if let Some(existing) = journal
            .records
            .iter()
            .find(|record| record.grant_id == grant_id)
        {
            return match &existing.disposition {
                GrantDisposition::Consumed { request_digest, .. }
                    if *request_digest == grant.request_digest() =>
                {
                    Err(OwnerGrantStoreError::AlreadyConsumed)
                }
                GrantDisposition::Consumed { .. } => Err(OwnerGrantStoreError::Conflict),
                GrantDisposition::Revoked { .. } => Err(OwnerGrantStoreError::Revoked),
            };
        }
        if journal.records.len() >= MAX_RECORDS {
            return Err(OwnerGrantStoreError::Exhausted);
        }
        journal.records.push(GrantRecord {
            grant_id,
            disposition: GrantDisposition::Consumed {
                request_digest: grant.request_digest(),
                consumed_at_secs: now_secs,
                expires_at_secs: grant.expires_at_secs(),
            },
        });
        let bytes = serialize(&journal)?;
        (self.commit)(&self.path, &bytes)
            .map_err(|source| OwnerGrantStoreError::CommitUnknown { grant_id, source })?;
        Ok(ConsumedOwnerGrant {
            grant_id,
            request_digest: grant.request_digest(),
            expires_at_secs: grant.expires_at_secs(),
        })
    }

    /// Revoke an unconsumed public grant identity.
    ///
    /// Revocation cannot erase or rewrite a consumed disposition.
    ///
    /// # Errors
    /// Refuses conflicts, capacity and uncertain storage publication.
    pub fn revoke(&self, grant_id: [u8; 32]) -> Result<(), OwnerGrantStoreError> {
        if grant_id == [0; 32] {
            return Err(OwnerGrantStoreError::Conflict);
        }
        let _lock = self.lock()?;
        let mut journal = self.read()?;
        let now_secs = self.observe_time(&mut journal, grant_id, 0)?;
        if let Some(existing) = journal
            .records
            .iter()
            .find(|record| record.grant_id == grant_id)
        {
            return match existing.disposition {
                GrantDisposition::Revoked { .. } => Ok(()),
                GrantDisposition::Consumed { .. } => Err(OwnerGrantStoreError::Conflict),
            };
        }
        if journal.records.len() >= MAX_RECORDS {
            return Err(OwnerGrantStoreError::Exhausted);
        }
        journal.records.push(GrantRecord {
            grant_id,
            disposition: GrantDisposition::Revoked {
                revoked_at_secs: now_secs,
            },
        });
        let bytes = serialize(&journal)?;
        (self.commit)(&self.path, &bytes)
            .map_err(|source| OwnerGrantStoreError::CommitUnknown { grant_id, source })
    }

    /// Observe retained disposition without consuming or granting authority.
    ///
    /// `None` after a protected locked read proves that the current journal did
    /// not retain the attempted publication. It is not a consumed capability.
    ///
    /// # Errors
    /// Refuses missing, corrupt or unavailable storage.
    pub fn disposition(
        &self,
        grant_id: [u8; 32],
    ) -> Result<Option<OwnerGrantDisposition>, OwnerGrantStoreError> {
        let _lock = self.lock()?;
        let journal = self.read()?;
        Ok(journal
            .records
            .iter()
            .find(|record| record.grant_id == grant_id)
            .map(|record| match record.disposition {
                GrantDisposition::Consumed { .. } => OwnerGrantDisposition::Consumed,
                GrantDisposition::Revoked { .. } => OwnerGrantDisposition::Revoked,
            }))
    }

    pub(crate) fn authorize_consumed(
        &self,
        grant_id: [u8; 32],
        request_digest: [u8; 32],
    ) -> Result<ConsumedGrantAuthorization<'_>, OwnerGrantStoreError> {
        let lock = self.lock()?;
        let mut journal = self.read()?;
        let now_secs = self.observe_time(&mut journal, grant_id, 0)?;
        let expires_at_secs = validate_consumed(&journal, grant_id, request_digest, now_secs)?;
        self.commit_journal(&journal, grant_id)?;
        let observed_at_secs = self.fresh_time(now_secs, expires_at_secs)?;
        Ok(ConsumedGrantAuthorization {
            store: self,
            _lock: lock,
            journal,
            grant_id,
            request_digest,
            observed_at_secs,
        })
    }

    fn lock(&self) -> Result<atomic_io::FileLock, OwnerGrantStoreError> {
        crate::admission_budget::acquire_lock(&self.path.with_extension("lock"))
            .map_err(OwnerGrantStoreError::Storage)
    }

    fn now_secs(&self) -> Result<u64, OwnerGrantStoreError> {
        self.clock
            .now_secs()
            .map_err(|error| OwnerGrantStoreError::Storage(error.into()))
    }

    fn observe_time(
        &self,
        journal: &mut GrantJournal,
        grant_id: [u8; 32],
        minimum_secs: u64,
    ) -> Result<u64, OwnerGrantStoreError> {
        let now_secs = self.now_secs()?;
        if now_secs < journal.last_observed_secs.max(minimum_secs) {
            return Err(OwnerGrantStoreError::Conflict);
        }
        if now_secs > journal.last_observed_secs {
            journal.last_observed_secs = now_secs;
            self.commit_journal(journal, grant_id)?;
        }
        Ok(now_secs)
    }

    fn fresh_time(
        &self,
        minimum_secs: u64,
        expires_at_secs: u64,
    ) -> Result<u64, OwnerGrantStoreError> {
        let now_secs = self.now_secs()?;
        if now_secs < minimum_secs {
            return Err(OwnerGrantStoreError::Conflict);
        }
        if now_secs >= expires_at_secs {
            return Err(OwnerGrantStoreError::Expired);
        }
        Ok(now_secs)
    }

    fn commit_journal(
        &self,
        journal: &GrantJournal,
        grant_id: [u8; 32],
    ) -> Result<(), OwnerGrantStoreError> {
        let bytes = serialize(journal)?;
        (self.commit)(&self.path, &bytes)
            .map_err(|source| OwnerGrantStoreError::CommitUnknown { grant_id, source })
    }

    fn read(&self) -> Result<GrantJournal, OwnerGrantStoreError> {
        let bytes = crate::admission_budget::read_private(&self.path, MAX_BYTES)
            .map_err(OwnerGrantStoreError::Storage)?
            .ok_or(OwnerGrantStoreError::Missing)?;
        let journal: GrantJournal =
            serde_json::from_slice(&bytes).map_err(|_| OwnerGrantStoreError::Corrupt)?;
        if journal.version != VERSION
            || journal.provider_id != self.provider_id
            || journal.records.len() > MAX_RECORDS
        {
            return Err(OwnerGrantStoreError::Corrupt);
        }
        for (index, record) in journal.records.iter().enumerate() {
            if record.grant_id == [0; 32]
                || journal.records[..index]
                    .iter()
                    .any(|earlier| earlier.grant_id == record.grant_id)
            {
                return Err(OwnerGrantStoreError::Corrupt);
            }
            if let GrantDisposition::Consumed {
                request_digest,
                consumed_at_secs,
                expires_at_secs,
            } = record.disposition
                && (request_digest == [0; 32]
                    || consumed_at_secs >= expires_at_secs
                    || consumed_at_secs > journal.last_observed_secs
                    || expires_at_secs == 0)
            {
                return Err(OwnerGrantStoreError::Corrupt);
            }
            if let GrantDisposition::Revoked { revoked_at_secs } = record.disposition
                && revoked_at_secs > journal.last_observed_secs
            {
                return Err(OwnerGrantStoreError::Corrupt);
            }
        }
        Ok(journal)
    }

    #[cfg(test)]
    pub(crate) fn with_commit(
        &self,
        commit: impl Fn(&Path, &[u8]) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            path: self.path.clone(),
            provider_id: self.provider_id,
            clock: Arc::clone(&self.clock),
            commit: Arc::new(commit),
        }
    }
}

fn validate_consumed(
    journal: &GrantJournal,
    grant_id: [u8; 32],
    request_digest: [u8; 32],
    now_secs: u64,
) -> Result<u64, OwnerGrantStoreError> {
    let record = journal
        .records
        .iter()
        .find(|record| record.grant_id == grant_id)
        .ok_or(OwnerGrantStoreError::Conflict)?;
    match record.disposition {
        GrantDisposition::Consumed {
            request_digest: retained,
            ..
        } if retained != request_digest => Err(OwnerGrantStoreError::Conflict),
        GrantDisposition::Consumed {
            expires_at_secs, ..
        } if now_secs >= expires_at_secs => Err(OwnerGrantStoreError::Expired),
        GrantDisposition::Consumed {
            expires_at_secs, ..
        } => Ok(expires_at_secs),
        GrantDisposition::Revoked { .. } => Err(OwnerGrantStoreError::Revoked),
    }
}

pub(crate) struct ConsumedGrantAuthorization<'a> {
    store: &'a OwnerGrantStore,
    _lock: atomic_io::FileLock,
    journal: GrantJournal,
    grant_id: [u8; 32],
    request_digest: [u8; 32],
    observed_at_secs: u64,
}

impl ConsumedGrantAuthorization<'_> {
    pub(crate) fn check_current(&mut self) -> Result<(), OwnerGrantStoreError> {
        let expires_at_secs = validate_consumed(
            &self.journal,
            self.grant_id,
            self.request_digest,
            self.observed_at_secs,
        )?;
        self.observed_at_secs = self
            .store
            .fresh_time(self.observed_at_secs, expires_at_secs)?;
        Ok(())
    }

    pub(crate) fn recheck(mut self) -> Result<u64, OwnerGrantStoreError> {
        let now_secs =
            self.store
                .observe_time(&mut self.journal, self.grant_id, self.observed_at_secs)?;
        let expires_at_secs =
            validate_consumed(&self.journal, self.grant_id, self.request_digest, now_secs)?;
        self.store
            .fresh_time(now_secs.max(self.observed_at_secs), expires_at_secs)?;
        Ok(expires_at_secs)
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BYTES.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("owner grant journal exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize(journal: &GrantJournal) -> Result<Vec<u8>, OwnerGrantStoreError> {
    if journal.records.len() > MAX_RECORDS {
        return Err(OwnerGrantStoreError::Exhausted);
    }
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(4096),
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, journal).is_err() {
        return Err(if writer.exceeded {
            OwnerGrantStoreError::Exhausted
        } else {
            OwnerGrantStoreError::Corrupt
        });
    }
    Ok(writer.bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::hvf_entrypoint_owner::{
        FreshAdmissionRequest, FreshOwnerBinding, OwnerGrant, VERSION,
    };
    use mvm_core::crypto::hvf_owner_grant::{
        OwnerGrantExpectation, provider_identity, sign_owner_grant, verify_owner_grant,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[derive(Debug)]
    struct TestClock(AtomicU64);

    impl TestClock {
        fn new(now: u64) -> Self {
            Self(AtomicU64::new(now))
        }

        fn set(&self, now: u64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl OwnerGrantClock for TestClock {
        fn now_secs(&self) -> io::Result<u64> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    fn verified(grant_id: [u8; 32]) -> VerifiedOwnerGrant {
        let key = SigningKey::from_bytes(&[7; 32]);
        let verifying = key.verifying_key();
        let plan = br#"{"schema_version":1}"#.to_vec();
        let request = FreshAdmissionRequest {
            binding: FreshOwnerBinding {
                version: VERSION,
                operation_id: [1; 32],
                owner_incarnation: [2; 32],
                controlling_principal: [3; 32],
                installation: [4; 16],
                tenant_id: "tenant".into(),
                workload_id: "workload".into(),
                canonical_plan_digest: Sha256::digest(&plan).into(),
                frozen_inputs_digest: [5; 32],
                policy_revision: [6; 32],
                expires_at_secs: 90,
            },
            canonical_plan: plan,
        };
        let signed = sign_owner_grant(
            OwnerGrant {
                version: VERSION,
                issuer: "provider".into(),
                provider_epoch: 1,
                grant_id,
                request_digest: request.digest().unwrap(),
                issued_at_secs: 10,
                expires_at_secs: 100,
            },
            &key,
        )
        .unwrap();
        verify_owner_grant(
            &signed,
            &request,
            OwnerGrantExpectation {
                issuer: "provider",
                issuer_key: &verifying,
                provider_epoch: 1,
                operation_id: [1; 32],
                owner_incarnation: [2; 32],
                controlling_principal: [3; 32],
                installation: [4; 16],
                tenant_id: "tenant",
                workload_id: "workload",
                canonical_plan_digest: Sha256::digest(br#"{"schema_version":1}"#).into(),
                frozen_inputs_digest: [5; 32],
                policy_revision: [6; 32],
                expires_at_secs: 90,
            },
            50,
        )
        .unwrap()
    }

    fn provider_id() -> [u8; 32] {
        provider_identity(
            "provider",
            &SigningKey::from_bytes(&[7; 32]).verifying_key(),
            1,
        )
    }

    fn initialized() -> (tempfile::TempDir, OwnerGrantStore, Arc<TestClock>) {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("owner-grants.json");
        let clock = Arc::new(TestClock::new(50));
        let store = OwnerGrantStore::initialize(&path, provider_id(), clock.clone()).unwrap();
        (directory, store, clock)
    }

    #[test]
    fn explicit_initialization_and_exact_consumption_are_one_shot() {
        let (directory, store, clock) = initialized();
        assert!(matches!(
            OwnerGrantStore::initialize(
                directory.path().join("owner-grants.json"),
                provider_id(),
                clock
            ),
            Err(OwnerGrantStoreError::Conflict)
        ));
        let consumed = store.consume(verified([8; 32])).unwrap();
        assert_eq!(consumed.grant_id(), [8; 32]);
        assert_eq!(consumed.expires_at_secs(), 90);
        assert!(matches!(
            store.consume(verified([8; 32])),
            Err(OwnerGrantStoreError::AlreadyConsumed)
        ));
        assert!(matches!(
            OwnerGrantStore::open(
                directory.path().join("owner-grants.json"),
                [99; 32],
                Arc::new(TestClock::new(50))
            ),
            Err(OwnerGrantStoreError::Corrupt)
        ));
    }

    #[test]
    fn revocation_expiry_and_missing_state_refuse() {
        let (directory, store, clock) = initialized();
        store.revoke([9; 32]).unwrap();
        assert!(matches!(
            store.consume(verified([9; 32])),
            Err(OwnerGrantStoreError::Revoked)
        ));
        clock.set(90);
        assert!(matches!(
            store.consume(verified([10; 32])),
            Err(OwnerGrantStoreError::Expired)
        ));
        clock.set(80);
        assert!(matches!(
            store.consume(verified([14; 32])),
            Err(OwnerGrantStoreError::Conflict)
        ));
        assert!(matches!(
            OwnerGrantStore::open(
                directory.path().join("missing.json"),
                provider_id(),
                Arc::new(TestClock::new(50))
            ),
            Err(OwnerGrantStoreError::Missing)
        ));
    }

    #[test]
    fn uncertain_publication_stays_non_retryable_after_reconciliation() {
        let (_directory, store, clock) = initialized();
        let failing = store.with_commit(|path, bytes| {
            atomic_io::write_private(path, bytes).map_err(io::Error::other)?;
            Err(io::Error::other("injected directory sync failure"))
        });
        assert!(matches!(
            failing.consume(verified([11; 32])),
            Err(OwnerGrantStoreError::CommitUnknown { .. })
        ));
        let reopened = OwnerGrantStore::open(&store.path, provider_id(), clock).unwrap();
        assert_eq!(
            reopened.disposition([11; 32]).unwrap(),
            Some(OwnerGrantDisposition::Consumed)
        );
        assert!(matches!(
            reopened.consume(verified([11; 32])),
            Err(OwnerGrantStoreError::AlreadyConsumed)
        ));
    }

    #[test]
    fn proven_prepublication_failure_can_be_observed_absent_then_retried() {
        let (_directory, store, _clock) = initialized();
        let failing = store.with_commit(|_, _| Err(io::Error::other("injected pre-publication")));
        assert!(matches!(
            failing.consume(verified([12; 32])),
            Err(OwnerGrantStoreError::CommitUnknown { .. })
        ));
        assert_eq!(store.disposition([12; 32]).unwrap(), None);
        assert!(store.consume(verified([12; 32])).is_ok());
    }

    #[test]
    fn expiry_is_resampled_after_waiting_for_exclusion() {
        let (_directory, store, clock) = initialized();
        let lock = store.lock().unwrap();
        let queued = store.clone();
        let (started, wait) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            queued.consume(verified([13; 32]))
        });
        wait.recv().unwrap();
        clock.set(90);
        drop(lock);
        assert!(matches!(
            worker.join().unwrap(),
            Err(OwnerGrantStoreError::Expired)
        ));
        assert_eq!(store.disposition([13; 32]).unwrap(), None);
    }

    #[test]
    fn clock_cannot_move_before_the_grant_verification_observation() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let clock = Arc::new(TestClock::new(20));
        let store = OwnerGrantStore::initialize(
            directory.path().join("owner-grants.json"),
            provider_id(),
            clock.clone(),
        )
        .unwrap();
        let grant = verified([15; 32]);
        assert_eq!(grant.verified_at_secs(), 50);
        clock.set(40);
        assert!(matches!(
            store.consume(grant),
            Err(OwnerGrantStoreError::ClockRegression)
        ));
        assert_eq!(store.disposition([15; 32]).unwrap(), None);
    }

    #[test]
    fn malformed_duplicate_and_inconsistent_records_refuse() {
        let (_directory, store, _clock) = initialized();
        for journal in [
            serde_json::json!({
                "version":2,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[]
            }),
            serde_json::json!({
                "version":1,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[
                    {"grant_id":vec![1;32],"disposition":{"state":"revoked","revoked_at_secs":1}},
                    {"grant_id":vec![1;32],"disposition":{"state":"revoked","revoked_at_secs":2}}
                ]
            }),
            serde_json::json!({
                "version":1,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[{
                    "grant_id":vec![2;32],
                    "disposition":{
                        "state":"consumed",
                        "request_digest":vec![3;32],
                        "consumed_at_secs":10,
                        "expires_at_secs":10
                    }
                }]
            }),
            serde_json::json!({
                "version":1,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[{
                    "grant_id":vec![4;32],
                    "disposition":{
                        "state":"revoked",
                        "revoked_at_secs":51
                    }
                }]
            }),
        ] {
            atomic_io::write_private(&store.path, &serde_json::to_vec(&journal).unwrap()).unwrap();
            assert!(matches!(store.read(), Err(OwnerGrantStoreError::Corrupt)));
        }
    }
}
