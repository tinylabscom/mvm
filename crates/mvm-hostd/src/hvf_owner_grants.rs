//! Durable one-shot consumption for protected cold-HVF owner grants.
//!
//! Initialization belongs to the trusted installer. A missing or corrupt
//! journal never becomes an empty authority namespace.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use mvm_contract::protocol::hvf_entrypoint_owner::{FreshAdmissionRequest, FreshOwnerBinding};
use mvm_core::{
    atomic_io, crypto::hvf_owner_grant::VerifiedOwnerGrant, protocol::hvf_control::HvfInstance,
};
use mvm_runtime::workload_runner::runner::OriginalHvfOwnerBinding;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const VERSION: u32 = 2;
const MAX_RECORDS: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;

/// Durable one-shot disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum GrantDisposition {
    Consumed {
        operation_id: [u8; 32],
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    birth: Option<OwnerBirthState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum OwnerBirthState {
    Prepared {
        binding: FreshOwnerBinding,
        request_digest: [u8; 32],
    },
    Bound {
        binding: FreshOwnerBinding,
        request_digest: [u8; 32],
        instance: HvfInstance,
    },
    AuditClosing {
        binding: FreshOwnerBinding,
        request_digest: [u8; 32],
        instance: HvfInstance,
    },
    AuditClosed {
        binding: FreshOwnerBinding,
        request_digest: [u8; 32],
        instance: HvfInstance,
    },
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
    provider_id: [u8; 32],
    grant_id: [u8; 32],
    operation_id: [u8; 32],
    request_digest: [u8; 32],
    expires_at_secs: u64,
}

impl ConsumedOwnerGrant {
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }

    #[must_use]
    pub fn operation_id(&self) -> [u8; 32] {
        self.operation_id
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

/// Read-only durable quarantine observation. It never authorizes native work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerBirthDisposition {
    Prepared,
    Bound,
    AuditClosing,
    AuditClosed,
}

/// Non-wire one-shot permission to attempt the original native birth.
#[derive(Debug)]
#[must_use = "dropping this reservation leaves absorbing pre-birth quarantine"]
pub struct OwnerBirthReservation {
    provider_id: [u8; 32],
    grant_id: [u8; 32],
    binding: FreshOwnerBinding,
    request_digest: [u8; 32],
    observed_at_secs: u64,
}

impl OwnerBirthReservation {
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }

    #[must_use]
    pub fn binding(&self) -> &FreshOwnerBinding {
        &self.binding
    }

    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Latest accepted clock observation the native birth path must not precede.
    #[must_use]
    pub fn observed_at_secs(&self) -> u64 {
        self.observed_at_secs
    }
}

/// Non-wire receipt that the prepared birth was bound to retained native custody.
///
/// This receipt is not terminal evidence and grants no stop, attach or recovery
/// operation.
#[derive(Debug)]
#[must_use = "retain this receipt with the original native owner"]
pub struct BoundOwnerBirthReceipt {
    provider_id: [u8; 32],
    grant_id: [u8; 32],
}

impl BoundOwnerBirthReceipt {
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }

    pub(crate) fn into_uncertain_audit(self) -> UncertainOwnerAudit {
        UncertainOwnerAudit {
            provider_id: self.provider_id,
            grant_id: self.grant_id,
        }
    }

    #[cfg(test)]
    pub(crate) fn duplicate_for_test(&self) -> Self {
        Self {
            provider_id: self.provider_id,
            grant_id: self.grant_id,
        }
    }
}

#[derive(Debug)]
#[must_use = "consume this capability exactly once to close the bound owner audit"]
pub(crate) struct OwnerAuditClosure {
    provider_id: [u8; 32],
    grant_id: [u8; 32],
    binding: FreshOwnerBinding,
    request_digest: [u8; 32],
    instance: HvfInstance,
}

impl OwnerAuditClosure {
    pub(crate) fn instance(&self) -> &HvfInstance {
        &self.instance
    }

    pub(crate) fn into_uncertain(self) -> UncertainOwnerAudit {
        UncertainOwnerAudit {
            provider_id: self.provider_id,
            grant_id: self.grant_id,
        }
    }
}

#[derive(Debug)]
#[must_use = "retain uncertain audit custody with the original native owner"]
pub struct UncertainOwnerAudit {
    provider_id: [u8; 32],
    grant_id: [u8; 32],
}

impl UncertainOwnerAudit {
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }
}

#[derive(Debug)]
#[must_use = "retain closed audit evidence with original terminal custody"]
pub struct ClosedOwnerAuditReceipt {
    provider_id: [u8; 32],
    grant_id: [u8; 32],
}

impl ClosedOwnerAuditReceipt {
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }
}

/// Non-retryable custody marker returned when binding did not yield a receipt.
#[derive(Debug)]
#[must_use = "retain uncertain birth custody with the original native owner"]
pub struct UncertainOwnerBirth {
    provider_id: [u8; 32],
    grant_id: [u8; 32],
}

impl UncertainOwnerBirth {
    #[must_use]
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }

    #[must_use]
    pub fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }
}

/// Failed or uncertain durable binding. The reservation is deliberately not
/// returned because retrying a publication with an unknown outcome is unsafe.
#[derive(Debug, Error)]
#[error("failed to bind prepared HVF owner birth")]
pub struct OwnerBirthBindError {
    quarantine: UncertainOwnerBirth,
    #[source]
    source: OwnerGrantStoreError,
}

impl OwnerBirthBindError {
    pub fn into_parts(self) -> (UncertainOwnerBirth, OwnerGrantStoreError) {
        (self.quarantine, self.source)
    }
}

#[derive(Debug, Error)]
#[error("failed or uncertain owner audit transition")]
pub struct OwnerAuditTransitionError {
    quarantine: UncertainOwnerAudit,
    #[source]
    source: OwnerGrantStoreError,
}

impl OwnerAuditTransitionError {
    pub fn into_parts(self) -> (UncertainOwnerAudit, OwnerGrantStoreError) {
        (self.quarantine, self.source)
    }
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
        if journal.records.iter().any(|record| {
            matches!(
                record.disposition,
                GrantDisposition::Consumed {
                    operation_id,
                    request_digest,
                    ..
                } if operation_id == grant.operation_id()
                    || request_digest == grant.request_digest()
            )
        }) {
            return Err(OwnerGrantStoreError::Conflict);
        }
        if journal.records.len() >= MAX_RECORDS {
            return Err(OwnerGrantStoreError::Exhausted);
        }
        journal.records.push(GrantRecord {
            grant_id,
            disposition: GrantDisposition::Consumed {
                operation_id: grant.operation_id(),
                request_digest: grant.request_digest(),
                consumed_at_secs: now_secs,
                expires_at_secs: grant.expires_at_secs(),
            },
            birth: None,
        });
        let bytes = serialize(&journal)?;
        (self.commit)(&self.path, &bytes)
            .map_err(|source| OwnerGrantStoreError::CommitUnknown { grant_id, source })?;
        Ok(ConsumedOwnerGrant {
            provider_id: self.provider_id,
            grant_id,
            operation_id: grant.operation_id(),
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
            birth: None,
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

    /// Persist absorbing pre-birth quarantine before any native effect.
    ///
    /// The consumed grant is moved into this call. Publication uncertainty or
    /// any returned error yields no reusable birth reservation.
    ///
    /// # Errors
    /// Refuses changed bindings, expiry, revocation, replay and storage errors.
    pub fn reserve_birth(
        &self,
        consumed: ConsumedOwnerGrant,
        admission: &FreshAdmissionRequest,
    ) -> Result<OwnerBirthReservation, OwnerGrantStoreError> {
        if consumed.provider_id() != self.provider_id
            || admission.validate().is_err()
            || admission.binding.operation_id != consumed.operation_id()
            || admission
                .digest()
                .map_err(|_| OwnerGrantStoreError::Conflict)?
                != consumed.request_digest()
            || admission.binding.expires_at_secs != consumed.expires_at_secs()
        {
            return Err(OwnerGrantStoreError::Conflict);
        }
        let grant_id = consumed.grant_id();
        let request_digest = consumed.request_digest();
        let _lock = self.lock()?;
        let mut journal = self.read()?;
        let now_secs = self.observe_time(&mut journal, grant_id, 0)?;
        if now_secs >= consumed.expires_at_secs() {
            return Err(OwnerGrantStoreError::Expired);
        }
        let record = journal
            .records
            .iter_mut()
            .find(|record| record.grant_id == grant_id)
            .ok_or(OwnerGrantStoreError::Conflict)?;
        match record.disposition {
            GrantDisposition::Consumed {
                request_digest: retained,
                ..
            } if retained == request_digest && record.birth.is_none() => {}
            GrantDisposition::Consumed { .. } => return Err(OwnerGrantStoreError::Conflict),
            GrantDisposition::Revoked { .. } => return Err(OwnerGrantStoreError::Revoked),
        }
        record.birth = Some(OwnerBirthState::Prepared {
            binding: admission.binding.clone(),
            request_digest,
        });
        self.commit_journal(&journal, grant_id)?;
        let now_secs = self.now_secs()?;
        if now_secs < journal.last_observed_secs {
            return Err(OwnerGrantStoreError::ClockRegression);
        }
        if now_secs >= consumed.expires_at_secs() {
            return Err(OwnerGrantStoreError::Expired);
        }
        Ok(OwnerBirthReservation {
            provider_id: self.provider_id,
            grant_id,
            binding: admission.binding.clone(),
            request_digest,
            observed_at_secs: now_secs,
        })
    }

    /// Bind a prepared birth to the actual original owner retained by the HVF
    /// backend.
    ///
    /// The native generation is derived inside this method. Public instance
    /// data cannot be supplied as custody evidence. Any failure consumes the
    /// live reservation into an uncertain marker so publication is never
    /// retried blindly.
    ///
    /// # Errors
    /// Refuses mismatched custody, expiry, clock regression, corrupt state and
    /// uncertain storage publication.
    pub fn bind_prepared_birth(
        &self,
        reservation: OwnerBirthReservation,
        owner: OriginalHvfOwnerBinding<'_>,
    ) -> Result<BoundOwnerBirthReceipt, OwnerBirthBindError> {
        let instance = owner
            .owner()
            .instance()
            .cloned()
            .map_err(OwnerGrantStoreError::Storage);
        if owner.canonical_plan_digest() != reservation.binding.canonical_plan_digest {
            return Err(OwnerBirthBindError {
                quarantine: UncertainOwnerBirth {
                    provider_id: reservation.provider_id,
                    grant_id: reservation.grant_id,
                },
                source: OwnerGrantStoreError::Conflict,
            });
        }
        self.bind_prepared_instance(reservation, instance)
    }

    fn bind_prepared_instance(
        &self,
        reservation: OwnerBirthReservation,
        instance: Result<HvfInstance, OwnerGrantStoreError>,
    ) -> Result<BoundOwnerBirthReceipt, OwnerBirthBindError> {
        let provider_id = reservation.provider_id;
        let grant_id = reservation.grant_id;
        let result = (|| {
            if provider_id != self.provider_id {
                return Err(OwnerGrantStoreError::Conflict);
            }
            let instance = instance?;
            if instance.vm_id != reservation.binding.workload_id || instance.boot_nonce == [0; 32] {
                return Err(OwnerGrantStoreError::Conflict);
            }
            let expires_at_secs = reservation.binding.expires_at_secs;
            let _lock = self.lock()?;
            let mut journal = self.read()?;
            let now_secs =
                self.observe_time(&mut journal, grant_id, reservation.observed_at_secs)?;
            if now_secs >= expires_at_secs {
                return Err(OwnerGrantStoreError::Expired);
            }
            let record = journal
                .records
                .iter_mut()
                .find(|record| record.grant_id == grant_id)
                .ok_or(OwnerGrantStoreError::Conflict)?;
            match &record.birth {
                Some(OwnerBirthState::Prepared {
                    binding,
                    request_digest,
                }) if binding == &reservation.binding
                    && request_digest == &reservation.request_digest => {}
                _ => return Err(OwnerGrantStoreError::Conflict),
            }
            record.birth = Some(OwnerBirthState::Bound {
                binding: reservation.binding,
                request_digest: reservation.request_digest,
                instance: instance.clone(),
            });
            self.commit_journal(&journal, grant_id)?;
            self.fresh_time(now_secs, expires_at_secs)?;
            Ok(BoundOwnerBirthReceipt {
                provider_id,
                grant_id,
            })
        })();
        result.map_err(|source| OwnerBirthBindError {
            quarantine: UncertainOwnerBirth {
                provider_id,
                grant_id,
            },
            source,
        })
    }

    #[cfg(test)]
    pub(crate) fn bind_prepared_instance_for_test(
        &self,
        reservation: OwnerBirthReservation,
        instance: HvfInstance,
    ) -> Result<BoundOwnerBirthReceipt, OwnerBirthBindError> {
        self.bind_prepared_instance(reservation, Ok(instance))
    }

    pub(crate) fn begin_audit_close(
        &self,
        receipt: BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        completion_instance: &HvfInstance,
    ) -> Result<OwnerAuditClosure, OwnerAuditTransitionError> {
        let provider_id = receipt.provider_id;
        let grant_id = receipt.grant_id;
        let result = (|| {
            if provider_id != self.provider_id || admission.validate().is_err() {
                return Err(OwnerGrantStoreError::Conflict);
            }
            let request_digest = admission
                .digest()
                .map_err(|_| OwnerGrantStoreError::Conflict)?;
            let _lock = self.lock()?;
            let mut journal = self.read()?;
            let now_secs = self.observe_time(&mut journal, grant_id, 0)?;
            let record = journal
                .records
                .iter_mut()
                .find(|record| record.grant_id == grant_id)
                .ok_or(OwnerGrantStoreError::Conflict)?;
            let (binding, retained_digest, instance) = match &record.birth {
                Some(OwnerBirthState::Bound {
                    binding,
                    request_digest,
                    instance,
                }) => (binding, request_digest, instance),
                _ => return Err(OwnerGrantStoreError::Conflict),
            };
            if binding != &admission.binding
                || retained_digest != &request_digest
                || instance != completion_instance
                || now_secs >= binding.expires_at_secs
            {
                return Err(if now_secs >= binding.expires_at_secs {
                    OwnerGrantStoreError::Expired
                } else {
                    OwnerGrantStoreError::Conflict
                });
            }
            let binding = binding.clone();
            let instance = instance.clone();
            record.birth = Some(OwnerBirthState::AuditClosing {
                binding: binding.clone(),
                request_digest,
                instance: instance.clone(),
            });
            self.commit_journal(&journal, grant_id)?;
            self.fresh_time(now_secs, binding.expires_at_secs)?;
            Ok(OwnerAuditClosure {
                provider_id,
                grant_id,
                binding,
                request_digest,
                instance,
            })
        })();
        result.map_err(|source| OwnerAuditTransitionError {
            quarantine: UncertainOwnerAudit {
                provider_id,
                grant_id,
            },
            source,
        })
    }

    pub(crate) fn finish_audit_close(
        &self,
        closure: OwnerAuditClosure,
    ) -> Result<ClosedOwnerAuditReceipt, OwnerAuditTransitionError> {
        let provider_id = closure.provider_id;
        let grant_id = closure.grant_id;
        let result = (|| {
            if provider_id != self.provider_id {
                return Err(OwnerGrantStoreError::Conflict);
            }
            let _lock = self.lock()?;
            let mut journal = self.read()?;
            let record = journal
                .records
                .iter_mut()
                .find(|record| record.grant_id == grant_id)
                .ok_or(OwnerGrantStoreError::Conflict)?;
            match &record.birth {
                Some(OwnerBirthState::AuditClosing {
                    binding,
                    request_digest,
                    instance,
                }) if binding == &closure.binding
                    && request_digest == &closure.request_digest
                    && instance == &closure.instance => {}
                _ => return Err(OwnerGrantStoreError::Conflict),
            }
            record.birth = Some(OwnerBirthState::AuditClosed {
                binding: closure.binding,
                request_digest: closure.request_digest,
                instance: closure.instance,
            });
            self.commit_journal(&journal, grant_id)?;
            Ok(ClosedOwnerAuditReceipt {
                provider_id,
                grant_id,
            })
        })();
        result.map_err(|source| OwnerAuditTransitionError {
            quarantine: UncertainOwnerAudit {
                provider_id,
                grant_id,
            },
            source,
        })
    }

    pub(crate) fn authorize_bound_original_control(
        &self,
        receipt: &BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        original: OriginalHvfOwnerBinding<'_>,
    ) -> Result<BoundControlAuthorization<'_>, OwnerGrantStoreError> {
        let instance = original
            .owner()
            .instance()
            .map_err(OwnerGrantStoreError::Storage)?
            .clone();
        self.authorize_bound_control_parts(
            receipt,
            admission,
            original.canonical_plan_digest(),
            instance,
        )
    }

    fn authorize_bound_control_parts(
        &self,
        receipt: &BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        canonical_plan_digest: [u8; 32],
        instance: HvfInstance,
    ) -> Result<BoundControlAuthorization<'_>, OwnerGrantStoreError> {
        if receipt.provider_id != self.provider_id
            || admission.validate().is_err()
            || canonical_plan_digest != admission.binding.canonical_plan_digest
        {
            return Err(OwnerGrantStoreError::Conflict);
        }
        let request_digest = admission
            .digest()
            .map_err(|_| OwnerGrantStoreError::Conflict)?;
        let lock = self.lock()?;
        let mut journal = self.read()?;
        let now_secs = self.observe_time(&mut journal, receipt.grant_id, 0)?;
        let expires_at_secs = validate_bound_control(
            &journal,
            receipt.grant_id,
            admission,
            request_digest,
            &instance,
            now_secs,
        )?;
        self.commit_journal(&journal, receipt.grant_id)?;
        let observed_at_secs = self.fresh_time(now_secs, expires_at_secs)?;
        Ok(BoundControlAuthorization {
            store: self,
            _lock: lock,
            journal,
            grant_id: receipt.grant_id,
            admission: admission.clone(),
            request_digest,
            instance,
            observed_at_secs,
        })
    }

    #[cfg(test)]
    pub(crate) fn authorize_bound_control_parts_for_test(
        &self,
        receipt: &BoundOwnerBirthReceipt,
        admission: &FreshAdmissionRequest,
        canonical_plan_digest: [u8; 32],
        instance: HvfInstance,
    ) -> Result<BoundControlAuthorization<'_>, OwnerGrantStoreError> {
        self.authorize_bound_control_parts(receipt, admission, canonical_plan_digest, instance)
    }

    /// Observe quarantine without recreating a birth or native-owner capability.
    ///
    /// # Errors
    /// Refuses missing, corrupt or unavailable protected state.
    pub fn birth_disposition(
        &self,
        grant_id: [u8; 32],
    ) -> Result<Option<OwnerBirthDisposition>, OwnerGrantStoreError> {
        let _lock = self.lock()?;
        let journal = self.read()?;
        let Some(record) = journal
            .records
            .iter()
            .find(|record| record.grant_id == grant_id)
        else {
            return Ok(None);
        };
        Ok(record.birth.as_ref().map(|birth| match birth {
            OwnerBirthState::Prepared { .. } => OwnerBirthDisposition::Prepared,
            OwnerBirthState::Bound { .. } => OwnerBirthDisposition::Bound,
            OwnerBirthState::AuditClosing { .. } => OwnerBirthDisposition::AuditClosing,
            OwnerBirthState::AuditClosed { .. } => OwnerBirthDisposition::AuditClosed,
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
            return Err(OwnerGrantStoreError::ClockRegression);
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
            return Err(OwnerGrantStoreError::ClockRegression);
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
                operation_id,
                request_digest,
                consumed_at_secs,
                expires_at_secs,
            } = record.disposition
                && (operation_id == [0; 32]
                    || request_digest == [0; 32]
                    || consumed_at_secs >= expires_at_secs
                    || consumed_at_secs > journal.last_observed_secs
                    || expires_at_secs == 0)
            {
                return Err(OwnerGrantStoreError::Corrupt);
            }
            if let GrantDisposition::Consumed {
                operation_id,
                request_digest,
                ..
            } = record.disposition
                && journal.records[..index].iter().any(|earlier| {
                    matches!(
                        earlier.disposition,
                        GrantDisposition::Consumed {
                            operation_id: earlier_operation,
                            request_digest: earlier_digest,
                            ..
                        } if earlier_operation == operation_id
                            || earlier_digest == request_digest
                    )
                })
            {
                return Err(OwnerGrantStoreError::Corrupt);
            }
            if let GrantDisposition::Revoked { revoked_at_secs } = record.disposition
                && revoked_at_secs > journal.last_observed_secs
            {
                return Err(OwnerGrantStoreError::Corrupt);
            }
            if let Some(birth) = &record.birth {
                let (
                    GrantDisposition::Consumed {
                        operation_id,
                        request_digest,
                        expires_at_secs,
                        ..
                    },
                    binding,
                    birth_digest,
                ) = (
                    &record.disposition,
                    match birth {
                        OwnerBirthState::Prepared { binding, .. }
                        | OwnerBirthState::Bound { binding, .. }
                        | OwnerBirthState::AuditClosing { binding, .. }
                        | OwnerBirthState::AuditClosed { binding, .. } => binding,
                    },
                    match birth {
                        OwnerBirthState::Prepared { request_digest, .. }
                        | OwnerBirthState::Bound { request_digest, .. }
                        | OwnerBirthState::AuditClosing { request_digest, .. }
                        | OwnerBirthState::AuditClosed { request_digest, .. } => request_digest,
                    },
                )
                else {
                    return Err(OwnerGrantStoreError::Corrupt);
                };
                if birth_digest != request_digest
                    || binding.validate().is_err()
                    || binding.operation_id != *operation_id
                    || binding.expires_at_secs != *expires_at_secs
                {
                    return Err(OwnerGrantStoreError::Corrupt);
                }
                if let OwnerBirthState::Bound { instance, .. }
                | OwnerBirthState::AuditClosing { instance, .. }
                | OwnerBirthState::AuditClosed { instance, .. } = birth
                    && (instance.vm_id != binding.workload_id || instance.boot_nonce == [0; 32])
                {
                    return Err(OwnerGrantStoreError::Corrupt);
                }
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

fn validate_bound_control(
    journal: &GrantJournal,
    grant_id: [u8; 32],
    admission: &FreshAdmissionRequest,
    request_digest: [u8; 32],
    instance: &HvfInstance,
    now_secs: u64,
) -> Result<u64, OwnerGrantStoreError> {
    let record = journal
        .records
        .iter()
        .find(|record| record.grant_id == grant_id)
        .ok_or(OwnerGrantStoreError::Conflict)?;
    let expires_at_secs = match record.disposition {
        GrantDisposition::Consumed {
            operation_id,
            request_digest: retained,
            expires_at_secs,
            ..
        } if operation_id == admission.binding.operation_id
            && retained == request_digest
            && expires_at_secs == admission.binding.expires_at_secs =>
        {
            expires_at_secs
        }
        GrantDisposition::Consumed { .. } => return Err(OwnerGrantStoreError::Conflict),
        GrantDisposition::Revoked { .. } => return Err(OwnerGrantStoreError::Revoked),
    };
    match &record.birth {
        Some(OwnerBirthState::Bound {
            binding,
            request_digest: retained,
            instance: retained_instance,
        }) if binding == &admission.binding
            && retained == &request_digest
            && retained_instance == instance => {}
        _ => return Err(OwnerGrantStoreError::Conflict),
    }
    if now_secs >= expires_at_secs {
        return Err(OwnerGrantStoreError::Expired);
    }
    Ok(expires_at_secs)
}

pub(crate) struct ConsumedGrantAuthorization<'a> {
    store: &'a OwnerGrantStore,
    _lock: atomic_io::FileLock,
    journal: GrantJournal,
    grant_id: [u8; 32],
    request_digest: [u8; 32],
    observed_at_secs: u64,
}

pub(crate) struct BoundControlAuthorization<'a> {
    store: &'a OwnerGrantStore,
    _lock: atomic_io::FileLock,
    journal: GrantJournal,
    grant_id: [u8; 32],
    admission: FreshAdmissionRequest,
    request_digest: [u8; 32],
    instance: HvfInstance,
    observed_at_secs: u64,
}

impl BoundControlAuthorization<'_> {
    pub(crate) fn instance(&self) -> &HvfInstance {
        &self.instance
    }

    pub(crate) fn observed_at_secs(&self) -> u64 {
        self.observed_at_secs
    }

    pub(crate) fn check_current(&mut self) -> Result<(), OwnerGrantStoreError> {
        let expires_at_secs = validate_bound_control(
            &self.journal,
            self.grant_id,
            &self.admission,
            self.request_digest,
            &self.instance,
            self.observed_at_secs,
        )?;
        self.observed_at_secs = self
            .store
            .fresh_time(self.observed_at_secs, expires_at_secs)?;
        Ok(())
    }

    pub(crate) fn recheck(mut self) -> Result<(), OwnerGrantStoreError> {
        let now_secs =
            self.store
                .observe_time(&mut self.journal, self.grant_id, self.observed_at_secs)?;
        let expires_at_secs = validate_bound_control(
            &self.journal,
            self.grant_id,
            &self.admission,
            self.request_digest,
            &self.instance,
            now_secs,
        )?;
        self.store
            .fresh_time(now_secs.max(self.observed_at_secs), expires_at_secs)?;
        Ok(())
    }
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

    fn admission() -> FreshAdmissionRequest {
        let plan = br#"{"schema_version":1}"#.to_vec();
        FreshAdmissionRequest {
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
        }
    }

    fn verified(grant_id: [u8; 32]) -> VerifiedOwnerGrant {
        verified_for(grant_id, &admission())
    }

    fn instance() -> HvfInstance {
        HvfInstance {
            vm_id: "workload".into(),
            boot_nonce: [9; 32],
        }
    }

    fn verified_for(grant_id: [u8; 32], request: &FreshAdmissionRequest) -> VerifiedOwnerGrant {
        let key = SigningKey::from_bytes(&[7; 32]);
        let verifying = key.verifying_key();
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
            request,
            OwnerGrantExpectation {
                issuer: "provider",
                issuer_key: &verifying,
                provider_epoch: 1,
                operation_id: request.binding.operation_id,
                owner_incarnation: request.binding.owner_incarnation,
                controlling_principal: request.binding.controlling_principal,
                installation: request.binding.installation,
                tenant_id: &request.binding.tenant_id,
                workload_id: &request.binding.workload_id,
                canonical_plan_digest: request.binding.canonical_plan_digest,
                frozen_inputs_digest: request.binding.frozen_inputs_digest,
                policy_revision: request.binding.policy_revision,
                expires_at_secs: request.binding.expires_at_secs,
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
            store.consume(verified([21; 32])),
            Err(OwnerGrantStoreError::Conflict)
        ));
        let mut changed = admission();
        changed.canonical_plan.push(b' ');
        changed.binding.canonical_plan_digest = Sha256::digest(&changed.canonical_plan).into();
        assert!(matches!(
            store.consume(verified_for([22; 32], &changed)),
            Err(OwnerGrantStoreError::Conflict)
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
            Err(OwnerGrantStoreError::ClockRegression)
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
    fn birth_quarantine_precedes_any_native_effect_and_observation_cannot_recreate_it() {
        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([16; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        assert_eq!(reservation.provider_id(), provider_id());
        assert_eq!(reservation.grant_id(), [16; 32]);
        assert_eq!(reservation.binding(), &admission().binding);
        assert_eq!(reservation.request_digest(), admission().digest().unwrap());
        assert_eq!(reservation.observed_at_secs(), 50);
        drop(reservation);
        assert_eq!(
            store.birth_disposition([16; 32]).unwrap(),
            Some(OwnerBirthDisposition::Prepared)
        );
        assert!(matches!(
            store.consume(verified([16; 32])),
            Err(OwnerGrantStoreError::AlreadyConsumed)
        ));
    }

    #[test]
    fn prepared_journal_transition_binds_once_to_a_generation() {
        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([29; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let receipt = store
            .bind_prepared_instance(reservation, Ok(instance()))
            .unwrap();
        assert_eq!(receipt.provider_id(), provider_id());
        assert_eq!(receipt.grant_id(), [29; 32]);
        assert_eq!(
            store.birth_disposition([29; 32]).unwrap(),
            Some(OwnerBirthDisposition::Bound)
        );
    }

    #[test]
    fn changed_or_uncertain_binding_returns_only_non_retryable_quarantine() {
        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([30; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let mut wrong = instance();
        wrong.vm_id = "other".into();
        let (uncertain, source) = store
            .bind_prepared_instance(reservation, Ok(wrong))
            .unwrap_err()
            .into_parts();
        assert_eq!(uncertain.grant_id(), [30; 32]);
        assert!(matches!(source, OwnerGrantStoreError::Conflict));
        assert_eq!(
            store.birth_disposition([30; 32]).unwrap(),
            Some(OwnerBirthDisposition::Prepared)
        );

        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([31; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let failing = store.with_commit(|path, bytes| {
            atomic_io::write_private(path, bytes).map_err(io::Error::other)?;
            Err(io::Error::other("injected bound durability uncertainty"))
        });
        let (uncertain, source) = failing
            .bind_prepared_instance(reservation, Ok(instance()))
            .unwrap_err()
            .into_parts();
        assert_eq!(uncertain.provider_id(), provider_id());
        assert!(matches!(source, OwnerGrantStoreError::CommitUnknown { .. }));
        assert_eq!(
            store.birth_disposition([31; 32]).unwrap(),
            Some(OwnerBirthDisposition::Bound)
        );
    }

    #[test]
    fn binding_time_and_publication_failures_never_return_a_receipt() {
        let (_directory, store, clock) = initialized();
        let consumed = store.consume(verified([32; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let writer_clock = Arc::clone(&clock);
        let expiring = store.with_commit(move |path, bytes| {
            atomic_io::write_private(path, bytes).map_err(io::Error::other)?;
            writer_clock.set(90);
            Ok(())
        });
        let (uncertain, source) = expiring
            .bind_prepared_instance(reservation, Ok(instance()))
            .unwrap_err()
            .into_parts();
        assert_eq!(uncertain.grant_id(), [32; 32]);
        assert!(matches!(source, OwnerGrantStoreError::Expired));
        assert_eq!(
            store.birth_disposition([32; 32]).unwrap(),
            Some(OwnerBirthDisposition::Bound)
        );

        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([33; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let failing = store.with_commit(|_, _| Err(io::Error::other("before bound publication")));
        let (_, source) = failing
            .bind_prepared_instance(reservation, Ok(instance()))
            .unwrap_err()
            .into_parts();
        assert!(matches!(source, OwnerGrantStoreError::CommitUnknown { .. }));
        assert_eq!(
            store.birth_disposition([33; 32]).unwrap(),
            Some(OwnerBirthDisposition::Prepared)
        );
    }

    #[test]
    fn malformed_bound_generation_refuses_on_reopen() {
        let (directory, store, clock) = initialized();
        let consumed = store.consume(verified([34; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let _receipt = store
            .bind_prepared_instance(reservation, Ok(instance()))
            .unwrap();
        let path = directory.path().join("owner-grants.json");
        let mut journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        journal["records"][0]["birth"]["instance"]["boot_nonce"] = vec![0; 32].into();
        atomic_io::write_private(&path, &serde_json::to_vec(&journal).unwrap()).unwrap();
        assert!(matches!(
            OwnerGrantStore::open(path, provider_id(), clock),
            Err(OwnerGrantStoreError::Corrupt)
        ));
    }

    #[test]
    fn bound_birth_audit_intent_and_completion_are_one_way() {
        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([35; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let receipt = store
            .bind_prepared_instance(reservation, Ok(instance()))
            .unwrap();
        let closure = store
            .begin_audit_close(receipt, &admission(), &instance())
            .unwrap();
        assert_eq!(closure.instance(), &instance());
        assert_eq!(
            store.birth_disposition([35; 32]).unwrap(),
            Some(OwnerBirthDisposition::AuditClosing)
        );
        let closed = store.finish_audit_close(closure).unwrap();
        assert_eq!(closed.provider_id(), provider_id());
        assert_eq!(closed.grant_id(), [35; 32]);
        assert_eq!(
            store.birth_disposition([35; 32]).unwrap(),
            Some(OwnerBirthDisposition::AuditClosed)
        );
    }

    #[test]
    fn uncertain_audit_intent_returns_no_retryable_bound_receipt() {
        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([36; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        let receipt = store
            .bind_prepared_instance(reservation, Ok(instance()))
            .unwrap();
        let failing = store.with_commit(|path, bytes| {
            atomic_io::write_private(path, bytes).map_err(io::Error::other)?;
            Err(io::Error::other("injected audit-intent uncertainty"))
        });
        let (uncertain, source) = failing
            .begin_audit_close(receipt, &admission(), &instance())
            .unwrap_err()
            .into_parts();
        assert_eq!(uncertain.grant_id(), [36; 32]);
        assert!(matches!(source, OwnerGrantStoreError::CommitUnknown { .. }));
        assert_eq!(
            store.birth_disposition([36; 32]).unwrap(),
            Some(OwnerBirthDisposition::AuditClosing)
        );
    }

    #[test]
    fn changed_birth_refuses_and_dropped_reservation_leaves_absorbing_quarantine() {
        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([17; 32])).unwrap();
        let mut changed = admission();
        changed.binding.workload_id.push_str("-other");
        assert!(matches!(
            store.reserve_birth(consumed, &changed),
            Err(OwnerGrantStoreError::Conflict)
        ));
        assert_eq!(store.birth_disposition([17; 32]).unwrap(), None);

        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([18; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        drop(reservation);
        assert_eq!(
            store.birth_disposition([18; 32]).unwrap(),
            Some(OwnerBirthDisposition::Prepared)
        );
    }

    #[test]
    fn uncertain_birth_publication_returns_no_reusable_native_capability() {
        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([19; 32])).unwrap();
        let failing = store.with_commit(|path, bytes| {
            atomic_io::write_private(path, bytes).map_err(io::Error::other)?;
            Err(io::Error::other("injected birth durability uncertainty"))
        });
        assert!(matches!(
            failing.reserve_birth(consumed, &admission()),
            Err(OwnerGrantStoreError::CommitUnknown { .. })
        ));
        assert_eq!(
            store.birth_disposition([19; 32]).unwrap(),
            Some(OwnerBirthDisposition::Prepared)
        );
        assert!(matches!(
            store.consume(verified([19; 32])),
            Err(OwnerGrantStoreError::AlreadyConsumed)
        ));
    }

    #[test]
    fn birth_reservation_refuses_expiry_regression_and_prepublication_failure() {
        let (_directory, store, clock) = initialized();
        let consumed = store.consume(verified([22; 32])).unwrap();
        clock.set(90);
        assert!(matches!(
            store.reserve_birth(consumed, &admission()),
            Err(OwnerGrantStoreError::Expired)
        ));
        assert_eq!(store.birth_disposition([22; 32]).unwrap(), None);

        let (_directory, store, clock) = initialized();
        let consumed = store.consume(verified([23; 32])).unwrap();
        clock.set(40);
        assert!(matches!(
            store.reserve_birth(consumed, &admission()),
            Err(OwnerGrantStoreError::ClockRegression)
        ));
        assert_eq!(store.birth_disposition([23; 32]).unwrap(), None);

        let (_directory, store, _clock) = initialized();
        let consumed = store.consume(verified([24; 32])).unwrap();
        let failing = store.with_commit(|_, _| Err(io::Error::other("before publication")));
        assert!(matches!(
            failing.reserve_birth(consumed, &admission()),
            Err(OwnerGrantStoreError::CommitUnknown { .. })
        ));
        assert_eq!(store.birth_disposition([24; 32]).unwrap(), None);
        assert!(matches!(
            store.consume(verified([24; 32])),
            Err(OwnerGrantStoreError::AlreadyConsumed)
        ));
    }

    #[test]
    fn postpublication_clock_is_retained_or_refuses_without_a_reservation() {
        for (grant_id, after, expected) in [
            ([26; 32], 40, Some(OwnerGrantStoreError::ClockRegression)),
            ([27; 32], 90, Some(OwnerGrantStoreError::Expired)),
            ([28; 32], 80, None),
        ] {
            let (_directory, store, clock) = initialized();
            let consumed = store.consume(verified(grant_id)).unwrap();
            let writer_clock = Arc::clone(&clock);
            let committing = store.with_commit(move |path, bytes| {
                atomic_io::write_private(path, bytes).map_err(io::Error::other)?;
                writer_clock.set(after);
                Ok(())
            });
            let result = committing.reserve_birth(consumed, &admission());
            match expected {
                Some(OwnerGrantStoreError::ClockRegression) => {
                    assert!(matches!(result, Err(OwnerGrantStoreError::ClockRegression)))
                }
                Some(OwnerGrantStoreError::Expired) => {
                    assert!(matches!(result, Err(OwnerGrantStoreError::Expired)))
                }
                None => assert_eq!(result.unwrap().observed_at_secs(), 80),
                Some(_) => unreachable!("test enumerates only time refusals"),
            }
            assert_eq!(
                store.birth_disposition(grant_id).unwrap(),
                Some(OwnerBirthDisposition::Prepared)
            );
        }
    }

    #[test]
    fn reopen_observes_prepared_quarantine_without_recreating_reservation() {
        let (directory, store, clock) = initialized();
        let consumed = store.consume(verified([25; 32])).unwrap();
        let reservation = store.reserve_birth(consumed, &admission()).unwrap();
        drop(reservation);
        drop(store);
        let reopened = OwnerGrantStore::open(
            directory.path().join("owner-grants.json"),
            provider_id(),
            clock,
        )
        .unwrap();
        assert_eq!(
            reopened.birth_disposition([25; 32]).unwrap(),
            Some(OwnerBirthDisposition::Prepared)
        );
        assert!(matches!(
            reopened.consume(verified([25; 32])),
            Err(OwnerGrantStoreError::AlreadyConsumed)
        ));
    }

    #[test]
    fn malformed_duplicate_and_inconsistent_records_refuse() {
        let (_directory, store, _clock) = initialized();
        for journal in [
            serde_json::json!({
                "version":3,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[]
            }),
            serde_json::json!({
                "version":2,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[
                    {"grant_id":vec![1;32],"disposition":{"state":"revoked","revoked_at_secs":1}},
                    {"grant_id":vec![1;32],"disposition":{"state":"revoked","revoked_at_secs":2}}
                ]
            }),
            serde_json::json!({
                "version":2,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[{
                    "grant_id":vec![2;32],
                    "disposition":{
                        "state":"consumed",
                        "operation_id":vec![1;32],
                        "request_digest":vec![3;32],
                        "consumed_at_secs":10,
                        "expires_at_secs":10
                    }
                }]
            }),
            serde_json::json!({
                "version":2,
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
            serde_json::json!({
                "version":2,
                "provider_id":provider_id(),
                "last_observed_secs":50,
                "records":[{
                    "grant_id":vec![5;32],
                    "disposition":{
                        "state":"revoked",
                        "revoked_at_secs":10
                    },
                    "birth":{
                        "state":"prepared",
                        "binding":serde_json::to_value(&admission().binding).unwrap(),
                        "request_digest":admission().digest().unwrap()
                    }
                }]
            }),
            {
                let mut binding = admission().binding;
                binding.operation_id = [9; 32];
                serde_json::json!({
                    "version":2,
                    "provider_id":provider_id(),
                    "last_observed_secs":50,
                    "records":[{
                        "grant_id":vec![6;32],
                        "disposition":{
                            "state":"consumed",
                            "operation_id":vec![1;32],
                            "request_digest":admission().digest().unwrap(),
                            "consumed_at_secs":10,
                            "expires_at_secs":90
                        },
                        "birth":{
                            "state":"prepared",
                            "binding":serde_json::to_value(binding).unwrap(),
                            "request_digest":admission().digest().unwrap()
                        }
                    }]
                })
            },
        ] {
            atomic_io::write_private(&store.path, &serde_json::to_vec(&journal).unwrap()).unwrap();
            assert!(matches!(store.read(), Err(OwnerGrantStoreError::Corrupt)));
        }
    }
}
