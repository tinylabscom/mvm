//! Recoverable storage-key identity for the durable mailbox journal.

use mvm_contract::protocol::mailbox::{EncryptionAlgorithm, ExecutionEpoch, MailboxAddress};
use serde::{Deserialize, Serialize};

use super::JournalError;

/// Recoverable storage-key identity for one mailbox and execution epoch.
///
/// This identifies the journal key, not the separately encrypted payload's
/// opening key. Deserialization is not admission authority; production must
/// bind it to a verified plan and authenticated restart manifest. A later
/// epoch or rotation needs an explicit anchored handoff.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryKeyRef {
    pub(super) address: MailboxAddress,
    pub(super) execution_epoch: ExecutionEpoch,
    pub(super) algorithm: EncryptionAlgorithm,
    pub(super) key_id: [u8; 32],
    pub(super) version: u32,
}

impl std::fmt::Debug for HistoryKeyRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HistoryKeyRef")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl HistoryKeyRef {
    /// Identify a custody key version; construction alone is not authority.
    ///
    /// The host must bind these fields to a verified plan and authenticated
    /// restart manifest before using the reference to reopen retained history.
    pub fn new(
        address: MailboxAddress,
        execution_epoch: ExecutionEpoch,
        key_id: [u8; 32],
        version: u32,
    ) -> Result<Self, JournalError> {
        if key_id == [0; 32] || version == 0 {
            return Err(JournalError::HistoryKeyUnavailable);
        }
        Ok(Self {
            address,
            execution_epoch,
            algorithm: EncryptionAlgorithm::AES_256_GCM,
            key_id,
            version,
        })
    }

    #[must_use]
    pub const fn address(&self) -> MailboxAddress {
        self.address
    }

    #[must_use]
    pub const fn execution_epoch(&self) -> ExecutionEpoch {
        self.execution_epoch
    }

    #[must_use]
    pub const fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    pub(super) fn validate(&self) -> Result<(), JournalError> {
        if self.key_id == [0; 32]
            || self.version == 0
            || self.algorithm != EncryptionAlgorithm::AES_256_GCM
        {
            return Err(JournalError::HistoryKeyUnavailable);
        }
        Ok(())
    }
}
