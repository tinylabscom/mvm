//! Retain the exact signed local outcome after acceptance, with bounded recovery capacity.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::mailbox::{
    DeliveryOutcome, DestinationReceipt, SignedDestinationReceipt,
};
use serde::{Deserialize, Serialize};

use super::{
    AcceptanceTier, FileJournalAnchor, JournalAdmission, JournalError, JournalEvent, JournalTip,
    MAX_RECORD_BYTES, MailboxJournal, Probe, Record, ReplayIdentity, Seen, aead,
    open_authenticated_envelope, sign_receipt,
};

/// A verified receipt and its exact JSON representation, without a transport wrapper.
///
/// Local journal methods return this only after the signed encoding is durable.
#[derive(Debug)]
pub struct EncodedDestinationReceipt {
    signed: SignedDestinationReceipt,
    encoded: Vec<u8>,
}

impl EncodedDestinationReceipt {
    pub(super) fn from_signed(signed: SignedDestinationReceipt) -> Result<Self, JournalError> {
        let encoded = serde_json::to_vec(&signed).map_err(|_| JournalError::Corrupt)?;
        Ok(Self { signed, encoded })
    }

    /// Borrow the exact persisted signed JSON, not a regenerated receipt.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the signed value for callers using the legacy typed interface.
    #[must_use]
    pub fn into_signed(self) -> SignedDestinationReceipt {
        self.signed
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReceiptCompletion {
    Pending { reserved_bytes: u64 },
    Retained { encoded_receipt: String },
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiptFault {
    BeforeSign,
    BeforePublication,
    AfterPublication,
    AfterAnchor,
}

impl MailboxJournal {
    pub(super) fn write_version(&self) -> u8 {
        match self.tier {
            AcceptanceTier::Local => 4,
            AcceptanceTier::Independent => self.format_version,
        }
    }

    pub(super) fn verify_admission(
        &self,
        request: &JournalAdmission<'_>,
        tier: AcceptanceTier,
    ) -> Result<ReplayIdentity, JournalError> {
        if self.poisoned {
            return Err(JournalError::Uncertain);
        }
        if self.tier != tier {
            return Err(JournalError::DurableAuthorityUnavailable);
        }
        let context = request.context;
        if self.address.tenant != context.expected_tenant
            || self.address.authorization_domain != context.expected_authorization_domain
            || self.address.mailbox != context.expected_mailbox
            || self.address.recipient != context.expected_recipient
            || request.signer.verifying_key() != self.authority
        {
            return Err(JournalError::WrongAuthority);
        }
        if self.history_key.is_some_and(|reference| {
            reference.address != self.address
                || reference.execution_epoch != context.current_execution_epoch
        }) {
            return Err(JournalError::HistoryKeyMismatch);
        }
        if tier == AcceptanceTier::Local {
            self.retention
                .ok_or(JournalError::DurableAuthorityUnavailable)?
                .retained_until(request.envelope.routing.expires_at_unix_ms)
                .map_err(|_| JournalError::InvalidLimits)?;
        }
        let mut probe = Probe::default();
        open_authenticated_envelope(
            request.envelope,
            request.capability,
            context,
            request.encryption_key,
            request.sender_key,
            &self.authority,
            &mut probe,
        )?;
        probe.0.ok_or(JournalError::Corrupt)
    }

    /// Admit locally and retain the exact signed encoding before returning success.
    ///
    /// # Errors
    /// Refuses invalid authority or capacity. A committed acceptance may remain
    /// receipt-pending; uncertain writes require reopening the journal.
    pub fn admit_local_encoded(
        &mut self,
        request: JournalAdmission<'_>,
        anchor: &FileJournalAnchor,
    ) -> Result<EncodedDestinationReceipt, JournalError> {
        self.local_ready(anchor, &request.signer.verifying_key())?;
        self.admit_at_tier(request, AcceptanceTier::Local, |next| anchor.advance(next))
            .map_err(|error| {
                if self.poisoned {
                    JournalError::Uncertain
                } else {
                    error
                }
            })
    }

    /// Recover a known local outcome under the current legacy admission checks.
    ///
    /// Only an authenticated, healthy, genuinely unseen operation returns `None`.
    /// This does not grant independent destination recovery authority.
    ///
    /// # Errors
    /// Refuses stale authority, changed requests and uncertain history. A known
    /// committed body without completion capacity remains receipt-pending.
    pub fn recover_local_encoded(
        &mut self,
        request: JournalAdmission<'_>,
        anchor: &FileJournalAnchor,
    ) -> Result<Option<EncodedDestinationReceipt>, JournalError> {
        self.local_ready(anchor, &request.signer.verifying_key())?;
        let identity = self.verify_admission(&request, AcceptanceTier::Local)?;
        let Some(entry) = self.seen.get(&identity) else {
            return Ok(None);
        };
        if entry.envelope != *request.envelope || entry.capability != *request.capability {
            return Err(JournalError::ConflictingRetry);
        }
        if entry.expired_at_unix_ms.is_some() {
            return Err(JournalError::Mailbox(super::MailboxError::Expired));
        }
        self.complete_local_receipt(identity, request.signer, |next| anchor.advance(next))
            .map(Some)
    }

    pub(super) fn complete_local_receipt(
        &mut self,
        identity: ReplayIdentity,
        signer: &SigningKey,
        anchor: impl FnOnce(JournalTip) -> Result<(), JournalError>,
    ) -> Result<EncodedDestinationReceipt, JournalError> {
        let entry = self.seen.get(&identity).ok_or(JournalError::Corrupt)?;
        if let Some(ReceiptCompletion::Retained { encoded_receipt }) = &entry.receipt_completion {
            return self.decode_retained_receipt(identity, entry, encoded_receipt);
        }
        let receipt = entry.accepted_receipt.clone();
        // Size the whole transaction before signing, including first retention
        // of a legacy body whose historical response cannot be reconstructed.
        let sample = self.completion_event(identity, receipt_size_sample(&receipt)?);
        self.check_append_capacity(&self.sizing_record(sample))
            .map_err(|_| JournalError::ReceiptPending)?;
        #[cfg(test)]
        {
            if self.receipt_fault == Some(ReceiptFault::BeforeSign) {
                return Err(JournalError::ReceiptPending);
            }
            self.receipt_sign_attempts += 1;
        }
        let signed = sign_receipt(receipt, signer).map_err(|_| JournalError::ReceiptPending)?;
        let retained = EncodedDestinationReceipt::from_signed(signed)
            .map_err(|_| JournalError::ReceiptPending)?;
        let encoded_receipt = STANDARD_NO_PAD.encode(retained.encoded());
        #[cfg(test)]
        if self.receipt_fault == Some(ReceiptFault::BeforePublication) {
            return Err(JournalError::ReceiptPending);
        }
        if let Err(error) = self.append(
            self.completion_event(identity, encoded_receipt.clone()),
            anchor,
        ) {
            return Err(if self.poisoned {
                JournalError::Uncertain
            } else {
                match error {
                    JournalError::Full => JournalError::ReceiptPending,
                    other => other,
                }
            });
        }
        self.seen
            .get_mut(&identity)
            .ok_or(JournalError::Corrupt)?
            .receipt_completion = Some(ReceiptCompletion::Retained { encoded_receipt });
        Ok(retained)
    }

    fn completion_event(&self, identity: ReplayIdentity, encoded_receipt: String) -> JournalEvent {
        JournalEvent::ReceiptCompleted {
            identity,
            encoded_receipt,
        }
    }

    pub(super) fn decode_retained_receipt(
        &self,
        identity: ReplayIdentity,
        entry: &Seen,
        encoded: &str,
    ) -> Result<EncodedDestinationReceipt, JournalError> {
        if encoded.len() != receipt_size_sample(&entry.accepted_receipt)?.len() {
            return Err(JournalError::Corrupt);
        }
        let bytes = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| JournalError::Corrupt)?;
        let signed: SignedDestinationReceipt =
            serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
        if signed.receipt != entry.accepted_receipt
            || signed.receipt.outcome != DeliveryOutcome::AcceptedLocalDurable
            || signed.receipt.address != self.address
            || signed.receipt.message_id != identity.message_id
            || signed.receipt.execution_epoch != identity.execution_epoch
            || signed.receipt.delivery_id != entry.envelope.routing.delivery_id
            || signed.receipt.ciphertext_commitment != entry.envelope.ciphertext_commitment
            || serde_json::to_vec(&signed).map_err(|_| JournalError::Corrupt)? != bytes
        {
            return Err(JournalError::Corrupt);
        }
        super::super::verify_receipt(&signed, &self.authority)
            .map_err(|_| JournalError::Corrupt)?;
        Ok(EncodedDestinationReceipt {
            signed,
            encoded: bytes,
        })
    }

    pub(super) fn pending_receipt(
        &self,
        identity: ReplayIdentity,
        receipt: &DestinationReceipt,
    ) -> Result<ReceiptCompletion, JournalError> {
        let event = self.completion_event(identity, receipt_size_sample(receipt)?);
        Ok(ReceiptCompletion::Pending {
            reserved_bytes: record_bytes(&self.sizing_record(event), 32)?,
        })
    }

    pub(super) fn sizing_record(&self, event: JournalEvent) -> Record {
        Record {
            version: 4,
            cursor: u64::MAX,
            previous: [u8::MAX; 32],
            address: self.address,
            history_key: self.history_key,
            event,
        }
    }
}

// The dummy signature is used only to measure base64/JSON lengths, never as
// authenticated data or a persisted completion.
pub(super) fn receipt_size_sample(receipt: &DestinationReceipt) -> Result<String, JournalError> {
    let sample = SignedDestinationReceipt {
        receipt: receipt.clone(),
        signature: vec![0; 64],
    };
    Ok(STANDARD_NO_PAD.encode(serde_json::to_vec(&sample).map_err(|_| JournalError::Corrupt)?))
}

pub(super) fn record_bytes(record: &Record, prefix: u64) -> Result<u64, JournalError> {
    let body = serde_json::to_vec(record).map_err(|_| JournalError::Corrupt)?;
    let bytes = u64::try_from(body.len())
        .ok()
        .and_then(|n| n.checked_add(prefix))
        .and_then(|n| n.checked_add(aead::NONCE_SIZE as u64 + aead::TAG_SIZE as u64))
        .filter(|n| *n <= MAX_RECORD_BYTES as u64)
        .ok_or(JournalError::Full)?;
    Ok(bytes)
}
