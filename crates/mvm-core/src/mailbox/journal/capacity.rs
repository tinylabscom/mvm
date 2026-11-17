//! Logical completion and checkpoint headroom, distinct from physical filesystem capacity.

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};

use super::checkpoint::{CheckpointEntry, CheckpointState};
use super::receipt::{ReceiptCompletion, receipt_size_sample, record_bytes};
use super::{
    JournalError, JournalEvent, JournalTip, LeaseState, MailboxJournal, Record, ReplayIdentity,
    Seen, frame,
};

impl MailboxJournal {
    pub(super) fn check_append_capacity(&self, record: &Record) -> Result<(), JournalError> {
        let state = self.projected_checkpoint(&record.event)?;
        let (pending_records, pending_bytes) = self.completion_reservations(&state)?;
        let checkpoint_bytes = self.checkpoint_bound(&state)?;
        checked_total(&[self.tip.cursor, 1, pending_records, 1], u64::MAX)?;
        checked_total(
            &[
                self.bytes,
                record_bytes(record, 32)?,
                pending_bytes,
                checkpoint_bytes,
            ],
            self.limits.max_bytes,
        )?;
        checked_total(
            &[self.records as u64, 1, pending_records, 1],
            self.limits.max_records as u64,
        )?;
        Ok(())
    }

    pub(super) fn check_checkpoint_capacity(
        &self,
        state: &CheckpointState,
        physical_bytes: u64,
    ) -> Result<(), JournalError> {
        let (pending_records, pending_bytes) = self.completion_reservations(state)?;
        checked_total(&[self.tip.cursor, 1, pending_records, 1], u64::MAX)?;
        // Publication temporarily retains both generations. Pruning cannot
        // finance the write that must precede it.
        checked_total(
            &[self.bytes, physical_bytes, pending_bytes],
            self.limits.max_bytes,
        )?;
        checked_total(
            &[self.records as u64, 1, pending_records],
            self.limits.max_records as u64,
        )?;
        // No recursive stored reserve: the next checkpoint is sized once from
        // retained state, independently of physical prefix occupancy.
        checked_total(
            &[physical_bytes, pending_bytes, self.checkpoint_bound(state)?],
            self.limits.max_bytes,
        )?;
        checked_total(&[1, pending_records, 1], self.limits.max_records as u64)?;
        Ok(())
    }

    pub(super) fn completion_reservations(
        &self,
        state: &CheckpointState,
    ) -> Result<(u64, u64), JournalError> {
        let mut records = 0u64;
        let mut bytes = 0u64;
        for entry in &state.entries {
            if let Some(ReceiptCompletion::Pending { reserved_bytes }) =
                &entry.seen.receipt_completion
            {
                if self.pending_receipt(entry.identity, &entry.seen.accepted_receipt)?
                    != (ReceiptCompletion::Pending {
                        reserved_bytes: *reserved_bytes,
                    })
                {
                    return Err(JournalError::Corrupt);
                }
                records = records.checked_add(1).ok_or(JournalError::Full)?;
                bytes = bytes
                    .checked_add(*reserved_bytes)
                    .ok_or(JournalError::Full)?;
            }
        }
        Ok((records, bytes))
    }

    pub(super) fn checkpoint_bound(&self, state: &CheckpointState) -> Result<u64, JournalError> {
        let mut state = state.clone();
        state.source = JournalTip {
            cursor: u64::MAX,
            head: [u8::MAX; 32],
        };
        state.created_at_unix_ms = i64::MAX;
        for entry in &mut state.entries {
            if matches!(
                entry.seen.receipt_completion,
                Some(ReceiptCompletion::Pending { .. })
            ) {
                let pending = ReceiptCompletion::Pending {
                    reserved_bytes: u64::MAX,
                };
                let retained = ReceiptCompletion::Retained {
                    encoded_receipt: receipt_size_sample(&entry.seen.accepted_receipt)?,
                };
                let size = |value: &ReceiptCompletion| {
                    serde_json::to_vec(value)
                        .map(|v| v.len())
                        .map_err(|_| JournalError::Corrupt)
                };
                entry.seen.receipt_completion = Some(if size(&pending)? > size(&retained)? {
                    pending
                } else {
                    retained
                });
            }
        }
        record_bytes(
            &self.sizing_record(JournalEvent::Checkpoint {
                state: Box::new(state),
                authorization_signature: vec![u8::MAX; 64],
            }),
            64,
        )
    }

    fn projected_checkpoint(&self, event: &JournalEvent) -> Result<CheckpointState, JournalError> {
        let mut state = self.checkpoint_state(0)?;
        match event {
            JournalEvent::Accepted {
                identity,
                frame: encoded,
                receipt,
                ..
            } => {
                let raw = STANDARD_NO_PAD
                    .decode(encoded)
                    .map_err(|_| JournalError::Corrupt)?;
                let (capability, envelope) =
                    frame::decode_frame(&raw).map_err(|_| JournalError::Corrupt)?;
                state.entries.push(CheckpointEntry {
                    identity: *identity,
                    seen: Seen {
                        envelope,
                        capability,
                        accepted_receipt: *receipt.clone(),
                        acknowledged: false,
                        expired_at_unix_ms: None,
                        lease: None,
                        signed_ack: None,
                        receipt_completion: Some(self.pending_receipt(*identity, receipt)?),
                    },
                });
            }
            JournalEvent::ReceiptCompleted {
                identity,
                encoded_receipt,
            } => {
                let entry = entry_mut(&mut state, *identity)?;
                if matches!(
                    entry.receipt_completion,
                    Some(ReceiptCompletion::Retained { .. })
                ) {
                    return Err(JournalError::Corrupt);
                }
                entry.receipt_completion = Some(ReceiptCompletion::Retained {
                    encoded_receipt: encoded_receipt.clone(),
                });
            }
            JournalEvent::Acknowledged { identity, .. } => {
                entry_mut(&mut state, *identity)?.acknowledged = true;
            }
            JournalEvent::Leased {
                identity,
                challenge,
                lease,
                enrollment,
                receive_capability,
            } => {
                entry_mut(&mut state, *identity)?.lease = Some(LeaseState {
                    retry_count: 0,
                    signed: *lease.clone(),
                    enrollment: *enrollment.clone(),
                    receive_capability: *receive_capability.clone(),
                });
                state.used_challenges.push((*challenge, *identity));
            }
            JournalEvent::LeasedRetry {
                identity,
                challenge,
            } => {
                let lease = entry_mut(&mut state, *identity)?
                    .lease
                    .as_mut()
                    .ok_or(JournalError::Corrupt)?;
                lease.retry_count = lease.retry_count.checked_add(1).ok_or(JournalError::Full)?;
                state.used_challenges.push((*challenge, *identity));
            }
            JournalEvent::AcknowledgedSigned { identity, ack } => {
                let entry = entry_mut(&mut state, *identity)?;
                entry.acknowledged = true;
                entry.signed_ack = Some(*ack.clone());
            }
            JournalEvent::Expired {
                identity,
                expired_at_unix_ms,
                ..
            } => {
                entry_mut(&mut state, *identity)?.expired_at_unix_ms = Some(*expired_at_unix_ms);
            }
            JournalEvent::Checkpoint { .. } => return Err(JournalError::Corrupt),
        }
        Ok(state)
    }
}

fn entry_mut(
    state: &mut CheckpointState,
    identity: ReplayIdentity,
) -> Result<&mut Seen, JournalError> {
    state
        .entries
        .iter_mut()
        .find(|entry| entry.identity == identity)
        .map(|entry| &mut entry.seen)
        .ok_or(JournalError::Corrupt)
}

fn checked_total(parts: &[u64], maximum: u64) -> Result<(), JournalError> {
    parts.iter().try_fold(0u64, |sum, part| {
        sum.checked_add(*part)
            .filter(|sum| *sum <= maximum)
            .ok_or(JournalError::Full)
    })?;
    Ok(())
}
