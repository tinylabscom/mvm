//! At-rest lifetime, independent of the plaintext byte/chunk admission budget.
use super::{TranscriptError, TranscriptManifest, sealed_root_hex, verify_sealed_root};
use serde::{Deserialize, Serialize};

/// Authenticated plaintext representation inside each AEAD chunk.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    #[default]
    Raw,
    StreamRecordV1,
}

impl PayloadEncoding {
    pub(super) fn is_raw(&self) -> bool {
        *self == Self::Raw
    }
}

/// A managed family is deliberately not a user-selected free-form label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationFamily {
    WorkloadOutput,
}

/// Aggregate retained plaintext (including encoded envelopes) and chunk budget
/// for this tenant, VM, and family across all newly enrolled generations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBudget {
    pub family: GenerationFamily,
    pub max_plaintext_bytes: u64,
    pub max_chunks: u64,
}

impl Default for GenerationBudget {
    fn default() -> Self {
        Self {
            family: GenerationFamily::WorkloadOutput,
            max_plaintext_bytes: 8 << 20,
            max_chunks: 64 << 10,
        }
    }
}

/// Explicit enrollment for a newly opened protected capture. Absence means
/// legacy retention-ineligible data, never implicit enrollment on read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AtRestRetention {
    pub payload_after_seal_secs: u64,
    pub max_generation_secs: u64,
}

impl Default for AtRestRetention {
    fn default() -> Self {
        Self {
            payload_after_seal_secs: 604_800,
            max_generation_secs: 3_600,
        }
    }
}

impl AtRestRetention {
    pub fn generation_deadline(self, opened: u64) -> Result<u64, TranscriptError> {
        if opened == 0
            || self.payload_after_seal_secs == 0
            || self.max_generation_secs == 0
            || self.max_generation_secs > 3_600
        {
            return Err(TranscriptError::RetentionClock);
        }
        let end = opened
            .checked_add(self.max_generation_secs)
            .ok_or(TranscriptError::RetentionClock)?;
        end.checked_add(self.payload_after_seal_secs)
            .ok_or(TranscriptError::RetentionClock)?;
        Ok(end)
    }
}

/// Read the wall clock without turning a pre-epoch clock into timestamp zero.
pub fn retention_now() -> Result<u64, TranscriptError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| TranscriptError::RetentionClock)
}

impl TranscriptManifest {
    /// Shared checked-clock gate for managed reads and destructive maintenance.
    pub fn check_retention_clock_at(&self, now: u64) -> Result<(), TranscriptError> {
        super::validate_format(self)?;
        let Some(policy) = self.at_rest else {
            return Ok(());
        };
        policy.generation_deadline(self.created_unix_secs)?;
        if now < self.created_unix_secs || self.sealed_unix_secs.is_some_and(|sealed| now < sealed)
        {
            return Err(TranscriptError::RetentionClock);
        }
        now.checked_add(policy.payload_after_seal_secs)
            .ok_or(TranscriptError::RetentionClock)?;
        Ok(())
    }

    /// AES-GCM frame widths are authenticated by the original manifest root.
    /// This counts plaintext envelope bytes, not ciphertext or disk allocation.
    pub fn retained_plaintext_bytes(&self) -> Result<u64, TranscriptError> {
        let overhead = (crate::crypto::aead::NONCE_SIZE + crate::crypto::aead::TAG_SIZE) as u64;
        self.chunks.iter().try_fold(0u64, |total, chunk| {
            chunk
                .size_bytes
                .checked_sub(overhead)
                .and_then(|bytes| total.checked_add(bytes))
                .ok_or(TranscriptError::RetentionClock)
        })
    }

    /// A terminal seal is required for destructive retirement. Integrity
    /// snapshots have roots too, but do not attest that the producer stopped.
    pub fn retention_deadline(&self) -> Result<Option<u64>, TranscriptError> {
        super::validate_format(self)?;
        let Some(policy) = self.at_rest else {
            return Ok(None);
        };
        let generation_end = policy.generation_deadline(self.created_unix_secs)?;
        let Some(sealed) = self.sealed_unix_secs else {
            return Ok(None);
        };
        if sealed < self.created_unix_secs || sealed > generation_end {
            return Err(TranscriptError::RetentionClock);
        }
        sealed
            .checked_add(policy.payload_after_seal_secs)
            .map(Some)
            .ok_or(TranscriptError::RetentionClock)
    }

    /// Refuse managed payload reads at the exact deadline, even if maintenance
    /// has not run. Unfinalized recovery snapshots cannot extend readable age.
    pub fn check_readable_at(&self, now: u64) -> Result<(), TranscriptError> {
        self.check_retention_clock_at(now)?;
        let Some(policy) = self.at_rest else {
            return Ok(());
        };
        let deadline = match self.retention_deadline()? {
            Some(deadline) => deadline,
            None => policy
                .generation_deadline(self.created_unix_secs)?
                .checked_add(policy.payload_after_seal_secs)
                .ok_or(TranscriptError::RetentionClock)?,
        };
        if now >= deadline {
            return Err(TranscriptError::PayloadExpired);
        }
        Ok(())
    }
}

/// Finalize an abandoned generation only after its lifecycle owner establishes
/// that no producer remains. Recovery never grants seven fresh days at restart.
/// Existing terminal seals and all legacy captures are left unchanged.
pub fn recover_abandoned_at(
    manifest: &mut TranscriptManifest,
    now: u64,
) -> Result<(), TranscriptError> {
    verify_sealed_root(manifest)?;
    manifest.check_retention_clock_at(now)?;
    let Some(policy) = manifest.at_rest else {
        return Ok(());
    };
    if manifest.sealed_unix_secs.is_some() {
        return Ok(());
    }
    let generation_end = policy.generation_deadline(manifest.created_unix_secs)?;
    manifest.sealed_unix_secs = Some(now.min(generation_end));
    manifest.adopted = true;
    manifest.sealed_root_hex = sealed_root_hex(manifest)?;
    Ok(())
}
