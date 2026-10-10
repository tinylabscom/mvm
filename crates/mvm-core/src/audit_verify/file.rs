//! Full-chain adapter using the canonical contract verifier.
use super::PlanAuditEntry;
use ed25519_dalek::VerifyingKey;
use mvm_contract::verify::{AuditVerifyError, hash_line, verify_audit_entries_bytes};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("io error: {0}")]
    Io(String),
    #[error("malformed envelope at line {line}: {reason}")]
    Malformed { line: usize, reason: String },
    #[error("prev_hash mismatch at line {line}: chain broken")]
    PrevHashMismatch { line: usize },
    #[error("signature invalid at line {line}")]
    SignatureInvalid { line: usize },
    #[error("line {line}: the readable entry disagrees with the bytes that were signed")]
    EntryCanonicalMismatch { line: usize },
    #[error("audit stream ends mid-record at line {line}: last append did not complete")]
    TruncatedTail { line: usize },
}

impl From<AuditVerifyError> for VerifyError {
    fn from(error: AuditVerifyError) -> Self {
        match error {
            AuditVerifyError::Malformed { line, reason } => Self::Malformed { line, reason },
            AuditVerifyError::PrevHashMismatch { line } => Self::PrevHashMismatch { line },
            AuditVerifyError::SignatureInvalid { line } => Self::SignatureInvalid { line },
            AuditVerifyError::EntryCanonicalMismatch { line } => {
                Self::EntryCanonicalMismatch { line }
            }
            AuditVerifyError::KeyDecode(reason) => Self::Malformed { line: 0, reason },
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentWalk {
    pub entries: Vec<PlanAuditEntry>,
    pub tip: [u8; 32],
}

pub fn verify_chain_bytes(content: &str, key: &VerifyingKey) -> Result<SegmentWalk, VerifyError> {
    if !content.is_empty() && !content.ends_with('\n') {
        return Err(VerifyError::TruncatedTail {
            line: content.lines().count().saturating_sub(1),
        });
    }
    let entries = verify_audit_entries_bytes(content, key)?
        .into_iter()
        .map(|(line, entry)| {
            // Both are instantiations of the same canonical wire schema.
            // Convert only authenticated values; never parse a second file view.
            serde_json::to_value(entry)
                .and_then(serde_json::from_value)
                .map_err(|error| VerifyError::Malformed {
                    line,
                    reason: error.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tip = content
        .lines()
        .rfind(|line| !line.is_empty())
        .map_or([0; 32], |line| hash_line(line.as_bytes()));
    Ok(SegmentWalk { entries, tip })
}
