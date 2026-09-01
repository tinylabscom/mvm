//! The vocabulary of an evidence-bearing emit.
//!
//! Kept beside the emitter rather than inside it because these types are what
//! *other* subsystems cite — the assurance ledger builds its references from
//! them — and because "what an emit produced" is a smaller idea than "how the
//! emitter works".

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::supervisor::PlanAuditEntry;

/// Whether an evidence-bearing emit must also produce a receipt.
///
/// A probe is a frequent, fine-grained record and rides the audit chain alone;
/// a trial completion is the unit a campaign publishes, and carries a receipt.
/// Making the caller say which keeps "this event has no receipt mapping" an
/// error rather than a silent `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceReceipt {
    /// The event must map to a receipt; a missing mapping is an error.
    Required,
    /// Audit chain only.
    Omitted,
}

/// References to what one evidence-bearing emit actually wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedEvidence {
    /// Lowercase hex SHA-256 of the exact signed entry bytes.
    pub audit_digest: String,
    /// Content address of the receipt, when receipts are enabled.
    pub receipt_id: Option<String>,
}

/// Digest the exact bytes an entry is signed as.
///
/// `seal` signs `serde_json::to_vec(entry)` and stores those same bytes in the
/// envelope's `canonical` field, so this digest identifies the on-disk line
/// exactly: a reader decodes `canonical`, hashes it, and compares. That is
/// what makes a citation to an audit entry resolvable rather than decorative.
pub fn audit_entry_digest_hex(entry: &PlanAuditEntry) -> Result<String> {
    let bytes = serde_json::to_vec(entry).context("serializing audit entry for its digest")?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::TenantId;

    fn entry(event: &str) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: TenantId("local".to_string()),
            plan_id: mvm_core::plan::PlanId("plan-1".to_string()),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "vm".to_string(),
            image_sha256: "a".repeat(64),
            event: event.to_string(),
            caller_commitment: None,
            labels: Default::default(),
        }
    }

    #[test]
    fn the_digest_covers_the_bytes_the_entry_is_signed_as() {
        let entry = entry("assurance.probe");
        let expected = hex::encode(Sha256::digest(serde_json::to_vec(&entry).unwrap()));
        assert_eq!(audit_entry_digest_hex(&entry).unwrap(), expected);
    }

    #[test]
    fn a_different_event_digests_differently() {
        // The digest is what a citation resolves on, so two entries that differ
        // anywhere must not share one.
        let a = audit_entry_digest_hex(&entry("assurance.probe")).unwrap();
        let b = audit_entry_digest_hex(&entry("assurance.session_opened")).unwrap();
        assert_ne!(a, b);
    }
}
