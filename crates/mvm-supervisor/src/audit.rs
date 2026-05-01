//! Audit signer slot. Wave 3 — chain-signed audit stream.
//!
//! Plan 37 §22: the supervisor signs each audit entry into the
//! previous entry's hash, producing a tamper-evident chain. Per
//! `mvm-policy::AuditPolicy`, entries can also be replicated to
//! per-tenant streams. Wave 1.3 ships the trait surface; Wave 3
//! wires the real chain-signing impl.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mvm_plan::{PlanId, TenantId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One audit-stream entry. Plan 37 §22's "audit binding" — every
/// entry references both the plan id+version and the policy
/// bundle id+version that were in force when the event happened.
/// Wave 3's chain-signing wraps this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub tenant: TenantId,
    pub plan_id: PlanId,
    pub plan_version: u32,
    pub event: String,
    /// Free-form details. Inherits `audit_labels` from the plan plus
    /// per-event extras the supervisor adds.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit signer not wired (Noop slot)")]
    NotWired,

    #[error("io error writing audit entry: {0}")]
    Io(String),
}

#[async_trait]
pub trait AuditSigner: Send + Sync {
    /// Sign and persist one entry. Wave 3's chain-signing impl
    /// computes `prev_hash` from the previous entry, derives the
    /// current entry's signature, and writes both to the audit
    /// stream destination(s).
    async fn sign_and_emit(&self, entry: &AuditEntry) -> Result<(), AuditError>;
}

pub struct NoopAuditSigner;

#[async_trait]
impl AuditSigner for NoopAuditSigner {
    async fn sign_and_emit(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
        Err(AuditError::NotWired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_audit_signer_is_constructable() {
        let _: Box<dyn AuditSigner> = Box::new(NoopAuditSigner);
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            tenant: TenantId("t".to_string()),
            plan_id: PlanId("p".to_string()),
            plan_version: 1,
            event: "plan.verified".to_string(),
            labels: std::collections::BTreeMap::from([(
                "actor".to_string(),
                "supervisor".to_string(),
            )]),
        };
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, entry);
    }
}
