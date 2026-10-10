//! Read-only host audit verification. No signer, key custody or runtime.
pub mod file;
pub mod segment;
pub mod set;

/// The host's typed instantiation of the canonical audit wire schema.
pub type PlanAuditEntry = mvm_contract::verify::PlanAuditEntry<
    crate::plan::TenantId,
    crate::plan::PlanId,
    crate::policy::PolicyId,
    chrono::DateTime<chrono::Utc>,
>;
pub type SignedEnvelope = mvm_contract::verify::SignedEnvelope<PlanAuditEntry>;
