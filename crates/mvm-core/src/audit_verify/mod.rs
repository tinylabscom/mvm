//! Read-only host audit verification. No signer, key custody or runtime.
use mvm_contract::timestamp::UtcTimestamp;
pub mod file;
pub mod live;
pub mod segment;
pub mod set;

/// The host's typed instantiation of the canonical audit wire schema.
pub type PlanAuditEntry = mvm_contract::verify::PlanAuditEntry<
    crate::plan::TenantId,
    crate::plan::PlanId,
    crate::policy::PolicyId,
    UtcTimestamp,
>;
pub type SignedEnvelope = mvm_contract::verify::SignedEnvelope<PlanAuditEntry>;

#[cfg(test)]
mod tests {
    /// A pre-`canonical` line is verified by re-serializing its entry, so the
    /// host type must write the timestamp bytes back exactly as chrono did.
    #[test]
    fn audit_entry_timestamps_keep_their_bytes() {
        for line in [
            r#"{"timestamp":"2026-06-03T12:00:00Z","tenant":"t","plan_id":"p","plan_version":1,"image_name":"i","image_sha256":"00","event":"plan.admitted","labels":{}}"#,
            r#"{"timestamp":"2026-06-03T12:00:00.123456Z","tenant":"t","plan_id":"p","plan_version":1,"image_name":"i","image_sha256":"00","event":"plan.admitted","labels":{}}"#,
        ] {
            let entry: super::PlanAuditEntry = serde_json::from_str(line).unwrap();
            assert_eq!(serde_json::to_string(&entry).unwrap(), line);
        }
    }
}
