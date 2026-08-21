//! Read-only exporter from chain-signed audit entries to signed
//! [`mvm_core::receipt::ExecutionReceipt`]s.
//!
//! Converts the existing host-side chain-signed audit log into portable,
//! offline-verifiable receipts without adding new runtime instrumentation.
//!
//! The exporter is deliberately conservative: it only emits receipts for
//! audit events whose semantics are unambiguously mappable to a receipt
//! type and outcome. Unknown events are skipped so a future audit-entry
//! extension cannot silently change the meaning of an exported receipt.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mvm_core::did_key::DidKey;
use mvm_core::receipt::{
    ExecutionReceipt, ReceiptAction, ReceiptOutcome, SignedExecutionReceipt, receipt_type,
};
use serde_json::Value;

use crate::supervisor::audit::PlanAuditEntry;
use crate::supervisor::audit_file::verify_audit_chain_entries;

/// Export signed execution receipts from a tenant's chain-signed audit log.
///
/// The chain is verified under `signing_key.verifying_key()` before any
/// entry is converted. Each authenticated `PlanAuditEntry` that maps to a known
/// receipt type is converted, signed, and returned in chain order.
///
/// If `plan_id_filter` is `Some`, only entries whose `plan_id` matches are
/// exported.
pub fn export_receipts(
    audit_dir: &std::path::Path,
    tenant: &str,
    plan_id_filter: Option<&str>,
    signing_key: &SigningKey,
) -> Result<Vec<SignedExecutionReceipt>> {
    let path = crate::audit::emitter::audit_path_for_tenant(audit_dir, tenant);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let entries = verify_audit_chain_entries(&path, &signing_key.verifying_key())
        .with_context(|| format!("verifying audit chain for tenant '{tenant}'"))?;
    let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();
    let signed_at = chrono::Utc::now().to_rfc3339();
    let mut receipts = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(filter) = plan_id_filter
            && entry.plan_id.0 != filter
        {
            continue;
        }
        let receipt = match audit_entry_to_receipt(&entry, &host_did) {
            Some(r) => r,
            None => continue,
        };
        let signed = SignedExecutionReceipt::sign(receipt, signing_key, signed_at.clone())
            .context("signing execution receipt")?;
        receipts.push(signed);
    }
    Ok(receipts)
}

/// Convert one verified audit entry into an execution-receipt payload.
///
/// Returns `None` for events that have no defined receipt mapping.
/// The receipt's `receipt_id` is computed from the canonical payload so
/// callers can verify content addressing offline.
pub fn audit_entry_to_receipt(entry: &PlanAuditEntry, host_did: &str) -> Option<ExecutionReceipt> {
    let (receipt_type, outcome) = map_event_to_receipt_type(&entry.event)?;
    let action = build_action(entry, receipt_type);
    let extensions = build_extensions(entry);

    let image_node_digest = entry.labels.get("image_node_digest").cloned();
    let agent_id = entry.labels.get("agent_id").cloned();
    let principal_did = entry.labels.get("principal_did").cloned();
    let granted_by = entry.labels.get("granted_by").cloned();
    let prev_receipt_id = entry.labels.get("prev_receipt_id").cloned();

    let mut receipt = ExecutionReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        receipt_type: receipt_type.to_string(),
        plan_id: entry.plan_id.0.clone(),
        image_node_digest,
        agent_id,
        principal_did,
        host_did: host_did.to_string(),
        action,
        outcome,
        granted_by,
        prev_receipt_id,
        issued_at: entry.timestamp.to_rfc3339(),
        extensions,
    };
    receipt.receipt_id = receipt.compute_id().ok()?;
    Some(receipt)
}

/// Map an audit `event` name to a receipt type and outcome.
///
/// Unknown events return `None`.
fn map_event_to_receipt_type(event: &str) -> Option<(&'static str, ReceiptOutcome)> {
    let pair = match event {
        "plan.admitted" => (receipt_type::PLAN_ADMITTED, ReceiptOutcome::Authorized),
        "plan.launched" => (receipt_type::PLAN_LAUNCHED, ReceiptOutcome::Running),
        "plan.exited" => (receipt_type::PLAN_EXITED, ReceiptOutcome::Succeeded),
        "plan.failed" => (receipt_type::PLAN_EXITED, ReceiptOutcome::Failed),
        "checkpoint.created" => (receipt_type::CHECKPOINT_CREATED, ReceiptOutcome::Succeeded),
        "checkpoint.restored" => (receipt_type::CHECKPOINT_RESTORED, ReceiptOutcome::Succeeded),
        "checkpoint.forked" => (receipt_type::CHECKPOINT_FORKED, ReceiptOutcome::Succeeded),
        "stream.input_refused" => (receipt_type::INPUT_REFUSED, ReceiptOutcome::Refused),
        "assurance.session_opened" => (
            receipt_type::ASSURANCE_SESSION_OPENED,
            ReceiptOutcome::Authorized,
        ),
        "assurance.trial_completed" => (
            receipt_type::ASSURANCE_TRIAL_COMPLETED,
            ReceiptOutcome::Succeeded,
        ),
        "assurance.observer_completed" => (
            receipt_type::ASSURANCE_OBSERVER_COMPLETED,
            ReceiptOutcome::Succeeded,
        ),
        "assurance.cleanup_completed" => (
            receipt_type::ASSURANCE_CLEANUP_COMPLETED,
            ReceiptOutcome::Succeeded,
        ),
        "assurance.attestation_verified" => (
            receipt_type::ASSURANCE_ATTESTATION_VERIFIED,
            ReceiptOutcome::Succeeded,
        ),
        _ => return None,
    };
    Some(pair)
}

/// Build the [`ReceiptAction`] for an audit entry.
///
/// The verb/resource are derived from the receipt type. All labels except
/// those consumed as top-level receipt fields become `params`.
fn build_action(entry: &PlanAuditEntry, receipt_type: &str) -> ReceiptAction {
    let mut params: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in &entry.labels {
        if is_top_level_label(k) {
            continue;
        }
        params.insert(k.clone(), Value::String(v.clone()));
    }

    let (verb, resource) = match receipt_type {
        receipt_type::PLAN_ADMITTED
        | receipt_type::PLAN_LAUNCHED
        | receipt_type::PLAN_EXITED
        | receipt_type::INPUT_REFUSED => ("run", entry.plan_id.0.clone()),
        receipt_type::CHECKPOINT_CREATED
        | receipt_type::CHECKPOINT_RESTORED
        | receipt_type::CHECKPOINT_FORKED => {
            let resource = entry
                .labels
                .get("checkpoint_id")
                .cloned()
                .unwrap_or_else(|| entry.plan_id.0.clone());
            ("checkpoint", resource)
        }
        _ => ("run", entry.plan_id.0.clone()),
    };

    ReceiptAction {
        verb: verb.to_string(),
        resource,
        params,
    }
}

/// Labels that are hoisted to top-level receipt fields rather than being
/// treated as generic action parameters.
fn is_top_level_label(key: &str) -> bool {
    matches!(
        key,
        "agent_id" | "principal_did" | "granted_by" | "prev_receipt_id" | "image_node_digest"
    )
}

/// Build namespace-prefixed extensions that preserve audit-entry metadata
/// not otherwise represented in the receipt payload.
fn build_extensions(entry: &PlanAuditEntry) -> BTreeMap<String, Value> {
    let mut ext = BTreeMap::new();
    ext.insert(
        "mvm.tenant".to_string(),
        Value::String(entry.tenant.0.clone()),
    );
    ext.insert(
        "mvm.image_name".to_string(),
        Value::String(entry.image_name.clone()),
    );
    ext.insert(
        "mvm.image_sha256".to_string(),
        Value::String(entry.image_sha256.clone()),
    );
    if let Some(bundle_id) = &entry.bundle_id {
        ext.insert(
            "mvm.bundle_id".to_string(),
            Value::String(bundle_id.0.clone()),
        );
    }
    if let Some(bundle_version) = entry.bundle_version {
        ext.insert(
            "mvm.bundle_version".to_string(),
            Value::Number(bundle_version.into()),
        );
    }
    ext
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::{PlanId, TenantId};
    use mvm_core::receipt::ReceiptOutcome;

    use crate::supervisor::AuditSigner;
    use crate::supervisor::audit::PlanAuditEntry;
    use crate::supervisor::audit_file::FileAuditSigner;

    fn sample_plan_id() -> PlanId {
        PlanId("sha256:0000000000000000000000000000000000000000000000000000000000000001".into())
    }

    fn sample_audit_entry(event: &str, labels: BTreeMap<String, String>) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 8, 6, 0, 0, 0).unwrap(),
            tenant: TenantId("local".into()),
            plan_id: sample_plan_id(),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "test-image".into(),
            image_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000002"
                .into(),
            event: event.into(),
            labels,
        }
    }

    #[test]
    fn admitted_entry_maps_to_authorized_receipt() {
        let entry = sample_audit_entry("plan.admitted", BTreeMap::new());
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did).unwrap();

        assert_eq!(receipt.receipt_type, receipt_type::PLAN_ADMITTED);
        assert_eq!(receipt.outcome, ReceiptOutcome::Authorized);
        assert_eq!(receipt.plan_id, sample_plan_id().0);
        assert_eq!(receipt.host_did, host_did);
        assert_eq!(receipt.action.verb, "run");
        assert_eq!(receipt.action.resource, sample_plan_id().0);
        assert!(!receipt.receipt_id.is_empty());
        receipt.verify_id().unwrap();
    }

    #[test]
    fn launched_entry_includes_backend_param() {
        let mut labels = BTreeMap::new();
        labels.insert("backend".into(), "firecracker".into());
        let entry = sample_audit_entry("plan.launched", labels);
        let host_did =
            DidKey::from_verifying_key(SigningKey::from_bytes(&[2u8; 32]).verifying_key())
                .to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did).unwrap();

        assert_eq!(receipt.receipt_type, receipt_type::PLAN_LAUNCHED);
        assert_eq!(receipt.outcome, ReceiptOutcome::Running);
        assert_eq!(
            receipt.action.params.get("backend"),
            Some(&Value::String("firecracker".into()))
        );
    }

    #[test]
    fn failed_entry_maps_to_failed_outcome() {
        let mut labels = BTreeMap::new();
        labels.insert("class".into(), "boot".into());
        labels.insert("message".into(), "kernel panic".into());
        let entry = sample_audit_entry("plan.failed", labels);
        let host_did =
            DidKey::from_verifying_key(SigningKey::from_bytes(&[3u8; 32]).verifying_key())
                .to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did).unwrap();

        assert_eq!(receipt.receipt_type, receipt_type::PLAN_EXITED);
        assert_eq!(receipt.outcome, ReceiptOutcome::Failed);
    }

    #[test]
    fn assurance_observer_entry_maps_to_a_signed_evidence_receipt() {
        let entry = sample_audit_entry("assurance.observer_completed", BTreeMap::new());
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did).expect("known event");

        assert_eq!(
            receipt.receipt_type,
            receipt_type::ASSURANCE_OBSERVER_COMPLETED
        );
        assert_eq!(receipt.outcome, ReceiptOutcome::Succeeded);
        receipt.verify_id().expect("content address verifies");
    }

    #[test]
    fn assurance_cleanup_entry_maps_to_a_signed_evidence_receipt() {
        let entry = sample_audit_entry("assurance.cleanup_completed", BTreeMap::new());
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did).expect("known event");

        assert_eq!(
            receipt.receipt_type,
            receipt_type::ASSURANCE_CLEANUP_COMPLETED
        );
        assert_eq!(receipt.outcome, ReceiptOutcome::Succeeded);
        receipt.verify_id().expect("content address verifies");
    }

    #[test]
    fn assurance_attestation_entry_maps_to_a_signed_evidence_receipt() {
        let entry = sample_audit_entry("assurance.attestation_verified", BTreeMap::new());
        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did).expect("known event");

        assert_eq!(
            receipt.receipt_type,
            receipt_type::ASSURANCE_ATTESTATION_VERIFIED
        );
        assert_eq!(receipt.outcome, ReceiptOutcome::Succeeded);
        receipt.verify_id().expect("content address verifies");
    }

    #[test]
    fn checkpoint_entry_uses_checkpoint_id_as_resource() {
        let mut labels = BTreeMap::new();
        labels.insert("checkpoint_id".into(), "chk-123".into());
        labels.insert("class".into(), "full".into());
        labels.insert("vm_name".into(), "my-vm".into());
        let entry = sample_audit_entry("checkpoint.created", labels);
        let host_did =
            DidKey::from_verifying_key(SigningKey::from_bytes(&[4u8; 32]).verifying_key())
                .to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did).unwrap();

        assert_eq!(receipt.receipt_type, receipt_type::CHECKPOINT_CREATED);
        assert_eq!(receipt.action.verb, "checkpoint");
        assert_eq!(receipt.action.resource, "chk-123");
    }

    #[test]
    fn unknown_event_is_skipped_by_export() {
        let entry = sample_audit_entry("plan.boot_posture", BTreeMap::new());
        let host_did =
            DidKey::from_verifying_key(SigningKey::from_bytes(&[5u8; 32]).verifying_key())
                .to_did_key();

        let result = audit_entry_to_receipt(&entry, &host_did);
        assert!(result.is_none());
    }

    #[test]
    fn exported_receipts_verify_and_form_chain() {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[6u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let _plan_id = sample_plan_id();
        let entries = vec![
            sample_audit_entry("plan.admitted", BTreeMap::new()),
            {
                let mut labels = BTreeMap::new();
                labels.insert("backend".into(), "firecracker".into());
                sample_audit_entry("plan.launched", labels)
            },
            {
                let mut labels = BTreeMap::new();
                labels.insert("backend".into(), "firecracker".into());
                labels.insert("exit_code".into(), "0".into());
                sample_audit_entry("plan.exited", labels)
            },
        ];

        for entry in &entries {
            rt.block_on(signer.sign_and_emit(entry)).unwrap();
        }

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        assert_eq!(receipts.len(), 3);

        for signed in &receipts {
            signed.verify().unwrap();
        }

        for signed in &receipts {
            assert!(signed.payload.prev_receipt_id.is_none());
        }
    }

    #[test]
    fn plan_id_filter_limits_exported_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let plan_a = sample_plan_id();
        let plan_b = PlanId(
            "sha256:0000000000000000000000000000000000000000000000000000000000000002".into(),
        );

        let mut entry_a = sample_audit_entry("plan.admitted", BTreeMap::new());
        entry_a.plan_id = plan_a.clone();
        let mut entry_b = sample_audit_entry("plan.admitted", BTreeMap::new());
        entry_b.plan_id = plan_b.clone();

        rt.block_on(signer.sign_and_emit(&entry_a)).unwrap();
        rt.block_on(signer.sign_and_emit(&entry_b)).unwrap();

        let receipts = export_receipts(dir.path(), "local", Some(&plan_a.0), &signing_key).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].payload.plan_id, plan_a.0);
    }

    #[test]
    fn missing_chain_returns_empty_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        assert!(receipts.is_empty());
    }
}
