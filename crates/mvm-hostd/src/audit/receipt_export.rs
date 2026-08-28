//! Read-only exporter from chain-signed audit entries to signed
//! [`mvm_core::receipt::ExecutionReceipt`]s.
//!
//! Converts the existing host-side chain-signed audit log into portable,
//! offline-verifiable receipts without adding new runtime instrumentation.
//!
//! The exporter is deliberately conservative about what becomes a *receipt*:
//! only audit events whose semantics are unambiguously mappable to a receipt
//! type and outcome, so a future audit-entry extension cannot silently change
//! the meaning of an exported receipt.
//!
//! Conservative is not the same as lossy. Every other in-scope entry —
//! `flow.egress.*`, `stream.*`, `transcript.sealed`, and anything added later
//! — is carried as a [`CitedEntry`] with its leaf index and digest. Receipts
//! plus citations cover every in-scope entry exactly once, which is what makes
//! "this export is complete" a checkable claim rather than a property of
//! whichever events happened to be on the mapping list.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use mvm_core::did_key::DidKey;
use mvm_core::receipt::{
    ExecutionReceipt, ReceiptAction, ReceiptOutcome, SignedExecutionReceipt, receipt_type,
};
use mvm_core::usage_capture::UsageCapture;
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
    Ok(export_evidence(audit_dir, tenant, plan_id_filter, signing_key)?.receipts)
}

/// Convert one verified audit entry into an execution-receipt payload.
///
/// Returns `None` for events that have no defined receipt mapping.
/// The receipt's `receipt_id` is computed from the canonical payload so
/// callers can verify content addressing offline.
pub fn audit_entry_to_receipt(
    entry: &PlanAuditEntry,
    host_did: &str,
    context: Option<&ReceiptContext>,
) -> Option<ExecutionReceipt> {
    let (receipt_type, outcome) = map_event_to_receipt_type(&entry.event)?;
    let action = build_action(entry, receipt_type);
    let mut extensions = build_extensions(entry);

    // Carried on the receipt, not only in the chain, so a receipt lifted out
    // of an archive and forwarded on its own still names the transcript it
    // belongs to. The extensions are signed material, so this is inside the
    // content address rather than beside it.
    if let Some(root) = context.and_then(|c| c.transcript_root.clone()) {
        extensions.insert(
            mvm_core::receipt::extension_key::TRANSCRIPT_ROOT.to_string(),
            Value::String(root),
        );
    }
    if let Some(adopted) = context.and_then(|c| c.transcript_adopted) {
        extensions.insert(
            mvm_core::receipt::extension_key::TRANSCRIPT_ADOPTED.to_string(),
            Value::Bool(adopted),
        );
    }

    // Where this execution sits in the tenant-wide tree, so a verifier can
    // bound its scan instead of walking every leaf.
    if let (Some(first), Some(last)) = (
        context.and_then(|c| c.leaf_first),
        context.and_then(|c| c.leaf_last),
    ) {
        extensions.insert(
            mvm_core::receipt::extension_key::PLAN_LEAF_FIRST.to_string(),
            Value::Number(first.into()),
        );
        extensions.insert(
            mvm_core::receipt::extension_key::PLAN_LEAF_LAST.to_string(),
            Value::Number(last.into()),
        );
    }

    let image_node_digest = entry.labels.get("image_node_digest").cloned();
    let agent_id = entry.labels.get("agent_id").cloned();
    let principal_did = entry.labels.get("principal_did").cloned();
    let granted_by = entry.labels.get("granted_by").cloned();
    let prev_receipt_id = entry.labels.get("prev_receipt_id").cloned();

    let started_at = context.and_then(|c| c.started_at.clone());
    let ended_at = if receipt_type == receipt_type::PLAN_EXITED {
        Some(entry.timestamp.to_rfc3339())
    } else {
        None
    };
    let exit_code = if receipt_type == receipt_type::PLAN_EXITED {
        entry
            .labels
            .get("exit_code")
            .and_then(|v| v.parse::<i32>().ok())
    } else {
        None
    };

    // Every exit receipt answers the usage question, even when the answer is
    // that nothing was observed. An absent extension would be ambiguous
    // between "not measured" and "not asked", and only one of those is true.
    if receipt_type == receipt_type::PLAN_EXITED {
        let usage: UsageCapture = entry
            .labels
            .get("usage")
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default();
        // A serialization failure here must not fall through to a
        // usage-free exit receipt: "present without exception" means a
        // receipt that cannot carry a valid usage extension does not build.
        let value = serde_json::to_value(usage).ok()?;
        extensions.insert(mvm_core::receipt::extension_key::USAGE.to_string(), value);
    }
    let granted_capabilities = context
        .map(|c| c.granted_capabilities.clone())
        .unwrap_or_default();
    let network_destinations = context
        .map(|c| c.network_destinations.clone())
        .unwrap_or_default();

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
        started_at,
        ended_at,
        exit_code,
        granted_capabilities,
        network_destinations,
        issued_at: entry.timestamp.to_rfc3339(),
        extensions,
    };
    receipt.receipt_id = receipt.compute_id().ok()?;
    Some(receipt)
}

/// What an audit entry becomes in an export.
///
/// Two arms rather than an `Option` so an event with no receipt mapping is a
/// classification the caller has to handle, not a value that falls out of a
/// `continue`. An export that silently skipped entries was indistinguishable
/// from an export of a run that never produced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryMapping {
    /// Maps to a receipt of this type and outcome.
    Receipt {
        /// Wire-stable receipt type.
        receipt_type: &'static str,
        /// Outcome the receipt records.
        outcome: ReceiptOutcome,
    },
    /// No receipt mapping; carried as a citation instead.
    Cited,
}

/// Per-plan context gathered from the audit chain to enrich receipts.
///
/// The exporter is intentionally read-only over the audit log, so any value
/// that appears on a receipt must have been recorded in the chain. This
/// struct captures adjacent entries that are needed to give a `plan.exited`
/// receipt a complete view of the run it summarizes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiptContext {
    /// Timestamp of the matching `plan.launched` entry, if one exists.
    pub started_at: Option<String>,
    /// Capability grants admitted for this workload, collected from
    /// `plan.grant_required` and `plan.grants_enforced` entries.
    pub granted_capabilities: Vec<String>,
    /// Network destinations admitted for this workload, collected from
    /// `plan.egress_destinations` entries.
    pub network_destinations: Vec<(String, u16)>,
    /// Ciphertext-manifest root of the sealed output transcript, from the
    /// `gateway.transcript_sealed` anchor. `None` until the transcript seals.
    pub transcript_root: Option<String>,
    /// Whether that seal was rebuilt from the journal rather than written by
    /// the capturing process.
    pub transcript_adopted: Option<bool>,
    /// Lowest and highest leaf index in the full verified chain carrying an
    /// entry for this plan. A bound on where this execution lives in the
    /// tenant-wide tree, not a claim that the range holds only its entries.
    pub leaf_first: Option<u64>,
    pub leaf_last: Option<u64>,
}

/// One in-scope audit entry that has no receipt mapping.
///
/// Carries enough to resolve the entry against the real audit tree: the leaf
/// index it sits at and the digest of its exact signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CitedEntry {
    /// 0-based index in the full verified chain, not within the filtered set.
    pub leaf_index: u64,
    /// `sha256:<hex>` of the exact signed entry bytes.
    pub digest: String,
    /// The audit entry's `event` name.
    pub event: String,
    /// Plan the entry is bound to.
    pub plan_id: String,
    /// RFC 3339 timestamp of the entry.
    pub timestamp: String,
}

/// Everything one export accounts for: the receipts, and the entries that
/// have no receipt mapping.
///
/// The two together cover every in-scope entry exactly once. That is the
/// property `every_in_scope_entry_is_either_a_receipt_or_a_citation` pins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportedEvidence {
    /// Signed receipts, in chain order.
    pub receipts: Vec<SignedExecutionReceipt>,
    /// In-scope entries with no receipt mapping, in chain order.
    pub cited: Vec<CitedEntry>,
}

/// The audit tree one export pass is anchored to.
///
/// Built once per export and shared by every receipt, so a run's receipts all
/// name the same tree.
pub struct ChainPosition {
    root_hash: String,
    tree_size: u64,
}

impl ChainPosition {
    /// Build the Merkle root over `tenant`'s verified chain.
    ///
    /// Refuses on a chain that does not verify, because
    /// [`crate::audit::merkle::build_root_in`] does — a root over a corrupt log
    /// would attest the corruption.
    pub fn build(
        audit_dir: &std::path::Path,
        tenant: &str,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        let (root, tree_size) =
            crate::audit::merkle::build_root_in(audit_dir, tenant, &signing_key.verifying_key())?;
        Ok(Self {
            root_hash: hex::encode(root),
            tree_size,
        })
    }

    /// Stamp a receipt with where it came from, then re-address it.
    ///
    /// The extensions are signed material, so the content address has to be
    /// recomputed after they land. Doing both here is deliberate: an insert
    /// that forgot the recompute would produce a receipt whose `receipt_id`
    /// does not match its own bytes, and `verify` would reject it far from the
    /// line that caused it.
    pub fn attach(&self, receipt: &mut ExecutionReceipt, entry: &PlanAuditEntry) -> Result<()> {
        let digest = crate::audit::evidence::audit_entry_digest_hex(entry)
            .with_context(|| format!("digesting audit entry '{}'", entry.event))?;
        receipt.extensions.insert(
            mvm_core::receipt::extension_key::AUDIT_DIGEST.to_string(),
            Value::String(digest),
        );
        receipt.extensions.insert(
            mvm_core::receipt::extension_key::AUDIT_ROOT.to_string(),
            Value::String(self.root_hash.clone()),
        );
        receipt.extensions.insert(
            mvm_core::receipt::extension_key::TREE_SIZE.to_string(),
            Value::Number(self.tree_size.into()),
        );
        receipt.receipt_id = receipt
            .compute_id()
            .map_err(|e| anyhow::anyhow!("recomputing receipt id after stamping position: {e}"))?;
        Ok(())
    }

    /// The root hash this pass is anchored to, as lowercase hex.
    #[must_use]
    pub fn root_hash(&self) -> &str {
        &self.root_hash
    }

    /// The tree size that root was built at.
    #[must_use]
    pub fn tree_size(&self) -> u64 {
        self.tree_size
    }
}

/// Classify an audit `event`.
///
/// Every event resolves: unrecognised ones are [`EntryMapping::Cited`] rather
/// than discarded.
pub fn map_event(event: &str) -> EntryMapping {
    match map_event_to_receipt_type(event) {
        Some((receipt_type, outcome)) => EntryMapping::Receipt {
            receipt_type,
            outcome,
        },
        None => EntryMapping::Cited,
    }
}

/// Export every in-scope audit entry: receipts where a mapping exists,
/// citations everywhere else.
///
/// The chain is verified under `signing_key.verifying_key()` before any entry
/// is converted. Leaf indices are positions in the **full** verified chain, so
/// a citation addresses the real Merkle tree; an index counted within the
/// filtered subset would not build a verifying inclusion proof.
pub fn export_evidence(
    audit_dir: &std::path::Path,
    tenant: &str,
    plan_id_filter: Option<&str>,
    signing_key: &SigningKey,
) -> Result<ExportedEvidence> {
    let path = crate::audit::emitter::audit_path_for_tenant(audit_dir, tenant);
    if !path.exists() {
        return Ok(ExportedEvidence::default());
    }
    let entries = verify_audit_chain_entries(&path, &signing_key.verifying_key())
        .with_context(|| format!("verifying audit chain for tenant '{tenant}'"))?;
    let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();
    let signed_at = chrono::Utc::now().to_rfc3339();

    // One root for the whole pass. Every receipt from this export cites it, and
    // every inclusion proof an archive builds binds to it; a root rebuilt
    // per-entry would let two receipts from one run name different trees.
    let position = ChainPosition::build(audit_dir, tenant, signing_key)
        .with_context(|| format!("building the audit root for tenant '{tenant}'"))?;

    // Build per-plan context once so every receipt for a plan can reference
    // adjacent entries (e.g. `plan.launched` timestamp) without re-scanning.
    let context_by_plan = build_context_map(&entries);

    let mut out = ExportedEvidence::default();
    for (leaf_index, entry) in entries.iter().enumerate() {
        if let Some(filter) = plan_id_filter
            && entry.plan_id.0 != filter
        {
            continue;
        }
        let context = context_by_plan.get(&entry.plan_id.0);
        match map_event(&entry.event) {
            EntryMapping::Receipt { .. } => {
                let mut receipt =
                    audit_entry_to_receipt(entry, &host_did, context).with_context(|| {
                        format!("building a receipt for a mapped event '{}'", entry.event)
                    })?;
                position
                    .attach(&mut receipt, entry)
                    .context("attaching the chain position to a receipt")?;
                let signed = SignedExecutionReceipt::sign(receipt, signing_key, signed_at.clone())
                    .context("signing execution receipt")?;
                out.receipts.push(signed);
            }
            EntryMapping::Cited => {
                let digest = crate::audit::evidence::audit_entry_digest_hex(entry)
                    .with_context(|| format!("digesting audit entry '{}'", entry.event))?;
                out.cited.push(CitedEntry {
                    leaf_index: leaf_index as u64,
                    digest: format!("sha256:{digest}"),
                    event: entry.event.clone(),
                    plan_id: entry.plan_id.0.clone(),
                    timestamp: entry.timestamp.to_rfc3339(),
                });
            }
        }
    }
    Ok(out)
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
        "agent_id"
            | "principal_did"
            | "granted_by"
            | "prev_receipt_id"
            | "image_node_digest"
            | "usage"
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

/// Build a per-plan context map from the verified audit chain.
///
/// This is a single pass that records information needed by receipts but
/// stored in separate audit entries, such as the `plan.launched` timestamp
/// and admitted capability grants.
fn build_context_map(entries: &[PlanAuditEntry]) -> BTreeMap<String, ReceiptContext> {
    let mut map: BTreeMap<String, ReceiptContext> = BTreeMap::new();

    // Enumerated over the FULL verified chain, matching `export_evidence`, so
    // these indices address the real Merkle tree. Counted within a filtered
    // subset they would point at the wrong leaves.
    for (leaf_index, entry) in entries.iter().enumerate() {
        let ctx = map.entry(entry.plan_id.0.clone()).or_default();
        let leaf_index = leaf_index as u64;
        ctx.leaf_first = Some(ctx.leaf_first.map_or(leaf_index, |f| f.min(leaf_index)));
        ctx.leaf_last = Some(ctx.leaf_last.map_or(leaf_index, |l| l.max(leaf_index)));

        if entry.event == "plan.launched" && ctx.started_at.is_none() {
            ctx.started_at = Some(entry.timestamp.to_rfc3339());
        }

        // The seal is the last thing a run produces, so a later anchor for the
        // same plan supersedes an earlier one rather than being ignored: a
        // restarted capture seals again and the newest root is the live one.
        if entry.event == crate::supervisor::audit::TRANSCRIPT_SEALED_EVENT {
            if let Some(root) = entry
                .labels
                .get(crate::supervisor::audit::LABEL_TRANSCRIPT_ROOT)
            {
                ctx.transcript_root = Some(root.clone());
            }
            ctx.transcript_adopted = entry
                .labels
                .get(crate::supervisor::audit::LABEL_ADOPTED)
                .map(|v| v == "true");
        }

        if entry.event == "plan.grant_required" {
            // Collect verb_N labels in order.
            let mut verbs: Vec<String> = Vec::new();
            let count = entry
                .labels
                .get("verb_count")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            for i in 0..count {
                if let Some(verb) = entry.labels.get(&format!("verb_{i}")) {
                    verbs.push(verb.clone());
                }
            }
            if !verbs.is_empty() {
                ctx.granted_capabilities = verbs;
            }
        }

        if entry.event == "plan.grants_enforced" {
            // Carry enforced tiers as capability annotations.
            let mut caps = Vec::new();
            if let Some(cpu) = entry.labels.get("grants_cpu_tier") {
                caps.push(format!("cpu:{cpu}"));
            }
            if let Some(wall) = entry.labels.get("grants_wall_clock_tier") {
                caps.push(format!("wall_clock:{wall}"));
            }
            if !caps.is_empty() {
                ctx.granted_capabilities.extend(caps);
            }
        }

        if entry.event == "plan.egress_destinations" {
            let count = entry
                .labels
                .get("destination_count")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let mut destinations = Vec::new();
            for i in 0..count {
                let host = entry
                    .labels
                    .get(&format!("destination_{i}_host"))
                    .cloned()
                    .unwrap_or_default();
                let port = entry
                    .labels
                    .get(&format!("destination_{i}_port"))
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(0);
                destinations.push((host, port));
            }
            if !destinations.is_empty() {
                ctx.network_destinations = destinations;
            }
        }
    }

    map
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

        let receipt = audit_entry_to_receipt(&entry, &host_did, None).unwrap();

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

        let receipt = audit_entry_to_receipt(&entry, &host_did, None).unwrap();

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

        let receipt = audit_entry_to_receipt(&entry, &host_did, None).unwrap();

        assert_eq!(receipt.receipt_type, receipt_type::PLAN_EXITED);
        assert_eq!(receipt.outcome, ReceiptOutcome::Failed);
    }

    #[test]
    fn assurance_observer_entry_maps_to_a_signed_evidence_receipt() {
        let entry = sample_audit_entry("assurance.observer_completed", BTreeMap::new());
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();

        let receipt = audit_entry_to_receipt(&entry, &host_did, None).expect("known event");

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

        let receipt = audit_entry_to_receipt(&entry, &host_did, None).expect("known event");

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

        let receipt = audit_entry_to_receipt(&entry, &host_did, None).expect("known event");

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

        let receipt = audit_entry_to_receipt(&entry, &host_did, None).unwrap();

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

        let result = audit_entry_to_receipt(&entry, &host_did, None);
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
    fn a_receipt_bounds_its_execution_in_the_tenant_wide_tree() {
        // The tree is per-tenant, so without a bound a verifier has to walk
        // every leaf to find one execution. The pair is a bound and not an
        // enumeration -- another plan's entries can sit between them -- and
        // this test pins exactly that, interleaving a second plan inside the
        // first one's range.
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let other = |event: &str| {
            let mut e = sample_audit_entry(event, BTreeMap::new());
            e.plan_id = mvm_core::plan::PlanId("some-other-plan".to_string());
            e
        };
        // leaf 0 = ours, leaf 1 = someone else's, leaf 2 = ours.
        for entry in [
            sample_audit_entry("plan.admitted", BTreeMap::new()),
            other("plan.admitted"),
            sample_audit_entry("plan.exited", {
                let mut l = BTreeMap::new();
                l.insert("backend".into(), "firecracker".into());
                l.insert("exit_code".into(), "0".into());
                l
            }),
        ] {
            rt.block_on(signer.sign_and_emit(&entry)).unwrap();
        }

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        let first_key = mvm_core::receipt::extension_key::PLAN_LEAF_FIRST;
        let last_key = mvm_core::receipt::extension_key::PLAN_LEAF_LAST;

        let ours: Vec<_> = receipts
            .iter()
            .filter(|r| r.payload.plan_id == sample_plan_id().0)
            .collect();
        assert!(!ours.is_empty(), "our plan produced receipts");
        for signed in &ours {
            assert_eq!(
                signed.payload.extensions.get(first_key),
                Some(&Value::Number(0u64.into()))
            );
            assert_eq!(
                signed.payload.extensions.get(last_key),
                Some(&Value::Number(2u64.into())),
                "the bound must span to our last entry even though another \
                 plan's entry sits inside the range"
            );
            signed.verify().unwrap();
        }

        // The interleaved plan gets its own, tighter bound.
        if let Some(theirs) = receipts
            .iter()
            .find(|r| r.payload.plan_id == "some-other-plan")
        {
            assert_eq!(
                theirs.payload.extensions.get(first_key),
                Some(&Value::Number(1u64.into()))
            );
            assert_eq!(
                theirs.payload.extensions.get(last_key),
                Some(&Value::Number(1u64.into()))
            );
        }
    }

    #[test]
    fn a_sealed_transcript_root_reaches_every_receipt_for_that_plan() {
        // Without this the receipt names the audit root and nothing the
        // workload produced, so a receipt forwarded on its own cannot say
        // which transcript belongs to it.
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let root = "ab".repeat(32);
        let sealed = {
            let mut labels = BTreeMap::new();
            labels.insert(
                crate::supervisor::audit::LABEL_TRANSCRIPT_ROOT.into(),
                root.clone(),
            );
            labels.insert(
                crate::supervisor::audit::LABEL_ADOPTED.into(),
                "false".into(),
            );
            labels.insert(
                crate::supervisor::audit::LABEL_CAPTURE_ID.into(),
                "cap-1".into(),
            );
            sample_audit_entry(crate::supervisor::audit::TRANSCRIPT_SEALED_EVENT, labels)
        };
        let exited = {
            let mut labels = BTreeMap::new();
            labels.insert("backend".into(), "firecracker".into());
            labels.insert("exit_code".into(), "0".into());
            sample_audit_entry("plan.exited", labels)
        };

        for entry in [
            sample_audit_entry("plan.admitted", BTreeMap::new()),
            sealed,
            exited,
        ] {
            rt.block_on(signer.sign_and_emit(&entry)).unwrap();
        }

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        assert!(!receipts.is_empty(), "the export produced receipts");

        let key = mvm_core::receipt::extension_key::TRANSCRIPT_ROOT;
        let adopted_key = mvm_core::receipt::extension_key::TRANSCRIPT_ADOPTED;
        for signed in &receipts {
            assert_eq!(
                signed.payload.extensions.get(key),
                Some(&Value::String(root.clone())),
                "receipt {} carries the sealed transcript root",
                signed.payload.receipt_type
            );
            assert_eq!(
                signed.payload.extensions.get(adopted_key),
                Some(&Value::Bool(false))
            );
            // The extensions are signed material, so the root is inside the
            // content address rather than beside it.
            signed.verify().unwrap();
        }
    }

    #[test]
    fn an_adopted_transcript_is_marked_incomplete_on_the_receipt() {
        // A floor presented as a full account would be a wrong record.
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[17u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let sealed = {
            let mut labels = BTreeMap::new();
            labels.insert(
                crate::supervisor::audit::LABEL_TRANSCRIPT_ROOT.into(),
                "cd".repeat(32),
            );
            labels.insert(
                crate::supervisor::audit::LABEL_ADOPTED.into(),
                "true".into(),
            );
            sample_audit_entry(crate::supervisor::audit::TRANSCRIPT_SEALED_EVENT, labels)
        };
        for entry in [sample_audit_entry("plan.admitted", BTreeMap::new()), sealed] {
            rt.block_on(signer.sign_and_emit(&entry)).unwrap();
        }

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        let adopted_key = mvm_core::receipt::extension_key::TRANSCRIPT_ADOPTED;
        assert!(
            receipts
                .iter()
                .all(|r| r.payload.extensions.get(adopted_key) == Some(&Value::Bool(true))),
            "an adopted seal must stay marked incomplete on every receipt"
        );
    }

    #[test]
    fn exited_receipt_includes_exit_code_and_timing() {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let launched = {
            let mut labels = BTreeMap::new();
            labels.insert("backend".into(), "firecracker".into());
            sample_audit_entry("plan.launched", labels)
        };
        let launched_at = launched.timestamp.to_rfc3339();

        let exited = {
            let mut labels = BTreeMap::new();
            labels.insert("backend".into(), "firecracker".into());
            labels.insert("exit_code".into(), "42".into());
            sample_audit_entry("plan.exited", labels)
        };
        let exited_at = exited.timestamp.to_rfc3339();

        rt.block_on(signer.sign_and_emit(&launched)).unwrap();
        rt.block_on(signer.sign_and_emit(&exited)).unwrap();

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        assert_eq!(receipts.len(), 2);

        let exit_receipt = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("exit receipt exists");
        assert_eq!(exit_receipt.payload.exit_code, Some(42));
        assert_eq!(exit_receipt.payload.started_at, Some(launched_at));
        assert_eq!(exit_receipt.payload.ended_at, Some(exited_at));
        exit_receipt.verify().unwrap();
    }

    #[test]
    fn grant_required_populates_capabilities_on_exported_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[12u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let admitted = sample_audit_entry("plan.admitted", BTreeMap::new());

        let grant_required = {
            let mut labels = BTreeMap::new();
            labels.insert("verb_count".into(), "2".into());
            labels.insert("verb_0".into(), "read".into());
            labels.insert("verb_1".into(), "write".into());
            sample_audit_entry("plan.grant_required", labels)
        };

        let exited = {
            let mut labels = BTreeMap::new();
            labels.insert("exit_code".into(), "0".into());
            sample_audit_entry("plan.exited", labels)
        };

        rt.block_on(signer.sign_and_emit(&admitted)).unwrap();
        rt.block_on(signer.sign_and_emit(&grant_required)).unwrap();
        rt.block_on(signer.sign_and_emit(&exited)).unwrap();

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        let exit_receipt = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("exit receipt exists");
        assert_eq!(
            exit_receipt.payload.granted_capabilities,
            vec!["read".to_string(), "write".to_string()]
        );
        exit_receipt.verify().unwrap();
    }

    #[test]
    fn egress_destinations_populate_network_destinations_on_exported_receipts() {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let admitted = sample_audit_entry("plan.admitted", BTreeMap::new());

        let egress = {
            let mut labels = BTreeMap::new();
            labels.insert("destination_count".into(), "2".into());
            labels.insert("destination_0_host".into(), "example.com".into());
            labels.insert("destination_0_port".into(), "443".into());
            labels.insert("destination_1_host".into(), "api.example.com".into());
            labels.insert("destination_1_port".into(), "8443".into());
            sample_audit_entry("plan.egress_destinations", labels)
        };

        let exited = {
            let mut labels = BTreeMap::new();
            labels.insert("exit_code".into(), "0".into());
            sample_audit_entry("plan.exited", labels)
        };

        rt.block_on(signer.sign_and_emit(&admitted)).unwrap();
        rt.block_on(signer.sign_and_emit(&egress)).unwrap();
        rt.block_on(signer.sign_and_emit(&exited)).unwrap();

        let receipts = export_receipts(dir.path(), "local", None, &signing_key).unwrap();
        let exit_receipt = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("exit receipt exists");
        assert_eq!(
            exit_receipt.payload.network_destinations,
            vec![
                ("example.com".to_string(), 443),
                ("api.example.com".to_string(), 8443),
            ]
        );
        exit_receipt.verify().unwrap();
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

    /// Export a `plan.launched` + `plan.exited` pair where the exit entry
    /// carries a `usage` label encoding `capture` as compact JSON, mirroring
    /// what Task 4's `emit_exited_with_capture` writes.
    fn export_fixture_with_usage(
        capture: mvm_core::usage_capture::UsageCapture,
    ) -> Vec<SignedExecutionReceipt> {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[21u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let launched = sample_audit_entry("plan.launched", BTreeMap::new());

        let exited = {
            let mut labels = BTreeMap::new();
            labels.insert("exit_code".into(), "0".into());
            labels.insert("usage".into(), serde_json::to_string(&capture).unwrap());
            sample_audit_entry("plan.exited", labels)
        };

        rt.block_on(signer.sign_and_emit(&launched)).unwrap();
        rt.block_on(signer.sign_and_emit(&exited)).unwrap();

        export_receipts(dir.path(), "local", None, &signing_key).unwrap()
    }

    /// Export a `plan.launched` + `plan.exited` pair where the exit entry
    /// carries no `usage` label at all, standing in for an entry written
    /// before this feature existed.
    fn export_fixture_without_usage_label() -> Vec<SignedExecutionReceipt> {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[22u8; 32]);
        let signer = FileAuditSigner::open(signing_key.clone(), dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let launched = sample_audit_entry("plan.launched", BTreeMap::new());

        let exited = {
            let mut labels = BTreeMap::new();
            labels.insert("exit_code".into(), "0".into());
            sample_audit_entry("plan.exited", labels)
        };

        rt.block_on(signer.sign_and_emit(&launched)).unwrap();
        rt.block_on(signer.sign_and_emit(&exited)).unwrap();

        export_receipts(dir.path(), "local", None, &signing_key).unwrap()
    }

    /// A bare, valid `plan.exited` receipt payload for tests that need to
    /// mutate `extensions` directly rather than going through the exporter.
    fn sample_exited_receipt() -> ExecutionReceipt {
        let mut labels = BTreeMap::new();
        labels.insert("exit_code".into(), "0".into());
        let entry = sample_audit_entry("plan.exited", labels);
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let host_did = DidKey::from_verifying_key(signing_key.verifying_key()).to_did_key();
        audit_entry_to_receipt(&entry, &host_did, None).expect("plan.exited maps to a receipt")
    }

    #[test]
    fn an_exited_receipt_carries_the_usage_extension() {
        use mvm_core::usage_capture::{Mechanism, Metric, UsageCapture};

        let receipts = export_fixture_with_usage(UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
            ..UsageCapture::default()
        });
        let exited = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("an exit receipt");
        let usage = exited
            .payload
            .extensions
            .get(mvm_core::receipt::extension_key::USAGE)
            .expect("mvm.usage");
        assert_eq!(usage["cpu_ms"]["value"], serde_json::json!(4210));
        assert_eq!(usage["cpu_ms"]["source"], serde_json::json!("measured"));
        assert_eq!(
            usage["cpu_ms"]["mechanism"],
            serde_json::json!("host_process_cpu")
        );
    }

    #[test]
    fn a_dimension_nobody_observed_carries_no_number_to_misread() {
        use mvm_core::usage_capture::UsageCapture;

        let receipts = export_fixture_with_usage(UsageCapture::default());
        let exited = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("an exit receipt");
        let usage = exited
            .payload
            .extensions
            .get(mvm_core::receipt::extension_key::USAGE)
            .expect("mvm.usage is present even when nothing was measured");
        assert_eq!(usage["cpu_ms"]["source"], serde_json::json!("unavailable"));
        assert!(
            usage["cpu_ms"].get("value").is_none(),
            "no number to read as zero"
        );
    }

    #[test]
    fn an_entry_with_no_usage_label_still_yields_an_all_unavailable_extension() {
        // An entry written before this feature must not be reported as a run
        // whose usage question was never asked.
        let receipts = export_fixture_without_usage_label();
        let exited = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("an exit receipt");
        let usage = exited
            .payload
            .extensions
            .get(mvm_core::receipt::extension_key::USAGE)
            .expect("mvm.usage");
        assert_eq!(usage["wall_ms"]["source"], serde_json::json!("unavailable"));
    }

    #[test]
    fn a_usage_extension_survives_the_receipt_value_space() {
        use mvm_core::usage_capture::{Mechanism, Metric, UsageCapture};

        // Integers and ASCII only: the receipt refuses floats, so a percentage
        // added here later would break every verifier rather than degrade.
        let receipts = export_fixture_with_usage(UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
            peak_rss_mib: Metric::measured(312, Mechanism::HostProcessRss),
            ..UsageCapture::default()
        });
        for receipt in &receipts {
            receipt.verify().expect("a signed receipt verifies");
            receipt
                .payload
                .verify_id()
                .expect("the content address holds");
        }
    }

    #[test]
    fn flipping_a_usage_integer_breaks_the_content_address() {
        use mvm_core::usage_capture::{Mechanism, Metric, UsageCapture};

        let receipts = export_fixture_with_usage(UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
            ..UsageCapture::default()
        });
        let mut tampered = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("an exit receipt")
            .clone();
        tampered.payload.extensions.insert(
            mvm_core::receipt::extension_key::USAGE.to_string(),
            serde_json::json!({ "cpu_ms": { "source": "measured", "value": 1, "mechanism": "host_process_cpu" } }),
        );
        assert!(tampered.payload.verify_id().is_err());
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn a_float_in_the_usage_extension_is_refused_by_the_value_space() {
        // Guards the no-percentages rule directly rather than by convention.
        let mut receipt = sample_exited_receipt();
        receipt.extensions.insert(
            mvm_core::receipt::extension_key::USAGE.to_string(),
            serde_json::json!({ "cpu_percent": 42.5 }),
        );
        assert!(receipt.compute_id().is_err(), "floats must not be signable");
    }

    #[test]
    fn the_raw_usage_label_does_not_leak_into_action_params() {
        // The usage claim must exist exactly once, typed and validated in
        // extensions["mvm.usage"]. A copy of the raw label string in
        // action.params would be a second, unvalidated usage claim inside
        // the same signed payload -- one that can disagree with the first.
        use mvm_core::usage_capture::{Mechanism, Metric, UsageCapture};

        let receipts = export_fixture_with_usage(UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
            ..UsageCapture::default()
        });
        let exited = receipts
            .iter()
            .find(|r| r.payload.receipt_type == receipt_type::PLAN_EXITED)
            .expect("an exit receipt");

        assert!(
            !exited.payload.action.params.contains_key("usage"),
            "the raw usage label must not be copied into action.params"
        );
        assert!(
            exited
                .payload
                .extensions
                .contains_key(mvm_core::receipt::extension_key::USAGE),
            "the typed usage extension must still be present"
        );
    }
}
