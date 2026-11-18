//! Admission verdict and decision-record emission for [`AuditEmitter`].
//!
//! `plan.admitted` / `plan.admission_refused` record the admission verdict,
//! `control_key.used` attributes orchestrator actions to the key that
//! authorized them, and `decision_record` entries carry signed decision
//! records into the chain and the local decision store.

use super::AuditEmitter;
use super::runtime_identity_labels;
use super::stream_audit;
use crate::audit::signer::for_plan;
use anyhow::{Context, Result};
use chrono::Utc;
use mvm_contract::provenance::{
    ActorRef, AttestationBinding, DecisionActorRole, DecisionCategory, DecisionId, DecisionOutcome,
    DecisionRecord, DecisionRecordBuilder,
};
use mvm_contract::verify::hash_line;
use mvm_core::plan::ExecutionPlan;

impl AuditEmitter {
    /// True when the emitter will cache decision records locally.
    pub fn decisions_enabled(&self) -> bool {
        self.decisions_enabled
    }

    /// Emit `plan.admitted` — fires immediately after `admit_for_run`
    /// succeeds. Binds the plan_id, signer (via `audit_labels` extras),
    /// and the workload context. A pinned release runtime is recorded as
    /// individual chain-signed fields; the caller must first compare the pin
    /// with the launch verifier's identity and require durable admission.
    ///
    /// Also carries the admitted output-retention mode. Without it, a workload
    /// with no transcript is ambiguous — nobody can tell a run that was
    /// admitted not to keep one from a run whose recording was lost or
    /// removed. The mode is a word off the signed plan, so recording it costs
    /// nothing and settles the question from the chain alone.
    pub fn emit_admitted(&self, plan: &ExecutionPlan, signer_id: &str) -> Result<()> {
        let mut labels = vec![
            ("workload".to_string(), plan.workload.0.clone()),
            ("signer_id".to_string(), signer_id.to_string()),
            ("authorizer_principal".to_string(), signer_id.to_string()),
            (
                stream_audit::LABEL_RETENTION.to_string(),
                plan.stream_retention.as_str().to_string(),
            ),
        ];
        labels.push((
            "kernel_sha256".to_string(),
            plan.environment
                .as_ref()
                .map_or_else(String::new, |environment| environment.kernel_sha256.clone()),
        ));
        if let Some(runtime) = plan.runtime_identity.as_ref() {
            labels.extend(runtime_identity_labels(runtime));
        }
        self.emit(plan, "plan.admitted", labels)
    }

    /// Emit `plan.admission_refused` — fires when `admit_plan_for_run` refuses
    /// to admit a plan before the VM is created. The stage and reason are
    /// recorded in the chain so an auditor can distinguish a refusal from a
    /// missing admission.
    pub fn emit_refused(&self, plan: &ExecutionPlan, stage: &str, reason: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.admission_refused",
            [
                ("workload".to_string(), plan.workload.0.clone()),
                ("stage".to_string(), stage.to_string()),
                ("reason".to_string(), reason.to_string()),
                (
                    "authorizer_principal".to_string(),
                    crate::audit::host_keypair::host_signer_id(),
                ),
            ],
        )
    }

    /// Emit `control_key.used` — fires when a `ControlKey` is used to
    /// authorize an orchestrator action. Carries the key id, role, and a
    /// short action label. No secret material is logged.
    pub fn emit_control_key_used(
        &self,
        plan: &ExecutionPlan,
        key: &mvm_core::mvmd_iface::ControlKey,
        action: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            "control_key.used",
            [
                ("kid".to_string(), key.kid.clone()),
                ("role".to_string(), format!("{:?}", key.role)),
                ("action".to_string(), action.to_string()),
                ("authorizer_principal".to_string(), key.kid.clone()),
            ],
        )?;

        if self.decisions_enabled() {
            let record = Self::control_key_decision_record(plan, key, action);
            let _ = self.emit_decision_record(plan, record);
        }
        Ok(())
    }

    fn control_key_decision_record(
        plan: &ExecutionPlan,
        key: &mvm_core::mvmd_iface::ControlKey,
        action: &str,
    ) -> DecisionRecord {
        let role = match key.role {
            mvm_core::mvmd_iface::ControlKeyRole::Promoter => Some(DecisionActorRole::Promoter),
            mvm_core::mvmd_iface::ControlKeyRole::Inventory => Some(DecisionActorRole::Inventory),
            mvm_core::mvmd_iface::ControlKeyRole::Orchestrator => {
                Some(DecisionActorRole::Orchestrator)
            }
        };
        DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Approval)
            .actor(ActorRef {
                principal: key.kid.clone(),
                key_id: key.kid.clone(),
                key_role: role,
            })
            .scenario(mvm_contract::provenance::DecisionScenario {
                plan_id: Some(plan.plan_id.0.clone()),
                ..Default::default()
            })
            .reasoning(format!("control key authorized action: {action}"))
            .outcome(DecisionOutcome::Approved)
            .timestamp(Utc::now().to_rfc3339())
            .attestation(AttestationBinding {
                plan_id: Some(plan.plan_id.0.clone()),
                ..AttestationBinding::default()
            })
            .build()
            .expect("control-key decision record is well-formed")
    }

    /// Emit a `decision_record` chain entry and cache the record locally.
    ///
    /// The record's content-address is recomputed from its semantic body
    /// (excluding `attestation`), then the attestation is updated with a
    /// hash of the audit context entry. The final record is serialized into
    /// the chain entry's `record` label and written to the decision store if
    /// enabled.
    pub fn emit_decision_record(
        &self,
        plan: &ExecutionPlan,
        mut record: DecisionRecord,
    ) -> Result<DecisionId> {
        record.decision_id = record.compute_id();

        // Hash a minimal context entry so the decision attests to the audit
        // chain without a circular dependency on the full record label.
        let context_entry = for_plan(
            plan,
            None,
            "decision_record",
            [
                ("decision_id".to_string(), record.decision_id.0.clone()),
                ("category".to_string(), format!("{:?}", record.category)),
            ],
        );
        let context_bytes =
            serde_json::to_vec(&context_entry).context("serializing decision context entry")?;
        record.attestation.audit_entry_hash = hex::encode(hash_line(&context_bytes));
        record.attestation.signer_pubkey = format!(
            "ed25519:{}",
            hex::encode(self.signing_key.verifying_key().to_bytes())
        );

        let record_json = serde_json::to_string(&record).context("serializing decision record")?;
        let entry = for_plan(
            plan,
            None,
            "decision_record",
            [
                ("decision_id".to_string(), record.decision_id.0.clone()),
                ("category".to_string(), format!("{:?}", record.category)),
                ("record".to_string(), record_json),
            ],
        );
        self.emit_entry(&entry)?;

        if self.decisions_enabled
            && let Some(store) = self.decision_store_for_tenant(&plan.tenant.0)
            && let Err(e) = store.put(&record)
        {
            tracing::warn!(
                decision_id = %record.decision_id.0,
                error = %e,
                "failed to cache decision record (non-fatal)"
            );
        }

        Ok(record.decision_id)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixture_plan, only_entry};
    use super::*;
    use crate::audit::audit_file::verify_audit_chain;
    use ed25519_dalek::SigningKey;
    use rand::Rng;

    /// A structured refusal carries the stage, a human-readable reason, and
    /// the host signer as the authorizer principal, so an auditor can answer
    /// "who refused this and why?" from the signed chain alone.
    #[test]
    fn admission_refusal_records_stage_reason_and_authorizer() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-refused");

        emitter
            .emit_refused(&plan, "grant_ceiling", "cpu tier exceeds ceiling")
            .unwrap();

        let entry = only_entry(dir.path(), "local");
        assert_eq!(entry["event"], "plan.admission_refused");
        assert_eq!(entry["labels"]["stage"], "grant_ceiling");
        assert_eq!(entry["labels"]["reason"], "cpu tier exceeds ceiling");
        let principal = entry["labels"]["authorizer_principal"]
            .as_str()
            .expect("authorizer_principal label");
        assert!(
            principal.starts_with("host:"),
            "authorizer must be the host signer: {principal}"
        );
        verify_audit_chain(&dir.path().join("local.jsonl"), &vk).expect("refusal entry verifies");
    }

    /// Control-key use is recorded with the key id and role as the
    /// authorizer principal, so orchestrator decisions are attributable.
    #[test]
    fn control_key_used_records_kid_role_action_and_authorizer() {
        use mvm_core::mvmd_iface::ControlKeyRole;

        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-ctl");
        let control_key = mvm_core::mvmd_iface::ControlKey {
            kid: "ck-prod-1".to_string(),
            role: ControlKeyRole::Orchestrator,
            expiry_unix_secs: u64::MAX,
        };

        emitter
            .emit_control_key_used(&plan, &control_key, "vm.stop")
            .unwrap();

        let entry = only_entry(dir.path(), "local");
        assert_eq!(entry["event"], "control_key.used");
        assert_eq!(entry["labels"]["kid"], "ck-prod-1");
        assert_eq!(entry["labels"]["role"], "Orchestrator");
        assert_eq!(entry["labels"]["action"], "vm.stop");
        assert_eq!(entry["labels"]["authorizer_principal"], "ck-prod-1");
        verify_audit_chain(&dir.path().join("local.jsonl"), &vk)
            .expect("control-key entry verifies");
    }

    /// A control-key decision record carries the plan it decided about.
    ///
    /// Both `plan_id` fields — on the scenario and on the attestation binding —
    /// could be deleted without a single test noticing. A decision record that
    /// does not name its plan is not attributable to anything, which is the
    /// entire purpose of emitting it.
    #[test]
    fn a_control_key_decision_record_names_the_plan_it_decided_about() {
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let key = mvm_core::mvmd_iface::ControlKey {
            kid: "kid-under-test".to_string(),
            role: mvm_core::mvmd_iface::ControlKeyRole::Promoter,
            expiry_unix_secs: 0,
        };

        let record = AuditEmitter::control_key_decision_record(&plan, &key, "promote");

        assert_eq!(
            record.scenario.plan_id.as_deref(),
            Some(plan.plan_id.0.as_str()),
            "the decision scenario must name the plan"
        );
        assert_eq!(
            record.attestation.plan_id.as_deref(),
            Some(plan.plan_id.0.as_str()),
            "the attestation binding must name the plan"
        );
    }

    /// `decisions_enabled` reports the emitter's actual setting.
    ///
    /// Replacing it with a constant `false` survived, which means nothing
    /// observed it returning true — and it is the branch that decides whether a
    /// decision record is built at all. Hardwired false, every control-key
    /// authorization would go unrecorded and every existing test would still
    /// pass.
    #[test]
    fn decisions_enabled_reports_the_configured_setting() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            SigningKey::from_bytes(&seed)
        };
        // `with_dir`, not `new`: `new` resolves the audit dir from the process
        // environment, which other tests in this binary point at their own
        // short-lived homes.
        let emitter =
            AuditEmitter::with_dir(key, &dir.path().join("audit")).expect("construct an emitter");
        // The default has to be observed too, or "always true" would pass.
        assert!(
            !emitter.decisions_enabled(),
            "decisions are off until asked for"
        );

        let emitter = emitter.with_decisions_dir(dir.path());
        assert!(
            emitter.decisions_enabled(),
            "the accessor must report the enabled setting, not a constant"
        );
    }

    #[test]
    fn decision_record_event_is_chain_signed_and_cached() {
        use mvm_contract::provenance::{
            ActorRef, AttestationBinding, DecisionCategory, DecisionOutcome, DecisionRecordBuilder,
        };

        let dir = tempfile::tempdir().unwrap();
        let decisions_dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path())
            .unwrap()
            .with_decisions_dir(decisions_dir.path());
        let plan = fixture_plan("local", "plan-decision");

        let record = DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Admission)
            .actor(ActorRef {
                principal: "host:builder".to_string(),
                key_id: "host-signer-1".to_string(),
                key_role: None,
            })
            .reasoning("grant ceiling satisfied")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-13T00:00:00Z".to_string())
            .attestation(AttestationBinding {
                plan_id: Some("sha256:abc".to_string()),
                audit_entry_hash: String::new(),
                signer_pubkey: hex::encode(vk.to_bytes()),
                ..AttestationBinding::default()
            })
            .build()
            .expect("valid record");

        let id = emitter.emit_decision_record(&plan, record.clone()).unwrap();
        assert!(!id.0.is_empty());

        let entry = only_entry(dir.path(), "local");
        assert_eq!(entry["event"], "decision_record");
        assert_eq!(entry["labels"]["decision_id"], id.0);
        assert!(entry["labels"].get("record").is_some());
        verify_audit_chain(&dir.path().join("local.jsonl"), &vk)
            .expect("decision record entry verifies");

        let decisions = crate::audit::decisions::DecisionStore::open(decisions_dir.path(), "local")
            .unwrap()
            .list()
            .unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].decision_id, id);
    }
}
