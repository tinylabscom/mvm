//! Operator containment of one workload: quarantine it, then replace it under a
//! fresh execution epoch, each recorded in the chain-signed audit log.
//!
//! The two actions order their side effects differently on purpose.
//! Quarantine changes the ledger first and audits second, so a broken audit
//! sink can never leave a suspect workload free to relaunch. Replace audits
//! first and changes the ledger second, so authority is never granted without
//! a record of it. Stopping the running VM is the caller's job (the existing
//! `machine stop` path); this module owns the authority and the evidence.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_core::host_interface::{ExecutionEpoch, workload::WorkloadLedger};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;
use crate::supervisor::audit::PlanAuditEntry;

/// Emit an operator event about a workload, bound to `plan` when one is at
/// hand and otherwise to the workload's own labels alone (no plan or image).
fn emit_operator_event(
    emitter: &AuditEmitter,
    plan: Option<&ExecutionPlan>,
    tenant: &str,
    event: &str,
    extras: impl IntoIterator<Item = (String, String)>,
) -> Result<()> {
    if let Some(plan) = plan {
        return emitter.emit(plan, event, extras);
    }
    emitter.emit_entry(&PlanAuditEntry {
        timestamp: chrono::Utc::now(),
        tenant: mvm_core::plan::TenantId(tenant.to_owned()),
        plan_id: mvm_core::plan::PlanId(String::new()),
        plan_version: 0,
        bundle_id: None,
        bundle_version: None,
        image_name: String::new(),
        image_sha256: String::new(),
        event: event.to_owned(),
        caller_commitment: None,
        labels: extras.into_iter().collect(),
    })
}

/// Longest operator reason recorded in the chain.
const MAX_REASON_BYTES: usize = 256;

fn bounded(reason: &str) -> String {
    reason.chars().take(MAX_REASON_BYTES).collect()
}

/// Refuse further launches of `plan`'s workload and record why.
pub fn quarantine_workload(
    home: &Path,
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    reason: &str,
) -> Result<()> {
    quarantine_with(
        home,
        emitter,
        Some(plan),
        &plan.tenant.0,
        &plan.workload.0,
        reason,
    )
}

/// Authorize a replacement of `plan`'s workload under a strictly newer epoch.
pub fn replace_workload(
    home: &Path,
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
) -> Result<ExecutionEpoch> {
    replace_with(home, emitter, Some(plan), &plan.tenant.0, &plan.workload.0)
}

/// Quarantine by workload name. The ledger and the audit log are the whole
/// authority; a stopped machine's plan is not needed.
pub fn quarantine_named(
    home: &Path,
    emitter: &AuditEmitter,
    tenant: &str,
    workload: &str,
    reason: &str,
) -> Result<()> {
    quarantine_with(home, emitter, None, tenant, workload, reason)
}

fn quarantine_with(
    home: &Path,
    emitter: &AuditEmitter,
    plan: Option<&ExecutionPlan>,
    tenant: &str,
    workload: &str,
    reason: &str,
) -> Result<()> {
    let mut ledger = WorkloadLedger::load_at(home)?;
    ledger.quarantine(workload);
    ledger.save_at(home).context("saving the workload ledger")?;
    emit_operator_event(
        emitter,
        plan,
        tenant,
        "workload.quarantined",
        [
            ("workload".to_string(), workload.to_owned()),
            (
                "epoch".to_string(),
                ledger.entry(workload).epoch.0.to_string(),
            ),
            ("reason".to_string(), bounded(reason)),
        ],
    )
}

/// Replace by workload name. Every call advances the epoch again: each one is
/// an audited authorization, and the previous epoch is already dead.
pub fn replace_named(
    home: &Path,
    emitter: &AuditEmitter,
    tenant: &str,
    workload: &str,
) -> Result<ExecutionEpoch> {
    replace_with(home, emitter, None, tenant, workload)
}

fn replace_with(
    home: &Path,
    emitter: &AuditEmitter,
    plan: Option<&ExecutionPlan>,
    tenant: &str,
    workload: &str,
) -> Result<ExecutionEpoch> {
    let mut ledger = WorkloadLedger::load_at(home)?;
    let previous = ledger.entry(workload).epoch;
    let next = previous.next();
    emit_operator_event(
        emitter,
        plan,
        tenant,
        "workload.replaced",
        [
            ("workload".to_string(), workload.to_owned()),
            ("previous_epoch".to_string(), previous.0.to_string()),
            ("epoch".to_string(), next.0.to_string()),
        ],
    )?;
    let granted = ledger.replace(workload);
    debug_assert_eq!(granted, next);
    ledger.save_at(home).context("saving the workload ledger")?;
    Ok(granted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::verify_audit_chain;
    use ed25519_dalek::SigningKey;

    fn plan() -> ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("suspect")
            .build()
    }

    fn entries(audit: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(audit.join("local.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["entry"].clone())
            .collect()
    }

    #[test]
    fn quarantine_then_replace_is_enforced_and_chain_signed() {
        let (home, audit) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let key = SigningKey::from_bytes(&[9; 32]);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, audit.path()).unwrap();
        let p = plan();

        quarantine_workload(home.path(), &emitter, &p, "planted compromise").unwrap();
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_err());
        assert!(ledger.authorize_local_start("bystander").is_ok());

        let fresh = replace_workload(home.path(), &emitter, &p).unwrap();
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_ok());
        assert!(ledger.authorize("suspect", ExecutionEpoch(1)).is_err());
        assert!(ledger.authorize("suspect", fresh).is_ok());

        let e = entries(audit.path());
        assert_eq!(e[0]["event"], "workload.quarantined");
        assert_eq!(e[0]["labels"]["reason"], "planted compromise");
        assert_eq!(e[1]["event"], "workload.replaced");
        assert_eq!(e[1]["labels"]["previous_epoch"], "1");
        assert_eq!(e[1]["labels"]["epoch"], "2");
        verify_audit_chain(&audit.path().join("local.jsonl"), &vk).expect("chain verifies");
    }

    #[test]
    fn the_timeline_follows_a_workload_across_a_replacement() {
        use crate::audit::session::{EventFilter, workload_events};
        let (home, audit) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let emitter =
            AuditEmitter::with_dir(SigningKey::from_bytes(&[9; 32]), audit.path()).unwrap();
        let old = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-old")
            .workload("suspect")
            .build();
        let new = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-new")
            .workload("suspect")
            .build();
        let other = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-other")
            .workload("bystander")
            .build();
        emitter.emit_admitted(&old, "host:test").unwrap();
        emitter.emit_admitted(&other, "host:test").unwrap();
        quarantine_workload(home.path(), &emitter, &old, "compromise").unwrap();
        emitter
            .emit_refused(&old, "host_interface", "workload suspect is quarantined")
            .unwrap();
        replace_workload(home.path(), &emitter, &old).unwrap();
        emitter.emit_admitted(&new, "host:test").unwrap();
        emitter.emit_launched(&new, "firecracker").unwrap();

        let lines: Vec<String> = std::fs::read_to_string(audit.path().join("local.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let events = workload_events(&lines, "suspect", &EventFilter::default()).unwrap();
        let names: Vec<_> = events
            .iter()
            .map(|e| e.envelope.entry.event.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "plan.admitted",
                "workload.quarantined",
                "plan.admission_refused",
                "workload.replaced",
                "plan.admitted",
                "plan.launched",
            ],
            "launch, containment, denial and replacement in chain order; the bystander is absent"
        );
        let plans: std::collections::BTreeSet<_> = events
            .iter()
            .map(|e| e.envelope.entry.plan_id.as_str())
            .collect();
        assert_eq!(plans.len(), 2, "the history spans the old and the new plan");
    }

    #[test]
    fn the_timeline_includes_unlabelled_events_on_the_workloads_own_plans_only() {
        use crate::audit::session::{EventFilter, workload_events};
        let audit = tempfile::tempdir().unwrap();
        let emitter =
            AuditEmitter::with_dir(SigningKey::from_bytes(&[9; 32]), audit.path()).unwrap();
        let mine = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-mine")
            .workload("suspect")
            .build();
        let theirs = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-theirs")
            .workload("bystander")
            .build();
        emitter.emit_admitted(&mine, "host:test").unwrap();
        // Carries no workload label, like a flow or exit event on the same plan.
        emitter.emit_verb_denied(&mine, "exec").unwrap();
        emitter.emit_admitted(&theirs, "host:test").unwrap();
        emitter.emit_verb_denied(&theirs, "exec").unwrap();

        let lines: Vec<String> = std::fs::read_to_string(audit.path().join("local.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let names: Vec<_> = workload_events(&lines, "suspect", &EventFilter::default())
            .unwrap()
            .into_iter()
            .map(|e| (e.envelope.entry.plan_id, e.envelope.entry.event))
            .collect();
        assert_eq!(
            names,
            [
                ("plan-mine".to_string(), "plan.admitted".to_string()),
                ("plan-mine".to_string(), "verb_denied".to_string()),
            ],
            "the same-plan event comes along; the other workload's plan does not"
        );
    }

    #[test]
    fn a_long_reason_is_bounded() {
        assert_eq!(bounded(&"x".repeat(10_000)).len(), MAX_REASON_BYTES);
    }

    #[test]
    fn replace_does_not_grant_authority_when_the_ledger_is_unreadable() {
        let (home, audit) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        std::fs::create_dir_all(home.path().join("host-interface")).unwrap();
        std::fs::write(home.path().join("host-interface/workloads.json"), b"[").unwrap();
        let emitter =
            AuditEmitter::with_dir(SigningKey::from_bytes(&[9; 32]), audit.path()).unwrap();
        assert!(replace_workload(home.path(), &emitter, &plan()).is_err());
        assert!(
            !audit.path().join("local.jsonl").exists(),
            "nothing audited as granted"
        );
    }
}
