//! Operator containment of one workload: quarantine it, then replace it under a
//! fresh execution epoch, each recorded in the chain-signed audit log.
//!
//! The ledger change is a commit to the policy coordinator, the ledger's only
//! writer; this module never writes it itself.
//!
//! The two actions order their side effects differently on purpose.
//! Quarantine commits the ledger first and audits second, so a broken audit
//! sink can never leave a suspect workload free to relaunch. Replace audits
//! first and commits the ledger second, so authority is never granted without
//! a record of it. Stopping the running VM is the caller's job (the existing
//! `machine stop` path); this module owns the authority and the evidence.

use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::workload::{WorkloadChange, WorkloadCommit, WorkloadLedger};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;
use crate::policy_generation::{coordinator, workload_store::OwnedWorkloadStore};
use crate::supervisor::audit::signer::PlanAuditEntry;

/// Where ledger reads come from and where changes are committed.
pub trait WorkloadAuthority {
    fn ledger(&self) -> Result<WorkloadLedger>;
    fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit>;
}

impl<T: WorkloadAuthority + ?Sized> WorkloadAuthority for &T {
    fn ledger(&self) -> Result<WorkloadLedger> {
        (**self).ledger()
    }

    fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit> {
        (**self).commit(change)
    }
}

impl WorkloadAuthority for OwnedWorkloadStore {
    fn ledger(&self) -> Result<WorkloadLedger> {
        Ok(WorkloadLedger::load_at(self.home())?)
    }

    fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit> {
        OwnedWorkloadStore::commit(self, change)
    }
}

/// The resident policy coordinator listening on `socket`.
pub struct CoordinatorWorkloads {
    socket: PathBuf,
}

impl CoordinatorWorkloads {
    #[must_use]
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }
}

impl WorkloadAuthority for CoordinatorWorkloads {
    fn ledger(&self) -> Result<WorkloadLedger> {
        Ok(WorkloadLedger::load_at(std::path::Path::new(
            &mvm_core::config::mvm_home(),
        ))?)
    }

    fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit> {
        coordinator::commit_workload(&self.socket, change)
    }
}

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
    authority: &dyn WorkloadAuthority,
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    reason: &str,
) -> Result<()> {
    quarantine_with(
        authority,
        emitter,
        Some(plan),
        &plan.tenant.0,
        &plan.workload.0,
        reason,
    )
}

/// Authorize a replacement of `plan`'s workload under a strictly newer epoch.
pub fn replace_workload(
    authority: &dyn WorkloadAuthority,
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
) -> Result<ExecutionEpoch> {
    replace_with(
        authority,
        emitter,
        Some(plan),
        &plan.tenant.0,
        &plan.workload.0,
    )
}

/// Quarantine by workload name. The ledger and the audit log are the whole
/// authority; a stopped machine's plan is not needed.
pub fn quarantine_named(
    authority: &dyn WorkloadAuthority,
    emitter: &AuditEmitter,
    tenant: &str,
    workload: &str,
    reason: &str,
) -> Result<()> {
    quarantine_with(authority, emitter, None, tenant, workload, reason)
}

fn quarantine_with(
    authority: &dyn WorkloadAuthority,
    emitter: &AuditEmitter,
    plan: Option<&ExecutionPlan>,
    tenant: &str,
    workload: &str,
    reason: &str,
) -> Result<()> {
    let commit = authority
        .commit(&WorkloadChange::Quarantine {
            workload: workload.to_owned(),
        })
        .context("committing the workload ledger")?;
    emit_operator_event(
        emitter,
        plan,
        tenant,
        "workload.quarantined",
        [
            ("workload".to_string(), workload.to_owned()),
            ("epoch".to_string(), commit.entry.epoch.get().to_string()),
            ("reason".to_string(), bounded(reason)),
        ],
    )
}

/// Replace by workload name. Every call advances the epoch again: each one is
/// an audited authorization, and the previous epoch is already dead.
pub fn replace_named(
    authority: &dyn WorkloadAuthority,
    emitter: &AuditEmitter,
    tenant: &str,
    workload: &str,
) -> Result<ExecutionEpoch> {
    replace_with(authority, emitter, None, tenant, workload)
}

fn replace_with(
    authority: &dyn WorkloadAuthority,
    emitter: &AuditEmitter,
    plan: Option<&ExecutionPlan>,
    tenant: &str,
    workload: &str,
) -> Result<ExecutionEpoch> {
    let previous = authority.ledger()?.entry(workload).epoch;
    let next = previous.saturating_next();
    emit_operator_event(
        emitter,
        plan,
        tenant,
        "workload.replaced",
        [
            ("workload".to_string(), workload.to_owned()),
            ("previous_epoch".to_string(), previous.get().to_string()),
            ("epoch".to_string(), next.get().to_string()),
        ],
    )?;
    let commit = authority
        .commit(&WorkloadChange::Replace {
            workload: workload.to_owned(),
            from_epoch: previous,
        })
        .context("committing the workload ledger")?;
    debug_assert_eq!(commit.entry.epoch, next);
    Ok(commit.entry.epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::verify_audit_chain;
    use ed25519_dalek::SigningKey;
    use std::path::Path;

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

        let store = OwnedWorkloadStore::open(home.path()).unwrap();
        quarantine_workload(&store, &emitter, &p, "planted compromise").unwrap();
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_err());
        assert!(ledger.authorize_local_start("bystander").is_ok());

        let fresh = replace_workload(&store, &emitter, &p).unwrap();
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_ok());
        assert!(
            ledger
                .authorize("suspect", ExecutionEpoch::new(1).unwrap())
                .is_err()
        );
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
        let store = OwnedWorkloadStore::open(home.path()).unwrap();
        quarantine_workload(&store, &emitter, &old, "compromise").unwrap();
        emitter
            .emit_refused(&old, "host_interface", "workload suspect is quarantined")
            .unwrap();
        replace_workload(&store, &emitter, &old).unwrap();
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
        let store = OwnedWorkloadStore::open(home.path()).unwrap();
        let emitter =
            AuditEmitter::with_dir(SigningKey::from_bytes(&[9; 32]), audit.path()).unwrap();
        assert!(replace_workload(&store, &emitter, &plan()).is_err());
        assert!(
            !audit.path().join("local.jsonl").exists(),
            "nothing audited as granted"
        );
    }

    /// An emitter whose chain directory is gone and replaced by a file, so
    /// every later append fails.
    fn broken_emitter(audit: &Path) -> AuditEmitter {
        let dir = audit.join("chain");
        let emitter = AuditEmitter::with_dir(SigningKey::from_bytes(&[9; 32]), &dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, b"not a directory").unwrap();
        emitter
    }

    #[test]
    fn an_audit_failure_after_quarantine_leaves_the_workload_quarantined() {
        let (home, audit) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let store = OwnedWorkloadStore::open(home.path()).unwrap();
        let emitter = broken_emitter(audit.path());
        assert!(quarantine_workload(&store, &emitter, &plan(), "x").is_err());
        assert!(
            WorkloadLedger::load_at(home.path())
                .unwrap()
                .authorize_local_start("suspect")
                .is_err()
        );
    }

    #[test]
    fn an_audit_failure_in_replace_grants_no_epoch_and_commits_nothing() {
        let (home, audit) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let store = OwnedWorkloadStore::open(home.path()).unwrap();
        let good = AuditEmitter::with_dir(SigningKey::from_bytes(&[9; 32]), audit.path()).unwrap();
        quarantine_workload(&store, &good, &plan(), "x").unwrap();
        let before = mvm_core::host_interface::workload::read_ledger_bytes_at(home.path())
            .unwrap()
            .unwrap();

        let emitter = broken_emitter(audit.path());
        assert!(replace_workload(&store, &emitter, &plan()).is_err());
        assert_eq!(
            mvm_core::host_interface::workload::read_ledger_bytes_at(home.path())
                .unwrap()
                .unwrap(),
            before
        );
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert_eq!(
            ledger.entry("suspect").epoch,
            ExecutionEpoch::new(1).unwrap()
        );
        assert!(ledger.entry("suspect").quarantined);
    }
}
