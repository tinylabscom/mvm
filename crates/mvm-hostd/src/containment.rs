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
    let mut ledger = WorkloadLedger::load_at(home)?;
    ledger.quarantine(&plan.workload.0);
    ledger.save_at(home).context("saving the workload ledger")?;
    emitter.emit(
        plan,
        "workload.quarantined",
        [
            ("workload".to_string(), plan.workload.0.clone()),
            (
                "epoch".to_string(),
                ledger.entry(&plan.workload.0).epoch.0.to_string(),
            ),
            ("reason".to_string(), bounded(reason)),
        ],
    )
}

/// Authorize a replacement of `plan`'s workload under a strictly newer epoch.
pub fn replace_workload(
    home: &Path,
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
) -> Result<ExecutionEpoch> {
    let mut ledger = WorkloadLedger::load_at(home)?;
    let previous = ledger.entry(&plan.workload.0).epoch;
    let next = previous.next();
    emitter.emit(
        plan,
        "workload.replaced",
        [
            ("workload".to_string(), plan.workload.0.clone()),
            ("previous_epoch".to_string(), previous.0.to_string()),
            ("epoch".to_string(), next.0.to_string()),
        ],
    )?;
    let granted = ledger.replace(&plan.workload.0);
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
