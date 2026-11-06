//! Contain one running workload by machine name: quarantine it, then replace
//! it under a fresh execution epoch. The CLI, the host library and the MCP
//! adapter all call these; the authority and audit logic lives in
//! `mvm_hostd::containment`.
//!
//! Quarantine does not stop the VM. The caller stops it through the ordinary
//! stop path, after this has recorded that the workload may not launch again.

use anyhow::{Context, Result};
use mvm_hostd::audit::{emitter::AuditEmitter, host_keypair, plan_persist};

fn home() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_home())
}

fn emitter() -> Result<AuditEmitter> {
    AuditEmitter::new(host_keypair::load_or_init()?.signing)
}

/// Refuse further launches of machine `name` and record `reason`.
pub fn quarantine(name: &str, reason: &str) -> Result<()> {
    let plan = plan_persist::read_plan(name)
        .with_context(|| format!("reading the admitted plan of {name:?}"))?;
    mvm_hostd::containment::quarantine_workload(&home(), &emitter()?, &plan, reason)
}

/// Authorize a replacement of machine `name`; returns the new execution epoch.
pub fn replace(name: &str) -> Result<u64> {
    let plan = plan_persist::read_plan(name)
        .with_context(|| format!("reading the admitted plan of {name:?}"))?;
    mvm_hostd::containment::replace_workload(&home(), &emitter()?, &plan).map(|e| e.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::host_interface::workload::WorkloadLedger;

    #[test]
    fn quarantine_and_replace_by_machine_name_round_trip_through_the_ledger() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .workload("suspect")
            .build();
        plan_persist::write_plan("suspect", &plan).unwrap();

        quarantine("suspect", "planted compromise").unwrap();
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_err());
        assert!(ledger.authorize_local_start("other").is_ok());

        assert_eq!(replace("suspect").unwrap(), 2);
        let ledger = WorkloadLedger::load_at(home.path()).unwrap();
        assert!(ledger.authorize_local_start("suspect").is_ok());
    }

    #[test]
    fn an_unknown_machine_is_an_error_not_a_silent_no_op() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        assert!(quarantine("never-admitted", "x").is_err());
        assert!(replace("never-admitted").is_err());
    }
}
