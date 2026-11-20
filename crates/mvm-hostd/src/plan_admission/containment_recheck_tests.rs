#![cfg(test)]

use super::containment_recheck::still_admitted;
use super::test_support::*;
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::workload::WorkloadChange;

fn plan(name: &str) -> mvm_core::plan::ExecutionPlan {
    mvm_core::plan::test_support::PlanFixture::new()
        .workload(name)
        .build()
}

fn commit(home: &std::path::Path, change: &WorkloadChange) {
    let store = crate::policy_generation::workload_store::OwnedWorkloadStore::open(home).unwrap();
    store.commit(change).unwrap();
}

#[test]
fn a_current_workload_is_still_admitted() {
    let (_env, _home) = host_with_ceiling(Default::default());
    still_admitted(&plan("recheck-current")).unwrap();
}

#[test]
fn a_quarantined_workload_is_refused() {
    let (_env, home) = host_with_ceiling(Default::default());
    let p = plan("recheck-quarantined");
    commit(
        home.path(),
        &WorkloadChange::Quarantine {
            workload: p.workload.0.clone(),
        },
    );
    assert!(still_admitted(&p).is_err());
}

#[test]
fn a_stale_epoch_is_refused() {
    let (_env, home) = host_with_ceiling(Default::default());
    let p = plan("recheck-stale");
    commit(
        home.path(),
        &WorkloadChange::Replace {
            workload: p.workload.0.clone(),
            from_epoch: ExecutionEpoch::new(p.execution_epoch).unwrap(),
        },
    );
    assert!(still_admitted(&p).is_err());
}
