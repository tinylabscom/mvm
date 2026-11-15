#![cfg(test)]

use super::start::launch_decision_record;
use mvm_contract::provenance::DecisionCategory;

/// The launch decision record names the plan it launched — in the
/// scenario it describes and in the attestation it binds to.
///
/// Deleting either `plan_id` leaves a record that says a workload was
/// launched but not which signed plan authorized it, and the scenario's
/// `plan_id` is part of the record's content address, so dropping it also
/// re-addresses the decision. Both deletions survived mutation because
/// nothing read the fields back.
#[test]
fn a_launch_decision_record_binds_the_plan_it_launched() {
    let plan = mvm_core::plan::test_support::PlanFixture::new()
        .plan_id("plan-under-launch")
        .build();

    let record = launch_decision_record(&plan, "firecracker");

    assert_eq!(record.category, DecisionCategory::Launch);
    assert_eq!(
        record.scenario.plan_id.as_deref(),
        Some("plan-under-launch"),
        "the scenario must name the launched plan"
    );
    assert_eq!(
        record.attestation.plan_id.as_deref(),
        Some("plan-under-launch"),
        "the attestation binding must name the launched plan"
    );
}
