use super::*;
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::protocol::mailbox::{BootId, ExecutionEpoch};
use mvm_contract::protocol::workload_actor::{
    ActorBindingId, ActorProtocolVersion, ControllerIdentity, DelegationDepth, LifecycleGrant,
    LifecycleOperation, ParentIdentity, TemplateBinding, WorkflowBinding, WorkflowRole,
    capability_descriptor,
};
use std::num::NonZeroU64;

fn controller_plan(operations: Vec<LifecycleOperation>) -> mvm_core::plan::ExecutionPlan {
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.services
        .push(ServiceId::parse("host.actor.v1").unwrap());
    plan.workflow = Some(WorkflowBinding {
        version: ActorProtocolVersion::V1,
        workflow_id: ActorBindingId::new("workflow").unwrap(),
        constraint_snapshot_digest: Sha256Digest::from_bytes(&[1; 32]),
        role: WorkflowRole::Controller {
            grant: LifecycleGrant {
                id: ActorBindingId::new("grant").unwrap(),
                controller: ControllerIdentity {
                    tenant: plan.tenant.clone(),
                    workload: plan.workload.clone(),
                    execution_epoch: ExecutionEpoch::new(plan.execution_epoch).unwrap(),
                    boot_id: BootId::from_bytes([2; 32]),
                    generation: NonZeroU64::new(1).unwrap(),
                },
                depth: DelegationDepth::One,
                templates: vec![TemplateBinding {
                    id: ActorBindingId::new("worker").unwrap(),
                    digest: Sha256Digest::from_bytes(&[3; 32]),
                }],
                operations,
                not_before_unix_ms: 1,
                expires_at_unix_ms: 2,
                workflow_deadline_unix_ms: 3,
            },
        },
    });
    plan
}

#[test]
fn actor_broker_capabilities_are_exactly_the_signed_operation_subset() {
    for (operation, verb) in [
        (LifecycleOperation::Launch, "launch_child"),
        (LifecycleOperation::ObserveChild, "observe_child"),
        (LifecycleOperation::ReleaseChild, "release_child"),
    ] {
        let plan = controller_plan(vec![operation]);
        assert_eq!(
            capabilities_for_plan(&plan).unwrap(),
            vec![capability_descriptor(verb).unwrap().binding()]
        );
    }
}

#[test]
fn direct_worker_and_unbound_controller_have_no_actor_capability() {
    let direct = mvm_core::plan::test_support::PlanFixture::new().build();
    assert!(capabilities_for_plan(&direct).unwrap().is_empty());
    let mut plan = controller_plan(vec![LifecycleOperation::Launch]);
    plan.services.clear();
    assert!(capabilities_for_plan(&plan).unwrap().is_empty());
    plan.services
        .push(ServiceId::parse("host.actor.v1").unwrap());
    let WorkflowRole::Controller { grant } = &plan.workflow.as_ref().unwrap().role else {
        panic!("controller fixture");
    };
    plan.workflow.as_mut().unwrap().role = WorkflowRole::Worker {
        parent: ParentIdentity {
            controller: grant.controller.clone(),
            plan_id: direct.plan_id,
        },
    };
    assert!(capabilities_for_plan(&plan).unwrap().is_empty());
}

#[test]
fn malformed_or_foreign_controller_grants_are_refused() {
    let repeated = controller_plan(vec![LifecycleOperation::Launch, LifecycleOperation::Launch]);
    assert!(capabilities_for_plan(&repeated).is_err());
    let mut foreign = controller_plan(vec![LifecycleOperation::ObserveChild]);
    foreign.execution_epoch += 1;
    assert!(capabilities_for_plan(&foreign).is_err());
}
