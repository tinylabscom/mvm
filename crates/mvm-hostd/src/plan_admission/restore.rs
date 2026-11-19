//! One-use admitted dispatch for a full-VM checkpoint child.
//!
//! A restore resumes a retained runtime, not a fresh kernel boot. The
//! checkpoint layer owns lineage/content verification and the backend's
//! paused-load/no-NIC/resume sequence; this boundary binds that operation to
//! the child's *new* signed admission before it can execute.

use anyhow::{Context, Result, ensure};
use mvm_runtime::checkpoint::{
    CheckpointChainAnchor, CheckpointStore, ForkParams, ForkRestore, VerifiedRetainedRuntime,
};

use super::AdmittedPlan;

/// Spend the child's admitted authority on exactly one authenticated restore.
///
/// The serialized envelope and tenant sent to the checkpoint layer are
/// projections of `admitted`, never authority supplied by the caller. On
/// failure the admission remains spent once restore was attempted; the caller
/// retains it only to record the source-specific failed audit and rollback.
pub fn dispatch_vm_full_fork(
    admitted: &mut AdmittedPlan,
    store: &CheckpointStore,
    mut params: ForkParams,
    restore: &ForkRestore<'_>,
    anchor: &dyn CheckpointChainAnchor,
    runtime: &VerifiedRetainedRuntime,
    stop_child: &dyn Fn(&str) -> Result<()>,
) -> Result<mvm_core::checkpoint::CheckpointMeta> {
    // The parent record alone is not the lineage: authenticate every ancestor
    // before the lower transaction binds the same parent object to the child.
    mvm_runtime::checkpoint::verify_lineage(store, &params.checkpoint, anchor)
        .context("authenticating the fork parent lineage before dispatch")?;
    let admitted_image = admitted.plan().image.sha256.clone();
    bind_fork_dispatch(admitted, &mut params, runtime.identity())?;
    // The lower checkpoint transaction re-verifies the parent against the
    // signed chain, its retained runtime, and the child's own image/grant
    // bounds before calling the backend-specific restorer.
    mvm_runtime::checkpoint::fork_vm_full_verified_with_rollback(
        store,
        params,
        restore,
        anchor,
        runtime,
        &admitted_image,
        stop_child,
    )
}

fn bind_fork_dispatch(
    admitted: &mut AdmittedPlan,
    params: &mut ForkParams,
    runtime_identity: Option<&mvm_core::plan::RuntimeIdentity>,
) -> Result<()> {
    ensure!(
        !admitted.dispatched,
        "original admitted plan was already dispatched"
    );
    ensure!(
        admitted.plan().workload.0 == params.child_vm_name,
        "admitted child plan names a different VM"
    );
    match (admitted.plan().runtime_identity.as_ref(), runtime_identity) {
        (Some(_), Some(identity)) => admitted
            .plan()
            .require_runtime_identity(identity)
            .context("retained fork runtime differs from the admitted child")?,
        (None, None) => {}
        _ => anyhow::bail!("admitted child and retained fork runtime disagree on runtime identity"),
    }
    params.child_plan_json = Some(
        serde_json::to_string(admitted.signed())
            .context("serializing the admitted fork child envelope")?,
    );
    params.child_tenant_id = Some(admitted.plan().tenant.0.clone());
    // Spend the plan before any snapshot cloning, including a failed or
    // uncertain restore. There is no permission to retry with the same plan.
    admitted.dispatched = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted_child() -> AdmittedPlan {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.workload.0 = "fork-child".into();
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let signer = "host:test".to_string();
        let signed = mvm_core::plan::sign_plan(
            &plan,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            &signer,
        );
        AdmittedPlan::for_test(plan, signer, signed)
    }

    fn params(name: &str) -> ForkParams {
        ForkParams {
            checkpoint: mvm_core::checkpoint::CheckpointId::new("parent"),
            child_id: mvm_core::checkpoint::CheckpointId::new("child"),
            child_vm_name: name.into(),
            dest_dir: std::path::PathBuf::new(),
            created_unix: 1,
            parent_liveness: mvm_runtime::checkpoint::ForkParentLiveness::MayBeRunning,
            // Caller projections must never become the dispatch authority.
            child_plan_json: Some("untrusted".into()),
            child_tenant_id: Some("other-tenant".into()),
        }
    }

    #[test]
    fn fork_dispatch_projects_its_own_plan_and_spends_it_once() {
        let mut admitted = admitted_child();
        let mut launch = params("fork-child");
        bind_fork_dispatch(&mut admitted, &mut launch, None).unwrap();
        let projected = mvm_core::plan::plan_from_admitted_json(
            launch.child_plan_json.as_deref().expect("signed envelope"),
        )
        .unwrap();
        assert_eq!(projected.plan_id, admitted.plan_id().clone());
        assert_eq!(
            launch.child_tenant_id.as_deref(),
            Some(admitted.plan().tenant.0.as_str())
        );
        let error = bind_fork_dispatch(&mut admitted, &mut launch, None).unwrap_err();
        assert!(
            error.to_string().contains("already dispatched"),
            "{error:#}"
        );
    }

    #[test]
    fn fork_dispatch_refuses_a_different_child_before_spending_plan() {
        let mut admitted = admitted_child();
        let mut wrong = params("other-child");
        let error = bind_fork_dispatch(&mut admitted, &mut wrong, None).unwrap_err();
        assert!(error.to_string().contains("different VM"), "{error:#}");
        let mut correct = params("fork-child");
        bind_fork_dispatch(&mut admitted, &mut correct, None).unwrap();
    }
}
