use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

/// Run the host-interface preflight for this plan through the local adapter.
///
/// Local state is read from `<mvm_home>/host-interface/`; with no files there
/// the node is `Active` under a permissive policy, so a plain local run is
/// unchanged. A revoked or quarantined node, an expired or out-of-scope
/// policy, an image outside a pinned list, an invalid volume grant or a
/// required attestation the node cannot meet refuses the boot. Enforcement is
/// covered by the runtime verification in `RunPosture`, which runs just before
/// this. Resources and secrets are not checked here: the durable host-budget
/// reservation (`reserve_plan_budget`, `verify_plan_resources`) and the grant
/// ceiling (`admit_grants`) bound resources on this same admission path, and
/// secrets are refused before signing when missing or unbound
/// (`bind_approval` for host-signed plans, the bundle's required secret slots
/// for bundle-pinned plans).
pub(super) fn admit_host_interface(plan: &ExecutionPlan) -> Result<()> {
    use mvm_core::host_interface::{
        Assurance, HostInterface, LaunchRequest, local::LocalHostInterface, store,
    };
    let home = mvm_home_path();
    let record = store::load_node_record_at(&home)?;
    let policy = store::load_policy_at(&home)?;
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    };
    // Per-unit containment: a quarantined workload, or a plan carrying an
    // epoch other than the workload's current one (a stale plan from before a
    // replacement, or a standby's epoch not yet promoted), is refused while
    // every other workload keeps launching. A local launch synthesizes its
    // plan at the current epoch; a plan arriving from a control plane carries
    // the epoch that authority issued.
    let (epoch, gate) = load_gate_and_admit(plan, &home)?;
    // Software evidence only: this adapter collects no hardware attestation.
    // The node admission check compares the plan's epoch with the unit's
    // durable record, never with a value derived from the request itself.
    let host = LocalHostInterface::new(&record.node_id, policy, Assurance::Software, now)
        .with_record(record.state, gate.current(&plan.workload.0));
    host.authorize_workload(&LaunchRequest {
        workload_id: plan.workload.0.clone(),
        image_digest: plan.image.sha256.clone(),
        epoch,
    })?;
    mvm_core::launch_trace::lap("admit_plan.grants_budget_and_host_interface");
    Ok(())
}

pub(super) fn mvm_home_path() -> std::path::PathBuf {
    std::path::PathBuf::from(mvm_core::config::mvm_home())
}

/// Read the workload ledger under `home` and admit the plan's workload at its
/// epoch. Shared by the admission preflight and the post-spawn recheck so the
/// two can never disagree on how the epoch is built.
pub(super) fn load_gate_and_admit(
    plan: &ExecutionPlan,
    home: &std::path::Path,
) -> Result<(
    mvm_contract::protocol::mailbox::ExecutionEpoch,
    mvm_core::host_interface::epoch_gate::CommandGate,
)> {
    use anyhow::Context;
    let epoch = mvm_contract::protocol::mailbox::ExecutionEpoch::new(plan.execution_epoch)
        .context("the plan carries a zero execution epoch")?;
    let gate = mvm_core::host_interface::epoch_gate::CommandGate::load_at(home)?;
    gate.admit(&plan.workload.0, epoch)
        .map_err(mvm_core::host_interface::HostInterfaceError::from)?;
    Ok((epoch, gate))
}
