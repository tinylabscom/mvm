use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

/// Run the host-interface preflight for this plan through the local adapter.
///
/// Local state is read from `<mvm_home>/host-interface/`; with no files there
/// the node is `Active` under a permissive policy, so a plain local run is
/// unchanged. A revoked or quarantined node, an expired or out-of-scope
/// policy, an image outside a pinned list, an invalid volume grant or a
/// required attestation the node cannot meet refuses the boot. Resources are
/// covered by the durable host-budget reservation and enforcement by the runtime
/// verification in `RunPosture`, both of which run just before this.
pub(super) fn admit_host_interface(plan: &ExecutionPlan) -> Result<()> {
    use anyhow::Context;
    use mvm_contract::protocol::mailbox::ExecutionEpoch;
    use mvm_core::host_interface::{
        Assurance, HostInterface, LaunchRequest, local::LocalHostInterface, store,
    };
    let home = std::path::PathBuf::from(mvm_core::config::mvm_home());
    let record = store::load_node_record_at(&home)?;
    let policy = store::load_policy_at(&home)?;
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    };
    // Software evidence only: this adapter collects no hardware attestation.
    let host = LocalHostInterface::new(&record.node_id, policy, Assurance::Software, now)
        .with_record(record.state, record.epoch);
    // Per-workload containment: a quarantined workload, or a plan carrying an
    // epoch other than the workload's current one (a stale plan from before a
    // replacement), is refused while every other workload keeps launching. A
    // local launch synthesizes its plan at the current epoch; a plan arriving
    // from a control plane carries the epoch that authority issued.
    let epoch = ExecutionEpoch::new(plan.execution_epoch)
        .context("the plan carries a zero execution epoch")?;
    mvm_core::host_interface::workload::WorkloadLedger::load_at(&home)?
        .authorize(&plan.workload.0, epoch)
        .map_err(mvm_core::host_interface::HostInterfaceError::from)?;
    host.authorize_workload(&LaunchRequest {
        workload_id: plan.workload.0.clone(),
        image_digest: plan.image.sha256.clone(),
        epoch: record.epoch,
    })?;
    mvm_core::launch_trace::lap("admit_plan.grants_budget_and_host_interface");
    Ok(())
}
