//! Launch decision records and assurance-proxy attachment.

use anyhow::Result;
use chrono::Utc;
use mvm_contract::provenance::{
    ActorRef, AttestationBinding, DecisionActorRole, DecisionCategory, DecisionOutcome,
    DecisionRecord, DecisionRecordBuilder,
};
use mvm_core::plan::ExecutionPlan;
use mvm_core::vm_backend::VmStartConfig;

pub(crate) fn launch_decision_record(plan: &ExecutionPlan, backend_name: &str) -> DecisionRecord {
    DecisionRecordBuilder::new()
        .version(1)
        .category(DecisionCategory::Launch)
        .actor(ActorRef {
            principal: crate::audit::host_keypair::host_signer_id(),
            key_id: crate::audit::host_keypair::host_signer_id(),
            key_role: Some(DecisionActorRole::Orchestrator),
        })
        .scenario(mvm_contract::provenance::DecisionScenario {
            plan_id: Some(plan.plan_id.0.clone()),
            ..Default::default()
        })
        .reasoning(format!("workload launched on backend {backend_name}"))
        .outcome(DecisionOutcome::Approved)
        .timestamp(Utc::now().to_rfc3339())
        .attestation(AttestationBinding {
            plan_id: Some(plan.plan_id.0.clone()),
            ..AttestationBinding::default()
        })
        .build()
        .expect("launch decision record is well-formed")
}

pub(crate) fn attach_assurance_proxy(
    config: &mut VmStartConfig,
    proxy: mvm_contract::protocol::broker_control::ServiceProxyBinding,
) -> Result<()> {
    if config
        .service_proxies
        .iter()
        .any(|binding| binding.service == proxy.service)
    {
        anyhow::bail!("assurance controller proxy service is already configured");
    }
    config.service_proxies.push(proxy);
    Ok(())
}
