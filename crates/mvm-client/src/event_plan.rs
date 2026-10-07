//! The audit envelope a host-side chain entry binds to when the event is not a
//! workload admission: an image-lineage marker, a reviewed workspace mutation.

use anyhow::{Context, Result};
use mvm_core::plan::{ExecutionPlan, SynthesisInput, synthesize_plan};

/// Synthesize the audit-envelope plan a host-side chain entry binds to: the
/// image-lineage markers (`image.created` / `image.reverted`) and the workspace
/// mutations (`workspace.snapshot`, `workspace.applied`, …). Such an event is
/// not a workload admission, so this plan is only the tenant / plan-id / image
/// binding the chain entry carries — it is never signed, admitted, or booted.
/// Tenant is the local host tenant (`DEFAULT_TENANT`); `workload` / `intent`
/// label the operation. `image_sha256` must be a 64-char lowercase hex digest.
pub fn build_event_plan(
    workload: &str,
    intent: &str,
    image_name: &str,
    image_sha256: &str,
) -> Result<ExecutionPlan> {
    let input = SynthesisInput {
        outputs: Vec::new(),
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        network_mode: Default::default(),
        ingress: Vec::new(),
        vm_name: workload,
        tenant: None,
        backend_name: workload,
        image_name,
        image_sha256,
        image_cosign_bundle: None,
        intent: Some(intent),
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: mvm_core::plan::SecretReleasePolicy::None,
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: 1,
        mem_mib: 64,
        disk_mib: 0,
        boot_timeout_secs: 1,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        assets: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        tools: Default::default(),
        caller_commitment: None,
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    };
    synthesize_plan(&input).context("synthesizing the image-lineage audit-envelope plan")
}
