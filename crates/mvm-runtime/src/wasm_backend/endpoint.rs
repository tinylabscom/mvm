//! Decide and spawn the per-run host-mediated Wasm egress endpoint.

use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_core::vm_backend::VmStartConfig;

/// Owned inputs for a wasm run's per-VM substitution-endpoint spawn, decided
/// once by [`wasm_endpoint_plan`] so the skip/spawn branch is unit-testable
/// without touching a subprocess. Kept separate from
/// `crate::network_endpoint_spawn::SubstitutionSpawnParams` (which borrows) so
/// the decided values can be asserted directly in a test.
struct WasmEndpointPlan {
    vm_name: String,
    state_dir: PathBuf,
    tenant: String,
    audit: mvm_core::audit_sink::AuditContext,
    secrets: Vec<mvm_core::plan::SecretBinding>,
    redaction: mvm_core::policy::RedactionPolicy,
    network_limits: mvm_core::plan::NetworkLimits,
    socket_path: PathBuf,
}

/// Decide whether a wasm run needs the per-VM substitution endpoint, and if
/// so, the owned inputs the spawn needs. Mirrors libkrun's
/// `spawn_libkrun_egress_endpoint_if_needed` skip logic exactly: nothing to
/// mediate — no bound secrets and the resolved policy denies egress — is a
/// no-op, returning `None`. `start()` then leaves the `mvm:egress`
/// host-import unconfigured, so every egress call fails closed with
/// `NoEndpointConfigured` (correct: no policy/secrets ⇒ no egress).
fn wasm_endpoint_plan(
    config: &VmStartConfig,
    state_dir: &std::path::Path,
) -> Result<Option<WasmEndpointPlan>> {
    let default_redaction = mvm_core::policy::RedactionPolicy::default();
    let decoded = mvm_vmm::host::egress_shared::decode_plan_secrets_from_state(state_dir)?;
    let (secrets, redaction, tenant) = match decoded {
        Some((secrets, redaction, tenant)) => (secrets, redaction, tenant),
        None => (
            Vec::new(),
            default_redaction,
            match config.tenant_id.as_deref() {
                Some(t) if !t.is_empty() => t.to_string(),
                _ => "local".to_string(),
            },
        ),
    };
    if secrets.is_empty() && !config.network_policy.allows_egress() {
        return Ok(None);
    }
    let network_limits = config
        .plan_json
        .as_deref()
        .map(mvm_core::plan::plan_from_admitted_json)
        .transpose()
        .context("parse admitted plan network limits")?
        .map(|plan| plan.effective_network_limits())
        .transpose()
        .context("validate admitted plan network limits")?
        .unwrap_or_default();
    Ok(Some(WasmEndpointPlan {
        vm_name: config.name.clone(),
        state_dir: state_dir.to_path_buf(),
        tenant,
        audit: config
            .audit_context
            .clone()
            .filter(|audit| audit.plan().is_some())
            .context("wasm endpoint has no admitted workload audit context")?,
        secrets,
        redaction,
        network_limits,
        socket_path: mvm_core::config::vm_network_endpoint_socket(&config.name),
    }))
}

/// Build the [`crate::network_endpoint_spawn::SubstitutionSpawnParams`] a wasm run's
/// endpoint spawn needs from a decided [`WasmEndpointPlan`]. Pure (no I/O)
/// so the wasm-specific literal fields are unit-testable without a spawn:
/// always `Uds` (the host-import connects to the endpoint directly — wasm has
/// no VMM to proxy a per-port vsock socket), no TLS intermediate (http-only
/// POC; HTTPS termination
/// is a later phase), and — unlike libkrun/hvf, which serve raw pass-through
/// when a run carries no secrets — the wasm tier mints no FlowMux identity:
/// the `mvm:egress` host-import always speaks the `WireRequest` wire
/// protocol, never a raw byte relay.
fn wasm_network_endpoint_spawn_params<'a>(
    plan: &'a WasmEndpointPlan,
    network_policy: &'a mvm_core::network_policy::NetworkPolicy,
) -> crate::network_endpoint_spawn::SubstitutionSpawnParams<'a> {
    crate::network_endpoint_spawn::SubstitutionSpawnParams {
        // Builder-VM and wasm endpoints never collect telemetry.
        telemetry: false,
        vm_name: &plan.vm_name,
        state_dir: &plan.state_dir,
        // The wasm guest runs inside this process.
        lifetime: crate::network_endpoint_spawn::EndpointLifetime::Launcher,
        tenant: &plan.tenant,
        audit: plan.audit.clone(),
        secrets: &plan.secrets,
        redaction: &plan.redaction,
        transport: crate::network_endpoint_spawn::EndpointTransport::Uds {
            path: plan.socket_path.clone(),
        },
        egress_proxy: None,
        tls_intermediate: None,
        network_policy: Some(network_policy),
        network_limits: plan.network_limits,
        ingress: &[],
        resolver_remote: None,
        binding_store_dir: None,
        flowmux_identity: None,
        session_marker: None,
    }
}

/// Spawn the per-VM substitution endpoint for a wasm run — mirroring
/// libkrun's `spawn_libkrun_egress_endpoint_if_needed` — and return the UDS
/// path to wire into the `mvm:egress` host-import. `None` when
/// [`wasm_endpoint_plan`] finds nothing to mediate; the caller then leaves
/// the host-import unconfigured rather than spawning a needless endpoint.
/// Creating `state_dir` is deferred to this Some-branch so a run that spawns
/// nothing touches no filesystem state.
pub(super) fn spawn_if_needed(
    config: &VmStartConfig,
    state_dir: &std::path::Path,
) -> Result<Option<PathBuf>> {
    let Some(plan) = wasm_endpoint_plan(config, state_dir)? else {
        return Ok(None);
    };
    std::fs::create_dir_all(state_dir)
        .map_err(|e| anyhow::anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;
    let params = wasm_network_endpoint_spawn_params(&plan, &config.network_policy);
    crate::network_endpoint_spawn::spawn_network_endpoint(params)?;
    Ok(Some(plan.socket_path))
}

#[cfg(test)]
mod tests;
