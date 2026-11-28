//! Bind the real recorder before serving guest decisions.

use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::audit_sink::AuditContext;

use super::network_endpoint::{EgressMode, EndpointConfig, EndpointNetworkProjection};
use crate::supervisor::audit::bound_sink::BoundRecorder;

/// Refuse missing or mismatched audit identity before binding listeners.
pub fn validate(cfg: &EndpointConfig) -> Result<()> {
    require_signed_cleartext(cfg)?;
    if !matches!(cfg.egress_mode, EgressMode::FlowMux) {
        return Ok(());
    }
    let context = cfg
        .audit
        .as_ref()
        .context("FlowMux requires a bound audit identity")?;
    match context {
        // A warm child's physical name need not equal its logical workload.
        AuditContext::Workload { plan } => {
            context.validate_for(&cfg.tenant_id, &plan.workload.0)?;
        }
        AuditContext::Builder { .. } => {
            context.validate_for(&cfg.tenant_id, &cfg.instance_id)?;
        }
    }
    Ok(())
}

/// Refuse a cleartext opt-in the admitted plan did not sign: the endpoint's
/// policy must be the one whose digest admission recorded, so a marker added
/// after admission is refused here rather than honoured by the gate. A policy
/// without an opt-in is not checked, exactly as before.
fn require_signed_cleartext(cfg: &EndpointConfig) -> Result<()> {
    let Some(policy) = cfg.network_policy.as_ref() else {
        return Ok(());
    };
    if policy.cleartext_destinations().is_empty() {
        return Ok(());
    }
    let signed = cfg
        .audit
        .as_ref()
        .and_then(AuditContext::plan)
        .is_some_and(|plan| {
            mvm_runtime::workload_runner::claim::bind_claim_policy_to_plan(
                &plan.asset_identities,
                policy,
            )
            .is_ok()
        });
    anyhow::ensure!(
        signed,
        "the endpoint's cleartext egress opt-in is not the network policy the plan admitted"
    );
    Ok(())
}

/// Establish the bound journal and its required preflight before startup readiness.
pub fn bind(
    cfg: &EndpointConfig,
    network: &EndpointNetworkProjection,
    runtime: &tokio::runtime::Handle,
) -> Result<Arc<BoundRecorder>> {
    validate(cfg)?;
    let context = cfg.audit.as_ref().context("missing bound audit identity")?;
    let recorder = network
        .recorder()
        .context("required audit recorder is unavailable")?;
    let path = BoundRecorder::health_path(&mvm_core::config::mvm_audit_dir(), context)?;
    let sink = Arc::new(
        BoundRecorder::builder(Arc::clone(&recorder), runtime.clone(), context.clone())
            .health_file(path)
            .build()
            .context("bound audit preflight failed")?,
    );
    let shared: Arc<dyn mvm_core::audit_sink::AuditSink> = sink.clone();
    recorder
        .bind_audit_sink(&shared)
        .context("binding endpoint service audit")?;
    Ok(sink)
}

#[cfg(test)]
mod tests;
