//! Bind the real recorder and lifecycle notifier before serving guest decisions.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use mvm_core::audit_sink::{AuditContext, AuditFailureMode};
use mvm_vmm::host::audit_control::EndpointControl;

use super::network_endpoint::{EgressMode, EndpointConfig, EndpointNetworkProjection};
use crate::supervisor::audit::bound_sink::BoundRecorder;

/// Owns the notification-only lifecycle channel for one endpoint process.
pub struct AuditStartup {
    control: Option<Arc<Mutex<EndpointControl>>>,
}

impl AuditStartup {
    /// Capture inherited control before confinement and verify its admitted identity.
    pub fn from_config(cfg: &EndpointConfig) -> Result<Self> {
        let control = EndpointControl::from_env().context("reading audit shutdown channel")?;
        validate(cfg, control.is_some())?;
        Ok(Self {
            control: control.map(|control| Arc::new(Mutex::new(control))),
        })
    }

    /// Establish the bound journal and its required preflight before startup readiness.
    pub fn bind(
        &self,
        cfg: &EndpointConfig,
        network: &EndpointNetworkProjection,
        runtime: &tokio::runtime::Handle,
    ) -> Result<Arc<BoundRecorder>> {
        let context = cfg.audit.as_ref().context("missing bound audit identity")?;
        let recorder = network
            .recorder()
            .context("required audit recorder is unavailable")?;
        let path = BoundRecorder::health_path(&mvm_core::config::mvm_audit_dir(), context)?;
        let mut builder =
            BoundRecorder::builder(Arc::clone(&recorder), runtime.clone(), context.clone())
                .health_file(path);
        if let Some(control) = &self.control {
            let control = Arc::clone(control);
            builder = builder.on_stop(Arc::new(move || {
                control
                    .lock()
                    .expect("audit control poisoned")
                    .notify_failure()
            }));
        }
        let sink = Arc::new(builder.build().context("bound audit preflight failed")?);
        let shared: Arc<dyn mvm_core::audit_sink::AuditSink> = sink.clone();
        recorder
            .bind_audit_sink(&shared)
            .context("binding endpoint service audit")?;
        Ok(sink)
    }

    /// Wait after startup readiness but before FlowMux serving for exact VM ownership.
    pub fn wait_ready(&self, cfg: &EndpointConfig) -> Result<()> {
        if let Some(control) = &self.control {
            let binding = cfg
                .audit_control
                .as_ref()
                .context("missing audit control binding")?;
            control
                .lock()
                .expect("audit control poisoned")
                .wait_ready(binding)
                .context("binding audit failures to this workload's lifecycle")?;
        }
        Ok(())
    }
}

fn validate(cfg: &EndpointConfig, inherited_control: bool) -> Result<()> {
    if !matches!(cfg.egress_mode, EgressMode::FlowMux) {
        ensure!(
            !inherited_control && cfg.audit_control.is_none(),
            "non-FlowMux endpoint has workload stop authority"
        );
        return Ok(());
    }
    match cfg
        .audit
        .as_ref()
        .context("FlowMux requires a bound audit identity")?
    {
        AuditContext::Builder { tenant, name } => {
            ensure!(
                tenant.0 == cfg.tenant_id && name == &cfg.instance_id && !name.is_empty(),
                "builder audit identity mismatch"
            );
            ensure!(
                !inherited_control && cfg.audit_control.is_none(),
                "builder endpoint must not hold workload stop authority"
            );
        }
        AuditContext::Workload { plan, mode } => {
            // A warm child may have a different physical VM name. Its logical
            // workload identity remains the one in its admitted plan.
            cfg.audit
                .as_ref()
                .expect("context checked")
                .validate_for(&cfg.tenant_id, &plan.workload.0)?;
            match mode {
                AuditFailureMode::Production => {
                    let control = cfg
                        .audit_control
                        .as_ref()
                        .context("production endpoint has no audit stop binding")?;
                    ensure!(
                        inherited_control,
                        "production endpoint has no audit stop channel"
                    );
                    ensure!(
                        control.tenant_id == plan.tenant.0
                            && control.workload_id == plan.workload.0
                            && control.plan_id == plan.plan_id.0
                            && control.epoch == plan.execution_epoch
                            && control.instance_id == cfg.instance_id,
                        "audit shutdown binding does not match the admitted workload"
                    );
                }
                AuditFailureMode::Development => ensure!(
                    !inherited_control && cfg.audit_control.is_none(),
                    "development endpoint unexpectedly holds workload stop authority"
                ),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
