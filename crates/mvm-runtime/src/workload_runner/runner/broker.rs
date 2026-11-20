use anyhow::{Context, Result, bail};
use std::path::Path;

use mvm_core::protocol::broker::ServiceId;

#[cfg(test)]
mod tests;

/// The production broker registrar delegates to the resident host agent or
/// the per-VM broker fork, preserving the admitted capability boundary.
pub struct RealBrokerRegistrar;

impl BrokerRegistrar for RealBrokerRegistrar {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        if req.services.is_empty() {
            return Ok(BrokerGuard::defused());
        }
        let (Some(tenant), Some(broker_listen_socket)) = (req.tenant, req.broker_listen_socket)
        else {
            return Ok(BrokerGuard::defused());
        };

        let guard = if mvm_vmm::host::host_agent_spawn::host_agent_daemon_enabled() {
            mvm_vmm::host::host_agent_spawn::register_host_agent_services_if_admitted(
                mvm_vmm::host::host_agent_spawn::HostAgentServicesParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                    services: req.services,
                    capability_bindings: req.capability_bindings,
                    service_proxies: req.service_proxies,
                },
            )
            .map(mvm_vmm::host::host_agent_spawn::ServicesGuard::Agent)?
        } else {
            if !req.service_proxies.is_empty() {
                bail!("controller-backed typed services require the resident host-agent path");
            }
            mvm_vmm::host::broker_services_spawn::spawn_broker_services_if_admitted(
                mvm_vmm::host::broker_services_spawn::BrokerServicesSpawnParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                    services: req.services,
                    capability_bindings: req.capability_bindings,
                },
            )
            .map(mvm_vmm::host::host_agent_spawn::ServicesGuard::Fork)?
        };
        Ok(BrokerGuard::from_services_guard(guard))
    }
}

/// What the runner needs to register the per-VM host-services broker after boot.
pub struct BrokerRegisterRequest<'a> {
    /// VM name — the registration's `vm_id`, workload id, and per-VM chain key.
    pub vm_name: &'a str,
    /// Per-VM state dir (audit-signer pid/sock + the daemon tenant-ref marker).
    pub state_dir: &'a Path,
    /// Tenant from the admitted plan. `None` ⇒ unadmitted ⇒ a defused no-op:
    /// no broker services and no BROKER_PORT in the spec, so a stray guest dial
    /// stays `ECONNREFUSED` (fail-closed).
    pub tenant: Option<&'a str>,
    /// The `BROKER_PORT` socket the broker/daemon binds — the same path the spec
    /// wires the guest's `BROKER_PORT` relay to. `None` on the unadmitted path.
    pub broker_listen_socket: Option<&'a Path>,
    /// Host services from the admitted plan. Empty means no broker process is
    /// needed and every broker call remains fail-closed.
    pub services: &'a [ServiceId],
    /// Exact typed capabilities carried by admitted extension bindings.
    pub capability_bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
    /// Controller-backed typed services prepared by the admitting process.
    pub service_proxies: &'a [mvm_contract::protocol::broker_control::ServiceProxyBinding],
}

/// Register/spawn the per-VM host-services broker for an admitted workload,
/// returning a guard whose Drop reaps until defused. The claims-12/13 seam:
/// Admitted host services reach the guest over `BROKER_PORT`. Behind a trait so
/// the runner is unit-testable with no real broker subprocess.
pub trait BrokerRegistrar: Send + Sync {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard>;
}

/// RAII guard around the registered broker services: Drop reaps them until the
/// VM is confirmed up and `defuse`d (the `stop` path then owns teardown). Wraps
/// the existing `ServicesGuard` so no reaping logic is duplicated.
pub struct BrokerGuard(pub(super) mvm_vmm::host::host_agent_spawn::ServicesGuard);

impl BrokerGuard {
    pub(crate) fn from_services_guard(
        guard: mvm_vmm::host::host_agent_spawn::ServicesGuard,
    ) -> Self {
        Self(guard)
    }

    /// A guard that reaps nothing on drop — the unadmitted / spawn-failed path.
    pub(super) fn defused() -> Self {
        Self(mvm_vmm::host::host_agent_spawn::ServicesGuard::None)
    }

    /// Disarm: the VM is up; the `stop` path now owns teardown.
    pub fn defuse(&mut self) {
        self.0.defuse();
    }

    /// Whether the launch came up with the host services it asked for.
    ///
    /// The guard alone cannot answer this. It records only whether anything was
    /// registered, which is the same `false` for a workload that bound no
    /// service as for one whose registration was skipped — `requested` is what
    /// separates them. Judging on the guard alone marks every workload that
    /// binds no host service as degraded, and a degraded launch is refused as a
    /// sample of a healthy one.
    #[must_use]
    pub fn services_healthy(&self, requested: &[ServiceId]) -> bool {
        requested.is_empty() || self.0.is_registered()
    }
}

pub(crate) fn admitted_broker_bindings(
    plan_json: Option<&str>,
) -> Result<(
    Vec<ServiceId>,
    Vec<mvm_contract::protocol::agent_capability::CapabilityBinding>,
)> {
    let plan = plan_json
        .map(mvm_core::plan::plan_from_admitted_json)
        .transpose()
        .context("parse admitted plan host services")?;
    let Some(plan) = plan else {
        return Ok((Vec::new(), Vec::new()));
    };
    let capabilities = capabilities_for_plan(&plan)?;
    Ok((plan.services, capabilities))
}

fn capabilities_for_plan(
    plan: &mvm_core::plan::ExecutionPlan,
) -> Result<Vec<mvm_contract::protocol::agent_capability::CapabilityBinding>> {
    use mvm_contract::protocol::workload_actor::{
        LifecycleOperation, WorkflowRole, capability_descriptor,
    };
    let mut capabilities: Vec<_> = plan
        .extensions
        .iter()
        .flat_map(|extension| extension.capabilities.iter().cloned())
        .collect();
    anyhow::ensure!(
        capabilities
            .iter()
            .all(|binding| binding.capability.service.as_str() != "host.actor.v1"),
        "actor lifecycle bindings must come from the signed controller grant"
    );
    if !plan
        .services
        .iter()
        .any(|service| service.as_str() == "host.actor.v1")
    {
        return Ok(capabilities);
    }
    let Some(workflow) = &plan.workflow else {
        return Ok(capabilities);
    };
    workflow.validate()?;
    if let WorkflowRole::Controller { grant } = &workflow.role {
        anyhow::ensure!(
            grant.controller.tenant == plan.tenant
                && grant.controller.workload == plan.workload
                && grant.controller.execution_epoch.get() == plan.execution_epoch,
            "actor grant belongs to another admitted controller"
        );
        for operation in &grant.operations {
            let verb = match operation {
                LifecycleOperation::Launch => "launch_child",
                LifecycleOperation::ObserveChild => "observe_child",
                LifecycleOperation::ReleaseChild => "release_child",
            };
            capabilities.push(capability_descriptor(verb)?.binding());
        }
    }
    Ok(capabilities)
}
