use anyhow::{Result, bail};

use super::{BrokerGuard, BrokerRegisterRequest, BrokerRegistrar};

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
