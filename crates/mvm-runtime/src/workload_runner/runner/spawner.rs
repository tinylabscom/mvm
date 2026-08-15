//! The per-VM gating-endpoint spawn seam.
//!
//! Behind a trait so the runner is unit-testable with no real VM and no real
//! endpoint process; the production impl is the one host-side egress bridge
//! (the claim-10 gate plus claims 12/13 substitution).

use super::*;

/// What the workload runner needs to stand up the per-VM gating endpoint.
pub struct NetworkEndpointSpawnRequest<'a> {
    pub vm_name: &'a str,
    pub state_dir: &'a Path,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    /// Raw TCP egress (no secrets) vs the WireRequest substitution protocol.
    pub raw_egress: bool,
}

/// Stand up the per-VM gating endpoint; return the host UDS the guest's
/// EGRESS_PORT relays to. The one host-side egress bridge (claim-10 gate +
/// claims 12/13 substitution).
pub trait NetworkEndpointSpawner: Send + Sync {
    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<PathBuf>;
}

/// The production `NetworkEndpointSpawner`: spawns the real `mvm-network-endpoint`
/// over the in-process-VMM UDS transport.
pub struct RealNetworkEndpointSpawner;

impl NetworkEndpointSpawner for RealNetworkEndpointSpawner {
    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<PathBuf> {
        let uds = vm_network_endpoint_socket(req.vm_name);
        spawn_network_endpoint(SubstitutionSpawnParams {
            vm_name: req.vm_name,
            state_dir: req.state_dir,
            tenant: req.tenant,
            secrets: req.secrets,
            redaction: req.redaction,
            transport: EndpointTransport::Uds { path: uds.clone() },
            terminator_listen: None,
            // None ⇒ inherit the host's proxy environment, resolved once inside
            // `spawn_network_endpoint` for every backend.
            egress_proxy: None,
            tls_intermediate: None,
            network_policy: Some(req.network_policy),
            raw_egress: req.raw_egress,
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: None,
        })?;
        Ok(uds)
    }
}
