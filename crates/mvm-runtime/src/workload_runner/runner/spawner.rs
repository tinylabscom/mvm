//! The per-VM gating-endpoint spawn seam.
//!
//! Behind a trait so the runner is unit-testable with no real VM and no real
//! endpoint process; the production impl is the one host-side egress bridge
//! (the claim-10 gate plus claims 12/13 substitution).

use super::*;

/// Where this boot's FlowMux identity comes from.
///
/// A cold boot mints one and hands the guest a drive carrying it. A warm claim
/// cannot: the child restores from its parent's memory image, so it already
/// holds the parent's signing key and there is no path back into a running
/// guest's memory to replace it. The child's endpoint therefore pins the key
/// its guest actually has, read from what the parent persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowMuxIdentitySource<'a> {
    /// Mint a fresh identity for this boot and emit a drive to attach.
    Mint,
    /// Inherit the identity the parent at this state dir persisted.
    InheritFrom(&'a Path),
}

/// What the workload runner needs to stand up the per-VM gating endpoint.
pub struct NetworkEndpointSpawnRequest<'a> {
    pub vm_name: &'a str,
    pub state_dir: &'a Path,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    /// Transport-neutral resource ceilings from the admitted plan.
    pub network_limits: mvm_core::plan::NetworkLimits,
    /// Exact signed ingress mappings owned by this endpoint.
    pub ingress: &'a [mvm_core::plan::IngressMapping],
    /// Where the guest's half of the authenticated session comes from.
    pub identity: FlowMuxIdentitySource<'a>,
}

/// A stood-up endpoint: the channel, and the drive the guest reads its identity
/// from when this boot minted one.
pub struct SpawnedEndpoint {
    /// The host UDS the guest's `EGRESS_PORT` relays to.
    pub egress_uds: PathBuf,
    /// The identity drive to attach to the guest. `None` for a warm claim,
    /// whose guest already holds its key in restored memory.
    pub identity_drive: Option<PathBuf>,
}

/// Stand up the per-VM gating endpoint. The one host-side egress bridge
/// (claim-10 gate + claims 12/13 substitution).
pub trait NetworkEndpointSpawner: Send + Sync {
    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint>;
}

/// The production `NetworkEndpointSpawner`: spawns the real `mvm-network-endpoint`
/// over the in-process-VMM UDS transport.
pub struct RealNetworkEndpointSpawner;

impl NetworkEndpointSpawner for RealNetworkEndpointSpawner {
    fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
        use mvm_vmm::host::flowmux_identity::{
            FlowMuxIdentityMaterial, IDENTITY_DRIVE_FILE, load_inheritable_identity,
        };
        use mvm_vmm::host::network_endpoint_spawn::FlowMuxIdentitySpawnConfig;

        let uds = vm_network_endpoint_socket(req.vm_name);
        let (identity, identity_drive) = match req.identity {
            FlowMuxIdentitySource::Mint => {
                let material = FlowMuxIdentityMaterial::mint_from_host_signer(req.vm_name)
                    .context("minting this boot's FlowMux identity")?;
                let drive = req.state_dir.join(IDENTITY_DRIVE_FILE);
                material.write_drive_with_ingress(&drive, req.ingress)?;
                // Persisted so a warm child claimed from this VM pins the key
                // its restored guest actually holds.
                material.persist_inheritable(req.state_dir)?;
                (material.spawn_config().clone(), Some(drive))
            }
            FlowMuxIdentitySource::InheritFrom(parent_state_dir) => {
                let inherited =
                    load_inheritable_identity(parent_state_dir)?.with_context(|| {
                        format!(
                            "parent at {} persisted no FlowMux identity, so a claimed child's \
                         endpoint has no key to pin — refusing rather than minting one the \
                         restored guest does not hold",
                            parent_state_dir.display()
                        )
                    })?;
                (
                    FlowMuxIdentitySpawnConfig {
                        session_id: inherited.session_id,
                        host_signing_key_base64: host_signer_key_base64()?,
                        guest_verifying_key_base64: inherited.guest_verifying_key_base64,
                    },
                    None,
                )
            }
        };

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
            session_marker: None,
            tls_intermediate: None,
            network_policy: Some(req.network_policy),
            network_limits: req.network_limits,
            ingress: req.ingress,
            resolver_remote: None,
            binding_store_dir: None,
            flowmux_identity: Some(identity),
        })?;
        Ok(SpawnedEndpoint {
            egress_uds: uds,
            identity_drive,
        })
    }
}

/// The host signer, base64-encoded for the endpoint's stdin.
fn host_signer_key_base64() -> Result<String> {
    use base64::Engine as _;
    let path = mvm_core::config::mvm_keys_dir()
        .join(mvm_vmm::host::broker_services_spawn::HOST_SIGNER_KEY);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading the host signer key at {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() == 32,
        "host signer key at {} is {} bytes, expected 32",
        path.display(),
        bytes.len()
    );
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}
