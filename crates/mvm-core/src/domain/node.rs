use serde::{Deserialize, Serialize};

/// Node identity and resource limits, persisted at /var/lib/mvm/node.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub hostname: String,
    pub arch: String,
    pub total_vcpus: u32,
    pub total_mem_mib: u64,
    #[serde(alias = "lima_status")]
    pub vm_status: Option<String>,
    pub firecracker_version: Option<String>,
    pub jailer_available: bool,
    pub cgroup_v2: bool,
    #[serde(default = "default_attestation_provider")]
    pub attestation_provider: String,
}

fn default_attestation_provider() -> String {
    "none".to_string()
}

/// Aggregate node statistics across all tenants.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStats {
    pub running_instances: u32,
    pub warm_instances: u32,
    pub sleeping_instances: u32,
    pub stopped_instances: u32,
    pub total_vcpus_used: u32,
    pub total_mem_used_mib: u64,
    pub tenant_count: u32,
    pub pool_count: u32,
}
