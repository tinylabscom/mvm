use serde::{Deserialize, Serialize};

/// Tenant: a security, isolation, and policy boundary that may own multiple microVMs.
/// NOT a runtime entity — tenants have no state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantConfig {
    pub tenant_id: String,
    pub quotas: TenantQuota,
    pub net: TenantNet,
    pub secrets_epoch: u64,
    pub config_version: u64,
    /// If true, reconcile cannot auto-stop this tenant's instances.
    pub pinned: bool,
    /// Audit log retention in days. 0 = forever.
    pub audit_retention_days: u32,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantQuota {
    pub max_vcpus: u32,
    pub max_mem_mib: u64,
    pub max_running: u32,
    pub max_warm: u32,
    pub max_pools: u32,
    pub max_instances_per_pool: u32,
    pub max_disk_gib: u64,
}

impl Default for TenantQuota {
    fn default() -> Self {
        Self {
            max_vcpus: 16,
            max_mem_mib: 32768,
            max_running: 8,
            max_warm: 4,
            max_pools: 4,
            max_instances_per_pool: 16,
            max_disk_gib: 100,
        }
    }
}

/// Coordinator-assigned, cluster-wide network identity for a tenant.
/// Agents MUST consume this verbatim — never derive or hash IPs locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantNet {
    /// Cluster-unique integer (0..4095), assigned by coordinator.
    pub tenant_net_id: u16,
    /// Coordinator-assigned CIDR, e.g. "10.240.3.0/24".
    pub ipv4_subnet: String,
    /// First usable IP in subnet, e.g. "10.240.3.1".
    pub gateway_ip: String,
    /// Bridge name derived from tenant_net_id, e.g. "br-tenant-3".
    pub bridge_name: String,
}

impl TenantNet {
    /// Construct TenantNet from coordinator-assigned values.
    pub fn new(tenant_net_id: u16, ipv4_subnet: &str, gateway_ip: &str) -> Self {
        Self {
            tenant_net_id,
            ipv4_subnet: ipv4_subnet.to_string(),
            gateway_ip: gateway_ip.to_string(),
            bridge_name: format!("br-tenant-{}", tenant_net_id),
        }
    }
}

/// Filesystem paths for tenant state.
pub const TENANT_BASE: &str = "/var/lib/mvm/tenants";

pub fn tenant_dir(id: &str) -> String {
    format!("{}/{}", TENANT_BASE, id)
}

pub fn tenant_config_path(id: &str) -> String {
    format!("{}/tenant.json", tenant_dir(id))
}

pub fn tenant_secrets_path(id: &str) -> String {
    format!("{}/secrets.json", tenant_dir(id))
}

pub fn tenant_audit_log_path(id: &str) -> String {
    format!("{}/audit.log", tenant_dir(id))
}

pub fn tenant_ssh_key_path(id: &str) -> String {
    format!("{}/ssh_key", tenant_dir(id))
}

pub fn tenant_pools_dir(id: &str) -> String {
    format!("{}/pools", tenant_dir(id))
}
