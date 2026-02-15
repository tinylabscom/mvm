use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

use mvm_core::pool::Role;
use mvm_core::tenant::TenantQuota;
use mvm_runtime::vm::tenant::lifecycle::{tenant_list, tenant_load};

/// A pool within a deployment template.
#[derive(Debug, Clone)]
pub struct PoolTemplate {
    pub pool_id: &'static str,
    pub role: Role,
    pub profile: &'static str,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub data_disk_mib: u32,
}

/// A complete deployment template (tenant + pools).
#[derive(Debug, Clone)]
pub struct DeploymentTemplate {
    pub name: &'static str,
    pub description: &'static str,
    pub default_flake: &'static str,
    pub quotas: TenantQuota,
    pub pools: Vec<PoolTemplate>,
}

/// Look up a built-in template by name.
pub fn get_template(name: &str) -> Option<DeploymentTemplate> {
    match name {
        "openclaw" => Some(openclaw_template()),
        _ => None,
    }
}

/// List all available template names.
pub fn list_templates() -> Vec<&'static str> {
    vec!["openclaw"]
}

fn openclaw_template() -> DeploymentTemplate {
    DeploymentTemplate {
        name: "openclaw",
        description: "OpenClaw deployment: gateway + worker pools for messaging integrations",
        default_flake: "github:openclaw/nix-openclaw",
        quotas: TenantQuota {
            max_vcpus: 32,
            max_mem_mib: 65536,
            max_running: 16,
            max_warm: 8,
            max_pools: 10,
            max_instances_per_pool: 32,
            max_disk_gib: 500,
        },
        pools: vec![
            PoolTemplate {
                pool_id: "gateways",
                role: Role::Gateway,
                profile: "minimal",
                vcpus: 2,
                mem_mib: 1024,
                data_disk_mib: 0,
            },
            PoolTemplate {
                pool_id: "workers",
                role: Role::Worker,
                profile: "minimal",
                vcpus: 2,
                mem_mib: 2048,
                data_disk_mib: 2048,
            },
        ],
    }
}

/// Auto-allocate a net_id by scanning existing tenants.
/// Returns max(existing_net_ids) + 1, or 1 if no tenants exist.
pub fn allocate_net_id() -> Result<u16> {
    let tenant_ids =
        tenant_list().with_context(|| "Failed to list tenants for net-id allocation")?;

    let mut max_net_id: u16 = 0;
    for tid in &tenant_ids {
        if let Ok(config) = tenant_load(tid)
            && config.net.tenant_net_id > max_net_id
        {
            max_net_id = config.net.tenant_net_id;
        }
    }

    Ok(max_net_id + 1)
}

/// Compute a /24 subnet from a net_id within the 10.240.0.0/12 cluster CIDR.
pub fn subnet_from_net_id(net_id: u16) -> String {
    format!("10.240.{}.0/24", net_id)
}

/// Derive gateway IP (first usable) from a /24 subnet CIDR.
pub fn gateway_from_subnet(subnet: &str) -> Result<String> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR subnet: {}", subnet);
    }
    let octets: Vec<&str> = parts[0].split('.').collect();
    if octets.len() != 4 {
        anyhow::bail!("Invalid IPv4 address in subnet: {}", subnet);
    }
    Ok(format!("{}.{}.{}.1", octets[0], octets[1], octets[2]))
}

// ============================================================================
// Deploy config (--config for `mvm new`)
// ============================================================================

/// Config file for `mvm new <template> <name> --config <path>`.
/// Provides secrets and resource overrides for template-based deployments.
#[derive(Debug, Deserialize)]
pub struct DeployConfig {
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
    #[serde(default)]
    pub overrides: OverrideConfig,
}

/// Reference to a secret file on disk.
#[derive(Debug, Deserialize)]
pub struct SecretRef {
    pub file: PathBuf,
}

/// Resource overrides applied on top of a template.
#[derive(Debug, Default, Deserialize)]
pub struct OverrideConfig {
    pub flake: Option<String>,
    pub workers: Option<PoolOverride>,
    pub gateways: Option<PoolOverride>,
}

/// Per-pool resource overrides.
#[derive(Debug, Deserialize)]
pub struct PoolOverride {
    pub vcpus: Option<u8>,
    pub mem_mib: Option<u32>,
    pub instances: Option<u32>,
}

impl DeployConfig {
    /// Load from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }
}

// ============================================================================
// Deployment manifest (standalone `mvm deploy`)
// ============================================================================

/// Standalone deployment manifest for `mvm deploy manifest.toml`.
/// Describes a complete deployment: tenant, pools, and secrets.
#[derive(Debug, Deserialize)]
pub struct DeploymentManifest {
    pub tenant: ManifestTenant,
    #[serde(default)]
    pub pools: Vec<ManifestPool>,
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRef>,
}

/// Tenant section of a deployment manifest.
#[derive(Debug, Deserialize)]
pub struct ManifestTenant {
    pub id: String,
    pub net_id: Option<u16>,
    pub subnet: Option<String>,
}

/// Pool section of a deployment manifest.
#[derive(Debug, Deserialize)]
pub struct ManifestPool {
    pub id: String,
    #[serde(default)]
    pub role: Role,
    #[serde(default = "default_profile")]
    pub profile: String,
    pub flake: Option<String>,
    #[serde(default = "default_vcpus")]
    pub vcpus: u8,
    #[serde(default = "default_mem_mib")]
    pub mem_mib: u32,
    #[serde(default)]
    pub data_disk_mib: u32,
    pub desired_running: Option<u32>,
    pub desired_warm: Option<u32>,
}

fn default_profile() -> String {
    "minimal".to_string()
}

fn default_vcpus() -> u8 {
    2
}

fn default_mem_mib() -> u32 {
    1024
}

impl DeploymentManifest {
    /// Load from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest: {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse manifest: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::pool::InstanceResources;

    #[test]
    fn test_get_template_openclaw() {
        let t = get_template("openclaw").unwrap();
        assert_eq!(t.name, "openclaw");
        assert_eq!(t.pools.len(), 2);
        assert_eq!(t.pools[0].pool_id, "gateways");
        assert_eq!(t.pools[0].role, Role::Gateway);
        assert_eq!(t.pools[1].pool_id, "workers");
        assert_eq!(t.pools[1].role, Role::Worker);
    }

    #[test]
    fn test_get_template_unknown() {
        assert!(get_template("nonexistent").is_none());
    }

    #[test]
    fn test_list_templates() {
        let names = list_templates();
        assert!(names.contains(&"openclaw"));
    }

    #[test]
    fn test_allocate_net_id_empty() {
        let (_guard, _fs) = mvm_runtime::shell_mock::mock_fs().install();
        let id = allocate_net_id().unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn test_allocate_net_id_with_existing() {
        let (_guard, _fs) = mvm_runtime::shell_mock::mock_fs().install();

        // Create tenants with net_ids 3 and 7
        mvm_runtime::vm::tenant::lifecycle::tenant_create(
            "alpha",
            mvm_core::tenant::TenantNet::new(3, "10.240.3.0/24", "10.240.3.1"),
            TenantQuota::default(),
        )
        .unwrap();
        mvm_runtime::vm::tenant::lifecycle::tenant_create(
            "beta",
            mvm_core::tenant::TenantNet::new(7, "10.240.7.0/24", "10.240.7.1"),
            TenantQuota::default(),
        )
        .unwrap();

        let id = allocate_net_id().unwrap();
        assert_eq!(id, 8); // max(3, 7) + 1
    }

    #[test]
    fn test_subnet_from_net_id() {
        assert_eq!(subnet_from_net_id(1), "10.240.1.0/24");
        assert_eq!(subnet_from_net_id(42), "10.240.42.0/24");
        assert_eq!(subnet_from_net_id(255), "10.240.255.0/24");
    }

    #[test]
    fn test_gateway_from_subnet() {
        assert_eq!(gateway_from_subnet("10.240.3.0/24").unwrap(), "10.240.3.1");
        assert_eq!(
            gateway_from_subnet("10.240.42.0/24").unwrap(),
            "10.240.42.1"
        );
    }

    #[test]
    fn test_gateway_from_subnet_invalid() {
        assert!(gateway_from_subnet("invalid").is_err());
        assert!(gateway_from_subnet("10.240.3.0").is_err());
    }

    #[test]
    fn test_openclaw_template_resources() {
        let t = get_template("openclaw").unwrap();
        let gw = &t.pools[0];
        assert_eq!(gw.vcpus, 2);
        assert_eq!(gw.mem_mib, 1024);
        assert_eq!(gw.data_disk_mib, 0);

        let wk = &t.pools[1];
        assert_eq!(wk.vcpus, 2);
        assert_eq!(wk.mem_mib, 2048);
        assert_eq!(wk.data_disk_mib, 2048);
    }

    #[test]
    fn test_deploy_config_parse() {
        let toml = r#"
[secrets]
anthropic_key = { file = "./secrets/anthropic.key" }
telegram_token = { file = "./secrets/telegram.token" }

[overrides]
flake = "github:openclaw/nix-openclaw"

[overrides.workers]
mem_mib = 4096
instances = 3
"#;
        let config: DeployConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.secrets.len(), 2);
        assert!(config.secrets.contains_key("anthropic_key"));
        assert_eq!(
            config.overrides.flake.as_deref(),
            Some("github:openclaw/nix-openclaw")
        );
        let workers = config.overrides.workers.unwrap();
        assert_eq!(workers.mem_mib, Some(4096));
        assert_eq!(workers.instances, Some(3));
    }

    #[test]
    fn test_deploy_config_minimal() {
        let toml = "";
        let config: DeployConfig = toml::from_str(toml).unwrap();
        assert!(config.secrets.is_empty());
        assert!(config.overrides.flake.is_none());
    }

    #[test]
    fn test_deployment_manifest_parse() {
        let toml = r#"
[tenant]
id = "alice"

[[pools]]
id = "gateways"
role = "gateway"
flake = "github:openclaw/nix-openclaw"
vcpus = 2
mem_mib = 1024

[[pools]]
id = "workers"
role = "worker"
flake = "github:openclaw/nix-openclaw"
vcpus = 2
mem_mib = 2048
desired_running = 1

[secrets]
anthropic_key = { file = "./secrets/anthropic.key" }
"#;
        let manifest: DeploymentManifest = toml::from_str(toml).unwrap();
        assert_eq!(manifest.tenant.id, "alice");
        assert_eq!(manifest.pools.len(), 2);
        assert_eq!(manifest.pools[0].role, Role::Gateway);
        assert_eq!(manifest.pools[1].role, Role::Worker);
        assert_eq!(manifest.pools[1].mem_mib, 2048);
        assert_eq!(manifest.pools[1].desired_running, Some(1));
        assert_eq!(manifest.secrets.len(), 1);
    }

    #[test]
    fn test_deployment_manifest_defaults() {
        let toml = r#"
[tenant]
id = "test"

[[pools]]
id = "workers"
"#;
        let manifest: DeploymentManifest = toml::from_str(toml).unwrap();
        assert_eq!(manifest.pools[0].role, Role::Worker); // default
        assert_eq!(manifest.pools[0].profile, "minimal"); // default
        assert_eq!(manifest.pools[0].vcpus, 2); // default
        assert_eq!(manifest.pools[0].mem_mib, 1024); // default
    }

    #[test]
    fn test_new_deployment_end_to_end() {
        let (_guard, _fs) = mvm_runtime::shell_mock::mock_fs().install();

        let template = get_template("openclaw").unwrap();
        let net_id = allocate_net_id().unwrap();
        let subnet = subnet_from_net_id(net_id);
        let gateway = gateway_from_subnet(&subnet).unwrap();

        let net = mvm_core::tenant::TenantNet::new(net_id, &subnet, &gateway);
        let config = mvm_runtime::vm::tenant::lifecycle::tenant_create(
            "myapp",
            net,
            template.quotas.clone(),
        )
        .unwrap();
        assert_eq!(config.tenant_id, "myapp");
        assert_eq!(config.net.tenant_net_id, 1);

        for pool_tmpl in &template.pools {
            let resources = InstanceResources {
                vcpus: pool_tmpl.vcpus,
                mem_mib: pool_tmpl.mem_mib,
                data_disk_mib: pool_tmpl.data_disk_mib,
            };
            let spec = mvm_runtime::vm::pool::lifecycle::pool_create(
                "myapp",
                pool_tmpl.pool_id,
                template.default_flake,
                pool_tmpl.profile,
                resources,
                pool_tmpl.role.clone(),
                template.name,
            )
            .unwrap();
            assert_eq!(spec.tenant_id, "myapp");
        }

        let mut pools = mvm_runtime::vm::pool::lifecycle::pool_list("myapp").unwrap();
        pools.sort();
        assert_eq!(pools, vec!["gateways", "workers"]);
    }
}
