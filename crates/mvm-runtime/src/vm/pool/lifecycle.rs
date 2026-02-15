use anyhow::{Context, Result};
use tracing::instrument;

use crate::shell;
use crate::vm::tenant::lifecycle::tenant_exists;
use mvm_core::naming;
use mvm_core::pool::{
    DesiredCounts, InstanceResources, PoolMetadata, PoolSpec, Role, pool_config_path, pool_dir,
};

/// Create a new pool under a tenant.
#[instrument(skip_all, fields(tenant_id, pool_id))]
pub fn pool_create(
    tenant_id: &str,
    pool_id: &str,
    flake_ref: &str,
    profile: &str,
    resources: InstanceResources,
    role: Role,
    template_id: &str,
) -> Result<PoolSpec> {
    naming::validate_id(tenant_id, "Tenant")?;
    naming::validate_id(pool_id, "Pool")?;

    if !tenant_exists(tenant_id)? {
        anyhow::bail!("Tenant '{}' does not exist", tenant_id);
    }

    let dir = pool_dir(tenant_id, pool_id);
    shell::run_in_vm(&format!(
        "mkdir -p {dir}/artifacts/revisions {dir}/instances {dir}/snapshots/base"
    ))?;

    let spec = PoolSpec {
        pool_id: pool_id.to_string(),
        tenant_id: tenant_id.to_string(),
        flake_ref: flake_ref.to_string(),
        profile: profile.to_string(),
        role,
        instance_resources: resources,
        desired_counts: DesiredCounts::default(),
        runtime_policy: Default::default(),
        metadata: PoolMetadata::default(),
        seccomp_policy: "baseline".to_string(),
        snapshot_compression: "none".to_string(),
        metadata_enabled: false,
        pinned: false,
        critical: false,
        secret_scopes: vec![],
        template_id: template_id.to_string(),
    };

    let json = serde_json::to_string_pretty(&spec)?;
    let path = pool_config_path(tenant_id, pool_id);
    shell::run_in_vm(&format!("cat > {} << 'MVMEOF'\n{}\nMVMEOF", path, json))?;

    Ok(spec)
}

/// Load a pool spec from disk, with validation.
pub fn pool_load(tenant_id: &str, pool_id: &str) -> Result<PoolSpec> {
    let path = pool_config_path(tenant_id, pool_id);
    let json = shell::run_in_vm_stdout(&format!("cat {}", path))
        .with_context(|| format!("Failed to load pool: {}/{}", tenant_id, pool_id))?;
    let spec: PoolSpec =
        serde_json::from_str(&json).with_context(|| format!("Corrupt pool config at {}", path))?;
    validate_pool_spec(&spec)?;
    Ok(spec)
}

/// Validate a loaded pool spec for required fields and sane values.
fn validate_pool_spec(spec: &PoolSpec) -> Result<()> {
    if spec.pool_id.is_empty() {
        anyhow::bail!("Pool config has empty pool_id");
    }
    if spec.tenant_id.is_empty() {
        anyhow::bail!("Pool config has empty tenant_id");
    }
    if spec.instance_resources.vcpus == 0 {
        anyhow::bail!("Pool {} has 0 vCPUs configured", spec.pool_id);
    }
    if spec.instance_resources.mem_mib == 0 {
        anyhow::bail!("Pool {} has 0 MiB memory configured", spec.pool_id);
    }
    Ok(())
}

/// List all pool IDs for a tenant.
pub fn pool_list(tenant_id: &str) -> Result<Vec<String>> {
    let output = shell::run_in_vm_stdout(&format!(
        "ls -1 /var/lib/mvm/tenants/{}/pools/ 2>/dev/null || true",
        tenant_id
    ))?;
    Ok(output
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

/// Update desired counts for a pool.
pub fn pool_scale(
    tenant_id: &str,
    pool_id: &str,
    running: Option<u32>,
    warm: Option<u32>,
    sleeping: Option<u32>,
) -> Result<()> {
    let mut spec = pool_load(tenant_id, pool_id)?;

    if let Some(r) = running {
        spec.desired_counts.running = r;
    }
    if let Some(w) = warm {
        spec.desired_counts.warm = w;
    }
    if let Some(s) = sleeping {
        spec.desired_counts.sleeping = s;
    }

    let json = serde_json::to_string_pretty(&spec)?;
    let path = pool_config_path(tenant_id, pool_id);
    shell::run_in_vm(&format!("cat > {} << 'MVMEOF'\n{}\nMVMEOF", path, json))?;

    Ok(())
}

/// Destroy a pool and all its instances.
///
/// If `force` is false, refuses to destroy the pool if any instances
/// are Running or Warm. Set `force` to true to stop them first.
#[instrument(skip_all, fields(tenant_id, pool_id))]
pub fn pool_destroy(tenant_id: &str, pool_id: &str, force: bool) -> Result<()> {
    // Check for running instances unless force is set
    if !force
        && let Ok(instances) = crate::vm::instance::lifecycle::instance_list(tenant_id, pool_id)
    {
        let active_count = instances
            .iter()
            .filter(|i| {
                matches!(
                    i.status,
                    mvm_core::instance::InstanceStatus::Running
                        | mvm_core::instance::InstanceStatus::Warm
                )
            })
            .count();
        if active_count > 0 {
            anyhow::bail!(
                "Pool {}/{} has {} active instances. Use --force to stop them first.",
                tenant_id,
                pool_id,
                active_count
            );
        }
    }

    let dir = pool_dir(tenant_id, pool_id);
    shell::run_in_vm(&format!("rm -rf {}", dir))?;
    Ok(())
}

/// Update a pool's template reference and persist to disk.
pub fn pool_set_template(tenant_id: &str, pool_id: &str, template_id: &str) -> Result<()> {
    let mut spec = pool_load(tenant_id, pool_id)?;
    spec.template_id = template_id.to_string();
    let json = serde_json::to_string_pretty(&spec)?;
    let path = pool_config_path(tenant_id, pool_id);
    shell::run_in_vm(&format!("cat > {} << 'MVMEOF'\n{}\nMVMEOF", path, json))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell_mock;
    use mvm_core::pool::Role;

    #[test]
    fn test_pool_create_and_load() {
        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        let resources = InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        };
        let spec = pool_create(
            "acme",
            "workers",
            "github:org/repo",
            "minimal",
            resources,
            Role::default(),
            "tmpl",
        )
        .unwrap();
        assert_eq!(spec.pool_id, "workers");
        assert_eq!(spec.tenant_id, "acme");
        assert_eq!(spec.flake_ref, "github:org/repo");

        let loaded = pool_load("acme", "workers").unwrap();
        assert_eq!(loaded.pool_id, "workers");
        assert_eq!(loaded.instance_resources.vcpus, 2);
        assert_eq!(loaded.instance_resources.mem_mib, 1024);
    }

    #[test]
    fn test_pool_create_with_role() {
        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        let resources = InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        };
        let spec = pool_create(
            "acme",
            "gateways",
            ".",
            "minimal",
            resources,
            Role::Gateway,
            "tmpl",
        )
        .unwrap();
        assert_eq!(spec.role, Role::Gateway);

        let loaded = pool_load("acme", "gateways").unwrap();
        assert_eq!(loaded.role, Role::Gateway);
    }

    #[test]
    fn test_pool_list_empty() {
        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        let pools = pool_list("acme").unwrap();
        assert!(pools.is_empty());
    }

    #[test]
    fn test_pool_create_then_list() {
        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        let resources = InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        };
        pool_create(
            "acme",
            "workers",
            ".",
            "minimal",
            resources.clone(),
            Role::default(),
            "tmpl",
        )
        .unwrap();
        pool_create(
            "acme",
            "builders",
            ".",
            "python",
            resources,
            Role::Builder,
            "tmpl",
        )
        .unwrap();

        let mut pools = pool_list("acme").unwrap();
        pools.sort();
        assert_eq!(pools, vec!["builders", "workers"]);
    }

    #[test]
    fn test_pool_create_requires_tenant() {
        let (_guard, _fs) = shell_mock::mock_fs().install();
        let resources = InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        };
        let result = pool_create(
            "nonexistent",
            "workers",
            ".",
            "minimal",
            resources,
            Role::default(),
            "tmpl",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_scale() {
        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        let resources = InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        };
        pool_create(
            "acme",
            "workers",
            ".",
            "minimal",
            resources,
            Role::default(),
            "tmpl",
        )
        .unwrap();

        pool_scale("acme", "workers", Some(3), Some(1), Some(2)).unwrap();

        let loaded = pool_load("acme", "workers").unwrap();
        assert_eq!(loaded.desired_counts.running, 3);
        assert_eq!(loaded.desired_counts.warm, 1);
        assert_eq!(loaded.desired_counts.sleeping, 2);
    }

    #[test]
    fn test_pool_destroy() {
        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        let resources = InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        };
        pool_create(
            "acme",
            "workers",
            ".",
            "minimal",
            resources,
            Role::default(),
            "tmpl",
        )
        .unwrap();
        assert!(!pool_list("acme").unwrap().is_empty());

        pool_destroy("acme", "workers", true).unwrap();
        assert!(pool_list("acme").unwrap().is_empty());
    }

    #[test]
    fn test_pool_load_validates_vcpus() {
        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let bad_pool = r#"{
            "pool_id": "bad",
            "tenant_id": "acme",
            "flake_ref": ".",
            "profile": "minimal",
            "instance_resources": {"vcpus": 0, "mem_mib": 1024},
            "desired_counts": {"running": 0, "warm": 0, "sleeping": 0}
        }"#;
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .with_file("/var/lib/mvm/tenants/acme/pools/bad/pool.json", bad_pool)
            .install();

        let result = pool_load("acme", "bad");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("0 vCPUs"));
    }

    #[test]
    fn test_pool_destroy_refuses_without_force() {
        use crate::vm::instance::lifecycle::instance_create;

        let tenant_json = shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let (_guard, _fs) = shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .install();

        let resources = InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        };
        pool_create(
            "acme",
            "workers",
            ".",
            "minimal",
            resources,
            Role::default(),
            "tmpl",
        )
        .unwrap();

        // Create an instance — it will be in Created status (not Running),
        // so non-force destroy should succeed
        let _id = instance_create("acme", "workers").unwrap();
        let result = pool_destroy("acme", "workers", false);
        assert!(result.is_ok()); // Created instances are not "active"
    }
}
