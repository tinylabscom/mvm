use anyhow::{Result, anyhow};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::instance::InstanceNet;
use mvm_core::pool::{BuildRevision, PoolSpec};
use mvm_core::tenant::{TenantConfig, TenantNet};

use crate::vm::pool::artifacts;
use crate::vm::{bridge, instance::net};
use crate::{shell, ui};

/// Concrete implementation of [`BuildEnvironment`] that delegates to
/// mvm-runtime shell, bridge, and pool modules.
///
/// Used by the CLI and agent when invoking `mvm_build::build::pool_build`.
pub struct RuntimeBuildEnv;

impl BuildEnvironment for RuntimeBuildEnv {
    fn shell_exec(&self, script: &str) -> Result<()> {
        let out = shell::run_in_vm(script)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Command failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn shell_exec_stdout(&self, script: &str) -> Result<String> {
        let out = shell::run_in_vm(script)?;
        if !out.status.success() {
            return Err(anyhow!(
                "Command failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn shell_exec_visible(&self, script: &str) -> Result<()> {
        shell::run_in_vm_visible(script)
    }

    fn load_pool_spec(&self, tenant_id: &str, pool_id: &str) -> Result<PoolSpec> {
        crate::vm::pool::lifecycle::pool_load(tenant_id, pool_id)
    }

    fn load_tenant_config(&self, tenant_id: &str) -> Result<TenantConfig> {
        crate::vm::tenant::lifecycle::tenant_load(tenant_id)
    }

    fn ensure_bridge(&self, tenant_net: &TenantNet) -> Result<()> {
        bridge::ensure_tenant_bridge(tenant_net)
    }

    fn setup_tap(&self, instance_net: &InstanceNet, bridge_name: &str) -> Result<()> {
        net::setup_tap(instance_net, bridge_name)
    }

    fn teardown_tap(&self, tap_dev: &str) -> Result<()> {
        net::teardown_tap(tap_dev)
    }

    fn record_revision(
        &self,
        tenant_id: &str,
        pool_id: &str,
        revision: &BuildRevision,
    ) -> Result<()> {
        artifacts::record_revision(tenant_id, pool_id, revision)
    }

    fn log_info(&self, msg: &str) {
        ui::info(msg);
    }

    fn log_success(&self, msg: &str) {
        ui::success(msg);
    }

    fn log_warn(&self, msg: &str) {
        ui::warn(msg);
    }
}
