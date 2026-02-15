use anyhow::Result;

use crate::instance::InstanceNet;
use crate::pool::{BuildRevision, PoolSpec};
use crate::tenant::{TenantConfig, TenantNet};

/// Abstraction over runtime operations needed by the build pipeline.
///
/// mvm-build depends on mvm-core only. At runtime, mvm-agent provides
/// a concrete implementation that delegates to mvm-runtime.
pub trait BuildEnvironment: Send + Sync {
    /// Execute a shell script in the VM.
    fn shell_exec(&self, script: &str) -> Result<()>;

    /// Execute a shell script in the VM and capture stdout.
    fn shell_exec_stdout(&self, script: &str) -> Result<String>;

    /// Execute a shell script with visible output.
    fn shell_exec_visible(&self, script: &str) -> Result<()>;

    /// Load a pool spec from the filesystem.
    fn load_pool_spec(&self, tenant_id: &str, pool_id: &str) -> Result<PoolSpec>;

    /// Load a tenant config from the filesystem.
    fn load_tenant_config(&self, tenant_id: &str) -> Result<TenantConfig>;

    /// Ensure the tenant network bridge is up.
    fn ensure_bridge(&self, net: &TenantNet) -> Result<()>;

    /// Create and attach a TAP device for a VM.
    fn setup_tap(&self, net: &InstanceNet, bridge_name: &str) -> Result<()>;

    /// Remove a TAP device.
    fn teardown_tap(&self, tap_dev: &str) -> Result<()>;

    /// Record a build revision and update the current symlink.
    fn record_revision(
        &self,
        tenant_id: &str,
        pool_id: &str,
        revision: &BuildRevision,
    ) -> Result<()>;

    /// Log an informational message.
    fn log_info(&self, msg: &str);

    /// Log a success message.
    fn log_success(&self, msg: &str);

    /// Log a warning (optional; default no-op for test fakes).
    fn log_warn(&self, _msg: &str) {
        // default implementation: no-op
    }
}
