use anyhow::Result;

use crate::instance::InstanceNet;
use crate::pool::{BuildRevision, PoolSpec};
use crate::tenant::{TenantConfig, TenantNet};

/// Minimal shell execution abstraction used by dev-mode builds.
///
/// This trait provides just shell execution and logging — enough for
/// `dev_build()` and related build flows that run Linux/Nix work via
/// the current execution boundary (the shared builder VM on macOS, or
/// the host itself on native Linux).
pub trait ShellEnvironment: Send + Sync {
    /// Execute a shell script in the VM.
    fn shell_exec(&self, script: &str) -> Result<()>;

    /// Execute a shell script in the VM and capture stdout.
    fn shell_exec_stdout(&self, script: &str) -> Result<String>;

    /// Execute a shell script with visible output.
    fn shell_exec_visible(&self, script: &str) -> Result<()>;

    /// Log an informational message.
    fn log_info(&self, msg: &str);

    /// Log a success message.
    fn log_success(&self, msg: &str);

    /// Log a warning (optional; default no-op for test fakes).
    fn log_warn(&self, _msg: &str) {
        // default implementation: no-op
    }

    /// Execute a shell script, capturing both stdout and stderr.
    ///
    /// Returns `(stdout, stderr)` on success. On failure, returns the exit code and
    /// captured stderr in the error. Used by the build pipeline to capture nix build
    /// errors for structured reporting.
    ///
    /// Default: falls back to `shell_exec_stdout` (stderr not captured).
    fn shell_exec_capture(&self, script: &str) -> Result<(String, String)> {
        let stdout = self.shell_exec_stdout(script)?;
        Ok((stdout, String::new()))
    }
}

/// Full build environment for orchestrated pool builds.
///
/// Extends [`ShellEnvironment`] with tenant/pool/network operations needed
/// by the pool build pipeline (ephemeral FC builder VMs, artifact recording).
/// mvm-build depends on mvm-core only. At runtime, the orchestrator provides
/// a concrete implementation that delegates to the runtime modules.
pub trait BuildEnvironment: ShellEnvironment {
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
}
