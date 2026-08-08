//! Firecracker backend control, artifact, snapshot, and observation helpers.
//!
//! Submodules split by concern; every item keeps its original visibility so
//! `crate::microvm::<name>` (and `mvm_runtime::microvm::<name>` for external
//! crates) resolves identically to before the split.

mod activation;
mod boot_config;
mod control;
mod daemon;
mod egress_bridge;
mod fc_api;
mod flake_run;
mod fork_namespace;
mod guards;
mod lifecycle;
mod observe;
mod run_info;
mod snapshot;

pub(crate) use activation::read_verb_grant_envelope;
pub use activation::*;
pub use boot_config::*;
pub use control::*;
pub use daemon::*;
pub(crate) use egress_bridge::*;
pub(crate) use fc_api::*;
pub use flake_run::*;
pub(crate) use fork_namespace::*;
pub use guards::*;
pub use lifecycle::*;
pub use observe::*;
pub use run_info::*;
pub use snapshot::*;

use anyhow::Result;

/// Ensure we have a Linux execution environment.
///
/// Today this is always a no-op: native Linux runs Firecracker directly,
/// macOS runs libkrun, and the Lima fallback is gone.
/// Kept as a function so callers stay well-formed; remove once every
/// callsite is audited and the call itself can be dropped.
fn require_linux_env() -> Result<()> {
    Ok(())
}

/// Absolute root of the per-VM directories (`<mvm_home>/vms`) as a `String`
/// for shell interpolation. A host path, resolved on the host — never `echo`d
/// inside a VM (on macOS every `run_in_vm` shells into the dev VM,
/// auto-starting a heavyweight builder; on Linux the in-VM env is the host,
/// so host-side resolution is identical anyway).
pub(crate) fn abs_vms_dir() -> String {
    mvm_core::config::vms_dir().display().to_string()
}

/// Resolve the absolute directory path for a running VM by name:
/// `<mvm_home>/vms/<name>`. A host path the VMM reads, resolved on the host.
pub fn resolve_running_vm_dir(name: &str) -> Result<String> {
    Ok(mvm_core::config::running_vm_dir(name))
}

/// Return the host-side path to Firecracker's PID file for VM `name`:
/// `<mvm_home>/vms/<name>/fc.pid`. The Firecracker workspace shares the
/// per-VM directory with the host metadata every backend writes; the file
/// sets are disjoint (`fc.*`, `run-info.json` vs pid/console/socket files).
///
/// Returns `None` when the mvm root cannot be resolved (neither `MVM_HOME`
/// nor `$HOME` set — e.g. hermetic test environments that intentionally
/// omit them).
pub fn fc_pid_path(name: &str) -> Option<std::path::PathBuf> {
    mvm_core::config::mvm_home_strict().ok()?;
    Some(mvm_core::config::vm_state_dir(name).join("fc.pid"))
}

/// Path to the host-side UDS that proxies the guest agent's vsock port for a
/// Firecracker VM whose per-VM directory is `dir` (as returned by
/// [`resolve_running_vm_dir`]). `pub` so CLI-layer callers — e.g. the FC fork
/// path delivering a post-restore grant to a forked child — can locate the
/// same socket used by the verified snapshot restore paths, without
/// reimplementing the layout.
pub fn firecracker_vsock_uds_path(dir: &str) -> String {
    format!("{dir}/runtime/v.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_vsock_uds_lives_under_vm_runtime_dir() {
        assert_eq!(
            firecracker_vsock_uds_path("/builder/vms/vm-a"),
            "/builder/vms/vm-a/runtime/v.sock"
        );
    }

    #[test]
    fn resolve_running_vm_dir_expands_host_side() {
        // Must resolve the vms root on the host, never shelling into the VM:
        // this sits on the agent-reachability poll, and a `run_in_vm` here wakes
        // the macOS dev VM. (The old in-VM `echo` returned Err in a test env with
        // no dev VM reachable.)
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", "/custom/root");
        assert_eq!(
            resolve_running_vm_dir("my-vm").unwrap(),
            "/custom/root/vms/my-vm",
        );
    }

    /// Verify the log-and-continue error policy works: when a cleanup
    /// operation returns Err, the enclosing function should NOT propagate it.
    /// This tests the log-and-continue pattern used throughout the codebase.
    #[test]
    fn test_log_and_continue_pattern_does_not_propagate_errors() {
        use crate::base::shell_mock;

        // Install a mock that fails for all commands.
        let _guard = shell_mock::install_handler(|_script: &str| shell_mock::MockResponse {
            exit_code: 1,
            stdout: String::new(),
        });

        // Simulate the log-and-continue pattern used in cleanup paths.
        // This is the exact pattern from instance/lifecycle.rs, microvm.rs, etc.
        fn cleanup_with_log_and_continue() -> anyhow::Result<()> {
            // These operations would fail (mock returns exit code 1),
            // but run_in_vm returns Ok(output) — the error is in exit status.
            // The real pattern: if let Err(e) = operation() { warn!(...) }
            if let Err(e) = crate::base::shell::run_in_vm("kill -9 12345 2>/dev/null || true") {
                tracing::warn!("failed to kill process: {e}");
            }
            if let Err(e) = crate::base::shell::run_in_vm("rm -rf /tmp/test-dir") {
                tracing::warn!("failed to remove directory: {e}");
            }

            // The function should still succeed.
            Ok(())
        }

        let result = cleanup_with_log_and_continue();
        assert!(
            result.is_ok(),
            "log-and-continue cleanup must not propagate errors: {:?}",
            result.err()
        );
    }
}
