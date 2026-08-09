//! Firecracker backend control, artifact, snapshot, and observation helpers.
//!
//! Submodules split by concern; every item keeps its original visibility so
//! `crate::microvm::<name>` (and `mvm_runtime::microvm::<name>` for external
//! crates) resolves identically to before the split.

mod activation;
mod boot_config;
mod flake_run;
mod run_info;
mod snapshot;

pub(crate) use activation::read_verb_grant_envelope;
pub use activation::*;
pub use boot_config::*;
pub use mvm_backends::fc::control::*;
// The Firecracker API client and VMM process lifecycle now live in
// mvm-backends::fc; re-exported so `crate::microvm::<name>` keeps resolving.
pub use flake_run::*;
pub use mvm_backends::fc::daemon::*;
pub use mvm_backends::fc::guards::*;
pub use mvm_backends::fc::lifecycle::*;
pub use mvm_backends::fc::observe::*;
pub use mvm_backends::fc::snapshot::*;
pub use run_info::*;
pub use snapshot::*;

// The per-VM path layout moved to mvm-backends::fc with the Firecracker
// mechanics that read it. Re-exported so `crate::microvm::<name>` and the
// external `mvm_runtime::microvm::<name>` paths keep resolving.
pub(crate) use mvm_backends::fc::abs_vms_dir;
pub use mvm_backends::fc::{fc_pid_path, firecracker_vsock_uds_path, resolve_running_vm_dir};

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
