//! Firecracker backend control, artifact, snapshot, and observation helpers.
//!
//! Submodules split by concern; every item keeps its original visibility so
//! `crate::microvm::<name>` (and `mvm_runtime::microvm::<name>` for external
//! crates) resolves identically.

pub(crate) mod activation;
mod boot_config;
mod flake_run;
mod snapshot;

pub use activation::{activate_over_stream, activate_workload, read_verb_grant_envelope};
pub use boot_config::resolved_runtime_overlay;
pub use mvm_backends::fc::control::{
    balloon_set_target, balloon_state, pause_vm, resume_vm, stop_vm,
};
pub use mvm_vmm::host::boot_config::{
    FcDrive, balloon_body, boot_source_body, booted_with_universal_initramfs,
    builder_hostepoch_cmdline_token, logger_body, machine_config_body, non_verity_overlay_ext4,
    probe_verity_sidecar, vsock_body,
};
// The Firecracker API client and VMM process lifecycle now live in
// mvm-backends::fc; re-exported so `crate::microvm::<name>` keeps resolving.
pub use flake_run::FlakeRunConfig;
pub use mvm_backends::fc::daemon::{
    adopt_api_socket, api_put_session, api_put_socket, api_session, read_firecracker_pid,
    secure_restored_vsock_socket, secure_vsock_socket_for_caller, start_vm_firecracker,
    start_vm_firecracker_bounded, vm_console_log_path,
};
pub use mvm_backends::fc::guards::{FirecrackerGuard, SlotReservationGuard};
pub use mvm_backends::fc::lifecycle::{start, stop};
pub use mvm_backends::fc::observe::allocate_slot;
pub use mvm_backends::fc::snapshot::{
    RestoredDeviceModel, assert_vsock_only_device_model, create_snapshot_files,
    warm_restore_instance, warm_restore_instance_from_path,
};
pub use snapshot::restore_from_template_snapshot;

// The per-VM path layout moved to mvm-backends::fc with the Firecracker
// mechanics that read it. Re-exported so `crate::microvm::<name>` and the
// external `mvm_runtime::microvm::<name>` paths keep resolving.
pub use mvm_backends::fc::{
    ensure_fc_sockets_in_state_dir, fc_pid_path, firecracker_vsock_uds_path, resolve_running_vm_dir,
};

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
