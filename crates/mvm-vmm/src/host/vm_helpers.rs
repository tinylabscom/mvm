//! The host processes and registrations a workload VM holds beside its VMM.
//!
//! A workload VM is more than the process that runs it: depending on its plan
//! it has a network endpoint, a GPU endpoint, a host-services broker, and a
//! registration with the tenant's host agent. Stopping the VM has to release
//! all of them, and two different processes stop a VM: the `stop` path, which
//! a client runs, and a per-VM supervisor that stops its own guest when a
//! bound it enforces runs out. Both release through [`reap_vm_host_helpers`],
//! so a VM stopped either way leaves the same host state behind.

use std::path::Path;

/// Release every host-side helper recorded in `state_dir` for `vm_name`.
///
/// Best-effort and idempotent: each helper that was never started, or has
/// already gone, is a no-op, so a caller need not know which ones the VM's
/// plan asked for.
pub fn reap_vm_host_helpers(state_dir: &Path, vm_name: &str) {
    super::network_endpoint_spawn::reap_network_endpoint(state_dir, vm_name);
    super::gpu_endpoint_spawn::reap_gpu_endpoint(state_dir);
    super::broker_services_spawn::reap_broker_services(state_dir);
    super::host_agent_spawn::reap_host_agent_services_from_state(state_dir, vm_name);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vm_that_started_no_helpers_reaps_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        reap_vm_host_helpers(dir.path(), "vm-plain");
        reap_vm_host_helpers(dir.path(), "vm-plain");
    }

    #[test]
    fn the_network_endpoint_a_vm_started_is_stopped_and_forgotten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut endpoint = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in endpoint");
        let pid_file = dir
            .path()
            .join(super::super::network_endpoint_spawn::SUBST_PID_FILE);
        std::fs::write(&pid_file, endpoint.id().to_string()).expect("record its pid");

        reap_vm_host_helpers(dir.path(), "vm-with-endpoint");

        let status = endpoint.wait().expect("the endpoint is reaped");
        assert!(
            !status.success(),
            "the endpoint is signalled, not left running"
        );
        assert!(!pid_file.exists(), "its pid file goes with it");
    }
}
