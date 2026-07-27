//! The workload role layer: maps an admitted `VmStartConfig` onto the
//! backend-agnostic `VmmSpec` a `VmmDriver` boots, and (in later slices) owns
//! the security wiring — plan admission, the host-side vsock egress bridge, and
//! audit. This module holds the pure, driver-independent pieces of that mapping
//! so they are unit-testable without a hypervisor.

pub mod claim;
pub(crate) mod cmdline;
pub mod runner;
pub mod spec_map;

pub use runner::{
    BrokerGuard, BrokerRegisterRequest, BrokerRegistrar, ClaimContext, EndpointSpawnRequest,
    EndpointSpawner, RealBrokerRegistrar, RealEndpointSpawner, WorkloadLaunchInputs,
    WorkloadRunner,
};
pub use spec_map::{
    WorkloadSockets, WorkloadSpecInputs, ensure_no_dir_share_volumes, workload_blocks,
    workload_spec, workload_vsock_ports,
};

/// Assemble the exact runner cmdline for conformance tests without booting a
/// VM. This is feature-gated with the rest of the test-support surface so the
/// BDD suite can exercise the real driver seam and shared assembler while the
/// production library keeps that implementation detail private.
#[cfg(feature = "test-support")]
pub fn assemble_workload_cmdline_for_test(
    driver: &dyn crate::driver::VmmDriver,
    config: &mvm_core::vm_backend::VmStartConfig,
    state_dir: &std::path::Path,
) -> String {
    cmdline::runner_cmdline(config, state_dir, |virtiofs_root, has_disk| {
        driver.workload_base_bootargs(virtiofs_root, has_disk)
    })
}
