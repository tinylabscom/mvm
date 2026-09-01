//! The workload role layer: maps an admitted `VmStartConfig` onto the
//! backend-agnostic `VmmSpec` a `VmmDriver` boots, and (in later slices) owns
//! the security wiring — plan admission, the host-side vsock egress bridge, and
//! audit. This module holds the pure, driver-independent pieces of that mapping
//! so they are unit-testable without a hypervisor.

pub mod claim;
pub mod console_stream;
pub mod runner;

pub use child_grant::ChildGrantIssuer;
pub use console_stream::{
    active_console_streamer, console_streamer_installed, install_console_streamer,
};
mod child_grant;
mod standby_boot;

pub use runner::{
    BrokerGuard, BrokerRegisterRequest, BrokerRegistrar, ClaimContext, ConsoleCapture,
    ConsoleStreamer, FlowMuxIdentitySource, NetworkEndpointSpawnRequest, NetworkEndpointSpawner,
    NoopConsoleStreamer, PreloadContext, RealBrokerRegistrar, RealNetworkEndpointSpawner,
    SpawnContext, SpawnedEndpoint, StopTiming, WorkloadLaunchInputs, WorkloadRunner,
};
pub use standby_boot::{factory_parent_config, factory_parent_spec};

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
    mvm_vmm::host::cmdline::runner_cmdline(config, state_dir, |has_disk| {
        driver.workload_base_bootargs(has_disk)
    })
}
