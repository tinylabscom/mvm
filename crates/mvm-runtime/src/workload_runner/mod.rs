//! The workload role layer: maps an admitted `VmStartConfig` onto the
//! backend-agnostic `VmmSpec` a `VmmDriver` boots, and (in later slices) owns
//! the security wiring — plan admission, the host-side vsock egress bridge, and
//! audit. This module holds the pure, driver-independent pieces of that mapping
//! so they are unit-testable without a hypervisor.

pub mod runner;
pub mod spec_map;

pub use runner::{
    EndpointSpawnRequest, EndpointSpawner, RealEndpointSpawner, WorkloadLaunchInputs,
    WorkloadRunner,
};
pub use spec_map::{
    WorkloadSockets, WorkloadSpecInputs, workload_blocks, workload_spec, workload_vsock_ports,
};
