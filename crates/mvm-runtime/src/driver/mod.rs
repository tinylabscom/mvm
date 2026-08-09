//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.
//!
//! The concrete driver implementations now live in `mvm-backends`; this module
//! is a compatibility re-export layer while downstream callers migrate.

#[cfg(test)]
mod fc_orchestration_tests;
pub mod spec;
pub mod traits;

pub use mvm_backends::driver::FcDriver;
pub use mvm_backends::driver::{HvfDriver, LibkrunDriver, QemuDriver};
// The modules as well as the types: callers reach in for driver-local helpers
// (`driver::libkrun::map_kernel_for_test`), so re-exporting only the driver
// types leaves those paths unresolvable.
pub use mvm_backends::driver::{fc, hvf, libkrun, qemu};
pub use spec::{
    BlockDev, ConsoleCapture, KernelImage, VirtioFsShare, VmmSpec, VsockDirection, VsockPort,
};
pub use traits::{
    ChildForkRequest, DuplexStream, PreloadChildRequest, PreloadedChild, RunningVm,
    StandbyParentSpawn, VmmDriver,
};

#[cfg(any(test, feature = "test-support"))]
pub use mvm_backends::mock::{MockDriver, MockRunningVm};
