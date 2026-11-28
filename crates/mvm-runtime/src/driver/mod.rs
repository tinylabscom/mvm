//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.
//!
//! The concrete driver implementations now live in `mvm-vmm`; this module
//! is a compatibility re-export layer while downstream callers migrate.

#[cfg(test)]
mod fc_orchestration_tests;

pub use mvm_vmm::driver::FcDriver;
pub use mvm_vmm::driver::{HvfDriver, LibkrunDriver, QemuDriver};
// The modules as well as the types: callers reach in for driver-local helpers
// (`driver::libkrun::map_kernel_for_test`), so re-exporting only the driver
// types leaves those paths unresolvable.
pub use mvm_vmm::driver::spec::{
    BlockDev, ConsoleCapture, KernelImage, VirtioFsShare, VmmSpec, VsockDirection, VsockPort,
};
pub use mvm_vmm::driver::traits::{
    ChildForkRequest, DuplexStream, LateVolumeAttach, PreloadChildRequest, PreloadedChild,
    PreloadedResumeError, RunningVm, RunningVmStopTiming, StandbyParentSpawn, VmmDriver,
};
pub use mvm_vmm::driver::{fc, hvf, libkrun, qemu};

#[cfg(any(test, feature = "test-support"))]
pub use mvm_vmm::mock::{MockDriver, MockRunningVm};
