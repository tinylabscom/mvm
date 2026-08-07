//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.

pub mod fc;
pub mod libkrun;
pub mod qemu;
pub mod spec;
pub mod traits;

pub use fc::FcDriver;
pub use libkrun::LibkrunDriver;
pub use qemu::QemuDriver;
pub use spec::{
    BlockDev, ConsoleCapture, KernelImage, VirtioFsShare, VmmSpec, VsockDirection, VsockPort,
};
pub use traits::{
    ChildForkRequest, DuplexStream, PreloadChildRequest, PreloadedChild, RunningVm,
    StandbyParentSpawn, VmmDriver,
};

#[cfg(any(test, feature = "test-support"))]
pub use mvm_backends::mock::{MockDriver, MockRunningVm};
