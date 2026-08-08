//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.
//!
//! The concrete driver implementations now live in `mvm-backends`; this module
//! is a compatibility re-export layer while downstream callers migrate.

pub mod fc;
pub mod spec;
pub mod traits;

pub use fc::FcDriver;
pub use mvm_backends::driver::{HvfDriver, LibkrunDriver, QemuDriver};
pub use spec::{
    BlockDev, ConsoleCapture, KernelImage, VirtioFsShare, VmmSpec, VsockDirection, VsockPort,
};
pub use traits::{
    ChildForkRequest, DuplexStream, PreloadChildRequest, PreloadedChild, RunningVm,
    StandbyParentSpawn, VmmDriver,
};

#[cfg(any(test, feature = "test-support"))]
pub use mvm_backends::mock::{MockDriver, MockRunningVm};
