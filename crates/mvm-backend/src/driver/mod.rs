//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.

pub mod spec;

pub use spec::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};
