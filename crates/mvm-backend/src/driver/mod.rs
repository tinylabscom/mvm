//! The `VmmDriver` seam: VMM mechanics written once per VMM, with role policy
//! (workload admission/egress/audit, builder orchestration) living in the role
//! runners above it.

pub mod inhouse;
pub mod mock;
pub mod spec;
pub mod traits;

pub use inhouse::InHouseDriver;
pub use mock::{MockDriver, MockRunningVm};
pub use spec::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};
pub use traits::{DuplexStream, RunningVm, VmmDriver};
