//! Backend-agnostic VMM driver seam.
//!
//! The `VmmDriver` trait, `RunningVm` handle, and the backend-agnostic boot
//! recipe (`VmmSpec`) live here so concrete backends can be implemented in a
//! downstream crate without a dependency cycle with the workload lifecycle
//! orchestration in `mvm-runtime`.

pub mod spec;
pub mod traits;

pub use traits::{
    ChildForkRequest, DuplexStream, RunningVm, RunningVmStopTiming, StandbyParentSpawn, VmmDriver,
};
