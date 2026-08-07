//! The `VmmDriver` seam re-exported from `mvm-vmm`.
//!
//! These types now live in the backend-agnostic seam crate so concrete backend
//! drivers can implement them without a dependency cycle with the workload
//! lifecycle orchestration in `mvm-runtime`.

pub use mvm_vmm::driver::traits::{
    ChildForkRequest, DuplexStream, PreloadChildRequest, PreloadedChild, RunningVm,
    StandbyParentSpawn, VmmDriver,
};
