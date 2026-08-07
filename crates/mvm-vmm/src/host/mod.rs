//! Host-side helpers that concrete VMM backends and the builder VM share.
//!
//! Keeping these helpers in `mvm-vmm` lets `mvm-backends` depend on them
//! without creating a dependency cycle with `mvm-runtime` or `mvm-build`.

pub mod virtiofsd;
pub mod workload_wait;
