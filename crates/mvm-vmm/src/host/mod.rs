//! Host-side helpers that concrete VMM backends and the builder VM share.
//!
//! Keeping these helpers in `mvm-vmm` lets `mvm-backends` depend on them
//! without creating a dependency cycle with `mvm-runtime` or `mvm-build`.

pub mod aux_bin;
pub mod boot_config;
pub mod console_capture;
pub mod broker_services_spawn;
pub mod drive_file;
pub mod egress_bridge;
pub mod egress_shared;
pub mod host_agent_spawn;
pub mod netd_spawn;
pub mod process_liveness;
pub mod substitution_spawn;
pub mod virtiofsd;
pub mod workload_wait;
