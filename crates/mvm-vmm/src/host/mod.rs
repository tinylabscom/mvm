//! Host-side helpers that concrete VMM backends and the builder VM share.
//!
//! Keeping these helpers in `mvm-vmm` lets `mvm-backends` depend on them
//! without creating a dependency cycle with `mvm-runtime` or `mvm-build`.

pub mod audit_substrate;
pub mod aux_bin;
pub mod boot_config;
pub mod broker_services_spawn;
pub mod cmdline;
pub mod console_capture;
pub mod drive_file;
pub mod egress_bridge;
pub mod egress_redirect;
pub mod egress_shared;
pub mod fc_kernel;
pub mod host_agent_spawn;
pub mod hvf_supervisor;
pub mod netd_spawn;
pub mod observability_target;
pub mod process_liveness;
pub mod runtime_meta;
pub mod snapshot_upper;
pub mod spec_map;
pub mod substitution_spawn;
pub mod ui;
pub mod virtiofsd;
pub mod workload_wait;
