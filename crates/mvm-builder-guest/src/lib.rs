//! What runs inside the builder VM, and the contract it shares with the host
//! that boots it.
//!
//! The binaries here (`mvm-host-vm-init`, `mvm-builderd`, `stage0-init`) are
//! cross-compiled to static musl and embedded in `mvmctl`. This crate holds
//! them and exactly the modules they and the host both read, so that build
//! compiles a small closure. `mvm-build` re-exports every module under its
//! old path.

pub mod builder_boot;
pub mod builder_guest_paths;
pub mod host_payload_manifest;
pub mod stage0_guest;

#[cfg(unix)]
pub mod builder_agent_uid;
#[cfg(unix)]
pub mod builder_disk_transport;
#[cfg(unix)]
pub mod builder_job_contract;
#[cfg(unix)]
pub mod builder_protocol;
#[cfg(unix)]
pub mod builderd;
#[cfg(unix)]
pub mod builderd_protocol;
#[cfg(unix)]
pub mod egress_readiness;
#[cfg(unix)]
pub mod rootfs_inject;
#[cfg(unix)]
pub mod seed_store_entries;
#[cfg(unix)]
pub mod store_readiness;
