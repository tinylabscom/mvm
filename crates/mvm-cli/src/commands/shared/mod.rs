//! Shared helpers used by multiple `commands/*` submodules.
//!
//! Each submodule owns one focused concern. `mod.rs` re-exports the public
//! surface so call sites can keep using `super::shared::clap_vm_name` etc.

mod build_mode;
mod drive;
mod event;
mod format;
mod hints;
mod parse;
mod resolve;
mod start;
mod state;
mod vsock;

pub(super) use build_mode::BuildModeFlags;
pub(super) use drive::{env_vars_to_drive_file, ports_to_drive_file, read_dir_to_drive_files};
pub(super) use event::PhaseEvent;
pub(super) use format::{human_age_secs, human_bytes};
pub(super) use hints::with_hints;
pub(super) use parse::{
    VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
    materialize_disk_volume, materialize_disk_volumes, merge_volume_specs, parse_port_spec,
    parse_port_specs, parse_secret_bindings, parse_volume_spec, vm_volume_from_spec_validated,
};
pub(super) use resolve::{
    ManifestArgRef, resolve_effective_hypervisor, resolve_flake_ref, resolve_manifest_arg,
    resolve_network_policy, resolve_running_vm,
};
pub(super) use start::VmStartParams;
pub(super) use state::{CHILD_PIDS, IN_CONSOLE_MODE};
pub(super) use vsock::{
    emit_vsock_rpc_audit, request_port_forward, start_port_proxy, wait_for_guest_agent,
};
