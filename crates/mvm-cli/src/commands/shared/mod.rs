//! Shared helpers used by multiple `commands/*` submodules.
//!
//! Each submodule owns one focused concern. `mod.rs` re-exports the public
//! surface so call sites can keep using `super::shared::clap_vm_name` etc.

mod drive;
mod event;
mod format;
mod hints;
mod parse;
mod resolve;
mod start;
mod state;
mod vsock;

pub(super) use drive::{env_vars_to_drive_file, ports_to_drive_file, read_dir_to_drive_files};
pub(super) use event::PhaseEvent;
pub(super) use format::{human_bytes, shell_escape};
pub(super) use hints::with_hints;
pub(super) use parse::{
    VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec, parse_port_spec,
    parse_port_specs, parse_volume_spec,
};
pub(super) use resolve::{
    TemplateArgRef, resolve_flake_ref, resolve_network_policy, resolve_optional_network_policy,
    resolve_running_vm, resolve_template_arg,
};
pub(super) use start::VmStartParams;
pub(super) use state::{CHILD_PIDS, IN_CONSOLE_MODE};
pub(super) use vsock::{request_port_forward, wait_for_guest_agent};
