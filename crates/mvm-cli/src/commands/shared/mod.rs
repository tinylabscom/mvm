//! Shared helpers used by multiple `commands/*` submodules.
//!
//! Each submodule owns one focused concern. `mod.rs` re-exports the public
//! surface so call sites can keep using `super::shared::clap_vm_name` etc.

mod build_mode;
mod drive;
mod event;
mod format;
mod grants;
mod hints;
mod parse;
mod resolve;
mod start;
mod state;
mod vsock;

pub(super) use build_mode::BuildModeFlags;
pub(super) use event::PhaseEvent;
pub(super) use format::{human_age_secs, human_bytes};
pub(in crate::commands) use grants::{GrantInputs, enforced_network_policy, resolve_run_grants};
pub(super) use hints::with_hints;
pub(crate) use parse::{DirShareSpec, parse_dir_share_spec};
pub(super) use parse::{
    VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec,
    materialize_disk_volume, parse_port_spec, parse_volume_spec, vm_volume_from_spec_validated,
};
pub(super) use resolve::{
    ManifestArgRef, egress_enforcement_label, parse_peer_binding, resolve_effective_hypervisor,
    resolve_flake_ref, resolve_manifest_arg, resolve_run_network_policy,
    resolve_run_network_policy_with_peers,
};
pub(super) use start::VmStartParams;
pub(super) use state::{CHILD_PIDS, IN_CONSOLE_MODE};
pub(super) use vsock::{emit_vsock_rpc_audit, wait_for_guest_agent};
