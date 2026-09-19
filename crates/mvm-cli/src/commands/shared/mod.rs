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
mod state;
mod vcpu_default;
mod vsock;

pub(super) use build_mode::BuildModeFlags;
pub(super) use event::PhaseEvent;
pub(super) use format::{human_age_secs, human_bytes};
pub(super) use hints::with_hints;
pub(in crate::commands) use mvm_client::admission::run_grants::{GrantInputs, resolve_run_grants};
pub(super) use mvm_client::admission::run_network::{
    parse_run_network_preset, resolve_ai_policy, resolve_run_network_policy,
    resolve_run_network_policy_with_preset_and_peers,
};
pub(super) use mvm_client::launch::machine_start::resolve_effective_hypervisor;
pub(crate) use parse::AssetSpec;
pub(crate) use parse::materialize_disk_volume;
pub(crate) use parse::{DirShareSpec, parse_dir_share_spec};
pub(super) use parse::{
    VolumeSpec, clap_flake_ref, clap_port_spec, clap_vm_name, clap_volume_spec, parse_asset_spec,
    parse_volume_spec, validate_volume_spec, vm_volume_from_spec_validated,
};
pub(in crate::commands) use parse::{parse_output_spec, resolve_output_destination};
pub(super) use resolve::{
    ManifestArgRef, egress_enforcement_label, resolve_flake_ref, resolve_manifest_arg,
};
pub(super) use state::{CHILD_PIDS, IN_CONSOLE_MODE};
pub(crate) use vcpu_default::default_vcpus;
pub(super) use vsock::{emit_vsock_rpc_audit, wait_for_guest_agent};
