//! Internal admission and boot helpers consumed by `machine/mod.rs`:
//! `start_persistent_oci_machine`, `admit_plan_for_boot`, `AdmitPlanForBootParams`,
//! `AdmissionContext`, `emit_launched`, `emit_failed`,
//! `persists_plan_before_start`, `resolve_workload_kernel`, and
//! workload runtime-source resolution.

mod kernel;

pub(super) use mvm_client::admission::{
    AdmissionContext, AdmitPlanForBootParams, admit_plan_for_boot,
    attach_guest_boot_config_for_plan, close_transient_session, emit_failed, emit_launched,
    guest_profile_for_boot, record_transient_launch,
};

pub(in crate::commands) use kernel::resolve_kernel_pin_path;
pub(super) use kernel::resolve_workload_kernel;

pub(crate) use mvm_client::launch::persistent::{
    persistent_oci_effective_initrd, persists_plan_before_start,
};

pub(crate) use mvm_client::launch::runtime_source::{
    SdkSidecarAttachment, attach_runtime_overlay_if_cached_version,
    attach_universal_initramfs_if_cached, emit_runtime_source_status,
    resolve_sdk_sidecar_attachment_for_host,
};
