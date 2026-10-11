//! Internal admission and boot helpers consumed by `machine/mod.rs`:
//! `start_persistent_oci_machine`, `admit_plan_for_boot`, `AdmitPlanForBootParams`,
//! `AdmissionContext`, `persists_plan_before_start`, and
//! workload runtime-source resolution.

pub(super) use mvm_client::admission::{
    AdmissionContext, AdmitPlanForBootParams, admit_plan_for_boot,
    attach_guest_boot_config_for_plan, guest_profile_for_boot,
};

pub(crate) use mvm_client::launch::persistent::{
    persistent_oci_effective_initrd, persists_plan_before_start,
};

pub(crate) use mvm_client::launch::runtime_source::{
    SdkSidecarAttachment, attach_runtime_overlay_if_cached_version,
    attach_universal_initramfs_if_cached, emit_runtime_source_status,
    resolve_sdk_sidecar_attachment_for_host,
};
