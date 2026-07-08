use anyhow::Result;

pub(in crate::commands) const DEV_VM_NAME: &str = super::dev_vm_legacy::DEV_VM_NAME;

pub(in crate::commands) use super::dev_vm_legacy::{
    DevBaseRef, KernelVariant, ReapOutcome, Stage0SweepOutcome, build_dev_down_json,
    build_dev_status_json, build_dev_status_json_linux_native, build_dev_status_json_vmless,
    build_dev_up_json, build_kernel_via_stage0, cmd_dev_cache_inspect, cmd_dev_import_image,
    ensure_default_microvm_image, ensure_dev_image, ensure_workload_kernel,
    find_builder_vm_flake_is_source_checkout,
};

pub(in crate::commands) fn is_dev_vm_running() -> bool {
    super::dev_vm_legacy::is_dev_vm_running_legacy()
}

pub(in crate::commands) fn dev_vsock_proxy_path() -> String {
    super::dev_vm_legacy::dev_vsock_proxy_path()
}

pub(in crate::commands) fn cmd_dev_vm_down(json: bool, reset: bool) -> Result<bool> {
    super::dev_vm_legacy::cmd_dev_vm_down_legacy(json, reset)
}

pub(in crate::commands) fn bootstrap_builder_vm_image() -> Result<()> {
    super::dev_vm_legacy::bootstrap_builder_vm_image()
}

pub(in crate::commands) fn stage0_bootstrap_in_flight() -> bool {
    super::dev_vm_legacy::stage0_bootstrap_in_flight()
}

pub(in crate::commands) fn sweep_orphaned_stage0_staging_dirs(
    dry_run: bool,
) -> Result<Stage0SweepOutcome> {
    super::dev_vm_legacy::sweep_orphaned_stage0_staging_dirs(dry_run)
}

pub(in crate::commands) fn reap_orphaned_vm_helpers(dry_run: bool) -> Result<ReapOutcome> {
    super::dev_vm_legacy::reap_orphaned_vm_helpers(dry_run)
}

pub(in crate::commands) fn sweep_orphaned_vm_helpers_on_startup() {
    super::dev_vm_legacy::sweep_orphaned_vm_helpers_on_startup();
}
