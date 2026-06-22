//! Shared host-side readiness milestone emission.
//!
//! Every `mvmctl` subcommand that observes a VM-lifecycle milestone
//! the user might want to see in `mvmctl ls/ps --json` ends up here.
//! The function is intentionally best-effort: readiness is
//! observability, never gating, so registry I/O failures and
//! unregistered VMs degrade silently with a `tracing::warn` /
//! `tracing::debug` rather than aborting the launch or shutdown.

use mvm_core::domain::instance::InstanceReadiness;

/// Persist a host-observed readiness milestone on the VM's registry
/// entry. Best-effort:
///
/// - If the registry can't be loaded or saved → `tracing::warn` and
///   return without bubbling the error.
/// - If the VM has no registry entry (the launchd-spawned direct-boot
///   path doesn't always register) → `tracing::debug` and return.
/// - If the registry update itself fails → `tracing::warn`.
///
/// Callers must never rely on this function to gate launch/teardown
/// — readiness is a downstream display signal, not a control flow.
pub(super) fn record_vm_readiness(vm_name: &str, readiness: InstanceReadiness) {
    let path = mvm::vm::name_registry::registry_path();
    let mut reg = match mvm::vm::name_registry::VmNameRegistry::load(&path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                err = %e,
                vm = vm_name,
                "failed to load VM name registry for readiness update"
            );
            return;
        }
    };
    let now = mvm_core::time::utc_now();
    match reg.set_readiness(vm_name, readiness, &now) {
        Ok(true) => {}
        Ok(false) => {
            tracing::debug!(
                vm = vm_name,
                "no registry entry for readiness update; skipping"
            );
            return;
        }
        Err(e) => {
            tracing::warn!(err = %e, vm = vm_name, "failed to set readiness");
            return;
        }
    }
    if let Err(e) = reg.save(&path) {
        tracing::warn!(err = %e, vm = vm_name, "failed to save VM name registry");
    }
}
