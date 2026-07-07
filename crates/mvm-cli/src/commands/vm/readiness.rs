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
    mvm::vm::name_registry::record_readiness(vm_name, readiness);
}
