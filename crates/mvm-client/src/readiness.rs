//! Host-observed readiness milestones.
//!
//! Recording a readiness milestone is best-effort local observability, not a
//! machine-lifecycle operation: a remote fleet's daemon records its own
//! milestones, so this is a sync free function on the client boundary rather
//! than an `MvmClient` trait method (whose async, remote-capable shape would be
//! an impedance mismatch for a purely-local registry write). It lives here so
//! the CLI reaches the host name registry through the client crate instead of
//! naming `mvm-runtime` internals directly.

use mvm_core::domain::instance::InstanceReadiness;

/// Persist a host-observed readiness milestone on the VM's name-registry entry.
///
/// Best-effort: an unregistered VM or a registry I/O error degrades to a log
/// line inside the registry helper, never an error here — readiness is a
/// display signal for `mvmctl ls/ps --json`, never a control-flow gate.
pub fn record_readiness(vm_name: &str, readiness: InstanceReadiness) {
    mvm_runtime::vm::name_registry::record_readiness(vm_name, readiness);
}

/// Read a machine's last-recorded readiness milestone from the name registry —
/// the read counterpart to [`record_readiness`]. `None` if the machine has no
/// registry entry or no recorded milestone. Best-effort: a registry that can't
/// be loaded reads as `None`.
pub fn readiness_of(vm_name: &str) -> Option<InstanceReadiness> {
    let path = mvm_runtime::vm::name_registry::registry_path();
    let registry = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).ok()?;
    registry.lookup(vm_name).and_then(|reg| reg.readiness.clone())
}
