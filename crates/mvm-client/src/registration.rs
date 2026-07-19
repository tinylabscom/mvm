//! Name-registry registration for locally-booted machines.
//!
//! Registering a booted VM in the host name registry is a host-local write, so
//! — like [`crate::record_readiness`] — it lives on the client boundary crate
//! (which owns the reach into the registry) rather than as an async `MvmClient`
//! trait method. The CLI hands an owned, path-free [`MachineRegistration`] and
//! this performs the load → deregister-stale → register → save cycle.
//!
//! In the eventual boot-behind-the-facade stage this call moves *inside*
//! `LocalBackend`'s run path (registration becomes part of booting, mirroring
//! how stop deregisters); until then it is the seam that keeps the CLI off
//! `mvm_runtime::vm::name_registry`.

use std::collections::BTreeMap;

/// Owned registration intent for a locally-booted machine — the mirror of the
/// registry's borrowed `RegisterParams`, with no host handles so a caller
/// assembles it without naming the runtime crate.
pub struct MachineRegistration {
    pub name: String,
    pub vm_dir: String,
    pub network: String,
    pub guest_ip: Option<String>,
    pub slot_index: u8,
    pub tags: BTreeMap<String, String>,
    pub expires_at: Option<String>,
    pub auto_resume: bool,
}

impl MachineRegistration {
    /// The common shape: no tags, no TTL, `auto_resume = true`.
    pub fn minimal(name: impl Into<String>, network: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            vm_dir: String::new(),
            network: network.into(),
            guest_ip: None,
            slot_index: 0,
            tags: BTreeMap::new(),
            expires_at: None,
            auto_resume: true,
        }
    }
}

/// Register (or re-register) a machine in the host name registry. Best-effort:
/// a registry it can't load or save degrades silently — registration is boot
/// bookkeeping, not a launch gate. A stale entry under the same name is
/// dropped first so re-registration is idempotent.
pub fn register_machine(reg: &MachineRegistration) {
    let path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm_runtime::vm::name_registry::VmNameRegistry::load(&path) {
        registry.deregister(&reg.name);
        let _ = registry.register_with_metadata(mvm_runtime::vm::name_registry::RegisterParams {
            name: &reg.name,
            vm_dir: &reg.vm_dir,
            network: &reg.network,
            guest_ip: reg.guest_ip.as_deref(),
            slot_index: reg.slot_index,
            tags: reg.tags.clone(),
            expires_at: reg.expires_at.clone(),
            auto_resume: reg.auto_resume,
        });
        let _ = registry.save(&path);
    }
}
