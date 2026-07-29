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
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::{MvmError, Result};

/// Path to the host-local VM name registry file.
///
/// Exposed so low-level pool / standby substrates can pass the registry path
/// into runtime claim runners without the CLI naming `mvm_runtime` internals.
pub fn name_registry_path() -> PathBuf {
    mvm_runtime::vm::name_registry::registry_path()
}

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

/// A registry entry whose VM is not currently live — a GC candidate.
pub struct StaleRegistration {
    pub name: String,
    /// The entry's TTL had already passed at the evaluation time.
    pub expired: bool,
}

/// Pure staleness policy: registry entries whose name is not in `live_names`,
/// sorted by name, tagged `expired` when their TTL parses and is before `now`.
fn stale_candidates<'a>(
    entries: impl Iterator<Item = (&'a str, Option<&'a str>)>,
    live_names: &BTreeSet<String>,
    now_rfc3339: &str,
) -> Vec<StaleRegistration> {
    let now = mvm_core::util::time::parse_iso8601(now_rfc3339);
    let mut stale: Vec<StaleRegistration> = entries
        .filter(|(name, _)| !live_names.contains(*name))
        .map(|(name, expires_at)| {
            let expired = matches!(
                (expires_at.and_then(mvm_core::util::time::parse_iso8601), now),
                (Some(exp), Some(n)) if exp < n
            );
            StaleRegistration {
                name: name.to_string(),
                expired,
            }
        })
        .collect();
    stale.sort_by(|a, b| a.name.cmp(&b.name));
    stale
}

/// Garbage-collect stale name-registry entries: those whose VM is not in
/// `live_names`. Returns them sorted by name (each tagged `expired`). When
/// `apply`, also deregisters them and saves. A registry that can't be loaded or
/// saved is an error — GC over an unreadable registry must not look like a
/// silent no-op.
pub fn gc_stale_registrations(
    live_names: &BTreeSet<String>,
    now_rfc3339: &str,
    apply: bool,
) -> Result<Vec<StaleRegistration>> {
    let path = mvm_runtime::vm::name_registry::registry_path();
    let mut registry =
        mvm_runtime::vm::name_registry::VmNameRegistry::load(&path).map_err(|e| {
            MvmError::Backend {
                reason: format!("loading VM name registry at {}: {e}", path.display()),
            }
        })?;
    let stale = stale_candidates(
        registry
            .vms
            .iter()
            .map(|(n, r)| (n.as_str(), r.expires_at.as_deref())),
        live_names,
        now_rfc3339,
    );
    if apply {
        for s in &stale {
            registry.deregister(&s.name);
        }
        registry.save(&path).map_err(|e| MvmError::Backend {
            reason: format!("saving VM name registry at {}: {e}", path.display()),
        })?;
    }
    Ok(stale)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries_from(rows: &[(String, Option<String>)]) -> Vec<(&str, Option<&str>)> {
        rows.iter()
            .map(|(n, e)| (n.as_str(), e.as_deref()))
            .collect()
    }

    const NOW: &str = "2026-01-01T00:00:00Z";
    const PAST: &str = "2020-01-01T00:00:00Z";
    const FUTURE: &str = "2100-01-01T00:00:00Z";

    #[test]
    fn live_vm_is_not_a_candidate() {
        let rows = vec![("live".to_string(), None)];
        let live = BTreeSet::from(["live".to_string()]);
        let stale = stale_candidates(entries_from(&rows).into_iter(), &live, NOW);
        assert!(stale.is_empty());
    }

    #[test]
    fn stopped_entry_without_ttl_is_a_candidate_not_expired() {
        let rows = vec![("stopped".to_string(), None)];
        let stale = stale_candidates(entries_from(&rows).into_iter(), &BTreeSet::new(), NOW);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].name, "stopped");
        assert!(!stale[0].expired);
    }

    #[test]
    fn stopped_entry_with_past_ttl_is_expired() {
        let rows = vec![("expired".to_string(), Some(PAST.to_string()))];
        let stale = stale_candidates(entries_from(&rows).into_iter(), &BTreeSet::new(), NOW);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].name, "expired");
        assert!(stale[0].expired);
    }

    #[test]
    fn stopped_entry_with_future_ttl_is_not_expired() {
        let rows = vec![("pending".to_string(), Some(FUTURE.to_string()))];
        let stale = stale_candidates(entries_from(&rows).into_iter(), &BTreeSet::new(), NOW);
        assert_eq!(stale.len(), 1);
        assert!(!stale[0].expired);
    }

    #[test]
    fn candidates_are_sorted_by_name() {
        let rows = vec![
            ("charlie".to_string(), None),
            ("alpha".to_string(), None),
            ("bravo".to_string(), None),
        ];
        let stale = stale_candidates(entries_from(&rows).into_iter(), &BTreeSet::new(), NOW);
        let names: Vec<&str> = stale.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["alpha", "bravo", "charlie"]);
    }
}
