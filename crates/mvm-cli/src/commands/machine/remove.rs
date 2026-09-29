//! `machine rm` target resolution and spec/runtime-state removal.
//!
//! Split out of `mod.rs` so the removal cluster (target resolution, the
//! running-machine refusal, and the spec + runtime-state deletion) lives
//! behind one small module; each piece is pure or filesystem-bound and
//! unit-tested in `tests.rs`.

use super::*;

#[derive(Debug, Serialize)]
pub(super) struct MachineRemoveSummary {
    pub(super) name: String,
    pub(super) removed: bool,
    /// Whether the runtime state under `vms/<name>/` went with the spec.
    ///
    /// Reported rather than assumed: a directory a live process still owns is
    /// kept, and a caller parsing this needs to be able to tell that apart from
    /// a complete removal.
    pub(super) runtime_state_removed: bool,
}

pub(super) fn remove_machine_runtime_state(name: &str) -> Result<bool> {
    let dir = config::vm_state_dir(name);
    if dir.exists() {
        if mvm_vmm::host::process_liveness::state_dir_has_live_process(&dir) {
            return Ok(false);
        }
        fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    let instance = config::instance_dir(name);
    if instance.exists() {
        fs::remove_dir_all(&instance)
            .with_context(|| format!("removing {}", instance.display()))?;
    }
    Ok(true)
}

pub(super) fn remove_machine_spec(name: &str, yes: bool) -> Result<MachineRemoveSummary> {
    validate_machine_name(name)?;
    if !yes {
        bail!("refusing to remove machine {:?} without --yes", name);
    }
    let dir = config::machine_state_dir(name);
    if !dir.exists() {
        bail!("machine {:?} does not exist", name);
    }
    fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    let runtime_state_removed = remove_machine_runtime_state(name)?;
    Ok(MachineRemoveSummary {
        name: name.to_string(),
        removed: true,
        runtime_state_removed,
    })
}

/// Resolve the concrete set of machine names a `rm` invocation targets. With
/// `--all` this is every persisted spec (already name-sorted); otherwise it is
/// the positional names, de-duplicated while preserving argument order.
pub(super) fn resolve_remove_targets(all: bool, names: &[String]) -> Result<Vec<String>> {
    if all {
        return Ok(list_machine_specs()?
            .into_iter()
            .map(|spec| spec.name)
            .collect());
    }
    let mut targets = Vec::with_capacity(names.len());
    for name in names {
        if !targets.contains(name) {
            targets.push(name.clone());
        }
    }
    Ok(targets)
}

/// Refusal message when `machine rm` targets running machines without
/// `--force`. Returns `None` when nothing is running (so removal proceeds).
/// Pure so the wording is unit-testable.
pub(super) fn rm_running_refusal(running: &[String]) -> Option<String> {
    if running.is_empty() {
        return None;
    }
    Some(format!(
        "refusing to remove running machine(s) {}: their VMs would be orphaned. \
         Stop them first (`mvmctl machine stop {}`), or pass `--force` to stop and remove.",
        running.join(", "),
        running.join(" ")
    ))
}
