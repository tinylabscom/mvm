//! Wire-stable event name and label keys for what bounded a workload, and for a
//! memory ceiling that fired.
//!
//! Shared so the launch path, the supervisor and any reader asserting on an
//! entry cannot drift on a string.

use mvm_contract::protocol::resource_controls::{EnforcedCeiling, EnforcedGrants};

/// Label: the mechanism that bounded CPU.
pub const LABEL_CPU_TIER: &str = "grants_cpu_tier";
/// Label: the mechanism that bounded wall clock.
pub const LABEL_WALL_CLOCK_TIER: &str = "grants_wall_clock_tier";
/// Label: the mechanism holding the VMM's memory ceiling.
pub const LABEL_MEMORY_TIER: &str = "grants_memory_tier";
/// Label: the memory ceiling read back, in bytes. Absent when declared.
pub const LABEL_MEMORY_MAX_BYTES: &str = "grants_memory_max_bytes";
/// Label: the mechanism holding the VMM's task ceiling.
pub const LABEL_TASKS_TIER: &str = "grants_tasks_tier";
/// Label: the task ceiling read back. Absent when declared.
pub const LABEL_TASKS_MAX: &str = "grants_tasks_max";

/// Emitted when the kernel killed a workload's VMM for crossing its memory
/// ceiling.
pub const MEMORY_LIMIT_EXCEEDED_EVENT: &str = "plan.memory_limit_exceeded";
/// Label: the ceiling the scope carried, in bytes, when it reported one.
pub const LABEL_KILLED_AT_BYTES: &str = "memory_max_bytes";
/// Label: which mechanism killed it.
pub const LABEL_ENFORCED_BY: &str = "enforced_by";

/// The labels naming what bounded each dimension, and the ceiling values read
/// back where a ceiling holds.
///
/// Tiers and read-back values, never requested numbers: a run that asked for
/// 1.5 cores and got nothing must not leave a record that mentions 1.5 cores,
/// or the audit trail asserts an enforcement that did not happen.
#[must_use]
pub fn enforced_grants_labels(enforced: &EnforcedGrants) -> Vec<(String, String)> {
    let mut labels = vec![
        (LABEL_CPU_TIER.to_string(), enforced.cpu.label().to_string()),
        (
            LABEL_WALL_CLOCK_TIER.to_string(),
            enforced.wall_clock.label().to_string(),
        ),
    ];
    push_ceiling(
        &mut labels,
        LABEL_MEMORY_TIER,
        LABEL_MEMORY_MAX_BYTES,
        enforced.memory,
    );
    push_ceiling(
        &mut labels,
        LABEL_TASKS_TIER,
        LABEL_TASKS_MAX,
        enforced.tasks,
    );
    labels
}

fn push_ceiling(
    labels: &mut Vec<(String, String)>,
    tier_key: &str,
    value_key: &str,
    ceiling: EnforcedCeiling,
) {
    labels.push((tier_key.to_string(), ceiling.tier().label().to_string()));
    if let Some(limit) = ceiling.limit() {
        labels.push((value_key.to_string(), limit.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::protocol::resource_controls::EnforcedTier;

    fn label<'a>(labels: &'a [(String, String)], key: &str) -> Option<&'a str> {
        labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn enforced_ceilings_are_labelled_with_their_tier_and_read_back_value() {
        let labels = enforced_grants_labels(&EnforcedGrants {
            cpu: EnforcedTier::Declared,
            wall_clock: EnforcedTier::Declared,
            memory: EnforcedCeiling::enforced(EnforcedTier::Cgroup2MemoryMax, 805_306_368),
            tasks: EnforcedCeiling::enforced(EnforcedTier::Cgroup2PidsMax, 1024),
        });
        assert_eq!(
            label(&labels, LABEL_MEMORY_TIER),
            Some("cgroup2:memory.max")
        );
        assert_eq!(label(&labels, LABEL_MEMORY_MAX_BYTES), Some("805306368"));
        assert_eq!(label(&labels, LABEL_TASKS_TIER), Some("cgroup2:pids.max"));
        assert_eq!(label(&labels, LABEL_TASKS_MAX), Some("1024"));
    }

    #[test]
    fn a_declared_ceiling_is_named_but_carries_no_number() {
        // A number beside "declared" would read as a bound that held.
        let labels = enforced_grants_labels(&EnforcedGrants::all_declared());
        assert_eq!(label(&labels, LABEL_MEMORY_TIER), Some("declared"));
        assert_eq!(label(&labels, LABEL_TASKS_TIER), Some("declared"));
        assert_eq!(label(&labels, LABEL_MEMORY_MAX_BYTES), None);
        assert_eq!(label(&labels, LABEL_TASKS_MAX), None);
        assert_eq!(label(&labels, LABEL_CPU_TIER), Some("declared"));
        assert_eq!(label(&labels, LABEL_WALL_CLOCK_TIER), Some("declared"));
    }
}
