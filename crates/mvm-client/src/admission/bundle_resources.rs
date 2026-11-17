//! A signed bundle's recorded sizing as launch defaults.
//!
//! A bundle records the vCPUs and memory its publisher sized the workload for.
//! Those figures seed a launch that did not size itself, in the same narrow
//! shape the project manifest's launch defaults have: cpus and memory only.
//! They are defaults, never grants:
//!
//! - a value the caller named always wins;
//! - the host's per-workload memory ceiling and what is left of its host-wide
//!   budget cap what a default may take, and when the cap lowers what the
//!   bundle asked for, the plan's `plan.admitted` labels record both figures;
//! - nothing here widens authority. The types carry sizes and no other field.
//!
//! Only memory is capped. The host's CPU bounds are millicore shares of host
//! time, not a vCPU count, so a bundle's vCPU figure has nothing to be measured
//! against and is taken as recorded.
//!
//! A value the caller typed, or the environment descriptor recorded, is not
//! capped here: it reaches admission and is refused there exactly as before.

use std::collections::BTreeMap;

use mvm_contract::grants::budget::HostBudget;
use mvm_contract::grants::ceiling::GrantCeiling;
use mvm_core::plan::{BundleResources, EnvironmentDescriptor};

/// The sizing a bundle recorded, before any caller value or cap is applied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SizingDefaults {
    pub cpus: Option<u32>,
    pub memory_mib: Option<u32>,
}

impl SizingDefaults {
    /// The manifest's recorded resources.
    #[must_use]
    pub fn from_manifest(resources: &BundleResources) -> Self {
        Self {
            cpus: Some(resources.vcpus),
            memory_mib: Some(resources.mem_mib),
        }
    }

    /// The signed environment descriptor's resources, when it names any.
    #[must_use]
    pub fn from_environment(environment: &EnvironmentDescriptor) -> Self {
        environment
            .resources
            .as_ref()
            .map_or_else(Self::default, |r| Self {
                cpus: Some(u32::from(r.cpu_cores)),
                memory_mib: Some(r.memory_mb),
            })
    }

    /// Each dimension of `self`, else the one `other` has.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self {
            cpus: self.cpus.or(other.cpus),
            memory_mib: self.memory_mib.or(other.memory_mib),
        }
    }
}

/// Which sizes the caller named, and so which a default must leave alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamedSizing {
    pub cpus: bool,
    pub memory: bool,
}

/// What seeding took from a bundle, for the launch and for its audit entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppliedSizing {
    /// vCPUs taken from the bundle.
    pub cpus: Option<u32>,
    /// Memory in MiB taken from the bundle, after any cap.
    pub memory_mib: Option<u32>,
    /// Memory the bundle asked for when a cap lowered it.
    pub memory_requested_mib: Option<u32>,
}

impl AppliedSizing {
    /// Nothing was taken from the bundle.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cpus.is_none() && self.memory_mib.is_none()
    }

    /// A cap lowered what the bundle asked for.
    #[must_use]
    pub fn clamped(&self) -> bool {
        self.memory_requested_mib.is_some()
    }

    /// The labels `plan.admitted` carries. Empty when nothing was taken, so a
    /// launch the bundle did not size records nothing new.
    #[must_use]
    pub fn audit_labels(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        if self.is_empty() {
            return labels;
        }
        labels.insert("sizing_source".to_string(), "bundle-resources".to_string());
        if let Some(cpus) = self.cpus {
            labels.insert("sizing_cpus".to_string(), cpus.to_string());
        }
        if let Some(applied) = self.memory_mib {
            labels.insert("sizing_memory_mib".to_string(), applied.to_string());
            labels.insert(
                "sizing_memory_requested_mib".to_string(),
                self.memory_requested_mib.unwrap_or(applied).to_string(),
            );
        }
        labels.insert("sizing_clamped".to_string(), self.clamped().to_string());
        labels
    }
}

/// The most memory a default may take: the per-workload ceiling and the
/// host-wide budget's remaining headroom, whichever is smaller. `None` when the
/// host bounds neither.
#[must_use]
pub fn memory_cap_mib(
    ceiling: &GrantCeiling,
    budget: &HostBudget,
    committed_mib: u64,
) -> Option<u64> {
    let headroom = budget
        .max_total_memory_mib
        .map(|total| total.saturating_sub(committed_mib));
    match (ceiling.max_memory_mib, headroom) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Take from `defaults` what the caller did not name, capping memory at `cap`.
///
/// A cap of zero lowers nothing: a zero-sized machine is not a smaller one, and
/// admission's own budget check refuses what the host cannot hold.
#[must_use]
pub fn seed(defaults: SizingDefaults, named: NamedSizing, cap: Option<u64>) -> AppliedSizing {
    let cpus = defaults.cpus.filter(|_| !named.cpus);
    let requested = defaults.memory_mib.filter(|_| !named.memory);
    let capped = requested.map(|mib| match cap {
        Some(cap) if cap > 0 => u32::try_from(cap).map_or(mib, |cap| mib.min(cap)),
        _ => mib,
    });
    AppliedSizing {
        cpus,
        memory_mib: capped,
        memory_requested_mib: requested
            .zip(capped)
            .and_then(|(r, c)| (r != c).then_some(r)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(vcpus: u32, mem_mib: u32) -> SizingDefaults {
        SizingDefaults::from_manifest(&BundleResources { vcpus, mem_mib })
    }

    #[test]
    fn unnamed_sizes_take_the_bundle_values() {
        let applied = seed(bundle(4, 2048), NamedSizing::default(), None);
        assert_eq!((applied.cpus, applied.memory_mib), (Some(4), Some(2048)));
        assert!(!applied.clamped());
    }

    #[test]
    fn a_named_size_is_left_to_the_caller() {
        let named = NamedSizing {
            cpus: true,
            memory: false,
        };
        let applied = seed(bundle(4, 2048), named, None);
        assert_eq!((applied.cpus, applied.memory_mib), (None, Some(2048)));
        let both = NamedSizing {
            cpus: true,
            memory: true,
        };
        assert!(seed(bundle(4, 2048), both, None).is_empty());
    }

    #[test]
    fn a_cap_lowers_memory_and_the_labels_say_so() {
        let applied = seed(bundle(2, 4096), NamedSizing::default(), Some(1024));
        assert_eq!(applied.memory_mib, Some(1024));
        assert!(applied.clamped());
        let labels = applied.audit_labels();
        assert_eq!(labels["sizing_memory_requested_mib"], "4096");
        assert_eq!(labels["sizing_memory_mib"], "1024");
        assert_eq!(labels["sizing_clamped"], "true");
    }

    #[test]
    fn a_value_within_the_cap_is_not_marked_clamped() {
        let applied = seed(bundle(2, 512), NamedSizing::default(), Some(1024));
        assert_eq!(applied.memory_mib, Some(512));
        assert_eq!(applied.audit_labels()["sizing_clamped"], "false");
    }

    #[test]
    fn a_zero_cap_lowers_nothing() {
        let applied = seed(bundle(2, 512), NamedSizing::default(), Some(0));
        assert_eq!(applied.memory_mib, Some(512));
    }

    #[test]
    fn the_cap_is_the_smaller_of_ceiling_and_headroom() {
        let ceiling = GrantCeiling {
            max_memory_mib: Some(8192),
            ..GrantCeiling::default()
        };
        let budget = HostBudget {
            max_total_memory_mib: Some(10_000),
            max_total_cpu_millicores: None,
        };
        assert_eq!(memory_cap_mib(&ceiling, &budget, 7000), Some(3000));
        assert_eq!(memory_cap_mib(&ceiling, &budget, 0), Some(8192));
        let unbounded = HostBudget {
            max_total_memory_mib: None,
            max_total_cpu_millicores: None,
        };
        assert_eq!(
            memory_cap_mib(&GrantCeiling::default(), &unbounded, 0),
            None
        );
    }

    #[test]
    fn nothing_taken_records_nothing() {
        assert!(AppliedSizing::default().audit_labels().is_empty());
    }

    #[test]
    fn a_descriptor_wins_over_the_manifest_per_dimension() {
        let descriptor: EnvironmentDescriptor = serde_json::from_value(serde_json::json!({
            "descriptor_version": 1,
            "target": "x86_64-linux",
            "entrypoint": { "argv": ["/bin/app"] },
            "resources": { "cpu_cores": 3, "memory_mb": 1536 },
        }))
        .unwrap();
        let merged = SizingDefaults::from_environment(&descriptor).or(bundle(8, 8192));
        assert_eq!((merged.cpus, merged.memory_mib), (Some(3), Some(1536)));
    }

    #[test]
    fn resources_carry_no_authority_fields() {
        // The recorded shape is sizes only and refuses anything else, so a
        // secret or grant cannot ride in beside them.
        for field in ["secrets", "network", "grants", "capabilities", "disk_mib"] {
            let value = serde_json::json!({ "vcpus": 1, "mem_mib": 256, field: [] });
            assert!(
                serde_json::from_value::<BundleResources>(value).is_err(),
                "{field}"
            );
        }
    }
}
