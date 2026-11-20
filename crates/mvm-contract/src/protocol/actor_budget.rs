//! Finite resource accounting for host-mediated actor lifecycle operations.

use serde::{Deserialize, Serialize};

macro_rules! resources {
    ($($field:ident),+ $(,)?) => {
        /// Releasable capacity, charged for the child's full admitted shape.
        ///
        /// Byte quantities and CPU millicores are integers. External cost is
        /// expressed in the workflow authority's fixed accounting unit.
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct ActorResources {
            $(#[doc = stringify!($field)] pub $field: u64,)+
        }

        impl ActorResources {
            /// Add every dimension, refusing any integer overflow.
            #[must_use]
            pub fn checked_add(self, other: Self) -> Option<Self> {
                Some(Self { $($field: self.$field.checked_add(other.$field)?,)+ })
            }

            /// Resolve ceilings without allowing either authority to widen them.
            #[must_use]
            pub fn intersection(self, other: Self) -> Self {
                Self { $($field: self.$field.min(other.$field),)+ }
            }

            /// Whether every dimension is within its ceiling.
            #[must_use]
            pub fn fits_within(self, ceiling: Self) -> bool {
                $(self.$field <= ceiling.$field)&&+
            }
        }
    };
}

resources!(
    live_vms,
    resident_vmms,
    concurrent_launches,
    controllers,
    warm_slots,
    parked_slots,
    checkpoint_slots,
    memory_bytes,
    cpu_millicores,
    disk_bytes,
    artifact_bytes,
    mailbox_bytes,
    network_bytes,
    external_cost_units,
    file_descriptors,
    host_sockets,
    vsock_channels,
);

/// Capacity ceiling and a separate, non-replenishing attempt allowance.
///
/// Deadlines, launch rate, delegation depth and graph limits must additionally
/// be enforced by the authenticated controller contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorBudget {
    /// Simultaneously reserved resource capacity.
    pub resources: ActorResources,
    /// Total accepted distinct child requests, including terminal requests.
    pub max_total_attempts: u64,
}

impl ActorBudget {
    /// Intersect independent authorities, never widening a dimension.
    #[must_use]
    pub fn intersection(self, other: Self) -> Self {
        Self {
            resources: self.resources.intersection(other.resources),
            max_total_attempts: self.max_total_attempts.min(other.max_total_attempts),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_and_wire_are_strict() {
        let full = ActorResources {
            memory_bytes: u64::MAX,
            ..Default::default()
        };
        let one = ActorResources {
            memory_bytes: 1,
            ..Default::default()
        };
        assert!(full.checked_add(one).is_none());
        assert_eq!(full.intersection(one), one);
        assert!(!full.fits_within(one));
        let budget = ActorBudget {
            resources: one,
            max_total_attempts: 2,
        };
        assert_eq!(
            serde_json::from_slice::<ActorBudget>(&serde_json::to_vec(&budget).unwrap()).unwrap(),
            budget
        );
        assert!(serde_json::from_str::<ActorResources>(r#"{"arbitrary":1}"#).is_err());
    }

    #[test]
    fn every_named_dimension_checks_overflow_and_ceiling() {
        let zero = serde_json::to_value(ActorResources::default()).unwrap();
        for field in zero.as_object().unwrap().keys() {
            let mut one = zero.clone();
            one[field] = 1.into();
            let one: ActorResources = serde_json::from_value(one).unwrap();
            let mut full = zero.clone();
            full[field] = u64::MAX.into();
            let full: ActorResources = serde_json::from_value(full).unwrap();
            assert!(full.checked_add(one).is_none(), "{field}");
            assert_eq!(full.intersection(one), one, "{field}");
            assert!(!full.fits_within(one), "{field}");
        }
    }
}
