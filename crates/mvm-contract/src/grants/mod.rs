//! What a workload is permitted to consume or reach.
//!
//! Named `Grants` rather than `Capabilities` because `VmCapabilities` already
//! means "what a VMM backend supports", and `capability` additionally collides
//! with Linux `capabilities(7)`, which this project drops via bounding-set.

use alloc::vec::Vec;
use core::num::NonZeroU32;
use serde::{Deserialize, Serialize};

use crate::policy::network_policy::HostPort;

pub mod budget;
pub mod ceiling;
pub mod projection;

/// A workload's permission set. Every field is optional: absent means
/// "unspecified", which each dimension resolves differently — an absent
/// `egress` is deny-all, an absent `cpu` is uncapped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock: Option<WallClockGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressGrant>,
}

/// CPU bound. The two variants are different units, not different precisions,
/// and no conversion between them is offered: a share is a fraction of host
/// wall-clock CPU, fuel is a count of executed instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "unit", rename_all = "snake_case", deny_unknown_fields)]
pub enum CpuGrant {
    /// Thousandths of one host core. 1500 = 1.5 cores. Integer because the
    /// value lands in a signed, content-addressed payload and float
    /// canonicalization is not stable across serializers.
    Share { millicores: u32 },
    /// A deterministic executed-instruction budget. Reproducible across hosts
    /// in a way no share-based bound is.
    Fuel { instructions: u64 },
}

/// Wall-clock bound.
///
/// `Unbounded` is a named variant rather than a sentinel value. The legacy
/// `TimeoutSpec::exec_secs` encodes unbounded as `0`, so a user writing `0` to
/// mean "no time allowed" would get "no limit" — the exact inversion of their
/// intent. `NonZeroU32` makes that unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WallClockGrant {
    Unbounded,
    Secs { secs: NonZeroU32 },
}

/// Outbound destinations. An empty `allow` is "no egress" and is distinct from
/// an absent `EgressGrant`, which is also deny-all — both are closed, so the
/// distinction never opens anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressGrant {
    pub allow: Vec<HostPort>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn default_grants_serialize_to_an_empty_object() {
        let g = Grants::default();
        let json = serde_json::to_string(&g).expect("serializes");
        assert_eq!(json, "{}", "absent grants must not emit null fields");
    }

    #[test]
    fn unknown_field_is_refused_not_ignored() {
        // A typo must not silently disable a cap.
        let err =
            serde_json::from_str::<Grants>(r#"{"cpu_limt":{"unit":"share","millicores":1500}}"#)
                .expect_err("unknown field must be refused");
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn wall_clock_zero_is_not_expressible() {
        // exec_secs == 0 means *unbounded* in the legacy encoding. The grant
        // must not inherit that trap: zero has to be unrepresentable, so
        // "no time allowed" can never parse as "no limit".
        let err = serde_json::from_str::<WallClockGrant>(r#"{"kind":"secs","secs":0}"#)
            .expect_err("zero seconds must not parse");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn grants_round_trip_through_json() {
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(600).expect("nonzero"),
            }),
            egress: Some(EgressGrant {
                allow: vec![HostPort::new("api.example.com", 443)],
            }),
        };
        let json = serde_json::to_string(&g).expect("serializes");
        let back: Grants = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(g, back);
    }

    #[test]
    fn cpu_share_carries_no_floating_point() {
        let json =
            serde_json::to_string(&CpuGrant::Share { millicores: 1500 }).expect("serializes");
        assert!(
            !json.contains('.'),
            "a signed payload must not carry a float: {json}"
        );
    }
}
