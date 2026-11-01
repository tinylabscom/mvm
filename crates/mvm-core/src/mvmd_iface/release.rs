//! Release-promotion wire types driven by `mvmd`, executed by `mvm`.
//!
//! `mvmd` decides *when* a release advances and what the
//! rollout strategy is; `mvm`'s supervisor verifies the signed envelope,
//! checks the workload's `ReleasePin`, and performs the local
//! stop/start/snapshot dance. This module declares the contract.

use serde::{Deserialize, Serialize};

/// A staged-rollout promotion announced by `mvmd`.
///
/// The supervisor on each host receives a signed `ReleasePromotion`
/// envelope. Workloads whose plan pin matches `from` are eligible to
/// advance to `to`. The `strategy` field tells the supervisor how to
/// pace its local share of the rollout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleasePromotion {
    /// Opaque release identifier (e.g. ULID). Stable across the
    /// promotion's lifetime; appears in audit events.
    pub release_id: String,
    /// Pin the workload must currently be at to be eligible. Empty
    /// string means "any prior pin".
    pub from_pin: String,
    /// Pin the workload should advance to.
    pub to_pin: String,
    /// How the supervisor should pace its share of the rollout.
    pub strategy: PromotionStrategy,
}

/// How a host should pace its share of a release rollout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PromotionStrategy {
    /// Replace one workload, observe, then continue. Default safe option.
    RollingReplace,
    /// Replace a small fraction first; `mvmd` decides when to fan out.
    Canary,
    /// Stand up the new version alongside the old; `mvmd` flips routing.
    BlueGreen,
    /// Wait for an explicit `mvmd` ack between each step.
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_promotion_roundtrip() {
        let p = ReleasePromotion {
            release_id: "rel_01HKZ".into(),
            from_pin: "img-sha256-aaa".into(),
            to_pin: "img-sha256-bbb".into(),
            strategy: PromotionStrategy::Canary,
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: ReleasePromotion = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn release_promotion_rejects_unknown_field() {
        let json = r#"{
            "release_id": "r",
            "from_pin": "",
            "to_pin": "b",
            "strategy": "manual",
            "extra": 1
        }"#;
        assert!(serde_json::from_str::<ReleasePromotion>(json).is_err());
    }

    #[test]
    fn promotion_strategy_roundtrip_each_variant() {
        for s in [
            PromotionStrategy::RollingReplace,
            PromotionStrategy::Canary,
            PromotionStrategy::BlueGreen,
            PromotionStrategy::Manual,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let parsed: PromotionStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(s, parsed);
        }
    }
}
