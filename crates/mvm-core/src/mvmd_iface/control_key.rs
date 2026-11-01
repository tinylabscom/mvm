//! Control-plane signing keys for the `mvmd` ↔ `mvm` boundary.
//!
//! `mvmd` mints control-plane envelopes signed with a `ControlKey`. `mvm`
//! verifies the signature against the key registered for that `kid` and
//! refuses to act on expired or unknown keys.

use serde::{Deserialize, Serialize};

/// A control-plane key identifier.
///
/// `kid` (key identifier) follows JWS conventions — an opaque, stable
/// string that maps to a public key in `mvm`'s registered set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ControlKey {
    /// Opaque key identifier. Stable across rotations.
    pub kid: String,
    /// Role this key is authorized to assert (see [`ControlKeyRole`]).
    pub role: ControlKeyRole,
    /// Unix seconds at which this key stops being valid.
    pub expiry_unix_secs: u64,
}

/// The control-plane action a key is authorized to sign.
///
/// `mvm`'s verifier checks role on the inner envelope: a release-promotion
/// envelope signed with an `Inventory` key is rejected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ControlKeyRole {
    /// Drives release promotions (plan-37 §11).
    Promoter,
    /// Reports / updates host inventory (plan-37 §17.1).
    Inventory,
    /// Catch-all for current-state orchestration: cordon, drain, suspend, wake.
    Orchestrator,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_key_roundtrip() {
        let key = ControlKey {
            kid: "mvmd-promoter-2026q2".into(),
            role: ControlKeyRole::Promoter,
            expiry_unix_secs: 1_780_000_000,
        };
        let json = serde_json::to_string(&key).unwrap();
        let parsed: ControlKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, parsed);
    }

    #[test]
    fn control_key_rejects_unknown_field() {
        let json = r#"{
            "kid": "k",
            "role": "promoter",
            "expiry_unix_secs": 1,
            "wat": true
        }"#;
        let err = serde_json::from_str::<ControlKey>(json);
        assert!(
            err.is_err(),
            "deny_unknown_fields must reject unexpected keys"
        );
    }

    #[test]
    fn control_key_role_roundtrip_each_variant() {
        for role in [
            ControlKeyRole::Promoter,
            ControlKeyRole::Inventory,
            ControlKeyRole::Orchestrator,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            let parsed: ControlKeyRole = serde_json::from_str(&json).unwrap();
            assert_eq!(role, parsed);
        }
    }
}
