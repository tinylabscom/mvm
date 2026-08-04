//! `EmergencyDeny` + `EffectivePolicy` — the wire DTOs the policy
//! precedence resolver produces and consumes.
//!
//! - `EmergencyDeny` is an out-of-band deny instruction with bounded
//!   lifetime: a signed update that bypasses the normal release cycle
//!   to revoke a destination, tool, or workload class fast. `is_active`
//!   is its pure "does this rule apply right now" check — no clock
//!   read, the caller supplies `now`.
//! - `EffectivePolicy` is the fully-resolved policy a workload boots
//!   under: same shape as `PolicyBundle`'s sub-policies, but
//!   flattened — no `Option<T>`, no overlays.
//!
//! The merge algorithm that produces an `EffectivePolicy` from a
//! `PolicyBundle` + tenant + `EmergencyDeny` (`resolve()`, plus its
//! `pick()` helper) stays in `mvm_core::policy::resolver` — it isn't
//! itself a wire type, just the pure function that builds one.

use alloc::string::String;
use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::policy::policies::{
    ArtifactPolicy, AuditPolicy, BundleNetworkPolicy, EgressPolicy, KeyPolicy, PiiPolicy,
    ToolPolicy, WasiCapPolicy,
};

/// An out-of-band deny instruction with bounded lifetime. Emergency
/// deny rules are signed updates that bypass the normal release cycle
/// to revoke a destination, tool, or workload class fast.
///
/// Today only the `tools` field ships — the only allow list in the
/// sub-policies. A future `destinations` field follows once
/// `EgressPolicy` carries a real allow list. `expires_at` makes
/// the rule self-expiring so a leftover emergency deny doesn't pin
/// the fleet forever after the incident clears.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyDeny {
    /// Tool names to remove from `EffectivePolicy.tool.allowed`.
    pub tools: Vec<String>,

    /// When this rule expires. The resolver treats expired rules as
    /// no-ops; `is_active` is the property test of "this rule
    /// applies right now". `None` means no expiry — supervisor
    /// implementations should refuse `None` in production (logged
    /// here as a forward-compat caveat) but the type allows it for
    /// dev-mode tests that don't want to thread a clock through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl EmergencyDeny {
    /// `true` iff this rule should affect the resolution at `now`.
    /// `expires_at = None` means "never expires" — see field docs.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            None => true,
            Some(at) => now < at,
        }
    }
}

/// The fully-resolved policy a workload boots under. Same shape as
/// `PolicyBundle`'s sub-policies, but flattened: no `Option<T>`,
/// no overlays. Every field is the value the supervisor should
/// enforce.
///
/// The supervisor consumes this; `mvmctl plan inspect <plan>` can
/// also print it for operator review.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicy {
    pub network: BundleNetworkPolicy,
    pub egress: EgressPolicy,
    pub pii: PiiPolicy,
    pub tool: ToolPolicy,
    pub artifact: ArtifactPolicy,
    pub keys: KeyPolicy,
    pub audit: AuditPolicy,
    #[serde(default)]
    pub wasi: WasiCapPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use chrono::TimeZone;

    #[test]
    fn emergency_deny_serde_roundtrip() {
        let e = EmergencyDeny {
            tools: vec![String::from("shell"), String::from("exec")],
            expires_at: Some(Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()),
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: EmergencyDeny = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn emergency_deny_no_expiry_field_is_omitted() {
        let e = EmergencyDeny {
            tools: vec![String::from("shell")],
            expires_at: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        // skip_serializing_if drops the field entirely so the wire
        // is `{"tools":[...]}` rather than carrying a noisy null.
        assert!(!json.contains("expires_at"));
    }

    #[test]
    fn emergency_deny_unknown_field_rejected() {
        let json = r#"{"tools":["x"],"new_field":1}"#;
        let result: Result<EmergencyDeny, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
