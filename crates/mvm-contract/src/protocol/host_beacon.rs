//! `host.beacon.v1` payload types — guest-agent boot beacon.
//!
//! One verb:
//!
//! - `report` — the in-guest agent reports its own liveness once at
//!   boot. Payload is [`BeaconReport`]; response is [`BeaconAck`]
//!   carrying the new `chain_head`.
//!
//! Unlike `host.audit.v1` (workload-emitted, workload-asserted entries),
//! the beacon originates from the platform's own guest agent, and the
//! host records it as a system `lifecycle` entry: the handler stamps the
//! supervisor-authoritative `workload_id` / `tenant_id` / `session_id` /
//! `correlation_id` from the call context, so the chain entry proves the
//! admitted workload's agent came alive, not merely that the VM process
//! started. The guest-supplied fields (`agent_version`, `boot_unix_ms`)
//! ride through as data under the host-authored `lifecycle.beacon_reported`
//! event name; a compromised guest can lie about them, but cannot forge
//! the binding to the admitted identity.
//!
//! Identity fields are deliberately absent from the payloads — the
//! broker handler fills them from `ServiceCallCtx`, same discipline as
//! `host.audit.v1`.

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// The broker service the guest agent's boot beacon targets.
pub const HOST_BEACON_SERVICE: &str = "host.beacon.v1";

/// The audit chain event the host handler records for a beacon report.
pub const BEACON_REPORTED_EVENT: &str = "lifecycle.beacon_reported";

/// Payload for `host.beacon.v1::report`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BeaconReport {
    /// Version of the reporting guest agent (`CARGO_PKG_VERSION` of
    /// `mvm-agentd`). Guest-asserted data, recorded verbatim.
    pub agent_version: String,
    /// Guest wall-clock milliseconds since UNIX epoch at agent boot.
    /// The audit-signer records its own monotonic receipt time in
    /// addition, so a guest clock skew is detectable, not destructive.
    pub boot_unix_ms: u64,
}

/// Response for `host.beacon.v1::report`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct BeaconAck {
    /// Hash of the JCS-canonical chain entry bytes, signed by the
    /// audit-signer's chain key. This is the new chain head after the
    /// append — the guest learns its beacon is durably recorded.
    pub chain_head: String,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_roundtrips_through_json() {
        let report = BeaconReport {
            agent_version: "0.17.0".into(),
            boot_unix_ms: 1_787_181_844_000,
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(
            json,
            serde_json::json!({
                "agent_version": "0.17.0",
                "boot_unix_ms": 1_787_181_844_000_u64,
            })
        );
        let back: BeaconReport = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, report);
    }

    #[test]
    fn report_rejects_unknown_fields() {
        let err = serde_json::from_value::<BeaconReport>(serde_json::json!({
            "agent_version": "0.17.0",
            "boot_unix_ms": 0,
            "workload_id": "wl-spoof",
        }))
        .expect_err("identity fields must not be guest-expressible");
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn report_rejects_missing_fields() {
        assert!(
            serde_json::from_value::<BeaconReport>(serde_json::json!({
                "agent_version": "0.17.0",
            }))
            .is_err()
        );
    }

    #[test]
    fn ack_roundtrips_through_json() {
        let ack = BeaconAck {
            chain_head: "head-001".into(),
        };
        let json = serde_json::to_value(&ack).expect("serialize");
        assert_eq!(json, serde_json::json!({"chain_head": "head-001"}));
        let back: BeaconAck = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, ack);
    }

    #[test]
    fn event_name_lives_under_the_lifecycle_category() {
        let (category, _) = BEACON_REPORTED_EVENT
            .split_once('.')
            .expect("event name is category-prefixed");
        assert_eq!(category, "lifecycle");
    }
}
