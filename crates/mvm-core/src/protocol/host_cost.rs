//! `host.cost.v1` payload types — accumulated spend for a scope.
//!
//! Two verbs select the scope; the request body is empty in both cases
//! because the scope is the verb and the identity comes from the
//! supervisor's [`crate::protocol::handler::ServiceCallCtx`]:
//!
//! - `workload` — spend attributed to the calling workload. No mvmd
//!   dependency; served in-process by the broker.
//! - `tenant` — spend aggregated across the calling workload's tenant.
//!   mvmd-delegated; a build without the cross-VM verb answers
//!   [`crate::protocol::broker::ServiceErrorCode::NotImplemented`].
//!
//! Spend is an integer count of micro-USD (1e-6 USD) — no floating-point
//! money on the wire — matching the broker's int-only time/cost contract.
//!
//! This module is the shared wire contract for the service: the in-guest
//! typed client (`mvm_guest::host_cost`) and the host-side broker handler
//! both deserialize against these types. The handler scaffold is not yet
//! built, so these types are the sole definition today; when the handler
//! lands it reuses them unchanged.

use serde::{Deserialize, Serialize};

/// Response for both `host.cost.v1` verbs: the accumulated spend for the
/// queried scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CostReport {
    /// Accumulated spend for the queried scope, in micro-USD (1e-6 USD).
    pub spent_micros_usd: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_report_roundtrips() {
        let report = CostReport {
            spent_micros_usd: 4_200_000,
        };
        let bytes = serde_json::to_vec(&report).unwrap();
        let parsed: CostReport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn cost_report_rejects_unknown_fields() {
        let bad = serde_json::json!({"spent_micros_usd": 1, "currency": "USD"});
        let err = serde_json::from_value::<CostReport>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
