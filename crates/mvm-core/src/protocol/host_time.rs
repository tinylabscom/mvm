//! `host.time.v1` payload types — host wall-clock query.
//!
//! One verb, `now`: the request carries no fields (the workload identity
//! comes from the supervisor's [`crate::protocol::handler::ServiceCallCtx`],
//! not the payload), and the response is [`TimeNowResponse`] carrying the
//! host wall-clock in milliseconds since the Unix epoch. Time is an integer
//! on the wire — no floating-point clock — matching the broker's int-only
//! time/cost contract.
//!
//! This module is the shared wire contract for the service: the in-guest
//! typed client (`mvm_guest::host_time`) and the host-side broker handler
//! both deserialize against these types. The handler scaffold is not yet
//! built, so these types are the sole definition today; when the handler
//! lands it reuses them unchanged.

use serde::{Deserialize, Serialize};

/// Response for `host.time.v1::now`: the host wall-clock, milliseconds since
/// the Unix epoch (UTC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeNowResponse {
    /// Milliseconds since the Unix epoch, host-authoritative.
    pub wall_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_now_response_roundtrips() {
        let resp = TimeNowResponse {
            wall_ms: 1_717_000_000_000,
        };
        let bytes = serde_json::to_vec(&resp).unwrap();
        let parsed: TimeNowResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, resp);
    }

    #[test]
    fn time_now_response_decodes_the_broker_wire_shape() {
        // The shape the broker proxy answers `now` with today.
        let parsed: TimeNowResponse =
            serde_json::from_value(serde_json::json!({"wall_ms": 1_717_000_000_000_u64})).unwrap();
        assert_eq!(parsed.wall_ms, 1_717_000_000_000);
    }

    #[test]
    fn time_now_response_rejects_unknown_fields() {
        let bad = serde_json::json!({"wall_ms": 1, "tz": "UTC"});
        let err = serde_json::from_value::<TimeNowResponse>(bad).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
