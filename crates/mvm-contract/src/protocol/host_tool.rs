//! `host.tool.v1` payload types — guest-origin declared-tool decisions.
//!
//! Two verbs:
//!
//! - `decide` — ask the host to decide one exact guest invocation of a
//!   declared tool. Payload is [`crate::protocol::network_flow::tool::ToolCheckRequest`];
//!   response is [`crate::protocol::network_flow::tool::ToolDecisionReply`].
//!   The caller is untrusted by construction (any guest process can dial the
//!   broker port), so the payload's `tool` label carries no authority: the
//!   endpoint re-derives the binding between tool and exact executable path
//!   from the admitted plan's signed tool rules and refuses a mismatch.
//! - `release` — retire an invocation's binding once the command has
//!   finished. Payload is [`crate::protocol::network_flow::attribution::ToolInvocationRelease`];
//!   response is [`ToolReleaseResponse`].
//!
//! Every `decide` is answered only after the per-VM decision gate records
//! the outcome in the chain-signed audit log, stamped with the broker
//! ingress origin so a workload-origin decision is distinguishable from a
//! host-initiated one. A missing gate, a malformed question, or a recorder
//! failure is a refusal, never an approval.

use serde::{Deserialize, Serialize};

/// Broker service id for guest-origin declared-tool decisions.
pub const HOST_TOOL_SERVICE: &str = "host.tool.v1";

/// Verb asking the admitted gate to decide one exact invocation.
pub const DECIDE_VERB: &str = "decide";

/// Verb retiring an invocation's binding after its command finished.
pub const RELEASE_VERB: &str = "release";

/// Response for `host.tool.v1::release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ToolReleaseResponse {
    /// The binding was retired (or was already gone, which is also fine:
    /// release is idempotent).
    pub released: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_and_verb_names_are_stable() {
        assert_eq!(HOST_TOOL_SERVICE, "host.tool.v1");
        assert_eq!(DECIDE_VERB, "decide");
        assert_eq!(RELEASE_VERB, "release");
    }

    #[test]
    fn release_response_roundtrips() {
        let response = ToolReleaseResponse { released: true };
        let json = serde_json::to_vec(&response).expect("serialize release response");
        let round: ToolReleaseResponse =
            serde_json::from_slice(&json).expect("deserialize release response");
        assert_eq!(round, response);
    }

    #[test]
    fn release_response_rejects_unknown_fields() {
        let json = serde_json::json!({"released": true, "extra": 1});
        assert!(serde_json::from_value::<ToolReleaseResponse>(json).is_err());
    }
}
