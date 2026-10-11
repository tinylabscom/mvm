//! Durable sessions, distinct from short-lived entrypoint authoring sessions.

use crate::{
    host_local::{error, parse},
    status::Outcome,
};
use mvm_client::{
    agent_sessions::{AgentSessions, OpenRequest, ParkRequest, RenewRequest, ResumeRequest},
    checkpoint::wire::{Empty, Mutation},
};

pub const METHODS: &[&str] = &[
    "agent_sessions.open",
    "agent_sessions.list",
    "agent_sessions.show",
    "agent_sessions.park",
    "agent_sessions.renew",
    "agent_sessions.resume",
];

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ShowRequest {
    pub session_id: String,
}

pub(crate) fn dispatch(method: &str, request: &[u8]) -> Outcome {
    match answer(method, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn answer(method: &str, request: &[u8]) -> Result<Outcome, Outcome> {
    let result = match method {
        "agent_sessions.list" => {
            let _: Empty = parse(request)?;
            AgentSessions::local()
                .list()
                .map(|reply| Outcome::ok(&reply))
        }
        "agent_sessions.show" => {
            let request: ShowRequest = parse(request)?;
            AgentSessions::local()
                .show(&request.session_id)
                .map(|reply| Outcome::ok(&reply))
        }
        "agent_sessions.open" => {
            let request: Mutation<OpenRequest> = parse(request)?;
            crate::declared()?;
            AgentSessions::local()
                .open(&request.request)
                .map(|reply| Outcome::ok(&reply))
        }
        "agent_sessions.park" => {
            let request: Mutation<ParkRequest> = parse(request)?;
            crate::declared()?;
            AgentSessions::local()
                .park(&request.request)
                .map(|reply| Outcome::ok(&reply))
        }
        "agent_sessions.renew" => {
            let request: Mutation<RenewRequest> = parse(request)?;
            crate::declared()?;
            AgentSessions::local()
                .renew(&request.request)
                .map(|reply| Outcome::ok(&reply))
        }
        "agent_sessions.resume" => {
            let request: Mutation<ResumeRequest> = parse(request)?;
            crate::declared()?;
            AgentSessions::local()
                .resume(&request.request)
                .map(|reply| Outcome::ok(&reply))
        }
        _ => {
            return Err(Outcome::invalid_input(
                "unknown durable agent-session method",
            ));
        }
    };
    result.map_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn call(method: &str, request: Value) -> Value {
        let outcome = dispatch(method, &serde_json::to_vec(&request).unwrap());
        assert_eq!(
            outcome.status,
            0,
            "{}",
            String::from_utf8_lossy(&outcome.body)
        );
        serde_json::from_slice(&outcome.body).unwrap()
    }

    #[test]
    fn durable_dispatch_transitions_and_fences() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        assert_eq!(call("agent_sessions.list", json!({})), json!([]));
        let opened = call(
            "agent_sessions.open",
            json!({
                "intent": "execute", "request": {"session_id": "durable-test", "members": []}
            }),
        );
        assert_eq!(opened["generation"], 1);
        let park = json!({"intent": "execute", "request": {
            "session_id": "durable-test", "reason": "operator", "journal_cursor": 7,
            "retain_for": "1h", "expected_generation": 1
        }});
        let parked = call("agent_sessions.park", park.clone());
        assert_eq!(parked["session"]["state"], "hibernated");
        assert_eq!(call("agent_sessions.park", park)["replayed"], true);
        let renewed = call(
            "agent_sessions.renew",
            json!({"intent": "execute", "request": {
                "session_id": "durable-test", "extend_for": "2h",
                "expected_generation": parked["session"]["generation"],
                "expected_deadline": parked["session"]["retain_until_unix"]
            }}),
        );
        assert!(
            renewed["session"]["retain_until_unix"].as_u64().unwrap()
                > parked["session"]["retain_until_unix"].as_u64().unwrap()
        );
        let shown = call("agent_sessions.show", json!({"session_id": "durable-test"}));
        let refused = dispatch(
            "agent_sessions.park",
            &serde_json::to_vec(&json!({
                "intent": "execute", "request": {"session_id": "durable-test",
                    "reason": "operator", "journal_cursor": 8, "expected_generation": 99}
            }))
            .unwrap(),
        );
        assert_ne!(refused.status, 0);
        assert_eq!(
            call("agent_sessions.show", json!({"session_id": "durable-test"}))["generation"],
            shown["generation"]
        );
        let resumed = dispatch(
            "agent_sessions.resume",
            &serde_json::to_vec(&json!({
                "intent": "execute", "request": {"session_id": "absent", "backend": "mock",
                    "image": "test", "image_sha256": "00", "cpus": 1, "mem_mib": 128, "boot": false}
            }))
            .unwrap(),
        );
        assert_ne!(resumed.status, 0);
        assert!(String::from_utf8_lossy(&resumed.body).contains("absent"));
    }

    #[test]
    fn strict_wire_refuses_privilege_and_missing_intent() {
        for method in METHODS {
            assert_eq!(
                dispatch(method, br#"{"root":"/outside"}"#).status,
                crate::status::MVM_HOSTLIB_INVALID_INPUT
            );
        }
        for request in [
            json!({"request": {"session_id": "test", "members": []}}),
            json!({"intent": "preview", "request": {"session_id": "test", "members": []}}),
            json!({"intent": "execute", "request": {"session_id": "test", "members": [],
                "private_key": [1], "nonce": "chosen"}}),
        ] {
            assert_eq!(
                dispatch(
                    "agent_sessions.open",
                    &serde_json::to_vec(&request).unwrap()
                )
                .status,
                crate::status::MVM_HOSTLIB_INVALID_INPUT
            );
        }
    }
}
