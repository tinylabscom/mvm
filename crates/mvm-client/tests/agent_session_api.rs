use mvm_client::{agent_session::AgentSessionId, agent_sessions::AgentSessions};

#[test]
fn protocol_reexport_keeps_type_identity_alongside_plural_service() {
    let id = AgentSessionId::parse("api-compatibility").unwrap();
    let protocol_id: mvm_contract::protocol::agent_session::AgentSessionId = id;
    let client_id: AgentSessionId = protocol_id;
    assert_eq!(client_id.as_str(), "api-compatibility");
    let _service_constructor: fn() -> AgentSessions = AgentSessions::local;
}
