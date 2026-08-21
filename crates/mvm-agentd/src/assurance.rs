//! The workload-facing assurance API.
//!
//! An AI workload driving a campaign gets exactly this surface: parse the
//! envelope it was handed, then call declared probes by *label*. There is no
//! method here that accepts a command, a path, a host, a port, a socket, or a
//! destination — not because callers are trusted to avoid them, but because
//! the type system offers nothing else to pass.
//!
//! # This client is advisory
//!
//! Like the rest of [`crate::broker_client`], this runs inside the untrusted
//! guest and is not a security boundary. A compromised workload can write raw
//! frames to the broker port and skip it entirely. Every gate that matters —
//! the service binding, effective authority, the declared-destination table,
//! nonce replay, the step budget, and the audit record — is enforced by the
//! host against the session *it* opened. The checks below exist to turn a
//! programming mistake into a local error instead of a round-trip and a
//! refusal, not to protect the host from the guest.

use mvm_contract::assurance::{
    AssuranceId, DeliveredSession, DeliveredSessionError, PROBE_REQUEST_SCHEMA, ProbeInvocation,
    ProbeObservation, ProbeRequest, ToolId, probe_capability_descriptor,
};
use mvm_contract::protocol::agent_session::AgentRequestId;
use mvm_core::protocol::broker::ServiceId;

use crate::broker_client::{BrokerError, broker_capability_call};

/// Wire name of the host-side assurance service.
pub const ASSURANCE_SERVICE: &str = "host.assurance.v1";
/// The one verb it exposes.
pub const PROBE_VERB: &str = "probe";
/// Wall-clock bound on one probe round-trip.
const PROBE_TIMEOUT_SECS: u64 = 10;

/// Why a workload-side probe did not happen.
#[derive(Debug, thiserror::Error)]
pub enum AssuranceError {
    /// The delivered envelope could not be read.
    #[error("delivered session is unusable: {0}")]
    Session(#[from] DeliveredSessionError),
    /// The session's effective authority does not include the tool.
    #[error("this session was not granted the campaign probe tool")]
    ToolNotGranted,
    /// The label is not one the campaign declared.
    #[error("destination label is not declared for this campaign")]
    UndeclaredDestination,
    /// The local step budget is spent. The host enforces its own.
    #[error("the session step budget is spent")]
    StepBudgetSpent,
    /// The host refused, or the transport failed.
    #[error(transparent)]
    Broker(#[from] BrokerError),
    /// The host's reply did not match the observation contract.
    #[error("host observation could not be read: {0}")]
    Observation(String),
}

/// A workload's handle on its own assurance session.
pub struct AssuranceCampaign {
    session: DeliveredSession,
    steps_used: u32,
    nonce_counter: u64,
}

impl AssuranceCampaign {
    /// Read the envelope this workload was started with.
    pub fn from_envelope(bytes: &[u8]) -> Result<Self, AssuranceError> {
        Ok(Self {
            session: DeliveredSession::parse_json(bytes)?,
            steps_used: 0,
            nonce_counter: 0,
        })
    }

    /// The envelope, for a workload that wants to read its own narrative.
    #[must_use]
    pub fn session(&self) -> &DeliveredSession {
        &self.session
    }

    /// Labels this campaign may probe. The only values `probe_egress` accepts.
    #[must_use]
    pub fn declared_destinations(&self) -> &[AssuranceId] {
        &self.session.synthetic_inputs.destination_labels
    }

    /// Steps left in the locally-tracked budget.
    #[must_use]
    pub fn steps_remaining(&self) -> u32 {
        self.session
            .authority
            .max_steps
            .saturating_sub(self.steps_used)
    }

    /// Ask whether the admitted policy would admit a declared destination.
    ///
    /// `idempotency_key` is the caller's: presenting the same one again returns
    /// the first answer without re-running the probe, which is what makes a
    /// retry after a lost reply safe. The nonce is generated here and never
    /// reused, so a replayed frame is refused by the host even when the key is
    /// legitimately repeated.
    pub fn probe_egress(
        &mut self,
        destination_label: &AssuranceId,
        idempotency_key: &AssuranceId,
    ) -> Result<ProbeObservation, AssuranceError> {
        // Unreachable while `ToolId` has one variant — an envelope granting no
        // tool is refused at parse time, and a non-empty grant can only be this
        // one. Kept because it becomes load-bearing the moment a second tool
        // exists, and because the alternative is a call site that silently
        // stops checking when that happens.
        if !self.session.permits_tool(ToolId::CampaignProbeV1) {
            return Err(AssuranceError::ToolNotGranted);
        }
        if !self.session.declares_destination(destination_label) {
            return Err(AssuranceError::UndeclaredDestination);
        }
        if self.steps_remaining() == 0 {
            return Err(AssuranceError::StepBudgetSpent);
        }

        let request = ProbeRequest {
            schema: PROBE_REQUEST_SCHEMA.to_string(),
            session_id: self.session.mvm_binding.session_id.clone(),
            request_id: self.session.session.request_id.clone(),
            campaign_id: self.session.session.campaign_id.clone(),
            trial_id: self.session.session.trial_id.clone(),
            plan_id: self.session.mvm_binding.plan_id.clone(),
            campaign_idempotency_key: self.session.session.idempotency_key.clone(),
            session_grant_digest: self.session.mvm_binding.session_grant_digest.clone(),
            session_grant_nonce: self.session.mvm_binding.nonce.clone(),
            idempotency_key: idempotency_key.clone(),
            nonce: self.next_nonce(),
            tool: ToolId::CampaignProbeV1,
            invocation: ProbeInvocation::EgressAdmission {
                destination_label: destination_label.clone(),
            },
        };
        let observation = self.dispatch(&request)?;
        self.steps_used = self.steps_used.saturating_add(1);
        Ok(observation)
    }

    fn dispatch(&self, request: &ProbeRequest) -> Result<ProbeObservation, AssuranceError> {
        let service = ServiceId::parse(ASSURANCE_SERVICE)
            .map_err(|error| AssuranceError::Observation(format!("{error:?}")))?;
        let payload = serde_json::to_value(request)
            .map_err(|error| AssuranceError::Observation(error.to_string()))?;
        let invocation_id =
            AgentRequestId::parse(format!("assurance-probe-{}", request.idempotency_key))
                .map_err(|error| AssuranceError::Observation(error.to_string()))?;
        let reply = broker_capability_call(
            service,
            PROBE_VERB,
            probe_capability_descriptor().binding(),
            invocation_id,
            payload,
            PROBE_TIMEOUT_SECS,
        )?;
        decode_observation(request, reply)
    }

    /// Mint the next single-use nonce for this session.
    ///
    /// Session-scoped and monotonic rather than random: the guest has no
    /// entropy requirement here, and the host's ledger only needs the values to
    /// be distinct within the session it is tracking.
    pub(crate) fn next_nonce(&mut self) -> AssuranceId {
        self.nonce_counter = self.nonce_counter.saturating_add(1);
        AssuranceId::parse(format!(
            "{}-n{}",
            self.session.mvm_binding.session_id, self.nonce_counter
        ))
        .expect("session id is a valid identifier and the suffix is alphanumeric")
    }
}

fn decode_observation(
    request: &ProbeRequest,
    reply: serde_json::Value,
) -> Result<ProbeObservation, AssuranceError> {
    let observation: ProbeObservation = serde_json::from_value(reply)
        .map_err(|error| AssuranceError::Observation(error.to_string()))?;
    observation
        .validate_for(&request.invocation)
        .map_err(|error| AssuranceError::Observation(error.to_string()))?;
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn envelope(max_steps: u32, tools: &str, labels: &str) -> String {
        format!(
            r#"{{
  "schema": "mvm.assurance.ai-session-input/v1",
  "session": {{
    "request_id": "mvm-request-1", "idempotency_key": "trial-1",
    "source_run_id": "scout-1", "campaign_id": "mvm-campaign-1", "trial_id": "trial-1"
  }},
  "source": {{
    "subject_kind": "local_repository", "subject_locator": "repository-ref-1", "subject_revision": null,
    "source_digest": "{DIGEST}", "finding_id": "SCOUT-RCE-001", "group_id": "group-1",
    "rule_id": "SCOUT-RCE-001", "category": "command_injection", "severity": "critical",
    "location": "src/worker.py:42:7", "evidence_refs": [], "artifact_locator": null,
    "requested_policy_digest": "{DIGEST}"
  }},
  "narrative": {{
    "narrative_id": "mvm.boundary.process-exec.v1", "objective": "attempt the effect",
    "expected_boundary": "it cannot cross", "required_capabilities": []
  }},
  "authority": {{
    "allowed_tools": {tools}, "observation_scopes": ["host.audit.refs"],
    "max_steps": {max_steps}, "max_output_bytes": 4096, "deadline_unix_ms": 9999999999999
  }},
  "synthetic_inputs": {{ "canary_ids": [], "destination_labels": {labels} }},
  "output_contract": {{
    "kind": "mvm.assurance.trial-result/v1",
    "required_fields": [
      "source_digest", "artifact_digest", "policy_digest", "attempted_effect",
      "effect_observed_in_guest", "boundary_crossed", "blocked_edges", "evidence_refs"
    ]
  }},
  "mvm_binding": {{
    "session_id": "session-1", "plan_id": "plan-1", "workload_digest": "{DIGEST}",
    "artifact_digest": "{DIGEST}", "effective_policy_digest": "{DIGEST}",
    "session_grant_digest": "{DIGEST}", "expires_at_unix_ms": 9999999999999,
    "nonce": "nonce-1", "allowed_tools": {tools}, "backend": "firecracker"
  }}
}}"#
        )
    }

    fn campaign(max_steps: u32) -> AssuranceCampaign {
        AssuranceCampaign::from_envelope(
            envelope(
                max_steps,
                r#"["campaign_probe.v1"]"#,
                r#"["undeclared.synthetic.destination"]"#,
            )
            .as_bytes(),
        )
        .expect("campaign")
    }

    fn label(raw: &str) -> AssuranceId {
        AssuranceId::parse(raw).expect("label")
    }

    #[test]
    fn a_delivered_envelope_yields_its_declared_surface() {
        let campaign = campaign(4);
        assert_eq!(
            campaign.declared_destinations(),
            &[label("undeclared.synthetic.destination")]
        );
        assert_eq!(campaign.steps_remaining(), 4);
        assert_eq!(
            campaign.session().mvm_binding.backend.as_str(),
            "firecracker"
        );
    }

    // The guards below must fire *before* any broker round-trip. Nothing is
    // listening in a unit test, so a guard that failed to fire would surface as
    // a transport error rather than the expected refusal — which is what makes
    // these assertions meaningful rather than incidental.

    #[test]
    fn an_undeclared_label_is_refused_without_a_round_trip() {
        let mut campaign = campaign(4);
        assert!(matches!(
            campaign.probe_egress(&label("some.other.host"), &label("k1")),
            Err(AssuranceError::UndeclaredDestination)
        ));
        assert_eq!(campaign.steps_remaining(), 4, "a refusal spends no step");
    }

    #[test]
    fn an_envelope_granting_no_tool_never_becomes_a_campaign() {
        // Refused at parse time, which is stronger than refusing the call:
        // there is no campaign object to invoke a probe on at all.
        let result = AssuranceCampaign::from_envelope(
            envelope(4, r#"[]"#, r#"["undeclared.synthetic.destination"]"#).as_bytes(),
        );
        assert!(matches!(
            result,
            Err(AssuranceError::Session(DeliveredSessionError::NoTools))
        ));
    }

    #[test]
    fn a_spent_step_budget_is_refused_without_a_round_trip() {
        let mut campaign = campaign(1);
        campaign.steps_used = 1;
        assert!(matches!(
            campaign.probe_egress(&label("undeclared.synthetic.destination"), &label("k1")),
            Err(AssuranceError::StepBudgetSpent)
        ));
    }

    #[test]
    fn nonces_are_single_use_within_a_session() {
        let mut campaign = campaign(4);
        let first = campaign.next_nonce();
        let second = campaign.next_nonce();
        assert_ne!(first, second);
        assert!(first.as_str().starts_with("session-1-n"), "{first}");
    }

    #[test]
    fn the_probe_payload_carries_no_command_path_or_destination() {
        let request = ProbeRequest {
            schema: PROBE_REQUEST_SCHEMA.to_string(),
            session_id: label("session-1"),
            request_id: label("mvm-request-1"),
            campaign_id: label("mvm-campaign-1"),
            trial_id: label("trial-1"),
            plan_id: label("plan-1"),
            campaign_idempotency_key: label("trial-1"),
            session_grant_digest: mvm_contract::assurance::Sha256Digest::parse(DIGEST)
                .expect("digest"),
            session_grant_nonce: label("nonce-1"),
            idempotency_key: label("k1"),
            nonce: label("n1"),
            tool: ToolId::CampaignProbeV1,
            invocation: ProbeInvocation::EgressAdmission {
                destination_label: label("undeclared.synthetic.destination"),
            },
        };
        let json = serde_json::to_string(&request).expect("serialize");
        for forbidden in ["command", "argv", "path", "host", "port", "socket"] {
            assert!(!json.contains(forbidden), "{forbidden} leaked into {json}");
        }
        assert!(json.contains("undeclared.synthetic.destination"), "{json}");
    }

    #[test]
    fn a_broker_observation_for_another_declared_edge_is_refused() {
        let request = ProbeRequest {
            schema: PROBE_REQUEST_SCHEMA.to_string(),
            session_id: label("session-1"),
            request_id: label("mvm-request-1"),
            campaign_id: label("mvm-campaign-1"),
            trial_id: label("trial-1"),
            plan_id: label("plan-1"),
            campaign_idempotency_key: label("trial-1"),
            session_grant_digest: mvm_contract::assurance::Sha256Digest::parse(DIGEST)
                .expect("digest"),
            session_grant_nonce: label("nonce-1"),
            idempotency_key: label("k1"),
            nonce: label("n1"),
            tool: ToolId::CampaignProbeV1,
            invocation: ProbeInvocation::EgressAdmission {
                destination_label: label("declared.synthetic.destination"),
            },
        };
        let reply = serde_json::json!({
            "schema": "mvm.assurance.probe-observation/v1",
            "probe": "egress.admission.v1",
            "admitted": false,
            "blocked_edge": "foreign.synthetic.destination",
            "decision": "deny_all",
            "steps_remaining": 3
        });
        assert!(matches!(
            decode_observation(&request, reply),
            Err(AssuranceError::Observation(message)) if message.contains("blocked edge")
        ));
    }

    #[test]
    fn a_foreign_envelope_is_refused() {
        assert!(matches!(
            AssuranceCampaign::from_envelope(b"{}"),
            Err(AssuranceError::Session(_))
        ));
    }
}
