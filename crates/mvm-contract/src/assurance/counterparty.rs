//! Strict boundary for the assurance controller's campaign-provider request.
//!
//! The current counterparty schema is intentionally smaller than
//! [`AssuranceSessionRequest`]: it does not carry a trial/idempotency identity,
//! detailed finding metadata, authority, or synthetic inputs. MVM never
//! invents those fields. Instead [`CampaignProviderRequest::join_session_request`]
//! accepts a separately operator-declared strict request and cross-checks every
//! fact the two documents share.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::{AssuranceId, AssuranceSessionRequest, Sha256Digest, SubjectKind, TrialEvidenceRecord};

/// Counterparty request schema consumed by an MVM-backed provider.
pub const CAMPAIGN_PROVIDER_REQUEST_SCHEMA: &str = "mvm.security.campaign-request/v1";
/// Operator-owned session declarations sent separately from the Scout request.
pub const OPERATOR_SESSION_BUNDLE_SCHEMA: &str = "mvm.assurance.operator-session-bundle/v1";
/// Counterparty response schema emitted by an MVM-backed provider.
pub const CAMPAIGN_PROVIDER_RESPONSE_SCHEMA: &str = "mvm.security.provider-response/v1";
/// Largest accepted counterparty provider request.
pub const MAX_CAMPAIGN_PROVIDER_BYTES: usize = 512 * 1024;
const MAX_CAMPAIGNS: usize = 256;
const MAX_PROVIDER_TEXT_BYTES: usize = 2 * 1024;
const MAX_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;

/// One campaign in the counterparty's provider request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CounterpartyCampaign {
    pub campaign_id: AssuranceId,
    pub finding_id: AssuranceId,
    pub narrative_id: Option<AssuranceId>,
    pub objective: Option<String>,
    pub expected_boundary: Option<String>,
    pub required_capabilities: Vec<AssuranceId>,
}

/// Bounded Scout-derived request sent to an out-of-process provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CampaignProviderRequest {
    pub schema: String,
    pub request_id: AssuranceId,
    pub source_run_id: AssuranceId,
    pub subject_kind: SubjectKind,
    /// Correlation-only locator. It is never opened or delivered as a path.
    pub subject_locator: String,
    pub subject_revision: Option<String>,
    pub source_digest: Sha256Digest,
    pub artifact_locator: Option<String>,
    pub requested_policy_digest: Sha256Digest,
    pub profile: String,
    pub runner: String,
    pub build_posture: String,
    pub timeout_seconds: u64,
    pub max_trials: u64,
    pub require_disposable_target: bool,
    pub require_attestation: bool,
    pub campaigns: Vec<CounterpartyCampaign>,
}

/// Strict operator authority joined to a Scout campaign before admission.
///
/// This document crosses the controller protocol in its own `OpenSession`
/// frame. Keeping it separate prevents Scout-derived data from silently
/// acquiring operator authority and lets MVM reject a campaign if either half
/// is absent or disagrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OperatorSessionBundle {
    pub schema: String,
    pub request_id: AssuranceId,
    pub sessions: Vec<AssuranceSessionRequest>,
}

/// Host-produced response returned to the assurance controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CampaignProviderResponse {
    pub schema: String,
    pub request_id: AssuranceId,
    pub status: String,
    pub certifying: bool,
    pub missing_brokers: Vec<String>,
    pub evidence: Vec<TrialEvidenceRecord>,
}

/// Why a counterparty request or its operator join was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum CounterpartyRequestError {
    #[error("counterparty campaign request exceeds its byte limit")]
    TooLarge,
    #[error("counterparty campaign request is malformed: {0}")]
    Malformed(String),
    #[error("operator session bundle exceeds its byte limit")]
    OperatorBundleTooLarge,
    #[error("operator session bundle is malformed: {0}")]
    OperatorBundleMalformed(String),
    #[error("unsupported counterparty campaign schema {0:?}")]
    UnsupportedSchema(String),
    #[error("unsupported operator session bundle schema {0:?}")]
    UnsupportedOperatorBundleSchema(String),
    #[error("counterparty field {0} is outside its bound")]
    OutOfBounds(&'static str),
    #[error("counterparty request contains no campaign {0}")]
    CampaignMissing(AssuranceId),
    #[error("counterparty campaign omits required field {0}")]
    MissingField(&'static str),
    #[error("operator session request disagrees with counterparty field {0}")]
    IdentityMismatch(&'static str),
    #[error("operator session request is invalid: {0}")]
    SessionRequest(String),
}

impl OperatorSessionBundle {
    /// Parse a bounded exact-key operator declaration bundle.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, CounterpartyRequestError> {
        if bytes.len() > MAX_CAMPAIGN_PROVIDER_BYTES {
            return Err(CounterpartyRequestError::OperatorBundleTooLarge);
        }
        let bundle: Self = serde_json::from_slice(bytes).map_err(|error| {
            CounterpartyRequestError::OperatorBundleMalformed(error.to_string())
        })?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Validate the bundle independently of any Scout request.
    pub fn validate(&self) -> Result<(), CounterpartyRequestError> {
        if self.schema != OPERATOR_SESSION_BUNDLE_SCHEMA {
            return Err(CounterpartyRequestError::UnsupportedOperatorBundleSchema(
                self.schema.clone(),
            ));
        }
        if self.sessions.is_empty() || self.sessions.len() > MAX_CAMPAIGNS {
            return Err(CounterpartyRequestError::OutOfBounds("operator_sessions"));
        }
        let mut campaigns = BTreeSet::new();
        let mut trials = BTreeSet::new();
        let mut idempotency_keys = BTreeSet::new();
        for session in &self.sessions {
            session
                .validate()
                .map_err(|error| CounterpartyRequestError::SessionRequest(error.to_string()))?;
            equal("request_id", &self.request_id, &session.session.request_id)?;
            if !campaigns.insert(session.session.campaign_id.clone()) {
                return Err(CounterpartyRequestError::OutOfBounds(
                    "operator_session.campaign_id",
                ));
            }
            if !trials.insert(session.session.trial_id.clone()) {
                return Err(CounterpartyRequestError::OutOfBounds(
                    "operator_session.trial_id",
                ));
            }
            if !idempotency_keys.insert(session.session.idempotency_key.clone()) {
                return Err(CounterpartyRequestError::OutOfBounds(
                    "operator_session.idempotency_key",
                ));
            }
        }
        Ok(())
    }

    /// Serialize after validating every nested declaration.
    pub fn to_json(&self) -> Result<Vec<u8>, CounterpartyRequestError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|error| {
            CounterpartyRequestError::OperatorBundleMalformed(error.to_string())
        })?;
        if encoded.len() > MAX_CAMPAIGN_PROVIDER_BYTES {
            return Err(CounterpartyRequestError::OperatorBundleTooLarge);
        }
        Ok(encoded)
    }
}

impl CampaignProviderRequest {
    /// Parse exact-key JSON and validate every non-type bound.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, CounterpartyRequestError> {
        if bytes.len() > MAX_CAMPAIGN_PROVIDER_BYTES {
            return Err(CounterpartyRequestError::TooLarge);
        }
        let request: Self = serde_json::from_slice(bytes)
            .map_err(|error| CounterpartyRequestError::Malformed(error.to_string()))?;
        request.validate()?;
        Ok(request)
    }

    /// Validate bounds not captured by strict serde types.
    pub fn validate(&self) -> Result<(), CounterpartyRequestError> {
        if self.schema != CAMPAIGN_PROVIDER_REQUEST_SCHEMA {
            return Err(CounterpartyRequestError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        if self.campaigns.is_empty() || self.campaigns.len() > MAX_CAMPAIGNS {
            return Err(CounterpartyRequestError::OutOfBounds("campaigns"));
        }
        let max_trials = usize::try_from(self.max_trials)
            .map_err(|_| CounterpartyRequestError::OutOfBounds("max_trials"))?;
        if max_trials == 0 || max_trials > MAX_CAMPAIGNS || max_trials < self.campaigns.len() {
            return Err(CounterpartyRequestError::OutOfBounds("max_trials"));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(CounterpartyRequestError::OutOfBounds("timeout_seconds"));
        }
        bounded_text("subject_locator", &self.subject_locator)?;
        optional_text("subject_revision", self.subject_revision.as_deref())?;
        optional_text("artifact_locator", self.artifact_locator.as_deref())?;
        bounded_text("profile", &self.profile)?;
        bounded_text("runner", &self.runner)?;
        bounded_text("build_posture", &self.build_posture)?;
        let mut campaign_ids = BTreeSet::new();
        for campaign in &self.campaigns {
            if !campaign_ids.insert(campaign.campaign_id.clone()) {
                return Err(CounterpartyRequestError::OutOfBounds("campaign_id"));
            }
            optional_text("objective", campaign.objective.as_deref())?;
            optional_text("expected_boundary", campaign.expected_boundary.as_deref())?;
            if campaign.required_capabilities.len() > 16 {
                return Err(CounterpartyRequestError::OutOfBounds(
                    "required_capabilities",
                ));
            }
        }
        Ok(())
    }

    /// Join every Scout campaign to exactly one operator session declaration.
    ///
    /// The join is all-or-nothing: a missing, duplicated, foreign, or
    /// mismatched session refuses the complete provider request before a
    /// runner can execute any campaign.
    pub fn join_session_bundle(
        &self,
        bundle: OperatorSessionBundle,
    ) -> Result<Vec<AssuranceSessionRequest>, CounterpartyRequestError> {
        self.validate()?;
        bundle.validate()?;
        equal("request_id", &self.request_id, &bundle.request_id)?;
        if bundle.sessions.len() != self.campaigns.len() {
            return Err(CounterpartyRequestError::OutOfBounds("operator_sessions"));
        }
        bundle
            .sessions
            .into_iter()
            .map(|session| self.join_session_request(session))
            .collect()
    }

    /// Join one campaign to an operator-authored strict session request.
    ///
    /// Fields absent from the counterparty schema remain operator inputs; all
    /// overlapping fields must be byte-for-byte equal. This is the only safe
    /// projection until the counterparty carries the missing facts itself.
    pub fn join_session_request(
        &self,
        session: AssuranceSessionRequest,
    ) -> Result<AssuranceSessionRequest, CounterpartyRequestError> {
        session
            .validate()
            .map_err(|error| CounterpartyRequestError::SessionRequest(error.to_string()))?;
        let campaign = self
            .campaigns
            .iter()
            .find(|campaign| campaign.campaign_id == session.session.campaign_id)
            .ok_or_else(|| {
                CounterpartyRequestError::CampaignMissing(session.session.campaign_id.clone())
            })?;
        equal("request_id", &self.request_id, &session.session.request_id)?;
        equal(
            "source_run_id",
            &self.source_run_id,
            &session.session.source_run_id,
        )?;
        equal(
            "campaign_id",
            &campaign.campaign_id,
            &session.session.campaign_id,
        )?;
        equal(
            "subject_kind",
            &self.subject_kind,
            &session.source.subject_kind,
        )?;
        equal(
            "subject_locator",
            &self.subject_locator,
            &session.source.subject_locator,
        )?;
        equal(
            "subject_revision",
            &self.subject_revision,
            &session.source.subject_revision,
        )?;
        equal(
            "source_digest",
            &self.source_digest,
            &session.source.source_digest,
        )?;
        equal(
            "artifact_locator",
            &self.artifact_locator,
            &session.source.artifact_locator,
        )?;
        equal(
            "requested_policy_digest",
            &self.requested_policy_digest,
            &session.source.requested_policy_digest,
        )?;
        equal(
            "finding_id",
            &campaign.finding_id,
            &session.source.finding_id,
        )?;
        let narrative_id = campaign
            .narrative_id
            .as_ref()
            .ok_or(CounterpartyRequestError::MissingField("narrative_id"))?;
        let objective = campaign
            .objective
            .as_ref()
            .ok_or(CounterpartyRequestError::MissingField("objective"))?;
        let expected_boundary = campaign
            .expected_boundary
            .as_ref()
            .ok_or(CounterpartyRequestError::MissingField("expected_boundary"))?;
        equal(
            "narrative_id",
            narrative_id,
            &session.narrative.narrative_id,
        )?;
        equal("objective", objective, &session.narrative.objective)?;
        equal(
            "expected_boundary",
            expected_boundary,
            &session.narrative.expected_boundary,
        )?;
        equal(
            "required_capabilities",
            &campaign.required_capabilities,
            &session.narrative.required_capabilities,
        )?;
        Ok(session)
    }
}

impl CampaignProviderResponse {
    /// Assemble a bounded response for the exact request identity.
    pub fn evaluated(
        request_id: AssuranceId,
        certifying: bool,
        evidence: Vec<TrialEvidenceRecord>,
    ) -> Result<Self, CounterpartyRequestError> {
        let response = Self {
            schema: CAMPAIGN_PROVIDER_RESPONSE_SCHEMA.to_string(),
            request_id,
            status: "evaluated".to_string(),
            certifying,
            missing_brokers: Vec::new(),
            evidence,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validate response bounds before crossing the controller frame.
    pub fn validate(&self) -> Result<(), CounterpartyRequestError> {
        if self.schema != CAMPAIGN_PROVIDER_RESPONSE_SCHEMA {
            return Err(CounterpartyRequestError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        bounded_text("status", &self.status)?;
        if self.evidence.len() > MAX_CAMPAIGNS || self.missing_brokers.len() > 32 {
            return Err(CounterpartyRequestError::OutOfBounds("response"));
        }
        for broker in &self.missing_brokers {
            bounded_text("missing_brokers", broker)?;
        }
        Ok(())
    }

    /// Serialize after revalidating bounds.
    pub fn to_json(&self) -> Result<Vec<u8>, CounterpartyRequestError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| CounterpartyRequestError::Malformed(error.to_string()))
    }
}

fn equal<T: PartialEq>(
    field: &'static str,
    counterparty: &T,
    session: &T,
) -> Result<(), CounterpartyRequestError> {
    if counterparty != session {
        return Err(CounterpartyRequestError::IdentityMismatch(field));
    }
    Ok(())
}

fn optional_text(field: &'static str, value: Option<&str>) -> Result<(), CounterpartyRequestError> {
    match value {
        Some(value) => bounded_text(field, value),
        None => Ok(()),
    }
}

fn bounded_text(field: &'static str, value: &str) -> Result<(), CounterpartyRequestError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CounterpartyRequestError::OutOfBounds(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> AssuranceSessionRequest {
        AssuranceSessionRequest::parse_json(include_bytes!(
            "../../fixtures/assurance-ai-session-request-v1.json"
        ))
        .expect("session fixture")
    }

    fn provider_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": CAMPAIGN_PROVIDER_REQUEST_SCHEMA,
            "request_id": "mvm-request-1",
            "source_run_id": "scout-1",
            "subject_kind": "local_repository",
            "subject_locator": "repository-ref-1",
            "subject_revision": "0123456789abcdef",
            "source_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "artifact_locator": "oci:example/app:1",
            "requested_policy_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "profile": "sealed",
            "runner": "mvm",
            "build_posture": "verified",
            "timeout_seconds": 600,
            "max_trials": 1,
            "require_disposable_target": true,
            "require_attestation": false,
            "campaigns": [{
                "campaign_id": "mvm-campaign-1",
                "finding_id": "SCOUT-RCE-001",
                "narrative_id": "mvm.boundary.process-exec.v1",
                "objective": "attempt the declared process effect",
                "expected_boundary": "the effect cannot cross from guest to host",
                "required_capabilities": ["observation.stream.v1"]
            }]
        }))
        .expect("provider JSON")
    }

    fn operator_bundle() -> OperatorSessionBundle {
        OperatorSessionBundle {
            schema: OPERATOR_SESSION_BUNDLE_SCHEMA.to_string(),
            request_id: AssuranceId::parse("mvm-request-1").expect("request id"),
            sessions: vec![session()],
        }
    }

    #[test]
    fn exact_counterparty_request_joins_an_operator_session_without_invention() {
        let provider = CampaignProviderRequest::parse_json(&provider_json()).expect("provider");
        assert_eq!(
            provider
                .join_session_request(session())
                .expect("all shared facts agree"),
            session()
        );
    }

    #[test]
    fn exact_operator_bundle_joins_every_campaign_without_invention() {
        let provider = CampaignProviderRequest::parse_json(&provider_json()).expect("provider");
        assert_eq!(
            provider
                .join_session_bundle(operator_bundle())
                .expect("complete exact join"),
            vec![session()]
        );
    }

    #[test]
    fn operator_bundle_rejects_unknown_fields_oversize_and_versions() {
        let mut value = serde_json::to_value(operator_bundle()).expect("bundle value");
        value
            .as_object_mut()
            .expect("object")
            .insert("mvm_binding".to_string(), serde_json::json!({}));
        assert!(matches!(
            OperatorSessionBundle::parse_json(&serde_json::to_vec(&value).expect("bundle JSON")),
            Err(CounterpartyRequestError::OperatorBundleMalformed(_))
        ));
        assert_eq!(
            OperatorSessionBundle::parse_json(&vec![b' '; MAX_CAMPAIGN_PROVIDER_BYTES + 1]),
            Err(CounterpartyRequestError::OperatorBundleTooLarge)
        );
        let mut unsupported = operator_bundle();
        unsupported.schema = "mvm.assurance.operator-session-bundle/v2".to_string();
        assert!(matches!(
            unsupported.validate(),
            Err(CounterpartyRequestError::UnsupportedOperatorBundleSchema(_))
        ));
    }

    #[test]
    fn operator_bundle_requires_one_unique_exact_session_per_campaign() {
        let provider = CampaignProviderRequest::parse_json(&provider_json()).expect("provider");
        let mut missing = operator_bundle();
        missing.sessions.clear();
        assert_eq!(
            provider.join_session_bundle(missing),
            Err(CounterpartyRequestError::OutOfBounds("operator_sessions"))
        );

        let mut duplicate = operator_bundle();
        duplicate.sessions.push(session());
        assert_eq!(
            duplicate.validate(),
            Err(CounterpartyRequestError::OutOfBounds(
                "operator_session.campaign_id"
            ))
        );

        let mut mismatch = operator_bundle();
        mismatch.sessions[0].source.finding_id =
            AssuranceId::parse("SCOUT-RCE-999").expect("finding id");
        assert_eq!(
            provider.join_session_bundle(mismatch),
            Err(CounterpartyRequestError::IdentityMismatch("finding_id"))
        );
    }

    #[test]
    fn unknown_fields_and_oversized_requests_fail_before_projection() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&provider_json()).expect("provider value");
        value
            .as_object_mut()
            .expect("object")
            .insert("mvm_binding".to_string(), serde_json::json!({}));
        let body = serde_json::to_vec(&value).expect("JSON");
        assert!(matches!(
            CampaignProviderRequest::parse_json(&body),
            Err(CounterpartyRequestError::Malformed(_))
        ));
        assert!(matches!(
            CampaignProviderRequest::parse_json(&vec![b' '; MAX_CAMPAIGN_PROVIDER_BYTES + 1]),
            Err(CounterpartyRequestError::TooLarge)
        ));
    }

    #[test]
    fn a_shared_identity_mismatch_fails_closed() {
        let provider = CampaignProviderRequest::parse_json(&provider_json()).expect("provider");
        let mut request = session();
        request.source.finding_id = AssuranceId::parse("SCOUT-RCE-999").expect("id");
        assert_eq!(
            provider.join_session_request(request),
            Err(CounterpartyRequestError::IdentityMismatch("finding_id"))
        );
    }

    #[test]
    fn a_missing_counterparty_narrative_is_not_invented_from_operator_data() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&provider_json()).expect("provider value");
        value["campaigns"][0]["objective"] = serde_json::Value::Null;
        let body = serde_json::to_vec(&value).expect("JSON");
        let provider = CampaignProviderRequest::parse_json(&body).expect("provider");
        assert_eq!(
            provider.join_session_request(session()),
            Err(CounterpartyRequestError::MissingField("objective"))
        );
    }

    #[test]
    fn evaluated_response_is_strict_bounded_and_request_bound() {
        let request = CampaignProviderRequest::parse_json(&provider_json()).expect("provider");
        let response =
            CampaignProviderResponse::evaluated(request.request_id.clone(), false, Vec::new())
                .expect("response");
        let encoded = response.to_json().expect("JSON");
        let decoded: CampaignProviderResponse =
            serde_json::from_slice(&encoded).expect("strict response");
        assert_eq!(decoded.request_id, request.request_id);

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).expect("value");
        value["outcome"] = serde_json::json!("PREVENTED");
        assert!(serde_json::from_value::<CampaignProviderResponse>(value).is_err());
    }
}
