//! Bounded, transport-free contracts for depth-one workload lifecycle delegation.
//!
//! These objects describe signed authority; they do not authenticate a caller.
//! Hosts resolve handle tokens against their journal and the authenticated boot,
//! and intersect exact templates with current host, tenant, and parent ceilings.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU64;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::assurance::Sha256Digest;
use crate::plan::{PlanId, TenantId, WorkloadId};
use crate::protocol::agent_capability::{
    ArgumentConstraint, ArgumentRule, CapabilityDescriptor, CapabilityError, CapabilityId,
    CapabilityLimits, SchemaRef,
};
use crate::protocol::broker::ServiceId;
use crate::protocol::mailbox::{BootId, ExecutionEpoch, MailboxAddress};

/// Maximum length of a plan-local identifier or mutation idempotency key.
pub const MAX_ACTOR_ID_BYTES: usize = 128;
/// Maximum number of exact templates in one lifecycle grant.
pub const MAX_ACTOR_TEMPLATES: usize = 32;
/// Maximum encoded lifecycle request, checked before deserializing.
pub const MAX_ACTOR_REQUEST_BYTES: usize = 4096;
/// Maximum encoded lifecycle response before decoding.
pub const MAX_ACTOR_RESPONSE_BYTES: usize = 4096;

/// Shared host/guest descriptor; only the three depth-one lifecycle verbs exist.
///
/// # Errors
/// Refuses unsupported verbs, rather than advertising unimplemented authority.
pub fn capability_descriptor(verb: &str) -> Result<CapabilityDescriptor, CapabilityError> {
    let operation = match verb {
        "launch_child" => "launch",
        "observe_child" => "observe_child",
        "release_child" => "release_child",
        _ => return Err(CapabilityError::InvalidVerb),
    };
    CapabilityDescriptor::builder()
        .id(CapabilityId::new(
            ServiceId::parse("host.actor.v1").expect("static actor service identity"),
            verb,
        )?)
        .description("Perform one exact, boot-bound child lifecycle operation")
        .input_schema(SchemaRef::new(
            "host.actor.request.v1",
            Sha256::digest(request_schema_document()).into(),
        )?)
        .output_schema(SchemaRef::new(
            "host.actor.response.v1",
            Sha256::digest(response_schema_document()).into(),
        )?)
        .limits(CapabilityLimits::new(4096, 4096, 60_000)?)
        .argument_policy(alloc::vec![ArgumentRule {
            pointer: "/operation/operation".into(),
            constraint: ArgumentConstraint::OneOf {
                values: alloc::vec![operation.into()],
            },
        }])
        .build()
}

fn schema_definitions() -> serde_json::Value {
    serde_json::json!({
        "id": {"type": "string", "minLength": 1, "maxLength": MAX_ACTOR_ID_BYTES,
               "pattern": "^[A-Za-z0-9._-]+$"},
        "bytes32": {"type": "array", "minItems": 32, "maxItems": 32,
                    "items": {"type": "integer", "minimum": 0, "maximum": 255}},
        "mailbox": {
            "type": "object", "additionalProperties": false,
            "required": ["tenant", "authorization_domain", "mailbox", "recipient"],
            "properties": {
                "tenant": {"$ref": "#/$defs/bytes32"},
                "authorization_domain": {"$ref": "#/$defs/bytes32"},
                "mailbox": {"$ref": "#/$defs/bytes32"},
                "recipient": {"$ref": "#/$defs/bytes32"}
            }
        },
        "handle": {
            "type": "object", "additionalProperties": false,
            "required": ["token", "mailbox"],
            "properties": {
                "token": {"$ref": "#/$defs/bytes32"},
                "mailbox": {"$ref": "#/$defs/mailbox"}
            }
        }
    })
}

// Sorting through a BTreeMap keeps canonical bytes independent of serde_json's
// optional insertion-order feature. Schemas contain only integer numbers.
fn canonical_schema_bytes(value: serde_json::Value) -> Vec<u8> {
    fn sorted(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let entries: alloc::collections::BTreeMap<_, _> = map
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect();
                serde_json::Value::Object(entries.into_iter().collect())
            }
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sorted).collect())
            }
            scalar => scalar,
        }
    }
    serde_json::to_vec(&sorted(value)).expect("static schema contains serializable JSON")
}

/// Canonical compact, key-sorted UTF-8 JSON Schema for the exact request DTO.
///
/// The descriptor hashes these document bytes, never the schema's name. Frame
/// length is enforced separately before parsing by the capability limits.
#[must_use]
pub fn request_schema_document() -> Vec<u8> {
    canonical_schema_bytes(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "host.actor.request.v1",
        "$defs": schema_definitions(),
        "type": "object", "additionalProperties": false,
        "required": ["version", "operation"],
        "properties": {
            "version": {"type": "integer", "const": 1},
            "operation": {
                "oneOf": [
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["operation", "grant_id", "template_id", "idempotency_key"],
                        "properties": {
                            "operation": {"const": "launch"},
                            "grant_id": {"$ref": "#/$defs/id"},
                            "template_id": {"$ref": "#/$defs/id"},
                            "idempotency_key": {"$ref": "#/$defs/id"}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["operation", "handle"],
                        "properties": {
                            "operation": {"const": "observe_child"},
                            "handle": {"$ref": "#/$defs/handle"}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["operation", "handle", "idempotency_key"],
                        "properties": {
                            "operation": {"const": "release_child"},
                            "handle": {"$ref": "#/$defs/handle"},
                            "idempotency_key": {"$ref": "#/$defs/id"}
                        }
                    }
                ]
            }
        }
    }))
}

/// Canonical compact, key-sorted UTF-8 JSON Schema for lifecycle knowledge.
#[must_use]
pub fn response_schema_document() -> Vec<u8> {
    canonical_schema_bytes(serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "host.actor.response.v1",
        "$defs": schema_definitions(),
        "type": "object", "additionalProperties": false,
        "required": ["version", "outcome"],
        "properties": {
            "version": {"type": "integer", "const": 1},
            "outcome": {
                "oneOf": [
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["status", "request_id"],
                        "properties": {
                            "status": {"enum": ["pending", "released", "unknown"]},
                            "request_id": {"$ref": "#/$defs/id"}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["status", "handle"],
                        "properties": {
                            "status": {"const": "running"},
                            "handle": {"$ref": "#/$defs/handle"}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["status", "code"],
                        "properties": {
                            "status": {"const": "refused"},
                            "code": {"enum": ["not_bound", "unauthorized", "stale_controller",
                                "expired", "unknown_template", "template_mismatch",
                                "request_conflict", "capacity", "unsupported", "unavailable"]}
                        }
                    }
                ]
            }
        }
    }))
}

/// Version one is the only supported lifecycle wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub enum ActorProtocolVersion {
    V1,
}

impl TryFrom<u16> for ActorProtocolVersion {
    type Error = ActorContractError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            _ => Err(ActorContractError::UnsupportedVersion),
        }
    }
}

impl From<ActorProtocolVersion> for u16 {
    fn from(_: ActorProtocolVersion) -> Self {
        1
    }
}

/// A bounded logical name, never a path, URI, or physical route.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ActorBindingId(String);

impl ActorBindingId {
    /// Parse an ASCII logical name.
    ///
    /// # Errors
    /// Refuses empty, oversized, or non-name input.
    pub fn new(value: impl Into<String>) -> Result<Self, ActorContractError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ACTOR_ID_BYTES
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(ActorContractError::InvalidId);
        }
        Ok(Self(value))
    }

    /// Borrow the logical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ActorBindingId {
    type Error = ActorContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ActorBindingId> for String {
    fn from(value: ActorBindingId) -> Self {
        value.0
    }
}

/// Boot-bound controller identity, with the signed plan ID supplied externally.
///
/// A root plan cannot embed its own content address. Admission binds this tuple
/// to the containing signed plan; child lineage names that already-signed plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerIdentity {
    pub tenant: TenantId,
    pub workload: WorkloadId,
    pub execution_epoch: ExecutionEpoch,
    pub boot_id: BootId,
    pub generation: NonZeroU64,
}

impl ControllerIdentity {
    /// Validate the existing string-based plan identities without changing them.
    pub fn validate(&self) -> Result<(), ActorContractError> {
        validate_plan_id(&self.tenant.0)?;
        validate_plan_id(&self.workload.0)
    }
}

fn validate_plan_id(value: &str) -> Result<(), ActorContractError> {
    if value.is_empty() || value.len() > MAX_ACTOR_ID_BYTES || value.chars().any(char::is_control) {
        return Err(ActorContractError::InvalidId);
    }
    Ok(())
}

/// The already-signed parent plan and the boot authorized by that plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParentIdentity {
    pub controller: ControllerIdentity,
    pub plan_id: PlanId,
}

/// One exact immutable host-held template; parameters travel only by mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateBinding {
    pub id: ActorBindingId,
    pub digest: Sha256Digest,
}

/// Children cannot delegate further in this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationDepth {
    One,
}

/// Closed set of initially supported lifecycle effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOperation {
    Launch,
    ObserveChild,
    ReleaseChild,
}

/// Explicit lifecycle authority inside a signed controller plan.
///
/// The constraint snapshot digest in the enclosing membership resolves to an
/// authenticated host-held budget and ceiling, not a controller-authored limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleGrant {
    pub id: ActorBindingId,
    pub controller: ControllerIdentity,
    pub depth: DelegationDepth,
    pub templates: Vec<TemplateBinding>,
    pub operations: Vec<LifecycleOperation>,
    pub not_before_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub workflow_deadline_unix_ms: i64,
}

impl LifecycleGrant {
    /// Check structural bounds. Signature, current time and ceilings remain host checks.
    ///
    /// # Errors
    /// Refuses invalid identities, windows, duplicate operations or template names.
    pub fn validate(&self) -> Result<(), ActorContractError> {
        self.controller.validate()?;
        if self.not_before_unix_ms < 0
            || self.not_before_unix_ms >= self.expires_at_unix_ms
            || self.expires_at_unix_ms > self.workflow_deadline_unix_ms
        {
            return Err(ActorContractError::InvalidValidityWindow);
        }
        if self.templates.is_empty() || self.templates.len() > MAX_ACTOR_TEMPLATES {
            return Err(ActorContractError::InvalidTemplates);
        }
        for (index, template) in self.templates.iter().enumerate() {
            if self.templates[..index]
                .iter()
                .any(|other| other.id == template.id)
            {
                return Err(ActorContractError::DuplicateTemplate);
            }
        }
        if self.operations.is_empty() || self.operations.len() > 3 {
            return Err(ActorContractError::InvalidOperations);
        }
        for (index, op) in self.operations.iter().enumerate() {
            if self.operations[..index].contains(op) {
                return Err(ActorContractError::InvalidOperations);
            }
        }
        Ok(())
    }

    /// Check a caller's operation at a host-supplied time.
    ///
    /// # Errors
    /// Refuses invalid grants, absent operations and times outside the signed window.
    pub fn check_operation(
        &self,
        operation: LifecycleOperation,
        now_unix_ms: i64,
    ) -> Result<(), ActorContractError> {
        self.validate()?;
        if now_unix_ms < self.not_before_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(ActorContractError::OutsideValidityWindow);
        }
        if !self.operations.contains(&operation) {
            return Err(ActorContractError::OperationNotGranted);
        }
        Ok(())
    }
}

/// Membership and authority are distinct; a worker cannot carry a lifecycle grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkflowRole {
    Controller { grant: LifecycleGrant },
    Worker { parent: ParentIdentity },
}

/// Optional signed workflow membership; absence means ordinary direct execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkflowBinding {
    pub version: ActorProtocolVersion,
    pub workflow_id: ActorBindingId,
    pub constraint_snapshot_digest: Sha256Digest,
    pub role: WorkflowRole,
}

impl WorkflowBinding {
    /// Validate membership without initializing any workflow machinery.
    ///
    /// # Errors
    /// Refuses invalid parent identities or malformed controller grants.
    pub fn validate(&self) -> Result<(), ActorContractError> {
        match &self.role {
            WorkflowRole::Controller { grant } => grant.validate(),
            WorkflowRole::Worker { parent } => {
                parent.controller.validate()?;
                validate_plan_id(&parent.plan_id.0)
            }
        }
    }
}

impl<'de> Deserialize<'de> for WorkflowBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            version: ActorProtocolVersion,
            workflow_id: ActorBindingId,
            constraint_snapshot_digest: Sha256Digest,
            role: WorkflowRole,
        }
        let wire = Wire::deserialize(deserializer)?;
        let binding = Self {
            version: wire.version,
            workflow_id: wire.workflow_id,
            constraint_snapshot_digest: wire.constraint_snapshot_digest,
            role: wire.role,
        };
        binding.validate().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

/// An unguessable host-issued lookup capability, never an encoded child identity.
///
/// Possession alone is insufficient: the host must match the authenticated caller,
/// current grant, exact token and mailbox to its durable child record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActorToken([u8; 32]);

impl ActorToken {
    /// Wrap host-generated cryptographically random bytes, or untrusted wire bytes.
    /// This constructor does not authenticate the token.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow bytes for journal lookup. Never write these bytes to logs.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ActorToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActorToken([REDACTED])")
    }
}

/// A lifecycle capability and its separately authorized canonical messaging address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorHandle {
    pub token: ActorToken,
    pub mailbox: MailboxAddress,
}

/// Exact lifecycle request with no mutable launch configuration or task payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActorOperation {
    Launch {
        grant_id: ActorBindingId,
        template_id: ActorBindingId,
        idempotency_key: ActorBindingId,
    },
    ObserveChild {
        handle: ActorHandle,
    },
    ReleaseChild {
        handle: ActorHandle,
        idempotency_key: ActorBindingId,
    },
}

/// Bounded versioned request carried only inside an authenticated encrypted channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorRequest {
    pub version: ActorProtocolVersion,
    pub operation: ActorOperation,
}

impl ActorRequest {
    /// Decode after bounding the entire untrusted frame.
    ///
    /// # Errors
    /// Refuses oversize frames, unsupported versions/operations, and unknown fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, ActorContractError> {
        if bytes.len() > MAX_ACTOR_REQUEST_BYTES {
            return Err(ActorContractError::RequestTooLarge);
        }
        serde_json::from_slice(bytes).map_err(|_| ActorContractError::InvalidRequest)
    }
}

/// Payload-free refusals; none disclose host routing or authentication material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRefusalCode {
    NotBound,
    Unauthorized,
    StaleController,
    Expired,
    UnknownTemplate,
    TemplateMismatch,
    RequestConflict,
    Capacity,
    Unsupported,
    Unavailable,
}

/// Durable lifecycle knowledge, separate from message delivery or application success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActorOutcome {
    /// Intent is committed but has no completed launch result yet.
    Pending { request_id: ActorBindingId },
    /// The exact child is admitted and running under this handle.
    Running { handle: ActorHandle },
    /// Child death, resource cleanup and the terminal record are all confirmed.
    Released { request_id: ActorBindingId },
    /// The operation was refused without granting new authority.
    Refused { code: ActorRefusalCode },
    /// Dispatch occurred but its outcome is uncertain; this never means released.
    Unknown { request_id: ActorBindingId },
}

/// Versioned lifecycle response with no application payload or duplicate mailbox receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorResponse {
    pub version: ActorProtocolVersion,
    pub outcome: ActorOutcome,
}

impl ActorResponse {
    /// Bound the frame and reject unsupported response shapes.
    ///
    /// # Errors
    /// Refuses oversized frames, unknown versions, statuses, codes, or fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, ActorContractError> {
        if bytes.len() > MAX_ACTOR_RESPONSE_BYTES {
            return Err(ActorContractError::ResponseTooLarge);
        }
        serde_json::from_slice(bytes).map_err(|_| ActorContractError::InvalidResponse)
    }
}

/// Structural contract refusals, containing no caller-controlled or secret bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActorContractError {
    #[error("unsupported actor protocol version")]
    UnsupportedVersion,
    #[error("invalid actor identifier")]
    InvalidId,
    #[error("invalid lifecycle validity window")]
    InvalidValidityWindow,
    #[error("lifecycle grant is not currently valid")]
    OutsideValidityWindow,
    #[error("invalid template allow-list")]
    InvalidTemplates,
    #[error("duplicate template binding")]
    DuplicateTemplate,
    #[error("invalid lifecycle operation set")]
    InvalidOperations,
    #[error("lifecycle operation not granted")]
    OperationNotGranted,
    #[error("actor request exceeds frame bound")]
    RequestTooLarge,
    #[error("invalid actor request")]
    InvalidRequest,
    #[error("actor response exceeds frame bound")]
    ResponseTooLarge,
    #[error("invalid actor response")]
    InvalidResponse,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use serde_json::json;

    fn controller() -> ControllerIdentity {
        ControllerIdentity {
            tenant: TenantId("tenant".into()),
            workload: WorkloadId("controller".into()),
            execution_epoch: ExecutionEpoch::new(1).unwrap(),
            boot_id: BootId::from_bytes([1; 32]),
            generation: NonZeroU64::new(1).unwrap(),
        }
    }

    fn binding() -> WorkflowBinding {
        WorkflowBinding {
            version: ActorProtocolVersion::V1,
            workflow_id: ActorBindingId::new("workflow").unwrap(),
            constraint_snapshot_digest: Sha256Digest::from_bytes(&[2; 32]),
            role: WorkflowRole::Controller {
                grant: LifecycleGrant {
                    id: ActorBindingId::new("grant").unwrap(),
                    controller: controller(),
                    depth: DelegationDepth::One,
                    templates: vec![TemplateBinding {
                        id: ActorBindingId::new("worker.small").unwrap(),
                        digest: Sha256Digest::from_bytes(&[3; 32]),
                    }],
                    operations: vec![
                        LifecycleOperation::Launch,
                        LifecycleOperation::ObserveChild,
                        LifecycleOperation::ReleaseChild,
                    ],
                    not_before_unix_ms: 10,
                    expires_at_unix_ms: 20,
                    workflow_deadline_unix_ms: 30,
                },
            },
        }
    }

    fn request() -> ActorRequest {
        ActorRequest {
            version: ActorProtocolVersion::V1,
            operation: ActorOperation::Launch {
                grant_id: ActorBindingId::new("grant").unwrap(),
                template_id: ActorBindingId::new("worker.small").unwrap(),
                idempotency_key: ActorBindingId::new("request-1").unwrap(),
            },
        }
    }

    #[test]
    fn capability_schema_documents_and_digests_are_frozen() {
        for (document, name, expected) in [
            (
                request_schema_document(),
                "host.actor.request.v1",
                "sha256:2928fb9fcd3f7f30369a25f7b80c870cc2ef0b069c886a02405fffb55e80b157",
            ),
            (
                response_schema_document(),
                "host.actor.response.v1",
                "sha256:e0101cf88cdad54fff26b3673d47ed335291ae0e03f5460d4ed81e17b7160615",
            ),
        ] {
            let schema: serde_json::Value = serde_json::from_slice(&document).unwrap();
            assert_eq!(schema["$id"], name);
            assert_eq!(schema["properties"]["version"]["const"], 1);
            assert_eq!(schema["additionalProperties"], false);
            assert_eq!(canonical_schema_bytes(schema), document);
            let digest: [u8; 32] = Sha256::digest(&document).into();
            assert_eq!(Sha256Digest::from_bytes(&digest).as_str(), expected);
            assert_ne!(digest, <[u8; 32]>::from(Sha256::digest(name.as_bytes())));
        }
        let descriptor = capability_descriptor("launch_child").unwrap();
        assert_eq!(descriptor.input_schema.name, "host.actor.request.v1");
        assert_eq!(descriptor.output_schema.name, "host.actor.response.v1");
        assert_eq!(
            descriptor.input_schema.digest,
            <[u8; 32]>::from(Sha256::digest(request_schema_document()))
        );
        assert_eq!(
            descriptor.output_schema.digest,
            <[u8; 32]>::from(Sha256::digest(response_schema_document()))
        );
    }

    #[test]
    fn descriptors_are_closed_bounded_and_pin_the_payload_operation() {
        use crate::protocol::agent_capability::evaluate_argument_policy;
        let verbs = [
            ("launch_child", "launch"),
            ("observe_child", "observe_child"),
            ("release_child", "release_child"),
        ];
        for (verb, operation) in verbs {
            let descriptor = capability_descriptor(verb).unwrap();
            assert_eq!(descriptor.id.service.as_str(), "host.actor.v1");
            assert_eq!(descriptor.id.verb, verb);
            assert_eq!(
                descriptor.limits.max_input_bytes as usize,
                MAX_ACTOR_REQUEST_BYTES
            );
            assert_eq!(
                descriptor.limits.max_output_bytes as usize,
                MAX_ACTOR_RESPONSE_BYTES
            );
            assert_eq!(descriptor.limits.timeout_ms, 60_000);
            for (_, payload_operation) in verbs {
                let result = evaluate_argument_policy(
                    &descriptor.argument_policy,
                    &json!({"operation": {"operation": payload_operation}}),
                );
                assert_eq!(result.is_ok(), operation == payload_operation);
            }
        }
        for unsupported in ["launch", "pause", "resume", "restore", "delegate", ""] {
            assert_eq!(
                capability_descriptor(unsupported),
                Err(CapabilityError::InvalidVerb)
            );
        }
        let schema: serde_json::Value = serde_json::from_slice(&request_schema_document()).unwrap();
        let operations = schema["properties"]["operation"]["oneOf"]
            .as_array()
            .unwrap();
        assert_eq!(operations.len(), 3);
        for (branch, (_, operation)) in operations.iter().zip(verbs) {
            assert_eq!(branch["properties"]["operation"]["const"], operation);
            assert_eq!(branch["additionalProperties"], false);
        }
    }

    #[test]
    fn controller_and_worker_membership_roundtrip() {
        let mut value = binding();
        assert_eq!(
            serde_json::from_slice::<WorkflowBinding>(&serde_json::to_vec(&value).unwrap())
                .unwrap(),
            value
        );
        value.role = WorkflowRole::Worker {
            parent: ParentIdentity {
                controller: controller(),
                plan_id: PlanId("sha256:parent-signed-plan".into()),
            },
        };
        assert_eq!(
            serde_json::from_slice::<WorkflowBinding>(&serde_json::to_vec(&value).unwrap())
                .unwrap(),
            value
        );
        let mut worker = serde_json::to_value(value).unwrap();
        worker["role"]["grant"] = serde_json::to_value(binding()).unwrap()["role"]["grant"].clone();
        assert!(serde_json::from_value::<WorkflowBinding>(worker).is_err());
    }

    #[test]
    fn membership_and_depth_are_not_optional_authority_defaults() {
        let valid = serde_json::to_value(binding()).unwrap();
        for field in [
            "version",
            "workflow_id",
            "constraint_snapshot_digest",
            "role",
        ] {
            let mut invalid = valid.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<WorkflowBinding>(invalid).is_err(),
                "{field}"
            );
        }
        for depth in [json!(0), json!(2), json!("recursive"), json!(null)] {
            let mut invalid = valid.clone();
            invalid["role"]["grant"]["depth"] = depth;
            assert!(serde_json::from_value::<WorkflowBinding>(invalid).is_err());
        }
        let mut invalid = valid;
        invalid["role"]["grant"]["controller"]["generation"] = json!(0);
        assert!(serde_json::from_value::<WorkflowBinding>(invalid).is_err());
    }

    #[test]
    fn duplicate_templates_and_invalid_windows_are_refused_on_decode() {
        let valid = serde_json::to_value(binding()).unwrap();
        for conflicting in [false, true] {
            let mut invalid = valid.clone();
            let mut duplicate = invalid["role"]["grant"]["templates"][0].clone();
            if conflicting {
                duplicate["digest"] = json!(Sha256Digest::from_bytes(&[9; 32]));
            }
            invalid["role"]["grant"]["templates"]
                .as_array_mut()
                .unwrap()
                .push(duplicate);
            assert!(serde_json::from_value::<WorkflowBinding>(invalid).is_err());
        }
        for (field, value) in [
            ("templates", json!([])),
            (
                "templates",
                json!(vec![valid["role"]["grant"]["templates"][0].clone(); 33]),
            ),
            ("operations", json!([])),
            ("operations", json!(["launch", "launch"])),
            ("operations", json!(["pause"])),
            ("not_before_unix_ms", json!(-1)),
            ("expires_at_unix_ms", json!(10)),
            ("workflow_deadline_unix_ms", json!(19)),
        ] {
            let mut invalid = valid.clone();
            invalid["role"]["grant"][field] = value;
            assert!(
                serde_json::from_value::<WorkflowBinding>(invalid).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn operations_obey_signed_time_and_explicit_subset() {
        let WorkflowRole::Controller { mut grant } = binding().role else {
            panic!("fixture is controller");
        };
        assert!(
            grant
                .check_operation(LifecycleOperation::Launch, 10)
                .is_ok()
        );
        assert!(
            grant
                .check_operation(LifecycleOperation::Launch, 19)
                .is_ok()
        );
        for now in [-1, 9, 20, 30, i64::MAX] {
            assert_eq!(
                grant.check_operation(LifecycleOperation::Launch, now),
                Err(ActorContractError::OutsideValidityWindow)
            );
        }
        grant.operations = vec![LifecycleOperation::ObserveChild];
        assert_eq!(
            grant.check_operation(LifecycleOperation::Launch, 15),
            Err(ActorContractError::OperationNotGranted)
        );
    }

    #[test]
    fn ids_and_tokens_are_bounded_and_tokens_redacted() {
        for id in ["", "host/path", "host:123", "\n", &"x".repeat(129)] {
            assert!(ActorBindingId::new(id).is_err());
            assert!(serde_json::from_value::<ActorBindingId>(json!(id)).is_err());
        }
        assert!(ActorBindingId::new("x".repeat(128)).is_ok());
        for length in [0, 1, 31, 33, 256] {
            assert!(serde_json::from_value::<ActorToken>(json!(vec![7; length])).is_err());
        }
        let token = ActorToken::from_bytes([7; 32]);
        assert_eq!(format!("{token:?}"), "ActorToken([REDACTED])");
        assert_eq!(
            serde_json::from_value::<ActorToken>(json!(vec![7; 32])).unwrap(),
            token
        );
    }

    #[test]
    fn exact_request_has_no_host_routing_or_mutable_launch_payload() {
        let bytes = serde_json::to_vec(&request()).unwrap();
        assert_eq!(ActorRequest::decode(&bytes).unwrap(), request());
        assert_eq!(
            ActorRequest::decode(&vec![b' '; MAX_ACTOR_REQUEST_BYTES + 1]),
            Err(ActorContractError::RequestTooLarge)
        );
        for field in [
            "vm_name",
            "cid",
            "socket",
            "path",
            "pid",
            "node",
            "keys",
            "argv",
            "env",
            "resources",
            "backend",
            "placement",
            "input",
        ] {
            let mut wire = serde_json::to_value(request()).unwrap();
            wire["operation"][field] = json!("untrusted");
            assert!(
                ActorRequest::decode(&serde_json::to_vec(&wire).unwrap()).is_err(),
                "{field}"
            );
        }
        for version in [json!(0), json!(2), json!("1"), json!(null)] {
            let mut wire = serde_json::to_value(request()).unwrap();
            wire["version"] = version;
            assert!(ActorRequest::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
        }
        for operation in ["pause", "resume", "restore", "delegate", "plan"] {
            let mut wire = serde_json::to_value(request()).unwrap();
            wire["operation"]["operation"] = json!(operation);
            assert!(ActorRequest::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
        }
    }

    #[test]
    fn handle_uses_only_token_and_canonical_mailbox() {
        use crate::protocol::mailbox::{AuthorizationDomainId, MailboxId, PrincipalId};
        let handle = ActorHandle {
            token: ActorToken::from_bytes([7; 32]),
            mailbox: MailboxAddress {
                tenant: crate::protocol::mailbox::TenantId::from_bytes([1; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([2; 32]),
                mailbox: MailboxId::from_bytes([3; 32]),
                recipient: PrincipalId::from_bytes([4; 32]),
            },
        };
        for operation in [
            ActorOperation::ObserveChild {
                handle: handle.clone(),
            },
            ActorOperation::ReleaseChild {
                handle: handle.clone(),
                idempotency_key: ActorBindingId::new("release-1").unwrap(),
            },
        ] {
            let request = ActorRequest {
                version: ActorProtocolVersion::V1,
                operation,
            };
            assert_eq!(
                ActorRequest::decode(&serde_json::to_vec(&request).unwrap()).unwrap(),
                request
            );
        }
        for field in [
            "child_id", "vm_name", "cid", "socket", "path", "pid", "node", "keys",
        ] {
            let mut wire = serde_json::to_value(&handle).unwrap();
            wire[field] = json!("untrusted");
            assert!(
                serde_json::from_value::<ActorHandle>(wire).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn direct_plan_has_no_workflow_or_lifecycle_service() {
        let plan = crate::plan::execution_plan::minimal_plan();
        assert!(plan.workflow.is_none());
        let bytes = serde_json::to_vec(&plan).unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(wire.get("workflow").is_none());
        assert!(!format!("{:?}", plan.services).contains("workflow"));
        let restored: crate::plan::ExecutionPlan = serde_json::from_slice(&bytes).unwrap();
        assert!(restored.workflow.is_none());
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
    }

    #[test]
    fn responses_preserve_uncertainty_and_refuse_extra_authority() {
        let request_id = ActorBindingId::new("request-1").unwrap();
        for outcome in [
            ActorOutcome::Pending {
                request_id: request_id.clone(),
            },
            ActorOutcome::Released {
                request_id: request_id.clone(),
            },
            ActorOutcome::Unknown { request_id },
            ActorOutcome::Refused {
                code: ActorRefusalCode::NotBound,
            },
        ] {
            let response = ActorResponse {
                version: ActorProtocolVersion::V1,
                outcome,
            };
            let bytes = serde_json::to_vec(&response).unwrap();
            assert!(bytes.len() < MAX_ACTOR_RESPONSE_BYTES);
            assert_eq!(ActorResponse::decode(&bytes).unwrap(), response);
            let mut wire = serde_json::to_value(&response).unwrap();
            wire["outcome"]["pid"] = json!(42);
            assert!(ActorResponse::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
        }
        for wire in [
            json!({"version": 2, "outcome": {"status": "refused", "code": "not_bound"}}),
            json!({"version": 1, "outcome": {"status": "refused", "code": "arbitrary"}}),
            json!({"version": 1, "outcome": {"status": "destroyed"}}),
        ] {
            assert!(ActorResponse::decode(&serde_json::to_vec(&wire).unwrap()).is_err());
        }
        assert_eq!(
            ActorResponse::decode(&vec![b' '; MAX_ACTOR_RESPONSE_BYTES + 1]),
            Err(ActorContractError::ResponseTooLarge)
        );
    }
}
