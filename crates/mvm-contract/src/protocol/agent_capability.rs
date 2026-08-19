//! Versioned host-mediated capability bindings for agent calls.
//!
//! A capability is a specific versioned service verb, not an arbitrary host
//! function. The descriptor advertises stable schema identities and resource
//! limits; the binding pins the descriptor digest that admission approved; an
//! invocation carries only a bounded id and a digest of the existing payload.
//! Payload bytes, credentials, and handler errors never enter the audit DTOs.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::agent_session::AgentRequestId;
use super::broker::ServiceId;

/// Current wire version for typed capability invocations.
pub const AGENT_CAPABILITY_PROTOCOL_VERSION: u16 = 1;
/// Maximum descriptor description length.
pub const MAX_DESCRIPTION_BYTES: usize = 512;
/// Maximum schema-name length.
pub const MAX_SCHEMA_NAME_BYTES: usize = 128;
/// Maximum accepted capability input or output size.
pub const MAX_CAPABILITY_PAYLOAD_BYTES: u32 = 256 * 1024;
/// Maximum handler execution time.
pub const MAX_CAPABILITY_TIMEOUT_MS: u32 = 60_000;

/// A versioned service verb that can be admitted independently.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CapabilityId {
    /// Versioned host service identity.
    pub service: ServiceId,
    /// Verb within the versioned service.
    pub verb: String,
}

impl CapabilityId {
    /// Construct a validated capability identity.
    pub fn new(service: ServiceId, verb: impl Into<String>) -> Result<Self, CapabilityError> {
        let verb = verb.into();
        if verb.is_empty() {
            return Err(CapabilityError::EmptyVerb);
        }
        if verb.len() > MAX_SCHEMA_NAME_BYTES
            || !verb.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
            })
        {
            return Err(CapabilityError::InvalidVerb);
        }
        Ok(Self { service, verb })
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}::{}", self.service, self.verb)
    }
}

/// A stable schema identity and digest. The schema document remains on the
/// host/SDK side; only this bounded reference crosses the agent boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SchemaRef {
    /// Stable schema name, including its schema version.
    pub name: String,
    /// SHA-256 of the canonical schema document.
    pub digest: [u8; 32],
}

impl SchemaRef {
    /// Construct a validated schema reference.
    pub fn new(name: impl Into<String>, digest: [u8; 32]) -> Result<Self, CapabilityError> {
        let name = name.into();
        if name.is_empty() {
            return Err(CapabilityError::EmptySchemaName);
        }
        if name.len() > MAX_SCHEMA_NAME_BYTES
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(CapabilityError::InvalidSchemaName);
        }
        Ok(Self { name, digest })
    }
}

/// Resource bounds the host must enforce for one capability invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CapabilityLimits {
    /// Maximum serialized input payload size.
    pub max_input_bytes: u32,
    /// Maximum serialized output payload size.
    pub max_output_bytes: u32,
    /// Maximum handler execution time.
    pub timeout_ms: u32,
}

impl CapabilityLimits {
    /// Construct bounds, rejecting zero and values above the protocol caps.
    pub fn new(
        max_input_bytes: u32,
        max_output_bytes: u32,
        timeout_ms: u32,
    ) -> Result<Self, CapabilityError> {
        if max_input_bytes == 0
            || max_output_bytes == 0
            || max_input_bytes > MAX_CAPABILITY_PAYLOAD_BYTES
            || max_output_bytes > MAX_CAPABILITY_PAYLOAD_BYTES
            || timeout_ms == 0
            || timeout_ms > MAX_CAPABILITY_TIMEOUT_MS
        {
            return Err(CapabilityError::InvalidLimits);
        }
        Ok(Self {
            max_input_bytes,
            max_output_bytes,
            timeout_ms,
        })
    }
}

/// One constraint on one argument position inside a capability payload.
///
/// Deliberately a closed, bounded vocabulary rather than an embedded
/// expression language: a policy an operator cannot read is a policy nobody
/// audits, and an evaluator with loops is an evaluator with a denial of
/// service in it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ArgumentConstraint {
    /// The value must be a string drawn from this exact set.
    OneOf {
        /// Permitted values.
        values: Vec<String>,
    },
    /// The value must be a string under one of these prefixes, carrying no
    /// `..` segment.
    PathUnder {
        /// Permitted path prefixes.
        prefixes: Vec<String>,
    },
    /// The value's UTF-8 length must not exceed this.
    MaxLen {
        /// Inclusive upper bound in bytes.
        bytes: u32,
    },
}

impl ArgumentConstraint {
    /// A stable, value-free label for audit and refusal messages.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::OneOf { .. } => "one_of",
            Self::PathUnder { .. } => "path_under",
            Self::MaxLen { .. } => "max_len",
        }
    }
}

/// A constraint bound to one location in the payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ArgumentRule {
    /// RFC 6901 JSON pointer into the payload, e.g. `/destination`.
    pub pointer: String,
    /// The constraint the value at that pointer must satisfy.
    pub constraint: ArgumentConstraint,
}

/// Why an argument policy refused a call. Carries the location and the rule
/// kind, never the offending value: a refusal is audited, and an audited
/// refusal that quotes the argument re-publishes whatever the argument held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentRefusal {
    /// Pointer of the rule that refused.
    pub pointer: String,
    /// Stable kind label of the constraint that refused.
    pub kind: &'static str,
}

/// Evaluate an argument policy against a payload.
///
/// A pointer that resolves to nothing is a refusal rather than a pass: a rule
/// naming an argument the payload omits would otherwise be satisfied by
/// leaving the argument out, which is the opposite of what the rule says.
///
/// # Errors
///
/// Returns the first rule that refuses, in policy order.
pub fn evaluate_argument_policy(
    rules: &[ArgumentRule],
    payload: &serde_json::Value,
) -> Result<(), ArgumentRefusal> {
    for rule in rules {
        let refusal = || ArgumentRefusal {
            pointer: rule.pointer.clone(),
            kind: rule.constraint.kind(),
        };
        let Some(value) = payload.pointer(&rule.pointer) else {
            return Err(refusal());
        };
        let Some(text) = value.as_str() else {
            return Err(refusal());
        };
        let ok = match &rule.constraint {
            ArgumentConstraint::OneOf { values } => values.iter().any(|v| v == text),
            ArgumentConstraint::PathUnder { prefixes } => {
                !text.split('/').any(|segment| segment == "..")
                    && prefixes
                        .iter()
                        .any(|prefix| text.starts_with(prefix.as_str()))
            }
            ArgumentConstraint::MaxLen { bytes } => text.len() <= *bytes as usize,
        };
        if !ok {
            return Err(refusal());
        }
    }
    Ok(())
}

/// Host-advertised metadata for one capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CapabilityDescriptor {
    /// Exact service and verb identity.
    pub id: CapabilityId,
    /// Human-readable description with no credential or host-path content.
    pub description: String,
    /// Input schema reference.
    pub input_schema: SchemaRef,
    /// Output schema reference.
    pub output_schema: SchemaRef,
    /// Enforced execution and payload bounds.
    pub limits: CapabilityLimits,
    /// Host-side constraints on argument values, evaluated before dispatch.
    #[serde(default)]
    pub argument_policy: Vec<ArgumentRule>,
}

impl CapabilityDescriptor {
    /// Begin descriptor construction.
    pub fn builder() -> CapabilityDescriptorBuilder {
        CapabilityDescriptorBuilder::default()
    }

    /// Digest the canonical serde representation used by admission binding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self)
            .expect("capability descriptor contains only serializable fields");
        Sha256::digest(bytes).into()
    }

    /// Produce the exact binding an admission record should carry.
    #[must_use]
    pub fn binding(&self) -> CapabilityBinding {
        CapabilityBinding {
            capability: self.id.clone(),
            descriptor_digest: self.digest(),
        }
    }
}

/// Builder for the multi-field capability descriptor.
#[derive(Debug, Default)]
pub struct CapabilityDescriptorBuilder {
    id: Option<CapabilityId>,
    description: Option<String>,
    input_schema: Option<SchemaRef>,
    output_schema: Option<SchemaRef>,
    limits: Option<CapabilityLimits>,
    argument_policy: Vec<ArgumentRule>,
}

impl CapabilityDescriptorBuilder {
    /// Set the capability identity.
    pub fn id(mut self, id: CapabilityId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the public description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the input schema reference.
    pub fn input_schema(mut self, schema: SchemaRef) -> Self {
        self.input_schema = Some(schema);
        self
    }

    /// Set the output schema reference.
    pub fn output_schema(mut self, schema: SchemaRef) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Set the execution and payload limits.
    pub fn limits(mut self, limits: CapabilityLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Set the host-side argument policy. Absent means no constraint beyond
    /// the payload bounds in [`CapabilityLimits`].
    pub fn argument_policy(mut self, rules: Vec<ArgumentRule>) -> Self {
        self.argument_policy = rules;
        self
    }

    /// Validate and build the descriptor.
    pub fn build(self) -> Result<CapabilityDescriptor, CapabilityError> {
        let description = self
            .description
            .ok_or(CapabilityError::MissingField("description"))?;
        if description.is_empty() || description.len() > MAX_DESCRIPTION_BYTES {
            return Err(CapabilityError::InvalidDescription);
        }
        Ok(CapabilityDescriptor {
            id: self.id.ok_or(CapabilityError::MissingField("id"))?,
            description,
            input_schema: self
                .input_schema
                .ok_or(CapabilityError::MissingField("input_schema"))?,
            output_schema: self
                .output_schema
                .ok_or(CapabilityError::MissingField("output_schema"))?,
            limits: self.limits.ok_or(CapabilityError::MissingField("limits"))?,
            argument_policy: self.argument_policy,
        })
    }
}

/// Exact descriptor identity admitted for one workload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CapabilityBinding {
    /// Capability identity approved by admission.
    pub capability: CapabilityId,
    /// Digest of the complete descriptor approved by admission.
    pub descriptor_digest: [u8; 32],
}

impl CapabilityBinding {
    /// Check this binding against a host descriptor.
    pub fn matches(&self, descriptor: &CapabilityDescriptor) -> bool {
        self.capability == descriptor.id && self.descriptor_digest == descriptor.digest()
    }
}

/// Typed invocation metadata carried alongside the existing broker payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CapabilityInvocation {
    /// Version of this invocation contract.
    pub protocol_version: u16,
    /// Exact binding the caller claims to use.
    pub binding: CapabilityBinding,
    /// Bounded request identity used for replay refusal and audit joins.
    pub invocation_id: AgentRequestId,
    /// Digest of the `ServiceCall::payload` value.
    pub input_digest: [u8; 32],
}

impl CapabilityInvocation {
    /// Build a typed invocation and digest its payload without retaining it.
    pub fn from_payload<T: Serialize>(
        binding: CapabilityBinding,
        invocation_id: AgentRequestId,
        payload: &T,
    ) -> Result<Self, CapabilityError> {
        let bytes = serde_json::to_vec(payload).map_err(|_| CapabilityError::PayloadEncoding)?;
        Ok(Self {
            protocol_version: AGENT_CAPABILITY_PROTOCOL_VERSION,
            binding,
            invocation_id,
            input_digest: Sha256::digest(bytes).into(),
        })
    }

    /// Verify the invocation metadata and payload digest against a descriptor.
    pub fn validate_payload<T: Serialize>(
        &self,
        descriptor: &CapabilityDescriptor,
        payload: &T,
    ) -> Result<(), CapabilityFailureCode> {
        if self.protocol_version != AGENT_CAPABILITY_PROTOCOL_VERSION {
            return Err(CapabilityFailureCode::ProtocolMismatch);
        }
        if !self.binding.matches(descriptor) {
            return Err(CapabilityFailureCode::BindingMismatch);
        }
        let bytes = serde_json::to_vec(payload).map_err(|_| CapabilityFailureCode::InvalidInput)?;
        if Sha256::digest(bytes) != self.input_digest {
            return Err(CapabilityFailureCode::InputDigestMismatch);
        }
        Ok(())
    }
}

/// Closed failure vocabulary safe to expose to an agent and to audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum CapabilityFailureCode {
    ProtocolMismatch,
    NotRegistered,
    AdmissionDenied,
    BindingMismatch,
    InputDigestMismatch,
    InputTooLarge,
    InvalidInput,
    ArgumentRefused,
    OutputTooLarge,
    Timeout,
    Canceled,
    Replay,
    HandlerFailed,
}

/// Digest-only evidence of capability lifecycle and invocation outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum CapabilityAuditEvent {
    Registered {
        capability: CapabilityId,
        descriptor_digest: [u8; 32],
    },
    Admitted {
        capability: CapabilityId,
        descriptor_digest: [u8; 32],
    },
    Invoked {
        capability: CapabilityId,
        descriptor_digest: [u8; 32],
        invocation_id: AgentRequestId,
        input_digest: [u8; 32],
    },
    Completed {
        capability: CapabilityId,
        invocation_id: AgentRequestId,
        output_digest: [u8; 32],
    },
    Refused {
        capability: CapabilityId,
        invocation_id: Option<AgentRequestId>,
        code: CapabilityFailureCode,
    },
    TimedOut {
        capability: CapabilityId,
        invocation_id: AgentRequestId,
    },
    Canceled {
        capability: CapabilityId,
        invocation_id: AgentRequestId,
    },
    Failed {
        capability: CapabilityId,
        invocation_id: AgentRequestId,
        code: CapabilityFailureCode,
    },
}

/// Contract construction and encoding errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum CapabilityError {
    #[error("capability verb is empty")]
    EmptyVerb,
    #[error("capability verb is invalid")]
    InvalidVerb,
    #[error("schema name is empty")]
    EmptySchemaName,
    #[error("schema name is invalid")]
    InvalidSchemaName,
    #[error("capability limits are outside the supported bounds")]
    InvalidLimits,
    #[error("capability description is invalid")]
    InvalidDescription,
    #[error("capability descriptor is missing {0}")]
    MissingField(&'static str),
    #[error("capability payload could not be encoded")]
    PayloadEncoding,
}

/// Digest a serialized output for a completion audit event.
#[must_use]
pub fn payload_digest<T: Serialize>(payload: &T) -> [u8; 32] {
    let bytes = serde_json::to_vec(payload).expect("capability payload is serializable");
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.dev.echo.v1").expect("service id"),
                "echo",
            )
            .expect("capability id"))
            .description("echoes a bounded structured value")
            .input_schema(SchemaRef::new("host.dev.echo.input.v1", [1; 32]).expect("schema"))
            .output_schema(SchemaRef::new("host.dev.echo.output.v1", [2; 32]).expect("schema"))
            .limits(CapabilityLimits::new(1024, 2048, 100).expect("limits"))
            .build()
            .expect("descriptor")
    }

    #[test]
    fn descriptor_digest_binds_identity_schemas_and_limits() {
        let descriptor = descriptor();
        let binding = descriptor.binding();
        assert!(binding.matches(&descriptor));

        let mut changed = descriptor.clone();
        changed.limits.timeout_ms = 101;
        assert!(!binding.matches(&changed));
    }

    #[test]
    fn invocation_round_trip_and_payload_digest_are_stable() {
        let descriptor = descriptor();
        let invocation = CapabilityInvocation::from_payload(
            descriptor.binding(),
            AgentRequestId::parse("request-1").expect("request id"),
            &serde_json::json!({"value": 7}),
        )
        .expect("invocation");
        invocation
            .validate_payload(&descriptor, &serde_json::json!({"value": 7}))
            .expect("valid payload");
        let bytes = serde_json::to_vec(&invocation).expect("serialize");
        let parsed: CapabilityInvocation = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(parsed, invocation);
    }

    #[test]
    fn binding_mismatch_and_input_tampering_fail_closed() {
        let descriptor = descriptor();
        let mut invocation = CapabilityInvocation::from_payload(
            descriptor.binding(),
            AgentRequestId::parse("request-2").expect("request id"),
            &serde_json::json!({"value": 7}),
        )
        .expect("invocation");
        invocation.input_digest = [9; 32];
        assert_eq!(
            invocation.validate_payload(&descriptor, &serde_json::json!({"value": 7})),
            Err(CapabilityFailureCode::InputDigestMismatch)
        );

        let mut binding = descriptor.binding();
        binding.descriptor_digest = [8; 32];
        invocation.binding = binding;
        assert_eq!(
            invocation.validate_payload(&descriptor, &serde_json::json!({"value": 7})),
            Err(CapabilityFailureCode::BindingMismatch)
        );
    }

    #[test]
    fn audit_event_does_not_contain_payload_bytes() {
        let descriptor = descriptor();
        let secret = "do-not-cross-boundary";
        let event = CapabilityAuditEvent::Invoked {
            capability: descriptor.id.clone(),
            descriptor_digest: descriptor.digest(),
            invocation_id: AgentRequestId::parse("request-3").expect("request id"),
            input_digest: payload_digest(&secret),
        };
        let encoded = serde_json::to_string(&event).expect("serialize");
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("payload"));
    }

    fn rule(pointer: &str, constraint: ArgumentConstraint) -> ArgumentRule {
        ArgumentRule {
            pointer: pointer.into(),
            constraint,
        }
    }

    #[test]
    fn one_of_admits_a_listed_value_and_refuses_anything_else() {
        let rules = [rule(
            "/destination",
            ArgumentConstraint::OneOf {
                values: alloc::vec!["api.example.com".into()],
            },
        )];
        let ok = serde_json::json!({"destination": "api.example.com"});
        assert!(evaluate_argument_policy(&rules, &ok).is_ok());

        let bad = serde_json::json!({"destination": "attacker.example.com"});
        let refusal = evaluate_argument_policy(&rules, &bad).expect_err("must refuse");
        assert_eq!(refusal.pointer, "/destination");
        assert_eq!(refusal.kind, "one_of");
    }

    #[test]
    fn path_under_refuses_a_traversal_segment_even_below_the_prefix() {
        let rules = [rule(
            "/path",
            ArgumentConstraint::PathUnder {
                prefixes: alloc::vec!["/work/".into()],
            },
        )];
        let ok = serde_json::json!({"path": "/work/report.txt"});
        assert!(evaluate_argument_policy(&rules, &ok).is_ok());

        let escape = serde_json::json!({"path": "/work/../etc/shadow"});
        assert!(
            evaluate_argument_policy(&rules, &escape).is_err(),
            "a prefix match is not containment once `..` is in play"
        );
    }

    #[test]
    fn path_under_refuses_a_value_outside_every_prefix() {
        let rules = [rule(
            "/path",
            ArgumentConstraint::PathUnder {
                prefixes: alloc::vec!["/work/".into()],
            },
        )];
        let outside = serde_json::json!({"path": "/etc/shadow"});
        assert!(evaluate_argument_policy(&rules, &outside).is_err());
    }

    #[test]
    fn max_len_is_inclusive_at_the_bound() {
        let rules = [rule("/q", ArgumentConstraint::MaxLen { bytes: 4 })];
        assert!(evaluate_argument_policy(&rules, &serde_json::json!({"q": "abcd"})).is_ok());
        assert!(evaluate_argument_policy(&rules, &serde_json::json!({"q": "abcde"})).is_err());
    }

    #[test]
    fn a_pointer_resolving_to_nothing_is_refused_not_skipped() {
        let rules = [rule(
            "/destination",
            ArgumentConstraint::OneOf {
                values: alloc::vec!["api.example.com".into()],
            },
        )];
        let missing = serde_json::json!({"other": "api.example.com"});
        assert!(
            evaluate_argument_policy(&rules, &missing).is_err(),
            "omitting the argument must not satisfy a rule about it"
        );
    }

    #[test]
    fn a_non_string_value_is_refused() {
        let rules = [rule("/q", ArgumentConstraint::MaxLen { bytes: 64 })];
        let numeric = serde_json::json!({"q": 7});
        assert!(evaluate_argument_policy(&rules, &numeric).is_err());
    }

    #[test]
    fn argument_policy_participates_in_the_descriptor_digest() {
        fn build(policy: Vec<ArgumentRule>) -> CapabilityDescriptor {
            CapabilityDescriptor::builder()
                .id(CapabilityId::new(
                    ServiceId::parse("host.dev.echo.v1").expect("service"),
                    "echo",
                )
                .expect("capability"))
                .description("echo")
                .input_schema(SchemaRef::new("in.v1", [1; 32]).expect("schema"))
                .output_schema(SchemaRef::new("out.v1", [2; 32]).expect("schema"))
                .limits(CapabilityLimits::new(64, 64, 10).expect("limits"))
                .argument_policy(policy)
                .build()
                .expect("descriptor")
        }
        assert_ne!(
            build(alloc::vec![]).digest(),
            build(alloc::vec![rule(
                "/q",
                ArgumentConstraint::MaxLen { bytes: 4 }
            )])
            .digest(),
            "a policy outside the digest could be swapped after admission"
        );
    }
}
