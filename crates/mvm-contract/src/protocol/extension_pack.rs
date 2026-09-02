//! Generic optional extension-pack contract.
//!
//! An extension is an independently built executable admitted beside a
//! workload. The contract describes its placement, entrypoint, maximum typed
//! broker authority, and resource ceiling. It contains no product-specific
//! rule or binary identity.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::agent_capability::{
    AGENT_CAPABILITY_PROTOCOL_VERSION, CapabilityBinding, CapabilityDescriptor, CapabilityId,
};

/// Current serialized extension descriptor schema.
pub const EXTENSION_PACK_SCHEMA: &str = "mvm.extension-pack/v1";
/// Largest extension identifier or version.
pub const MAX_EXTENSION_TOKEN_BYTES: usize = 128;
/// Largest human-readable permission summary.
pub const MAX_PERMISSION_DELTA_BYTES: usize = 4096;
/// Most typed capabilities one extension may expose.
pub const MAX_EXTENSION_CAPABILITIES: usize = 64;
/// Absolute resource ceilings accepted by the wire contract.
pub const MAX_EXTENSION_MEMORY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_EXTENSION_CPU_MILLIS: u32 = 60 * 60 * 1000;
pub const MAX_EXTENSION_DURATION_MS: u64 = 60 * 60 * 1000;
pub const MAX_EXTENSION_STEPS: u32 = 1024;
pub const MAX_EXTENSION_CONCURRENCY: u16 = 64;
pub const MAX_EXTENSION_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_EXTENSION_OUTPUT_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_EXTENSION_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

/// Stable publisher-selected extension identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionId(String);

impl ExtensionId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionContractError> {
        let value = value.into();
        validate_token(&value, true)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ExtensionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for ExtensionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Publisher-selected version. Kept opaque but tightly shaped so publishers
/// may use semver or a content-addressed release identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionVersion(String);

impl ExtensionVersion {
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionContractError> {
        let value = value.into();
        validate_token(&value, true)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ExtensionVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Where MVM places and launches the verified executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ExtensionPlacement {
    GuestWorkload,
    IsolatedController,
}

/// Inclusive MVM and typed-broker protocol compatibility range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionProtocolRange {
    pub min_mvm_version: ExtensionVersion,
    pub max_mvm_version: ExtensionVersion,
    pub min_protocol: u16,
    pub max_protocol: u16,
}

/// Maximum resources the extension publisher permits one admitted instance to
/// receive. Host policy and the short-lived grant may only narrow these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionBudgets {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub duration_ms: u64,
    pub max_steps: u32,
    pub max_concurrency: u16,
    pub max_payload_bytes: u32,
    pub max_output_bytes: u32,
    pub max_artifact_bytes: u64,
}

/// Signed extension-specific content carried inside the generic pack
/// manifest. Artifact identity, publisher identity, SBOM, provenance, expiry,
/// and revocation are supplied by the enclosing signed pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionPackContract {
    pub schema: String,
    pub extension_id: ExtensionId,
    pub version: ExtensionVersion,
    pub protocol: ExtensionProtocolRange,
    pub placement: ExtensionPlacement,
    /// Relative path of the guest-mountable, read-only filesystem artifact
    /// inside the verified pack.
    pub artifact: String,
    /// Relative executable path inside the mounted artifact.
    pub entrypoint: String,
    /// Maximum typed host capabilities this publisher allows the extension to
    /// receive. Admission intersects this set with every local authority.
    pub capabilities: Vec<CapabilityDescriptor>,
    pub budgets: ExtensionBudgets,
    /// Stable publisher revocation identity, distinct from a download URL.
    pub revocation_identity: String,
    /// Bounded operator-facing explanation of the authority added by install.
    pub permission_delta: String,
}

/// Exact extension identity and authority embedded in the signed execution
/// plan after pack verification and policy/grant intersection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExtensionPlanBinding {
    pub extension_id: ExtensionId,
    pub version: ExtensionVersion,
    /// SHA-256 of the enclosing verified pack's canonical manifest.
    pub pack_digest: [u8; 32],
    /// SHA-256 of [`ExtensionPackContract`].
    pub contract_digest: [u8; 32],
    pub placement: ExtensionPlacement,
    pub artifact: String,
    pub entrypoint: String,
    /// Already-intersected exact typed capabilities. The broker receives these
    /// from the host-signed admission; the extension cannot widen them.
    pub capabilities: Vec<CapabilityBinding>,
    pub budgets: ExtensionBudgets,
}

impl ExtensionPlanBinding {
    pub fn validate(&self) -> Result<(), ExtensionContractError> {
        if !safe_relative_path(&self.artifact) || !safe_relative_path(&self.entrypoint) {
            return Err(ExtensionContractError::InvalidEntrypoint);
        }
        validate_budgets(self.budgets)?;
        if self.capabilities.len() > MAX_EXTENSION_CAPABILITIES {
            return Err(ExtensionContractError::TooManyCapabilities);
        }
        let mut ids: Vec<&CapabilityId> = Vec::with_capacity(self.capabilities.len());
        for binding in &self.capabilities {
            if ids.contains(&&binding.capability) {
                return Err(ExtensionContractError::DuplicateCapability);
            }
            ids.push(&binding.capability);
        }
        Ok(())
    }
}

impl ExtensionPackContract {
    pub fn validate(&self) -> Result<(), ExtensionContractError> {
        if self.schema != EXTENSION_PACK_SCHEMA {
            return Err(ExtensionContractError::UnsupportedSchema);
        }
        if self.protocol.min_protocol == 0
            || self.protocol.min_protocol > self.protocol.max_protocol
            || !(self.protocol.min_protocol..=self.protocol.max_protocol)
                .contains(&AGENT_CAPABILITY_PROTOCOL_VERSION)
        {
            return Err(ExtensionContractError::UnsupportedProtocolRange);
        }
        let minimum = parse_semver(&self.protocol.min_mvm_version)?;
        let maximum = parse_semver(&self.protocol.max_mvm_version)?;
        if minimum > maximum {
            return Err(ExtensionContractError::InvalidMvmVersionRange);
        }
        if !safe_relative_path(&self.artifact) || !safe_relative_path(&self.entrypoint) {
            return Err(ExtensionContractError::InvalidEntrypoint);
        }
        validate_token(&self.revocation_identity, true)
            .map_err(|_| ExtensionContractError::InvalidRevocationIdentity)?;
        if self.permission_delta.is_empty()
            || self.permission_delta.len() > MAX_PERMISSION_DELTA_BYTES
            || self.permission_delta.chars().any(char::is_control)
        {
            return Err(ExtensionContractError::InvalidPermissionDelta);
        }
        validate_budgets(self.budgets)?;
        if self.capabilities.len() > MAX_EXTENSION_CAPABILITIES {
            return Err(ExtensionContractError::TooManyCapabilities);
        }
        let mut ids: Vec<&CapabilityId> = Vec::with_capacity(self.capabilities.len());
        for descriptor in &self.capabilities {
            if ids.contains(&&descriptor.id) {
                return Err(ExtensionContractError::DuplicateCapability);
            }
            if descriptor.limits.max_input_bytes > self.budgets.max_payload_bytes
                || descriptor.limits.max_output_bytes > self.budgets.max_output_bytes
                || u64::from(descriptor.limits.timeout_ms) > self.budgets.duration_ms
            {
                return Err(ExtensionContractError::CapabilityExceedsBudget);
            }
            ids.push(&descriptor.id);
        }
        Ok(())
    }
}

fn validate_token(value: &str, dotted: bool) -> Result<(), ExtensionContractError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_EXTENSION_TOKEN_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') || (dotted && byte == b'.')
        });
    if valid {
        Ok(())
    } else {
        Err(ExtensionContractError::InvalidToken)
    }
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn validate_budgets(budgets: ExtensionBudgets) -> Result<(), ExtensionContractError> {
    let valid = budgets.cpu_millis > 0
        && budgets.cpu_millis <= MAX_EXTENSION_CPU_MILLIS
        && budgets.memory_bytes > 0
        && budgets.memory_bytes <= MAX_EXTENSION_MEMORY_BYTES
        && budgets.duration_ms > 0
        && budgets.duration_ms <= MAX_EXTENSION_DURATION_MS
        && budgets.max_steps > 0
        && budgets.max_steps <= MAX_EXTENSION_STEPS
        && budgets.max_concurrency > 0
        && budgets.max_concurrency <= MAX_EXTENSION_CONCURRENCY
        && budgets.max_payload_bytes > 0
        && budgets.max_payload_bytes <= MAX_EXTENSION_PAYLOAD_BYTES
        && budgets.max_output_bytes > 0
        && budgets.max_output_bytes <= MAX_EXTENSION_OUTPUT_BYTES
        && budgets.max_artifact_bytes > 0
        && budgets.max_artifact_bytes <= MAX_EXTENSION_ARTIFACT_BYTES;
    if valid {
        Ok(())
    } else {
        Err(ExtensionContractError::InvalidBudgets)
    }
}

fn parse_semver(version: &ExtensionVersion) -> Result<(u64, u64, u64), ExtensionContractError> {
    let core = version
        .as_str()
        .split_once('-')
        .map_or(version.as_str(), |(core, _)| core);
    let mut parts = core.split('.');
    let major = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or(ExtensionContractError::InvalidMvmVersionRange)?;
    let minor = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or(ExtensionContractError::InvalidMvmVersionRange)?;
    let patch = parts
        .next()
        .and_then(|part| part.parse().ok())
        .ok_or(ExtensionContractError::InvalidMvmVersionRange)?;
    if parts.next().is_some() {
        return Err(ExtensionContractError::InvalidMvmVersionRange);
    }
    Ok((major, minor, patch))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExtensionContractError {
    #[error("invalid extension token")]
    InvalidToken,
    #[error("unsupported extension schema")]
    UnsupportedSchema,
    #[error("unsupported extension protocol range")]
    UnsupportedProtocolRange,
    #[error("invalid MVM version range")]
    InvalidMvmVersionRange,
    #[error("invalid extension entrypoint")]
    InvalidEntrypoint,
    #[error("invalid extension budgets")]
    InvalidBudgets,
    #[error("too many extension capabilities")]
    TooManyCapabilities,
    #[error("duplicate extension capability")]
    DuplicateCapability,
    #[error("capability exceeds extension budget")]
    CapabilityExceedsBudget,
    #[error("invalid revocation identity")]
    InvalidRevocationIdentity,
    #[error("invalid permission delta")]
    InvalidPermissionDelta,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::agent_capability::{CapabilityId, CapabilityLimits, SchemaRef};
    use crate::protocol::broker::ServiceId;

    fn contract() -> ExtensionPackContract {
        let service = ServiceId::parse("host.assurance.v1").expect("service");
        ExtensionPackContract {
            schema: EXTENSION_PACK_SCHEMA.to_string(),
            extension_id: ExtensionId::parse("org.example.assurance").expect("id"),
            version: ExtensionVersion::parse("1.0.0-rc1").expect("version"),
            protocol: ExtensionProtocolRange {
                min_mvm_version: ExtensionVersion::parse("0.18.0").expect("min"),
                max_mvm_version: ExtensionVersion::parse("0.18.9").expect("max"),
                min_protocol: 1,
                max_protocol: 1,
            },
            placement: ExtensionPlacement::GuestWorkload,
            artifact: "extension.ext4".to_string(),
            entrypoint: "bin/assurance-extension".to_string(),
            capabilities: vec![
                CapabilityDescriptor::builder()
                    .id(CapabilityId::new(service, "probe").expect("capability"))
                    .description("perform one declared probe")
                    .input_schema(SchemaRef::new("probe.input.v1", [1; 32]).expect("input"))
                    .output_schema(SchemaRef::new("probe.output.v1", [2; 32]).expect("output"))
                    .limits(CapabilityLimits::new(4096, 4096, 1000).expect("limits"))
                    .build()
                    .expect("descriptor"),
            ],
            budgets: ExtensionBudgets {
                cpu_millis: 500,
                memory_bytes: 128 * 1024 * 1024,
                duration_ms: 60_000,
                max_steps: 12,
                max_concurrency: 1,
                max_payload_bytes: 4096,
                max_output_bytes: 4096,
                max_artifact_bytes: 1024 * 1024,
            },
            revocation_identity: "org.example.assurance.release".to_string(),
            permission_delta: "May invoke one declared assurance probe.".to_string(),
        }
    }

    #[test]
    fn strict_contract_roundtrips() {
        let value = contract();
        value.validate().expect("valid contract");
        let bytes = serde_json::to_vec(&value).expect("encode");
        let decoded: ExtensionPackContract = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn unknown_fields_and_unsafe_entrypoints_fail_closed() {
        let mut value = serde_json::to_value(contract()).expect("value");
        value["host_path"] = serde_json::json!("/tmp/escape");
        assert!(serde_json::from_value::<ExtensionPackContract>(value).is_err());

        let mut value = contract();
        value.entrypoint = "../escape".to_string();
        assert_eq!(
            value.validate(),
            Err(ExtensionContractError::InvalidEntrypoint)
        );
    }

    #[test]
    fn capability_cannot_exceed_pack_budget() {
        let mut value = contract();
        value.budgets.max_payload_bytes = 1;
        assert_eq!(
            value.validate(),
            Err(ExtensionContractError::CapabilityExceedsBudget)
        );
    }

    #[test]
    fn every_resource_budget_has_an_absolute_wire_ceiling() {
        let mut value = contract();
        value.budgets.max_concurrency = MAX_EXTENSION_CONCURRENCY + 1;
        assert_eq!(
            value.validate(),
            Err(ExtensionContractError::InvalidBudgets)
        );

        let mut value = contract();
        value.budgets.cpu_millis = MAX_EXTENSION_CPU_MILLIS + 1;
        assert_eq!(
            value.validate(),
            Err(ExtensionContractError::InvalidBudgets)
        );
    }
}
