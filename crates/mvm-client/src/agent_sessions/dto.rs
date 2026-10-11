//! DTOs for the durable agent-session service, separate from protocol types.

use serde::{Deserialize, Serialize};

/// Creation inputs contain references and identities, never secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct OpenRequest {
    pub session_id: String,
    pub resume_point: Option<String>,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ParkRequest {
    pub session_id: String,
    pub reason: String,
    pub journal_cursor: u64,
    pub approval_head: Option<String>,
    pub retain_for: Option<String>,
    pub expected_generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    pub session_id: String,
    pub extend_for: String,
    pub expected_deadline: Option<u64>,
    pub expected_generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ResumeRequest {
    pub session_id: String,
    pub backend: String,
    pub image: String,
    pub image_sha256: String,
    pub kernel_sha256: Option<String>,
    pub cpus: u32,
    pub mem_mib: u64,
    pub approval_head: Option<String>,
    pub boot: bool,
    pub kernel: Option<std::path::PathBuf>,
    pub expected_generation: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Residency {
    Active,
    Hibernated,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ParkReason {
    ApprovalWait,
    Idle,
    HostShutdown,
    Operator,
    RetentionDemotion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    Resident,
    Parked,
    Cold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RetentionStatus {
    Alive {
        until_unix: u64,
        remaining_secs: u64,
    },
    Expired {
        until_unix: u64,
        expired_for_secs: u64,
    },
}

/// The durable transition identity as published by the session contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RecordedTransition {
    pub identity: TransitionIdentity,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_plan_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TransitionIdentity {
    pub kind: Transition,
    pub session_id: String,
    pub observed_generation: u64,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub observed: std::collections::BTreeMap<String, Option<String>>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub inputs: std::collections::BTreeMap<String, Option<String>>,
}

/// Stable, owned view of a stored session, including retention at observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SessionReport {
    pub session_id: String,
    pub generation: u64,
    pub state: Residency,
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_checkpoint: Option<String>,
    pub created_unix: u64,
    pub updated_unix: u64,
    pub journal_cursor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_head: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_tier: Option<StorageTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub park_reason: Option<ParkReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_until_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition: Option<RecordedTransition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<RetentionStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Transition {
    Park,
    Resume,
    Renew,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TransitionReport {
    pub transition: Transition,
    pub replayed: bool,
    pub session: SessionReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admitted_plan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub booted_sandbox: Option<String>,
    /// Audit failures after a durable mutation do not imply the mutation failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}
