//! Frozen ordinary machine-spec reader used to test old-reader refusal.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineSpec {
    pub schema_version: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_digest: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub runtime_pack: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_pack_image: Option<mvm_core::registry_pack::PackPin>,
    pub net: bool,
    pub allow_host: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<mvm_contract::policy::routes::EgressRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai: Option<mvm_core::network_policy::AiPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    pub cpus: u32,
    pub memory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_initial: Option<String>,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub init: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_verb: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_commitment: Option<mvm_contract::plan::CallerCommitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<mvm_contract::ir::HealthCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<mvm_contract::grants::Grants>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub gpu: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_device: Option<u32>,
}

fn is_false(value: &bool) -> bool {
    !*value
}
