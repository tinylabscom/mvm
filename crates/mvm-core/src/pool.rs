use std::fmt;

use serde::{Deserialize, Serialize};

use crate::tenant::tenant_pools_dir;

// ============================================================================
// Role-based VM type
// ============================================================================

/// Role for a pool's instances. Determines services, ports, drive
/// expectations, reconcile ordering, and sleep policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Gateway,
    #[default]
    Worker,
    Builder,
    CapabilityImessage,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gateway => write!(f, "gateway"),
            Self::Worker => write!(f, "worker"),
            Self::Builder => write!(f, "builder"),
            Self::CapabilityImessage => write!(f, "capability-imessage"),
        }
    }
}

// ============================================================================
// Minimum runtime policy
// ============================================================================

// ============================================================================
// Pool metadata
// ============================================================================

/// Optional metadata for categorizing and tagging pools.
/// Enables capability-based queries and policies without hardcoding types in Role enum.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolMetadata {
    /// Capability identifier (e.g., "openclaw", "mcp-server", "database").
    /// Used for grouping pools by functional capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,

    /// Integration types supported by this pool (e.g., ["telegram", "discord"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub integration_types: Vec<String>,

    /// Arbitrary key-value tags for custom categorization.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tags: std::collections::BTreeMap<String, String>,
}

/// Per-pool runtime policy for minimum runtime enforcement and graceful lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePolicy {
    /// Minimum seconds an instance must stay Running before eligible for Warm.
    #[serde(default = "default_min_running")]
    pub min_running_seconds: u64,
    /// Minimum seconds an instance must stay Warm before eligible for Sleep.
    #[serde(default = "default_min_warm")]
    pub min_warm_seconds: u64,
    /// Maximum seconds to wait for guest drain ACK before forcing sleep.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_seconds: u64,
    /// Maximum seconds for graceful shutdown before SIGKILL.
    #[serde(default = "default_graceful_shutdown")]
    pub graceful_shutdown_seconds: u64,
}

fn default_min_running() -> u64 {
    60
}
fn default_min_warm() -> u64 {
    30
}
fn default_drain_timeout() -> u64 {
    30
}
fn default_graceful_shutdown() -> u64 {
    15
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            min_running_seconds: default_min_running(),
            min_warm_seconds: default_min_warm(),
            drain_timeout_seconds: default_drain_timeout(),
            graceful_shutdown_seconds: default_graceful_shutdown(),
        }
    }
}

// ============================================================================
// Pool spec
// ============================================================================

/// A WorkerPool defines a homogeneous group of instances within a tenant.
/// Has desired counts but NO runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSpec {
    pub pool_id: String,
    pub tenant_id: String,
    pub flake_ref: String,
    /// Guest profile name. Built-in: "minimal", "python".
    /// Users can define custom profiles in their own flake.
    pub profile: String,
    /// Role for all instances in this pool.
    #[serde(default)]
    pub role: Role,
    pub instance_resources: InstanceResources,
    pub desired_counts: DesiredCounts,
    /// Minimum runtime policy for this pool's instances.
    #[serde(default)]
    pub runtime_policy: RuntimePolicy,
    /// Optional metadata for capability tagging and categorization.
    #[serde(default)]
    pub metadata: PoolMetadata,
    /// "baseline" | "strict"
    #[serde(default = "default_seccomp")]
    pub seccomp_policy: String,
    /// "none" | "lz4" | "zstd"
    #[serde(default = "default_compression")]
    pub snapshot_compression: String,
    #[serde(default)]
    pub metadata_enabled: bool,
    /// If true, reconcile won't auto-sleep this pool's instances.
    #[serde(default)]
    pub pinned: bool,
    /// If true, reconcile won't touch this pool at all.
    #[serde(default)]
    pub critical: bool,
    /// Per-integration secret scoping. When non-empty, secrets are split
    /// into per-integration directories on the secrets drive.
    #[serde(default)]
    pub secret_scopes: Vec<SecretScope>,
    /// Optional template reference for shared base image.
    #[serde(default)]
    pub template_id: String,
}

/// Scoped secret delivery: only give an integration the secrets it needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScope {
    /// Integration name (e.g. "whatsapp", "telegram").
    pub integration: String,
    /// Secret key names to include for this integration.
    /// Empty means include all keys (no filtering).
    pub keys: Vec<String>,
}

fn default_seccomp() -> String {
    "baseline".to_string()
}

fn default_compression() -> String {
    "none".to_string()
}

/// Resource allocation for each instance in the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceResources {
    pub vcpus: u8,
    pub mem_mib: u32,
    #[serde(default)]
    pub data_disk_mib: u32,
}

/// Desired instance counts by status, evaluated by the reconcile loop.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesiredCounts {
    pub running: u32,
    pub warm: u32,
    pub sleeping: u32,
}

/// A completed build revision with artifact locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRevision {
    pub revision_hash: String,
    pub flake_ref: String,
    pub flake_lock_hash: String,
    pub artifact_paths: ArtifactPaths,
    pub built_at: String,
}

/// Paths to build artifacts within the pool's artifact directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPaths {
    pub vmlinux: String,
    pub rootfs: String,
    pub fc_base_config: String,
}

// --- Filesystem paths ---

pub fn pool_dir(tenant_id: &str, pool_id: &str) -> String {
    format!("{}/{}", tenant_pools_dir(tenant_id), pool_id)
}

pub fn pool_config_path(tenant_id: &str, pool_id: &str) -> String {
    format!("{}/pool.json", pool_dir(tenant_id, pool_id))
}

pub fn pool_artifacts_dir(tenant_id: &str, pool_id: &str) -> String {
    format!("{}/artifacts", pool_dir(tenant_id, pool_id))
}

pub fn pool_instances_dir(tenant_id: &str, pool_id: &str) -> String {
    format!("{}/instances", pool_dir(tenant_id, pool_id))
}

pub fn pool_snapshots_dir(tenant_id: &str, pool_id: &str) -> String {
    format!("{}/snapshots", pool_dir(tenant_id, pool_id))
}

/// Directory for pool-level configuration data (mounted as config drive).
pub fn pool_config_data_dir(tenant_id: &str, pool_id: &str) -> String {
    format!("{}/config", pool_dir(tenant_id, pool_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_dir_path() {
        assert_eq!(
            pool_dir("acme", "workers"),
            "/var/lib/mvm/tenants/acme/pools/workers"
        );
    }

    #[test]
    fn test_pool_config_roundtrip() {
        let spec = PoolSpec {
            pool_id: "workers".to_string(),
            tenant_id: "acme".to_string(),
            flake_ref: "github:org/repo".to_string(),
            profile: "minimal".to_string(),
            role: Role::Worker,
            instance_resources: InstanceResources {
                vcpus: 2,
                mem_mib: 1024,
                data_disk_mib: 2048,
            },
            desired_counts: DesiredCounts {
                running: 3,
                warm: 1,
                sleeping: 2,
            },
            runtime_policy: RuntimePolicy::default(),
            metadata: PoolMetadata::default(),
            seccomp_policy: "baseline".to_string(),
            snapshot_compression: "zstd".to_string(),
            metadata_enabled: false,
            pinned: false,
            critical: false,
            secret_scopes: vec![],
            template_id: String::new(),
        };

        let json = serde_json::to_string(&spec).unwrap();
        let parsed: PoolSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pool_id, "workers");
        assert_eq!(parsed.instance_resources.vcpus, 2);
        assert_eq!(parsed.desired_counts.running, 3);
        assert_eq!(parsed.role, Role::Worker);
    }

    #[test]
    fn test_role_serde_roundtrip() {
        for (role, expected) in [
            (Role::Gateway, "\"gateway\""),
            (Role::Worker, "\"worker\""),
            (Role::Builder, "\"builder\""),
            (Role::CapabilityImessage, "\"capability-imessage\""),
        ] {
            let json = serde_json::to_string(&role).unwrap();
            assert_eq!(json, expected);
            let parsed: Role = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, role);
        }
    }

    #[test]
    fn test_role_display() {
        assert_eq!(Role::Gateway.to_string(), "gateway");
        assert_eq!(Role::Worker.to_string(), "worker");
        assert_eq!(Role::Builder.to_string(), "builder");
        assert_eq!(Role::CapabilityImessage.to_string(), "capability-imessage");
    }

    #[test]
    fn test_role_default_is_worker() {
        assert_eq!(Role::default(), Role::Worker);
    }

    #[test]
    fn test_runtime_policy_defaults() {
        let p = RuntimePolicy::default();
        assert_eq!(p.min_running_seconds, 60);
        assert_eq!(p.min_warm_seconds, 30);
        assert_eq!(p.drain_timeout_seconds, 30);
        assert_eq!(p.graceful_shutdown_seconds, 15);
    }

    #[test]
    fn test_pool_spec_backward_compat() {
        // JSON without role/runtime_policy should deserialize with defaults
        let json = r#"{
            "pool_id": "workers",
            "tenant_id": "acme",
            "flake_ref": ".",
            "profile": "minimal",
            "instance_resources": {"vcpus": 1, "mem_mib": 512},
            "desired_counts": {"running": 1, "warm": 0, "sleeping": 0}
        }"#;
        let parsed: PoolSpec = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.role, Role::Worker);
        assert_eq!(parsed.runtime_policy.min_running_seconds, 60);
    }

    #[test]
    fn test_pool_config_data_dir() {
        assert_eq!(
            pool_config_data_dir("acme", "gateways"),
            "/var/lib/mvm/tenants/acme/pools/gateways/config"
        );
    }

    #[test]
    fn test_secret_scope_serde_roundtrip() {
        let scopes = vec![
            SecretScope {
                integration: "whatsapp".to_string(),
                keys: vec![
                    "WHATSAPP_API_KEY".to_string(),
                    "WHATSAPP_SECRET".to_string(),
                ],
            },
            SecretScope {
                integration: "telegram".to_string(),
                keys: vec!["TELEGRAM_BOT_TOKEN".to_string()],
            },
        ];

        let json = serde_json::to_string(&scopes).unwrap();
        let parsed: Vec<SecretScope> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].integration, "whatsapp");
        assert_eq!(parsed[0].keys.len(), 2);
        assert_eq!(parsed[1].integration, "telegram");
    }

    #[test]
    fn test_pool_spec_backward_compat_secret_scopes() {
        // JSON without secret_scopes should parse fine (defaults to empty vec)
        let json = r#"{
            "pool_id": "workers",
            "tenant_id": "acme",
            "flake_ref": ".",
            "profile": "minimal",
            "instance_resources": {"vcpus": 1, "mem_mib": 512},
            "desired_counts": {"running": 1, "warm": 0, "sleeping": 0}
        }"#;
        let parsed: PoolSpec = serde_json::from_str(json).unwrap();
        assert!(parsed.secret_scopes.is_empty());
    }
}
