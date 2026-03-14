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
// Sleep policy configuration (optional per-pool override)
// ============================================================================

/// Configurable thresholds for per-pool sleep policy.
///
/// When set on a `DesiredPool`, overrides the system-wide default thresholds
/// for idle detection and sleep transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SleepPolicyConfig {
    /// Idle seconds before Running → Warm transition (default: 300).
    #[serde(default = "default_warm_threshold")]
    pub warm_threshold_secs: u64,
    /// Idle seconds before Warm → Sleeping transition (default: 900).
    #[serde(default = "default_sleep_threshold")]
    pub sleep_threshold_secs: u64,
    /// CPU % below which an instance is considered idle (default: 5.0).
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold: f32,
    /// Net bytes below which an instance is considered idle (default: 1024).
    #[serde(default = "default_net_threshold")]
    pub net_bytes_threshold: u64,
}

fn default_warm_threshold() -> u64 {
    300
}
fn default_sleep_threshold() -> u64 {
    900
}
fn default_cpu_threshold() -> f32 {
    5.0
}
fn default_net_threshold() -> u64 {
    1024
}

impl Default for SleepPolicyConfig {
    fn default() -> Self {
        Self {
            warm_threshold_secs: default_warm_threshold(),
            sleep_threshold_secs: default_sleep_threshold(),
            cpu_threshold: default_cpu_threshold(),
            net_bytes_threshold: default_net_threshold(),
        }
    }
}

// ============================================================================
// Update strategy (shared with mvmd for rollout orchestration)
// ============================================================================

/// Strategy for rolling out artifact updates to a pool's instances.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpdateStrategy {
    /// Replace instances one at a time (or in small batches).
    Rolling(RollingUpdateStrategy),
    /// Deploy a small number of canary instances first, then proceed.
    Canary(CanaryStrategy),
}

impl Default for UpdateStrategy {
    fn default() -> Self {
        Self::Rolling(RollingUpdateStrategy::default())
    }
}

/// Configuration for a rolling update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollingUpdateStrategy {
    /// Max instances being updated simultaneously.
    #[serde(default = "default_max_unavailable")]
    pub max_unavailable: u32,
    /// Max extra instances during rollout (surge capacity).
    #[serde(default = "default_max_surge")]
    pub max_surge: u32,
    /// Seconds to wait for health check after each instance starts.
    #[serde(default = "default_health_check_timeout")]
    pub health_check_timeout_secs: u64,
}

impl Default for RollingUpdateStrategy {
    fn default() -> Self {
        Self {
            max_unavailable: default_max_unavailable(),
            max_surge: default_max_surge(),
            health_check_timeout_secs: default_health_check_timeout(),
        }
    }
}

/// Configuration for a canary deployment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanaryStrategy {
    /// Number of canary instances to deploy.
    #[serde(default = "default_canary_count")]
    pub canary_count: u32,
    /// Observation window in seconds before deciding to proceed.
    #[serde(default = "default_canary_duration")]
    pub canary_duration_secs: u64,
    /// Minimum health success rate to proceed (0.0–1.0).
    #[serde(default = "default_success_threshold")]
    pub success_threshold: f64,
}

impl Default for CanaryStrategy {
    fn default() -> Self {
        Self {
            canary_count: default_canary_count(),
            canary_duration_secs: default_canary_duration(),
            success_threshold: default_success_threshold(),
        }
    }
}

fn default_max_unavailable() -> u32 {
    1
}
fn default_max_surge() -> u32 {
    1
}
fn default_health_check_timeout() -> u64 {
    60
}
fn default_canary_count() -> u32 {
    1
}
fn default_canary_duration() -> u64 {
    300
}
fn default_success_threshold() -> f64 {
    0.95
}

// ============================================================================
// Registry artifact reference
// ============================================================================

/// Reference to pre-built artifacts in an S3-compatible registry.
/// When present on a DesiredPool, the agent pulls artifacts from the registry
/// instead of running a local Nix build.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryArtifact {
    /// Template ID in the registry (matches `mvmctl template` name).
    pub template_id: String,
    /// Specific revision hash to pull. When None, the registry's "current"
    /// pointer is resolved at pull time.
    #[serde(default)]
    pub revision: Option<String>,
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

/// Artifact file sizes in bytes for build reporting and size tracking.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ArtifactSizes {
    #[serde(default)]
    pub vmlinux_bytes: u64,
    #[serde(default)]
    pub rootfs_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd_bytes: Option<u64>,
    /// Nix closure size (all transitive dependencies). Optional — only
    /// populated when `nix path-info -S` succeeds after a build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nix_closure_bytes: Option<u64>,
}

impl ArtifactSizes {
    /// Total size of all artifacts in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.vmlinux_bytes + self.rootfs_bytes + self.initrd_bytes.unwrap_or(0)
    }
}

/// Format a byte count as a human-readable string (e.g. "45.2 MiB").
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Paths to build artifacts within the pool's artifact directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPaths {
    pub vmlinux: String,
    pub rootfs: String,
    pub fc_base_config: String,
    /// NixOS initrd (optional — present when the flake produces one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initrd: Option<String>,
    /// Artifact file sizes (optional — populated by builds after Sprint 37).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sizes: Option<ArtifactSizes>,
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

    #[test]
    fn test_update_strategy_default_is_rolling() {
        let strategy = UpdateStrategy::default();
        assert!(matches!(strategy, UpdateStrategy::Rolling(_)));
        if let UpdateStrategy::Rolling(r) = strategy {
            assert_eq!(r.max_unavailable, 1);
            assert_eq!(r.max_surge, 1);
            assert_eq!(r.health_check_timeout_secs, 60);
        }
    }

    #[test]
    fn test_update_strategy_rolling_serde_roundtrip() {
        let strategy = UpdateStrategy::Rolling(RollingUpdateStrategy {
            max_unavailable: 2,
            max_surge: 3,
            health_check_timeout_secs: 120,
        });
        let json = serde_json::to_string(&strategy).unwrap();
        let parsed: UpdateStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(strategy, parsed);
    }

    #[test]
    fn test_update_strategy_canary_serde_roundtrip() {
        let strategy = UpdateStrategy::Canary(CanaryStrategy {
            canary_count: 3,
            canary_duration_secs: 600,
            success_threshold: 0.99,
        });
        let json = serde_json::to_string(&strategy).unwrap();
        let parsed: UpdateStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(strategy, parsed);
    }

    #[test]
    fn test_canary_strategy_defaults() {
        let c = CanaryStrategy::default();
        assert_eq!(c.canary_count, 1);
        assert_eq!(c.canary_duration_secs, 300);
        assert!((c.success_threshold - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_rolling_strategy_defaults() {
        let r = RollingUpdateStrategy::default();
        assert_eq!(r.max_unavailable, 1);
        assert_eq!(r.max_surge, 1);
        assert_eq!(r.health_check_timeout_secs, 60);
    }

    #[test]
    fn test_update_strategy_tagged_json_format() {
        // Verify the tagged enum uses "type" field
        let rolling = UpdateStrategy::Rolling(RollingUpdateStrategy::default());
        let json = serde_json::to_string(&rolling).unwrap();
        assert!(json.contains(r#""type":"rolling""#));

        let canary = UpdateStrategy::Canary(CanaryStrategy::default());
        let json = serde_json::to_string(&canary).unwrap();
        assert!(json.contains(r#""type":"canary""#));
    }

    #[test]
    fn test_registry_artifact_serde_roundtrip() {
        let ra = RegistryArtifact {
            template_id: "hello".to_string(),
            revision: Some("abc123def".to_string()),
        };
        let json = serde_json::to_string(&ra).unwrap();
        let parsed: RegistryArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.template_id, "hello");
        assert_eq!(parsed.revision.as_deref(), Some("abc123def"));
    }

    #[test]
    fn test_registry_artifact_no_revision() {
        let json = r#"{"template_id": "openclaw"}"#;
        let parsed: RegistryArtifact = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.template_id, "openclaw");
        assert!(parsed.revision.is_none());
    }

    #[test]
    fn test_registry_artifact_default_revision() {
        let ra = RegistryArtifact {
            template_id: "hello".to_string(),
            revision: None,
        };
        let json = serde_json::to_string(&ra).unwrap();
        // revision: None should be omitted or null
        let parsed: RegistryArtifact = serde_json::from_str(&json).unwrap();
        assert!(parsed.revision.is_none());
    }

    #[test]
    fn test_artifact_sizes_serde_roundtrip() {
        let sizes = ArtifactSizes {
            vmlinux_bytes: 12_345_678,
            rootfs_bytes: 45_678_901,
            initrd_bytes: Some(2_345_678),
            nix_closure_bytes: Some(100_000_000),
        };
        let json = serde_json::to_string(&sizes).unwrap();
        let parsed: ArtifactSizes = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sizes);
    }

    #[test]
    fn test_artifact_sizes_default() {
        let sizes = ArtifactSizes::default();
        assert_eq!(sizes.vmlinux_bytes, 0);
        assert_eq!(sizes.rootfs_bytes, 0);
        assert!(sizes.initrd_bytes.is_none());
        assert!(sizes.nix_closure_bytes.is_none());
    }

    #[test]
    fn test_artifact_sizes_total_bytes() {
        let sizes = ArtifactSizes {
            vmlinux_bytes: 100,
            rootfs_bytes: 200,
            initrd_bytes: Some(50),
            nix_closure_bytes: None,
        };
        assert_eq!(sizes.total_bytes(), 350);

        let no_initrd = ArtifactSizes {
            vmlinux_bytes: 100,
            rootfs_bytes: 200,
            initrd_bytes: None,
            nix_closure_bytes: None,
        };
        assert_eq!(no_initrd.total_bytes(), 300);
    }

    #[test]
    fn test_artifact_sizes_backward_compat() {
        // JSON without sizes field should deserialize ArtifactPaths fine
        let json = r#"{
            "vmlinux": "vmlinux",
            "rootfs": "rootfs.ext4",
            "fc_base_config": "fc-base.json"
        }"#;
        let parsed: ArtifactPaths = serde_json::from_str(json).unwrap();
        assert!(parsed.sizes.is_none());
    }

    #[test]
    fn test_artifact_paths_with_sizes() {
        let paths = ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
            initrd: None,
            sizes: Some(ArtifactSizes {
                vmlinux_bytes: 10_000_000,
                rootfs_bytes: 50_000_000,
                initrd_bytes: None,
                nix_closure_bytes: None,
            }),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let parsed: ArtifactPaths = serde_json::from_str(&json).unwrap();
        assert!(parsed.sizes.is_some());
        assert_eq!(parsed.sizes.unwrap().rootfs_bytes, 50_000_000);
    }

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn test_format_bytes_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(47_400_000), "45.2 MiB");
    }

    #[test]
    fn test_format_bytes_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes(2_684_354_560), "2.5 GiB");
    }
}
