use sha2::Digest;

use serde::{Deserialize, Serialize};

/// Current schema version for persisted state files.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

/// Complete template configuration that can define multiple variants/roles.
/// Typically loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Optional base name used when a variant omits `name`.
    #[serde(default)]
    pub template_id: String,
    pub flake_ref: String,
    /// Default profile if a variant omits it.
    #[serde(default = "default_profile")]
    pub profile: String,
    pub variants: Vec<TemplateVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariant {
    /// Template name for this variant; if empty, falls back to `<template_id>-<role>`.
    #[serde(default)]
    pub name: String,
    pub role: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    #[serde(default)]
    pub data_disk_mib: u32,
}

fn default_profile() -> String {
    "minimal".to_string()
}

/// Global template definition (tenant-agnostic base image).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSpec {
    /// Schema version for forward-compatible migrations. Current: 1.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub template_id: String,
    pub flake_ref: String,
    pub profile: String,
    pub role: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub data_disk_mib: u32,
    pub created_at: String,
    pub updated_at: String,
    /// Default network policy applied when `mvmctl up` / `mvmctl exec`
    /// don't override it on the CLI. ADR-004 §"Decisions" 6 / plan 32.
    /// Lets templates ship with their intended posture baked in
    /// (e.g. `claude-code-vm` defaults to the `agent` preset) so
    /// operators don't have to remember `--network-preset agent` per
    /// invocation. Backward-compat: existing `template.json` files
    /// that predate this field deserialize as `None` (open egress,
    /// matching prior behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_network_policy: Option<crate::policy::network_policy::NetworkPolicy>,
}

/// Path helpers
pub fn templates_base_dir() -> String {
    format!("{}/templates", crate::config::mvm_data_dir())
}

pub fn template_dir(template_id: &str) -> String {
    format!("{}/{}", templates_base_dir(), template_id)
}

pub fn template_spec_path(template_id: &str) -> String {
    format!("{}/template.json", template_dir(template_id))
}

/// Artifacts base dir for a template.
pub fn template_artifacts_dir(template_id: &str) -> String {
    format!("{}/artifacts", template_dir(template_id))
}

/// Specific revision dir for a template.
pub fn template_revision_dir(template_id: &str, revision: &str) -> String {
    format!("{}/{}", template_artifacts_dir(template_id), revision)
}

/// Symlink to current revision.
pub fn template_current_symlink(template_id: &str) -> String {
    format!("{}/current", template_dir(template_id))
}

/// Snapshot directory within a template revision.
pub fn template_snapshot_dir(template_id: &str, revision: &str) -> String {
    format!("{}/snapshot", template_revision_dir(template_id, revision))
}

/// Metadata about a template's pre-built Firecracker snapshot.
///
/// Created by `template build --snapshot` after booting the VM and
/// waiting for the service to become healthy. Used by `run --template`
/// to restore the VM instantly instead of cold-booting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub created_at: String,
    pub vmstate_size_bytes: u64,
    pub mem_size_bytes: u64,
    /// Boot args used when the snapshot was created (must match on restore).
    pub boot_args: String,
    /// vCPU count at snapshot time (must match on restore).
    pub vcpus: u8,
    /// Memory MiB at snapshot time (must match on restore).
    pub mem_mib: u32,
}

/// Describes what kind of pre-built artifact a template provides.
///
/// All backends support `Image` (cold-boot from rootfs). Only backends
/// with `capabilities().snapshots == true` (e.g. Firecracker) support
/// `Snapshot` (warm-start from memory image).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemplateKind {
    /// Pre-built rootfs image only — cold-boot on every start.
    /// Supported by all backends.
    Image,
    /// Pre-built rootfs + Firecracker memory snapshot — warm-start.
    /// Only supported by backends with snapshot capability.
    Snapshot(SnapshotInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRevision {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub revision_hash: String,
    pub flake_ref: String,
    pub flake_lock_hash: String,
    pub artifact_paths: crate::pool::ArtifactPaths,
    pub built_at: String,
    pub profile: String,
    pub role: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub data_disk_mib: u32,
    #[serde(default)]
    pub snapshot: Option<SnapshotInfo>,
}

impl TemplateRevision {
    /// Composite cache key from the three dimensions that define a unique build
    /// output: flake.lock content, Nix profile, and workload role.
    pub fn cache_key(&self) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.flake_lock_hash.as_bytes());
        hasher.update(b":");
        hasher.update(self.profile.as_bytes());
        hasher.update(b":");
        hasher.update(self.role.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::ArtifactPaths;

    fn make_revision(flake_lock_hash: &str, profile: &str, role: &str) -> TemplateRevision {
        TemplateRevision {
            schema_version: CURRENT_SCHEMA_VERSION,
            revision_hash: "abc123".to_string(),
            flake_ref: ".".to_string(),
            flake_lock_hash: flake_lock_hash.to_string(),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".to_string(),
                rootfs: "rootfs.ext4".to_string(),
                fc_base_config: "fc-base.json".to_string(),
                initrd: None,
                sizes: None,
            },
            built_at: "2025-01-01T00:00:00Z".to_string(),
            profile: profile.to_string(),
            role: role.to_string(),
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
            snapshot: None,
        }
    }

    #[test]
    fn same_inputs_same_cache_key() {
        let a = make_revision("lock1", "minimal", "worker");
        let b = make_revision("lock1", "minimal", "worker");
        assert_eq!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn different_profile_different_cache_key() {
        let a = make_revision("lock1", "minimal", "worker");
        let b = make_revision("lock1", "full", "worker");
        assert_ne!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn different_role_different_cache_key() {
        let a = make_revision("lock1", "minimal", "worker");
        let b = make_revision("lock1", "minimal", "gateway");
        assert_ne!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn different_flake_different_cache_key() {
        let a = make_revision("lock1", "minimal", "worker");
        let b = make_revision("lock2", "minimal", "worker");
        assert_ne!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn cache_key_depends_on_flake_lock_not_revision_hash() {
        let mut a = make_revision("same-lock", "minimal", "worker");
        a.revision_hash = "rev-aaa".to_string();
        let mut b = make_revision("same-lock", "minimal", "worker");
        b.revision_hash = "rev-zzz".to_string();
        // Different revision hashes but same flake_lock/profile/role → same cache key
        assert_eq!(a.cache_key(), b.cache_key());
    }

    #[test]
    fn snapshot_info_serde_roundtrip() {
        let info = SnapshotInfo {
            created_at: "2025-03-01T00:00:00Z".to_string(),
            vmstate_size_bytes: 1024,
            mem_size_bytes: 1048576,
            boot_args: "root=/dev/vda rw init=/init console=ttyS0".to_string(),
            vcpus: 2,
            mem_mib: 1024,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: SnapshotInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vcpus, 2);
        assert_eq!(back.mem_mib, 1024);
        assert_eq!(back.vmstate_size_bytes, 1024);
    }

    #[test]
    fn revision_without_snapshot_deserializes() {
        let json = r#"{
            "revision_hash": "abc",
            "flake_ref": ".",
            "flake_lock_hash": "lock1",
            "artifact_paths": {
                "vmlinux": "vmlinux",
                "rootfs": "rootfs.ext4",
                "fc_base_config": "fc-base.json"
            },
            "built_at": "2025-01-01T00:00:00Z",
            "profile": "minimal",
            "role": "worker",
            "vcpus": 2,
            "mem_mib": 1024,
            "data_disk_mib": 0
        }"#;
        let rev: TemplateRevision = serde_json::from_str(json).unwrap();
        assert!(rev.snapshot.is_none());
    }

    #[test]
    fn revision_with_snapshot_deserializes() {
        let rev = make_revision("lock1", "minimal", "worker");
        let mut rev = rev;
        rev.snapshot = Some(SnapshotInfo {
            created_at: "2025-03-01T00:00:00Z".to_string(),
            vmstate_size_bytes: 512,
            mem_size_bytes: 2048,
            boot_args: "console=ttyS0".to_string(),
            vcpus: 2,
            mem_mib: 1024,
        });
        let json = serde_json::to_string(&rev).unwrap();
        let back: TemplateRevision = serde_json::from_str(&json).unwrap();
        assert!(back.snapshot.is_some());
        assert_eq!(back.snapshot.unwrap().mem_size_bytes, 2048);
    }

    #[test]
    fn template_snapshot_dir_format() {
        let dir = template_snapshot_dir("my-tmpl", "abc123");
        assert!(dir.ends_with("/templates/my-tmpl/artifacts/abc123/snapshot"));
    }

    #[test]
    fn template_kind_image_serde_roundtrip() {
        let kind = TemplateKind::Image;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: TemplateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TemplateKind::Image);
    }

    #[test]
    fn template_kind_snapshot_serde_roundtrip() {
        let snap = SnapshotInfo {
            created_at: "2025-03-01T00:00:00Z".to_string(),
            vmstate_size_bytes: 1024,
            mem_size_bytes: 2048,
            boot_args: "console=ttyS0".to_string(),
            vcpus: 2,
            mem_mib: 512,
        };
        let kind = TemplateKind::Snapshot(snap.clone());
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: TemplateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TemplateKind::Snapshot(snap));
    }

    #[test]
    fn template_spec_default_network_policy_omitted_for_back_compat() {
        // Pre-plan-32 template.json files don't have the field; they
        // must still parse (Option<…> defaults to None) and round-trip
        // without spuriously emitting `"default_network_policy":null`.
        let json_pre_plan_32 = r#"{
            "schema_version": 1,
            "template_id": "legacy",
            "flake_ref": ".",
            "profile": "minimal",
            "role": "worker",
            "vcpus": 2,
            "mem_mib": 1024,
            "data_disk_mib": 0,
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z"
        }"#;
        let parsed: TemplateSpec = serde_json::from_str(json_pre_plan_32).unwrap();
        assert!(parsed.default_network_policy.is_none());
        let reserialized = serde_json::to_string(&parsed).unwrap();
        assert!(
            !reserialized.contains("default_network_policy"),
            "field should be skipped when None to keep round-trip stable: {reserialized}"
        );
    }

    #[test]
    fn template_spec_with_network_policy_roundtrips() {
        use crate::policy::network_policy::{NetworkPolicy, NetworkPreset};
        let spec = TemplateSpec {
            schema_version: CURRENT_SCHEMA_VERSION,
            template_id: "claude-code-vm".to_string(),
            flake_ref: ".".to_string(),
            profile: "minimal".to_string(),
            role: "agent".to_string(),
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            default_network_policy: Some(NetworkPolicy::preset(NetworkPreset::Agent)),
        };
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: TemplateSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.default_network_policy,
            Some(NetworkPolicy::preset(NetworkPreset::Agent))
        );
    }
}
