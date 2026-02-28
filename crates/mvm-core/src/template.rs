use sha2::Digest;

use serde::{Deserialize, Serialize};

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
    pub template_id: String,
    pub flake_ref: String,
    pub profile: String,
    pub role: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub data_disk_mib: u32,
    pub created_at: String,
    pub updated_at: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRevision {
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
            revision_hash: "abc123".to_string(),
            flake_ref: ".".to_string(),
            flake_lock_hash: flake_lock_hash.to_string(),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".to_string(),
                rootfs: "rootfs.ext4".to_string(),
                fc_base_config: "fc-base.json".to_string(),
                initrd: None,
            },
            built_at: "2025-01-01T00:00:00Z".to_string(),
            profile: profile.to_string(),
            role: role.to_string(),
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
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
}
