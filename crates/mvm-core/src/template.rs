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
pub fn template_dir(template_id: &str) -> String {
    format!("/var/lib/mvm/templates/{}", template_id)
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
