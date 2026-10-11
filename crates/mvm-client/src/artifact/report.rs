//! Owned wire reports for artifact inspection; no runtime handles cross the ABI.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ArtifactReport {
    pub artifact_id: String,
    pub build_id: String,
    pub tenant_id: Option<String>,
    pub arch: String,
    pub backend: String,
    pub kernel: KernelReport,
    pub rootfs: RootfsReport,
    pub config_path: Option<PathBuf>,
    pub provenance: Option<ProvenanceReport>,
    pub builder_version: String,
    pub timestamp_unix: u64,
    pub validation: Option<ValidationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct KernelReport {
    pub path: PathBuf,
    pub format: String,
    pub hash: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RootfsReport {
    pub path: PathBuf,
    pub format: String,
    pub hash: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProvenanceReport {
    pub flake_ref: Option<String>,
    pub lock_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ValidationReport {
    pub ok: bool,
    pub checks: Vec<ValidationCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ValidationCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct BackendConfigReport {
    pub backend: String,
    pub path: PathBuf,
}

// The runtime's serialized public report is the compatibility boundary.
pub fn inspect(request: &super::ArtifactRequest) -> anyhow::Result<ArtifactReport> {
    convert(super::ArtifactService.inspect(request)?)
}

pub fn validate(request: &super::ArtifactRequest) -> anyhow::Result<ValidationReport> {
    convert(super::ArtifactService.validate(request)?)
}

pub fn configure_firecracker(
    request: &super::ArtifactRequest,
) -> anyhow::Result<BackendConfigReport> {
    convert(super::ArtifactService.configure_firecracker(request)?)
}

fn convert<T: serde::de::DeserializeOwned>(report: impl Serialize) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&serde_json::to_vec(&report)?)?)
}
