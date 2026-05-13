//! SPDX SBOM emission for `mvm addon publish`.
//!
//! v1 scope: minimal SPDX 2.3 Document covering the addon's manifest +
//! workload tree. Real SBOM wiring (extracting third-party dependency
//! licenses from the inner workload's lockfile, resolving Nix-package
//! licenses from `meta.license`) lands in a follow-up.

use crate::addon::manifest::AddonManifest;
use serde::{Deserialize, Serialize};

/// Emit a minimal SPDX 2.3 JSON document for an addon. Returns the
/// canonical bytes the signature payload covers.
///
/// v1 returns an SBOM that names the addon itself (single `Package`
/// with the manifest's name + version + license — once `[addon].license`
/// is added, currently inferred from the workspace `Cargo.toml`'s
/// `license` field). Subsequent versions populate the document's
/// `relationships` and `packages[]` arrays from the inner workload's
/// actual dependency tree.
pub fn emit(manifest: &AddonManifest) -> Result<Vec<u8>, SbomError> {
    let doc = SpdxDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdx_id: "SPDXRef-DOCUMENT".to_string(),
        name: format!("addon-{}-{}", manifest.addon.name, manifest.addon.version),
        document_namespace: format!(
            "https://addons.mvm.io/sbom/{}/{}",
            manifest.addon.name, manifest.addon.version
        ),
        creation_info: CreationInfo {
            creators: vec!["Tool: mvm-sdk-addon".to_string()],
            // Deterministic timestamp — the signature covers exact bytes.
            created: "1970-01-01T00:00:00Z".to_string(),
        },
        packages: vec![SpdxPackage {
            spdx_id: format!("SPDXRef-Package-{}", manifest.addon.name),
            name: manifest.addon.name.clone(),
            version_info: manifest.addon.version.clone(),
            download_location: "NOASSERTION".to_string(),
            license_concluded: "NOASSERTION".to_string(),
            license_declared: "NOASSERTION".to_string(),
            copyright_text: "NOASSERTION".to_string(),
        }],
    };
    serde_json::to_vec(&doc).map_err(SbomError::Serialize)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxDocument {
    spdx_version: String,
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    document_namespace: String,
    creation_info: CreationInfo,
    packages: Vec<SpdxPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreationInfo {
    creators: Vec<String>,
    created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: String,
    download_location: String,
    license_concluded: String,
    license_declared: String,
    copyright_text: String,
}

#[derive(Debug)]
pub enum SbomError {
    Serialize(serde_json::Error),
}

impl std::fmt::Display for SbomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(e) => write!(f, "SPDX serialize error: {e}"),
        }
    }
}

impl std::error::Error for SbomError {}
