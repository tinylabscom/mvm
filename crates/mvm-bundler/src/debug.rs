//! The optional summary written beside an exported bundle.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::plan::bundle::BundleManifest;
use serde::Serialize;

/// The encoding of a debug summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DebugFormat {
    Json,
}

/// Where to write a debug summary, and in which encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugOutput {
    pub path: PathBuf,
    pub format: DebugFormat,
}

impl DebugOutput {
    /// A JSON summary at `path`.
    pub fn json(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            format: DebugFormat::Json,
        }
    }
}

/// What an export produced, for a person to read. Nothing reads it back.
#[derive(Debug, Serialize)]
struct DebugSummary<'a> {
    bundle_path: String,
    bundle_sha256: String,
    size_bytes: u64,
    manifest: &'a BundleManifest,
}

/// The written archive's digest and size.
pub(crate) struct ArchiveIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

/// Render the summary of the archive written to `bundle_path`.
pub(crate) fn render(
    format: DebugFormat,
    bundle_path: &Path,
    archive: ArchiveIdentity,
    manifest: &BundleManifest,
) -> Result<Vec<u8>> {
    let summary = DebugSummary {
        bundle_path: bundle_path.display().to_string(),
        bundle_sha256: archive.sha256,
        size_bytes: archive.size_bytes,
        manifest,
    };
    match format {
        DebugFormat::Json => {
            serde_json::to_vec_pretty(&summary).context("encoding the bundle debug summary as JSON")
        }
    }
}
