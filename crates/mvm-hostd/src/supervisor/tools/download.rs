//! `mvm.download` — host staging-area → agent read.
//!
//! Plan 60 Phase 7. The agent supplies a relative path; the
//! supervisor validates, reads from the configured staging area,
//! and returns the bytes as URL-safe-no-pad base64 (same shape
//! `mvm.web_fetch` uses, so callers parse one envelope for both
//! tools).
//!
//! Security model lives in [`super::staging`]: every read goes
//! through the same path validator + `O_NOFOLLOW` open the upload
//! tool uses, so a tenant can only round-trip data they themselves
//! placed under their staging subdir.
//!
//! ## Wire shape
//!
//! Params:
//! - `path` (required): relative path under the staging root.
//! - `max_bytes` (optional): cap on file size. Defaults to
//!   [`super::staging::DEFAULT_MAX_BYTES`]; clamped to
//!   [`super::staging::MAX_ALLOWED_BYTES`].
//!
//! Result:
//! - `path`: echoes the validated path.
//! - `bytes`: pre-encoding length.
//! - `content_base64`: URL-safe-no-pad base64 of the file bytes.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::staging::{DEFAULT_MAX_BYTES, MAX_ALLOWED_BYTES, StagingArea, StagingError};
use super::{HostMediatedTool, ToolInvokeError};

pub const TOOL_NAME: &str = "mvm.download";

pub struct DownloadTool {
    staging: Arc<dyn StagingArea>,
}

impl DownloadTool {
    /// Build with an explicit staging-area impl.
    pub fn with_staging(staging: Arc<dyn StagingArea>) -> Self {
        Self { staging }
    }

    /// Fail-closed default.
    pub fn fail_closed() -> Self {
        Self {
            staging: Arc::new(super::staging::NoopStagingArea),
        }
    }
}

impl Default for DownloadTool {
    fn default() -> Self {
        Self::fail_closed()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadParams {
    pub path: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DownloadResult {
    pub path: String,
    pub bytes: u64,
    pub content_base64: String,
}

#[async_trait]
impl HostMediatedTool for DownloadTool {
    fn name(&self) -> &'static str {
        TOOL_NAME
    }

    async fn invoke(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ToolInvokeError> {
        let parsed: DownloadParams =
            serde_json::from_value(params).map_err(|e| ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: e.to_string(),
            })?;
        let cap = parsed.max_bytes.min(MAX_ALLOWED_BYTES);
        let bytes = self
            .staging
            .read(&parsed.path, cap)
            .await
            .map_err(|e| map_staging_error(e, &parsed.path))?;
        let content_base64 = URL_SAFE_NO_PAD.encode(&bytes);
        serde_json::to_value(DownloadResult {
            path: parsed.path,
            bytes: bytes.len() as u64,
            content_base64,
        })
        .map_err(|e| ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: format!("serializing result: {e}"),
        })
    }
}

fn map_staging_error(err: StagingError, path: &str) -> ToolInvokeError {
    match err {
        StagingError::InvalidPath { reason, .. } => ToolInvokeError::InvalidParams {
            tool: TOOL_NAME.to_string(),
            message: format!("invalid path {path:?}: {reason}"),
        },
        StagingError::NotFound { .. } => ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: format!("path {path:?} not found in staging area"),
        },
        StagingError::BodyTooLarge { limit } => ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: format!("file exceeds max_bytes {limit}"),
        },
        other => ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::super::staging::FsStagingArea;
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use tempfile::tempdir;

    fn tool_with_tempdir_and_seed(name: &str, content: &[u8]) -> (DownloadTool, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join(name), content).unwrap();
        let staging = Arc::new(FsStagingArea::with_root(dir.path()).unwrap());
        (DownloadTool::with_staging(staging), dir)
    }

    #[tokio::test]
    async fn download_round_trip_returns_base64_payload() {
        let (tool, _dir) = tool_with_tempdir_and_seed("greeting.txt", b"hello there");
        let out = tool
            .invoke(serde_json::json!({ "path": "greeting.txt" }))
            .await
            .unwrap();
        let parsed: DownloadResult = serde_json::from_value(out).unwrap();
        assert_eq!(parsed.path, "greeting.txt");
        assert_eq!(parsed.bytes, 11);
        let decoded = B64.decode(&parsed.content_base64).unwrap();
        assert_eq!(decoded, b"hello there");
    }

    #[tokio::test]
    async fn download_missing_path_returns_clear_error() {
        let (tool, _dir) = tool_with_tempdir_and_seed("placeholder", b"_");
        let err = tool
            .invoke(serde_json::json!({ "path": "nope.txt" }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { message, .. } => {
                assert!(message.contains("not found"), "got: {message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_rejects_absolute_path() {
        let (tool, _dir) = tool_with_tempdir_and_seed("p", b"x");
        let err = tool
            .invoke(serde_json::json!({ "path": "/etc/passwd" }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn download_rejects_parent_ref() {
        let (tool, _dir) = tool_with_tempdir_and_seed("p", b"x");
        let err = tool
            .invoke(serde_json::json!({ "path": "../escape" }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn download_oversize_file_returns_body_too_large() {
        let (tool, _dir) = tool_with_tempdir_and_seed("big.bin", &[0u8; 32]);
        let err = tool
            .invoke(serde_json::json!({
                "path": "big.bin",
                "max_bytes": 16,
            }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { message, .. } => {
                assert!(message.contains("exceeds max_bytes"), "got: {message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_rejects_unknown_field() {
        let (tool, _dir) = tool_with_tempdir_and_seed("p", b"x");
        let err = tool
            .invoke(serde_json::json!({
                "path": "p",
                "extra": 1,
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn download_fails_closed_without_staging() {
        let tool = DownloadTool::default();
        let err = tool
            .invoke(serde_json::json!({ "path": "x" }))
            .await
            .unwrap_err();
        match err {
            ToolInvokeError::Upstream { message, .. } => {
                assert!(message.contains("not wired"), "got: {message}");
            }
            other => panic!("expected Upstream, got {other:?}"),
        }
    }

    #[test]
    fn tool_name_is_canonical_mvm_prefix() {
        assert_eq!(DownloadTool::default().name(), TOOL_NAME);
        assert!(TOOL_NAME.starts_with("mvm."));
    }
}
