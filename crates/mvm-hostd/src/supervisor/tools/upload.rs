//! `mvm.upload` — agent → host staging-area write.
//!
//! Plan 60 Phase 7. The agent posts a base64-encoded payload + a
//! relative path; the supervisor decodes, validates the path, and
//! writes to the configured staging area (see [`super::staging`]
//! for the security model + path validator).
//!
//! ## Wire shape
//!
//! Params:
//! - `path` (required): relative path under the staging root.
//! - `content_base64` (required): URL-safe-no-pad base64 of the
//!   payload bytes. Base64 keeps binary content round-trippable
//!   across the JSON wire.
//! - `max_bytes` (optional): post-decode size cap. Defaults to
//!   [`super::staging::DEFAULT_MAX_BYTES`]; clamped to
//!   [`super::staging::MAX_ALLOWED_BYTES`].
//!
//! Result:
//! - `path`: echoes the validated path.
//! - `bytes`: decoded payload length.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::staging::{DEFAULT_MAX_BYTES, MAX_ALLOWED_BYTES, StagingArea, StagingError};
use super::{HostMediatedTool, ToolInvokeError};

pub const TOOL_NAME: &str = "mvm.upload";

pub struct UploadTool {
    staging: Arc<dyn StagingArea>,
}

impl UploadTool {
    /// Build with an explicit staging-area impl. Production
    /// callers use [`super::staging::default_for_tenant`]; tests
    /// inject a tempdir-backed
    /// [`super::staging::FsStagingArea`].
    pub fn with_staging(staging: Arc<dyn StagingArea>) -> Self {
        Self { staging }
    }

    /// Fail-closed default — uses [`super::staging::NoopStagingArea`]
    /// so every upload returns `Unwired` until the dispatcher
    /// wires a real backend.
    pub fn fail_closed() -> Self {
        Self {
            staging: Arc::new(super::staging::NoopStagingArea),
        }
    }
}

impl Default for UploadTool {
    fn default() -> Self {
        Self::fail_closed()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadParams {
    pub path: String,
    pub content_base64: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadResult {
    pub path: String,
    pub bytes: u64,
}

#[async_trait]
impl HostMediatedTool for UploadTool {
    fn name(&self) -> &'static str {
        TOOL_NAME
    }

    async fn invoke(
        &self,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ToolInvokeError> {
        let parsed: UploadParams =
            serde_json::from_value(params).map_err(|e| ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: e.to_string(),
            })?;
        let cap = parsed.max_bytes.min(MAX_ALLOWED_BYTES);
        let bytes = URL_SAFE_NO_PAD
            .decode(parsed.content_base64.as_bytes())
            .map_err(|e| ToolInvokeError::InvalidParams {
                tool: TOOL_NAME.to_string(),
                message: format!("content_base64 decode: {e}"),
            })?;
        if (bytes.len() as u64) > cap {
            return Err(ToolInvokeError::Upstream {
                tool: TOOL_NAME.to_string(),
                message: format!("payload size {} exceeds max_bytes {}", bytes.len(), cap),
            });
        }
        self.staging
            .write(&parsed.path, &bytes)
            .await
            .map_err(|e| map_staging_error(e, &parsed.path))?;
        serde_json::to_value(UploadResult {
            path: parsed.path,
            bytes: bytes.len() as u64,
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
        StagingError::BodyTooLarge { limit } => ToolInvokeError::Upstream {
            tool: TOOL_NAME.to_string(),
            message: format!("payload exceeded max_bytes {limit}"),
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

    fn tool_with_tempdir() -> (UploadTool, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let staging = Arc::new(FsStagingArea::with_root(dir.path()).unwrap());
        (UploadTool::with_staging(staging), dir)
    }

    #[tokio::test]
    async fn upload_round_trip_writes_decoded_bytes() {
        let (tool, dir) = tool_with_tempdir();
        let payload = b"hello there";
        let b64 = B64.encode(payload);
        let out = tool
            .invoke(serde_json::json!({
                "path": "greeting.txt",
                "content_base64": b64,
            }))
            .await
            .unwrap();
        let parsed: UploadResult = serde_json::from_value(out).unwrap();
        assert_eq!(parsed.path, "greeting.txt");
        assert_eq!(parsed.bytes, payload.len() as u64);
        // Confirm the file actually landed on disk.
        let read = std::fs::read(dir.path().join("greeting.txt")).unwrap();
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn upload_rejects_absolute_path() {
        let (tool, _dir) = tool_with_tempdir();
        let b64 = B64.encode(b"x");
        let err = tool
            .invoke(serde_json::json!({
                "path": "/etc/passwd",
                "content_base64": b64,
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn upload_rejects_parent_ref() {
        let (tool, _dir) = tool_with_tempdir();
        let b64 = B64.encode(b"x");
        let err = tool
            .invoke(serde_json::json!({
                "path": "../escape",
                "content_base64": b64,
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn upload_rejects_invalid_base64() {
        let (tool, _dir) = tool_with_tempdir();
        let err = tool
            .invoke(serde_json::json!({
                "path": "x",
                "content_base64": "this is not base64 !!!",
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn upload_rejects_oversize_payload() {
        let (tool, _dir) = tool_with_tempdir();
        let payload = vec![0u8; 32];
        let b64 = B64.encode(&payload);
        let err = tool
            .invoke(serde_json::json!({
                "path": "x",
                "content_base64": b64,
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
    async fn upload_rejects_unknown_field() {
        let (tool, _dir) = tool_with_tempdir();
        let err = tool
            .invoke(serde_json::json!({
                "path": "x",
                "content_base64": "",
                "extra": 1,
            }))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolInvokeError::InvalidParams { .. }));
    }

    #[tokio::test]
    async fn upload_fails_closed_without_staging() {
        let tool = UploadTool::default();
        let b64 = B64.encode(b"x");
        let err = tool
            .invoke(serde_json::json!({
                "path": "y",
                "content_base64": b64,
            }))
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
        assert_eq!(UploadTool::default().name(), TOOL_NAME);
        assert!(TOOL_NAME.starts_with("mvm."));
    }
}
