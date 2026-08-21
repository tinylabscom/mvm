//! Host-local client for the per-VM network endpoint's typed connector.
//!
//! This type deliberately knows only a Unix-socket path and the bounded typed
//! request contract. It cannot resolve DNS or open an Internet socket; the
//! endpoint process remains the sole owner of workload network execution.

use std::path::{Path, PathBuf};
use std::time::Duration;

use mvm_core::substitution_wire::{WireRequest, WireResponse};

use crate::framing::{FrameError, read_json_frame, write_json_frame};

// A 16 MiB endpoint response body expands to roughly 21.4 MiB as base64 plus
// JSON framing. Keep the same bounded compatibility envelope without
// accidentally lowering the endpoint's body ceiling.
const MAX_CONNECTOR_FRAME_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum EndpointConnectorError {
    #[error("network endpoint connector timed out")]
    Timeout,
    #[error("network endpoint connector unavailable")]
    Unavailable(#[source] std::io::Error),
    #[error("network endpoint connector framing failed")]
    Frame(#[from] FrameError),
}

/// A cloneable capability for one per-VM endpoint connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHttpConnector {
    uds_path: PathBuf,
    timeout: Duration,
}

impl EndpointHttpConnector {
    #[must_use]
    pub fn new(uds_path: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            uds_path: uds_path.into(),
            timeout,
        }
    }

    #[must_use]
    pub fn uds_path(&self) -> &Path {
        &self.uds_path
    }

    pub async fn execute(
        &self,
        request: &WireRequest,
    ) -> Result<WireResponse, EndpointConnectorError> {
        tokio::time::timeout(self.timeout, self.execute_inner(request))
            .await
            .map_err(|_| EndpointConnectorError::Timeout)?
    }

    async fn execute_inner(
        &self,
        request: &WireRequest,
    ) -> Result<WireResponse, EndpointConnectorError> {
        let mut stream = tokio::net::UnixStream::connect(&self.uds_path)
            .await
            .map_err(EndpointConnectorError::Unavailable)?;
        write_json_frame(&mut stream, request).await?;
        read_json_frame(&mut stream, MAX_CONNECTOR_FRAME_BYTES)
            .await
            .map_err(EndpointConnectorError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn request() -> WireRequest {
        WireRequest {
            method: "GET".into(),
            url: "https://example.test/data".into(),
            headers: Vec::new(),
            body_b64: String::new(),
        }
    }

    #[tokio::test]
    async fn round_trips_only_through_the_endpoint_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let got: WireRequest = read_json_frame(&mut stream, MAX_CONNECTOR_FRAME_BYTES)
                .await
                .unwrap();
            assert_eq!(got, request());
            write_json_frame(
                &mut stream,
                &WireResponse::Ok {
                    status: 204,
                    headers: Vec::new(),
                    body_b64: String::new(),
                },
            )
            .await
            .unwrap();
        });

        let connector = EndpointHttpConnector::new(&path, Duration::from_secs(1));
        let response = connector.execute(&request()).await.unwrap();
        assert!(matches!(response, WireResponse::Ok { status: 204, .. }));
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_endpoint_is_canceled_by_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).await.unwrap();
            let body_len = u32::from_be_bytes(prefix) as usize;
            let mut body = vec![0_u8; body_len];
            stream.read_exact(&mut body).await.unwrap();
            std::future::pending::<()>().await;
        });

        let connector = EndpointHttpConnector::new(&path, Duration::from_secs(5));
        let error = connector.execute(&request()).await.unwrap_err();
        assert!(matches!(error, EndpointConnectorError::Timeout));
        server.abort();
    }

    #[tokio::test]
    async fn an_oversized_reply_is_refused_before_allocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connector.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _: WireRequest = read_json_frame(&mut stream, MAX_CONNECTOR_FRAME_BYTES)
                .await
                .unwrap();
            stream.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        });

        let connector = EndpointHttpConnector::new(&path, Duration::from_secs(1));
        let error = connector.execute(&request()).await.unwrap_err();
        assert!(matches!(
            error,
            EndpointConnectorError::Frame(FrameError::TooLarge { .. })
        ));
        server.await.unwrap();
    }
}
