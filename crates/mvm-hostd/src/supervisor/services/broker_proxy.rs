//! Client for `mvm-broker` (the general-broker subprocess hosting
//! `host.time.v1` / `host.cost.v1` / `broker.v1`).

use std::path::PathBuf;

use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceId, ServiceResponse};

use super::{
    ProxyError,
    frame::{DEFAULT_MAX_FRAME_BYTES, connect, read_frame, write_frame},
};

/// Stateless client. One UDS connection per `call`. Connection pooling
/// lands in W1b.2b alongside the per-spawn response-signature verify.
#[derive(Debug, Clone)]
pub struct BrokerProxy {
    pub uds_path: PathBuf,
    pub max_frame_bytes: usize,
}

impl BrokerProxy {
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            uds_path: uds_path.into(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    /// Open a connection, send the call, read the response, close.
    /// The returned `ServiceResponse` is the subprocess's typed
    /// reply — callers MUST inspect its `Ok` vs `Err` variant.
    pub async fn call(
        &self,
        service: ServiceId,
        verb: impl Into<String>,
        correlation_id: CorrelationId,
        payload: serde_json::Value,
    ) -> Result<ServiceResponse, ProxyError> {
        let call = ServiceCall {
            service,
            verb: verb.into(),
            correlation_id,
            payload,
        };
        let mut stream = connect(&self.uds_path).await?;
        write_frame(&mut stream, &self.uds_path, &call).await?;
        read_frame::<ServiceResponse>(&mut stream, &self.uds_path, self.max_frame_bytes).await
    }
}

// ============================================================================
// Tests — mock server that emulates mvm-broker's wire protocol
// ============================================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use mvm_core::protocol::broker::ServiceErrorCode;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use super::*;

    /// In-test mock that emulates the mvm-broker subprocess: reads one
    /// `ServiceCall`, returns a configurable `ServiceResponse`, closes.
    async fn spawn_mock(
        path: PathBuf,
        response: ServiceResponse,
        captured: Arc<Mutex<Option<ServiceCall>>>,
    ) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            let call: ServiceCall = serde_json::from_slice(&body).unwrap();
            *captured.lock().await = Some(call);

            let resp_bytes = serde_json::to_vec(&response).unwrap();
            let resp_len: u32 = resp_bytes.len().try_into().unwrap();
            stream.write_all(&resp_len.to_be_bytes()).await.unwrap();
            stream.write_all(&resp_bytes).await.unwrap();
            let _ = stream.shutdown().await;
        })
    }

    #[tokio::test]
    async fn call_round_trips_through_mock_server() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("broker.sock");

        let correlation = CorrelationId::new("01HCORR0000000000000000");
        let expected_response = ServiceResponse::Ok {
            correlation_id: correlation.clone(),
            payload: serde_json::json!({"wall_ms": 1717000000000_u64}),
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), expected_response.clone(), captured.clone()).await;
        tokio::task::yield_now().await;

        let proxy = BrokerProxy::new(&path);
        let actual = proxy
            .call(
                ServiceId::parse("host.time.v1").unwrap(),
                "now",
                correlation.clone(),
                serde_json::json!({}),
            )
            .await
            .expect("call must succeed");

        assert_eq!(actual, expected_response);
        let captured_call = captured.lock().await.clone().expect("mock must capture");
        assert_eq!(captured_call.service.as_str(), "host.time.v1");
        assert_eq!(captured_call.verb, "now");
        assert_eq!(captured_call.correlation_id, correlation);

        mock.abort();
    }

    #[tokio::test]
    async fn call_round_trips_typed_err_responses() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("broker.sock");

        let correlation = CorrelationId::new("01HCORR_ERR");
        let err_response = ServiceResponse::Err {
            correlation_id: correlation.clone(),
            code: ServiceErrorCode::NotBound,
            message: "service host.time.v1 not bound".into(),
        };
        let captured = Arc::new(Mutex::new(None));
        let mock = spawn_mock(path.clone(), err_response.clone(), captured.clone()).await;
        tokio::task::yield_now().await;

        let proxy = BrokerProxy::new(&path);
        let actual = proxy
            .call(
                ServiceId::parse("host.time.v1").unwrap(),
                "now",
                correlation,
                serde_json::json!({}),
            )
            .await
            .expect("transport must succeed even when subprocess returns Err variant");

        match actual {
            ServiceResponse::Err { code, .. } => assert_eq!(code, ServiceErrorCode::NotBound),
            other => panic!("expected Err variant, got {:?}", other),
        }
        mock.abort();
    }

    #[tokio::test]
    async fn connect_failure_surfaces_as_proxy_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("never-bound.sock");
        let proxy = BrokerProxy::new(&path);
        let err = proxy
            .call(
                ServiceId::parse("host.time.v1").unwrap(),
                "now",
                CorrelationId::new("01HCORR"),
                serde_json::json!({}),
            )
            .await
            .expect_err("connect to missing UDS must fail");
        assert!(matches!(err, ProxyError::Connect { .. }), "got {:?}", err);
    }

    #[tokio::test]
    async fn oversized_response_surfaces_as_response_too_large() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("oversized.sock");
        let listener = UnixListener::bind(&path).unwrap();

        // Mock that writes a length prefix bigger than the proxy's cap.
        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Drain the request first so the client write succeeds.
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await.unwrap();
            let req_len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; req_len];
            stream.read_exact(&mut body).await.unwrap();
            // Write a response prefix that claims 1 MB body.
            let huge: u32 = 1_048_576;
            stream.write_all(&huge.to_be_bytes()).await.unwrap();
            // Then dribble out a few bytes and close — the client should
            // never read body because the cap check fires first.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = stream.shutdown().await;
        });
        tokio::task::yield_now().await;

        let mut proxy = BrokerProxy::new(&path);
        proxy.max_frame_bytes = 1024;
        let err = proxy
            .call(
                ServiceId::parse("host.time.v1").unwrap(),
                "now",
                CorrelationId::new("01HCORR"),
                serde_json::json!({}),
            )
            .await
            .expect_err("oversized response must error");
        assert!(
            matches!(
                err,
                ProxyError::ResponseTooLarge {
                    size: 1_048_576,
                    cap: 1024,
                    ..
                }
            ),
            "got {:?}",
            err
        );
        mock.abort();
    }
}
