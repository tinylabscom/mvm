//! UDS server loop — accepts `ServiceCall` envelopes from the supervisor
//! proxy, dispatches via [`Registry`], writes back the [`ServiceResponse`].
//!
//! W1a ships the UDS server only; vsock 5300 wiring lands in W1b (the
//! supervisor sets up the backend-specific listener and hands an FD; this
//! crate consumes the FD via [`serve_on_listener`]).
//!
//! Frame format: 4-byte big-endian length prefix + JSON `ServiceCall`.
//! Response: 4-byte big-endian length prefix + JSON `ServiceResponse`.
//! The max-frame-bytes gate (Plan 104 §"Capability gating" gate 1) is
//! enforced *before* the parse so a malformed length prefix cannot
//! provoke an unbounded allocation.

use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{ServiceCall, ServiceResponse};
use mvm_core::protocol::handler::ServiceCallCtx;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::broker::registry::Registry;

/// Accept loop. Each accepted UDS connection runs to completion in its
/// own `tokio::spawn`; one connection per supervisor-proxy call in W1a.
pub async fn serve(
    listener: UnixListener,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    info!(
        workload_id = %workload_id,
        max_frame_bytes,
        "mvm-broker accept loop started"
    );
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("mvm-broker UDS accept failed")?;
        let registry = registry.clone();
        let workload_id = workload_id.clone();
        let tenant_id = tenant_id.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, registry, workload_id, tenant_id, max_frame_bytes).await
            {
                warn!(error = %e, "mvm-broker connection terminated with error");
            }
        });
    }
}

/// Variant of [`serve`] for tests + cases where the caller already has a
/// `UnixListener` (e.g., from a tempdir-bound test fixture). The
/// supervisor's spawn path will call this in W1b once it sets up the
/// listener at the per-VM UDS path from `SubprocessConfig::uds_path`.
pub async fn serve_on_listener(
    listener: UnixListener,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    serve(listener, registry, workload_id, tenant_id, max_frame_bytes).await
}

async fn handle_connection(
    mut stream: UnixStream,
    registry: Arc<Registry>,
    workload_id: String,
    tenant_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    let call = read_frame::<ServiceCall>(&mut stream, max_frame_bytes).await?;
    debug!(
        service = %call.service,
        verb = %call.verb,
        correlation_id = %call.correlation_id,
        "mvm-broker received call"
    );

    // W1a stub ctx: profile = Dev (default), composition counters = 0.
    // W1b will populate from the supervisor-side enriched envelope.
    let ctx = ServiceCallCtx {
        workload_id: workload_id.clone(),
        tenant_id: tenant_id.clone(),
        correlation_id: call.correlation_id.clone(),
        session_id: "w1a-stub-session".to_string(),
        profile: AgentProfile::default(),
        composition_depth: 0,
        composition_width: 0,
    };

    let response = match registry
        .dispatch(&ctx, &call.service, &call.verb, call.payload)
        .await
    {
        Ok(payload) => ServiceResponse::Ok {
            correlation_id: call.correlation_id,
            payload,
        },
        Err(e) => ServiceResponse::Err {
            correlation_id: call.correlation_id,
            code: e.code,
            message: e.message,
        },
    };

    write_frame(&mut stream, &response).await?;
    stream
        .shutdown()
        .await
        .context("mvm-broker UDS shutdown failed")?;
    Ok(())
}

/// Read a length-prefixed JSON frame. Enforces the max-frame-bytes cap
/// before allocating the body buffer (Plan 104 §"Capability gating"
/// gate 1).
// Length-prefixed JSON framing lives in `crate::framing` (plan 126 B5;
// was `mvm_core::framing`); these wrappers keep the broker error context
// on the shared transport. The cap-before-alloc gate is enforced there.
pub async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<T> {
    crate::framing::read_json_frame(stream, max_frame_bytes)
        .await
        .context("mvm-broker frame read failed")
}

/// Write a length-prefixed JSON frame.
pub async fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    crate::framing::write_json_frame(stream, value)
        .await
        .context("mvm-broker frame write failed")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
    use tempfile::tempdir;
    use tokio::net::UnixStream as ClientStream;

    use super::*;
    use tokio::io::AsyncReadExt;

    async fn write_call(stream: &mut ClientStream, call: &ServiceCall) -> Result<()> {
        let body = serde_json::to_vec(call).unwrap();
        let len: u32 = body.len().try_into().unwrap();
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&body).await?;
        Ok(())
    }

    async fn read_response(stream: &mut ClientStream) -> Result<ServiceResponse> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn uds_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("broker.sock")
    }

    #[tokio::test]
    async fn round_trips_a_call_and_returns_not_bound_with_empty_registry() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = UnixListener::bind(&path).unwrap();
        let registry = Arc::new(Registry::new());

        let server_task = tokio::spawn({
            let registry = registry.clone();
            let path_clone = path.clone();
            async move {
                let _ = serve_on_listener(
                    listener,
                    registry,
                    "wl-test".into(),
                    "t-test".into(),
                    65_536,
                )
                .await;
                drop(path_clone);
            }
        });

        // Give the listener a tick to start.
        tokio::task::yield_now().await;

        let mut client = ClientStream::connect(&path).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.time.v1").unwrap(),
            verb: "now".into(),
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            payload: serde_json::json!({}),
        };
        write_call(&mut client, &call).await.unwrap();
        let response = read_response(&mut client).await.unwrap();

        match response {
            ServiceResponse::Err {
                correlation_id,
                code,
                message,
            } => {
                assert_eq!(correlation_id.as_str(), "01HBROKER0000000000000000");
                assert_eq!(code, ServiceErrorCode::NotBound);
                assert!(message.contains("host.time.v1"));
            }
            other => panic!("expected NotBound err, got {:?}", other),
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn rejects_frames_above_the_cap() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("failed to bind broker test listener: {err}"),
        };
        let registry = Arc::new(Registry::new());

        let server_task = tokio::spawn({
            let registry = registry.clone();
            let path_clone = path.clone();
            async move {
                let _ = serve_on_listener(
                    listener,
                    registry,
                    "wl-test".into(),
                    "t-test".into(),
                    // Tiny cap so any real envelope blows past it.
                    32,
                )
                .await;
                drop(path_clone);
            }
        });

        tokio::task::yield_now().await;

        let mut client = ClientStream::connect(&path).await.unwrap();
        let call = ServiceCall {
            service: ServiceId::parse("host.time.v1").unwrap(),
            verb: "now".into(),
            correlation_id: CorrelationId::new("01HBROKER0000000000000000"),
            payload: serde_json::json!({"padding": "x".repeat(256)}),
        };
        // Manually write the length prefix + body so the test exercises
        // the server-side cap check (the server reads the prefix, sees
        // it's > 32, and closes the connection).
        let body = serde_json::to_vec(&call).unwrap();
        let len: u32 = body.len().try_into().unwrap();
        client.write_all(&len.to_be_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();

        // The server should drop the connection; depending on platform
        // scheduling, the client may observe either EOF or a reset.
        let mut buf = [0u8; 4];
        match client.read(&mut buf).await {
            Ok(0) => {}
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(n) => panic!("expected EOF/reset after oversized frame rejection, got {n} bytes"),
            Err(err) => {
                panic!("expected EOF/reset after oversized frame rejection, got {err}")
            }
        }

        server_task.abort();
    }
}
