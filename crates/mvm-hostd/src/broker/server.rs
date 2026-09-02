//! UDS server loop — accepts `ServiceCall` envelopes from the supervisor
//! proxy, dispatches via [`Registry`], writes back the [`ServiceResponse`].
//!
//! Currently the UDS server only; vsock 5300 wiring is separate (the
//! supervisor sets up the backend-specific listener and hands an FD; this
//! crate consumes the FD via [`serve_on_listener`]).
//!
//! Frame format: 4-byte big-endian length prefix + JSON `ServiceCall`.
//! Response: 4-byte big-endian length prefix + JSON `ServiceResponse`.
//! The max-frame-bytes gate is enforced *before* the parse so a malformed
//! length prefix cannot provoke an unbounded allocation.

use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceResponse};
use mvm_core::protocol::handler::ServiceCallCtx;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::broker::registry::{CancellationToken, Registry};

/// Accept loop. Each accepted UDS connection runs to completion in its
/// own `tokio::spawn`; one connection per supervisor-proxy call.
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
/// supervisor's spawn path calls this once it sets up the listener at
/// the per-VM UDS path from `SubprocessConfig::uds_path`.
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
    // Reassign a server-authoritative correlation id at ingress: the
    // guest-supplied `call.correlation_id` is NEVER trusted — a workload could
    // otherwise choose an id that collides with or impersonates another entry
    // in the chain-signed audit log. The reassigned id flows into the ctx
    // (hence the audit entry) and the response. The guest does not match on it
    // (one call per connection), so reassignment is transparent to it.
    let correlation_id = mint_correlation_id();
    debug!(
        service = %call.service,
        verb = %call.verb,
        client_correlation_id = %call.correlation_id,
        correlation_id = %correlation_id,
        "mvm-broker received call (correlation id reassigned)"
    );

    // The registration's workload identity is also this broker connection's
    // server-derived session lookup key. A guest cannot choose it: each VM has
    // a separately bound listener carrying its admitted registration context.
    let ctx = ServiceCallCtx {
        workload_id: workload_id.clone(),
        tenant_id: tenant_id.clone(),
        correlation_id: correlation_id.clone(),
        session_id: workload_id.clone(),
        profile: AgentProfile::default(),
        composition_depth: 0,
        composition_width: 0,
    };

    let cancellation = CancellationToken::new();
    let result = match call.capability {
        Some(invocation) => {
            registry
                .dispatch_capability(
                    &ctx,
                    &call.service,
                    &call.verb,
                    &invocation,
                    call.payload,
                    &cancellation,
                )
                .await
        }
        None => {
            registry
                .dispatch(&ctx, &call.service, &call.verb, call.payload)
                .await
        }
    };
    let response = match result {
        Ok(payload) => ServiceResponse::Ok {
            correlation_id,
            payload,
        },
        Err(e) => ServiceResponse::Err {
            correlation_id,
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

/// Mint a fresh, server-authoritative correlation id at frame ingress. Unique
/// per (broker process, call): a process-id prefix + a monotonic counter — the
/// broker is per-VM and serves one call per connection, so this never collides
/// within a workload. No new dependency; the value is opaque (a future change
/// to ULID/Snowflake is a serde-compatible widening since it stays a string).
fn mint_correlation_id() -> CorrelationId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    CorrelationId::new(format!("brk-{}-{:016x}", std::process::id(), n))
}

/// Read a length-prefixed JSON frame. Enforces the max-frame-bytes cap
/// before allocating the body buffer.
// Length-prefixed JSON framing lives in `crate::framing`; these wrappers
// keep the broker error context on the shared transport. The
// cap-before-alloc gate is enforced there.
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
    use std::pin::Pin;
    use std::time::Duration;

    use mvm_contract::protocol::agent_capability::{
        CapabilityDescriptor, CapabilityId, CapabilityInvocation, CapabilityLimits, SchemaRef,
    };
    use mvm_contract::protocol::agent_session::AgentRequestId;
    use mvm_core::policy::security::AgentProfile;
    use mvm_core::protocol::broker::{CorrelationId, ServiceCall, ServiceErrorCode, ServiceId};
    use mvm_core::protocol::handler::{ServiceCallCtx, ServiceDispatchResult, ServiceHandler};
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

    struct TypedEchoHandler;

    impl ServiceHandler for TypedEchoHandler {
        fn id(&self) -> ServiceId {
            ServiceId::parse("host.dev.echo.v1").expect("service id")
        }

        fn profiles(&self) -> &[AgentProfile] {
            &[AgentProfile::Dev]
        }

        fn audit_durability(&self) -> mvm_core::protocol::broker::AuditDurability {
            mvm_core::protocol::broker::AuditDurability::default_batched()
        }

        fn idempotency(&self) -> mvm_core::protocol::broker::Idempotency {
            mvm_core::protocol::broker::Idempotency::MintFresh
        }

        fn call_timeout(&self) -> Duration {
            Duration::from_millis(50)
        }

        fn dispatch<'a>(
            &'a self,
            _ctx: &'a ServiceCallCtx,
            _verb: &'a str,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
            Box::pin(async move { Ok(payload) })
        }
    }

    fn typed_echo_descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(
                ServiceId::parse("host.dev.echo.v1").expect("service id"),
                "echo",
            )
            .expect("capability id"))
            .description("echo a bounded test value")
            .input_schema(SchemaRef::new("host.dev.echo.input.v1", [1; 32]).expect("schema"))
            .output_schema(SchemaRef::new("host.dev.echo.output.v1", [2; 32]).expect("schema"))
            .limits(CapabilityLimits::new(1024, 1024, 100).expect("limits"))
            .build()
            .expect("descriptor")
    }

    #[tokio::test]
    async fn round_trips_a_call_and_returns_not_bound_with_empty_registry() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind typed broker test listener: {error}"),
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
            capability: None,
        };
        write_call(&mut client, &call).await.unwrap();
        let response = read_response(&mut client).await.unwrap();

        match response {
            ServiceResponse::Err {
                correlation_id,
                code,
                message,
            } => {
                // The broker reassigns a server-authoritative correlation id at
                // ingress — the guest-supplied value is never trusted/echoed.
                assert_ne!(correlation_id.as_str(), "01HBROKER0000000000000000");
                assert!(
                    correlation_id.as_str().starts_with("brk-"),
                    "correlation id must be server-minted: {}",
                    correlation_id.as_str()
                );
                assert_eq!(code, ServiceErrorCode::NotBound);
                assert!(message.contains("host.time.v1"));
            }
            other => panic!("expected NotBound err, got {:?}", other),
        }

        server_task.abort();
    }

    #[tokio::test]
    async fn typed_call_round_trips_over_uds_and_replay_is_refused() {
        let dir = tempdir().unwrap();
        let path = uds_path(&dir);
        let listener = match UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind typed broker test listener: {error}"),
        };
        let descriptor = typed_echo_descriptor();
        let binding = descriptor.binding();
        let mut registry = Registry::new();
        registry
            .register_capability(Arc::new(TypedEchoHandler), descriptor)
            .expect("register typed handler");
        registry
            .admit_capabilities([binding.clone()])
            .expect("admit typed binding");
        let registry = Arc::new(registry);
        let server_task = tokio::spawn({
            let registry = registry.clone();
            async move {
                let _ = serve_on_listener(
                    listener,
                    registry,
                    "wl-test".into(),
                    "t-test".into(),
                    65_536,
                )
                .await;
            }
        });
        tokio::task::yield_now().await;

        let payload = serde_json::json!({"value": 7});
        let invocation = CapabilityInvocation::from_payload(
            binding,
            AgentRequestId::parse("uds-request-1").expect("request id"),
            &payload,
        )
        .expect("invocation");
        let call = ServiceCall {
            service: ServiceId::parse("host.dev.echo.v1").expect("service id"),
            verb: "echo".into(),
            correlation_id: CorrelationId::new("guest-correlation"),
            payload: payload.clone(),
            capability: Some(invocation.clone()),
        };
        let mut client = ClientStream::connect(&path).await.unwrap();
        write_call(&mut client, &call).await.unwrap();
        assert!(matches!(
            read_response(&mut client).await.unwrap(),
            ServiceResponse::Ok { payload: response, .. } if response == payload
        ));

        let mut replay_client = ClientStream::connect(&path).await.unwrap();
        write_call(&mut replay_client, &call).await.unwrap();
        let response = read_response(&mut replay_client).await.unwrap();
        assert!(matches!(
            response,
            ServiceResponse::Err {
                code: ServiceErrorCode::CapabilityReplay,
                ..
            }
        ));
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
            capability: None,
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
