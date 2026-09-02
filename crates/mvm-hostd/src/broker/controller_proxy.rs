//! Host-only endpoint for controller-owned typed broker handlers.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{Context, Result, bail};
use mvm_contract::protocol::agent_capability::CapabilityDescriptor;
use mvm_contract::protocol::broker_control::{
    MAX_SERVICE_PROXY_FRAME_BYTES, ServiceProxyBinding, ServiceProxyRequest, ServiceProxyResponse,
};
use mvm_core::protocol::broker::ServiceErrorCode;
use mvm_core::protocol::handler::{ServiceCallCtx, ServiceHandler};
use tokio::net::{UnixListener, UnixStream};

use crate::framing::{read_json_frame, write_json_frame};

struct ControllerEndpoint {
    binding: ServiceProxyBinding,
}

static ENDPOINTS: OnceLock<Mutex<HashMap<String, ControllerEndpoint>>> = OnceLock::new();

/// Bind a controller-owned handler and return the exact signed registration
/// binding the resident broker must receive.
pub fn prepare_controller_service(
    vm_id: &str,
    handler: Arc<dyn ServiceHandler>,
    capabilities: Vec<CapabilityDescriptor>,
) -> Result<ServiceProxyBinding> {
    let service = handler.id();
    let endpoint = controller_endpoint_path(vm_id, service.as_str());
    let binding = ServiceProxyBinding {
        service,
        endpoint: endpoint.to_string_lossy().into_owned(),
        capabilities,
    };
    binding
        .validate()
        .map_err(|message| anyhow::anyhow!(message))?;

    let endpoints = ENDPOINTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut endpoints = endpoints
        .lock()
        .expect("controller endpoint map is not poisoned");
    if let Some(existing) = endpoints.get(&binding.endpoint) {
        if existing.binding == binding {
            return Ok(binding);
        }
        bail!("controller endpoint is already bound to a different service contract");
    }
    if let Some(parent) = endpoint.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create controller proxy directory {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(&endpoint);
    let listener = std::os::unix::net::UnixListener::bind(&endpoint)
        .with_context(|| format!("bind controller proxy {}", endpoint.display()))?;
    std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict controller proxy {}", endpoint.display()))?;
    listener
        .set_nonblocking(true)
        .context("make controller proxy listener nonblocking")?;
    let thread_binding = binding.clone();
    std::thread::Builder::new()
        .name("mvm-controller-proxy".to_string())
        .spawn(move || run_controller_service(listener, handler, thread_binding))
        .context("spawn controller proxy thread")?;
    endpoints.insert(
        binding.endpoint.clone(),
        ControllerEndpoint {
            binding: binding.clone(),
        },
    );
    Ok(binding)
}

fn controller_endpoint_path(vm_id: &str, service: &str) -> PathBuf {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(service.as_bytes());
    mvm_core::config::vm_socket_dir(vm_id).join(format!("ctl-{}.sock", hex::encode(&digest[..8])))
}

fn run_controller_service(
    listener: std::os::unix::net::UnixListener,
    handler: Arc<dyn ServiceHandler>,
    binding: ServiceProxyBinding,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "controller proxy runtime build failed");
            return;
        }
    };
    runtime.block_on(async move {
        let listener = match UnixListener::from_std(listener) {
            Ok(listener) => listener,
            Err(error) => {
                tracing::error!(%error, "controller proxy listener conversion failed");
                return;
            }
        };
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!(%error, "controller proxy accept failed");
                    continue;
                }
            };
            let handler = Arc::clone(&handler);
            let binding = binding.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, handler, &binding).await {
                    tracing::warn!(%error, "controller proxy request failed closed");
                }
            });
        }
    });
}

async fn handle_connection(
    mut stream: UnixStream,
    handler: Arc<dyn ServiceHandler>,
    binding: &ServiceProxyBinding,
) -> Result<()> {
    let request =
        read_json_frame::<_, ServiceProxyRequest>(&mut stream, MAX_SERVICE_PROXY_FRAME_BYTES)
            .await
            .context("read controller proxy request")?;
    let response = dispatch_request(handler, binding, request).await;
    let response = bound_response(response);
    write_json_frame(&mut stream, &response)
        .await
        .context("write controller proxy response")
}

async fn dispatch_request(
    handler: Arc<dyn ServiceHandler>,
    binding: &ServiceProxyBinding,
    request: ServiceProxyRequest,
) -> ServiceProxyResponse {
    if request.service != binding.service
        || !binding
            .capabilities
            .iter()
            .any(|descriptor| descriptor.id.verb == request.verb)
        || request.workload_id != request.session_id
    {
        return proxy_error(
            ServiceErrorCode::CapabilityBindingMismatch,
            "controller proxy identity mismatch",
        );
    }
    let ctx = ServiceCallCtx {
        workload_id: request.workload_id,
        tenant_id: request.tenant_id,
        correlation_id: request.correlation_id,
        session_id: request.session_id,
        profile: request.profile,
        composition_depth: request.composition_depth,
        composition_width: request.composition_width,
    };
    match handler.dispatch(&ctx, &request.verb, request.payload).await {
        Ok(payload) => ServiceProxyResponse::Ok { payload },
        Err(error) => proxy_error(error.code, &error.message),
    }
}

fn proxy_error(code: ServiceErrorCode, message: &str) -> ServiceProxyResponse {
    ServiceProxyResponse::Err {
        code,
        message: sanitize_message(message),
    }
}

fn bound_response(response: ServiceProxyResponse) -> ServiceProxyResponse {
    match serde_json::to_vec(&response) {
        Ok(bytes) if bytes.len() <= MAX_SERVICE_PROXY_FRAME_BYTES => response,
        _ => proxy_error(
            ServiceErrorCode::ResponseTooLarge,
            "controller proxy response exceeded its bound",
        ),
    }
}

fn sanitize_message(message: &str) -> String {
    message
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::time::Duration;

    use mvm_contract::protocol::agent_capability::{
        CapabilityDescriptor, CapabilityId, CapabilityLimits, SchemaRef,
    };
    use mvm_core::policy::security::AgentProfile;
    use mvm_core::protocol::broker::{AuditDurability, CorrelationId, Idempotency, ServiceId};
    use mvm_core::protocol::handler::{
        ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
    };

    use super::*;
    use crate::broker::service_proxy::ControllerServiceProxy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Echo;

    impl ServiceHandler for Echo {
        fn id(&self) -> ServiceId {
            service()
        }

        fn profiles(&self) -> &[AgentProfile] {
            &[AgentProfile::Dev]
        }

        fn audit_durability(&self) -> AuditDurability {
            AuditDurability::PerCall
        }

        fn idempotency(&self) -> Idempotency {
            Idempotency::MintFresh
        }

        fn call_timeout(&self) -> Duration {
            Duration::from_millis(250)
        }

        fn dispatch<'a>(
            &'a self,
            _ctx: &'a ServiceCallCtx,
            verb: &'a str,
            payload: serde_json::Value,
        ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
            Box::pin(async move {
                if verb != "echo" {
                    return Err(ServiceError::new(
                        ServiceErrorCode::NotImplemented,
                        "unexpected verb",
                    ));
                }
                Ok(payload)
            })
        }
    }

    fn service() -> ServiceId {
        ServiceId::parse("host.test.controller.v1").expect("service id")
    }

    fn descriptor() -> CapabilityDescriptor {
        CapabilityDescriptor::builder()
            .id(CapabilityId::new(service(), "echo").expect("capability"))
            .description("bounded controller proxy echo")
            .input_schema(SchemaRef::new("host.test.input.v1", [1; 32]).expect("schema"))
            .output_schema(SchemaRef::new("host.test.output.v1", [2; 32]).expect("schema"))
            .limits(CapabilityLimits::new(1024, 1024, 250).expect("limits"))
            .build()
            .expect("descriptor")
    }

    fn context(session: &str) -> ServiceCallCtx {
        ServiceCallCtx {
            workload_id: session.to_string(),
            tenant_id: "local".to_string(),
            correlation_id: CorrelationId::new("controller-proxy-test"),
            session_id: session.to_string(),
            profile: AgentProfile::Dev,
            composition_depth: 0,
            composition_width: 0,
        }
    }

    #[tokio::test]
    async fn controller_handler_round_trips_over_the_host_only_proxy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let binding =
            prepare_controller_service("proxy-roundtrip", Arc::new(Echo), vec![descriptor()])
                .expect("prepare proxy");
        let proxy = ControllerServiceProxy::new(binding).expect("resident proxy");
        let payload = serde_json::json!({"value": "synthetic"});
        assert_eq!(
            proxy
                .dispatch(&context("proxy-roundtrip"), "echo", payload.clone())
                .await
                .expect("proxy response"),
            payload
        );
    }

    #[tokio::test]
    async fn controller_endpoint_refuses_a_mismatched_session_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let binding =
            prepare_controller_service("proxy-mismatch", Arc::new(Echo), vec![descriptor()])
                .expect("prepare proxy");
        let mut stream = UnixStream::connect(&binding.endpoint)
            .await
            .expect("connect proxy");
        let request = ServiceProxyRequest {
            service: service(),
            verb: "echo".to_string(),
            workload_id: "proxy-mismatch".to_string(),
            tenant_id: "local".to_string(),
            correlation_id: CorrelationId::new("mismatch"),
            session_id: "another-session".to_string(),
            profile: AgentProfile::Dev,
            composition_depth: 0,
            composition_width: 0,
            payload: serde_json::json!({}),
        };
        write_json_frame(&mut stream, &request)
            .await
            .expect("write request");
        let response =
            read_json_frame::<_, ServiceProxyResponse>(&mut stream, MAX_SERVICE_PROXY_FRAME_BYTES)
                .await
                .expect("read refusal");
        assert!(matches!(
            response,
            ServiceProxyResponse::Err {
                code: ServiceErrorCode::CapabilityBindingMismatch,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn missing_controller_endpoint_is_unavailable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binding = ServiceProxyBinding {
            service: service(),
            endpoint: dir
                .path()
                .join("missing.sock")
                .to_string_lossy()
                .into_owned(),
            capabilities: vec![descriptor()],
        };
        let proxy = ControllerServiceProxy::new(binding).expect("resident proxy");
        let error = proxy
            .dispatch(&context("proxy-missing"), "echo", serde_json::json!({}))
            .await
            .expect_err("missing controller must fail closed");
        assert_eq!(error.code, ServiceErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn controller_rejects_an_oversized_announced_frame_before_body_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let binding =
            prepare_controller_service("proxy-oversize", Arc::new(Echo), vec![descriptor()])
                .expect("prepare proxy");
        let mut stream = UnixStream::connect(&binding.endpoint)
            .await
            .expect("connect proxy");
        stream
            .write_all(&u32::MAX.to_be_bytes())
            .await
            .expect("write hostile length");
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("controller must close an oversized request promptly")
            .expect("read closure");
        assert_eq!(read, 0, "oversized request must be closed without a body");
    }
}
