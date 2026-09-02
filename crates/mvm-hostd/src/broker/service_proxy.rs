//! Generic resident-broker proxy for a controller-owned typed service.

use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use mvm_contract::protocol::broker_control::{
    MAX_SERVICE_PROXY_FRAME_BYTES, ServiceProxyBinding, ServiceProxyRequest, ServiceProxyResponse,
};
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};
use tokio::net::UnixStream;

use crate::framing::{read_json_frame, write_json_frame};

/// A typed service whose implementation remains in the admitting controller.
pub struct ControllerServiceProxy {
    binding: ServiceProxyBinding,
    endpoint: PathBuf,
    timeout: Duration,
    response_cap: usize,
}

impl ControllerServiceProxy {
    /// Construct only from a validated host-signed registration binding.
    pub fn new(binding: ServiceProxyBinding) -> anyhow::Result<Self> {
        binding
            .validate()
            .map_err(|message| anyhow::anyhow!(message))?;
        let timeout_ms = binding
            .capabilities
            .iter()
            .map(|descriptor| descriptor.limits.timeout_ms)
            .max()
            .ok_or_else(|| anyhow::anyhow!("service proxy has no capability descriptor"))?;
        let response_cap = binding
            .capabilities
            .iter()
            .map(|descriptor| descriptor.limits.max_output_bytes as usize)
            .max()
            .ok_or_else(|| anyhow::anyhow!("service proxy has no output bound"))?
            .saturating_add(4096)
            .min(MAX_SERVICE_PROXY_FRAME_BYTES);
        Ok(Self {
            endpoint: PathBuf::from(&binding.endpoint),
            binding,
            timeout: Duration::from_millis(u64::from(timeout_ms)),
            response_cap,
        })
    }

    /// Exact descriptors admitted for this proxy.
    pub fn descriptors(&self) -> &[mvm_contract::protocol::agent_capability::CapabilityDescriptor] {
        &self.binding.capabilities
    }

    async fn forward(
        &self,
        ctx: &ServiceCallCtx,
        verb: &str,
        payload: serde_json::Value,
    ) -> ServiceDispatchResult {
        let request = ServiceProxyRequest {
            service: self.binding.service.clone(),
            verb: verb.to_string(),
            workload_id: ctx.workload_id.clone(),
            tenant_id: ctx.tenant_id.clone(),
            correlation_id: ctx.correlation_id.clone(),
            session_id: ctx.session_id.clone(),
            profile: ctx.profile,
            composition_depth: ctx.composition_depth,
            composition_width: ctx.composition_width,
            payload,
        };
        let exchange = async {
            let mut stream = UnixStream::connect(&self.endpoint).await.map_err(|_| {
                ServiceError::new(
                    ServiceErrorCode::Unavailable,
                    "controller-backed service is unavailable",
                )
            })?;
            write_json_frame(&mut stream, &request).await.map_err(|_| {
                ServiceError::new(
                    ServiceErrorCode::Unavailable,
                    "controller-backed service request failed",
                )
            })?;
            read_json_frame::<_, ServiceProxyResponse>(&mut stream, self.response_cap)
                .await
                .map_err(|_| {
                    ServiceError::new(
                        ServiceErrorCode::Unavailable,
                        "controller-backed service response failed",
                    )
                })
        };
        let response = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| {
                ServiceError::new(
                    ServiceErrorCode::Timeout,
                    "controller-backed service timed out",
                )
            })??;
        match response {
            ServiceProxyResponse::Ok { payload } => Ok(payload),
            ServiceProxyResponse::Err { code, message } => Err(ServiceError::new(code, message)),
        }
    }
}

impl ServiceHandler for ControllerServiceProxy {
    fn id(&self) -> ServiceId {
        self.binding.service.clone()
    }

    fn profiles(&self) -> &[AgentProfile] {
        &[AgentProfile::SealedProd, AgentProfile::Dev]
    }

    fn audit_durability(&self) -> AuditDurability {
        AuditDurability::PerCall
    }

    fn response_size_cap(&self) -> usize {
        self.response_cap
    }

    fn idempotency(&self) -> Idempotency {
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        self.timeout
    }

    fn dispatch<'a>(
        &'a self,
        ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        Box::pin(self.forward(ctx, verb, payload))
    }
}
