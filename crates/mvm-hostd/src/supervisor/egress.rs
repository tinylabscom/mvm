//! Egress proxy slot. Wave 2 differentiator.
//!
//! Plan 37 §15: the supervisor owns a single trusted egress proxy
//! that the workload's outbound traffic must traverse. The proxy
//! enforces L7 rules (SNI/Host pin sets), inspects payloads via the
//! inspector chain (`SecretsScanner`, `SsrfGuard`, `InjectionGuard`,
//! `DestinationPolicy`), and routes AI-provider calls through the
//! `AiProviderRouter` + `PiiRedactor`. Wave 1.3 lands the trait
//! surface; Wave 2 fills the inspector chain.

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    /// Allow the request to flow through unchanged.
    Allow,
    /// Block the request. The `reason` is surfaced to the workload
    /// (and to the audit stream).
    Deny { reason: String },
}

#[derive(Debug, Error)]
pub enum EgressError {
    #[error("egress proxy not wired (Noop slot)")]
    NotWired,

    #[error("inspector chain rejected request: {reason}")]
    Rejected { reason: String },

    #[error("upstream unreachable: {0}")]
    UpstreamUnreachable(String),
}

/// Async because Wave 2's real impl streams body bytes through the
/// inspector chain incrementally — a request can be allowed at
/// header-time, then have its body redacted by `PiiRedactor`
/// mid-stream, all under one `inspect` call.
#[async_trait]
pub trait EgressProxy: Send + Sync {
    /// Inspect an outbound HTTP request. The signature is intentionally
    /// loose at this stage — Wave 2 introduces the concrete `EgressRequest`
    /// + `EgressResponse` shapes once the inspector chain is wired.
    async fn inspect(&self, host: &str, path: &str) -> Result<EgressDecision, EgressError>;
}

/// Fail-closed default. A supervisor wired with `NoopEgressProxy`
/// refuses every outbound request.
///
/// This is intentional: a misconfigured deployment that forgot to wire
/// the real proxy fails loudly on the first egress attempt instead of
/// silently leaking traffic. Wave 2's real `L7EgressProxy` replaces
/// this slot.
pub struct NoopEgressProxy;

#[async_trait]
impl EgressProxy for NoopEgressProxy {
    async fn inspect(&self, _host: &str, _path: &str) -> Result<EgressDecision, EgressError> {
        Err(EgressError::NotWired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Wave 1.3 doesn't pull tokio as a dev-dep yet; the contract
    // test for the async `inspect` happy path lands in Wave 2
    // alongside the real `L7EgressProxy` impl. For now, confirm
    // the trait object constructs (which transitively asserts
    // `Send + Sync`) so a misconfigured `Default::default()`
    // supervisor compiles before it runs.
    #[test]
    fn noop_egress_proxy_is_constructable() {
        let _: Box<dyn EgressProxy> = Box::new(NoopEgressProxy);
    }
}
