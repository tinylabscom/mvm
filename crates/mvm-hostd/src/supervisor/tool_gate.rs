//! Tool-call gate slot. Wave 2 differentiator.
//!
//! Plan 37 §2.2 / §15: the supervisor mediates every tool the
//! workload invokes via vsock RPC. The gate consults the plan's
//! `tool_policy: PolicyRef`, looks the bundle up via
//! `mvm-policy::ToolPolicy`, and allow/deny per call. Audit entries
//! reference both the plan id and the tool name.

use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolDecision {
    Allow,
    Deny { reason: String },
}

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("tool gate not wired (Noop slot)")]
    NotWired,

    #[error("tool {name} is not on the plan's allowlist")]
    NotAllowed { name: String },
}

#[async_trait]
pub trait ToolGate: Send + Sync {
    async fn check(&self, tool_name: &str) -> Result<ToolDecision, ToolError>;
}

pub struct NoopToolGate;

#[async_trait]
impl ToolGate for NoopToolGate {
    async fn check(&self, _tool_name: &str) -> Result<ToolDecision, ToolError> {
        Err(ToolError::NotWired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_tool_gate_is_constructable() {
        let _: Box<dyn ToolGate> = Box::new(NoopToolGate);
    }
}
