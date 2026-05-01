//! Artifact collector slot. Wave 3 — captures runtime artifacts.
//!
//! Plan 37 §21: post-run, the supervisor sweeps the workload's
//! `artifact_policy.capture_paths` (typically `/artifacts` mounted
//! via virtiofs) and persists the contents to a per-tenant store.
//! Retention is governed by `artifact_policy.retention_days`. Wave
//! 1.3 lands the trait surface; Wave 3 wires the real impl.

use async_trait::async_trait;
use mvm_plan::PlanId;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("artifact collector not wired (Noop slot)")]
    NotWired,

    #[error("io error during capture: {0}")]
    Io(String),
}

#[async_trait]
pub trait ArtifactCollector: Send + Sync {
    /// Sweep the workload's capture paths and persist the contents
    /// keyed by `plan_id`. Wave 3's real impl streams via virtiofs
    /// and writes to the tenant's encrypted artifact store.
    async fn collect(&self, plan_id: &PlanId) -> Result<(), ArtifactError>;
}

pub struct NoopArtifactCollector;

#[async_trait]
impl ArtifactCollector for NoopArtifactCollector {
    async fn collect(&self, _plan_id: &PlanId) -> Result<(), ArtifactError> {
        Err(ArtifactError::NotWired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_artifact_collector_is_constructable() {
        let _: Box<dyn ArtifactCollector> = Box::new(NoopArtifactCollector);
    }
}
