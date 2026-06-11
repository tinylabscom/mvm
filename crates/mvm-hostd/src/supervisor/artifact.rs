//! Artifact collector slot — captures runtime artifacts.
//!
//! Post-run, the supervisor sweeps the workload's
//! `artifact_policy.capture_paths` (typically `/artifacts` mounted
//! via virtiofs) and persists the contents to a per-tenant store.
//! Retention is governed by `artifact_policy.retention_days`. This
//! module lands the trait surface; the real impl is wired separately.
//!
//! ## Three states
//!
//! - **`NoopArtifactCollector`** — `local-default` policy refs, no
//!   bundle on disk. `collect()` returns `NotWired`. The fail-closed
//!   default.
//! - **`LiveArtifactCollector`** — a tenant-scoped bundle parsed
//!   cleanly; `capture_paths` + `retention_days` were loaded but the
//!   virtiofs-streaming sweep that turns those paths into artifacts
//!   on disk lives in the mvm-hostd supervisor lift. `collect()`
//!   returns `NotImplemented` (distinct from `NotWired`) so
//!   operators can tell "no bundle" from "bundle present, consumer
//!   pending".
//! - **The real impl** — actually sweeps, encrypts, persists. Not in
//!   this crate yet.

use async_trait::async_trait;
use mvm_core::plan::PlanId;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("artifact collector not wired (Noop slot)")]
    NotWired,

    #[error(
        "artifact collector configured ({path_count} capture paths, \
         {retention_days}-day retention) but the virtiofs sweep is not yet \
         implemented in this build (pending mvm-hostd lift)"
    )]
    NotImplemented {
        path_count: usize,
        retention_days: u32,
    },

    #[error("io error during capture: {0}")]
    Io(String),
}

#[async_trait]
pub trait ArtifactCollector: Send + Sync {
    /// Sweep the workload's capture paths and persist the contents
    /// keyed by `plan_id`. The real impl streams via virtiofs
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

/// Carries the parsed bundle's capture configuration. The trait
/// `collect()` returns `NotImplemented` until the mvm-hostd lift
/// wires the virtiofs-streaming sweep; the configuration is loaded
/// off the public fields so an in-process consumer can downcast and
/// read the paths today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveArtifactCollector {
    pub capture_paths: Vec<String>,
    pub retention_days: u32,
}

impl LiveArtifactCollector {
    /// Construct from a parsed `mvm_core::policy::ArtifactPolicy`. Clones
    /// the path list so the collector outlives the borrowed policy.
    pub fn from_policy(policy: &mvm_core::policy::ArtifactPolicy) -> Self {
        Self {
            capture_paths: policy.capture_paths.clone(),
            retention_days: policy.retention_days,
        }
    }
}

#[async_trait]
impl ArtifactCollector for LiveArtifactCollector {
    async fn collect(&self, _plan_id: &PlanId) -> Result<(), ArtifactError> {
        Err(ArtifactError::NotImplemented {
            path_count: self.capture_paths.len(),
            retention_days: self.retention_days,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_artifact_collector_is_constructable() {
        let _: Box<dyn ArtifactCollector> = Box::new(NoopArtifactCollector);
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn noop_collector_errors_not_wired() {
        let plan_id = PlanId("plan-noop".to_string());
        let err = block_on(NoopArtifactCollector.collect(&plan_id)).expect_err("noop");
        assert!(matches!(err, ArtifactError::NotWired));
    }

    #[test]
    fn live_collector_carries_paths_from_policy() {
        let policy = mvm_core::policy::ArtifactPolicy {
            capture_paths: vec!["/artifacts".to_string(), "/output".to_string()],
            retention_days: 7,
        };
        let c = LiveArtifactCollector::from_policy(&policy);
        assert_eq!(c.capture_paths, policy.capture_paths);
        assert_eq!(c.retention_days, 7);
    }

    #[test]
    fn live_collector_errors_not_implemented_with_paths_count() {
        let policy = mvm_core::policy::ArtifactPolicy {
            capture_paths: vec!["/a".to_string(), "/b".to_string(), "/c".to_string()],
            retention_days: 30,
        };
        let c = LiveArtifactCollector::from_policy(&policy);
        let plan_id = PlanId("plan-live".to_string());
        let err = block_on(c.collect(&plan_id)).expect_err("live errors not-implemented");
        match err {
            ArtifactError::NotImplemented {
                path_count,
                retention_days,
            } => {
                assert_eq!(path_count, 3);
                assert_eq!(retention_days, 30);
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }

    #[test]
    fn live_collector_with_empty_paths_still_distinguishes_from_noop() {
        // A bundle that parses but specifies no capture_paths is
        // distinct from "no bundle at all" — the live collector
        // reports zero paths via NotImplemented, the noop reports
        // NotWired. This matters to operators auditing whether
        // their bundle parsed.
        let policy = mvm_core::policy::ArtifactPolicy {
            capture_paths: vec![],
            retention_days: 0,
        };
        let c = LiveArtifactCollector::from_policy(&policy);
        let plan_id = PlanId("plan-empty".to_string());
        let err = block_on(c.collect(&plan_id)).expect_err("live");
        match err {
            ArtifactError::NotImplemented {
                path_count,
                retention_days,
            } => {
                assert_eq!(path_count, 0);
                assert_eq!(retention_days, 0);
            }
            other => panic!("expected NotImplemented, got {other:?}"),
        }
    }
}
