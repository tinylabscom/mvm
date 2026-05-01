//! `Supervisor` — aggregate that owns every component slot plus the
//! plan execution state machine.
//!
//! Wave 1.3 ships the type with `Default::default()` returning a
//! supervisor wired with every `Noop` slot. The actual
//! `Supervisor::launch(plan)` happy path that walks the state
//! machine and pulls each slot lands in Wave 1.4.

use std::sync::Arc;

use thiserror::Error;

use crate::artifact::{ArtifactCollector, NoopArtifactCollector};
use crate::audit::{AuditSigner, NoopAuditSigner};
use crate::egress::{EgressProxy, NoopEgressProxy};
use crate::keystore::{KeystoreReleaser, NoopKeystoreReleaser};
use crate::state::{PlanStateMachine, StateTransitionError};
use crate::tool_gate::{NoopToolGate, ToolGate};

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("plan state transition failed: {0}")]
    State(#[from] StateTransitionError),

    #[error("egress proxy error: {0}")]
    Egress(String),

    #[error("tool gate error: {0}")]
    Tool(String),

    #[error("keystore error: {0}")]
    Keystore(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("artifact error: {0}")]
    Artifact(String),
}

/// Trusted host-side supervisor. Plan 37 §7B.
///
/// Holds Arc-wrapped trait objects so the daemon can hand the same
/// supervisor to multiple plan-execution tasks without cloning each
/// component. The Arc indirection also lets future tests swap one
/// slot at a time (e.g. mock `EgressProxy`, real `AuditSigner`)
/// without rebuilding the whole struct.
pub struct Supervisor {
    pub egress: Arc<dyn EgressProxy>,
    pub tool_gate: Arc<dyn ToolGate>,
    pub keystore: Arc<dyn KeystoreReleaser>,
    pub audit: Arc<dyn AuditSigner>,
    pub artifact: Arc<dyn ArtifactCollector>,
    pub state: PlanStateMachine,
}

impl Default for Supervisor {
    /// Default is the fail-closed configuration: every component slot
    /// is `Noop`, so any non-trivial operation errors with `NotWired`
    /// until a real impl is plumbed in. Plan 37 §7B's invariant —
    /// "tenant code never runs in Zone B unless every slot is owned
    /// by a real impl" — is encoded by this default + the typed
    /// errors each Noop returns.
    fn default() -> Self {
        Self {
            egress: Arc::new(NoopEgressProxy),
            tool_gate: Arc::new(NoopToolGate),
            keystore: Arc::new(NoopKeystoreReleaser),
            audit: Arc::new(NoopAuditSigner),
            artifact: Arc::new(NoopArtifactCollector),
            state: PlanStateMachine::new(),
        }
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::PlanState;

    #[test]
    fn default_supervisor_starts_in_pending() {
        let s = Supervisor::default();
        assert_eq!(s.state.current(), PlanState::Pending);
    }

    #[test]
    fn supervisor_aggregates_every_slot() {
        // Pure type-level assertion that every component is wired
        // in Default. If a future field is added without a Default,
        // this test won't compile.
        let _ = Supervisor::default();
    }
}
