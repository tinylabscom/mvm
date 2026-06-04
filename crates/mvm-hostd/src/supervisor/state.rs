//! Plan execution state machine.
//!
//! Plan 37 §7B specifies the transitions:
//!
//! ```text
//! Pending  ──verified──▶  Verified
//! Verified ──launched──▶  Launched
//! Launched ──running ──▶  Running
//! Running  ──stopping──▶  Stopping
//! Stopping ──stopped ──▶  Stopped
//! ```
//!
//! Plus error paths from any state to `Failed { from }`. Every
//! transition is logged as an audit entry once `AuditSigner` is
//! wired (Wave 3); here we return the error and let the caller
//! decide.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    /// Plan accepted but not yet verified (signature, schema, version,
    /// not_after, revocation, image digest). Initial state.
    Pending,
    /// Verification passed. Resources reserved, image fetched, but
    /// the VM has not been launched yet.
    Verified,
    /// VM start request issued to the backend; awaiting boot.
    Launched,
    /// Guest agent is up; supervisor has dispatched the workload.
    Running,
    /// Workload finishing; teardown in progress (artifact collection,
    /// secret revocation, audit flush).
    Stopping,
    /// Workload finished and supervisor has released every resource.
    /// Terminal.
    Stopped,
    /// Any state can transition to Failed; the `from` field records
    /// the state we left so the audit trail names the failure point.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateTransitionError {
    #[error("transition {from:?} -> {to:?} is not allowed by the plan state machine")]
    Disallowed { from: PlanState, to: PlanState },
}

/// Tracks one workload's lifecycle. The state machine is a thin
/// contract — the transitions are the rule set; the work each
/// transition does (verify image, launch backend, capture artifacts,
/// etc.) lives in `Supervisor::launch` (Wave 1.4) and pulls each
/// component slot in turn.
#[derive(Debug, Clone)]
pub struct PlanStateMachine {
    state: PlanState,
}

impl Default for PlanStateMachine {
    fn default() -> Self {
        Self {
            state: PlanState::Pending,
        }
    }
}

impl PlanStateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current(&self) -> PlanState {
        self.state
    }

    /// Attempt a transition. The allowed transitions are:
    ///
    /// - Pending  → Verified | Failed
    /// - Verified → Launched | Failed
    /// - Launched → Running | Failed
    /// - Running  → Stopping | Failed
    /// - Stopping → Stopped | Failed
    /// - Failed   → (terminal, no further transitions)
    /// - Stopped  → (terminal, no further transitions)
    pub fn transition(&mut self, to: PlanState) -> Result<PlanState, StateTransitionError> {
        let from = self.state;
        let allowed = matches!(
            (from, to),
            (PlanState::Pending, PlanState::Verified)
                | (PlanState::Pending, PlanState::Failed)
                | (PlanState::Verified, PlanState::Launched)
                | (PlanState::Verified, PlanState::Failed)
                | (PlanState::Launched, PlanState::Running)
                | (PlanState::Launched, PlanState::Failed)
                | (PlanState::Running, PlanState::Stopping)
                | (PlanState::Running, PlanState::Failed)
                | (PlanState::Stopping, PlanState::Stopped)
                | (PlanState::Stopping, PlanState::Failed)
        );
        if !allowed {
            return Err(StateTransitionError::Disallowed { from, to });
        }
        self.state = to;
        Ok(to)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, PlanState::Stopped | PlanState::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_walks_every_state() {
        let mut m = PlanStateMachine::new();
        assert_eq!(m.current(), PlanState::Pending);
        m.transition(PlanState::Verified).unwrap();
        m.transition(PlanState::Launched).unwrap();
        m.transition(PlanState::Running).unwrap();
        m.transition(PlanState::Stopping).unwrap();
        m.transition(PlanState::Stopped).unwrap();
        assert!(m.is_terminal());
    }

    #[test]
    fn each_state_can_transition_to_failed() {
        for state in [
            PlanState::Pending,
            PlanState::Verified,
            PlanState::Launched,
            PlanState::Running,
            PlanState::Stopping,
        ] {
            let mut m = PlanStateMachine::new();
            // Walk to `state` first.
            match state {
                PlanState::Pending => {}
                PlanState::Verified => {
                    m.transition(PlanState::Verified).unwrap();
                }
                PlanState::Launched => {
                    m.transition(PlanState::Verified).unwrap();
                    m.transition(PlanState::Launched).unwrap();
                }
                PlanState::Running => {
                    m.transition(PlanState::Verified).unwrap();
                    m.transition(PlanState::Launched).unwrap();
                    m.transition(PlanState::Running).unwrap();
                }
                PlanState::Stopping => {
                    m.transition(PlanState::Verified).unwrap();
                    m.transition(PlanState::Launched).unwrap();
                    m.transition(PlanState::Running).unwrap();
                    m.transition(PlanState::Stopping).unwrap();
                }
                _ => unreachable!(),
            }
            m.transition(PlanState::Failed).unwrap();
            assert!(m.is_terminal());
        }
    }

    #[test]
    fn skipping_states_is_disallowed() {
        let mut m = PlanStateMachine::new();
        // Pending -> Running (skipping Verified + Launched) must fail.
        match m.transition(PlanState::Running) {
            Err(StateTransitionError::Disallowed { from, to }) => {
                assert_eq!(from, PlanState::Pending);
                assert_eq!(to, PlanState::Running);
            }
            other => panic!("expected Disallowed, got {other:?}"),
        }
    }

    #[test]
    fn no_transitions_out_of_terminal_states() {
        let mut m = PlanStateMachine::new();
        m.transition(PlanState::Verified).unwrap();
        m.transition(PlanState::Launched).unwrap();
        m.transition(PlanState::Running).unwrap();
        m.transition(PlanState::Stopping).unwrap();
        m.transition(PlanState::Stopped).unwrap();
        // Stopped -> anything must fail.
        assert!(m.transition(PlanState::Running).is_err());
        assert!(m.transition(PlanState::Failed).is_err());

        let mut m2 = PlanStateMachine::new();
        m2.transition(PlanState::Failed).unwrap();
        // Failed -> anything must fail.
        assert!(m2.transition(PlanState::Verified).is_err());
        assert!(m2.transition(PlanState::Stopped).is_err());
    }

    #[test]
    fn backwards_transitions_disallowed() {
        let mut m = PlanStateMachine::new();
        m.transition(PlanState::Verified).unwrap();
        m.transition(PlanState::Launched).unwrap();
        m.transition(PlanState::Running).unwrap();
        // Running -> Verified is not allowed.
        assert!(m.transition(PlanState::Verified).is_err());
    }
}
