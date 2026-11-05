use serde::{Deserialize, Serialize};

/// Primary lifecycle. Disconnected/degraded/reconnecting are [`Conditions`],
/// not states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Pending,
    Active,
    Quarantined,
    Revoked,
}

impl NodeState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
        }
    }

    /// `Revoked` is terminal: a revoked key is re-admitted as a new node.
    pub fn can_transition_to(self, to: Self) -> bool {
        use NodeState::*;
        matches!(
            (self, to),
            (Pending, Active)
                | (Pending, Revoked)
                | (Active, Quarantined)
                | (Active, Revoked)
                | (Quarantined, Active)
                | (Quarantined, Revoked)
        )
    }
}

/// Orthogonal conditions layered on a [`NodeState`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conditions {
    pub disconnected: bool,
    pub degraded: bool,
    pub reconnecting: bool,
}

/// Monotonic per-workload authority generation. A replacement workload gets a
/// strictly greater epoch; anything carrying an older one is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionEpoch(pub u64);

impl ExecutionEpoch {
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
    pub fn is_current(self, current: Self) -> bool {
        self == current
    }
}
