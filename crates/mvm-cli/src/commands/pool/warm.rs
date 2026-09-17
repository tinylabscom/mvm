//! Result type for warm-pool replenishment.

/// Summary returned by [`super::warm_to_target`].
#[derive(Debug, PartialEq, Eq)]
pub struct WarmResult {
    /// Standbys newly spawned and recorded in this call.
    pub spawned: u32,
    /// Spawn attempts that failed (each was logged as a warning).
    pub failed: u32,
    /// Human-readable failure chains, one for each failed attempt.
    ///
    /// Pool warming is best-effort across attempts, so failures cannot be
    /// returned immediately. Keep their full context for the command boundary
    /// instead of requiring a tracing subscriber to explain why the target was
    /// not reached.
    pub failures: Vec<String>,
}
