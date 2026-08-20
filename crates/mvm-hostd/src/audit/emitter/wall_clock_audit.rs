//! Wire-stable event name and label keys for wall-clock enforcement entries.
//!
//! Shared so the supervisor that emits an entry and any reader asserting on it
//! cannot drift on a string.

/// Emitted when a supervisor timer killed a workload at its deadline.
pub const EXPIRED_EVENT: &str = "plan.wall_clock_expired";
/// Label: the bound that was enforced, in seconds.
pub const LABEL_BOUND_SECS: &str = "wall_clock_secs";
/// Label: wall-clock seconds actually elapsed when the timer fired.
pub const LABEL_ELAPSED_SECS: &str = "elapsed_secs";
/// Label: which mechanism killed it, so the entry names a fact rather than
/// leaving the reader to infer one.
pub const LABEL_ENFORCED_BY: &str = "enforced_by";
