//! Per-VM lifecycle and containment: HVF stop, wall-clock bounds, session expiry, liveness expiry, teardown reaping, and the memory balloon.

pub mod balloon;
pub mod balloon_runtime;
pub mod hvf_stop;
/// The supervisor-side owner of its unit's liveness expiry.
pub mod liveness_expiry;
pub mod reaper;
/// Session idle-timeout enforcement: the shared reap decision and the
/// supervisor-side watcher.
pub mod session_expiry;
/// The supervisor-side wall-clock timer — the mechanism behind
/// `WallClockControl::SupervisorTimer`.
pub mod wall_clock;
