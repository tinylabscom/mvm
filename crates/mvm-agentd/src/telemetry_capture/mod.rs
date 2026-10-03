//! Guest-side telemetry capture core.
//!
//! One process-wide [`CaptureState`] holds the producer epoch, the monotonic
//! origin, the shared bounded outbox and per-producer attempt/shed counters;
//! [`CaptureState::emit`] is one non-waiting admission attempt, and
//! [`AgentSubscriber`] is a hand-rolled events-only `tracing` collector over
//! it (the sealed agent deliberately carries no subscriber crate).
//!
//! This is a pure component: nothing here installs the subscriber, spawns a
//! worker, opens a transport, or wakes a consumer — the transport worker owns
//! the draining cadence and dials on its own. Per-producer counters exist
//! because the outbox's own loss evidence is queue-global; starvation between
//! producers sharing the one queue is a measured deficiency of this design,
//! not something this module corrects.

mod emit;
mod state;
mod subscriber;

pub use emit::{EmitOutcome, ShedReason};
pub use state::{CaptureState, LossTally, ProducerId, SourceLosses};
pub use subscriber::AgentSubscriber;
