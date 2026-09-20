//! Tracing subscriber assembly for mvm's host-side binaries.
//!
//! `mvm-core` owns the span-timing *registry* (the counters, histograms and
//! Prometheus rendering) because `MetricsSnapshot` and friends are part of the
//! agent wire protocol. What lives here is the half that needs
//! `tracing-subscriber`: installing a global subscriber and the `Layer` that
//! feeds that registry.
//!
//! The split is deliberate. Installing a subscriber is process-global state
//! that only a binary should do, and `tracing-subscriber` pulls ~32 crates.
//! Holding it here rather than in the foundation crate keeps it out of the
//! sealed guest agent and the embedded musl host binaries, which emit through
//! the `tracing` facade and never install a subscriber.

mod exit;
pub mod logging;
pub mod otlp;
pub mod span_timing_layer;

pub use exit::{INTERRUPT_FLUSH_BOUND, exit, exit_after_interrupt};
pub use logging::{DEFAULT_FILTER, LogFormat, ObservabilityConfig, ObservabilityGuard, init};
pub use otlp::OtlpLayer;
pub use span_timing_layer::SpanTimingLayer;
