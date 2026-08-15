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

pub mod logging;
pub mod span_timing_layer;

pub use logging::{DEFAULT_FILTER, LogFormat, init, init_with_filter};
pub use span_timing_layer::SpanTimingLayer;
