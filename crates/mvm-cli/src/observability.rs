//! Tracing subscriber assembly for mvm's host-side binaries.
//!
//! `mvm-core` owns the span-timing *registry* (the counters, histograms and
//! Prometheus rendering) because `MetricsSnapshot` and friends are part of the
//! agent wire protocol. What lives here is the half that needs
//! `tracing-subscriber`: installing a global subscriber and the `Layer` that
//! feeds that registry.
//!
//! Installing a subscriber is process-global state that only a binary should
//! do, so the assembly lives in the CLI crate rather than the foundation
//! crate: `tracing-subscriber` stays out of `mvm-core`'s graph and therefore
//! off the sealed guest agent and the embedded musl host binaries, which emit
//! through the `tracing` facade and never install a subscriber.

// `exit` is the one sanctioned `std::process::exit` caller: the crate-level
// `#![deny(clippy::exit)]` exists to force every early end through it, so the
// wrapper itself carries the allow.
#[allow(clippy::exit)]
mod exit;
pub mod logging;
pub mod otlp;
pub mod span_timing_layer;

pub use exit::{INTERRUPT_FLUSH_BOUND, exit, exit_after_interrupt};
pub use logging::{DEFAULT_FILTER, LogFormat, ObservabilityConfig, ObservabilityGuard, init};
pub use otlp::OtlpLayer;
pub use span_timing_layer::SpanTimingLayer;
