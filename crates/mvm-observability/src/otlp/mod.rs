//! OTLP/HTTP JSON trace export.
//!
//! Opt-in: nothing is installed unless an OTLP endpoint is configured through
//! the standard OpenTelemetry environment variables (see [`config`]). Spans are
//! encoded here and sent with `mvm-http`, which keeps the OpenTelemetry SDK's
//! HTTP and protobuf stack out of the binaries that link this crate.
//!
//! Export is an analysis projection. It is lossy by design — a full queue or an
//! unreachable collector drops spans rather than slowing the program — so it is
//! never the record of what happened; the chain-signed audit log is.

pub mod config;
mod encode;
mod export;
mod layer;
mod record;

pub use config::{ConfigError, OtlpConfig};
pub use export::{ExportGuard, ExportSlot};
pub use layer::OtlpLayer;

/// Start the export thread for `config` and return the layer that feeds it
/// with the guard that flushes it.
///
/// Fails only if the HTTP client cannot be built or the thread cannot be
/// spawned. Hold the guard for as long as spans should be exported.
pub fn spawn_exporter(config: &OtlpConfig) -> std::io::Result<(OtlpLayer, ExportGuard)> {
    let (queue, guard) = export::start(config)?;
    Ok((OtlpLayer::new(queue), guard))
}
