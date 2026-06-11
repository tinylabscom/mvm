//! Supervisor-side UDS proxy clients for the three broker subprocesses.
//!
//! The supervisor no longer holds handler logic, the host signer key, or
//! the audit chain-signing key. All three responsibilities live in their
//! own subprocesses; the supervisor's job is to route requests over per-VM
//! UDS to the right subprocess. This module is the client-side library
//! that does the routing.
//!
//! Subprocess → proxy mapping:
//!
//! | Subprocess | Proxy module | Wire protocol |
//! | --- | --- | --- |
//! | `mvm-broker` | [`broker_proxy`] | `mvm_core::protocol::broker::ServiceCall` |
//! | `mvm-host-signer` | [`host_signer_proxy`] | `mvm_core::protocol::host_signer::SignRequest` |
//! | `mvm-audit-signer` | [`audit_signer_proxy`] | `mvm_core::protocol::audit_signer::AppendEntryRequest` |
//!
//! Each proxy opens a fresh UDS connection per call. This is the
//! baseline — single in-flight call per proxy struct, no connection
//! pooling, no retry. The lifecycle pipeline adds: pooled connections,
//! exponential-backoff retry on subprocess restart, and per-spawn
//! ephemeral response signature verification at this seam.
//!
//! What this baseline does NOT do (deferred):
//! - Verify the subprocess's per-spawn ephemeral response signature
//!   (the response envelopes already carry the seam: each proxy returns
//!   the raw `ServiceResponse` / `SignResponse` / `AppendEntryResponse`,
//!   which the lifecycle pipeline wraps with signature verification)
//! - Connection pooling, retry policy, circuit breaker
//! - Subprocess spawn / supervise / parent-death wiring (the lifecycle
//!   pipeline)
//! - Cosign verify the subprocess binary at spawn
//! - Sign the config envelope before writing to subprocess stdin
//! - Quota / rate-limit / circuit-breaker at this seam (handled by the
//!   supervisor's existing rate-limit modules when they call into these
//!   proxies)

pub mod audit_signer_proxy;
// Pre-spawn binary integrity check (cosign-style verify). The TOCTOU
// close via fexecve is the deferred follow-on; the seam is documented
// at the spawn call site.
pub mod binary_integrity;
pub mod broker_proxy;
// Supervisor-side config envelope signer. Wraps SubprocessConfig bytes
// before stdin write. ProcessSpawner integration, subprocess
// parse_signed adoption, and removal of the unsigned `config::parse`
// paths are still pending.
pub mod config_signer;
pub mod frame;
pub mod host_signer_proxy;
// Subprocess spawn lifecycle: SubprocessSpawner + ProcessSpawner +
// RestartSupervisor + UDS-connect readiness probe. The spawn site is
// later wrapped with cosign verify + TOCTOU-resistant exec, a signed
// config envelope, and per-spawn response signing.
pub mod spawn;

use thiserror::Error;

/// Errors any proxy can return.
///
/// Concrete proxy methods may also surface a typed *subprocess* error
/// (e.g. `ServiceErrorCode::NotBound` from the broker, or
/// `AuditSignerErrorCode::ChainDriftDetected` from the audit-signer);
/// those are returned alongside this enum via a `Result<Response, ProxyError>`
/// where `Response` is the typed wire enum that itself can be `Err`.
/// This split keeps transport failures (connect refused, timeout, frame
/// too big) distinct from protocol-level errors (subprocess responded
/// with a typed `Err` variant).
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Connecting to the UDS path failed. Likely cause: the subprocess
    /// hasn't started yet, or has died.
    #[error("connect to {path} failed: {source}")]
    Connect {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Read / write on the UDS connection failed mid-call.
    #[error("UDS I/O on {path} failed: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The subprocess's response exceeded the frame-size cap. Indicates
    /// either misbehavior or a buffer-overflow attempt.
    #[error("response frame too large from {path}: {size} > {cap}")]
    ResponseTooLarge {
        path: std::path::PathBuf,
        size: usize,
        cap: usize,
    },
    /// The subprocess returned bytes that didn't parse as the expected
    /// response envelope. Treat as a protocol violation; caller should
    /// drop the connection and audit.
    #[error("response envelope parse failed from {path}: {source}")]
    Decode {
        path: std::path::PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// The request envelope itself couldn't be serialised. Should never
    /// happen for well-formed callers — surfaced so callers don't have
    /// to handle a plain `serde_json::Error`.
    #[error("request envelope encode failed: {source}")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
}
