//! Supervisor-side UDS proxy clients for the three broker subprocesses
//! (Plan 104 W1b.2a; Plan 104 §"Host-side: three-subprocess architecture"
//! and ADR-061 / ADR-062).
//!
//! Per the supersession in ADR-061, the supervisor no longer holds
//! handler logic, the host signer key, or the audit chain-signing key.
//! All three responsibilities live in their own subprocesses; the
//! supervisor's job is to route requests over per-VM UDS to the right
//! subprocess. This module is the client-side library that does the
//! routing.
//!
//! Subprocess → proxy mapping:
//!
//! | Subprocess | Proxy module | Wire protocol |
//! | --- | --- | --- |
//! | `mvm-broker` | [`broker_proxy`] | `mvm_core::protocol::broker::ServiceCall` |
//! | `mvm-host-signer` | [`host_signer_proxy`] | `mvm_core::protocol::host_signer::SignRequest` |
//! | `mvm-audit-signer` | [`audit_signer_proxy`] | `mvm_core::protocol::audit_signer::AppendEntryRequest` |
//!
//! Each proxy opens a fresh UDS connection per call. This is the W1b.2a
//! baseline — single in-flight call per proxy struct, no connection
//! pooling, no retry. W1b.2b's lifecycle pipeline adds: pooled
//! connections, exponential-backoff retry on subprocess restart, and
//! per-spawn ephemeral response signature verification (Plan 104
//! §H-L4.2) at this seam.
//!
//! What W1b.2a does NOT do (deferred to W1b.2b or later):
//! - Verify the subprocess's per-spawn ephemeral response signature
//!   (§H-L4.2 — the response envelopes already carry the seam: each
//!   proxy returns the raw `ServiceResponse` / `SignResponse` /
//!   `AppendEntryResponse`; W1b.2b wraps with signature verification)
//! - Connection pooling, retry policy, circuit breaker (§S13)
//! - Subprocess spawn / supervise / parent-death wiring (§H-L1,
//!   §H-L3.1, §H-L3.2 — the lifecycle pipeline)
//! - Cosign verify the subprocess binary at spawn (§H-L3.1)
//! - Sign the config envelope before writing to subprocess stdin
//!   (§H-L3.6)
//! - Quota / rate-limit / circuit-breaker at this seam (§S6 / §S12 /
//!   §S13 — handled by the supervisor's existing rate-limit modules
//!   when they call into these proxies)

pub mod audit_signer_proxy;
// Plan 104 W1b.2b.2 — pre-spawn binary integrity check
// (§H-L3.1 cosign-style verify). TOCTOU close (§H-L3.2) via
// fexecve is the deferred follow-on; the seam is documented at
// the spawn call site.
pub mod binary_integrity;
pub mod broker_proxy;
// Plan 104 W1b.2b.3 — supervisor-side config envelope signer
// (§H-L3.6 / G1). Wraps SubprocessConfig bytes before stdin write.
// ProcessSpawner integration + subprocess parse_signed adoption +
// no-backcompat removal of unsigned `config::parse` paths land in
// W1b.2b.3.5 (or W1b.2b.5 — TBD).
pub mod config_signer;
pub mod frame;
pub mod host_signer_proxy;
// Plan 104 W1b.2b.1 — subprocess spawn lifecycle: SubprocessSpawner +
// ProcessSpawner + RestartSupervisor + UDS-connect readiness probe.
// W1b.2b.2 wraps the spawn site with cosign verify (§H-L3.1) +
// TOCTOU-resistant exec (§H-L3.2). W1b.2b.3 wraps with signed config
// envelope (§H-L3.6). W1b.2b.4 wraps with per-spawn response signing
// (§H-L4.2).
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
