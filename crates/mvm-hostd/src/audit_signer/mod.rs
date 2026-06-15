//! `mvm-audit-signer` — audit chain-signer subprocess.
//!
//! Sole writer to `~/.mvm/audit/<tenant>.jsonl`. Sole holder of the
//! audit chain-signing key. The supervisor delegates **every** audit
//! append to this subprocess over a per-VM UDS — the chain-signing
//! key never enters the supervisor's, the broker's, the
//! secrets-dispatcher's, or the host-signer's address space.
//!
//! Append pipeline:
//!
//! 1. Supervisor sends typed [`AppendEntryRequest::AppendEntry`].
//! 2. This subprocess [`canonical::canonicalize`]s the entry bytes
//!    via JCS (RFC 8785).
//! 3. Computes the new entry hash as `SHA256(prev_hash || canonical)`,
//!    signs it with the chain key, writes the
//!    `{canonical, sig, prev_hash, sig_alg}` line to the JSONL via the
//!    `O_APPEND`-only FD.
//! 4. Fsyncs. On `fsync` failure → [`AuditSignerErrorCode::FsyncFailed`]
//!    (supervisor must pause the workload).
//! 5. Updates the in-memory chain head + persists it to the secondary
//!    location. On secondary-mismatch detect →
//!    [`AuditSignerErrorCode::ChainDriftDetected`].
//! 6. Returns the new `chain_head` so the supervisor can record it
//!    against its own correlation table.
//!
//! What does NOT live here:
//! - Cosign verification of the binary at spawn (supervisor)
//! - TOCTOU-resistant verify-then-exec (supervisor)
//! - Subprocess config-envelope signature verification (the verify runs
//!   before [`config::parse`] accepts an envelope)
//! - Seccomp + setpriv + resource caps (supervisor)
//! - Per-workload cgroup + namespace (supervisor)
//! - Dir-immutable flag (`chattr +a` / `UF_APPEND`) on the audit dir
//!   (supervisor sets at dir creation)
//! - Per-tenant ChaCha20-Poly1305 encryption-at-rest (with a
//!   TPM/SE-derived master)
//! - Per-category schema validation against an allow-list (the freeform
//!   `fields: serde_json::Value` ships today; the per-category schema
//!   registry lands when the supervisor's `EventCategory` enum is wired in)

pub mod canonical;
pub mod category;
pub mod chain;
pub mod config;
pub mod server;
pub mod verify;
