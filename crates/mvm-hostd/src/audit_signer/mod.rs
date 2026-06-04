//! `mvm-audit-signer` — audit chain-signer subprocess (Plan 104 §H-L1.2,
//! ADR-061).
//!
//! Sole writer to `~/.mvm/audit/<tenant>.jsonl`. Sole holder of the
//! audit chain-signing key. The supervisor delegates **every** audit
//! append to this subprocess over a per-VM UDS — the chain-signing
//! key never enters the supervisor's, the broker's, the
//! secrets-dispatcher's, or the host-signer's address space (Plan 104
//! §H-L1.2 + §H-L5.1).
//!
//! Append pipeline:
//!
//! 1. Supervisor sends typed [`AppendEntryRequest::AppendEntry`].
//! 2. This subprocess [`canonical::canonicalize`]s the entry bytes
//!    via JCS (RFC 8785, Plan 104 §S28).
//! 3. Computes the new entry hash as `SHA256(prev_hash || canonical)`,
//!    signs it with the chain key, writes the
//!    `{canonical, sig, prev_hash, sig_alg}` line to the JSONL via the
//!    `O_APPEND`-only FD (Plan 104 §H-L5.1).
//! 4. Fsyncs. On `fsync` failure → [`AuditSignerErrorCode::FsyncFailed`]
//!    (Plan 104 §H-L6.6 — supervisor must pause the workload).
//! 5. Updates the in-memory chain head + persists it to the secondary
//!    location (Plan 104 §H-L5.2). On secondary-mismatch detect →
//!    [`AuditSignerErrorCode::ChainDriftDetected`].
//! 6. Returns the new `chain_head` so the supervisor can record it
//!    against its own correlation table.
//!
//! What does NOT live here (lands in W1b.2 / W8 unless noted):
//! - Cosign verification of the binary at spawn (§H-L3.1, supervisor)
//! - TOCTOU-resistant verify-then-exec (§H-L3.2, supervisor)
//! - Subprocess config-envelope signature verification (§H-L3.6;
//!   W1b.2 wires the verify before [`config::parse`] accepts an envelope)
//! - Seccomp + setpriv + resource caps (§H-L3.3 / §H-L3.9, supervisor)
//! - Per-workload cgroup + namespace (§H-L1.4, supervisor)
//! - Dir-immutable flag (`chattr +a` / `UF_APPEND`) on the audit dir
//!   (supervisor sets at dir creation; W1b.2)
//! - Per-tenant ChaCha20-Poly1305 encryption-at-rest (§H-L5.4; W8 +
//!   TPM/SE-derived master)
//! - Per-category schema validation against an allow-list (W1b.1 ships
//!   the freeform `fields: serde_json::Value`; the per-category schema
//!   registry lands when the supervisor's `EventCategory` enum is
//!   wired in W1b.2)

pub mod canonical;
pub mod category;
pub mod chain;
pub mod config;
pub mod server;
