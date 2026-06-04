//! `mvm-host-signer` — host signer subprocess (Plan 104 §H-L1.1, ADR-061).
//!
//! Sole holder of the host signer key. The supervisor sends typed
//! [`SignRequest`](mvm_core::protocol::host_signer::SignRequest) RPCs
//! over a per-VM UDS; this subprocess responds with the signature +
//! the public key the supervisor should use to verify.
//!
//! W1b.1 ships the software in-memory key path. The key is generated
//! at subprocess boot from `OsRng` and held in memory (mlock-pinned in
//! W1b.2 via the supervisor-side resource caps; the crate itself stays
//! free of platform-specific syscalls). W8 swaps the in-memory path
//! for an HW enclave handle (Apple Secure Enclave / Linux TPM 2.0).
//!
//! What does NOT live here (lands in W1b.2 / W8 unless noted):
//! - Cosign verification of the binary at spawn (Plan 104 §H-L3.1,
//!   supervisor side)
//! - TOCTOU-resistant verify-then-exec (§H-L3.2, supervisor side)
//! - Subprocess config-envelope signature verification (§H-L3.6,
//!   this crate; W1b.2 wires the verify before [`config::parse`]
//!   accepts an envelope)
//! - Seccomp + setpriv + resource caps (§H-L3.3 / §H-L3.9, supervisor
//!   side)
//! - Per-workload cgroup + namespace (§H-L1.4, supervisor side)
//! - Hardware enclave keygen + sign (W8)
//! - TPM monotonic counter for rotation rollback resistance
//!   (Plan 104 §H-L2.2; W8)

pub mod config;
pub mod keystore;
pub mod server;
