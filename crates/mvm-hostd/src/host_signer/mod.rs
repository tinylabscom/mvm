//! `mvm-host-signer` — host signer subprocess.
//!
//! Sole holder of the host signer key. The supervisor sends typed
//! [`SignRequest`](mvm_core::protocol::host_signer::SignRequest) RPCs
//! over a per-VM UDS; this subprocess responds with the signature +
//! the public key the supervisor should use to verify.
//!
//! Today this is the software in-memory key path. The key is generated
//! at subprocess boot from `OsRng` and held in memory (mlock-pinning is
//! a supervisor-side resource cap; the crate itself stays free of
//! platform-specific syscalls). A later pass swaps the in-memory path
//! for an HW enclave handle (Apple Secure Enclave / Linux TPM 2.0).
//!
//! What does NOT live here yet:
//! - Cosign verification of the binary at spawn (supervisor side)
//! - TOCTOU-resistant verify-then-exec (supervisor side)
//! - Subprocess config-envelope signature verification (this crate; the
//!   verify runs before [`config::parse`] accepts an envelope)
//! - Seccomp + setpriv + resource caps (supervisor side)
//! - Per-workload cgroup + namespace (supervisor side)
//! - Hardware enclave keygen + sign
//! - TPM monotonic counter for rotation rollback resistance

pub mod config;
pub mod keystore;
pub mod server;
