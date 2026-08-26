//! Attestation surface.
//!
//! Three layers:
//!
//! - [`identity`] — Ed25519 identity-key lifecycle (`load_or_init_at`,
//!   refuse-on-loose-perms; mirrors the host signer pattern).
//! - [`header`]   — `AttestationBody` + `AttestationReport`,
//!   `sign_report` / `verify_report`.
//! - [`provider`] — feature-gated TPM2 / SEV-SNP / TDX stubs behind a
//!   `HwAttestationProvider` trait. Real hardware bring-up is not yet
//!   sequenced.
//!
//! Re-exports below collapse the module path so callers can write
//! `use crate::crypto::attestation::{IdentityKey, sign_report, ...}`.
//!
//! The CLI surface (`mvmctl attest export`, `mvmctl attest verify`)
//! lives in `mvm-cli`; this crate carries only the library primitives
//! and unit tests.

pub mod error;
pub mod header;
pub mod identity;
pub mod provider;
#[cfg(all(target_os = "linux", feature = "attestation-tpm2"))]
pub mod tpm2;

pub use error::AttestationError;
pub use header::{
    AttestationBody, AttestationReport, NONCE_BYTES, SCHEMA_VERSION, sign_report, verify_report,
};
pub use identity::{
    IdentityKey, KEY_BYTES, PUBLIC_FILENAME, PUBLIC_MODE, SECRET_FILENAME, SECRET_MODE,
    default_identity_dir, identity_signer_id, load_or_init, load_or_init_at,
};
pub use provider::{HwAttestationProvider, HwMeasurement, HwProviderKind};
