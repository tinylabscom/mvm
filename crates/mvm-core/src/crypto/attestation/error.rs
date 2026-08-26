//! Error type for the attestation surface.
//!
//! Kept in its own module so the header + provider stubs can share
//! it without a circular dep, and so the CLI / supervisor can match
//! on variants by name rather than text.

use crate::crypto::attestation::provider::HwProviderKind;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The selected hardware provider is wired in (feature enabled)
    /// but its bring-up has not landed yet. v0 stubs return this
    /// from `measure()` for every provider.
    #[error("attestation provider {0:?} is wired but not yet implemented")]
    NotYetImplemented(HwProviderKind),

    /// The supervisor was asked to honor a hardware attestation
    /// mode but the binary was compiled without the corresponding
    /// feature flag.
    #[error(
        "attestation mode {kind:?} not compiled in (rebuild with `--features {feature}` to enable)"
    )]
    ProviderNotCompiled {
        kind: HwProviderKind,
        feature: &'static str,
    },

    /// A report failed signature verification (bad sig, missing
    /// pubkey, or canonical-bytes mismatch).
    #[error("attestation signature failed: {0}")]
    SignatureInvalid(String),

    /// The signer_id in a report does not match any trusted key.
    #[error("no trusted attestation key matched signer_id `{0}`")]
    UnknownSigner(String),

    /// Report parse / decode failure (malformed JSON, bad hex,
    /// schema mismatch).
    #[error("attestation report parse failed: {0}")]
    Parse(String),

    /// Report schema_version newer than this build supports.
    #[error("attestation schema_version {found} > supported {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },

    /// A hardware attestation provider failed to produce a measurement.
    /// Carries a provider-specific error message; the caller should treat
    /// this as a transient or environmental failure (no TPM, TPM in failure
    /// mode, permission denied, etc.).
    #[error("attestation measurement failed for {provider:?}: {message}")]
    MeasurementFailed {
        provider: HwProviderKind,
        message: String,
    },
}
