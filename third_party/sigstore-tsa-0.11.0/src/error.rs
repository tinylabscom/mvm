//! Error types for sigstore-tsa

use thiserror::Error;

/// Errors that can occur in TSA operations
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(String),

    /// ASN.1 encoding/decoding error
    #[error("ASN.1 error: {0}")]
    Asn1(String),

    /// Timestamp verification error
    #[error("Timestamp verification error: {0}")]
    Verification(String),

    /// Invalid timestamp response
    #[error("Invalid timestamp response: {0}")]
    InvalidResponse(String),

    /// Failed to parse timestamp response
    #[error("Failed to parse timestamp response: {0}")]
    ParseError(String),

    /// Failed to verify timestamp signature
    #[error("Failed to verify timestamp signature: {0}")]
    SignatureVerificationError(String),

    /// Timestamp message hash does not match signature
    #[error("Timestamp message hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    /// Timestamp response indicates failure status
    #[error("Timestamp response indicates failure status")]
    ResponseFailure,

    /// No timestamp token in response
    #[error("No timestamp token in response")]
    NoToken,

    /// No TSTInfo in timestamp token
    #[error("No TSTInfo in timestamp token")]
    NoTstInfo,

    /// Leaf certificate does not have TimeStamping EKU
    #[error("Leaf certificate does not have TimeStamping Extended Key Usage")]
    InvalidEKU,

    /// TSA certificate validation failed
    #[error("TSA certificate validation failed: {0}")]
    CertificateValidationError(String),

    /// Timestamp parsing error
    #[error("Timestamp parsing error: {0}")]
    Parse(String),
}

/// Result type for TSA operations
pub type Result<T> = std::result::Result<T, Error>;
