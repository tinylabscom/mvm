//! Error types for sigstore-rekor

use thiserror::Error;

/// Errors that can occur in Rekor operations
#[derive(Error, Debug)]
pub enum Error {
    /// HTTP request error
    #[error("HTTP error: {0}")]
    Http(String),

    /// API error
    #[error("API error: {0}")]
    Api(String),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Merkle proof error
    #[error("Merkle proof error: {0}")]
    Merkle(#[from] sigstore_merkle::Error),

    /// Invalid response error
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Base64 decoding error
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// Result type for Rekor operations
pub type Result<T> = std::result::Result<T, Error>;
