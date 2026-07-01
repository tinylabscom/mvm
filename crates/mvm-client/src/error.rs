//! The facade's error type. Deliberately transport-agnostic: a `LocalBackend`
//! and a `GatewayBackend` surface the same variants so callers branch on the
//! failure, not on which backend produced it.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, MvmError>;

#[derive(Debug, Error)]
pub enum MvmError {
    #[error("machine not found: {id}")]
    NotFound { id: String },
    #[error("invalid machine spec: {reason}")]
    InvalidSpec { reason: String },
    #[error("backend error: {reason}")]
    Backend { reason: String },
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_displays_the_id() {
        let e = MvmError::NotFound { id: "m1".into() };
        assert_eq!(e.to_string(), "machine not found: m1");
    }
}
