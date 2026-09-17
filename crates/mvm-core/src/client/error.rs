//! The facade's error type. Deliberately transport-agnostic: a `LocalBackend`
//! and a `GatewayBackend` surface the same variants so callers branch on the
//! failure, not on which backend produced it.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, MvmError>;

#[derive(Debug, Clone, Error)]
pub enum MvmError {
    #[error("machine not found: {id}")]
    NotFound { id: String },
    #[error("invalid machine spec: {reason}")]
    InvalidSpec { reason: String },
    #[error("backend error: {reason}")]
    Backend { reason: String },
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },
    #[error("conflict: {reason}")]
    Conflict { reason: String },
    #[error("request rejected: {reason}")]
    Rejected { reason: String },
    #[error("service unavailable: {reason}")]
    Unavailable { reason: String },
}

impl MvmError {
    /// A stable, machine-readable identifier for this variant. Every surface
    /// that reports an `MvmError` to a programmatic caller (currently the MCP
    /// tool server's `_meta`) derives its error code from here, so the
    /// mapping has exactly one source of truth instead of drifting copies.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "NOT_FOUND",
            Self::InvalidSpec { .. } => "INVALID_SPEC",
            Self::Backend { .. } => "BACKEND_ERROR",
            Self::Unauthorized { .. } => "UNAUTHORIZED",
            Self::Conflict { .. } => "CONFLICT",
            Self::Rejected { .. } => "REJECTED",
            Self::Unavailable { .. } => "UNAVAILABLE",
        }
    }

    /// Whether a caller may reasonably retry the exact same request and
    /// expect a different outcome. Only `Unavailable` describes a transient
    /// backend condition; every other variant is a property of the request
    /// itself and retrying it unchanged would fail the same way.
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_displays_the_id() {
        let e = MvmError::NotFound { id: "m1".into() };
        assert_eq!(e.to_string(), "machine not found: m1");
    }

    #[test]
    fn only_unavailable_is_retryable() {
        let all = [
            MvmError::NotFound { id: "m1".into() },
            MvmError::InvalidSpec { reason: "r".into() },
            MvmError::Backend { reason: "r".into() },
            MvmError::Unauthorized { reason: "r".into() },
            MvmError::Conflict { reason: "r".into() },
            MvmError::Rejected { reason: "r".into() },
            MvmError::Unavailable { reason: "r".into() },
        ];
        for error in &all {
            let expected_retryable = matches!(error, MvmError::Unavailable { .. });
            assert_eq!(
                error.retryable(),
                expected_retryable,
                "{error:?} retryable mismatch"
            );
        }
    }

    #[test]
    fn every_variant_has_the_documented_stable_code() {
        assert_eq!(MvmError::NotFound { id: "m1".into() }.code(), "NOT_FOUND");
        assert_eq!(
            MvmError::InvalidSpec { reason: "r".into() }.code(),
            "INVALID_SPEC"
        );
        assert_eq!(
            MvmError::Backend { reason: "r".into() }.code(),
            "BACKEND_ERROR"
        );
        assert_eq!(
            MvmError::Unauthorized { reason: "r".into() }.code(),
            "UNAUTHORIZED"
        );
        assert_eq!(MvmError::Conflict { reason: "r".into() }.code(), "CONFLICT");
        assert_eq!(MvmError::Rejected { reason: "r".into() }.code(), "REJECTED");
        assert_eq!(
            MvmError::Unavailable { reason: "r".into() }.code(),
            "UNAVAILABLE"
        );
    }
}
