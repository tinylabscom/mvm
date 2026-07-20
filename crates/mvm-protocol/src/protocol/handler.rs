//! Handler dispatch result DTOs.
//!
//! The typed error a handler returns from `dispatch`, and the result
//! alias wrapping it. The dispatch trait itself (`ServiceHandler`) and
//! its call-context type (`ServiceCallCtx`) are runtime shape, not
//! DTOs, and stay in `mvm_core::protocol::handler`.

use alloc::format;
use alloc::string::String;

pub use crate::protocol::broker::ServiceErrorCode;

/// The result a handler returns from `dispatch`.
///
/// `Ok` carries the typed response payload (will be folded into a
/// `ServiceResponse::Ok` envelope by the broker substrate). `Err`
/// carries a typed error code + a message — the message MUST NOT
/// embed payload-derived data (redaction discipline).
pub type ServiceDispatchResult = Result<serde_json::Value, ServiceError>;

/// A typed handler error.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ServiceError {
    pub code: ServiceErrorCode,
    pub message: String,
}

impl ServiceError {
    pub fn new(code: ServiceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Shorthand for the common `NotImplemented` case (used by handlers
    /// shipping partial verb sets, e.g. `host.cost.v1::tenant` before
    /// the cross-VM tenant verb lands).
    pub fn not_implemented(verb: impl AsRef<str>) -> Self {
        Self::new(
            ServiceErrorCode::NotImplemented,
            format!("verb `{}` not implemented in this build", verb.as_ref()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_error_not_implemented_shorthand() {
        let e = ServiceError::not_implemented("tenant");
        assert_eq!(e.code, ServiceErrorCode::NotImplemented);
        assert!(e.message.contains("tenant"));
    }
}
