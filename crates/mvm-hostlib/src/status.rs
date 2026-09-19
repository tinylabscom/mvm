//! The status codes `mvm_hostlib_call` returns, and the error body written
//! beside a non-zero one.
//!
//! Codes 1 to 7 mirror [`MvmError`] one to one, so a binding branches on the
//! same failures a Rust caller of the client does. The rest are failures of
//! the call itself rather than of the operation it asked for.

use mvm_core::client::MvmError;

/// The call succeeded; the reply is the method's typed response JSON.
pub const MVM_HOSTLIB_OK: i32 = 0;
/// The machine the request named does not exist.
pub const MVM_HOSTLIB_NOT_FOUND: i32 = 1;
/// The request described a machine the backend cannot build.
pub const MVM_HOSTLIB_INVALID_SPEC: i32 = 2;
/// The backend failed while carrying the request out.
pub const MVM_HOSTLIB_BACKEND: i32 = 3;
/// The caller is not allowed to do this.
pub const MVM_HOSTLIB_UNAUTHORIZED: i32 = 4;
/// The request conflicts with the machine's current state.
pub const MVM_HOSTLIB_CONFLICT: i32 = 5;
/// A policy refused the request.
pub const MVM_HOSTLIB_REJECTED: i32 = 6;
/// The backend cannot answer right now. The only retryable status.
pub const MVM_HOSTLIB_UNAVAILABLE: i32 = 7;
/// The method is unknown, is not UTF-8, or its request did not parse.
pub const MVM_HOSTLIB_INVALID_INPUT: i32 = 8;
/// `mvm_hostlib_call` ran before the binding confirmed, through
/// `mvm_hostlib_abi_is_compatible`, that it was built for this ABI.
pub const MVM_HOSTLIB_ABI_NOT_NEGOTIATED: i32 = 9;
/// The library could not set itself up in the host process: it could not find
/// its own directory, or a different helper directory was already declared.
pub const MVM_HOSTLIB_EMBEDDER: i32 = 10;
/// A fault in the library itself: a panic, a runtime that would not start, or
/// a reply that would not encode.
pub const MVM_HOSTLIB_INTERNAL: i32 = 11;

/// A status and the bytes written to the caller's buffer with it.
#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) status: i32,
    pub(crate) body: Vec<u8>,
}

impl Outcome {
    /// A success carrying `value` as JSON.
    pub(crate) fn ok<T: serde::Serialize>(value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self {
                status: MVM_HOSTLIB_OK,
                body,
            },
            Err(e) => Self::failure(
                MVM_HOSTLIB_INTERNAL,
                mvm_core::error_codes::INTERNAL,
                &format!("reply did not encode: {e}"),
                false,
            ),
        }
    }

    /// A failure of the call itself, with a code that is not an [`MvmError`].
    pub(crate) fn failure(status: i32, code: &str, message: &str, retryable: bool) -> Self {
        Self {
            status,
            body: error_body(code, message, retryable),
        }
    }

    /// The request could not be understood.
    pub(crate) fn invalid_input(message: &str) -> Self {
        Self::failure(
            MVM_HOSTLIB_INVALID_INPUT,
            mvm_core::error_codes::INVALID_INPUT,
            message,
            false,
        )
    }
}

impl From<MvmError> for Outcome {
    fn from(error: MvmError) -> Self {
        Self {
            status: status_of(&error),
            body: error_body(error.code(), &error.to_string(), error.retryable()),
        }
    }
}

/// The status for an [`MvmError`].
pub(crate) fn status_of(error: &MvmError) -> i32 {
    match error {
        MvmError::NotFound { .. } => MVM_HOSTLIB_NOT_FOUND,
        MvmError::InvalidSpec { .. } => MVM_HOSTLIB_INVALID_SPEC,
        MvmError::Backend { .. } => MVM_HOSTLIB_BACKEND,
        MvmError::Unauthorized { .. } => MVM_HOSTLIB_UNAUTHORIZED,
        MvmError::Conflict { .. } => MVM_HOSTLIB_CONFLICT,
        MvmError::Rejected { .. } => MVM_HOSTLIB_REJECTED,
        MvmError::Unavailable { .. } => MVM_HOSTLIB_UNAVAILABLE,
    }
}

/// `{"code": ..., "message": ..., "retryable": ...}`. `code` is the same
/// symbol [`MvmError::code`] gives every other programmatic surface.
fn error_body(code: &str, message: &str, retryable: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "code": code,
        "message": message,
        "retryable": retryable,
    }))
    .unwrap_or_else(|_| {
        br#"{"code":"INTERNAL","message":"error did not encode","retryable":false}"#.to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_error() -> [MvmError; 7] {
        [
            MvmError::NotFound { id: "m".into() },
            MvmError::InvalidSpec { reason: "r".into() },
            MvmError::Backend { reason: "r".into() },
            MvmError::Unauthorized { reason: "r".into() },
            MvmError::Conflict { reason: "r".into() },
            MvmError::Rejected { reason: "r".into() },
            MvmError::Unavailable { reason: "r".into() },
        ]
    }

    /// Each client error has its own status, none of them success, and none
    /// shared with a failure of the call itself.
    #[test]
    fn every_client_error_has_its_own_status() {
        let statuses: std::collections::BTreeSet<i32> =
            every_error().iter().map(status_of).collect();
        assert_eq!(statuses.len(), 7);
        for status in [
            MVM_HOSTLIB_OK,
            MVM_HOSTLIB_INVALID_INPUT,
            MVM_HOSTLIB_ABI_NOT_NEGOTIATED,
            MVM_HOSTLIB_EMBEDDER,
            MVM_HOSTLIB_INTERNAL,
        ] {
            assert!(!statuses.contains(&status), "{status} is shared");
        }
    }

    /// The body carries the client's own code and retryability, so a binding
    /// needs no table of its own to know which failures to retry.
    #[test]
    fn an_error_body_carries_the_client_code_and_retryability() {
        for error in every_error() {
            let outcome = Outcome::from(error.clone());
            let body: serde_json::Value = serde_json::from_slice(&outcome.body).unwrap();
            assert_eq!(body["code"], error.code());
            assert_eq!(body["message"], error.to_string());
            assert_eq!(body["retryable"], error.retryable());
        }
    }
}
