//! The stable error codes a programmatic caller branches on.
//!
//! One definition, used by every surface that reports an error to code
//! rather than to a person: `MvmError::code`, the MCP tool server, the host
//! library's error bodies, and the error classes generated for the language
//! SDKs. Ungated, so crates that do not enable this crate's `client` feature
//! can name them.

/// The machine named does not exist.
pub const NOT_FOUND: &str = "NOT_FOUND";
/// The request described a machine that cannot be built.
pub const INVALID_SPEC: &str = "INVALID_SPEC";
/// The backend failed while carrying the request out.
pub const BACKEND_ERROR: &str = "BACKEND_ERROR";
/// The caller is not allowed to do this.
pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
/// The request conflicts with the machine's current state.
pub const CONFLICT: &str = "CONFLICT";
/// A policy refused the request.
pub const REJECTED: &str = "REJECTED";
/// The backend cannot answer right now. The only retryable code.
pub const UNAVAILABLE: &str = "UNAVAILABLE";

/// A host-library call whose method is unknown or whose request did not
/// parse.
pub const INVALID_INPUT: &str = "INVALID_INPUT";
/// A host-library call made before the binding confirmed its ABI version.
pub const ABI_NOT_NEGOTIATED: &str = "ABI_NOT_NEGOTIATED";
/// The host library could not set itself up in the process that loaded it.
pub const EMBEDDER: &str = "EMBEDDER";
/// A fault inside the host library itself.
pub const INTERNAL: &str = "INTERNAL";
