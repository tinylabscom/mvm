//! Error types surfaced by the builder and emit paths.

/// Errors surfaced when constructing a [`crate::ir::Workload`] or
/// [`crate::ir::App`] via the builders. The builders enforce required-field
/// presence at `.build()` time so the rest of the SDK can take typed
/// values.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("workload requires at least one app (call `.app(...)` before `.build()`)")]
    EmptyWorkload,
    #[error("app `{name}` is missing required field `{field}`")]
    MissingField { name: String, field: &'static str },
}

/// Errors surfaced by [`crate::emit`] / [`crate::emit_json`].
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error("workload validation failed: {0:?}")]
    Validation(Vec<crate::ir::ValidationError>),
    #[error("canonicalization failed: {0}")]
    Canonicalize(serde_json::Error),
    #[error("write to MVM_IR_OUT path `{0}` failed: {1}")]
    Write(String, std::io::Error),
    #[error("write to stdout failed: {0}")]
    Stdout(std::io::Error),
}
