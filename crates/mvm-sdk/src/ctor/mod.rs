//! One-shot constructors for `mvm_ir` variants. Unlike the
//! [`crate::builder`] module, these don't track state — they're thin
//! wrappers that pre-fill IR struct/variant fields with sensible
//! defaults so the prelude stays readable at the call site.

pub(crate) mod addon;
pub(crate) mod concurrency;
pub(crate) mod deps;
pub(crate) mod entrypoint;
pub(crate) mod image;
pub(crate) mod network;
pub(crate) mod resources;
pub(crate) mod source;
