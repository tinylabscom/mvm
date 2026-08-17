//! One-shot constructors for `mvm_ir` variants. Unlike the
//! [`crate::builder`] module, these don't track state — they're thin
//! wrappers that pre-fill IR struct/variant fields with sensible
//! defaults so the prelude stays readable at the call site.

pub mod addon;
pub mod concurrency;
pub mod deps;
pub mod entrypoint;
pub mod image;
pub mod network;
pub mod resources;
pub mod source;
