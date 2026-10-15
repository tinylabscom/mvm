//! Compatibility facade — the decorator parser now lives in `mvm-compiler`.
//!
//! All types and parsers are re-exported unchanged so existing
//! `mvm_sdk::decorator` paths keep working.

pub use mvm_compiler::decorator::python;
pub use mvm_compiler::decorator::typescript;
pub use mvm_compiler::decorator::value;
pub use mvm_compiler::decorator::*;
