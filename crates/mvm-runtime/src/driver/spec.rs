//! `VmmSpec` is re-exported from `mvm-vmm` for compatibility.
//!
//! The backend-agnostic boot recipe now lives in `mvm-vmm::driver::spec`;
//! `mvm-runtime` re-exports it at the old path for downstream callers.

pub use mvm_vmm::driver::spec::*;
