//! `VmmSpec` re-exported from `mvm-vmm`.
//!
//! The backend-agnostic boot recipe lives in `mvm-vmm::driver::spec`;
//! `mvm-runtime` re-exports it at the old path until downstream callers are
//! migrated.

pub use mvm_vmm::driver::spec::*;
