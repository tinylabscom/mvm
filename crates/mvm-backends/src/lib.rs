//! Concrete VMM backend implementations.
//!
//! Each backend implements the backend-agnostic [`mvm_vmm::driver::VmmDriver`]
//! seam. Orchestration lives in `mvm-runtime`; this crate owns only VMM
//! mechanics.

#[cfg(any(test, feature = "test-support"))]
pub mod mock;
