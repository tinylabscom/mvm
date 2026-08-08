//! Concrete VMM backend implementations.
//!
//! Each backend implements the backend-agnostic [`mvm_vmm::driver::VmmDriver`]
//! seam. Orchestration lives in `mvm-runtime`; this crate owns only VMM
//! mechanics.

pub mod driver;
pub mod legacy;

pub mod mock;
