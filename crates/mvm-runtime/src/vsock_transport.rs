//! Backend-agnostic vsock connect dispatch re-exported from `mvm-vmm`.
//!
//! The implementation lives in `mvm-vmm::vsock_transport`; `mvm-runtime`
//! re-exports the public surface at the old path for downstream callers.

pub use mvm_vmm::vsock_transport::*;
