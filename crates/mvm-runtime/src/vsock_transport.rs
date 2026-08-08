//! Backend-agnostic vsock connect dispatch re-exported from `mvm-vmm`.
//!
//! The implementation now lives in `mvm-vmm::vsock_transport`; `mvm-runtime`
//! re-exports the public surface at the old path until downstream callers are
//! migrated.

pub use mvm_vmm::vsock_transport::*;
