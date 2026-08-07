//! Backend-agnostic vsock connect dispatch re-exported from `mvm-vmm`.
//!
//! During the plan 298 migration the implementation moved to
//! `mvm-vmm::vsock_transport`; `mvm-runtime` re-exports the public surface
//! at the old path until downstream callers are migrated.

pub use mvm_vmm::vsock_transport::*;
