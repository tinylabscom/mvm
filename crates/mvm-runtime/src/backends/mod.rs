//! Concrete VM backend implementations.
//!
//! Each subdirectory implements one selectable backend: the raw hypervisor
//! substrate, the `VmBackend` lifecycle, and the `VmmDriver` boot mechanics.
//! Keeping them together makes the backend boundary obvious and keeps the rest
//! of `mvm-runtime` backend-agnostic.

pub mod hvf;
