//! Backend-specific config writers.
//!
//! Each submodule implements `BackendConfigWriter` for one backend.
//! Slice 1 ships Firecracker; QEMU is deferred.

pub mod firecracker;

pub use firecracker::FirecrackerConfigWriter;
