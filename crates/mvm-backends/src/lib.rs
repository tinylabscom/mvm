//! Concrete VMM backend implementations.
//!
//! Each backend implements the backend-agnostic [`mvm_vmm::driver::VmmDriver`]
//! seam. Orchestration lives in `mvm-runtime`; this crate owns only VMM
//! mechanics.
//!
//! The drivers are Unix-only: each one reaches its VMM through Unix sockets,
//! file descriptors, and vsock. On any other host only [`run_sidecars`] is
//! built.

#[cfg(unix)]
pub mod driver;
#[cfg(unix)]
pub mod fc;

#[cfg(unix)]
pub mod mock;
/// Clearing one run's leftover sidecars before the next boot.
pub mod run_sidecars;
