//! Host platform detection (macOS / Linux / WSL2 / KVM availability).

pub mod linux_env;
#[allow(clippy::module_inception)]
pub mod platform;

// Flatten platform.rs contents up to `mvm_core::platform::*` so legacy
// callers (e.g. `mvm_core::platform::current()`) keep working.
pub use self::platform::*;
