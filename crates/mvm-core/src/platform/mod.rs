//! Host platform detection (macOS / Linux / WSL2 / KVM availability).

pub mod linux_env;
#[allow(clippy::module_inception)]
pub mod platform;

pub use self::platform::{LIBKRUN_LIB_PATHS, Platform, current};
