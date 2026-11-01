//! Shared utility helpers, including explicit filesystem resource ownership.

pub mod atomic_io;
pub mod curl;
pub mod glob;
pub mod idle_metrics;
pub mod retry;
#[cfg(any(test, feature = "test-support"))]
pub mod test_env;
pub mod time;
#[allow(clippy::module_inception)]
pub mod util;
#[cfg(unix)]
pub mod writable_image;

// Flatten util.rs contents up to `mvm_core::util::*` (e.g. `parse_human_size`).
pub use self::util::*;
