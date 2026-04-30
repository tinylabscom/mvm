//! Pure utility helpers — formatters, retry policy, time, idle metrics.

pub mod atomic_io;
pub mod idle_metrics;
pub mod retry;
pub mod time;
#[allow(clippy::module_inception)]
pub mod util;

// Flatten util.rs contents up to `mvm_core::util::*` (e.g. `parse_human_size`).
pub use self::util::*;
