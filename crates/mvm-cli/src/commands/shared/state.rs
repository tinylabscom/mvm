//! Process-wide state used by the signal handler and console mode.

use std::sync::{Arc, Mutex};

/// Global registry of spawned child PIDs so the signal handler can clean them up.
pub static CHILD_PIDS: std::sync::LazyLock<Arc<Mutex<Vec<u32>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(Vec::new())));

/// When true, the Ctrl-C handler does nothing — console mode forwards
/// raw bytes to the guest instead.
pub static IN_CONSOLE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
