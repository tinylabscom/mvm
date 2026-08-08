//! Write-only console capture helpers shared by VMM backends.
//!
//! A sealed production guest must never have an interactive console input
//! path. Backends open the host-side log file with write-only, truncate-on-open
//! semantics so the host can read the log but cannot write to the guest console.

use std::io;
use std::path::Path;

/// Open a write-only, truncated console log file.
///
/// This is the shared primitive used by every concrete backend to capture
/// guest console output without creating an interactive input channel.
pub fn open_console_capture(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}
