//! Guest-wide filesystem flush used by every forced-shutdown path.

/// Schedule every dirty filesystem page for writeback before the host tears
/// down the VM.
///
/// Linux `sync(2)` has no error return. The non-Linux stub keeps host-side
/// workspace builds portable; this code runs for real only inside Linux guests.
#[cfg(target_os = "linux")]
pub fn flush_filesystems() {
    // SAFETY: `sync` takes no arguments, returns nothing, and has no failure
    // mode to inspect.
    unsafe { libc::sync() };
}

#[cfg(not(target_os = "linux"))]
pub fn flush_filesystems() {}
