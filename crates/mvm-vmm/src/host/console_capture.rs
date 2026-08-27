//! Write-only console capture helpers shared by VMM backends.
//!
//! A sealed production guest must never have an interactive console input
//! path. Backends open the host-side log file with write-only, truncate-on-open
//! semantics so the host can read the log but cannot write to the guest console.

use std::io;
use std::path::Path;
use std::process::Stdio;

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

/// File name the per-VM supervisor's stderr is captured to inside a VM state
/// directory.
pub const SUPERVISOR_STDERR_LOG: &str = "supervisor.stderr.log";

/// Stderr for a per-VM supervisor that outlives the process spawning it.
///
/// Never `Stdio::inherit()` on the happy path, and that is the whole point. The
/// supervisor owns its guest for the VM's entire life, so an inherited stderr
/// keeps the *spawning* process's stderr file descriptor open for that entire
/// life. `mvmctl machine start` itself returns in well under a second, but any
/// caller that captures stderr through a pipe and reads to EOF never sees EOF:
/// `Command::output()`, Python's `subprocess.run(capture_output=True)` — which
/// is how the SDK's live transport shells every verb — or any `2>&1 |` pipeline.
/// Redirecting to a file instead makes the same command return immediately,
/// which is why the failure is invisible interactively at a TTY and only bites
/// under automation.
///
/// The fallback to `inherit` covers an unwritable state directory: losing the
/// supervisor's diagnostics entirely would be worse than a caller that hangs,
/// and a state dir that cannot be written is already a failing boot.
pub fn supervisor_stderr(state_dir: &Path) -> Stdio {
    open_console_capture(&state_dir.join(SUPERVISOR_STDERR_LOG))
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::inherit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_stderr_creates_the_log_inside_the_state_dir() {
        let dir = tempfile::tempdir().unwrap();
        let _stdio = supervisor_stderr(dir.path());
        let log = dir.path().join(SUPERVISOR_STDERR_LOG);
        assert!(
            log.is_file(),
            "supervisor stderr must land in a file, not the caller's fd: {} missing",
            log.display()
        );
    }

    #[test]
    fn supervisor_stderr_truncates_a_previous_boots_log() {
        // Each boot's diagnostics stand alone; a stale tail read as this boot's
        // is how a fixed build looks broken.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join(SUPERVISOR_STDERR_LOG);
        std::fs::write(&log, b"previous boot noise").unwrap();
        let _stdio = supervisor_stderr(dir.path());
        assert_eq!(std::fs::read(&log).unwrap(), b"");
    }

    #[test]
    fn supervisor_stderr_falls_back_when_the_state_dir_is_absent() {
        // Must not panic: an unwritable state dir is a failing boot that should
        // report its own error, not abort inside stdio setup.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-state-dir");
        let _stdio = supervisor_stderr(&missing);
    }
}
