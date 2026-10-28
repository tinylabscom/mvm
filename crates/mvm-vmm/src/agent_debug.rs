//! The opt-in agent-path trace selected by `MVM_HVF_AGENT_DEBUG`.
//!
//! The variable names a file every agent bridge, vsock device and host-agent
//! spawn appends one line per event to. Those lines carry socket paths, guest
//! errors and handoff details, so the file is a sensitive diagnostic like any
//! console log: it is created owner-only, a symbolic link or second hard link
//! at the path is refused rather than written through, and nothing is written
//! when the variable is unset. A trace that cannot be opened privately is
//! dropped; the caller never falls back to a looser open.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// The environment variable naming the trace file.
pub const AGENT_DEBUG_ENV: &str = "MVM_HVF_AGENT_DEBUG";

/// The trace file, read from the environment once so the accept and drain
/// paths never take the process-global environment lock per connection.
pub fn path() -> Option<&'static Path> {
    static PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| std::env::var_os(AGENT_DEBUG_ENV).map(PathBuf::from))
        .as_deref()
}

/// Open the trace for appending, or `None` when tracing is off or the file
/// cannot be opened privately.
pub fn open() -> Option<File> {
    open_at(path()?)
}

/// Append `[tag] message` to the trace when tracing is on.
pub fn line(tag: &str, message: impl std::fmt::Display) {
    if let Some(path) = path() {
        line_at(path, tag, message);
    }
}

/// Append `[tag] {fields} elapsed_us=.. unix_us=..` when tracing is on: how long
/// into a step `started` marks the caller is, and the wall clock so a detached
/// helper's lines line up with the launch that spawned it.
pub fn phase(tag: &str, started: Instant, fields: impl std::fmt::Display) {
    if let Some(path) = path() {
        phase_at(path, tag, started, fields);
    }
}

fn phase_at(path: &Path, tag: &str, started: Instant, fields: impl std::fmt::Display) {
    let elapsed_us = started.elapsed().as_micros();
    let unix_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros());
    line_at(
        path,
        tag,
        format_args!("{fields} elapsed_us={elapsed_us} unix_us={unix_us}"),
    );
}

fn open_at(path: &Path) -> Option<File> {
    mvm_core::util::atomic_io::open_private_append(path).ok()
}

fn line_at(path: &Path, tag: &str, message: impl std::fmt::Display) {
    if let Some(mut file) = open_at(path) {
        let _ = writeln!(file, "[{tag}] {message}");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn trace_lines_land_in_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let trace = dir.path().join("agent-debug.log");
        line_at(&trace, "vsock", "SYNTHETIC_MARKER first");
        line_at(&trace, "handoff", "second");
        assert_eq!(mode(&trace), 0o600);
        assert_eq!(
            std::fs::read_to_string(&trace).unwrap(),
            "[vsock] SYNTHETIC_MARKER first\n[handoff] second\n"
        );
    }

    #[test]
    fn a_phase_line_carries_the_step_and_both_clocks() {
        let dir = tempfile::tempdir().unwrap();
        let trace = dir.path().join("agent-debug.log");
        phase_at(&trace, "pool-refill", Instant::now(), "phase=scheduled");
        let written = std::fs::read_to_string(&trace).unwrap();
        assert!(written.starts_with("[pool-refill] phase=scheduled elapsed_us="));
        assert!(written.contains(" unix_us="));
    }

    #[test]
    fn a_link_at_the_trace_path_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let symlinked = dir.path().join("symlinked.log");
        std::os::unix::fs::symlink(&victim, &symlinked).unwrap();
        let hard_linked = dir.path().join("hard-linked.log");
        std::fs::hard_link(&victim, &hard_linked).unwrap();

        line_at(&symlinked, "vsock", "SYNTHETIC_MARKER");
        line_at(&hard_linked, "vsock", "SYNTHETIC_MARKER");

        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(open_at(&symlinked).is_none());
        assert!(open_at(&hard_linked).is_none());
    }

    #[test]
    fn an_unopenable_trace_drops_the_line_instead_of_failing_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        let missing_parent = dir.path().join("absent/agent-debug.log");
        line_at(&missing_parent, "vsock", "SYNTHETIC_MARKER");
        assert!(!missing_parent.exists());
    }
}
