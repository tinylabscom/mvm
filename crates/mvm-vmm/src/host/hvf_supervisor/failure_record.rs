//! Why a supervisor's own startup failed, kept where the launcher can read it.
//!
//! The supervisor's raw stderr is discarded on purpose, so a startup that dies
//! on an ordinary error reported only a stage and an exit code. This is not that
//! stderr: it is the error chain the supervisor's own startup code produced,
//! rewritten to one bounded line with control characters and the mvm home
//! removed, and kept in the VM's private state directory.

use std::io::Read;
use std::path::{Path, PathBuf};

/// File name of the record inside a VM's state directory.
pub const FAILURE_FILE: &str = "supervisor-failure.txt";

/// Longest record, in bytes. Longer chains are cut at a character boundary.
const MAX_BYTES: usize = 1024;

pub fn failure_path(state_dir: &Path) -> PathBuf {
    state_dir.join(FAILURE_FILE)
}

fn sanitize(text: &str, home: &str) -> String {
    let flat: String = text
        .replace(home, "<mvm-home>")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut end = flat.len().min(MAX_BYTES);
    while !flat.is_char_boundary(end) {
        end -= 1;
    }
    flat[..end].to_string()
}

/// Record `error` for the launcher. Best effort: a supervisor that is already
/// failing has no better place to report a failure to write.
pub fn record(state_dir: &Path, error: &anyhow::Error) {
    let text = sanitize(&format!("{error:#}"), &mvm_core::config::mvm_home());
    let _ = mvm_core::util::atomic_io::atomic_write(&failure_path(state_dir), text.as_bytes());
}

/// Forget a previous run's record so a new launch cannot report it.
pub fn clear(state_dir: &Path) {
    let _ = std::fs::remove_file(failure_path(state_dir));
}

/// The record as a suffix for a launcher error, or nothing when there is none.
pub fn detail(state_dir: &Path) -> String {
    let Ok(file) = std::fs::File::open(failure_path(state_dir)) else {
        return String::new();
    };
    let mut bytes = Vec::new();
    if file.take(MAX_BYTES as u64).read_to_end(&mut bytes).is_err() || bytes.is_empty() {
        return String::new();
    }
    let home = mvm_core::config::mvm_home();
    format!(
        "; supervisor reported: {}",
        sanitize(&String::from_utf8_lossy(&bytes), &home)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_failure_reaches_the_launcher_flattened_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let error = anyhow::anyhow!("bind\nfailed").context("start\tstop control");
        record(dir.path(), &error);
        assert_eq!(
            detail(dir.path()),
            "; supervisor reported: start stop control: bind failed"
        );

        record(dir.path(), &anyhow::anyhow!("é".repeat(MAX_BYTES)));
        let bounded = detail(dir.path());
        assert!(bounded.len() <= MAX_BYTES + "; supervisor reported: ".len());
        assert!(bounded.ends_with('é'));
    }

    #[test]
    fn the_mvm_home_is_not_repeated_in_the_record() {
        assert_eq!(
            sanitize("open /h/vms/a: denied", "/h"),
            "open <mvm-home>/vms/a: denied"
        );
    }

    #[test]
    fn nothing_recorded_or_a_cleared_record_adds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(detail(dir.path()), "");
        record(dir.path(), &anyhow::anyhow!("boom"));
        clear(dir.path());
        assert_eq!(detail(dir.path()), "");
    }
}
