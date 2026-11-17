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

/// Validate an existing managed directory without creating or repairing it.
pub fn validate_directory(state_dir: &Path, expected: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(state_dir == expected, "supervisor state directory mismatch");
    let metadata = std::fs::symlink_metadata(state_dir)?;
    anyhow::ensure!(
        metadata.is_dir(),
        "supervisor state must be a real directory"
    );
    mvm_core::private_fs::require_current_owner(&metadata)?;
    anyhow::ensure!(
        mvm_core::private_fs::mode_bits(state_dir, &metadata)? == 0o700,
        "supervisor state must have private mode 0700"
    );
    anyhow::ensure!(
        state_dir.canonicalize()? == state_dir,
        "supervisor state must not contain symlinks"
    );
    Ok(())
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

/// Borrow the startup error for bounded diagnostics without releasing its custody.
pub fn summary(error: &anyhow::Error) -> String {
    sanitize(&format!("{error:#}"), &mvm_core::config::mvm_home())
}

/// Record `error` for the launcher. Best effort: a supervisor that is already
/// failing has no better place to report a failure to write.
pub fn record(state_dir: &Path, error: &anyhow::Error) {
    let text = summary(error);
    // The managed ancestors are trusted to remain stable during startup.
    // Do not recreate a directory removed after recorder validation.
    let _ = mvm_core::util::atomic_io::write_private(&failure_path(state_dir), text.as_bytes());
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

    #[cfg(unix)]
    #[test]
    fn startup_diagnostics_require_an_existing_private_canonical_directory() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let state = root.path().canonicalize().unwrap().join("vm");
        assert!(validate_directory(&state, &state).is_err());
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        validate_directory(&state, &state).unwrap();
        assert!(validate_directory(&state, &state.with_file_name("other")).is_err());
        let link = state.with_file_name("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        assert!(validate_directory(&link, &link).is_err());
        let child = state.join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_directory(&link.join("child"), &link.join("child")).is_err());
        let file = state.join("not-a-directory");
        std::fs::write(&file, b"unchanged").unwrap();
        assert!(validate_directory(&file, &file).is_err());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_directory(&state, &state).is_err());
        assert!(!failure_path(&state).exists());
    }

    #[test]
    fn failure_recording_never_recreates_a_removed_namespace() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("removed");
        record(&state, &anyhow::anyhow!("startup failed"));
        assert!(!state.exists());
    }

    #[test]
    fn borrowed_failure_summary_preserves_context_without_consuming_error() {
        let error = anyhow::anyhow!("bind\nfailed").context("verify\tboot inputs");
        assert_eq!(summary(&error), "verify boot inputs: bind failed");
        assert_eq!(error.root_cause().to_string(), "bind\nfailed");
        let long = anyhow::anyhow!("é".repeat(MAX_BYTES));
        assert!(summary(&long).len() <= MAX_BYTES);
    }

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
