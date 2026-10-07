//! The per-run record that a human typed a credential into a guest.
//!
//! A credential entered through the display leaves a session cookie or a
//! refresh token in guest memory and on guest disk. Checkpoint and fork copy
//! both, so once a credential has been entered the run may be neither
//! checkpointed nor forked: every child would hold a live human session.
//!
//! Two files in the VM's state directory carry this, both written by the
//! display input gate:
//!
//! - `human-credential-entered` exists from the first credential entry until
//!   the run ends. Its presence is what refuses a capture. Nothing removes it
//!   during the run; [`clear_for_new_run`] removes it when a new plan is
//!   admitted for the VM name.
//! - `display-credential-window` exists while an entry is in progress. The
//!   display frame source drops frames while it is present, so the frames that
//!   show the credential being typed are never recorded. A writer that dies
//!   with the window open leaves recording paused until the window is closed or
//!   the run ends, which errs toward not recording.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use anyhow::{Context, Result};

const ENTERED_FILE: &str = "human-credential-entered";
const WINDOW_FILE: &str = "display-credential-window";

/// Record that a credential entry began on `vm`: mark the run as carrying a
/// human credential and open the recording pause.
///
/// # Errors
/// The VM has no state directory, or either marker could not be written.
pub fn begin_entry(vm: &str) -> Result<()> {
    begin_entry_at(&mvm_core::config::vm_state_dir(vm))
}

/// Close the recording pause that [`begin_entry`] opened. The run stays marked.
///
/// # Errors
/// The window marker exists and could not be removed.
pub fn end_entry(vm: &str) -> Result<()> {
    end_entry_at(&mvm_core::config::vm_state_dir(vm))
}

/// Whether a credential entry is in progress on `vm`.
#[must_use]
pub fn entry_window_open(vm: &str) -> bool {
    entry_window_open_at(&mvm_core::config::vm_state_dir(vm))
}

/// Whether a human credential has been entered during `vm`'s current run.
#[must_use]
pub fn credential_entered(vm: &str) -> bool {
    credential_entered_at(&mvm_core::config::vm_state_dir(vm))
}

/// Refuse to checkpoint or fork `vm` once a human credential has been entered.
///
/// # Errors
/// Always, when the run carries an entered credential.
pub fn refuse_capture_after_entry(vm: &str) -> Result<()> {
    if credential_entered(vm) {
        anyhow::bail!(
            "refusing to checkpoint or fork {vm:?}: a human credential was entered through \
             its display during this run, and a checkpoint or fork would copy the resulting \
             session into every child. Stop the machine to end the run."
        );
    }
    Ok(())
}

/// Remove both markers ahead of a new run under the same VM name.
///
/// # Errors
/// A marker exists and could not be removed.
pub fn clear_for_new_run(state_dir: &Path) -> Result<()> {
    remove_if_present(&state_dir.join(WINDOW_FILE))?;
    remove_if_present(&state_dir.join(ENTERED_FILE))
}

fn begin_entry_at(state_dir: &Path) -> Result<()> {
    if !state_dir.is_dir() {
        anyhow::bail!(
            "no running state at {}; a credential entry needs a live VM",
            state_dir.display()
        );
    }
    write_marker(&state_dir.join(ENTERED_FILE))?;
    write_marker(&state_dir.join(WINDOW_FILE))
}

fn end_entry_at(state_dir: &Path) -> Result<()> {
    remove_if_present(&state_dir.join(WINDOW_FILE))
}

fn entry_window_open_at(state_dir: &Path) -> bool {
    state_dir.join(WINDOW_FILE).exists()
}

fn credential_entered_at(state_dir: &Path) -> bool {
    state_dir.join(ENTERED_FILE).exists()
}

/// Write a marker carrying the time it was set. Mode 0600: the state
/// directory's other files are private to the host user and so are these.
fn write_marker(path: &Path) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    writeln!(file, "{now}").with_context(|| format!("writing {}", path.display()))
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_marks_the_run_and_pauses_recording_until_it_ends() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!credential_entered_at(dir.path()));
        begin_entry_at(dir.path()).unwrap();
        assert!(credential_entered_at(dir.path()));
        assert!(entry_window_open_at(dir.path()));

        end_entry_at(dir.path()).unwrap();
        assert!(!entry_window_open_at(dir.path()));
        assert!(
            credential_entered_at(dir.path()),
            "ending the entry must not unmark the run"
        );
    }

    #[test]
    fn markers_are_private_to_the_host_user() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        begin_entry_at(dir.path()).unwrap();
        for name in [ENTERED_FILE, WINDOW_FILE] {
            let mode = std::fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }

    #[test]
    fn an_entry_needs_a_live_state_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(begin_entry_at(&dir.path().join("gone")).is_err());
    }

    #[test]
    fn a_new_run_starts_unmarked() {
        let dir = tempfile::tempdir().unwrap();
        begin_entry_at(dir.path()).unwrap();
        clear_for_new_run(dir.path()).unwrap();
        assert!(!credential_entered_at(dir.path()));
        assert!(!entry_window_open_at(dir.path()));
        clear_for_new_run(dir.path()).unwrap();
    }
}
