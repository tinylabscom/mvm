//! Clearing one run's leftover sidecars before the next boot out of the same
//! state directory.
//!
//! The per-run sidecars the process owning a VM writes at teardown — the
//! captured exit code and the captured usage record — outlive the run that
//! produced them, and a state directory is reused across starts. A boot that
//! does not clear them leaves the previous run's numbers where this run's
//! reader will find them, and the reader has no way to tell the difference:
//! both files are written best-effort, so "absent" is a normal outcome and
//! "present" is taken at face value.
//!
//! The gap is reachable rather than theoretical. A machine that ran to
//! completion writes both files; started again and stopped with a signal, the
//! second run writes neither — libkrun's `SIGTERM` handler calls `_exit`,
//! which skips the `atexit` hook that writes them. Without this clear, the
//! second run's exit report would read the first run's CPU and resident size
//! and sign them into a receipt stamped as measured.

use std::path::Path;

/// Remove any prior run's captured exit code and usage record.
///
/// Best-effort, exactly like the writes it undoes: an absent file is the
/// desired end state either way, and a state directory that cannot be written
/// is a failure the boot itself reports far more clearly than a removal would.
pub fn clear_prior_run(state_dir: &Path) {
    let _ = std::fs::remove_file(mvm_core::exit_capture::exit_file_path(state_dir));
    let _ = std::fs::remove_file(mvm_core::usage_capture::usage_file_path(state_dir));
    #[cfg(unix)]
    mvm_vmm::host::hvf_supervisor::failure_record::clear(state_dir);
}

/// Remove a marker file a boot is about to wait for, so the wait cannot be
/// satisfied by a previous run's copy. An absent file is the desired state; a
/// file that exists and cannot be removed would pass for this boot's marker,
/// so that failure refuses the boot.
pub fn remove_stale_marker(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(anyhow::Error::new(error)
                .context(format!("removing stale marker {}", path.display())))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_marker_is_removed_and_an_absent_one_is_fine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("pid");
        remove_stale_marker(&marker).expect("absent marker is fine");
        std::fs::write(&marker, "1").expect("write");
        remove_stale_marker(&marker).expect("stale marker removed");
        assert!(!marker.exists());
    }

    #[test]
    fn a_marker_that_cannot_be_removed_refuses_the_boot() {
        // A directory is not removable with remove_file, standing in for any
        // unremovable stale marker.
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("pid");
        std::fs::create_dir(&marker).expect("mkdir");
        assert!(remove_stale_marker(&marker).is_err());
    }
    use mvm_core::usage_capture::{Mechanism, Metric, UsageCapture};

    #[test]
    fn a_prior_runs_usage_does_not_survive_into_the_next_boot() {
        // The regression this exists for: run one measures 4210ms of CPU, run
        // two is killed before it can write anything, and run two's exit
        // report must not find run one's number sitting there.
        let dir = tempfile::tempdir().expect("tempdir");
        mvm_core::usage_capture::write_captured(
            dir.path(),
            &UsageCapture {
                cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
                ..UsageCapture::default()
            },
        )
        .expect("write");

        clear_prior_run(dir.path());

        assert!(!mvm_core::usage_capture::usage_file_path(dir.path()).exists());
        assert_eq!(
            mvm_core::usage_capture::read_captured(dir.path()),
            UsageCapture::default(),
            "a cleared sidecar reads as unobserved, never as the last run's numbers"
        );
    }

    #[test]
    fn a_prior_runs_exit_code_does_not_survive_into_the_next_boot() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(mvm_core::exit_capture::exit_file_path(dir.path()), b"7\n").expect("write");

        clear_prior_run(dir.path());

        assert_eq!(mvm_core::exit_capture::read_captured(dir.path()), None);
    }

    #[test]
    fn clearing_a_state_dir_with_nothing_to_clear_is_not_an_error() {
        // Every boot calls this, and the first boot of a machine has neither
        // file. Failing there would turn the guard into an outage.
        let dir = tempfile::tempdir().expect("tempdir");
        clear_prior_run(dir.path());
        clear_prior_run(&dir.path().join("never-created"));
    }
}
