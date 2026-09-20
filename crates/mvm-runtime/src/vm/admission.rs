//! Markers that say what a Firecracker VMM's current process was last admitted
//! as: paused, or resumed and admitted.
//!
//! A resume restores a sealed snapshot into a fresh VMM and resumes its vCPUs
//! before the guest has confirmed it reseeded. Until it does, the guest is
//! running on random state it has already used, and it must end either
//! admitted or stopped. The process doing the resume normally decides that,
//! but a process killed mid-admission decides nothing, so reconcile needs to
//! tell such a guest apart on its own.
//!
//! Each marker holds the pid of the Firecracker process it describes, next to
//! `fc.pid` in the VM's state directory. A marker counts only while it names
//! the pid `fc.pid` names, so one left behind by an earlier process of the same
//! VM says nothing about the current one.
//!
//! - `fc.paused` is written when a pause has sealed the snapshot.
//! - `fc.admitted` is written only after a resumed guest has confirmed its
//!   reseed, and removed by the next pause.
//!
//! A live Firecracker named by neither marker, under a machine the registry
//! records as paused, is a resume that never admitted its guest. The registry
//! alone cannot say this: a machine that was never paused has no marker either,
//! and a registry write that failed after an admission would make an admitted
//! guest look unadmitted. The admission marker is what protects that guest.

use std::path::Path;

use anyhow::{Context, Result};

/// The Firecracker pid file in a VM's state directory.
pub const PID_FILE: &str = "fc.pid";
/// Written by a pause, naming the paused process.
pub const PAUSED_MARKER: &str = "fc.paused";
/// Written once a resumed guest confirmed its reseed, naming that process.
pub const ADMITTED_MARKER: &str = "fc.admitted";

fn recorded_pid(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|pid| pid.trim().to_string())
        .filter(|pid| !pid.is_empty())
}

/// Copy the current `fc.pid` into `marker`. No pid file means no Firecracker
/// process for the marker to describe, which is an error: the caller is about
/// to rely on the marker.
fn stamp(state_dir: &Path, marker: &str) -> Result<()> {
    let pid_file = state_dir.join(PID_FILE);
    let pid = recorded_pid(&pid_file)
        .with_context(|| format!("no Firecracker pid in {}", pid_file.display()))?;
    let path = state_dir.join(marker);
    // Written to a temporary file and renamed into place, so a reader never
    // sees a half-written pid.
    mvm_core::atomic_io::atomic_write(&path, pid.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// Record that a pause sealed the VM whose Firecracker `state_dir` holds, and
/// withdraw any earlier admission. Does nothing for a VM with no `fc.pid`,
/// which is not a Firecracker VM.
pub fn record_paused(state_dir: &Path) -> Result<()> {
    if !state_dir.join(PID_FILE).exists() {
        return Ok(());
    }
    stamp(state_dir, PAUSED_MARKER)?;
    remove_if_present(&state_dir.join(ADMITTED_MARKER))
}

/// Record that the guest of the VM whose Firecracker `state_dir` holds has
/// confirmed its reseed. An error means the admission is not recorded.
pub fn record_admitted(state_dir: &Path) -> Result<()> {
    stamp(state_dir, ADMITTED_MARKER)
}

/// Remove the pause marker once a resume has restored the VM.
pub fn clear_paused(state_dir: &Path) -> Result<()> {
    remove_if_present(&state_dir.join(PAUSED_MARKER))
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// Whether `state_dir` holds a live Firecracker that neither a pause nor an
/// admission accounts for. Cheap: two reads and a `kill(pid, 0)`.
pub fn is_unaccounted(state_dir: &Path) -> bool {
    let Some(pid) = recorded_pid(&state_dir.join(PID_FILE)) else {
        return false;
    };
    let names_this_process =
        |marker: &str| recorded_pid(&state_dir.join(marker)).as_deref() == Some(pid.as_str());
    !names_this_process(PAUSED_MARKER)
        && !names_this_process(ADMITTED_MARKER)
        && mvm_vmm::host::process_liveness::pid_file_has_live_process(&state_dir.join(PID_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state dir whose `fc.pid` names this test's own process, which stands
    /// in for a live Firecracker.
    fn live_vm() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(PID_FILE), std::process::id().to_string()).unwrap();
        dir
    }

    #[test]
    fn a_live_vmm_with_no_marker_is_unaccounted() {
        assert!(is_unaccounted(live_vm().path()));
    }

    #[test]
    fn a_paused_or_admitted_vmm_is_accounted_for() {
        let paused = live_vm();
        record_paused(paused.path()).unwrap();
        assert!(!is_unaccounted(paused.path()));

        let admitted = live_vm();
        record_admitted(admitted.path()).unwrap();
        assert!(!is_unaccounted(admitted.path()));
    }

    /// A marker left by an earlier process of the same VM names a different
    /// pid, and says nothing about the current one.
    #[test]
    fn a_marker_for_another_process_does_not_count() {
        let dir = live_vm();
        std::fs::write(dir.path().join(ADMITTED_MARKER), "1").unwrap();
        std::fs::write(dir.path().join(PAUSED_MARKER), "2").unwrap();
        assert!(is_unaccounted(dir.path()));
    }

    #[test]
    fn no_vmm_is_never_unaccounted() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!is_unaccounted(dir.path()));
        // A pid no process has: above the kernel's pid limit.
        std::fs::write(dir.path().join(PID_FILE), i32::MAX.to_string()).unwrap();
        assert!(!is_unaccounted(dir.path()));
    }

    /// A pause withdraws the admission, so the next resume starts unaccounted
    /// for until it admits again.
    #[test]
    fn a_pause_withdraws_the_admission() {
        let dir = live_vm();
        record_admitted(dir.path()).unwrap();
        record_paused(dir.path()).unwrap();
        assert!(!dir.path().join(ADMITTED_MARKER).exists());
        clear_paused(dir.path()).unwrap();
        assert!(is_unaccounted(dir.path()));
    }

    #[test]
    fn recording_an_admission_without_a_vmm_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        record_admitted(dir.path()).expect_err("nothing to admit");
        record_paused(dir.path()).expect("a VM with no fc.pid is not Firecracker");
    }

    #[test]
    fn a_marker_that_cannot_be_written_is_an_error() {
        let dir = live_vm();
        std::fs::create_dir(dir.path().join(ADMITTED_MARKER)).unwrap();
        record_admitted(dir.path()).expect_err("a directory is in the way");
    }
}
