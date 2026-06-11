//! Workload exit-code file convention.
//!
//! The supervisor captures a finished one-shot workload's exit code
//! (written by the guest `/init` over the control vsock port) and
//! persists it to `<vm_state_dir>/workload.exit`. This module is the
//! shared home for the file name + path + reader, so the backend
//! (`mvm-backend`) can read it without depending on the supervisor crate
//! (`mvm-vm-host`), which sits above it in the dep graph. The capture
//! side (`capture_once`) lives in `mvm-vm-host` and uses `exit_file_path`
//! from here.

use std::path::{Path, PathBuf};

/// File name under `vm_state_dir` holding the captured exit code (decimal).
pub const WORKLOAD_EXIT_FILE: &str = "workload.exit";

pub fn exit_file_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join(WORKLOAD_EXIT_FILE)
}

/// Read a previously-captured exit code, if present.
pub fn read_captured(vm_state_dir: &Path) -> Option<i32> {
    std::fs::read_to_string(exit_file_path(vm_state_dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_captured_roundtrips_decimal() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(exit_file_path(dir.path()), "-7").unwrap();
        assert_eq!(read_captured(dir.path()), Some(-7));
    }

    #[test]
    fn read_captured_is_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_captured(dir.path()), None);
    }
}
