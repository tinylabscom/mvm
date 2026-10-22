//! A host process named by what the kernel says it is, not by its PID.
//!
//! The identity is the PID plus the process start time and the host boot id,
//! so a recycled PID, or a PID that survives only in a record across a reboot,
//! is never mistaken for the process that was observed. Exit is judged against
//! the live process table; a caller's assertion never stands in for it.

use std::io;

use serde::{Deserialize, Serialize};

#[cfg(any(target_os = "linux", test))]
use super::process_liveness::parse_proc_starttime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub vm_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
}

#[cfg(target_os = "linux")]
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

impl ProcessIdentity {
    /// Observe a live process. A process that is already gone is an error.
    pub fn capture(vm_id: &str, pid: u32) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
            Ok(Self {
                vm_id: vm_id.to_owned(),
                pid,
                start_ticks: parse_proc_starttime(&stat)?,
                boot_id: std::fs::read_to_string(BOOT_ID_PATH)?.trim().to_owned(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (vm_id, pid);
            Err(unsupported())
        }
    }

    /// True only when the observed process is positively gone. A process table
    /// that cannot be read is an error, never "exited".
    pub fn has_exited(&self) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let boot_id = std::fs::read_to_string(BOOT_ID_PATH)?;
            self.has_exited_with(
                boot_id.trim(),
                std::fs::read_to_string(format!("/proc/{}/stat", self.pid)),
            )
        }
        #[cfg(not(target_os = "linux"))]
        Err(unsupported())
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn has_exited_with(
        &self,
        current_boot_id: &str,
        stat: io::Result<String>,
    ) -> io::Result<bool> {
        if current_boot_id != self.boot_id {
            return Ok(true);
        }
        match stat {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
            Ok(stat) => Ok(parse_proc_starttime(&stat)? != self.start_ticks),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "process identity requires a Linux process table",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> ProcessIdentity {
        ProcessIdentity {
            vm_id: "vm".into(),
            pid: 42,
            start_ticks: 777,
            boot_id: "boot-a".into(),
        }
    }

    /// Field 22 (starttime) sits after a comm that may hold spaces and ')'.
    fn stat(start: u64) -> io::Result<String> {
        Ok(format!(
            "42 (fire cracker)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 {start} 23"
        ))
    }

    #[test]
    fn the_same_process_has_not_exited() {
        assert!(!identity().has_exited_with("boot-a", stat(777)).unwrap());
    }

    #[test]
    fn a_missing_recycled_or_pre_reboot_process_has_exited() {
        let gone = Err(io::Error::from(io::ErrorKind::NotFound));
        assert!(identity().has_exited_with("boot-a", gone).unwrap());
        assert!(identity().has_exited_with("boot-a", stat(778)).unwrap());
        assert!(identity().has_exited_with("boot-b", stat(777)).unwrap());
    }

    #[test]
    fn an_unreadable_or_garbled_process_table_is_never_an_exit() {
        let denied = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(identity().has_exited_with("boot-a", denied).is_err());
        assert!(
            identity()
                .has_exited_with("boot-a", Ok("garbled".into()))
                .is_err()
        );
    }
}
