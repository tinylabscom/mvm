//! Notice a builder guest that halted instead of powering off.
//!
//! A builder guest ends with `reboot(RB_POWER_OFF)`. When its kernel has no
//! power-off method the kernel halts the CPUs instead and says so on the
//! console. Whether the VMM then exits is the VMM's business: HVF and libkrun
//! do, Firecracker does not — it keeps a halted guest alive indefinitely, so a
//! runner that waits only for the process would wait out its whole backstop on
//! a guest that finished long ago.
//!
//! Reading the console for the kernel's own banner is VMM-neutral and needs no
//! guest change. Seeing it ends the wait and nothing more: success is still
//! decided by the job's on-disk result, so a banner echoed by a build script
//! can cut a job short but cannot make one pass.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// What the kernel prints when a halt stands in for a power-off, or when a
/// halt was asked for outright.
const HALT_BANNERS: [&str; 2] = [
    "reboot: Power off not available: System halted instead",
    "reboot: System halted",
];

/// Tails a console log, reading only what was appended since the last poll.
pub(super) struct ConsoleHaltWatch {
    path: PathBuf,
    offset: u64,
    /// The unterminated tail of the last read, so a banner split across two
    /// polls is still seen whole.
    partial: String,
}

/// What one poll of the console found: the lines completed since the previous
/// poll, and whether any of them was a halt banner.
#[derive(Debug, Default)]
pub(super) struct ConsolePoll {
    pub(super) lines: Vec<String>,
    pub(super) halted: bool,
}

impl ConsoleHaltWatch {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            partial: String::new(),
        }
    }

    /// Read what the guest appended. `halted` turns true once the console has
    /// shown a halt banner. A missing or unreadable log reads as "nothing yet":
    /// the console appears after boot, and the process exit check still bounds
    /// the wait.
    pub(super) fn poll(&mut self) -> ConsolePoll {
        let Some(appended) = self.read_appended() else {
            return ConsolePoll::default();
        };
        self.partial.push_str(&appended);
        let Some(end) = self.partial.rfind('\n') else {
            return ConsolePoll::default();
        };
        let complete = end + 1;
        let lines: Vec<String> = self.partial[..complete]
            .lines()
            .map(str::to_string)
            .collect();
        self.partial.drain(..complete);
        let halted = lines.iter().any(|line| is_halt_banner(line));
        ConsolePoll { lines, halted }
    }

    fn read_appended(&mut self) -> Option<String> {
        let mut file = File::open(&self.path).ok()?;
        file.seek(SeekFrom::Start(self.offset)).ok()?;
        let mut bytes = Vec::new();
        let read = file.read_to_end(&mut bytes).ok()?;
        self.offset += read as u64;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// A console line carrying a halt banner. The kernel may prefix it with a
/// printk timestamp, so the banner has to end the line rather than start it.
fn is_halt_banner(line: &str) -> bool {
    let line = line.trim_end();
    HALT_BANNERS.iter().any(|banner| line.ends_with(banner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(path: &std::path::Path, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn the_firecracker_power_off_fallback_is_a_halt() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(
            &log,
            "stage0-init: done; halting\n\
             [ 1023.955294] reboot: Power off not available: System halted instead\n",
        );

        assert!(ConsoleHaltWatch::new(log).poll().halted);
    }

    #[test]
    fn an_explicit_halt_without_a_timestamp_is_a_halt() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "reboot: System halted\n");

        assert!(ConsoleHaltWatch::new(log).poll().halted);
    }

    #[test]
    fn a_clean_power_off_is_not_a_halt() {
        // The VMM exits on its own after this; the process check owns it.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "[   12.000000] reboot: Power down\n");

        assert!(!ConsoleHaltWatch::new(log).poll().halted);
    }

    #[test]
    fn a_missing_console_is_not_yet_a_halt() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            !ConsoleHaltWatch::new(dir.path().join("console.log"))
                .poll()
                .halted
        );
    }

    #[test]
    fn a_banner_split_across_polls_is_seen_once_complete() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        let mut watch = ConsoleHaltWatch::new(log.clone());

        append(&log, "building...\n[ 9.1] reboot: Power off not av");
        assert!(!watch.poll().halted, "half a banner is not a halt");

        append(&log, "ailable: System halted instead\n");
        assert!(watch.poll().halted);
    }

    #[test]
    fn a_banner_quoted_mid_line_is_not_a_halt() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "grep 'reboot: System halted' kernel.log || true\n");

        assert!(!ConsoleHaltWatch::new(log).poll().halted);
    }

    #[test]
    fn completed_lines_are_handed_back_in_order_and_partials_wait() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        let mut watch = ConsoleHaltWatch::new(log.clone());

        append(&log, "one\ntwo\nthr");
        assert_eq!(watch.poll().lines, vec!["one", "two"]);

        append(&log, "ee\n");
        assert_eq!(watch.poll().lines, vec!["three"]);
        assert!(
            watch.poll().lines.is_empty(),
            "nothing new, nothing returned"
        );
    }

    #[test]
    fn only_appended_output_is_reread() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        let mut watch = ConsoleHaltWatch::new(log.clone());

        append(&log, "boot line\n");
        assert!(!watch.poll().halted);
        assert_eq!(watch.offset, "boot line\n".len() as u64);

        append(&log, "reboot: System halted\n");
        assert!(watch.poll().halted);
    }
}
