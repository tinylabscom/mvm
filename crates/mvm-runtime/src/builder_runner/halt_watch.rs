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
use std::time::{Duration, Instant};

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

impl ConsoleHaltWatch {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            partial: String::new(),
        }
    }

    /// True once the console has shown a halt banner. A missing or unreadable
    /// log reads as "not yet": the console appears after boot, and the process
    /// exit check still bounds the wait.
    pub(super) fn guest_halted(&mut self) -> bool {
        let Some(appended) = self.read_appended() else {
            return false;
        };
        self.partial.push_str(&appended);
        let complete = match self.partial.rfind('\n') {
            Some(end) => end + 1,
            None => return false,
        };
        let halted = self.partial[..complete].lines().any(is_halt_banner);
        self.partial.drain(..complete);
        halted
    }

    /// Block until the console stops growing, so the guest's last lines are on
    /// disk before its VMM is killed.
    ///
    /// The kernel prints the halt banner from inside `reboot(2)`, which can
    /// interleave with a line userspace is still writing: a guest was seen
    /// halting mid-`stage0-init: done; halting`, and killing on the banner
    /// alone truncated the marker the host reads its result from — a finished
    /// build reported as an unclean halt. Bounded, because a VMM that keeps
    /// writing forever must not hold the run open.
    pub(super) fn wait_for_console_to_settle(&self, quiet_for: Duration, limit: Duration) {
        let deadline = Instant::now() + limit;
        let mut last_len = self.console_len();
        let mut quiet_since = Instant::now();
        while Instant::now() < deadline {
            std::thread::sleep(quiet_for.min(Duration::from_millis(50)));
            let len = self.console_len();
            if len != last_len {
                last_len = len;
                quiet_since = Instant::now();
            } else if quiet_since.elapsed() >= quiet_for {
                return;
            }
        }
    }

    fn console_len(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
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

        assert!(ConsoleHaltWatch::new(log).guest_halted());
    }

    #[test]
    fn an_explicit_halt_without_a_timestamp_is_a_halt() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "reboot: System halted\n");

        assert!(ConsoleHaltWatch::new(log).guest_halted());
    }

    #[test]
    fn a_clean_power_off_is_not_a_halt() {
        // The VMM exits on its own after this; the process check owns it.
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "[   12.000000] reboot: Power down\n");

        assert!(!ConsoleHaltWatch::new(log).guest_halted());
    }

    #[test]
    fn a_missing_console_is_not_yet_a_halt() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!ConsoleHaltWatch::new(dir.path().join("console.log")).guest_halted());
    }

    #[test]
    fn a_banner_split_across_polls_is_seen_once_complete() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        let mut watch = ConsoleHaltWatch::new(log.clone());

        append(&log, "building...\n[ 9.1] reboot: Power off not av");
        assert!(!watch.guest_halted(), "half a banner is not a halt");

        append(&log, "ailable: System halted instead\n");
        assert!(watch.guest_halted());
    }

    #[test]
    fn a_banner_quoted_mid_line_is_not_a_halt() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "grep 'reboot: System halted' kernel.log || true\n");

        assert!(!ConsoleHaltWatch::new(log).guest_halted());
    }

    #[test]
    fn settling_returns_once_the_console_stops_growing() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "reboot: System halted\n");
        let watch = ConsoleHaltWatch::new(log);

        let started = Instant::now();
        watch.wait_for_console_to_settle(Duration::from_millis(100), Duration::from_secs(5));

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a quiet console must not wait out the limit"
        );
    }

    #[test]
    fn a_console_still_being_written_holds_the_kill_until_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "stage0-init: don");
        let watch = ConsoleHaltWatch::new(log.clone());

        let writer = std::thread::spawn(move || {
            for _ in 0..6 {
                std::thread::sleep(Duration::from_millis(30));
                append(&log, "e; halting\n");
            }
        });
        let started = Instant::now();
        watch.wait_for_console_to_settle(Duration::from_millis(100), Duration::from_secs(5));
        writer.join().unwrap();

        assert!(
            started.elapsed() >= Duration::from_millis(150),
            "a console that keeps growing must not settle immediately"
        );
    }

    #[test]
    fn a_console_that_never_stops_is_bounded_by_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        append(&log, "noisy\n");
        let watch = ConsoleHaltWatch::new(log.clone());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_stop = stop.clone();
        let writer = std::thread::spawn(move || {
            while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
                append(&log, "more\n");
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        let started = Instant::now();
        watch.wait_for_console_to_settle(Duration::from_millis(100), Duration::from_millis(400));
        let waited = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        writer.join().unwrap();

        assert!(
            waited < Duration::from_secs(2),
            "the limit bounds the wait: {waited:?}"
        );
    }

    #[test]
    fn only_appended_output_is_reread() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("console.log");
        let mut watch = ConsoleHaltWatch::new(log.clone());

        append(&log, "boot line\n");
        assert!(!watch.guest_halted());
        assert_eq!(watch.offset, "boot line\n".len() as u64);

        append(&log, "reboot: System halted\n");
        assert!(watch.guest_halted());
    }
}
