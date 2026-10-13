//! Raise the kernel console loglevel back to `quiet` once PID 1 is running.
//!
//! A Firecracker workload boots with `loglevel=3`, which keeps the kernel's
//! own `KERN_ERR` lines off the emulated serial port during early boot. On a
//! healthy boot those lines are noise: Firecracker describes its virtio-mmio
//! devices both in ACPI and on the command line, so every device registers
//! twice and the second registration fails loudly, and each byte on that port
//! is a VM exit. After boot the same level would also hide errors that matter,
//! such as the OOM killer's `Out of memory: Killed process`, which diagnostics
//! scan `console.log` for. PID 1 therefore lifts the level back to the value
//! `quiet` sets as soon as it has `/proc`.
//!
//! The adjustment only ever raises the level. A boot that asked for more
//! output (`loglevel=8` on the virtio-console backends, or the verbose
//! Firecracker escape hatch) is left alone.

use std::io;
use std::path::Path;

/// Where the kernel exposes the console loglevel: the first of four fields.
pub const PRINTK_PATH: &str = "/proc/sys/kernel/printk";

/// The console loglevel `quiet` selects: errors (`KERN_ERR`, level 3) and
/// more severe messages reach the console, warnings and chatter do not.
pub const QUIET_CONSOLE_LOGLEVEL: u8 = 4;

/// The console loglevel recorded in a `printk` sysctl value, the first
/// whitespace-separated field.
#[must_use]
pub fn console_loglevel_in(printk: &str) -> Option<u8> {
    printk.split_whitespace().next()?.parse().ok()
}

/// Raise the console loglevel in `printk_path` to at least `floor`.
///
/// Returns the level that was replaced, or `None` when the current level
/// already met the floor and nothing was written. Writing a single number to
/// the sysctl sets only the console loglevel and leaves the other three fields
/// as they were.
pub fn raise_console_loglevel_at(printk_path: &Path, floor: u8) -> io::Result<Option<u8>> {
    let current = std::fs::read_to_string(printk_path)?;
    let Some(level) = console_loglevel_in(&current) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} holds no console loglevel: {current:?}",
                printk_path.display()
            ),
        ));
    };
    if level >= floor {
        return Ok(None);
    }
    std::fs::write(printk_path, floor.to_string())?;
    Ok(Some(level))
}

/// Raise the live kernel's console loglevel to [`QUIET_CONSOLE_LOGLEVEL`].
pub fn restore_quiet_console_loglevel() -> io::Result<Option<u8>> {
    raise_console_loglevel_at(Path::new(PRINTK_PATH), QUIET_CONSOLE_LOGLEVEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printk_file(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temp printk");
        std::fs::write(file.path(), contents).expect("seed printk");
        file
    }

    #[test]
    fn the_console_loglevel_is_the_first_field() {
        assert_eq!(console_loglevel_in("3\t4\t1\t7\n"), Some(3));
        assert_eq!(console_loglevel_in("7 4 1 7"), Some(7));
        assert_eq!(console_loglevel_in(""), None);
        assert_eq!(console_loglevel_in("quiet 4 1 7"), None);
    }

    /// The Firecracker boot lowers the level to 3; PID 1 must bring it back
    /// to 4 so a runtime `pr_err` (the OOM killer's report) reaches the
    /// console again.
    #[test]
    fn a_lowered_boot_level_is_raised_to_quiet() {
        let file = printk_file("3\t4\t1\t7\n");
        let replaced =
            raise_console_loglevel_at(file.path(), QUIET_CONSOLE_LOGLEVEL).expect("raise");
        assert_eq!(replaced, Some(3));
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "4");
    }

    /// A boot that asked for more output keeps it: the restore is a floor,
    /// never a cap.
    #[test]
    fn a_louder_level_is_left_alone() {
        for level in ["4\t4\t1\t7\n", "7\t4\t1\t7\n", "8\t4\t1\t7\n"] {
            let file = printk_file(level);
            let replaced =
                raise_console_loglevel_at(file.path(), QUIET_CONSOLE_LOGLEVEL).expect("raise");
            assert_eq!(replaced, None, "{level:?}");
            assert_eq!(std::fs::read_to_string(file.path()).unwrap(), level);
        }
    }

    #[test]
    fn an_unparseable_sysctl_is_an_error_and_is_not_overwritten() {
        let file = printk_file("garbage\n");
        let error = raise_console_loglevel_at(file.path(), QUIET_CONSOLE_LOGLEVEL)
            .expect_err("unparseable printk must not be written");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read_to_string(file.path()).unwrap(), "garbage\n");
    }

    #[test]
    fn a_missing_sysctl_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = raise_console_loglevel_at(&dir.path().join("printk"), QUIET_CONSOLE_LOGLEVEL)
            .expect_err("missing printk");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
