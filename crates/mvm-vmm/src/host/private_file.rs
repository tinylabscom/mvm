//! Writing a host-side file that carries key material.
//!
//! `fs::write`, and `OpenOptions::mode()` on its own, get three things wrong for
//! a file holding a private key:
//!
//! - **The mode only applies at creation.** Opening an existing file with
//!   `.mode(0o600)` leaves whatever mode that file already had, so a key written
//!   over a 0644 predecessor stays 0644.
//! - **Truncate-in-place is observable.** A concurrent reader — a warm claim
//!   reading the parent's material while the parent rewrites it — can see an
//!   empty or half-written file.
//! - **It follows a symlink** at the destination, so anything that can plant one
//!   inside the state dir chooses where the key lands.
//!
//! [`write_private`] writes a fresh per-process temporary beside the
//! destination, gives *that* inode the mode, flushes it, and renames. The rename
//! replaces the destination name — including a symlink sitting at it — with an
//! inode that was 0600 from its first byte, and a reader sees either the whole
//! old file or the whole new one.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Mode every file written through here carries: owner read/write only.
const PRIVATE_MODE: u32 = 0o600;

/// Write `bytes` to `path` at mode 0600, atomically and without following a
/// symlink at either the destination or the temporary.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_path_for(path);
    // Remove first so `create_new` cannot lose to a planted symlink or to
    // leftovers from a process that died between create and rename.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        // `create_new` refuses an existing path outright, so the open cannot be
        // redirected through a symlink and the mode is guaranteed to be the one
        // this inode was born with.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_MODE)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Leaving a readable temporary behind would defeat the point.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// The temporary this process writes through, beside the destination so the
/// rename stays within one filesystem.
///
/// Keyed by pid rather than by extension: two processes writing the same
/// destination would otherwise fight over one temporary, and
/// `Path::with_extension` would collide `a.json` with `a.ext4`.
fn temp_path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn a_fresh_file_is_written_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        write_private(&path, b"secret").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"secret");
        assert_eq!(mode_of(&path), PRIVATE_MODE);
    }

    #[test]
    fn writing_over_a_world_readable_file_leaves_it_owner_only() {
        // The failure this exists for: `OpenOptions::mode()` applies at
        // creation, so writing through an existing 0644 file keeps 0644 and the
        // key stays readable by every uid on the host.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        std::fs::write(&path, b"old").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("seed mode");

        write_private(&path, b"secret").expect("write");

        assert_eq!(mode_of(&path), PRIVATE_MODE);
        assert_eq!(std::fs::read(&path).expect("read"), b"secret");
    }

    #[test]
    fn a_symlink_at_the_destination_is_replaced_rather_than_written_through() {
        let dir = tempfile::tempdir().expect("tempdir");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"untouched").expect("seed");
        let path = dir.path().join("key.pem");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("plant a symlink");

        write_private(&path, b"secret").expect("write");

        assert_eq!(
            std::fs::read(&elsewhere).expect("read"),
            b"untouched",
            "the key must not be written through a planted symlink"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"secret");
        assert!(
            !std::fs::symlink_metadata(&path)
                .expect("stat")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn no_temporary_survives_a_successful_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        write_private(&path, b"secret").expect("write");
        assert!(!temp_path_for(&path).exists());
    }

    #[test]
    fn a_stale_temporary_does_not_block_the_next_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("key.pem");
        std::fs::write(temp_path_for(&path), b"leftover").expect("seed a stale temporary");
        write_private(&path, b"secret").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"secret");
    }
}
