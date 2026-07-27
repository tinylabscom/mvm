//! Reflink (copy-on-write) file cloning primitives.
//!
//! APFS Copy-on-Write for Apple Container templates. Cloning a 1 GiB
//! ext4 rootfs via `clonefile(2)` on macOS takes ~constant time regardless
//! of file size, since APFS only writes new metadata and shares the
//! underlying blocks until either side writes. The same shape works on
//! Linux via the `FICLONE` ioctl on btrfs/xfs/overlayfs — those
//! filesystems also have block-level CoW. ext4 returns `EOPNOTSUPP` (the
//! default on the Linux host / builder VM), so the caller falls back to a
//! regular byte copy.
//!
//! The cloned ext4 is the L3 rootfs; per-instance writes diverge into the
//! clone's blocks and never touch the template.

#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// What strategy [`reflink_or_copy`] used to materialize the destination.
///
/// `Reflink` is the fast path (O(1) metadata operation, blocks shared
/// until written). `Copied` is the byte-copy fallback that fires when the
/// filesystem doesn't support reflinks (ext4 without explicit support,
/// NTFS on Windows, network mounts, cross-volume copies on APFS, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneStrategy {
    /// Filesystem-level CoW clone (`clonefile(2)` on macOS,
    /// `FICLONE` ioctl on Linux btrfs/xfs).
    Reflink,
    /// Byte-by-byte copy (slow path, no CoW).
    Copied,
}

/// Reflink-clone `src` to `dst`. Errors with `EOPNOTSUPP` if the
/// underlying filesystem does not support reflinks.
///
/// Use [`reflink_or_copy`] if you want to fall back to a regular copy
/// instead of erroring.
///
/// On macOS: `libc::clonefile(src, dst, 0)`.
/// On Linux: `ioctl(dst_fd, FICLONE, src_fd)` after creating `dst`.
/// On other platforms: always returns `EOPNOTSUPP`.
pub fn reflink_or_err(src: &Path, dst: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::clonefile_path(src, dst)
    }
    #[cfg(target_os = "linux")]
    {
        linux::ficlone(src, dst)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (src, dst);
        Err(io::Error::from_raw_os_error(libc_eopnotsupp()))
    }
}

/// Reflink-clone `src` to `dst`, falling back to a byte copy if the
/// filesystem doesn't support reflinks. Returns the strategy used so
/// callers can log the fast/slow path for performance analysis.
///
/// Always succeeds modulo I/O errors (missing source, permission denied,
/// disk full, etc.).
pub fn reflink_or_copy(src: &Path, dst: &Path) -> io::Result<CloneStrategy> {
    match reflink_or_err(src, dst) {
        Ok(()) => Ok(CloneStrategy::Reflink),
        Err(e) if is_unsupported(&e) => {
            // Sparse-aware fallback: a memory snapshot or an ext4 image with
            // free space has large zero runs that must not fully expand
            // into allocated bytes just because reflink isn't available.
            sparse_copy(src, dst)?;
            Ok(CloneStrategy::Copied)
        }
        Err(e) => Err(e),
    }
}

/// Byte-copy `src` to `dst`, skipping any fixed-size block that is
/// entirely zero by seeking the destination forward instead of writing it.
/// On a sparse-capable filesystem the skipped region becomes a hole and
/// reads back as zeros (POSIX semantics) without ever being allocated on
/// disk.
///
/// Data-only: `dst` is created with default (umask-derived) permissions,
/// not `src`'s mode bits — unlike the `std::fs::copy` this replaces, which
/// copies source permissions onto a freshly created destination.
///
/// `dst` must not already exist.
pub fn sparse_copy(src: &Path, dst: &Path) -> io::Result<()> {
    const BLOCK: usize = 64 * 1024;

    let mut src_file = File::open(src)?;
    let src_len = src_file.metadata()?.len();
    let mut dst_file = OpenOptions::new().write(true).create_new(true).open(dst)?;

    let mut buf = vec![0u8; BLOCK];
    loop {
        let n = src_file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if buf[..n].iter().all(|&b| b == 0) {
            dst_file.seek(SeekFrom::Current(n as i64))?;
        } else {
            dst_file.write_all(&buf[..n])?;
        }
    }
    // A trailing zero run leaves the file short of `src_len` (the final
    // seek has no write behind it to extend the file) — pin the length
    // explicitly so a zero-tailed source still produces an exact-length
    // destination.
    dst_file.set_len(src_len)?;
    Ok(())
}

fn is_unsupported(e: &io::Error) -> bool {
    // ENOTSUP and EOPNOTSUPP are the same value on macOS/Linux but
    // we check both names defensively. EXDEV indicates cross-device
    // (cross-volume) — APFS CoW requires same volume, btrfs/xfs FICLONE
    // requires same filesystem instance. ENOTTY is what the kernel
    // returns when the underlying filesystem doesn't implement the
    // FICLONE ioctl at all — ext4 without reflink support (the
    // default on stock Ubuntu, including the GitHub Actions Linux
    // runner image) returns this rather than EOPNOTSUPP.
    matches!(
        e.raw_os_error(),
        Some(libc::ENOTSUP) | Some(libc::EXDEV) | Some(libc::EINVAL) | Some(libc::ENOTTY)
    )
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // `clonefile(const char *src, const char *dst, uint32_t flags)` from
    // `<sys/clonefile.h>`. Available since macOS 10.12.
    unsafe extern "C" {
        fn clonefile(src: *const libc::c_char, dst: *const libc::c_char, flags: u32)
        -> libc::c_int;
    }

    pub(super) fn clonefile_path(src: &Path, dst: &Path) -> io::Result<()> {
        let src_c = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let dst_c = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: both pointers come from CStrings that outlive the call.
        // Flags = 0 means default (clone metadata + data links, no
        // symlink follow).
        let rc = unsafe { clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    // ioctl(dst, FICLONE, src) — see <linux/fs.h>. Encoded the same way
    // across architectures: _IOW('f', 9, int).
    const FICLONE: libc::c_ulong = 0x4020_9409;

    pub(super) fn ficlone(src: &Path, dst: &Path) -> io::Result<()> {
        let src_fd = OpenOptions::new().read(true).open(src)?;
        let dst_fd = OpenOptions::new().write(true).create_new(true).open(dst)?;
        // SAFETY: both file descriptors are owned and valid for the
        // duration of the ioctl. FICLONE atomically clones extents from
        // src into dst (which must be empty / freshly created).
        let rc = unsafe { libc::ioctl(dst_fd.as_raw_fd(), FICLONE as _, src_fd.as_raw_fd()) };
        if rc == 0 {
            Ok(())
        } else {
            // Clean up the empty destination so the caller's copy
            // fallback can recreate it without EEXIST.
            let err = io::Error::last_os_error();
            drop(dst_fd);
            let _ = std::fs::remove_file(dst);
            Err(err)
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn libc_eopnotsupp() -> i32 {
    libc::ENOTSUP
}

/// Recursively clone a directory tree from `src` to `dst` using reflink
/// where possible, falling back to byte copies otherwise.
///
/// Directories are created, regular files are cloned with
/// [`reflink_or_copy`], and symlinks are recreated with the same target.
/// Other file types (devices, FIFOs, sockets) are skipped because they
/// cannot be meaningfully snapshotted as regular files.
///
/// `dst` must not already exist; its parent is created if necessary.
/// Returns the aggregate strategy: `Reflink` only if every regular file
/// was reflinked; `Copied` if any file fell back.
pub fn reflink_or_copy_dir(src: &Path, dst: &Path) -> io::Result<CloneStrategy> {
    if !src.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("source is not a directory: {}", src.display()),
        ));
    }

    std::fs::create_dir_all(dst.parent().unwrap_or(dst))?;

    fn walk(current_src: &Path, current_dst: &Path, saw_copy: &mut bool) -> io::Result<()> {
        let meta = current_src.symlink_metadata()?;
        let file_type = meta.file_type();

        if file_type.is_dir() {
            std::fs::create_dir_all(current_dst)?;
            for entry in std::fs::read_dir(current_src)? {
                let entry = entry?;
                walk(
                    &entry.path(),
                    &current_dst.join(entry.file_name()),
                    saw_copy,
                )?;
            }
        } else if file_type.is_file() {
            let strategy = reflink_or_copy(current_src, current_dst)?;
            if strategy == CloneStrategy::Copied {
                *saw_copy = true;
            }
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(current_src)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, current_dst)?;
            #[cfg(not(unix))]
            {
                let _ = (target, current_dst);
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "symlink cloning is only supported on unix",
                ));
            }
        }
        // Non-regular files (devices, FIFOs, sockets) are silently skipped
        // because they have no stable on-disk identity.

        Ok(())
    }

    let mut saw_copy = false;
    walk(src, dst, &mut saw_copy)?;

    if saw_copy {
        Ok(CloneStrategy::Copied)
    } else {
        Ok(CloneStrategy::Reflink)
    }
}

/// Compute a content-addressed path for a snapshot file within a store
/// rooted at `store_root`.
///
/// The id is opaque to this helper; callers produce it from a manifest
/// hash or another stable identifier.
pub fn snapshot_path(store_root: &Path, id: &str) -> PathBuf {
    store_root.join(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_errors_classify_correctly() {
        let enotsup = io::Error::from_raw_os_error(libc::ENOTSUP);
        let exdev = io::Error::from_raw_os_error(libc::EXDEV);
        let einval = io::Error::from_raw_os_error(libc::EINVAL);
        let enotty = io::Error::from_raw_os_error(libc::ENOTTY);
        let other = io::Error::from_raw_os_error(libc::EACCES);
        assert!(is_unsupported(&enotsup));
        assert!(is_unsupported(&exdev));
        assert!(is_unsupported(&einval));
        assert!(is_unsupported(&enotty));
        assert!(!is_unsupported(&other));
    }

    #[test]
    fn reflink_or_copy_produces_byte_equal_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");
        std::fs::write(&src, b"hello snapshot").unwrap();

        let strategy = reflink_or_copy(&src, &dst).expect("clone or copy");
        assert!(matches!(
            strategy,
            CloneStrategy::Reflink | CloneStrategy::Copied
        ));
        assert_eq!(std::fs::read(&dst).unwrap(), b"hello snapshot");
    }

    #[test]
    fn sparse_copy_roundtrips_byte_equal_across_hole_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");

        const BLOCK: usize = 64 * 1024;
        let mut data = Vec::with_capacity(BLOCK * 4);
        data.extend(std::iter::repeat_n(0xAB_u8, BLOCK)); // nonzero block
        data.extend(std::iter::repeat_n(0u8, BLOCK)); // zero block -> hole
        data.extend(std::iter::repeat_n(0xCD_u8, BLOCK)); // nonzero block
        data.extend(std::iter::repeat_n(0u8, BLOCK)); // trailing zero run
        std::fs::write(&src, &data).unwrap();

        sparse_copy(&src, &dst).expect("sparse copy");

        assert_eq!(std::fs::read(&dst).unwrap(), data, "must be byte-identical");
        assert_eq!(
            std::fs::metadata(&dst).unwrap().len(),
            data.len() as u64,
            "length must match exactly even with a trailing zero run"
        );
    }

    #[test]
    fn reflink_or_copy_refuses_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("dst.bin");
        std::fs::write(&src, b"src content").unwrap();
        std::fs::write(&dst, b"existing").unwrap();

        let result = reflink_or_copy(&src, &dst);
        assert!(result.is_err());
    }

    #[test]
    fn reflink_or_copy_dir_clones_tree() {
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let dst_dir = tempfile::tempdir().expect("dst tempdir");

        std::fs::create_dir(src_dir.path().join("subdir")).unwrap();
        std::fs::write(src_dir.path().join("top.txt"), b"top").unwrap();
        std::fs::write(src_dir.path().join("subdir").join("nested.txt"), b"nested").unwrap();

        let dst = dst_dir.path().join("clone");
        let strategy = reflink_or_copy_dir(src_dir.path(), &dst).expect("clone dir");
        assert!(matches!(
            strategy,
            CloneStrategy::Reflink | CloneStrategy::Copied
        ));

        assert_eq!(std::fs::read(dst.join("top.txt")).unwrap(), b"top");
        assert_eq!(
            std::fs::read(dst.join("subdir").join("nested.txt")).unwrap(),
            b"nested"
        );

        // Mutating the clone must not affect the source.
        std::fs::write(dst.join("top.txt"), b"mutated").unwrap();
        assert_eq!(
            std::fs::read(src_dir.path().join("top.txt")).unwrap(),
            b"top"
        );
    }

    /// On macOS with an APFS-backed `TMPDIR` (the default), `clonefile`
    /// always works. The test asserts the fast path was taken and that
    /// writes to the clone don't tamper the source.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_clonefile_creates_independent_copy() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let src_path = dir.path().join("src.bin");
        let dst_path = dir.path().join("dst.bin");
        let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src_path, &payload).expect("write src");

        let strategy =
            reflink_or_copy(&src_path, &dst_path).expect("reflink_or_copy on macOS APFS tempdir");
        assert_eq!(strategy, CloneStrategy::Reflink);

        let cloned = std::fs::read(&dst_path).expect("read clone");
        assert_eq!(cloned, payload, "clone must byte-equal source");

        std::fs::write(&dst_path, b"clone-only payload").expect("write clone");
        let src_after = std::fs::read(&src_path).expect("re-read src");
        assert_eq!(
            src_after, payload,
            "writing to clone must not affect source"
        );
    }

    /// `reflink_or_copy` falls back to a byte copy when the source path
    /// can be read but the FS doesn't support reflinks. We can't easily
    /// force EOPNOTSUPP on macOS APFS (it always works), so this test
    /// exercises the *Copied* path on Linux ext4 (where `FICLONE`
    /// returns EOPNOTSUPP) and is skipped elsewhere.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_falls_back_to_copy_on_ext4() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let src_path = dir.path().join("src.bin");
        let dst_path = dir.path().join("dst.bin");
        std::fs::write(&src_path, b"hello").expect("write src");
        let strategy = reflink_or_copy(&src_path, &dst_path).expect("clone or copy");
        assert!(matches!(
            strategy,
            CloneStrategy::Reflink | CloneStrategy::Copied
        ));
        let read = std::fs::read(&dst_path).expect("read dst");
        assert_eq!(read, b"hello");
    }
}
