//! Reflink (copy-on-write) file cloning primitives.
//!
//! Plan 53 / Sprint 47 / Plan D: APFS Copy-on-Write for Apple Container
//! templates. Cloning a 1 GiB ext4 rootfs via `clonefile(2)` on macOS
//! takes ~constant time regardless of file size, since APFS only writes
//! new metadata and shares the underlying blocks until either side writes.
//! The same shape works on Linux via the `FICLONE` ioctl on btrfs/xfs/
//! overlayfs — those filesystems also have block-level CoW. ext4 returns
//! `EOPNOTSUPP` (the Linux-on-Lima default), so the caller falls back to
//! a regular byte copy.
//!
//! See ADR-002 §"Trust layers" for the security context (the cloned ext4
//! is the L3 rootfs; per-instance writes diverge into the clone's blocks
//! and never touch the template) and plan 53 §"Plan D" for the design.

use std::io;
use std::path::Path;

use anyhow::{Context, Result};

/// Reflink-clone a rootfs file for per-instance use.
///
/// Plan 53 Plan D: when starting a VM from a template (or any time
/// concurrent instances need their own writable rootfs), call this
/// instead of pointing the hypervisor at the source directly. The
/// clone shares blocks with the source until either side writes, so
/// on APFS / btrfs / xfs the operation is O(1) wall-clock regardless
/// of rootfs size. On filesystems without reflink support (ext4 in
/// the default Lima VM, NTFS, etc.) it falls back to a byte copy.
///
/// `src` must exist; `dst` must not. The destination's parent
/// directory is created if it doesn't already exist.
///
/// Apple VZ and Firecracker each expect a running VM to own its disk
/// image — sharing a rootfs path between two concurrent VMs makes
/// the second start fail. This helper is the seam where that
/// per-instance ownership is created.
#[tracing::instrument(skip_all, fields(src = %src.display(), dst = %dst.display()))]
pub fn clone_rootfs_for_instance(src: &Path, dst: &Path) -> Result<CloneStrategy> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory for {}", dst.display()))?;
    }
    let strategy = reflink_or_copy(src, dst)
        .with_context(|| format!("cloning rootfs {} -> {}", src.display(), dst.display()))?;
    tracing::debug!(?strategy, "rootfs clone complete");
    Ok(strategy)
}

/// What strategy [`reflink_or_copy`] used to materialize the destination.
///
/// `Reflink` is the fast path (O(1) metadata operation, blocks shared
/// until written). `Copied` is the byte-copy fallback that fires when
/// the filesystem doesn't support reflinks (ext4 without explicit
/// support, NTFS on Windows, network mounts, cross-volume copies on
/// APFS, etc.).
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
            std::fs::copy(src, dst)?;
            Ok(CloneStrategy::Copied)
        }
        Err(e) => Err(e),
    }
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
        let rc = unsafe { libc::ioctl(dst_fd.as_raw_fd(), FICLONE, src_fd.as_raw_fd()) };
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

    /// On macOS with an APFS-backed `TMPDIR` (the default), `clonefile`
    /// always works. The test asserts the fast path was taken and that
    /// writes to the clone don't tamper the source.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_clonefile_creates_independent_copy() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let src_path = dir.path().join("src.bin");
        let dst_path = dir.path().join("dst.bin");
        // 1 MiB of arbitrary bytes — small enough to keep the test fast,
        // large enough that "block-level CoW" is the only way to hit the
        // expected timing on real APFS volumes.
        let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src_path, &payload).expect("write src");

        let strategy =
            reflink_or_copy(&src_path, &dst_path).expect("reflink_or_copy on macOS APFS tempdir");
        assert_eq!(strategy, CloneStrategy::Reflink);

        // The clone has the same contents as the source.
        let cloned = std::fs::read(&dst_path).expect("read clone");
        assert_eq!(cloned, payload, "clone must byte-equal source");

        // Writing to the clone does not mutate the source. APFS CoW
        // diverges blocks at the first write to either side.
        std::fs::write(&dst_path, b"clone-only payload").expect("write clone");
        let src_after = std::fs::read(&src_path).expect("re-read src");
        assert_eq!(
            src_after, payload,
            "writing to clone must not affect source"
        );
    }

    /// `reflink_or_err` errors `EEXIST` if the destination already
    /// exists — both on macOS (`clonefile` rejects existing dst) and on
    /// Linux (we call `create_new(true)`). The test exercises the
    /// real-OS surface, not just the helper logic.
    #[test]
    fn reflink_or_err_refuses_existing_destination() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let src_path = dir.path().join("src.bin");
        let dst_path = dir.path().join("dst.bin");
        std::fs::write(&src_path, b"src content").expect("write src");
        std::fs::write(&dst_path, b"existing").expect("write dst");

        let result = reflink_or_err(&src_path, &dst_path);
        // Either AlreadyExists (Linux create_new) or "File exists"
        // wrapped from clonefile's EEXIST. Both are surfacings of the
        // same invariant: never silently overwrite.
        assert!(result.is_err());
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
        // /tmp on Linux CI runners is usually ext4 or tmpfs. tmpfs
        // does support FICLONE (Linux 5.10+); ext4 doesn't unless
        // mounted with explicit reflink support. We accept either
        // outcome and just assert the helper succeeded.
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
