//! C ABI exports — MUST match `include/fs_ext4.h` exactly. Consumers
//! link `libfs_ext4.a` and #include that header; any signature change
//! here requires the header to change in lockstep.
//!
//! Phase 1 (read-only) surface:
//! - fs_ext4_mount(device_path) -> *mut fs_ext4_fs_t
//! - fs_ext4_mount_with_callbacks(cfg) -> *mut fs_ext4_fs_t
//! - fs_ext4_umount(fs)
//! - fs_ext4_get_volume_info(fs, info) -> int
//! - fs_ext4_stat(fs, path, attr) -> int
//! - fs_ext4_dir_open(fs, path) -> *mut iter
//! - fs_ext4_dir_next(iter) -> *const dirent
//! - fs_ext4_dir_close(iter)
//! - fs_ext4_read_file(fs, ...) -> i64 (extents + inline_data)
//! - fs_ext4_readlink(fs, path, buf, bufsize) -> int
//! - fs_ext4_listxattr(fs, path, buf, bufsize) -> i64
//! - fs_ext4_getxattr(fs, path, name, buf, bufsize) -> i64
//! - fs_ext4_last_error() -> *const c_char
//! - fs_ext4_last_errno() -> c_int          (POSIX errno companion to last_error)
//!
//! Phase 4 (write path, in progress):
//! - fs_ext4_mount_rw(device_path) -> *mut fs_ext4_fs_t
//! - fs_ext4_mount_rw_with_callbacks(cfg) -> *mut fs_ext4_fs_t  (RW via FSKit-style read+write callbacks)
//! - fs_ext4_truncate(fs, path, new_size) -> int (shrink + sparse grow)
//! - fs_ext4_symlink(fs, target, linkpath) -> u32 inode (fast + slow path)
//! - fs_ext4_chmod(fs, path, mode) -> int
//! - fs_ext4_chown(fs, path, uid, gid) -> int
//! - fs_ext4_utimens(fs, path, atime_sec, atime_nsec, mtime_sec, mtime_nsec) -> int
//! - fs_ext4_unlink(fs, path) -> int
//! - fs_ext4_write_file(fs, path, data, len) -> i64 (save-as replace body)
//!
//! Memory ownership rules (from ntfsbridge precedent, documented in docs/ext4-rs-capi.md):
//! - `fs_ext4_fs_t*` is owned by the caller. Freed via `fs_ext4_umount`
//!   (use for both `mount`, `mount_with_callbacks`, and `mount_rw` handles).
//! - `fs_ext4_dir_iter_t*` is owned by the caller. Freed via `fs_ext4_dir_close`.
//! - `fs_ext4_dir_next` returns a pointer into the iterator's internal buffer;
//!   valid until the next `fs_ext4_dir_next` or `fs_ext4_dir_close` call.
//! - `fs_ext4_last_error` / `fs_ext4_last_errno` read thread-local
//!   storage; valid until the next FFI call on the same thread.

#![allow(non_camel_case_types)]
// Module-level docs (above) cover the FFI memory-ownership contract for
// every exported unsafe fn; per-function `# Safety` sections would be
// near-duplicates.
#![allow(clippy::missing_safety_doc)]

use crate::block_io::{BlockDevice, CallbackDevice, FileDevice};
use crate::dir::{self, DirBlockIter, DirEntryType};
use crate::error::errno::{EINVAL, EISDIR, ENAMETOOLONG, ENOENT, ENOSYS, ENOTDIR};
use crate::error::{Error, Result};
use crate::extent;
use crate::features;
use crate::file_io;
use crate::fs::Filesystem;
use crate::inode::{Inode, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK};
use crate::path as path_mod;
use crate::xattr;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

// ===========================================================================
// Thread-local last error
// ===========================================================================

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
    static LAST_ERRNO: RefCell<c_int> = const { RefCell::new(0) };
}

fn set_last_error<E: std::fmt::Display>(e: E) {
    let msg = format!("{e}");
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() =
            CString::new(msg).unwrap_or_else(|_| CString::new("unknown error").unwrap());
    });
}

fn set_last_errno(errno: c_int) {
    LAST_ERRNO.with(|cell| *cell.borrow_mut() = errno);
}

/// Record both the error string (with context) and the POSIX errno.
/// Call this instead of `set_last_error` whenever the source is an `Error`.
fn set_err_from(err: &Error, context: &str) {
    set_last_error(format!("{context}: {err}"));
    set_last_errno(err.to_errno());
}

/// Record a string message and an explicit errno. Use for validation failures
/// (null args, wrong file type) where there is no underlying `Error`.
fn set_err_msg(msg: &str, errno: c_int) {
    set_last_error(msg);
    set_last_errno(errno);
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = CString::new("").unwrap();
    });
    LAST_ERRNO.with(|cell| *cell.borrow_mut() = 0);
}

/// Wrap an FFI body in `catch_unwind`. If the body panics, record the panic
/// message in `last_error` and return `fail`. This prevents unwinding across
/// the C ABI boundary (undefined behaviour).
fn ffi_guard<T>(fail: T, body: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    match std::panic::catch_unwind(body) {
        Ok(v) => v,
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&'static str>() {
                format!("panic: {s}")
            } else if let Some(s) = panic.downcast_ref::<String>() {
                format!("panic: {s}")
            } else {
                "panic: (non-string payload)".to_string()
            };
            set_err_msg(&msg, crate::error::errno::EIO);
            fail
        }
    }
}

/// Get the last error message for the current thread.
/// Returns a pointer valid until the next FFI call on this thread.
#[no_mangle]
pub extern "C" fn fs_ext4_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| cell.borrow().as_ptr())
}

/// Get the POSIX errno for the last failed FFI call on this thread.
/// Returns 0 if the last call succeeded (or no call has been made yet).
/// Codes: ENOENT (2), EIO (5), ENOTDIR (20), EINVAL (22), ENOTSUP (45),
/// or any errno surfaced by the underlying I/O layer.
#[no_mangle]
pub extern "C" fn fs_ext4_last_errno() -> c_int {
    LAST_ERRNO.with(|cell| *cell.borrow())
}

// ===========================================================================
// ABI types — MUST match include/fs_ext4.h
// ===========================================================================

/// File type (matches `fs_ext4_file_type_t` in the header).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum fs_ext4_file_type_t {
    Unknown = 0,
    RegFile = 1,
    Dir = 2,
    ChrDev = 3,
    BlkDev = 4,
    Fifo = 5,
    Sock = 6,
    Symlink = 7,
}

/// File/directory attributes (matches `fs_ext4_attr_t`).
#[repr(C)]
pub struct fs_ext4_attr_t {
    pub inode: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub mtime: u32,
    pub ctime: u32,
    pub crtime: u32,
    pub link_count: u16,
    pub file_type: fs_ext4_file_type_t,
    /// Sub-second nanoseconds for atime/mtime/ctime/crtime (0 for old inodes).
    pub atime_nsec: u32,
    pub mtime_nsec: u32,
    pub ctime_nsec: u32,
    pub crtime_nsec: u32,
    /// On-disk `i_flags` (e2_flags / FS_IOC_GETFLAGS convention).
    pub inode_flags: u32,
    /// `i_generation` — NFS stale-handle counter.
    pub generation: u32,
    /// `i_blocks` in 512-byte units (matches `st_blocks` from POSIX stat).
    pub blocks_512: u64,
}

/// Directory entry (matches `fs_ext4_dirent_t`).
#[repr(C)]
pub struct fs_ext4_dirent_t {
    pub inode: u32,
    pub file_type: u8,
    pub name_len: u8,
    pub name: [c_char; 256],
}

/// Volume info (matches `fs_ext4_volume_info_t`). Layout is part of
/// the FFI ABI; new fields land at the end so existing zero-init
/// memcpy callers stay valid. Anything that derives from the on-disk
/// superblock can be added here — long-term goal is to give callers
/// everything they could possibly want to surface in a UI without
/// having to re-parse the superblock themselves.
#[repr(C)]
pub struct fs_ext4_volume_info_t {
    /* ----- Identity ----- */
    pub volume_name: [c_char; 16],
    /// Raw 16-byte UUID. Caller formats as 8-4-4-4-12 hyphenated hex
    /// to match comparable inspection tools.
    pub uuid: [u8; 16],
    /// Last mount path the kernel wrote into `s_last_mounted` (64
    /// bytes, NUL-terminated). Empty on a freshly mkfs'd FS.
    pub last_mounted: [c_char; 64],

    /* ----- Sizing ----- */
    pub block_size: u32,
    pub total_blocks: u64,
    pub free_blocks: u64,
    /// `s_r_blocks_count` — blocks reserved for the superuser (the
    /// "root reserve", typically ~5%). Explains the gap between
    /// `free_blocks` and what `df` reports as available to a regular
    /// user.
    pub reserved_blocks: u64,
    pub total_inodes: u32,
    pub free_inodes: u32,
    pub inode_size: u16,
    /// First non-reserved inode (s_first_ino, dynamic-rev only;
    /// 11 on legacy filesystems).
    pub first_inode: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,

    /* ----- Provenance + capabilities ----- */
    /// 0=Linux, 1=Hurd, 2=Masix, 3=FreeBSD, 4=Lites.
    pub creator_os: u32,
    pub rev_level: u32,
    pub minor_rev_level: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    /// Block-group descriptor size: 32 or 64 (64 when 64BIT incompat
    /// feature is set).
    pub desc_size: u16,
    pub default_hash_version: u8,

    /* ----- Lifecycle / health ----- */
    /// `s_state`. Bit 0 (EXT4_VALID_FS) = cleanly unmounted; bit 1
    /// (EXT4_ERROR_FS) = errors detected; bit 2 (EXT4_ORPHAN_FS) =
    /// orphans pending recovery.
    pub state: u16,
    /// `s_errors`. Kernel error policy: 1=continue, 2=remount-ro,
    /// 3=panic.
    pub errors_behavior: u16,
    /// `s_mtime` — last mount time (unix epoch seconds).
    pub last_mount_time: u32,
    /// `s_wtime` — last write time (unix epoch seconds).
    pub last_write_time: u32,
    /// `s_lastcheck` — last fsck pass (unix epoch seconds).
    pub last_check_time: u32,
    /// `s_checkinterval` — seconds between forced fscks; 0 disables
    /// time-based forced fsck.
    pub check_interval: u32,
    /// `s_mnt_count` — mounts since last fsck.
    pub mount_count: u16,
    /// `s_max_mnt_count` — forced fsck after this many mounts; 0 =
    /// unlimited.
    pub max_mount_count: u16,
    pub def_resuid: u16,
    pub def_resgid: u16,

    /// `1` if the filesystem was NOT cleanly unmounted last time it was
    /// used (dirty) — the caller should surface this to the user and
    /// run fsck / journal replay before permitting writes. `0` if the
    /// filesystem is clean. Derived from `state` for caller convenience.
    pub mounted_dirty: u8,
}

/// Block device read callback (matches `fs_ext4_read_fn`).
pub type fs_ext4_read_fn = Option<
    unsafe extern "C" fn(context: *mut c_void, buf: *mut c_void, offset: u64, length: u64) -> c_int,
>;

/// Block device write callback (matches `fs_ext4_write_fn`). NULL when
/// mounting read-only. NEW in v0.1.3.
pub type fs_ext4_write_fn = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        buf: *const c_void,
        offset: u64,
        length: u64,
    ) -> c_int,
>;

/// Optional flush/fsync callback (matches `fs_ext4_flush_fn`). NULL means
/// the driver treats `flush()` as a no-op. NEW in v0.1.3.
pub type fs_ext4_flush_fn = Option<unsafe extern "C" fn(context: *mut c_void) -> c_int>;

/// Callback-based mount config (matches `fs_ext4_blockdev_cfg_t`).
///
/// `write` / `flush` were appended in v0.1.3 — `fs_ext4_mount_with_callbacks`
/// ignores them (still RO), `fs_ext4_mount_rw_with_callbacks` requires
/// `write` to be set.
#[repr(C)]
pub struct fs_ext4_blockdev_cfg_t {
    pub read: fs_ext4_read_fn,
    pub context: *mut c_void,
    pub size_bytes: u64,
    pub block_size: u32,
    pub write: fs_ext4_write_fn,
    pub flush: fs_ext4_flush_fn,
}

// ===========================================================================
// Opaque handle types
// ===========================================================================

/// Opaque mounted filesystem handle. The caller treats this as `fs_ext4_fs_t*`.
pub struct fs_ext4_fs_t {
    fs: Filesystem,
}

/// Opaque directory iterator handle. The caller treats this as `fs_ext4_dir_iter_t*`.
pub struct fs_ext4_dir_iter_t {
    /// Pre-collected entries (Phase 1 simplicity — streaming can come later).
    entries: Vec<fs_ext4_dirent_t>,
    /// Current position in `entries`.
    position: usize,
    /// Last returned entry — backing storage for the pointer returned from `_dir_next`.
    current: fs_ext4_dirent_t,
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Hard upper bound on accepted path/string length from FFI callers,
/// in bytes (NUL excluded). Matches Linux `PATH_MAX`. A C string longer
/// than this is treated as caller bug — `cstr_to_str` returns `""` so
/// downstream lookups land at a clearly-invalid empty path rather than
/// us walking a multi-megabyte buffer twice (CStr scan + UTF-8 scan).
pub(crate) const FFI_PATH_MAX: usize = 4096;

/// Convert a `*const c_char` to a Rust string. Returns empty string on
/// null, on lengths exceeding [`FFI_PATH_MAX`], or on invalid UTF-8.
///
/// The empty-on-failure return is intentional — it preserves the
/// established FFI contract (callers branch on `path.is_empty()` to
/// reject), and downstream path resolution treats `""` as ENOENT.
/// New strict callers that need to distinguish null vs non-UTF-8 vs
/// oversize should use [`cstr_to_str_strict`] instead.
unsafe fn cstr_to_str<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    let cstr = CStr::from_ptr(p);
    if cstr.to_bytes().len() > FFI_PATH_MAX {
        return "";
    }
    cstr.to_str().unwrap_or("")
}

/// Strict variant of [`cstr_to_str`]. Returns `Err` for null pointers,
/// strings longer than [`FFI_PATH_MAX`], or invalid UTF-8 — useful for
/// callers that want a distinct EILSEQ/EINVAL/ENOENT response instead
/// of the legacy "treat as ENOENT" behavior. Currently unused but
/// available for new entry points that want to be explicit.
#[allow(dead_code)]
unsafe fn cstr_to_str_strict<'a>(p: *const c_char) -> std::result::Result<&'a str, &'static str> {
    if p.is_null() {
        return Err("null pointer");
    }
    let cstr = CStr::from_ptr(p);
    if cstr.to_bytes().len() > FFI_PATH_MAX {
        return Err("string exceeds FFI_PATH_MAX");
    }
    cstr.to_str().map_err(|_| "invalid UTF-8")
}

/// Convert POSIX mode bits to `fs_ext4_file_type_t`.
fn mode_to_file_type(mode: u16) -> fs_ext4_file_type_t {
    match mode & S_IFMT {
        S_IFREG => fs_ext4_file_type_t::RegFile,
        S_IFDIR => fs_ext4_file_type_t::Dir,
        S_IFLNK => fs_ext4_file_type_t::Symlink,
        S_IFCHR => fs_ext4_file_type_t::ChrDev,
        S_IFBLK => fs_ext4_file_type_t::BlkDev,
        S_IFIFO => fs_ext4_file_type_t::Fifo,
        S_IFSOCK => fs_ext4_file_type_t::Sock,
        _ => fs_ext4_file_type_t::Unknown,
    }
}

/// Fill an `fs_ext4_attr_t` from an inode.
fn fill_attr(out: &mut fs_ext4_attr_t, ino: u32, inode: &Inode) {
    out.inode = ino;
    out.mode = inode.mode & 0x0FFF; // keep permission bits
    out.uid = inode.uid;
    out.gid = inode.gid;
    out.size = inode.size;
    out.atime = inode.atime;
    out.mtime = inode.mtime;
    out.ctime = inode.ctime;
    out.crtime = inode.crtime;
    out.link_count = inode.links_count;
    out.file_type = mode_to_file_type(inode.mode);
    out.atime_nsec = inode.atime_nsec;
    out.mtime_nsec = inode.mtime_nsec;
    out.ctime_nsec = inode.ctime_nsec;
    out.crtime_nsec = inode.crtime_nsec;
    out.inode_flags = inode.flags;
    out.generation = inode.generation;
    out.blocks_512 = inode.blocks;
}

// ===========================================================================
// Lifecycle
// ===========================================================================

/// Mount an ext4 filesystem from a device path. Returns NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mount(device_path: *const c_char) -> *mut fs_ext4_fs_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| {
            clear_last_error();
            let path = cstr_to_str(device_path);
            if path.is_empty() {
                set_err_msg("null or empty device_path", EINVAL);
                return std::ptr::null_mut();
            }

            let dev = match FileDevice::open(path) {
                Ok(d) => Arc::new(d) as Arc<dyn BlockDevice>,
                Err(e) => {
                    set_err_from(&e, &format!("open {path}"));
                    return std::ptr::null_mut();
                }
            };

            match Filesystem::mount(dev) {
                Ok(fs) => Box::into_raw(Box::new(fs_ext4_fs_t { fs })),
                Err(e) => {
                    set_err_from(&e, &format!("mount {path}"));
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

/// Mount via a caller-supplied read callback.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mount_with_callbacks(
    cfg: *const fs_ext4_blockdev_cfg_t,
) -> *mut fs_ext4_fs_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| mount_with_callbacks_inner(cfg)),
    )
}

unsafe fn mount_with_callbacks_inner(cfg: *const fs_ext4_blockdev_cfg_t) -> *mut fs_ext4_fs_t {
    clear_last_error();
    if cfg.is_null() {
        set_err_msg("null cfg", EINVAL);
        return std::ptr::null_mut();
    }
    let cfg = &*cfg;
    let Some(read_fn) = cfg.read else {
        set_err_msg("cfg.read is null", EINVAL);
        return std::ptr::null_mut();
    };

    // Wrap the C context + callback in a thread-safe closure.
    // The caller is responsible for context lifetime ≥ fs lifetime.
    // We store context as usize to make the closure Send+Sync; Swift/C side
    // is expected to keep the context pointer valid (FSKit guarantees serial
    // access from the extension's queue).
    let ctx_addr = cfg.context as usize;
    let size = cfg.size_bytes;

    let dev = CallbackDevice {
        size,
        read: Box::new(move |offset, buf| {
            let rc = unsafe {
                read_fn(
                    ctx_addr as *mut c_void,
                    buf.as_mut_ptr() as *mut c_void,
                    offset,
                    buf.len() as u64,
                )
            };
            if rc != 0 {
                Err(std::io::Error::other(format!("callback returned {rc}")))
            } else {
                Ok(())
            }
        }),
        // Swift-side callback mount is read-only for now (no write callback
        // plumbed through the C struct). Phase 4 writes go through a
        // different C entry point that accepts a write_fn.
        write: None,
        flush: None,
    };

    match Filesystem::mount(Arc::new(dev) as Arc<dyn BlockDevice>) {
        Ok(fs) => Box::into_raw(Box::new(fs_ext4_fs_t { fs })),
        Err(e) => {
            set_err_from(&e, "mount (callback)");
            std::ptr::null_mut()
        }
    }
}

/// Mount via an `FsCoreDevice` handle from a sister crate (`qcow2_open`,
/// `partitions_open_slice`, `fs_core_file_open`, …). Single entry point —
/// the inner device's `is_writable()` decides RO vs RW, so callers don't
/// need a `_rw` variant.
///
/// The handle's reference count is incremented; closing this mount via
/// `fs_ext4_umount` drops that reference. The C caller still owns its
/// own `*mut FsCoreDevice` and frees it independently via
/// `fs_core_device_close`.
///
/// Returns NULL on failure; consult `fs_ext4_last_error()` for detail.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mount_with_fs_core_device(
    handle: *mut fs_core::ffi::FsCoreDevice,
) -> *mut fs_ext4_fs_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| {
            clear_last_error();
            if handle.is_null() {
                set_err_msg("null fs_core handle", EINVAL);
                return std::ptr::null_mut();
            }
            // Borrow the handle's Arc<dyn fs_core::BlockDevice> and clone it
            // so the mount holds its own reference. The caller is free to
            // close their handle whenever they want.
            let inner = (*handle).inner().clone();
            let adapter = crate::fs_core_bridge::CoreDevice::new(inner);
            let dev: Arc<dyn BlockDevice> = Arc::new(adapter);

            match Filesystem::mount(dev) {
                Ok(fs) => Box::into_raw(Box::new(fs_ext4_fs_t { fs })),
                Err(e) => {
                    set_err_from(&e, "mount via fs_core handle");
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

/// Same as [`fs_ext4_mount_with_fs_core_device`] but defers journal replay
/// until the caller invokes [`fs_ext4_replay_journal_if_dirty`]. Use this
/// from FSKit `loadResource` paths where replaying mid-load can hang the
/// mount call — replay can run safely once the volume is fully active.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mount_with_fs_core_device_lazy(
    handle: *mut fs_core::ffi::FsCoreDevice,
) -> *mut fs_ext4_fs_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| {
            clear_last_error();
            if handle.is_null() {
                set_err_msg("null fs_core handle", EINVAL);
                return std::ptr::null_mut();
            }
            let inner = (*handle).inner().clone();
            let adapter = crate::fs_core_bridge::CoreDevice::new(inner);
            let dev: Arc<dyn BlockDevice> = Arc::new(adapter);

            match Filesystem::mount_lazy(dev) {
                Ok(fs) => Box::into_raw(Box::new(fs_ext4_fs_t { fs })),
                Err(e) => {
                    set_err_from(&e, "mount_lazy via fs_core handle");
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

/// Mount read-write via caller-supplied read+write callbacks. Companion to
/// `fs_ext4_mount_rw` for sandboxed consumers (FSKit, etc.) that own a
/// block-device resource but cannot open `/dev/diskN`. Both `cfg.read`
/// and `cfg.write` must be set; `cfg.flush` is optional. Returns NULL on
/// failure with errno set (EINVAL when callbacks / cfg are missing).
///
/// A successful mount replays a dirty journal before returning, just like
/// `fs_ext4_mount_rw` — the underlying `BlockDevice::is_writable()` is
/// `true` because a write callback is attached.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mount_rw_with_callbacks(
    cfg: *const fs_ext4_blockdev_cfg_t,
) -> *mut fs_ext4_fs_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| mount_rw_with_callbacks_inner(cfg)),
    )
}

unsafe fn mount_rw_with_callbacks_inner(cfg: *const fs_ext4_blockdev_cfg_t) -> *mut fs_ext4_fs_t {
    clear_last_error();
    if cfg.is_null() {
        set_err_msg("null cfg", EINVAL);
        return std::ptr::null_mut();
    }
    let cfg = &*cfg;
    let Some(read_fn) = cfg.read else {
        set_err_msg("cfg.read is null", EINVAL);
        return std::ptr::null_mut();
    };
    let Some(write_fn) = cfg.write else {
        set_err_msg("cfg.write is null (required for RW callback mount)", EINVAL);
        return std::ptr::null_mut();
    };
    let flush_fn = cfg.flush; // Option — None is fine, treated as no-op.

    // Stash the C context as usize so the closures are Send+Sync. Caller
    // owns the context lifetime; FSKit guarantees serial access from the
    // extension's queue, which matches the synchronisation model the
    // rest of the driver assumes.
    let ctx_addr = cfg.context as usize;
    let size = cfg.size_bytes;

    let read_closure = move |offset: u64, buf: &mut [u8]| -> std::io::Result<()> {
        let rc = unsafe {
            read_fn(
                ctx_addr as *mut c_void,
                buf.as_mut_ptr() as *mut c_void,
                offset,
                buf.len() as u64,
            )
        };
        if rc != 0 {
            Err(std::io::Error::other(format!(
                "read callback returned {rc}"
            )))
        } else {
            Ok(())
        }
    };
    let write_closure = move |offset: u64, buf: &[u8]| -> std::io::Result<()> {
        let rc = unsafe {
            write_fn(
                ctx_addr as *mut c_void,
                buf.as_ptr() as *const c_void,
                offset,
                buf.len() as u64,
            )
        };
        if rc != 0 {
            Err(std::io::Error::other(format!(
                "write callback returned {rc}"
            )))
        } else {
            Ok(())
        }
    };
    let flush_closure: Option<crate::block_io::FlushCb> = flush_fn.map(|f| {
        let cb: crate::block_io::FlushCb = Box::new(move || -> std::io::Result<()> {
            let rc = unsafe { f(ctx_addr as *mut c_void) };
            if rc != 0 {
                Err(std::io::Error::other(format!(
                    "flush callback returned {rc}"
                )))
            } else {
                Ok(())
            }
        });
        cb
    });

    let dev = CallbackDevice {
        size,
        read: Box::new(read_closure),
        write: Some(Box::new(write_closure)),
        flush: flush_closure,
    };

    match Filesystem::mount(Arc::new(dev) as Arc<dyn BlockDevice>) {
        Ok(fs) => Box::into_raw(Box::new(fs_ext4_fs_t { fs })),
        Err(e) => {
            set_err_from(&e, "mount_rw (callback)");
            std::ptr::null_mut()
        }
    }
}

/// Mount RW via callbacks WITHOUT performing journal replay automatically.
/// Same semantics as `fs_ext4_mount_rw_with_callbacks` except a dirty
/// journal is recorded but NOT replayed during this call. Use this when
/// the consumer is in a context where its write callback can't service
/// writes yet (e.g. inside FSKit's `loadResource`, before the kernel opens
/// the writable FD on `FSBlockDeviceResource`).
///
/// After mount, call `fs_ext4_replay_journal_if_dirty(fs)` once the
/// consumer's write path is ready.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mount_rw_with_callbacks_lazy(
    cfg: *const fs_ext4_blockdev_cfg_t,
) -> *mut fs_ext4_fs_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| mount_rw_with_callbacks_lazy_inner(cfg)),
    )
}

unsafe fn mount_rw_with_callbacks_lazy_inner(
    cfg: *const fs_ext4_blockdev_cfg_t,
) -> *mut fs_ext4_fs_t {
    clear_last_error();
    if cfg.is_null() {
        set_err_msg("null cfg", EINVAL);
        return std::ptr::null_mut();
    }
    let cfg = &*cfg;
    let Some(read_fn) = cfg.read else {
        set_err_msg("cfg.read is null", EINVAL);
        return std::ptr::null_mut();
    };
    let Some(write_fn) = cfg.write else {
        set_err_msg("cfg.write is null (required for RW callback mount)", EINVAL);
        return std::ptr::null_mut();
    };
    let flush_fn = cfg.flush;

    let ctx_addr = cfg.context as usize;
    let size = cfg.size_bytes;

    let read_closure = move |offset: u64, buf: &mut [u8]| -> std::io::Result<()> {
        let rc = unsafe {
            read_fn(
                ctx_addr as *mut c_void,
                buf.as_mut_ptr() as *mut c_void,
                offset,
                buf.len() as u64,
            )
        };
        if rc != 0 {
            Err(std::io::Error::other(format!(
                "read callback returned {rc}"
            )))
        } else {
            Ok(())
        }
    };
    let write_closure = move |offset: u64, buf: &[u8]| -> std::io::Result<()> {
        let rc = unsafe {
            write_fn(
                ctx_addr as *mut c_void,
                buf.as_ptr() as *const c_void,
                offset,
                buf.len() as u64,
            )
        };
        if rc != 0 {
            Err(std::io::Error::other(format!(
                "write callback returned {rc}"
            )))
        } else {
            Ok(())
        }
    };
    let flush_closure: Option<crate::block_io::FlushCb> = flush_fn.map(|f| {
        let cb: crate::block_io::FlushCb = Box::new(move || -> std::io::Result<()> {
            let rc = unsafe { f(ctx_addr as *mut c_void) };
            if rc != 0 {
                Err(std::io::Error::other(format!(
                    "flush callback returned {rc}"
                )))
            } else {
                Ok(())
            }
        });
        cb
    });

    let dev = CallbackDevice {
        size,
        read: Box::new(read_closure),
        write: Some(Box::new(write_closure)),
        flush: flush_closure,
    };

    match Filesystem::mount_lazy(Arc::new(dev) as Arc<dyn BlockDevice>) {
        Ok(fs) => Box::into_raw(Box::new(fs_ext4_fs_t { fs })),
        Err(e) => {
            set_err_from(&e, "mount_rw_lazy (callback)");
            std::ptr::null_mut()
        }
    }
}

/// Replay the JBD2 journal on `fs` now if it is dirty. Idempotent — safe to
/// call on a clean volume (returns 0, performs no writes). Returns 0 on
/// success or already-clean, -1 on failure (call `fs_ext4_last_error` /
/// `fs_ext4_last_errno` for details). Pairs with
/// `fs_ext4_mount_rw_with_callbacks_lazy`; calling this on a handle that
/// was eager-mounted is a no-op (journal already clean) and returns 0.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_replay_journal_if_dirty(fs: *mut fs_ext4_fs_t) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() {
                set_err_msg("null fs handle", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            match fs_ref.replay_journal_if_dirty() {
                Ok(_) => 0,
                Err(e) => {
                    set_err_from(&e, "replay_journal_if_dirty");
                    -1
                }
            }
        }),
    )
}

/// Unmount and free the filesystem handle.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_umount(fs: *mut fs_ext4_fs_t) {
    ffi_guard(
        (),
        AssertUnwindSafe(|| {
            if !fs.is_null() {
                drop(Box::from_raw(fs));
            }
        }),
    )
}

// ===========================================================================
// Volume info
// ===========================================================================

/// Fill `info` with volume statistics. Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_get_volume_info(
    fs: *mut fs_ext4_fs_t,
    info: *mut fs_ext4_volume_info_t,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || info.is_null() {
                set_err_msg("null fs or info", EINVAL);
                return -1;
            }
            let fs = &(*fs).fs;
            let info = &mut *info;

            // Zero the struct first so any field we don't explicitly
            // populate (e.g. `last_mounted` when the FS was never
            // mounted) reads as all-zero / NUL-terminated empty.
            std::ptr::write_bytes(info as *mut fs_ext4_volume_info_t, 0, 1);

            // ----- Identity -----
            // Volume name (up to 16 bytes incl. NUL).
            let name_bytes = fs.sb.volume_name.as_bytes();
            let copy_len = name_bytes.len().min(15);
            for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
                info.volume_name[i] = b as c_char;
            }
            info.volume_name[copy_len] = 0;
            info.uuid = fs.sb.uuid;
            // last_mounted (up to 64 bytes incl. NUL). Already
            // truncated by the parser to a printable substring.
            let lm_bytes = fs.sb.last_mounted.as_bytes();
            let lm_copy = lm_bytes.len().min(63);
            for (i, &b) in lm_bytes[..lm_copy].iter().enumerate() {
                info.last_mounted[i] = b as c_char;
            }
            info.last_mounted[lm_copy] = 0;

            // ----- Sizing -----
            info.block_size = fs.sb.block_size();
            info.total_blocks = fs.sb.blocks_count;
            info.free_blocks = fs.sb.free_blocks_count;
            info.reserved_blocks = fs.sb.r_blocks_count;
            info.total_inodes = fs.sb.inodes_count;
            info.free_inodes = fs.sb.free_inodes_count;
            info.inode_size = fs.sb.inode_size;
            info.first_inode = fs.sb.first_inode;
            info.blocks_per_group = fs.sb.blocks_per_group;
            info.inodes_per_group = fs.sb.inodes_per_group;

            // ----- Provenance + capabilities -----
            info.creator_os = fs.sb.creator_os;
            info.rev_level = fs.sb.rev_level;
            info.minor_rev_level = fs.sb.minor_rev_level;
            info.feature_compat = fs.sb.feature_compat;
            info.feature_incompat = fs.sb.feature_incompat;
            info.feature_ro_compat = fs.sb.feature_ro_compat;
            info.desc_size = fs.sb.desc_size;
            info.default_hash_version = fs.sb.default_hash_version;

            // ----- Lifecycle / health -----
            info.state = fs.sb.state;
            info.errors_behavior = fs.sb.errors_behavior;
            info.last_mount_time = fs.sb.mtime;
            info.last_write_time = fs.sb.wtime;
            info.last_check_time = fs.sb.lastcheck;
            info.check_interval = fs.sb.checkinterval;
            info.mount_count = fs.sb.mnt_count;
            info.max_mount_count = fs.sb.max_mnt_count;
            info.def_resuid = fs.sb.def_resuid;
            info.def_resgid = fs.sb.def_resgid;

            info.mounted_dirty = if fs.sb.is_clean() { 0 } else { 1 };

            0
        }),
    )
}

// ===========================================================================
// Stat / readdir / read — STUBBED until dir.rs + extent.rs land
// ===========================================================================

/// Resolve a path to an inode number via `path::lookup`.
///
/// Each intermediate inode read goes through `Filesystem::read_inode_verified`
/// so the path-walk surfaces `Error::BadChecksum` if any directory inode is
/// corrupt (when `RO_COMPAT_METADATA_CSUM` is enabled).
fn resolve_path(fs: &Filesystem, path: &str) -> Result<u32> {
    let mut reader = |ino: u32| fs.read_inode_verified(ino).map(|(inode, _)| inode);
    let ino = path_mod::lookup_with_csum(fs.dev.as_ref(), &fs.sb, &mut reader, path, &fs.csum)?;

    // POSIX: a trailing slash implies the caller expects a directory. If the
    // resolved target is not a directory, surface ENOTDIR. `path::lookup`
    // drops trailing empty components so this has to be re-checked here.
    // Root (`/`) short-circuits trivially since inode 2 is always a dir.
    if path.ends_with('/') && path != "/" {
        let (inode, _raw) = fs.read_inode_verified(ino)?;
        if !inode.is_dir() {
            return Err(Error::NotADirectory);
        }
    }
    Ok(ino)
}

/// Stat a path. Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_stat(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    attr: *mut fs_ext4_attr_t,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() || attr.is_null() {
                set_err_msg("null fs, path, or attr", EINVAL);
                return -1;
            }
            let fs = &(*fs).fs;
            let path = cstr_to_str(path);
            let attr = &mut *attr;

            let ino = match resolve_path(fs, path) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("stat {path}"));
                    return -1;
                }
            };

            let (inode, _raw) = match fs.read_inode_verified(ino) {
                Ok(p) => p,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return -1;
                }
            };

            fill_attr(attr, ino, &inode);
            0
        }),
    )
}

/// Open a directory for iteration. Returns NULL on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_dir_open(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
) -> *mut fs_ext4_dir_iter_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs or path", EINVAL);
                return std::ptr::null_mut();
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);

            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("dir_open {path_str}"));
                    return std::ptr::null_mut();
                }
            };
            let (inode, _raw) = match fs_ref.read_inode_verified(ino) {
                Ok(p) => p,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return std::ptr::null_mut();
                }
            };
            if !inode.is_dir() {
                set_err_msg(&format!("dir_open {path_str}: not a directory"), ENOTDIR);
                return std::ptr::null_mut();
            }

            // Collect entries from all dir data blocks.
            let entries = match collect_dir_entries(fs_ref, &inode) {
                Ok(e) => e,
                Err(e) => {
                    set_err_from(&e, &format!("read directory {path_str}"));
                    return std::ptr::null_mut();
                }
            };

            let iter = Box::new(fs_ext4_dir_iter_t {
                entries,
                position: 0,
                current: std::mem::zeroed(),
            });
            Box::into_raw(iter)
        }),
    )
}

/// Read all directory entries from an inode into `fs_ext4_dirent_t`s.
fn collect_dir_entries(fs: &Filesystem, inode: &Inode) -> Result<Vec<fs_ext4_dirent_t>> {
    if !inode.has_extents() {
        return Err(Error::Corrupt("legacy (non-extent) dirs not yet supported"));
    }
    let block_size = fs.sb.block_size();
    let has_filetype = fs.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;

    // Bound on entries we'll buffer per directory open. Each
    // `fs_ext4_dirent_t` is ~264 bytes; 1M entries = ~264 MiB. A crafted
    // image with `inode.size` claiming gigabytes would otherwise allocate
    // proportionally, since the loop below grows `entries` straight from
    // on-disk content.
    const MAX_DIR_ENTRIES: usize = 1_000_000;
    let mut entries = Vec::new();

    // Handle inline-data dirs (tiny dirs stored inside the inode itself)
    if inode.has_inline_data() {
        for entry in DirBlockIter::new(&inode.block, has_filetype) {
            let e = entry?;
            if entries.len() >= MAX_DIR_ENTRIES {
                return Err(Error::Corrupt("dir entries exceed MAX_DIR_ENTRIES"));
            }
            entries.push(dir_entry_to_bridge(&e));
        }
        return Ok(entries);
    }

    let total_blocks = inode.size.div_ceil(block_size as u64);
    let mut block_buf = vec![0u8; block_size as usize];

    for logical in 0..total_blocks {
        let phys = match extent::map_logical(&inode.block, fs.dev.as_ref(), block_size, logical)? {
            Some(p) => p,
            None => continue, // sparse hole
        };
        fs.dev.read_at(phys * block_size as u64, &mut block_buf)?;

        for entry in DirBlockIter::new(&block_buf, has_filetype) {
            let e = entry?;
            if entries.len() >= MAX_DIR_ENTRIES {
                return Err(Error::Corrupt("dir entries exceed MAX_DIR_ENTRIES"));
            }
            entries.push(dir_entry_to_bridge(&e));
        }
    }

    Ok(entries)
}

/// Convert a parsed DirEntry to the C ABI dirent struct.
fn dir_entry_to_bridge(e: &dir::DirEntry) -> fs_ext4_dirent_t {
    let mut name = [0 as c_char; 256];
    let copy_len = e.name.len().min(255);
    for (i, &b) in e.name[..copy_len].iter().enumerate() {
        name[i] = b as c_char;
    }
    name[copy_len] = 0;

    let file_type = match e.file_type {
        DirEntryType::RegFile => 1u8,
        DirEntryType::Directory => 2,
        DirEntryType::CharDev => 3,
        DirEntryType::BlockDev => 4,
        DirEntryType::Fifo => 5,
        DirEntryType::Socket => 6,
        DirEntryType::Symlink => 7,
        DirEntryType::Unknown => 0,
    };

    fs_ext4_dirent_t {
        inode: e.inode,
        file_type,
        name_len: copy_len as u8,
        name,
    }
}

/// Get the next dir entry. Returns NULL at end or on error.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_dir_next(
    iter: *mut fs_ext4_dir_iter_t,
) -> *const fs_ext4_dirent_t {
    ffi_guard(
        std::ptr::null(),
        AssertUnwindSafe(|| {
            if iter.is_null() {
                return std::ptr::null();
            }
            let iter = &mut *iter;
            if iter.position >= iter.entries.len() {
                return std::ptr::null();
            }
            // Copy into the iterator's `current` buffer so the returned pointer
            // remains valid until the next _dir_next / _dir_close call.
            iter.current = fs_ext4_dirent_t {
                inode: iter.entries[iter.position].inode,
                file_type: iter.entries[iter.position].file_type,
                name_len: iter.entries[iter.position].name_len,
                name: iter.entries[iter.position].name,
            };
            iter.position += 1;
            &iter.current
        }),
    )
}

/// Close a directory iterator.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_dir_close(iter: *mut fs_ext4_dir_iter_t) {
    ffi_guard(
        (),
        AssertUnwindSafe(|| {
            if !iter.is_null() {
                drop(Box::from_raw(iter));
            }
        }),
    )
}

/// Read bytes from a file. Returns bytes read, or -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_read_file(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    buf: *mut c_void,
    offset: u64,
    length: u64,
) -> i64 {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() || buf.is_null() {
                set_err_msg("null fs, path, or buf", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);

            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("read_file {path_str}"));
                    return -1;
                }
            };
            let (inode, inode_raw) = match fs_ref.read_inode_verified(ino) {
                Ok(p) => p,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return -1;
                }
            };
            if !inode.is_file() {
                set_err_msg(&format!("read_file {path_str}: not a regular file"), EINVAL);
                return -1;
            }

            // Cap `length` against the file's actual size so a caller passing
            // `u64::MAX` doesn't fabricate an absurd output slice. The
            // downstream reader would refuse, but the slice descriptor itself
            // is built from caller-controlled bytes — undefined behaviour if
            // the caller's `buf` is smaller than `length`. Bounding here
            // keeps the slice within the file and within `usize`.
            let length = length.min(inode.size).min(usize::MAX as u64);
            let out = std::slice::from_raw_parts_mut(buf as *mut u8, length as usize);
            match file_io::read_with_raw_verified(
                fs_ref, &inode, &inode_raw, ino, offset, length, out,
            ) {
                Ok(n) => n as i64,
                Err(e) => {
                    set_err_from(&e, &format!("read_file {path_str}"));
                    -1
                }
            }
        }),
    )
}

/// Read a symlink target. Returns 0 on success, -1 on failure.
/// Handles both fast symlinks (target stored inline in i_block, size < 60 bytes)
/// and long symlinks (target stored in data blocks, read via file_io).
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_readlink(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    buf: *mut c_char,
    bufsize: usize,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() || buf.is_null() || bufsize == 0 {
                set_err_msg("null fs/path/buf or zero bufsize", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);

            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("readlink {path_str}"));
                    return -1;
                }
            };
            let (inode, _raw) = match fs_ref.read_inode_verified(ino) {
                Ok(p) => p,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return -1;
                }
            };
            if !inode.is_symlink() {
                set_err_msg(&format!("readlink {path_str}: not a symlink"), EINVAL);
                return -1;
            }

            // Fast symlink: target < 60 bytes, stored inline in i_block.
            // Long symlink: target stored in data blocks, read via file_io.
            let target = if inode.size < 60 {
                inode.block[..inode.size as usize].to_vec()
            } else {
                let mut out = vec![0u8; inode.size as usize];
                match file_io::read_verified(fs_ref, &inode, ino, 0, inode.size, &mut out) {
                    Ok(_) => out,
                    Err(e) => {
                        set_err_from(&e, &format!("readlink {path_str}"));
                        return -1;
                    }
                }
            };

            // Copy to output buffer with null terminator, truncating if needed.
            let copy_len = target.len().min(bufsize - 1);
            let out = std::slice::from_raw_parts_mut(buf as *mut u8, bufsize);
            out[..copy_len].copy_from_slice(&target[..copy_len]);
            out[copy_len] = 0;

            0
        }),
    )
}

// ===========================================================================
// Extended attributes
// ===========================================================================

/// List xattr names for a path. NUL-separated, fully-qualified.
/// Returns required total bytes (so callers can probe with NULL/0).
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_listxattr(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    buf: *mut c_char,
    bufsize: usize,
) -> i64 {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs or path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);

            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("listxattr {path_str}"));
                    return -1;
                }
            };
            let (inode, inode_raw) = match fs_ref.read_inode_verified(ino) {
                Ok(p) => p,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return -1;
                }
            };

            let entries = match xattr::read_all(
                fs_ref.dev.as_ref(),
                &inode,
                &inode_raw,
                fs_ref.sb.inode_size,
                fs_ref.sb.block_size(),
            ) {
                Ok(v) => v,
                Err(e) => {
                    set_err_from(&e, &format!("listxattr {path_str}"));
                    return -1;
                }
            };

            let required: usize = entries.iter().map(|e| e.name.len() + 1).sum();

            if !buf.is_null() && bufsize > 0 {
                let out = std::slice::from_raw_parts_mut(buf as *mut u8, bufsize);
                let mut pos = 0;
                for e in &entries {
                    let name_bytes = e.name.as_bytes();
                    let needed = name_bytes.len() + 1;
                    if pos + needed > bufsize {
                        break;
                    }
                    out[pos..pos + name_bytes.len()].copy_from_slice(name_bytes);
                    out[pos + name_bytes.len()] = 0;
                    pos += needed;
                }
            }

            required as i64
        }),
    )
}

/// Get a single xattr value by fully-qualified name.
/// Returns value size (so callers can probe with NULL/0), or -1 if missing / error.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_getxattr(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    name: *const c_char,
    buf: *mut c_void,
    bufsize: usize,
) -> i64 {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() || name.is_null() {
                set_err_msg("null fs, path, or name", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            let name_str = cstr_to_str(name);

            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("getxattr {path_str}"));
                    return -1;
                }
            };
            let (inode, inode_raw) = match fs_ref.read_inode_verified(ino) {
                Ok(p) => p,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return -1;
                }
            };

            let value = match xattr::get(
                fs_ref.dev.as_ref(),
                &inode,
                &inode_raw,
                fs_ref.sb.inode_size,
                fs_ref.sb.block_size(),
                name_str,
            ) {
                Ok(Some(v)) => v,
                Ok(None) => {
                    set_err_msg(
                        &format!("getxattr {path_str}: {name_str} not found"),
                        ENOENT,
                    );
                    return -1;
                }
                Err(e) => {
                    set_err_from(&e, &format!("getxattr {path_str} {name_str}"));
                    return -1;
                }
            };

            if !buf.is_null() && bufsize > 0 {
                let copy_len = value.len().min(bufsize);
                let out = std::slice::from_raw_parts_mut(buf as *mut u8, bufsize);
                out[..copy_len].copy_from_slice(&value[..copy_len]);
            }

            value.len() as i64
        }),
    )
}

// ===========================================================================
// Write path — Phase 4 surface. Currently only truncate-shrink is wired;
// create/unlink/write_file follow as the write path matures.
// ===========================================================================

/// Truncate a file to `new_size`. Only valid when the device was mounted
/// R/W (e.g. via `fs_ext4_mount_rw`). Returns 0 on success, -1 on failure
/// with details in `fs_ext4_last_error`.
///
/// Both directions are supported:
/// - **Shrink** (`new_size < inode.size`): frees the dropped extents,
///   updates block-bitmap + BGD + SB counters, patches i_size +
///   i_blocks + inode csum.
/// - **Sparse grow** (`new_size >= inode.size`): pure metadata update;
///   ext4's extent tree treats unmapped logical blocks as zero-filled
///   holes, so no block allocation happens. Only i_size, i_mtime,
///   i_ctime, and the inode checksum change.
///
/// Refuses directories (POSIX EISDIR); refuses symlinks and special
/// files (EINVAL).
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_truncate(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    new_size: u64,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("truncate {path_str}"));
                    return -1;
                }
            };
            // Type guard: truncating a directory corrupts it (frees data blocks,
            // loses . and .. entries). POSIX ftruncate(2) mandates EISDIR on dir.
            // Symlinks, devices, sockets are also not truncatable → EINVAL.
            let inode = match fs_ref.read_inode_verified(ino) {
                Ok((i, _)) => i,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return -1;
                }
            };
            if inode.is_dir() {
                set_err_msg(&format!("truncate {path_str}: is a directory"), EISDIR);
                return -1;
            }
            if !inode.is_file() {
                set_err_msg(&format!("truncate {path_str}: not a regular file"), EINVAL);
                return -1;
            }
            // Dispatch to grow (sparse) or shrink based on direction. At
            // equality either path works; grow wins since it only bumps
            // timestamps.
            let res = if new_size >= inode.size {
                fs_ref.apply_truncate_grow(ino, new_size)
            } else {
                fs_ref.apply_truncate_shrink(ino, new_size)
            };
            match res {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("truncate {path_str} -> {new_size}"));
                    -1
                }
            }
        }),
    )
}

/// Linux `fallocate(2)` mode flags. KEEP_SIZE, PUNCH_HOLE, and
/// ZERO_RANGE are implemented; COLLAPSE_RANGE / INSERT_RANGE return
/// ENOSYS.
pub const FS_EXT4_FALLOC_FL_KEEP_SIZE: c_int = 0x01;
pub const FS_EXT4_FALLOC_FL_PUNCH_HOLE: c_int = 0x02;
pub const FS_EXT4_FALLOC_FL_ZERO_RANGE: c_int = 0x10;

/// `fallocate(path, offset, len, flags)` — preallocate blocks, punch a
/// hole, or zero a range without writing actual data.
///
/// Supported `flags` combinations:
/// - `KEEP_SIZE` alone — preallocate blocks as uninitialized extents
///   (reads return zeros) without changing `i_size`.
/// - `PUNCH_HOLE | KEEP_SIZE` — free the data blocks underlying the
///   range; reads return zeros (sparse hole) thereafter. Linux
///   requires both bits; we follow the same convention.
/// - `ZERO_RANGE` (with or without `KEEP_SIZE`) — punch then re-allocate
///   as uninitialized extents in one call. `i_size` is preserved.
///
/// Anything else returns ENOSYS (78). v1 limits documented per
/// `Filesystem::apply_fallocate_punch_hole` and `apply_fallocate_keep_size`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_fallocate(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    offset: u64,
    len: u64,
    flags: c_int,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("fallocate {path_str}"));
                    return -1;
                }
            };
            // Flag dispatch. PUNCH_HOLE always implies KEEP_SIZE (Linux
            // requires both); we accept either spelling.
            let is_punch = flags & FS_EXT4_FALLOC_FL_PUNCH_HOLE != 0;
            let is_zero = flags & FS_EXT4_FALLOC_FL_ZERO_RANGE != 0;
            let is_keep = flags & FS_EXT4_FALLOC_FL_KEEP_SIZE != 0;
            let result = if is_zero {
                fs_ref.apply_fallocate_zero_range(ino, offset, len)
            } else if is_punch {
                if !is_keep {
                    set_err_msg("fallocate: PUNCH_HOLE requires KEEP_SIZE", EINVAL);
                    return -1;
                }
                fs_ref.apply_fallocate_punch_hole(ino, offset, len)
            } else if flags == FS_EXT4_FALLOC_FL_KEEP_SIZE {
                fs_ref.apply_fallocate_keep_size(ino, offset, len)
            } else {
                set_err_msg(
                    "fallocate: unsupported flag combination (KEEP_SIZE / PUNCH_HOLE+KEEP_SIZE / ZERO_RANGE only)",
                    ENOSYS,
                );
                return -1;
            };
            match result {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("fallocate {path_str} @{offset}+{len}"));
                    -1
                }
            }
        }),
    )
}

/// Remove a file entry at `path`. Requires a R/W mount.
///
/// Refuses directories (caller should use a future `fs_ext4_rmdir`).
/// Decrements `i_links_count`; if the count reaches zero the inode's data
/// blocks are freed, its bitmap slot is cleared, and the inode body is
/// zeroed with `i_dtime = now` (matching the kernel's unlink convention).
///
/// Returns 0 on success, -1 on failure with details in
/// `fs_ext4_last_error`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_unlink(fs: *mut fs_ext4_fs_t, path: *const c_char) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_unlink(path_str) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("unlink {path_str}"));
                    -1
                }
            }
        }),
    )
}

/// Create a new empty regular file at `path` with permission bits `mode`
/// (e.g. 0o644). Parent must exist and be a directory; path must not already
/// exist. Returns the allocated inode number on success (> 0), or 0 on failure
/// with details in `fs_ext4_last_error`.
///
/// We return `u32` rather than `c_int` so Swift sees a plain uint32_t —
/// matches the convention for other inode-returning exports.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_create(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    mode: u16,
) -> u32 {
    ffi_guard(
        0u32,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return 0u32;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_create(path_str, mode) {
                Ok(ino) => ino,
                Err(e) => {
                    set_err_from(&e, &format!("create {path_str}"));
                    0u32
                }
            }
        }),
    )
}

/// Replace the content of `path` with `len` bytes from `data`. The file
/// must already exist. Frees every existing extent, allocates one
/// contiguous run for the new bytes, writes the payload (zero-padded in
/// the last block), and updates size/mtime. Returns the new size on
/// success or -1 on failure.
///
/// This is the "save-as" path: atomic replacement of a file's body.
/// Appends, sparse writes, and partial overwrites are follow-up work.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_write_file(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    data: *const c_void,
    len: u64,
) -> i64 {
    ffi_guard(
        -1i64,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            if data.is_null() && len > 0 {
                set_err_msg("null data with non-zero len", EINVAL);
                return -1;
            }
            // Hard cap to defang a hostile or buggy caller passing
            // `len = u64::MAX`. Constructing `&[u8]` from raw parts with
            // a length larger than the caller's actual buffer is UB even
            // before any read happens. 1 GiB matches the apply_replace
            // working assumption (whole payload held in memory) without
            // forcing legitimate large writes to chunk.
            const MAX_WRITE_LEN: u64 = 1 << 30;
            if len > MAX_WRITE_LEN {
                set_err_msg(
                    &format!("write_file: len {len} exceeds {MAX_WRITE_LEN}"),
                    EINVAL,
                );
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            // Type guard at the capi level — mirrors fs_ext4_truncate so the
            // caller gets EISDIR/EINVAL instead of Error::Corrupt → EIO when
            // the target is the wrong kind of file.
            let ino = match resolve_path(fs_ref, path_str) {
                Ok(n) => n,
                Err(e) => {
                    set_err_from(&e, &format!("write_file {path_str}"));
                    return -1;
                }
            };
            let inode = match fs_ref.read_inode_verified(ino) {
                Ok((i, _)) => i,
                Err(e) => {
                    set_err_from(&e, &format!("read inode {ino}"));
                    return -1;
                }
            };
            if inode.is_dir() {
                set_err_msg(&format!("write_file {path_str}: is a directory"), EISDIR);
                return -1;
            }
            if !inode.is_file() {
                set_err_msg(
                    &format!("write_file {path_str}: not a regular file"),
                    EINVAL,
                );
                return -1;
            }
            let slice: &[u8] = if len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(data as *const u8, len as usize)
            };
            match fs_ref.apply_replace_file_content(path_str, slice) {
                Ok(new_size) => new_size as i64,
                Err(e) => {
                    set_err_from(&e, &format!("write_file {path_str} ({len} bytes)"));
                    -1
                }
            }
        }),
    )
}

/// Positional write: splice `len` bytes from `data` into `path` at byte
/// `offset`. Allocates new physical blocks for any logical blocks not yet
/// mapped (sparse holes / past EOF). Existing mapped blocks are read-
/// modify-written for partial overlap; full-block writes go in fresh.
///
/// This is the streaming-write primitive — it costs O(len), not
/// O(filesize). The streaming write paths in FUSE / WinFsp / FSKit
/// adapters should use this instead of `fs_ext4_write_file` (which is
/// the "save-as" / whole-file-replace primitive).
///
/// Returns the new file size on success, -1 on failure (errno via
/// `fs_ext4_last_errno()`, message via `fs_ext4_last_error()`). The file
/// must already exist; create-then-pwrite is the standard streaming
/// pattern.
///
/// Hard cap on `len`: 1 GiB per call (matches `fs_ext4_write_file`).
/// Streaming writers should chunk above that — typical FS adapters
/// dispatch at most ~1 MiB anyway.
///
/// v1 limitations are documented on `Filesystem::apply_pwrite`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_pwrite(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    data: *const c_void,
    len: u64,
    offset: u64,
) -> i64 {
    ffi_guard(
        -1i64,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            if data.is_null() && len > 0 {
                set_err_msg("null data with non-zero len", EINVAL);
                return -1;
            }
            // Same hard cap as `fs_ext4_write_file` to defang a hostile
            // caller passing `len = u64::MAX` — constructing `&[u8]` from
            // raw parts with a length larger than the caller's buffer is
            // UB even before any read happens.
            const MAX_PWRITE_LEN: u64 = 1 << 30;
            if len > MAX_PWRITE_LEN {
                set_err_msg(
                    &format!("pwrite: len {len} exceeds {MAX_PWRITE_LEN}"),
                    EINVAL,
                );
                return -1;
            }
            // offset+len overflow: catch here so the FS-layer error has
            // a clear FFI-level message rather than "offset+len overflow"
            // surfaced from deep inside path handling.
            if offset.checked_add(len).is_none() {
                set_err_msg("pwrite: offset+len overflow", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            let slice: &[u8] = if len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(data as *const u8, len as usize)
            };
            match fs_ref.apply_pwrite(path_str, offset, slice) {
                Ok(new_size) => new_size as i64,
                Err(e) => {
                    set_err_from(&e, &format!("pwrite {path_str} @{offset}+{len}"));
                    -1
                }
            }
        }),
    )
}

/// Mount an ext4 filesystem read-write. Companion to `fs_ext4_mount`.
/// Returns NULL on failure. A successful mount will replay a dirty journal
/// before returning.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mount_rw(device_path: *const c_char) -> *mut fs_ext4_fs_t {
    ffi_guard(
        std::ptr::null_mut(),
        AssertUnwindSafe(|| {
            clear_last_error();
            let path = cstr_to_str(device_path);
            if path.is_empty() {
                set_err_msg("null or empty device_path", EINVAL);
                return std::ptr::null_mut();
            }
            let dev = match FileDevice::open_rw(path) {
                Ok(d) => Arc::new(d) as Arc<dyn BlockDevice>,
                Err(e) => {
                    set_err_from(&e, &format!("open_rw {path}"));
                    return std::ptr::null_mut();
                }
            };
            match Filesystem::mount(dev) {
                Ok(fs) => Box::into_raw(Box::new(fs_ext4_fs_t { fs })),
                Err(e) => {
                    set_err_from(&e, &format!("mount_rw {path}"));
                    std::ptr::null_mut()
                }
            }
        }),
    )
}

/// Create a hard link at `dst` pointing at the same inode as `src`.
/// Source must not be a directory; dest must not already exist; dest's
/// parent must be a directory. Increments the shared inode's
/// `i_links_count`. Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_link(
    fs: *mut fs_ext4_fs_t,
    src: *const c_char,
    dst: *const c_char,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || src.is_null() || dst.is_null() {
                set_err_msg("null fs/src/dst", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let src_str = cstr_to_str(src);
            let dst_str = cstr_to_str(dst);
            match fs_ref.apply_link(src_str, dst_str) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("link {src_str} -> {dst_str}"));
                    -1
                }
            }
        }),
    )
}

/// Rename / move `src` → `dst` within this mount. Works for files and
/// directories; cross-parent moves fix the moved dir's `..` entry and
/// adjust both parents' `i_links_count`. Dest must NOT already exist —
/// for atomic overwrite use `fs_ext4_rename2` with the
/// `FS_EXT4_RENAME_REPLACE` flag. Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_rename(
    fs: *mut fs_ext4_fs_t,
    src: *const c_char,
    dst: *const c_char,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || src.is_null() || dst.is_null() {
                set_err_msg("null fs/src/dst", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let src_str = cstr_to_str(src);
            let dst_str = cstr_to_str(dst);
            match fs_ref.apply_rename(src_str, dst_str, false) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("rename {src_str} -> {dst_str}"));
                    -1
                }
            }
        }),
    )
}

/// `fs_ext4_rename2` flag bits. `FS_EXT4_RENAME_REPLACE` enables
/// atomic overwrite of an existing destination — required to support
/// "Save As" / drag-drop-onto-existing on Windows / FUSE callers that
/// pass the equivalent of `RENAME_EXCHANGE`'s "replace" semantics.
/// Unknown flag bits are rejected with EINVAL so future flag additions
/// stay forward-compatible.
pub const FS_EXT4_RENAME_REPLACE: c_int = 0x01;

/// Rename / move `src` → `dst` within this mount, with explicit flags.
/// Currently the only flag is `FS_EXT4_RENAME_REPLACE` — when set, an
/// existing destination is atomically replaced (POSIX `rename(2)`
/// semantics): file→file overwrites the old file's data and frees its
/// inode (or decrements link count on a hardlinked target), empty-dir
/// → empty-dir overwrites the dropped subdir, and crossing the
/// file/directory boundary returns `EISDIR` / `ENOTDIR`. Without the
/// flag, behaves identically to `fs_ext4_rename`. Returns 0 on success,
/// -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_rename2(
    fs: *mut fs_ext4_fs_t,
    src: *const c_char,
    dst: *const c_char,
    flags: c_int,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || src.is_null() || dst.is_null() {
                set_err_msg("null fs/src/dst", EINVAL);
                return -1;
            }
            // Reject any flag bits we don't define so future additions
            // can be detected by callers via EINVAL probing.
            let known = FS_EXT4_RENAME_REPLACE;
            if flags & !known != 0 {
                set_err_msg("rename2: unknown flag bits", EINVAL);
                return -1;
            }
            let replace = flags & FS_EXT4_RENAME_REPLACE != 0;
            let fs_ref = &(*fs).fs;
            let src_str = cstr_to_str(src);
            let dst_str = cstr_to_str(dst);
            match fs_ref.apply_rename(src_str, dst_str, replace) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("rename2 {src_str} -> {dst_str}"));
                    -1
                }
            }
        }),
    )
}

/// Create a subdirectory at `path` with POSIX permission bits `mode` (low
/// 12 bits used; file-type bits are set automatically). Returns the new
/// directory's inode number on success, 0 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mkdir(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    mode: u16,
) -> u32 {
    ffi_guard(
        0u32,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return 0u32;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_mkdir(path_str, mode) {
                Ok(ino) => ino,
                Err(e) => {
                    set_err_from(&e, &format!("mkdir {path_str}"));
                    0u32
                }
            }
        }),
    )
}

/// Remove an empty directory at `path`. Fails if the directory contains
/// entries other than `.` and `..`. Returns 0 on success, -1 on failure
/// with details in `fs_ext4_last_error`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_rmdir(fs: *mut fs_ext4_fs_t, path: *const c_char) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_rmdir(path_str) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("rmdir {path_str}"));
                    -1
                }
            }
        }),
    )
}

/// Change the permission bits on `path`. Only the low 12 bits of `mode`
/// (suid/sgid/sticky + rwx/rwx/rwx) are applied; file-type bits (`S_IFMT`)
/// are preserved from the existing inode. Bumps `i_ctime`.
///
/// Returns 0 on success, -1 on failure with details in `fs_ext4_last_error`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_chmod(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    mode: u16,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_chmod(path_str, mode) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("chmod {path_str}"));
                    -1
                }
            }
        }),
    )
}

/// Change the owner of `path` to (`uid`, `gid`). Passing `u32::MAX` (0xFFFF_FFFF)
/// for either parameter leaves that value unchanged (matches Linux chown(2)
/// "-1 means leave alone" convention). Bumps `i_ctime`.
///
/// Returns 0 on success, -1 on failure with details in `fs_ext4_last_error`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_chown(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    uid: u32,
    gid: u32,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_chown(path_str, uid, gid) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("chown {path_str}"));
                    -1
                }
            }
        }),
    )
}

/// Create a special file: FIFO, socket, or character/block device.
///
/// `mode` must include the file-type bits plus permission bits, e.g.:
///   `0x1000 | 0644` for a FIFO (S_IFIFO), `0xC000 | 0666` for a socket,
///   `0x2000 | 0660` for a char device, `0x6000 | 0660` for a block device.
///
/// `major` / `minor` are device numbers for char/block devices; pass 0 for
/// FIFOs and sockets. Returns the new inode number on success, 0 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mknod(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    mode: u16,
    major: u32,
    minor: u32,
) -> u32 {
    ffi_guard(
        0u32,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return 0u32;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_mknod(path_str, mode, major, minor) {
                Ok(ino) => ino,
                Err(e) => {
                    set_err_from(&e, &format!("mknod {path_str}"));
                    0u32
                }
            }
        }),
    )
}

/// Set the `i_flags` word (FS_IOC_SETFLAGS) on `path`.
///
/// `flags` is the full new flags value. Common flags:
///   0x00000010  EXT4_IMMUTABLE_FL (cannot modify / rename / delete)
///   0x00000020  EXT4_APPEND_FL    (append-only)
///   0x00000040  EXT4_NODUMP_FL    (excluded from `dump`)
///   0x00000200  EXT4_NOATIME_FL   (no atime updates on read)
///
/// Bumps i_ctime. Returns 0 on success, -1 on failure.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_set_flags(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    flags: u32,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_set_flags(path_str, flags) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("set_flags {path_str}"));
                    -1
                }
            }
        }),
    )
}

/// Set the access + modification times on `path`. Each `*_sec` is the
/// POSIX seconds-since-epoch; pass `u32::MAX` (0xFFFF_FFFF) to leave a
/// given pair unchanged. `*_nsec` are the sub-second nanoseconds (written
/// only when i_extra_isize covers them). Bumps i_ctime.
///
/// Returns 0 on success, -1 on failure with details in
/// `fs_ext4_last_error`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_utimens(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    atime_sec: u32,
    atime_nsec: u32,
    mtime_sec: u32,
    mtime_nsec: u32,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() {
                set_err_msg("null fs/path", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            match fs_ref.apply_utimens(path_str, atime_sec, atime_nsec, mtime_sec, mtime_nsec) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("utimens {path_str}"));
                    -1
                }
            }
        }),
    )
}

/// Create a symbolic link at `linkpath` whose target is `target`. POSIX
/// `symlink(target, linkpath)` semantics: `target` is the arbitrary string
/// the symlink points to (can be absolute or relative, need not exist);
/// `linkpath` is the path where the symlink is created. Parent of
/// `linkpath` must exist and be a directory; `linkpath` itself must not
/// already exist.
///
/// Targets <60 bytes use the fast-symlink path (stored inline in the
/// inode's i_block area). Targets >=60 and <=4096 bytes use the slow path
/// (one fs block allocated, target stored there, single extent inserted).
/// Targets longer than 4096 (Linux PATH_MAX) return 0 with errno set to
/// ENAMETOOLONG via `fs_ext4_last_error`.
///
/// Returns the new inode number on success (> 0), or 0 on failure with
/// details in `fs_ext4_last_error`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_symlink(
    fs: *mut fs_ext4_fs_t,
    target: *const c_char,
    linkpath: *const c_char,
) -> u32 {
    ffi_guard(
        0u32,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || target.is_null() || linkpath.is_null() {
                set_err_msg("null fs/target/linkpath", EINVAL);
                return 0u32;
            }
            // Length-cap target/linkpath at FFI_PATH_MAX explicitly. The
            // generic `cstr_to_str` silently returns "" past the cap; for
            // symlink targets we want the ENAMETOOLONG distinction so that
            // a hostile caller can't fabricate a multi-megabyte slice and
            // an honest one with a 5000-byte target sees the right errno.
            let target_bytes = CStr::from_ptr(target).to_bytes();
            if target_bytes.len() > FFI_PATH_MAX {
                set_err_msg(
                    &format!(
                        "symlink target length {} exceeds FFI_PATH_MAX {FFI_PATH_MAX}",
                        target_bytes.len()
                    ),
                    ENAMETOOLONG,
                );
                return 0u32;
            }
            let linkpath_bytes = CStr::from_ptr(linkpath).to_bytes();
            if linkpath_bytes.len() > FFI_PATH_MAX {
                set_err_msg(
                    &format!(
                        "symlink linkpath length {} exceeds FFI_PATH_MAX {FFI_PATH_MAX}",
                        linkpath_bytes.len()
                    ),
                    ENAMETOOLONG,
                );
                return 0u32;
            }
            let fs_ref = &(*fs).fs;
            let target_str = cstr_to_str(target);
            let linkpath_str = cstr_to_str(linkpath);
            match fs_ref.apply_symlink(target_str, linkpath_str) {
                Ok(ino) => ino,
                Err(e) => {
                    set_err_from(&e, &format!("symlink {linkpath_str} -> {target_str}"));
                    0u32
                }
            }
        }),
    )
}

/// Remove the extended attribute `name` from the inode at `path`. `name`
/// must be fully-qualified (carry a known namespace prefix like `"user."`
/// or `"security."`). v1 scope: in-inode xattrs only; external-block
/// removal surfaces EINVAL until the slow path lands.
///
/// Returns 0 on success, -1 on failure with details in
/// `fs_ext4_last_error`. `fs_ext4_last_errno` codes: ENOENT if the name
/// isn't present, EINVAL on unknown prefix or external-block-only entry,
/// EROFS on a read-only mount.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_removexattr(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    name: *const c_char,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() || name.is_null() {
                set_err_msg("null fs/path/name", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            let name_str = cstr_to_str(name);
            match fs_ref.apply_removexattr(path_str, name_str) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("removexattr {path_str} {name_str}"));
                    -1
                }
            }
        }),
    )
}

/// Set (create or replace) the extended attribute `name` on `path` with
/// `value_len` bytes from `value`. `name` must be fully-qualified
/// (carry a known namespace prefix like "user.").
///
/// v1 scope: in-inode xattrs only. ENOSPC if the in-inode region is
/// too small; external-block spill is not implemented.
///
/// Returns 0 on success, -1 on failure with details in
/// `fs_ext4_last_error`. `fs_ext4_last_errno` codes: EINVAL on unknown
/// prefix or null args, ENAMETOOLONG on >255-byte suffix, ENOSPC on
/// in-inode overflow, EROFS on RO mount.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_setxattr(
    fs: *mut fs_ext4_fs_t,
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    value_len: usize,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || path.is_null() || name.is_null() {
                set_err_msg("null fs/path/name", EINVAL);
                return -1;
            }
            if value.is_null() && value_len > 0 {
                set_err_msg("null value with nonzero len", EINVAL);
                return -1;
            }
            // Cap `value_len` to defang oversize input. The kernel's
            // ext4 xattr value cap is one fs block (typically 4 KiB);
            // we use 64 KiB as a pragmatic ceiling that comfortably
            // exceeds real-world xattr usage but prevents a hostile
            // caller from triggering UB during slice construction.
            const MAX_XATTR_VALUE_LEN: usize = 64 * 1024;
            if value_len > MAX_XATTR_VALUE_LEN {
                set_err_msg(
                    &format!("setxattr: value_len {value_len} exceeds {MAX_XATTR_VALUE_LEN}"),
                    EINVAL,
                );
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let path_str = cstr_to_str(path);
            let name_str = cstr_to_str(name);
            let value_bytes = if value_len == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(value as *const u8, value_len)
            };
            match fs_ref.apply_setxattr(path_str, name_str, value_bytes) {
                Ok(()) => 0,
                Err(e) => {
                    set_err_from(&e, &format!("setxattr {path_str} {name_str}"));
                    -1
                }
            }
        }),
    )
}

// ===========================================================================
// mkfs (volume creation)
// ===========================================================================

/// Format a block device as ext4. The device is reached through the same
/// callback config used by `fs_ext4_mount_*_with_callbacks`; `cfg->write` and
/// `cfg->size_bytes` must be set. `label` is an optional NUL-terminated UTF-8
/// volume name (≤ 16 bytes — longer names are truncated). `uuid` may be NULL
/// (the driver generates one) or a pointer to 16 raw bytes.
///
/// Returns 0 on success or `-errno` on failure. Use `fs_ext4_last_error` /
/// `fs_ext4_last_errno` for context.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_mkfs(
    cfg: *const fs_ext4_blockdev_cfg_t,
    label: *const c_char,
    uuid: *const u8,
) -> c_int {
    ffi_guard(
        -EINVAL,
        AssertUnwindSafe(|| {
            clear_last_error();
            if cfg.is_null() {
                set_err_msg("null cfg", EINVAL);
                return -EINVAL;
            }
            let cfg = &*cfg;
            let Some(read_fn) = cfg.read else {
                set_err_msg("cfg.read is null", EINVAL);
                return -EINVAL;
            };
            let Some(write_fn) = cfg.write else {
                set_err_msg("cfg.write is null (mkfs needs writes)", EINVAL);
                return -EINVAL;
            };
            let flush_fn = cfg.flush; // optional
            if cfg.size_bytes == 0 {
                set_err_msg("cfg.size_bytes is 0", EINVAL);
                return -EINVAL;
            }
            let block_size = if cfg.block_size == 0 {
                4096
            } else {
                cfg.block_size
            };

            let ctx_addr = cfg.context as usize;

            let read_closure = move |offset: u64, buf: &mut [u8]| -> std::io::Result<()> {
                let rc = unsafe {
                    read_fn(
                        ctx_addr as *mut c_void,
                        buf.as_mut_ptr() as *mut c_void,
                        offset,
                        buf.len() as u64,
                    )
                };
                if rc != 0 {
                    Err(std::io::Error::other(format!("read cb {rc}")))
                } else {
                    Ok(())
                }
            };
            let write_closure = move |offset: u64, buf: &[u8]| -> std::io::Result<()> {
                let rc = unsafe {
                    write_fn(
                        ctx_addr as *mut c_void,
                        buf.as_ptr() as *const c_void,
                        offset,
                        buf.len() as u64,
                    )
                };
                if rc != 0 {
                    Err(std::io::Error::other(format!("write cb {rc}")))
                } else {
                    Ok(())
                }
            };
            let flush_closure: Option<crate::block_io::FlushCb> = flush_fn.map(|f| {
                let cb: crate::block_io::FlushCb = Box::new(move || -> std::io::Result<()> {
                    let rc = unsafe { f(ctx_addr as *mut c_void) };
                    if rc != 0 {
                        Err(std::io::Error::other(format!("flush cb {rc}")))
                    } else {
                        Ok(())
                    }
                });
                cb
            });

            let dev = CallbackDevice {
                size: cfg.size_bytes,
                read: Box::new(read_closure),
                write: Some(Box::new(write_closure)),
                flush: flush_closure,
            };

            let label_str: Option<&str> = if label.is_null() {
                None
            } else {
                Some(cstr_to_str(label))
            };
            let uuid_arr: Option<[u8; 16]> = if uuid.is_null() {
                None
            } else {
                let mut tmp = [0u8; 16];
                std::ptr::copy_nonoverlapping(uuid, tmp.as_mut_ptr(), 16);
                Some(tmp)
            };

            match crate::mkfs::format_filesystem(
                &dev,
                label_str,
                uuid_arr,
                cfg.size_bytes,
                block_size,
            ) {
                Ok(()) => 0,
                Err(e) => {
                    let errno = e.to_errno();
                    set_err_from(&e, "mkfs");
                    -errno
                }
            }
        }),
    )
}

// ===========================================================================
// Fsck (read-only audit)
//
// Architecture note: this is a *read-only* fsck — it never writes to disk.
// Findings are delivered via a per-finding C callback rather than collected
// into a Vec returned by reference, so a host UI can stream progress on huge
// volumes without buffering the entire anomaly list. Repair (link-count
// fixup, orphan relink, dotdot rewrite) is explicit future work and will
// require a journaled write path plus a new ABI entry point.
//
// The caller-supplied `on_progress` and `on_finding` callbacks run on the
// thread that called `fs_ext4_fsck_run`. They MUST NOT unwind / throw across
// the FFI boundary — Rust panics inside them turn into the same EIO last-
// error other capi functions surface (the whole body is wrapped in
// `ffi_guard`). The `phase_name`, `kind`, and `detail` strings are valid
// only for the duration of the callback call.
// ===========================================================================

/// Phase id (matches `fs_ext4_fsck_phase_t` in `include/fs_ext4.h`).
#[repr(C)]
#[derive(Copy, Clone)]
pub enum fs_ext4_fsck_phase_t {
    Superblock = 0,
    Journal = 1,
    Directory = 2,
    Inodes = 3,
    Finalize = 4,
}

/// Progress callback (matches `fs_ext4_fsck_progress_fn`).
pub type fs_ext4_fsck_progress_fn = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        phase: fs_ext4_fsck_phase_t,
        phase_name: *const c_char,
        done: u64,
        total: u64,
    ),
>;

/// Per-finding callback (matches `fs_ext4_fsck_finding_fn`).
pub type fs_ext4_fsck_finding_fn = Option<
    unsafe extern "C" fn(
        context: *mut c_void,
        kind: *const c_char,
        inode: u32,
        detail: *const c_char,
    ),
>;

/// Fsck options struct (matches `fs_ext4_fsck_options_t`).
#[repr(C)]
pub struct fs_ext4_fsck_options_t {
    /// 1 = audit only (no writes). 0 + `repair == 1` = repair pass.
    /// Non-{0,1} values are rejected with EINVAL.
    pub read_only: u8,
    /// 1 = call `fs_ext4_replay_journal_if_dirty` before the audit.
    /// Useful when the volume was mounted via the lazy variant and the
    /// caller wants a single fsck call to replay-then-audit.
    pub replay_journal: u8,
    /// 0 = unbounded (fsck visits every directory). Otherwise capped.
    pub max_dirs: u32,
    /// 0 = unbounded. Otherwise per-directory entry cap.
    pub max_entries_per_dir: u32,
    /// Nullable. Called with phase + done/total counters. See module
    /// note for which phases are emitted.
    pub on_progress: fs_ext4_fsck_progress_fn,
    /// Nullable. Called once per `Anomaly` discovered.
    pub on_finding: fs_ext4_fsck_finding_fn,
    /// Opaque pointer threaded through both callbacks. Not interpreted
    /// by Rust.
    pub context: *mut c_void,
    /// Repair-pass switch. Only honoured when `read_only == 0`. See
    /// the C header for the list of anomaly classes the current repair
    /// pass actually fixes.
    pub repair: u8,
}

/// Fsck report (matches `fs_ext4_fsck_report_t`).
#[repr(C)]
pub struct fs_ext4_fsck_report_t {
    pub inodes_visited: u64,
    pub directories_scanned: u64,
    pub entries_scanned: u64,
    /// Authoritative current anomaly count. After a repair pass this
    /// is the **post-repair re-scan** count — actual anomalies still
    /// present on disk, NOT a delta against `repaired_count`.
    pub anomalies_found: u64,
    /// 1 if the on-disk superblock `s_state` showed dirty before the
    /// run started. Captured *before* journal replay (so the caller
    /// can tell whether the volume was crash-state on entry).
    pub was_dirty: u8,
    /// 1 if a repair commit cleared the dirty bit, 0 otherwise.
    pub dirty_cleared: u8,
    /// Number of anomalies repaired (0 unless the run was a repair pass).
    pub repaired_count: u64,
    /// Anomalies the audit found BEFORE any repair commits. Equal to
    /// `anomalies_found` for non-repair runs. After a repair pass:
    /// `initial_anomalies_count - repaired_count` is what we EXPECT
    /// to remain; `anomalies_found` is what ACTUALLY remains. A
    /// mismatch flags repair-logic bugs (we either failed to fix
    /// what we claimed to fix, or fixing one thing introduced a new
    /// anomaly).
    pub initial_anomalies_count: u64,
}

/// Map an [`Anomaly`] variant to its locked C ABI kind string + the
/// most relevant inode + a short free-form detail blob.
fn anomaly_to_capi(a: &crate::fsck::Anomaly) -> (&'static str, u32, String) {
    use crate::fsck::Anomaly;
    match a {
        &Anomaly::LinkCountTooLow {
            ino,
            stored,
            observed,
        } => (
            "link_count_low",
            ino,
            format!("stored={stored} observed={observed}"),
        ),
        &Anomaly::LinkCountTooHigh {
            ino,
            stored,
            observed,
        } => (
            "link_count_high",
            ino,
            format!("stored={stored} observed={observed}"),
        ),
        &Anomaly::DanglingEntry {
            parent_ino,
            child_ino,
            observed,
        } => (
            "dangling_entry",
            child_ino,
            format!("parent_ino={parent_ino} observed={observed}"),
        ),
        &Anomaly::WrongDotDot {
            dir_ino,
            claims,
            actual_parent,
        } => (
            "wrong_dotdot",
            dir_ino,
            format!("claims={claims} actual_parent={actual_parent}"),
        ),
        Anomaly::BogusEntry {
            parent_ino,
            child_ino,
            name,
        } => (
            "bogus_entry",
            *child_ino,
            format!(
                "parent_ino={parent_ino} name={}",
                String::from_utf8_lossy(name)
            ),
        ),
        &Anomaly::BlockGroupFreeCountDrift {
            group_index,
            stored_blocks,
            observed_blocks,
            stored_inodes,
            observed_inodes,
        } => (
            "block_group_free_count_drift",
            group_index,
            format!(
                "stored_blocks={stored_blocks} observed_blocks={observed_blocks} \
                 stored_inodes={stored_inodes} observed_inodes={observed_inodes}"
            ),
        ),
        &Anomaly::SuperblockFreeCountDrift {
            stored_blocks,
            observed_blocks,
            stored_inodes,
            observed_inodes,
        } => (
            "superblock_free_count_drift",
            0,
            format!(
                "stored_blocks={stored_blocks} observed_blocks={observed_blocks} \
                 stored_inodes={stored_inodes} observed_inodes={observed_inodes}"
            ),
        ),
        // Surfaced via the new repair-aware Rust API; the C ABI
        // doesn't expose a repair entry point yet, but the read-only
        // audit can still encounter and report this variant once a
        // duplicate has slipped past detection. Mirror the existing
        // string format: short kind tag + parent/name details for
        // every alias so a downstream UI can render them.
        Anomaly::DuplicateDirentForDirInode { ino, dirents } => {
            let detail = dirents
                .iter()
                .map(|(p, n)| format!("{p}:{n}"))
                .collect::<Vec<_>>()
                .join(",");
            ("duplicate_dir_inode", *ino, format!("aliases={detail}"))
        }
    }
}

/// Run a read-only fsck audit on `fs`. Findings are delivered live via
/// `opts->on_finding`; counters are written to `*report` before return.
///
/// Returns 0 on success (regardless of how many anomalies were found —
/// they're surfaced through `on_finding` and counted in
/// `report->anomalies_found`). Returns -1 on hard failure (null args,
/// `read_only != 1`, journal replay failure, etc.) with the cause in
/// `fs_ext4_last_error` / `fs_ext4_last_errno`.
#[no_mangle]
pub unsafe extern "C" fn fs_ext4_fsck_run(
    fs: *mut fs_ext4_fs_t,
    opts: *const fs_ext4_fsck_options_t,
    report: *mut fs_ext4_fsck_report_t,
) -> c_int {
    ffi_guard(
        -1,
        AssertUnwindSafe(|| {
            clear_last_error();
            if fs.is_null() || opts.is_null() || report.is_null() {
                set_err_msg("null fs/opts/report", EINVAL);
                return -1;
            }
            let fs_ref = &(*fs).fs;
            let opts_ref = &*opts;
            // Sanity: read_only must be 0 or 1; repair can only run
            // when read_only == 0. Anything outside this matrix is a
            // caller bug worth surfacing rather than silently ignoring.
            if opts_ref.read_only > 1 {
                set_err_msg("fsck: opts.read_only must be 0 or 1", EINVAL);
                return -1;
            }
            if opts_ref.replay_journal > 1 {
                set_err_msg("fsck: opts.replay_journal must be 0 or 1", EINVAL);
                return -1;
            }
            if opts_ref.repair > 1 {
                set_err_msg("fsck: opts.repair must be 0 or 1", EINVAL);
                return -1;
            }
            if opts_ref.read_only == 1 && opts_ref.repair == 1 {
                set_err_msg("fsck: opts.repair = 1 requires opts.read_only = 0", EINVAL);
                return -1;
            }
            let repair_requested = opts_ref.repair == 1;

            // Zero the report so partial fills on early-error paths don't
            // leave stale stack data visible to the caller.
            std::ptr::write_bytes(report, 0, 1);
            let report_out = &mut *report;

            // Capture pre-run dirty flag (before any replay).
            report_out.was_dirty = if fs_ref.sb.is_clean() { 0 } else { 1 };

            // Stash callbacks + context for the closures.
            let progress_cb = opts_ref.on_progress;
            let finding_cb = opts_ref.on_finding;
            let ctx = opts_ref.context;

            // Helper: push a progress event through the C callback (if set).
            let emit_progress = |phase: crate::fsck::FsckPhase, done: u64, total: u64| {
                if let Some(cb) = progress_cb {
                    let phase_c = match phase {
                        crate::fsck::FsckPhase::Superblock => fs_ext4_fsck_phase_t::Superblock,
                        crate::fsck::FsckPhase::Journal => fs_ext4_fsck_phase_t::Journal,
                        crate::fsck::FsckPhase::Directory => fs_ext4_fsck_phase_t::Directory,
                        crate::fsck::FsckPhase::Inodes => fs_ext4_fsck_phase_t::Inodes,
                        crate::fsck::FsckPhase::Finalize => fs_ext4_fsck_phase_t::Finalize,
                    };
                    // phase_name strings are short ASCII literals; CString
                    // construction can't fail.
                    let name = CString::new(phase.name()).unwrap();
                    cb(ctx, phase_c, name.as_ptr(), done, total);
                }
            };

            // Optional journal replay before the audit. We drive the
            // Journal phase ourselves (the audit walker doesn't know
            // whether the FFI shim asked for replay).
            if opts_ref.replay_journal != 0 {
                emit_progress(crate::fsck::FsckPhase::Journal, 0, 1);
                if let Err(e) = fs_ref.replay_journal_if_dirty() {
                    set_err_from(&e, "fsck: replay_journal_if_dirty");
                    return -1;
                }
                emit_progress(crate::fsck::FsckPhase::Journal, 1, 1);
            }

            // Map opts.max_* (0 = unbounded → u32::MAX).
            let max_dirs = if opts_ref.max_dirs == 0 {
                u32::MAX
            } else {
                opts_ref.max_dirs
            };
            let max_entries = if opts_ref.max_entries_per_dir == 0 {
                u32::MAX
            } else {
                opts_ref.max_entries_per_dir
            };

            // Helper: push a finding through the C callback (if set).
            let emit_finding = |a: &crate::fsck::Anomaly| {
                if let Some(cb) = finding_cb {
                    let (kind, ino, detail) = anomaly_to_capi(a);
                    // Both strings are static / format!-derived ASCII, no
                    // interior NUL — CString::new can't fail here, but we
                    // still fall back gracefully if it ever does.
                    let kind_c = CString::new(kind).unwrap_or_else(|_| CString::new("?").unwrap());
                    let detail_c =
                        CString::new(detail).unwrap_or_else(|_| CString::new("").unwrap());
                    // Safety: callbacks run synchronously; the CStrings
                    // outlive the call because they're local stack vars.
                    cb(ctx, kind_c.as_ptr(), ino, detail_c.as_ptr());
                }
            };

            let result = crate::fsck::audit_with_repair(
                fs_ref,
                max_dirs,
                max_entries,
                emit_progress,
                emit_finding,
                repair_requested,
            );

            match result {
                Ok(audit_report) => {
                    report_out.inodes_visited = audit_report.inodes_visited as u64;
                    report_out.directories_scanned = audit_report.directories_scanned as u64;
                    report_out.entries_scanned = audit_report.entries_scanned;
                    report_out.anomalies_found = audit_report.anomalies_count;
                    report_out.initial_anomalies_count = audit_report.initial_anomalies_count;
                    report_out.repaired_count = audit_report.repaired_count;
                    // `dirty_cleared` reports whether the on-disk
                    // dirty bit transitioned from set to clear over
                    // this run. Two requirements: (a) the FS was
                    // dirty pre-run (otherwise there's nothing to
                    // clear), and (b) the on-disk SB is clean after
                    // any repair commits. We can't trust
                    // `fs_ref.sb.is_clean()` here — that's the parsed
                    // mount-time snapshot, never mutated by repair —
                    // so re-read the SB from disk to get the truth.
                    let post_sb_clean = if repair_requested && report_out.was_dirty == 1 {
                        crate::superblock::Superblock::read(fs_ref.dev.as_ref())
                            .map(|sb| sb.is_clean())
                            .unwrap_or(false)
                    } else {
                        false
                    };
                    report_out.dirty_cleared = if post_sb_clean { 1 } else { 0 };
                    0
                }
                Err(e) => {
                    set_err_from(&e, "fsck: audit");
                    -1
                }
            }
        }),
    )
}
