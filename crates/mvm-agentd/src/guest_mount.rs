//! Guest-side mount library for PID-1 initramfs boot.
//!
//! This module owns the transition from the tiny initramfs to the
//! provisioned workload environment: dm-verity rootfs, dm-verity runtime
//! overlay, optional virtio-fs custom volumes, and the privilege drop that
//! follows.  It is intentionally separate from the runtime virtio-fs volume
//! handler (`crate::volume`) because the boot-time mounts run as root before
//! the agent drops privilege, use raw syscalls rather than `mount(8)`, and
//! must fail closed on roothash mismatch.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::path::{Path, PathBuf};

use crate::vsock::{RootfsConfig, RuntimeOverlayConfig, VolumeConfig};

/// Boot-time mount error.  Every failure path is terminal: PID 1 has no
/// init to fall back to, so the agent logs and exits non-zero.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    /// A syscall (mount, mkdir, pivot_root, setuid, ...) failed.
    #[error("syscall failed: {context}")]
    Syscall {
        context: String,
        #[source]
        source: std::io::Error,
    },
    /// The requested mountpoint or device path was rejected by policy.
    #[error("path policy denied: {0}")]
    PathPolicyDenied(String),
    /// dm-verity roothash mismatch or malformed hash.
    #[error("verity setup failed: {0}")]
    VeritySetup(String),
    /// A required filesystem type is unavailable.
    #[error("unsupported filesystem: {0}")]
    UnsupportedFilesystem(String),
    /// The activation message itself is contradictory or malformed.
    #[error("invalid activation config: {0}")]
    InvalidConfig(String),
}

impl MountError {
    /// Convenience constructor for libc wrappers.
    pub fn syscall(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Syscall {
            context: context.into(),
            source,
        }
    }
}

/// Result type for boot-time mount operations.
pub type Result<T> = std::result::Result<T, MountError>;

/// Fixed path where the rootfs is staged before pivot/switch_root.
pub(crate) const ROOTFS_STAGING: &str = "/mnt/root";

/// Validate a 64-character lowercase hex dm-verity roothash.
pub fn validate_roothash(roothash: &str, name: &str) -> Result<()> {
    if roothash.len() != 64
        || !roothash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(MountError::VeritySetup(format!(
            "invalid {name}={roothash:?} (expected 64 lowercase hex chars)"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Basic early-boot filesystems the PID-1 agent needs before it can
/// receive `ActivateEnvironment` over vsock.
pub fn mount_early_filesystems() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        mount(
            "proc",
            "/proc",
            "proc",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            "",
        )?;
        mount(
            "sysfs",
            "/sys",
            "sysfs",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            "",
        )?;
        // devtmpfs gives us /dev/console, /dev/null, etc. without a static
        // device table in the initramfs.
        if !Path::new("/dev/console").exists() {
            mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "")?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ();
    }
    Ok(())
}

/// Mount the rootfs, returning the staging path (`/mnt/root`).
///
/// Three mount shapes, selected by the config's optional fields: a
/// dm-verity block root (`roothash` + `hash_dev` set — create the `root`
/// target and mount it read-only), an unverified plain-block root
/// (neither set — mount the data device read-only directly), or a
/// virtio-fs root (`virtiofs_tag` set — mount the tag read-only). The
/// fourth shape, `in_place`, mounts nothing and returns `/` directly: the
/// runtime already owns the root (a shared-kernel container whose root is
/// the image). On non-Linux platforms it is a no-op stub so the workspace
/// compiles.
pub fn mount_rootfs(rootfs: &RootfsConfig) -> Result<PathBuf> {
    if rootfs.in_place {
        // Mutually exclusive with every mount-carrying field: a host that
        // sets both gets a loud validation error, never a silent choice
        // between "mount this device" and "the root is already there".
        if !rootfs.data_dev.is_empty()
            || rootfs.hash_dev.is_some()
            || rootfs.roothash.is_some()
            || rootfs.virtiofs_tag.is_some()
        {
            return Err(MountError::InvalidConfig(
                "rootfs.in_place is mutually exclusive with data_dev/hash_dev/roothash/virtiofs_tag"
                    .to_string(),
            ));
        }
        return Ok(PathBuf::from("/"));
    }

    ensure_dir(ROOTFS_STAGING)?;

    #[cfg(not(target_os = "linux"))]
    let _ = rootfs;
    #[cfg(target_os = "linux")]
    {
        if let Some(tag) = &rootfs.virtiofs_tag {
            mount(tag, ROOTFS_STAGING, "virtiofs", libc::MS_RDONLY, "")?;
        } else if let Some(roothash) = &rootfs.roothash {
            validate_roothash(roothash, "rootfs.roothash")?;
            let hash_dev = rootfs.hash_dev.as_deref().ok_or_else(|| {
                MountError::VeritySetup(
                    "rootfs.roothash present but rootfs.hash_dev missing".to_string(),
                )
            })?;
            let ctrl = open_dm_control()?;
            let fd = ctrl.as_raw_fd();
            dm_version(fd)?;
            setup_verity_target(fd, "root", &rootfs.data_dev, hash_dev, roothash)?;
            let root_dm = resolved_dm_device("root", 0)?;
            mount(&root_dm, ROOTFS_STAGING, "ext4", libc::MS_RDONLY, "")?;
        } else {
            mount(
                &rootfs.data_dev,
                ROOTFS_STAGING,
                "ext4",
                libc::MS_RDONLY,
                "",
            )?;
        }
    }

    Ok(PathBuf::from(ROOTFS_STAGING))
}

/// Mount the dm-verity runtime overlay inside the new root tree at
/// `/mvm/runtime`.  `None` for a rootfs-only boot: nothing is mounted.
pub fn mount_runtime_overlay(runtime: Option<&RuntimeOverlayConfig>, root: &Path) -> Result<()> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    validate_roothash(&runtime.roothash, "runtime.roothash")?;
    let target = root.join("mvm/runtime");
    ensure_dir(&target.to_string_lossy())?;

    #[cfg(target_os = "linux")]
    {
        let ctrl = open_dm_control()?;
        let fd = ctrl.as_raw_fd();
        setup_verity_target(
            fd,
            "runtime",
            &runtime.data_dev,
            &runtime.hash_dev,
            &runtime.roothash,
        )?;
        let runtime_dm = resolved_dm_device("runtime", 1)?;
        mount(
            &runtime_dm,
            &target.to_string_lossy(),
            "ext4",
            libc::MS_RDONLY,
            "",
        )?;
    }

    Ok(())
}

/// Reserved mountpoints that volumes are not allowed to shadow.
pub(crate) const RESERVED_MOUNTS: &[&str] =
    &["/", "/mvm", "/mvm/runtime", "/dev", "/dev/vda", "/dev/vdc"];

/// Validate that a volume mountpoint does not collide with reserved paths.
pub fn validate_volume_mountpoint(mountpoint: &str) -> Result<()> {
    let normalized = if mountpoint.ends_with('/') && mountpoint.len() > 1 {
        &mountpoint[..mountpoint.len() - 1]
    } else {
        mountpoint
    };
    if !normalized.starts_with('/') {
        return Err(MountError::PathPolicyDenied(format!(
            "volume mountpoint {mountpoint:?} must be absolute"
        )));
    }
    for reserved in RESERVED_MOUNTS {
        if normalized == *reserved || normalized.starts_with(&format!("{reserved}/")) {
            return Err(MountError::PathPolicyDenied(format!(
                "volume mountpoint {mountpoint:?} shadows reserved path {reserved:?}"
            )));
        }
    }
    Ok(())
}

/// Mount any custom virtio-fs volumes inside the new root tree.
pub fn mount_volumes(volumes: &[VolumeConfig], root: &Path) -> Result<()> {
    for vol in volumes {
        validate_volume_mountpoint(&vol.mountpoint)?;
        let target = root.join(&vol.mountpoint);
        ensure_dir(&target.to_string_lossy())?;
        #[cfg(target_os = "linux")]
        {
            let flags = if vol.read_only { libc::MS_RDONLY } else { 0 };
            mount(&vol.tag, &target.to_string_lossy(), "virtiofs", flags, "")?;
        }
    }
    Ok(())
}

/// Pivot into the mounted rootfs, making it the active `/`.
///
/// Moves `/proc`, `/sys`, and `/dev` into the new root, then performs the
/// canonical switch_root sequence (chdir + MS_MOVE + chroot).  The agent
/// process keeps running; it does not exec a new init.
pub fn pivot_to_root(new_root: &Path) -> Result<()> {
    pivot_common(new_root, false)
}

/// Container-mode pivot: like [`pivot_to_root`], but a pseudo-filesystem
/// that is not its own mount in the container root (commonly `/dev`) is
/// mounted fresh inside the new root instead of moved.  MS_MOVE only works
/// on real mountpoints; the fresh mount has the same effect inside the
/// caller's private mount namespace and never touches the init system's.
pub fn pivot_to_root_container(new_root: &Path) -> Result<()> {
    pivot_common(new_root, true)
}

/// Enter a private mount namespace (`CLONE_NEWNS`) and make mount
/// propagation private, so every subsequent mount/move stays local to this
/// process.  The container-mode activation path runs the agent as an
/// ordinary child of the guest's init system, which keeps its own mount
/// namespace untouched.  On non-Linux platforms this is a no-op so the
/// workspace compiles.
pub fn unshare_mount_namespace() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: unshare(CLONE_NEWNS) takes no pointers; it detaches this
        // process's mount namespace from the parent's.
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            return Err(MountError::syscall(
                "unshare(CLONE_NEWNS)",
                std::io::Error::last_os_error(),
            ));
        }
        // Propagation is inherited from the parent subtree; without this,
        // later mounts and moves would propagate back into the init
        // system's namespace whenever the inherited root is shared.
        mount("none", "/", "none", libc::MS_REC | libc::MS_PRIVATE, "")?;
    }
    Ok(())
}

/// The shared switch_root sequence behind [`pivot_to_root`] and
/// [`pivot_to_root_container`].  `fresh_pseudo_fallback` mounts a fresh
/// pseudo-filesystem inside the new root when the source is not a
/// mountpoint of its own (EINVAL) — the container-mode case.
#[cfg(target_os = "linux")]
fn pivot_common(new_root: &Path, fresh_pseudo_fallback: bool) -> Result<()> {
    // Ensure the target directories exist in the new root.
    for sub in ["proc", "sys", "dev"] {
        let dst = new_root.join(sub);
        ensure_dir(&dst.to_string_lossy())?;
    }

    // Move the pseudo-filesystems into the new root so the workload (and
    // the agent itself) keeps seeing them.
    let pseudo: [(&str, &str, libc::c_ulong); 3] = [
        (
            "/proc",
            "proc",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        ),
        (
            "/sys",
            "sysfs",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
        ),
        ("/dev", "devtmpfs", libc::MS_NOSUID),
    ];
    for (src, fstype, flags) in pseudo {
        let dst = new_root.join(&src[1..]).to_string_lossy().to_string();
        let _ = ensure_dir(&dst);
        match move_mount(src, &dst) {
            Ok(()) => {}
            Err(e) if fresh_pseudo_fallback && e.raw_os_error() == Some(libc::EINVAL) => {
                mount(fstype, &dst, fstype, flags, "")?;
            }
            Err(e) => {
                return Err(MountError::syscall(format!("move-mount {src} -> {dst}"), e));
            }
        }
    }

    // switch_root: chdir to new_root, move it onto /, chroot into it.
    chdir(new_root)?;
    mount(".", "/", "", libc::MS_MOVE, "")?;
    chroot(".")?;
    chdir("/")?;
    Ok(())
}

/// Non-Linux stub so the workspace compiles on macOS.
#[cfg(not(target_os = "linux"))]
fn pivot_common(new_root: &Path, _fresh_pseudo_fallback: bool) -> Result<()> {
    let _ = new_root;
    Ok(())
}

/// Drop root privilege to the fixed workload UID/GID (901).  Must run after
/// all root-only mounts are complete.
pub fn drop_privilege(uid: u32, gid: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Drop any supplementary groups first while still root.
        // SAFETY: setgroups(0, NULL) is the documented Linux way to clear all supplementary groups.
        if unsafe { libc::setgroups(0, std::ptr::null::<libc::gid_t>()) } != 0 {
            return Err(MountError::syscall(
                "setgroups",
                std::io::Error::last_os_error(),
            ));
        }
        // Order matters: setgid before setuid so the saved gid stays usable.
        setgid(gid)?;
        setuid(uid)?;
        // Paranoia: confirm we cannot regain root.
        // SAFETY: getuid() has no precondition and cannot fail.
        if unsafe { libc::getuid() } == 0 {
            return Err(MountError::Syscall {
                context: "privilege drop failed: still uid 0".to_string(),
                source: std::io::Error::from_raw_os_error(libc::EPERM),
            });
        }
    }
    let _ = (uid, gid);
    Ok(())
}

// ---------------------------------------------------------------------------
// Low-level syscall wrappers (Linux)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    pub use std::os::fd::AsRawFd;

    // DM ioctl constants and structs (mirror /usr/include/linux/dm-ioctl.h).
    pub const DM_VERSION_MAJOR: u32 = 4;
    pub const DM_VERSION_MINOR: u32 = 0;
    pub const DM_VERSION_PATCH: u32 = 0;
    pub const DM_NAME_LEN: usize = 128;
    pub const DM_UUID_LEN: usize = 129;
    pub const DM_DATA_LEN: usize = 7;
    pub const DM_READONLY_FLAG: u32 = 1 << 0;
    pub const DM_EXISTS_FLAG: u32 = 1 << 2;
    pub const DM_VERSION_CMD: u32 = 0;
    pub const DM_DEV_CREATE_CMD: u32 = 3;
    pub const DM_DEV_SUSPEND_CMD: u32 = 6;
    pub const DM_TABLE_LOAD_CMD: u32 = 9;
    pub const DM_IOCTL: u32 = 0xfd;
    pub const DM_IOCTL_STRUCT_SIZE: u32 = 312;

    pub fn iowr(nr: u32) -> u64 {
        ((3u32 << 30) | (DM_IOCTL_STRUCT_SIZE << 16) | (DM_IOCTL << 8) | nr) as u64
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct DmIoctl {
        pub version: [u32; 3],
        pub data_size: u32,
        pub data_start: u32,
        pub target_count: u32,
        pub open_count: i32,
        pub flags: u32,
        pub event_nr: u32,
        pub padding: u32,
        pub dev: u64,
        pub name: [u8; DM_NAME_LEN],
        pub uuid: [u8; DM_UUID_LEN],
        pub data: [u8; DM_DATA_LEN],
    }

    impl Default for DmIoctl {
        fn default() -> Self {
            Self {
                version: [0; 3],
                data_size: 0,
                data_start: 0,
                target_count: 0,
                open_count: 0,
                flags: 0,
                event_nr: 0,
                padding: 0,
                dev: 0,
                name: [0; DM_NAME_LEN],
                uuid: [0; DM_UUID_LEN],
                data: [0; DM_DATA_LEN],
            }
        }
    }

    const _: () = assert!(DM_IOCTL_STRUCT_SIZE as usize == std::mem::size_of::<DmIoctl>());

    #[repr(C)]
    pub struct DmTargetSpec {
        pub sector_start: u64,
        pub length: u64,
        pub status: i32,
        pub next: u32,
        pub target_type: [u8; 16],
    }
}

#[cfg(target_os = "linux")]
use linux_impl::*;

#[cfg(target_os = "linux")]
fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> Result<()> {
    let invalid = |e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);
    let src =
        CString::new(source).map_err(|e| MountError::syscall("source has NUL", invalid(e)))?;
    let tgt =
        CString::new(target).map_err(|e| MountError::syscall("target has NUL", invalid(e)))?;
    let typ =
        CString::new(fstype).map_err(|e| MountError::syscall("fstype has NUL", invalid(e)))?;
    let dat = CString::new(data).map_err(|e| MountError::syscall("data has NUL", invalid(e)))?;
    // SAFETY: all five pointers are valid NUL-terminated C strings or null pointers owned by this stack frame and outlive the call.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            typ.as_ptr(),
            flags,
            dat.as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("mount({source} -> {target}, {fstype})"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn move_mount(src: &str, dst: &str) -> std::io::Result<()> {
    let src_c =
        CString::new(src).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let dst_c =
        CString::new(dst).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: src_c and dst_c are NUL-terminated C strings that outlive the call; null fstype/data are valid for MS_MOVE.
    let rc = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn chdir(path: impl AsRef<Path>) -> Result<()> {
    let p = CString::new(path.as_ref().to_string_lossy().as_bytes()).map_err(|e| {
        MountError::syscall(
            "chdir path has NUL",
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
        )
    })?;
    // SAFETY: p is a NUL-terminated C string that outlives the call.
    let rc = unsafe { libc::chdir(p.as_ptr()) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("chdir({})", path.as_ref().display()),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn chroot(path: &str) -> Result<()> {
    let p = CString::new(path).map_err(|e| {
        MountError::syscall(
            "chroot path has NUL",
            std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
        )
    })?;
    // SAFETY: p is a NUL-terminated C string that outlives the call.
    let rc = unsafe { libc::chroot(p.as_ptr()) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("chroot({path})"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn ensure_dir(path: &str) -> Result<()> {
    match std::fs::create_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(MountError::syscall(format!("mkdir {path}"), e)),
    }
}

#[cfg(target_os = "linux")]
fn setuid(uid: u32) -> Result<()> {
    // SAFETY: setuid receives a plain uid_t value; no pointer contract.
    let rc = unsafe { libc::setuid(uid) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("setuid({uid})"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn setgid(gid: u32) -> Result<()> {
    // SAFETY: setgid receives a plain gid_t value; no pointer contract.
    let rc = unsafe { libc::setgid(gid) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("setgid({gid})"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// dm-verity helpers (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn open_dm_control() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/mapper/control")
        .map_err(|e| MountError::syscall("open /dev/mapper/control", e))
}

#[cfg(target_os = "linux")]
fn base_ioctl() -> DmIoctl {
    DmIoctl {
        version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCH],
        data_size: DM_IOCTL_STRUCT_SIZE,
        data_start: 0,
        flags: DM_EXISTS_FLAG,
        ..Default::default()
    }
}

#[cfg(target_os = "linux")]
fn write_name(buf: &mut [u8; DM_NAME_LEN], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(DM_NAME_LEN - 1);
    buf[..n].copy_from_slice(&bytes[..n]);
    buf[n] = 0;
}

#[cfg(target_os = "linux")]
fn dm_ioctl_fixed(fd: libc::c_int, cmd: u32, io: &mut DmIoctl, context: &str) -> Result<()> {
    // SAFETY: fd is an open /dev/mapper/control descriptor; io is a live, writable DmIoctl valid for the ioctl size.
    unsafe {
        do_ioctl(fd, iowr(cmd), io).map_err(|e| MountError::syscall(context.to_string(), e))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn dm_version(fd: libc::c_int) -> Result<()> {
    let mut io = base_ioctl();
    dm_ioctl_fixed(fd, DM_VERSION_CMD, &mut io, "DM_VERSION")
}

#[cfg(target_os = "linux")]
fn setup_verity_target(
    fd: libc::c_int,
    device_name: &str,
    data_dev: &str,
    hash_dev: &str,
    roothash: &str,
) -> Result<()> {
    const HASH_BLOCK_SIZE: u64 = 4096;
    let data_block_size = probe_ext4_block_size(data_dev)?;
    let data_size = block_device_size(data_dev)?;
    let hash_size = block_device_size(hash_dev)?;
    if !data_size.is_multiple_of(data_block_size) {
        return Err(MountError::VeritySetup(format!(
            "{device_name}: data device {data_dev} size {data_size} not multiple of {data_block_size}"
        )));
    }
    let data_blocks = data_size / data_block_size;
    let num_sectors = data_blocks * (data_block_size / 512);
    let hash_start_block = choose_hash_start_block(data_blocks, hash_size)?;
    let salt = "0".repeat(64);
    let table_args = format!(
        "1 {data_dev} {hash_dev} {data_block_size} {HASH_BLOCK_SIZE} {data_blocks} {hash_start_block} sha256 {roothash} {salt}"
    );

    // DM_DEV_CREATE
    let mut io = base_ioctl();
    write_name(&mut io.name, device_name);
    dm_ioctl_fixed(
        fd,
        DM_DEV_CREATE_CMD,
        &mut io,
        &format!("DM_DEV_CREATE({device_name})"),
    )?;

    // DM_TABLE_LOAD
    let payload = build_table_payload(device_name, num_sectors, "verity", &table_args)?;
    let mut buf = vec![0u8; payload.len()];
    buf.copy_from_slice(&payload);
    let header_ptr = buf.as_mut_ptr().cast::<DmIoctl>();
    unsafe {
        do_ioctl(fd, iowr(DM_TABLE_LOAD_CMD), header_ptr)
            .map_err(|e| MountError::syscall(format!("DM_TABLE_LOAD({device_name})"), e))?;
    }

    // DM_DEV_SUSPEND (resume)
    let mut io = base_ioctl();
    write_name(&mut io.name, device_name);
    dm_ioctl_fixed(
        fd,
        DM_DEV_SUSPEND_CMD,
        &mut io,
        &format!("DM_DEV_SUSPEND({device_name})"),
    )?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn resolved_dm_device(name: &str, index: usize) -> Result<String> {
    let mapper = format!("/dev/mapper/{name}");
    if Path::new(&mapper).exists() {
        return Ok(mapper);
    }
    let fallback = format!("/dev/dm-{index}");
    if Path::new(&fallback).exists() {
        return Ok(fallback);
    }
    Err(MountError::VeritySetup(format!(
        "neither {mapper} nor {fallback} exists after DM_DEV_SUSPEND"
    )))
}

#[cfg(target_os = "linux")]
fn build_table_payload(
    device_name: &str,
    sectors: u64,
    target_type: &str,
    params: &str,
) -> Result<Vec<u8>> {
    use std::mem::size_of;
    let header_size = size_of::<DmIoctl>();
    let spec_size = size_of::<DmTargetSpec>();
    let params_nul = params.len() + 1;
    let total_unaligned = header_size + spec_size + params_nul;
    let aligned_total = total_unaligned.div_ceil(8) * 8;

    let mut buf = vec![0u8; aligned_total];

    let header = DmIoctl {
        version: [DM_VERSION_MAJOR, DM_VERSION_MINOR, DM_VERSION_PATCH],
        data_size: aligned_total as u32,
        data_start: header_size as u32,
        target_count: 1,
        open_count: 0,
        flags: DM_EXISTS_FLAG | DM_READONLY_FLAG,
        event_nr: 0,
        padding: 0,
        dev: 0,
        name: {
            let mut n = [0u8; DM_NAME_LEN];
            write_name(&mut n, device_name);
            n
        },
        uuid: [0u8; DM_UUID_LEN],
        data: [0u8; DM_DATA_LEN],
    };
    // SAFETY: `header` is a live DmIoctl; `buf` is allocated with at least header_size bytes; pointers are valid for the copy.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&header as *const DmIoctl).cast::<u8>(),
            buf.as_mut_ptr(),
            header_size,
        );
    }

    let mut tt = [0u8; 16];
    let n = target_type.len().min(15);
    tt[..n].copy_from_slice(&target_type.as_bytes()[..n]);
    let spec = DmTargetSpec {
        sector_start: 0,
        length: sectors,
        status: 0,
        next: (aligned_total - header_size) as u32,
        target_type: tt,
    };
    // SAFETY: `spec` is a live DmTargetSpec; `buf` has at least header_size+spec_size bytes; the destination offset is in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&spec as *const DmTargetSpec).cast::<u8>(),
            buf.as_mut_ptr().add(header_size),
            spec_size,
        );
    }

    let params_off = header_size + spec_size;
    buf[params_off..params_off + params.len()].copy_from_slice(params.as_bytes());
    buf[params_off + params.len()] = 0;

    if aligned_total > u32::MAX as usize {
        return Err(MountError::VeritySetup(
            "verity payload exceeds u32".to_string(),
        ));
    }
    Ok(buf)
}

/// Compute the Merkle tree block count for `data_blocks` hashes.
fn verity_tree_block_count(data_blocks: u64, hash_block_size: u64) -> u64 {
    const DIGEST_SIZE: u64 = 32;
    let hashes_per_block = hash_block_size / DIGEST_SIZE;
    let mut level_hashes = data_blocks.max(1);
    let mut total_blocks = 0;
    loop {
        let level_blocks = level_hashes.div_ceil(hashes_per_block).max(1);
        total_blocks += level_blocks;
        if level_blocks == 1 {
            return total_blocks;
        }
        level_hashes = level_blocks;
    }
}

/// Choose `hash_start_block` based on whether the sidecar has a verity
/// superblock in block 0.
pub fn choose_hash_start_block(data_blocks: u64, hash_size: u64) -> Result<u64> {
    const HASH_BLOCK_SIZE: u64 = 4096;
    if !hash_size.is_multiple_of(HASH_BLOCK_SIZE) {
        return Err(MountError::VeritySetup(format!(
            "hash device size {hash_size} is not a multiple of {HASH_BLOCK_SIZE}"
        )));
    }
    let hash_blocks = hash_size / HASH_BLOCK_SIZE;
    let tree_blocks = verity_tree_block_count(data_blocks, HASH_BLOCK_SIZE);
    if hash_blocks > tree_blocks {
        Ok(1)
    } else if hash_blocks >= tree_blocks {
        Ok(0)
    } else {
        Err(MountError::VeritySetup(format!(
            "hash device too small: need at least {tree_blocks} hash blocks for {data_blocks} data blocks, got {hash_blocks}"
        )))
    }
}

/// Return the size in bytes of a block device.
#[cfg(target_os = "linux")]
fn block_device_size(path: &str) -> Result<u64> {
    const BLKGETSIZE64: u64 = 0x80081272;
    let f =
        std::fs::File::open(path).map_err(|e| MountError::syscall(format!("open {path}"), e))?;
    let mut size: u64 = 0;
    // SAFETY: fd is an open block device; BLKGETSIZE64 writes exactly one u64 to the provided mutable pointer.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), BLKGETSIZE64 as libc::Ioctl, &mut size) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("BLKGETSIZE64 on {path}"),
            std::io::Error::last_os_error(),
        ));
    }
    Ok(size)
}

/// Read the ext4 logical block size from the data device's superblock.
pub fn probe_ext4_block_size(path: &str) -> Result<u64> {
    const SUPERBLOCK_OFFSET: u64 = 1024;
    const LOG_BLOCK_SIZE_OFFSET: usize = 0x18;
    const MAGIC_OFFSET: usize = 0x38;
    const EXT4_SUPER_MAGIC: u16 = 0xef53;

    let file =
        std::fs::File::open(path).map_err(|e| MountError::syscall(format!("open {path}"), e))?;
    let mut superblock = [0u8; 1024];
    std::os::unix::fs::FileExt::read_exact_at(&file, &mut superblock, SUPERBLOCK_OFFSET)
        .map_err(|e| MountError::syscall(format!("read ext4 superblock from {path}"), e))?;

    let magic = u16::from_le_bytes([superblock[MAGIC_OFFSET], superblock[MAGIC_OFFSET + 1]]);
    if magic != EXT4_SUPER_MAGIC {
        return Err(MountError::VeritySetup(format!(
            "{path} ext4 superblock magic mismatch: expected 0x{EXT4_SUPER_MAGIC:04x}, got 0x{magic:04x}"
        )));
    }

    let log_block_size = u32::from_le_bytes(
        superblock[LOG_BLOCK_SIZE_OFFSET..LOG_BLOCK_SIZE_OFFSET + 4]
            .try_into()
            .map_err(|_| {
                MountError::VeritySetup(format!("parse ext4 log block size from {path}"))
            })?,
    );
    if log_block_size > 6 {
        return Err(MountError::VeritySetup(format!(
            "{path} ext4 log block size {log_block_size} is out of range"
        )));
    }

    Ok(1024u64 << log_block_size)
}

#[cfg(target_os = "linux")]
/// # Safety
/// The caller must ensure `fd` is a valid descriptor and `arg` points to a value whose type matches `request`.
unsafe fn do_ioctl<T>(fd: libc::c_int, request: u64, arg: *mut T) -> std::io::Result<()> {
    // SAFETY: caller upholds the fd/arg contract for this ioctl request.
    let rc = unsafe { libc::ioctl(fd, request as libc::Ioctl, arg) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    const FAKE_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn validate_roothash_accepts_64_lowercase_hex() {
        assert!(validate_roothash(FAKE_HASH, "test").is_ok());
    }

    #[test]
    fn in_place_rootfs_mounts_nothing_and_returns_root() {
        let cfg = RootfsConfig {
            data_dev: String::new(),
            hash_dev: None,
            roothash: None,
            virtiofs_tag: None,
            in_place: true,
        };
        assert_eq!(mount_rootfs(&cfg).unwrap(), PathBuf::from("/"));
    }

    #[test]
    fn in_place_rootfs_rejects_mount_carrying_fields() {
        for cfg in [
            RootfsConfig {
                data_dev: "/dev/vda".to_string(),
                hash_dev: None,
                roothash: None,
                virtiofs_tag: None,
                in_place: true,
            },
            RootfsConfig {
                data_dev: String::new(),
                hash_dev: Some("/dev/vdb".to_string()),
                roothash: None,
                virtiofs_tag: None,
                in_place: true,
            },
            RootfsConfig {
                data_dev: String::new(),
                hash_dev: None,
                roothash: Some(FAKE_HASH.to_string()),
                virtiofs_tag: None,
                in_place: true,
            },
            RootfsConfig {
                data_dev: String::new(),
                hash_dev: None,
                roothash: None,
                virtiofs_tag: Some("mvmroot".to_string()),
                in_place: true,
            },
        ] {
            let err = mount_rootfs(&cfg).unwrap_err();
            assert!(
                matches!(err, MountError::InvalidConfig(_)),
                "expected InvalidConfig, got: {err}"
            );
        }
    }

    #[test]
    fn validate_roothash_rejects_short() {
        assert!(validate_roothash("abc", "test").is_err());
    }

    #[test]
    fn validate_roothash_rejects_uppercase() {
        let upper = "ABCDEF0123456789".repeat(4);
        assert!(validate_roothash(&upper, "test").is_err());
    }

    #[test]
    fn validate_volume_mountpoint_accepts_normal_paths() {
        assert!(validate_volume_mountpoint("/data").is_ok());
        assert!(validate_volume_mountpoint("/srv/app").is_ok());
        assert!(validate_volume_mountpoint("/nested/mvm/other").is_ok());
    }

    #[test]
    fn validate_volume_mountpoint_rejects_reserved_paths() {
        for reserved in RESERVED_MOUNTS {
            assert!(
                validate_volume_mountpoint(reserved).is_err(),
                "reserved path {reserved:?} should be rejected"
            );
            assert!(
                validate_volume_mountpoint(&format!("{reserved}/sub")).is_err(),
                "child of reserved path {reserved:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_volume_mountpoint_rejects_relative_and_empty() {
        assert!(validate_volume_mountpoint("data").is_err());
        assert!(validate_volume_mountpoint("").is_err());
    }

    #[test]
    fn verity_tree_block_count_for_small_data() {
        // 1 data block -> 1 hash block.
        assert_eq!(verity_tree_block_count(1, 4096), 1);
    }

    #[test]
    fn choose_hash_start_block_uses_superblock_when_extra_block() {
        let data_blocks = 9_448;
        let hash_dev_size = 76 * 4_096;
        assert_eq!(
            choose_hash_start_block(data_blocks, hash_dev_size).expect("hash start block"),
            1
        );
    }

    #[test]
    fn choose_hash_start_block_accepts_no_superblock() {
        let data_blocks = 9_448;
        let hash_dev_size = 75 * 4_096;
        assert_eq!(
            choose_hash_start_block(data_blocks, hash_dev_size).expect("hash start block"),
            0
        );
    }

    #[test]
    fn choose_hash_start_block_rejects_truncated_sidecar() {
        let data_blocks = 9_448;
        let hash_dev_size = 74 * 4_096;
        let err = choose_hash_start_block(data_blocks, hash_dev_size).unwrap_err();
        assert!(err.to_string().contains("hash device too small"), "{err}");
    }

    fn write_superblock_image(log_block_size: u32) -> tempfile::NamedTempFile {
        let mut image = tempfile::NamedTempFile::new().expect("temp image");
        image
            .as_file_mut()
            .set_len(8 * 1024)
            .expect("set temp image length");
        image
            .as_file_mut()
            .seek(SeekFrom::Start(1024))
            .expect("seek to ext4 superblock");
        let mut superblock = [0u8; 1024];
        superblock[0x18..0x1c].copy_from_slice(&log_block_size.to_le_bytes());
        superblock[0x38..0x3a].copy_from_slice(&0xef53u16.to_le_bytes());
        image
            .as_file_mut()
            .write_all(&superblock)
            .expect("write ext4 superblock");
        image
    }

    #[test]
    fn probe_ext4_block_size_reads_1k() {
        let image = write_superblock_image(0);
        assert_eq!(
            probe_ext4_block_size(image.path().to_str().expect("temp path")).expect("block size"),
            1024
        );
    }

    #[test]
    fn probe_ext4_block_size_reads_4k() {
        let image = write_superblock_image(2);
        assert_eq!(
            probe_ext4_block_size(image.path().to_str().expect("temp path")).expect("block size"),
            4096
        );
    }

    #[test]
    fn probe_ext4_block_size_rejects_bad_magic() {
        let mut image = tempfile::NamedTempFile::new().expect("temp image");
        image
            .as_file_mut()
            .set_len(8 * 1024)
            .expect("set temp image length");
        let err = probe_ext4_block_size(image.path().to_str().expect("temp path"))
            .expect_err("bad magic must fail");
        assert!(err.to_string().contains("magic mismatch"), "{err}");
    }
}
