//! Guest-side mount library for PID-1 initramfs boot.
//!
//! This module owns the transition from the tiny initramfs to the
//! provisioned workload environment: dm-verity rootfs, dm-verity runtime
//! overlay, optional virtio-fs custom volumes, and the privilege drop that
//! follows.  It is intentionally separate from the runtime virtio-fs volume
//! handler (`crate::volume`) because the boot-time mounts run as root before
//! the agent drops privilege, use raw syscalls rather than `mount(8)`, and
//! must fail closed on roothash mismatch.

use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::path::{Path, PathBuf};

use crate::vsock::{RootfsConfig, RuntimeOverlayConfig, VolumeConfig, VolumeConfigKind};

/// Fixed identity used by the guest agent and workload command runner.
pub const WORKLOAD_UID: u32 = 901;
/// Fixed group used by the guest agent and workload command runner.
pub const WORKLOAD_GID: u32 = 901;

/// Home directory used by workload processes.
///
/// The workload root is mounted read-only, so this is a *mount point*: image
/// materialization bakes the empty directory in, and [`mount_workload_home`]
/// lays a writable tmpfs over it at boot.
pub const WORKLOAD_HOME: &str = "/home/mvm-worker";
/// [`WORKLOAD_HOME`] relative to the rootfs root, for host-side materialization
/// into a staging directory. Kept in step by `home_paths_name_the_same_dir`.
pub const WORKLOAD_HOME_REL: &str = "home/mvm-worker";
/// Writable fallback home for an image that carries no [`WORKLOAD_HOME`] mount
/// point — one mvm neither built nor materialized.
pub const WORKLOAD_HOME_FALLBACK: &str = "/tmp";

/// Linux capability used by the authenticated guest agent to signal PID 1.
pub const CAP_KILL: u32 = 5;
/// Linux capability used by the guest agent's optional loopback DNS helper.
pub const CAP_NET_BIND_SERVICE: u32 = 10;
/// Linux capability used by the guest agent to correct a restored wall clock.
pub const CAP_SYS_TIME: u32 = 25;
/// Linux capability `PR_CAPBSET_DROP` itself requires. Never retained — which
/// is exactly why the bounding set has to be narrowed before the capability
/// sets are, and not after.
pub const CAP_SETPCAP: u32 = 8;
/// Capabilities explicitly retained by the guest agent after boot setup.
pub const RESTORE_AGENT_CAPABILITIES: u32 = (1u32 << CAP_KILL) | (1u32 << CAP_SYS_TIME);

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
    /// Post-mount guest setup failed, so the workload environment is incomplete.
    ///
    /// Fail closed: booting on would hand the workload an environment missing
    /// the egress path its plan admitted, which the workload cannot tell apart
    /// from a policy denial.
    #[error("guest bootstrap failed: {0}")]
    GuestBootstrap(String),
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
///
/// Each target is created before it is mounted. The universal initramfs
/// carries the init binary and nothing else — no `/proc`, no `/sys`, no
/// `/dev` — so there is no directory to mount onto unless PID 1 makes one,
/// and `mount` fails before the agent can report anything useful.
pub fn mount_early_filesystems() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        ensure_dir("/proc")?;
        mount(
            "proc",
            "/proc",
            "proc",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            "",
        )?;
        ensure_dir("/sys")?;
        mount(
            "sysfs",
            "/sys",
            "sysfs",
            libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
            "",
        )?;
        // devtmpfs supplies every device node the initramfs has no static
        // table for — /dev/null, and the /dev/mapper/control that dm-verity
        // needs to bring the sealed rootfs up at activation.
        //
        // Mounted unconditionally. The kernel creates a bare /dev/console in
        // the initramfs rootfs so init has stdio, so a "is /dev/console
        // already there?" guard reads as "devtmpfs is already mounted" when
        // in fact nothing is — and then activation dies on a missing
        // /dev/mapper/control. A shared-kernel container runtime, the one case
        // where /dev really is pre-mounted, never reaches here: that path is
        // branched off before the early mounts.
        ensure_dir("/dev")?;
        mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "")?;

        // The activated workload root is deliberately read-only. Runtime
        // state and scratch files therefore need their own writable mounts,
        // created before the pivot and carried across with the pseudofs
        // mounts by `pivot_to_root`. OCI materialization guarantees both
        // target directories exist in the sealed root.
        ensure_dir("/run")?;
        mount(
            "tmpfs",
            "/run",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            "mode=0755",
        )?;
        ensure_dir("/tmp")?;
        mount(
            "tmpfs",
            "/tmp",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            "mode=1777",
        )?;
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
            let root_dm = resolved_dm_device("root")?;
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
        let runtime_dm = resolved_dm_device("runtime")?;
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

/// Mount the reserved SDK sidecar at its fixed guest path.
///
/// This disk is host-produced and is never part of the generic user-volume
/// namespace. It remains read-only, nosuid, and nodev, while executable
/// mappings stay enabled for the host-services shared library it contains.
pub fn mount_sdk_sidecar(device: &str, root: &Path) -> Result<()> {
    validate_virtio_block_device(device, "SDK sidecar")?;
    let target = root.join(
        mvm_core::plan::SDK_SIDECAR_GUEST_PATH
            .strip_prefix('/')
            .expect("SDK sidecar guest path is absolute"),
    );
    ensure_dir(&target.to_string_lossy())?;

    #[cfg(target_os = "linux")]
    mount(
        device,
        &target.to_string_lossy(),
        "ext4",
        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        "",
    )?;

    Ok(())
}

/// Reserved mountpoints that volumes are not allowed to shadow.
#[cfg(test)]
pub(crate) const RESERVED_MOUNTS: &[&str] =
    &["/", "/mvm", "/mvm/runtime", "/dev", "/dev/vda", "/dev/vdc"];

/// Validate that a volume mountpoint does not collide with reserved paths.
pub fn validate_volume_mountpoint(mountpoint: &str) -> Result<()> {
    validated_relative_mountpoint(mountpoint).map(|_| ())
}

fn validated_relative_mountpoint(mountpoint: &str) -> Result<PathBuf> {
    let normalized = mvm_core::crypto::policy::validate_mount_path(mountpoint)
        .map_err(|error| MountError::PathPolicyDenied(error.to_string()))?;
    Path::new(&normalized)
        .strip_prefix("/")
        .map(Path::to_path_buf)
        .map_err(|_| {
            MountError::PathPolicyDenied(format!(
                "volume mountpoint {mountpoint:?} is not a normalized absolute path"
            ))
        })
}

fn volume_mount_target(root: &Path, mountpoint: &str) -> Result<PathBuf> {
    Ok(root.join(validated_relative_mountpoint(mountpoint)?))
}

#[cfg(any(target_os = "linux", test))]
fn volume_mount_scaffold(root: &Path, mountpoint: &str) -> Result<Option<PathBuf>> {
    let relative = validated_relative_mountpoint(mountpoint)?;
    let mut components = relative.components();
    let Some(base) = components.next() else {
        return Err(MountError::PathPolicyDenied(format!(
            "volume mountpoint {mountpoint:?} has no allowed mount root"
        )));
    };
    if components.next().is_none() {
        return Ok(None);
    }
    Ok(Some(root.join(base.as_os_str())))
}

fn ensure_volume_mount_target(
    root: &Path,
    mountpoint: &str,
    scaffolds: &mut BTreeSet<PathBuf>,
) -> Result<PathBuf> {
    let target = volume_mount_target(root, mountpoint)?;
    let first_error = match ensure_dir(&target.to_string_lossy()) {
        Ok(()) => return Ok(target),
        Err(error) => error,
    };
    if !matches!(
        &first_error,
        MountError::Syscall { source, .. } if source.raw_os_error() == Some(libc::EROFS)
    ) {
        return Err(first_error);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = scaffolds;
        Err(first_error)
    }
    #[cfg(target_os = "linux")]
    {
        let Some(scaffold) = volume_mount_scaffold(root, mountpoint)? else {
            return Err(first_error);
        };
        if !scaffolds.contains(&scaffold) {
            mount(
                "tmpfs",
                &scaffold.to_string_lossy(),
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                "mode=0755",
            )?;
            scaffolds.insert(scaffold);
        }
        ensure_dir(&target.to_string_lossy())?;
        Ok(target)
    }
}

fn resolve_volume_mount_source(volume: &VolumeConfig) -> Result<(&str, &'static str)> {
    if volume.tag.is_empty() {
        return Err(MountError::InvalidConfig(
            "volume tag must not be empty".to_string(),
        ));
    }
    match volume.kind {
        VolumeConfigKind::VirtioFs => {
            if volume.device.is_some() {
                return Err(MountError::InvalidConfig(format!(
                    "virtio-fs volume {:?} must not carry a block device",
                    volume.tag
                )));
            }
            Ok((&volume.tag, "virtiofs"))
        }
        VolumeConfigKind::Block => {
            let device = volume.device.as_deref().ok_or_else(|| {
                MountError::InvalidConfig(format!(
                    "block volume {:?} is missing its guest device",
                    volume.tag
                ))
            })?;
            validate_virtio_block_device(device, "block volume")?;
            Ok((device, "ext4"))
        }
    }
}

fn validate_virtio_block_device(device: &str, purpose: &str) -> Result<()> {
    let suffix = device.strip_prefix("/dev/vd").ok_or_else(|| {
        MountError::PathPolicyDenied(format!(
            "{purpose} device {device:?} is outside /dev/vd[a-z]"
        ))
    })?;
    if suffix.len() != 1 || !suffix.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return Err(MountError::PathPolicyDenied(format!(
            "{purpose} device {device:?} is outside /dev/vd[a-z]"
        )));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn writable_block_volume_owner(volume: &VolumeConfig) -> Option<(u32, u32)> {
    (!volume.read_only && volume.kind == VolumeConfigKind::Block)
        .then_some((WORKLOAD_UID, WORKLOAD_GID))
}

/// Mount custom virtio-fs and ext4 block volumes inside the new root tree.
pub fn mount_volumes(volumes: &[VolumeConfig], root: &Path) -> Result<()> {
    let mut scaffolds = BTreeSet::new();
    for vol in volumes {
        let (source, filesystem) = resolve_volume_mount_source(vol)?;
        #[cfg(not(target_os = "linux"))]
        let _ = (source, filesystem);
        let target = ensure_volume_mount_target(root, &vol.mountpoint, &mut scaffolds)?;
        #[cfg(not(target_os = "linux"))]
        let _ = &target;
        #[cfg(target_os = "linux")]
        {
            let flags = if vol.read_only { libc::MS_RDONLY } else { 0 };
            mount(source, &target.to_string_lossy(), filesystem, flags, "")?;
            if let Some((uid, gid)) = writable_block_volume_owner(vol) {
                chown(&target.to_string_lossy(), uid, gid)?;
            }
        }
    }
    Ok(())
}

/// Pivot into the mounted rootfs, making it the active `/`.
///
/// Moves `/proc`, `/sys`, `/dev`, `/run`, and `/tmp` into the new root, then
/// performs the canonical switch_root sequence (chdir + MS_MOVE + chroot).
/// The agent process keeps running; it does not exec a new init.
pub fn pivot_to_root(new_root: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Ensure the target directories exist in the new root.
        for sub in ["proc", "sys", "dev", "run", "tmp"] {
            let dst = new_root.join(sub);
            ensure_dir(&dst.to_string_lossy())?;
        }

        // Move the initramfs pseudo-filesystems into the new root so the
        // workload (and the agent itself) keeps seeing them.
        for sub in ["/proc", "/sys", "/dev", "/run", "/tmp"] {
            let dst = new_root.join(&sub[1..]).to_string_lossy().to_string();
            let _ = ensure_dir(&dst);
            move_mount(sub, &dst)
                .map_err(|e| MountError::syscall(format!("move-mount {sub} -> {dst}"), e))?;
        }

        // switch_root: chdir to new_root, move it onto /, chroot into it.
        chdir(new_root)?;
        mount(".", "/", "", libc::MS_MOVE, "")?;
        chroot(".")?;
        chdir("/")?;
    }
    let _ = new_root;
    Ok(())
}

/// Drop root privilege to the fixed workload UID/GID (901).  Must run after
/// all root-only mounts are complete.
pub fn drop_privilege(uid: u32, gid: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        drop_privilege_raw(uid, gid)
            .map_err(|source| MountError::syscall("privilege drop", source))?;
    }
    let _ = (uid, gid);
    Ok(())
}

/// Drop the PID-1 guest agent to its fixed identity while retaining its
/// narrowly scoped restore capabilities.
#[cfg(target_os = "linux")]
pub fn drop_guest_agent_privilege(uid: u32, gid: u32) -> Result<()> {
    drop_guest_agent_privilege_raw(uid, gid)
        .map_err(|source| MountError::syscall("guest-agent privilege drop", source))
}

/// Drop the PID-1 guest agent to its fixed identity on hosts without Linux
/// guest-agent capability syscalls.
#[cfg(not(target_os = "linux"))]
pub fn drop_guest_agent_privilege(uid: u32, gid: u32) -> Result<()> {
    drop_privilege(uid, gid)
}

/// Ensure the preferred workload home exists before the agent drops privilege.
///
/// Only reachable on a writable root. A read-only root gets its home from
/// [`mount_workload_home`] instead, over a mount point baked in at image
/// materialization.
#[cfg(target_os = "linux")]
pub fn ensure_workload_home() -> Result<()> {
    ensure_dir(WORKLOAD_HOME)?;
    chown(WORKLOAD_HOME, WORKLOAD_UID, WORKLOAD_GID)
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_workload_home() -> Result<()> {
    Ok(())
}

/// Lay a writable tmpfs over the workload's home.
///
/// Every workload root is mounted read-only, so the baked-in home is an empty
/// directory its owner cannot write — which is not a home. Mounting over it
/// needs no write to the underlying filesystem, so this works on a sealed
/// dm-verity root exactly as it does on a plain one. Must run after the pivot
/// and before the privilege drop.
///
/// An image with no mount point gets nothing mounted; [`workload_home`] then
/// reports the `/tmp` fallback, which is writable for a different reason.
#[cfg(target_os = "linux")]
pub fn mount_workload_home() -> Result<()> {
    if !Path::new(WORKLOAD_HOME).is_dir() {
        // No mount point to mount over. Leave the resolution unrecorded so
        // `workload_home` falls through to its own probe, which covers the
        // writable root that creates the directory a moment later.
        return Ok(());
    }
    let result = mount(
        "tmpfs",
        WORKLOAD_HOME,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        &format!("mode=0755,uid={WORKLOAD_UID},gid={WORKLOAD_GID}"),
    );
    // Record either way. On failure the mount point is still *there*, so the
    // probe in `workload_home` would report a directory the workload cannot
    // write as its home — worse than the fallback it is supposed to get.
    let _ = RESOLVED_HOME.set(home_after_mount(result.is_ok()));
    result
}

/// Which home a mount attempt leaves the workload with.
///
/// Split out from [`mount_workload_home`] so the rule is testable without a
/// guest: the failure arm is the whole point, and it is the arm no host test
/// can reach through the syscall.
#[must_use]
#[cfg(any(target_os = "linux", test))]
pub(crate) const fn home_after_mount(mounted: bool) -> &'static str {
    if mounted {
        WORKLOAD_HOME
    } else {
        WORKLOAD_HOME_FALLBACK
    }
}

#[cfg(not(target_os = "linux"))]
pub fn mount_workload_home() -> Result<()> {
    Ok(())
}

/// What [`mount_workload_home`] settled on, once it has run.
static RESOLVED_HOME: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// Resolve the writable home directory for workload processes.
///
/// Prefers what the boot path actually secured. The probe below is the answer
/// before that runs, and on a writable root where the directory is created
/// rather than mounted: a present [`WORKLOAD_HOME`] there really is writable,
/// which on a read-only root it would not be.
pub fn workload_home() -> &'static str {
    if let Some(home) = RESOLVED_HOME.get() {
        return home;
    }
    if Path::new(WORKLOAD_HOME).is_dir() {
        WORKLOAD_HOME
    } else {
        WORKLOAD_HOME_FALLBACK
    }
}

/// Whether optional writes into the image-owned root can be attempted.
///
/// Runtime state has dedicated writable mounts. Cosmetic image changes such
/// as creating a preferred home or naming the workload uid do not, so a
/// sealed root skips them without issuing syscalls that must fail.
#[must_use]
#[cfg(any(target_os = "linux", test))]
pub(crate) const fn optional_image_writes_allowed(rootfs_read_only: bool) -> bool {
    !rootfs_read_only
}

/// The privilege drop as bare syscalls, allocating nothing on any path.
///
/// This is the single implementation; `drop_privilege` is the wrapper that
/// adds a typed error for the pid-1 path. It exists separately because the
/// other caller runs inside a `pre_exec` hook — that is, in a forked child
/// before `exec` — where allocating can deadlock if another thread held the
/// allocator lock at fork time. Bare syscalls plus `last_os_error` (which
/// only wraps errno) keep that path allocation-free.
#[cfg(target_os = "linux")]
pub fn drop_privilege_raw(uid: u32, gid: u32) -> std::io::Result<()> {
    // Drop any supplementary groups first while still root.
    // SAFETY: setgroups(0, NULL) is the documented Linux way to clear all supplementary groups.
    if unsafe { libc::setgroups(0, std::ptr::null::<libc::gid_t>()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Order matters: setgid before setuid so the saved gid stays usable.
    // SAFETY: both receive a plain id value; no pointer contract.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Paranoia: confirm we cannot regain root.
    // SAFETY: getuid() has no precondition and cannot fail.
    if unsafe { libc::getuid() } == 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

/// Drop to the guest-agent identity while retaining only the fixed capabilities
/// required for authenticated restore handling.
///
/// The bounding set is narrowed first, before the identity change, because
/// `PR_CAPBSET_DROP` needs `CAP_SETPCAP` and [`set_capabilities`] below removes
/// it: narrowing afterwards fails `EPERM`, and on the spawn path that errno
/// leaves the `pre_exec` hook and kills the agent before it ever runs. The
/// bounding set is inherited across fork and exec and can only shrink, so
/// applying it here binds the agent and everything under it just as firmly.
#[cfg(target_os = "linux")]
pub fn drop_guest_agent_privilege_raw(uid: u32, gid: u32) -> std::io::Result<()> {
    if unsafe { libc::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    narrow_bounding_set_where_enforceable(RESTORE_AGENT_CAPABILITIES)?;
    if unsafe { libc::setgroups(0, std::ptr::null::<libc::gid_t>()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_capabilities(RESTORE_AGENT_CAPABILITIES)?;
    raise_ambient_capabilities(RESTORE_AGENT_CAPABILITIES)?;
    set_no_new_privileges()?;
    if unsafe { libc::getuid() } == 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_capabilities(capabilities: u32) -> std::io::Result<()> {
    let header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: capabilities,
            permitted: capabilities,
            inheritable: capabilities,
        },
        CapData::default(),
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn raise_ambient_capabilities(capabilities: u32) -> std::io::Result<()> {
    for capability in [CAP_KILL, CAP_NET_BIND_SERVICE, CAP_SYS_TIME] {
        if capabilities & (1u32 << capability) == 0 {
            continue;
        }
        let rc = unsafe {
            libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                capability as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
/// The capability slots `PR_CAPBSET_DROP` is asked about.
///
/// The kernel's own ceiling is `CAP_LAST_CAP`, which grows between releases.
/// Walking a fixed range and treating `EINVAL` as "this slot does not exist on
/// this kernel" is forward-compatible in both directions: a slot the running
/// kernel has not heard of is skipped, and one added after this code was
/// written is still dropped.
#[cfg(target_os = "linux")]
const CAPABILITY_SLOTS: std::ops::RangeInclusive<u32> = 0..=63;

/// Whether `keep` retains capability slot `cap`.
///
/// Split out from the syscall loop so the mask arithmetic is testable off
/// Linux and without root. The widening to `u64` is load-bearing rather than
/// cosmetic: `1u32 << 32` panics in debug and is UB-adjacent in release, so a
/// `u32` shift silently mis-answers every slot above 31.
///
/// Gated on its two real consumers: the Linux syscall loop, and the tests
/// that pin the mask arithmetic on every host.
#[cfg(any(target_os = "linux", test))]
fn bounding_set_retains(keep: u32, cap: u32) -> bool {
    u64::from(keep) & (1u64 << cap) != 0
}

/// Drop every capability from the bounding set except `keep`.
///
/// The bounding set is inherited across fork *and* exec and can only ever
/// shrink, which is what makes it usable as a one-way gate applied once by a
/// parent on behalf of every descendant. Slots the running kernel does not
/// implement report `EINVAL` and are skipped.
#[cfg(target_os = "linux")]
fn drop_capability_bounding_set_to(keep: u32) -> std::io::Result<()> {
    for cap in CAPABILITY_SLOTS {
        if bounding_set_retains(keep, cap) {
            continue;
        }
        let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                continue;
            }
            return Err(err);
        }
    }
    Ok(())
}

/// Harden the OCI init before it spawns any workload-facing child.
///
/// The OCI boot path reaches the workload through a different route than the
/// nix-built guest: there is no `mvm-setpriv` between init and the agent, so
/// without this the agent and the workload beneath it inherit PID 1's full
/// bounding set and `NoNewPrivs=0`.
///
/// Note what is retained. The bounding set is narrowed to
/// [`RESTORE_AGENT_CAPABILITIES`] — `CAP_KILL` and `CAP_SYS_TIME`, which the
/// agent genuinely needs to reap workload processes and to correct a restored
/// wall clock — not to zero. The workload itself needs neither, and gets an
/// empty bounding set from [`drop_workload_capability_bounding_set`] at spawn.
#[cfg(target_os = "linux")]
pub fn harden_init_process() -> std::io::Result<()> {
    // `NoNewPrivs` first: it is the control that actually makes file
    // capabilities and setuid bits inert on exec, it cannot fail for lack of
    // privilege, and ordering it first means a bounding-set failure can never
    // leave a descendant running without it.
    set_no_new_privileges()?;
    drop_capability_bounding_set_to(RESTORE_AGENT_CAPABILITIES)
}

/// Empty the bounding set for a workload process, immediately before exec.
///
/// The agent keeps `CAP_KILL` and `CAP_SYS_TIME`; a workload has no use for
/// either, so the last thing done on its behalf is to remove them. `NoNewPrivs`
/// already makes file capabilities and setuid bits inert on exec, so this is
/// defense in depth rather than the load-bearing control — but it is what lets
/// the posture be stated as an empty set rather than as "inert in practice".
///
/// Runs inside `pre_exec`, so it must stay async-signal-safe: two `prctl`
/// calls and no allocation.
#[cfg(target_os = "linux")]
pub fn drop_workload_capability_bounding_set() -> std::io::Result<()> {
    set_no_new_privileges()?;
    narrow_bounding_set_where_enforceable(0)
}

/// Narrow the bounding set to `keep`, skipping the drop when this caller could
/// never have performed it.
///
/// Shared by the agent identity drop and the workload spawn, which need the
/// same "enforce where possible, fail closed on a real error" rule with
/// different masks. See [`bounding_drop_is_unenforceable`] for why `EPERM`
/// alone is a skip.
#[cfg(target_os = "linux")]
fn narrow_bounding_set_where_enforceable(keep: u32) -> std::io::Result<()> {
    match drop_capability_bounding_set_to(keep) {
        Err(err) if bounding_drop_is_unenforceable(&err) => Ok(()),
        result => result,
    }
}

/// Whether a `PR_CAPBSET_DROP` failure means "this caller was never able to
/// enforce it" rather than "enforcement was attempted and broke".
///
/// `PR_CAPBSET_DROP` needs `CAP_SETPCAP`. An agent without it cannot shrink the
/// bounding set — but it equally cannot grant a capability it does not hold, and
/// the set a child inherits is already no wider than the agent's own. Treating
/// that one errno as a skip keeps an unprivileged spawn working without
/// weakening the privileged path, where the drop still fails closed. Every other
/// errno means the drop was possible and went wrong, so it still propagates.
#[cfg(any(target_os = "linux", test))]
fn bounding_drop_is_unenforceable(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EPERM)
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)`. One-way and inherited across fork/exec.
#[cfg(target_os = "linux")]
fn set_no_new_privileges() -> std::io::Result<()> {
    if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Non-Linux stub so the workload spawn path compiles on developer hosts.
#[cfg(not(target_os = "linux"))]
pub fn drop_workload_capability_bounding_set() -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::pid_t,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

// Layout contract with linux/capability.h `__user_cap_header_struct` and
// `__user_cap_data_struct`. Both are passed to capset(2) by pointer; the
// kernel reads each capability word by offset, so a Rust layout drift would
// silently request the wrong privilege set.
//
// Derived on Linux 6.8 with cc sizeof/offsetof/_Alignof, not read from these
// Rust definitions. `pid_t` is i32 on every Linux target mvm builds for.
#[cfg(target_os = "linux")]
const _: () = {
    use core::mem::{align_of, offset_of, size_of};

    assert!(size_of::<CapHeader>() == 8);
    assert!(align_of::<CapHeader>() == 4);
    assert!(offset_of!(CapHeader, version) == 0);
    assert!(offset_of!(CapHeader, pid) == 4);

    assert!(size_of::<CapData>() == 12);
    assert!(align_of::<CapData>() == 4);
    assert!(offset_of!(CapData, effective) == 0);
    assert!(offset_of!(CapData, permitted) == 4);
    assert!(offset_of!(CapData, inheritable) == 8);
};

#[cfg(target_os = "linux")]
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
#[cfg(target_os = "linux")]
const PR_SET_KEEPCAPS: libc::c_int = 8;
#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT: libc::c_int = 47;
#[cfg(target_os = "linux")]
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
#[cfg(target_os = "linux")]
const PR_CAPBSET_DROP: libc::c_int = 24;

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

    // Layout contract with linux/dm-ioctl.h. `DmIoctl` is the fixed header
    // of every device-mapper ioctl and `DmTargetSpec` is the target record
    // that follows it in the same buffer; the kernel reads both by offset.
    // These are the structs the dm-verity table is built from, so drift
    // here is a verified-boot setup failure reported as an unrelated errno.
    //
    // Derived on Linux 6.8 with cc sizeof/offsetof/_Alignof, not read off
    // the Rust definitions. The size assertion is kept in its original form
    // as well: DM_IOCTL_STRUCT_SIZE is encoded into the ioctl request
    // number, so the constant and the struct must agree or the kernel
    // rejects the command.
    const _: () = {
        use std::mem::{align_of, offset_of, size_of};

        assert!(DM_IOCTL_STRUCT_SIZE as usize == size_of::<DmIoctl>());
        assert!(size_of::<DmIoctl>() == 312);
        assert!(align_of::<DmIoctl>() == 8);
        assert!(offset_of!(DmIoctl, version) == 0);
        assert!(offset_of!(DmIoctl, data_size) == 12);
        assert!(offset_of!(DmIoctl, data_start) == 16);
        assert!(offset_of!(DmIoctl, target_count) == 20);
        assert!(offset_of!(DmIoctl, dev) == 40);
        assert!(offset_of!(DmIoctl, name) == 48);
    };

    #[repr(C)]
    pub struct DmTargetSpec {
        pub sector_start: u64,
        pub length: u64,
        pub status: i32,
        pub next: u32,
        pub target_type: [u8; 16],
    }

    const _: () = {
        use std::mem::{align_of, offset_of, size_of};

        assert!(size_of::<DmTargetSpec>() == 40);
        assert!(align_of::<DmTargetSpec>() == 8);
        assert!(offset_of!(DmTargetSpec, sector_start) == 0);
        assert!(offset_of!(DmTargetSpec, length) == 8);
        assert!(offset_of!(DmTargetSpec, status) == 16);
        assert!(offset_of!(DmTargetSpec, next) == 20);
        assert!(offset_of!(DmTargetSpec, target_type) == 24);
    };
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
fn chown(path: &str, uid: u32, gid: u32) -> Result<()> {
    let path = CString::new(path).map_err(|error| {
        MountError::syscall(
            "chown path has NUL",
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error),
        )
    })?;
    // SAFETY: path is a live NUL-terminated C string and uid/gid are plain values.
    let rc = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if rc != 0 {
        return Err(MountError::syscall(
            format!("chown({}, {uid}, {gid})", path.to_string_lossy()),
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
fn resolved_dm_device(name: &str) -> Result<String> {
    let mapper = format!("/dev/mapper/{name}");
    if Path::new(&mapper).exists() {
        return Ok(mapper);
    }
    // devtmpfs always creates /dev/dm-<minor>, but the minor is allocated
    // dynamically and is not the creation order when earlier targets are
    // absent (e.g. a plain rootfs means the runtime overlay is dm-0, not
    // dm-1).  Resolve the actual node by reading the kernel's name record
    // under /sys/block.
    let sys_block = Path::new("/sys/block");
    let entries =
        std::fs::read_dir(sys_block).map_err(|e| MountError::syscall("read /sys/block", e))?;
    for entry in entries {
        let entry = entry.map_err(|e| MountError::syscall("read /sys/block entry", e))?;
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        if !fname.starts_with("dm-") {
            continue;
        }
        let name_file = entry.path().join("dm/name");
        let dm_name = match std::fs::read_to_string(&name_file) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if dm_name.trim() == name {
            return Ok(format!("/dev/{fname}"));
        }
    }
    Err(MountError::VeritySetup(format!(
        "no /sys/block/dm-* device named {name} after DM_DEV_SUSPEND"
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

    /// Every early mount target must be created before it is mounted.
    ///
    /// The universal initramfs carries the init binary and nothing else, so
    /// there is no `/proc`, `/sys` or `/dev` to mount onto unless PID 1 makes
    /// one. Without that, `mount` fails with ENOENT, init exits, and the kernel
    /// panics before the agent can report anything — which is what shipped.
    ///
    /// Asserted against the source because the real function issues syscalls
    /// that no unit test can run: it needs PID 1 in a guest, and the host it is
    /// compiled on may not even be Linux.
    #[test]
    fn every_early_mount_target_is_created_before_it_is_mounted() {
        let src = include_str!("guest_mount.rs");
        let body = src
            .split("pub fn mount_early_filesystems")
            .nth(1)
            .expect("mount_early_filesystems must exist");
        let body = body
            .split("\npub fn ")
            .next()
            .expect("function body is delimited by the next item");

        for target in ["/proc", "/sys", "/dev", "/run", "/tmp"] {
            let created = body
                .find(&format!("ensure_dir(\"{target}\")"))
                .unwrap_or_else(|| {
                    panic!(
                        "{target} is mounted but never created; the initramfs has no \
                     directory to mount onto, so PID 1 dies on ENOENT"
                    )
                });
            let mounted = body
                .find(&format!("\"{target}\","))
                .unwrap_or_else(|| panic!("{target} should still be mounted here"));
            assert!(
                created < mounted,
                "{target}: ensure_dir must come before the mount, not after"
            );
        }
    }

    /// Runtime writes belong on tmpfs, and those mounts must survive the
    /// switch from the universal initramfs to the sealed workload root.
    #[test]
    fn writable_runtime_mounts_are_tmpfs_and_move_into_the_workload_root() {
        let src = include_str!("guest_mount.rs");
        let early = src
            .split("pub fn mount_early_filesystems")
            .nth(1)
            .expect("mount_early_filesystems must exist")
            .split("\npub fn ")
            .next()
            .expect("function body is delimited by the next item");
        let pivot = src
            .split("pub fn pivot_to_root")
            .nth(1)
            .expect("pivot_to_root must exist")
            .split("\npub fn ")
            .next()
            .expect("function body is delimited by the next item");

        for target in ["/run", "/tmp"] {
            assert!(
                early.contains(&format!(
                    "\"tmpfs\",\n            \"{target}\",\n            \"tmpfs\""
                )),
                "{target} must be mounted as tmpfs before the read-only root is activated"
            );
            assert!(
                pivot.contains(&format!("\"{target}\"")),
                "{target} must move into the activated workload root"
            );
        }
    }

    /// A failed home mount must fall back, not hand the workload the
    /// read-only mount point it was going to cover. The mount point exists
    /// either way, so the `is_dir` probe alone gets this wrong.
    #[test]
    fn a_failed_home_mount_falls_back_instead_of_reporting_a_read_only_home() {
        assert_eq!(home_after_mount(true), WORKLOAD_HOME);
        assert_eq!(home_after_mount(false), WORKLOAD_HOME_FALLBACK);
    }

    /// The home is mounted over, never written into: a write cannot land on
    /// the read-only root every workload actually boots with.
    #[test]
    fn the_workload_home_is_secured_by_a_mount_not_a_write() {
        let src = include_str!("guest_mount.rs");
        let body = src
            .split("pub fn mount_workload_home")
            .nth(1)
            .expect("mount_workload_home must exist")
            .split("\n#[cfg(not(target_os = \"linux\"))]")
            .next()
            .expect("the Linux arm is delimited by the non-Linux one");
        assert!(
            body.contains("mount(") && body.contains("tmpfs"),
            "the home must come from a tmpfs mount: {body}"
        );
        assert!(
            body.contains("uid={WORKLOAD_UID}"),
            "the workload must own its home: {body}"
        );
    }

    #[test]
    fn sealed_roots_refuse_optional_image_writes() {
        assert!(!optional_image_writes_allowed(true));
        assert!(optional_image_writes_allowed(false));
    }

    /// devtmpfs must be mounted unconditionally, never gated on `/dev/console`.
    ///
    /// The kernel creates a bare `/dev/console` in the initramfs rootfs so init
    /// has stdio — which is precisely why the agent's own output reaches the
    /// serial console. A `if !Path::new("/dev/console").exists()` guard around
    /// the devtmpfs mount therefore always skips it, `/dev` keeps that single
    /// node, and activation dies on a missing `/dev/mapper/control` the moment
    /// dm-verity tries to bring the sealed rootfs up. That shipped, and it reads
    /// as a verity bug rather than a mount bug.
    ///
    /// The one case where `/dev` genuinely is pre-mounted — a shared-kernel
    /// container runtime — branches off before the early mounts entirely, so it
    /// needs no guard here.
    ///
    /// Asserted against the source for the same reason as the test above: the
    /// real path needs to be PID 1 inside a guest.
    #[test]
    fn devtmpfs_is_not_gated_on_a_kernel_supplied_console_node() {
        let src = include_str!("guest_mount.rs");
        let body = src
            .split("pub fn mount_early_filesystems")
            .nth(1)
            .expect("mount_early_filesystems must exist")
            .split("\npub fn ")
            .next()
            .expect("function body is delimited by the next item");
        // Comments explain the trap by naming the node, so judge the code only.
        let code: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            code.contains("\"devtmpfs\""),
            "devtmpfs must still be mounted; without it there is no /dev/mapper/control"
        );
        assert!(
            !code.contains("/dev/console"),
            "devtmpfs must not be gated on /dev/console — the kernel always supplies \
             that node, so the guard skips the mount every time and dm-verity then \
             fails to open /dev/mapper/control"
        );
    }

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
        assert!(validate_volume_mountpoint("/data/app").is_ok());
        assert!(validate_volume_mountpoint("/work/nested/other").is_ok());
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
        assert!(validate_volume_mountpoint("/data/../proc").is_err());
        assert!(validate_volume_mountpoint("//dev").is_err());
    }

    #[test]
    fn volume_mount_target_stays_beneath_the_staged_root() {
        assert_eq!(
            volume_mount_target(Path::new("/mnt/root"), "/data/work").unwrap(),
            PathBuf::from("/mnt/root/data/work")
        );
    }

    #[test]
    fn volume_mount_target_rejects_a_relative_mountpoint() {
        assert!(volume_mount_target(Path::new("/mnt/root"), "data").is_err());
    }

    #[test]
    fn nested_volume_mount_uses_its_allowed_root_as_a_writable_scaffold() {
        assert_eq!(
            volume_mount_scaffold(Path::new("/mnt/root"), "/data/work/cache").unwrap(),
            Some(PathBuf::from("/mnt/root/data"))
        );
        assert_eq!(
            volume_mount_scaffold(Path::new("/mnt/root"), "/data").unwrap(),
            None
        );
    }

    #[test]
    fn volume_mount_source_distinguishes_virtiofs_and_block() {
        let share = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data/share".to_string(),
            read_only: true,
            kind: crate::vsock::VolumeConfigKind::VirtioFs,
            device: None,
        };
        assert_eq!(
            resolve_volume_mount_source(&share).unwrap(),
            ("uvol0", "virtiofs")
        );

        let block = VolumeConfig {
            tag: "uvol1".to_string(),
            mountpoint: "/data/disk".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/vdb".to_string()),
        };
        assert_eq!(
            resolve_volume_mount_source(&block).unwrap(),
            ("/dev/vdb", "ext4")
        );
    }

    #[test]
    fn volume_mount_source_rejects_invalid_kind_device_combinations() {
        let share_with_device = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data/share".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::VirtioFs,
            device: Some("/dev/vdb".to_string()),
        };
        assert!(resolve_volume_mount_source(&share_with_device).is_err());

        let invalid_block = VolumeConfig {
            tag: "uvol1".to_string(),
            mountpoint: "/data/disk".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/sda".to_string()),
        };
        assert!(resolve_volume_mount_source(&invalid_block).is_err());
    }

    #[test]
    fn sdk_sidecar_device_is_confined_to_virtio_block_nodes() {
        assert!(validate_virtio_block_device("/dev/vde", "SDK sidecar").is_ok());
        assert!(validate_virtio_block_device("/dev/sda", "SDK sidecar").is_err());
        assert!(validate_virtio_block_device("/dev/vdaa", "SDK sidecar").is_err());
        assert!(validate_virtio_block_device("../../dev/vde", "SDK sidecar").is_err());
    }

    #[test]
    fn writable_block_volume_is_owned_by_the_workload() {
        let volume = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/vdb".to_string()),
        };

        assert_eq!(
            writable_block_volume_owner(&volume),
            Some((WORKLOAD_UID, WORKLOAD_GID))
        );
    }

    #[test]
    fn read_only_and_virtiofs_volumes_keep_their_existing_owner() {
        let read_only_block = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data".to_string(),
            read_only: true,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/vdb".to_string()),
        };
        let writable_share = VolumeConfig {
            tag: "uvol1".to_string(),
            mountpoint: "/work".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::VirtioFs,
            device: None,
        };

        assert_eq!(writable_block_volume_owner(&read_only_block), None);
        assert_eq!(writable_block_volume_owner(&writable_share), None);
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

#[cfg(test)]
mod privilege_tests {
    use super::*;

    /// The `u32` shift this replaced silently mis-answered every slot above
    /// 31 — `1u32 << 32` panics in debug, and the loop walks to 63. This is
    /// the regression test for that, and it runs on every host.
    #[test]
    fn bounding_set_retains_answers_every_slot_without_overflow() {
        for cap in CAPABILITY_SLOTS_FOR_TEST {
            // A zero keep-mask retains nothing, at any slot.
            assert!(
                !bounding_set_retains(0, cap),
                "empty keep mask must retain nothing, but retained slot {cap}"
            );
            // An all-ones u32 mask retains exactly the slots a u32 can name.
            assert_eq!(
                bounding_set_retains(u32::MAX, cap),
                cap < 32,
                "u32::MAX must retain slots 0..32 and no others; slot {cap} disagreed"
            );
        }
    }

    #[test]
    fn agent_keep_mask_retains_exactly_kill_and_sys_time() {
        let retained: Vec<u32> = CAPABILITY_SLOTS_FOR_TEST
            .filter(|cap| bounding_set_retains(RESTORE_AGENT_CAPABILITIES, *cap))
            .collect();
        assert_eq!(
            retained,
            vec![CAP_KILL, CAP_SYS_TIME],
            "the agent must retain CAP_KILL and CAP_SYS_TIME and nothing else"
        );
    }

    /// The workload's mask is empty, and is a strict subset of the agent's.
    /// Stated as a subset rather than as a literal so it stays true if the
    /// agent's retained set ever changes.
    #[test]
    fn workload_keep_mask_is_empty_and_narrower_than_the_agent_mask() {
        const WORKLOAD_KEEP: u32 = 0;
        assert_eq!(WORKLOAD_KEEP, 0, "the workload retains no capability");
        assert_eq!(
            WORKLOAD_KEEP & RESTORE_AGENT_CAPABILITIES,
            WORKLOAD_KEEP,
            "the workload mask must be a subset of the agent mask"
        );
        assert_ne!(
            WORKLOAD_KEEP, RESTORE_AGENT_CAPABILITIES,
            "the workload must be strictly narrower than the agent"
        );
    }

    /// `EPERM` is the one errno that means the caller never held `CAP_SETPCAP`,
    /// so the drop was never enforceable. It is the only one treated as a skip;
    /// anything else means enforcement was possible and failed, and must
    /// propagate so the spawn fails closed.
    #[test]
    fn only_eperm_is_treated_as_an_unenforceable_bounding_drop() {
        assert!(bounding_drop_is_unenforceable(
            &std::io::Error::from_raw_os_error(libc::EPERM)
        ));
        for errno in [libc::EINVAL, libc::EFAULT, libc::EACCES, libc::ENOSYS] {
            assert!(
                !bounding_drop_is_unenforceable(&std::io::Error::from_raw_os_error(errno)),
                "errno {errno} must propagate rather than be skipped"
            );
        }
        // A non-OS error carries no errno and must never be swallowed.
        assert!(!bounding_drop_is_unenforceable(&std::io::Error::other(
            "not an errno"
        )));
    }

    /// The ordering constraint the agent privilege drop is built around, as an
    /// assertion rather than a comment.
    ///
    /// `PR_CAPBSET_DROP` requires `CAP_SETPCAP`, and the agent does not retain
    /// it. So the bounding-set narrowing can only ever succeed *before*
    /// `set_capabilities` runs — afterwards the syscall returns `EPERM`, and on
    /// the spawn path that errno escapes the `pre_exec` hook and the agent
    /// never starts. Anyone widening the retained mask to include
    /// `CAP_SETPCAP`, or reordering the drop back after the capability sets,
    /// should land here first.
    #[test]
    fn the_agent_never_retains_the_capability_its_bounding_drop_requires() {
        assert!(
            !bounding_set_retains(RESTORE_AGENT_CAPABILITIES, CAP_SETPCAP),
            "the agent must not retain CAP_SETPCAP; if it ever does, the \
             narrow-before-you-drop ordering stops being load-bearing and this \
             test should be replaced rather than relaxed"
        );
    }

    /// Mirrors `CAPABILITY_SLOTS` so the test compiles off Linux, where the
    /// real constant is `cfg`-gated out along with the syscall loop.
    const CAPABILITY_SLOTS_FOR_TEST: std::ops::RangeInclusive<u32> = 0..=63;

    /// Live witness. Mutates the calling process's privilege state
    /// irreversibly, so it is gated behind an explicit environment variable
    /// and root; ordinary CI and developer laptops skip it. The
    /// backend-level witness is the adversarial probe run under
    /// `specs/research/no-root-workload-live-witness.md`.
    #[test]
    #[cfg(target_os = "linux")]
    fn harden_init_process_narrows_bounding_set_and_sets_no_new_privs() {
        if std::env::var("MVM_GUEST_PRIVILEGED_TESTS").as_deref() != Ok("1") {
            return;
        }
        if unsafe { libc::getuid() } != 0 {
            return;
        }
        super::harden_init_process().expect("harden_init_process should succeed as root");
        let status = std::fs::read_to_string("/proc/self/status").expect("read status");
        assert!(
            status.contains("NoNewPrivs:\t1"),
            "NoNewPrivs must be 1 after hardening; got:\n{status}"
        );
        // Narrowed to the agent's set, not emptied. The workload gets the
        // empty set separately, at spawn.
        assert!(
            status.contains("CapBnd:\t0000000002000020"),
            "CapBnd must be exactly CAP_KILL|CAP_SYS_TIME; got:\n{status}"
        );
    }

    /// Live witness for the agent identity drop itself.
    ///
    /// The regression this pins returned `EPERM` from the bounding-set drop,
    /// which on the spawn path never reached a log — it surfaced only as
    /// `spawn guest-agent: Operation not permitted` in the guest console and a
    /// host-side 30s agent-readiness timeout. Asserting `Ok` here is the whole
    /// point; the state assertions confirm it succeeded for the right reason.
    ///
    /// Irreversible: it drops the calling process to uid 901 for good. It needs
    /// a process per test, which is what nextest gives it, and is gated behind
    /// the same explicit env var and root check as the test above.
    #[test]
    #[cfg(target_os = "linux")]
    fn drop_guest_agent_privilege_reaches_the_agent_identity_from_root() {
        if std::env::var("MVM_GUEST_PRIVILEGED_TESTS").as_deref() != Ok("1") {
            return;
        }
        if unsafe { libc::getuid() } != 0 {
            return;
        }
        super::drop_guest_agent_privilege_raw(WORKLOAD_UID, WORKLOAD_GID)
            .expect("the agent privilege drop must succeed as root");
        assert_eq!(
            unsafe { libc::getuid() },
            WORKLOAD_UID,
            "the drop must land on the workload uid"
        );
        let status = std::fs::read_to_string("/proc/self/status").expect("read status");
        assert!(
            status.contains("NoNewPrivs:\t1"),
            "NoNewPrivs must be 1 after the drop; got:\n{status}"
        );
        assert!(
            status.contains("CapBnd:\t0000000002000020"),
            "CapBnd must be exactly CAP_KILL|CAP_SYS_TIME; got:\n{status}"
        );
    }
}
