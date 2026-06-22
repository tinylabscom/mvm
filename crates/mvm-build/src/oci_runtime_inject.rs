//! Inject the mvm guest runtime into an OCI-unpacked rootfs.
//!
//! An arbitrary OCI image (alpine, debian, a language base) ships none
//! of the mvm runtime: no guest agent, no `/init` that brings the agent
//! up, no `/mvm/runtime` overlay mount point. Without those, a microVM
//! booted from the image has no vsock control plane — `run --image`
//! boots a kernel that can't be talked to and times out at
//! `wait_for_agent`.
//!
//! This module is the host-side fix. It runs against the unpacked OCI
//! tree *before* it is sealed into `rootfs.ext4`, baking in:
//!
//! - `/usr/local/bin/mvm-guest-agent` + `/usr/local/bin/mvm-guest-netinit`
//!   — the cross-compiled guest binaries (the agent is the sole control
//!   plane; netinit installs the guest-side network defense).
//! - `/init` — PID 1. Mounts the pseudo-filesystems, runs netinit, then
//!   forks the agent and idles. The OCI image's own entrypoint never
//!   runs as PID 1; it only ever runs *under* the agent, over vsock —
//!   preserving the agent-is-the-only-exec-gate posture.
//! - `/mvm/runtime` — the overlay mount point. On Firecracker the host
//!   attaches a verity-sealed overlay here; the injected `/init` prefers
//!   the overlay-resident agent and falls back to the baked one, exactly
//!   like a mkGuest rootfs. On libkrun/Vz no overlay attaches and the
//!   baked binaries are used.
//! - `/etc/mvm/{name,variant}` — the minimal markers the agent reads.
//!
//! Because the mount point + overlay-preferring `/init` are genuinely
//! present after injection, the rootfs can carry an honest
//! `overlay_aware: true` sidecar ([`crate::builder_vm::GuestSidecar::for_oci_run`])
//! and pass `admit_overlay_aware` without scoping the gate off.
//!
//! Everything here is plain host filesystem I/O against the staging
//! directory — no VM, no nix. The builder-VM materialize step copies the
//! staging tree (now carrying the injected runtime) into the ext4 as-is.

use std::io;
use std::path::{Path, PathBuf};

/// The cross-compiled guest binaries to bake into the rootfs. Produced
/// on the host by [`crate::guest_agent_build`] (source-checkout
/// `cargo-zigbuild`) or unpacked from the published runtime overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MvmRuntimeBinaries {
    /// Static guest agent binary (`mvm-guest-agent`).
    pub agent: PathBuf,
    /// Static guest netinit binary (`mvm-guest-netinit`).
    pub netinit: PathBuf,
}

/// Where the injected guest binaries land inside the rootfs.
const AGENT_DEST: &str = "usr/local/bin/mvm-guest-agent";
const NETINIT_DEST: &str = "usr/local/bin/mvm-guest-netinit";

/// PID-1 init baked into an OCI rootfs so `run --image` has a vsock
/// control plane. POSIX `sh` (busybox `ash` in alpine and friends).
///
/// Contract, in order:
/// 1. Mount `/proc`, `/sys`, `/dev` (+ `devpts`, `tmpfs` for `/run`,
///    `/tmp`) — the agent and any exec'd command need them.
/// 2. Create the `/mvm/runtime` overlay mount point.
/// 3. Mount each `machine run --volume` host share (`mvm.uvols=` cmdline)
///    as virtio-fs at its guest path, before the workload comes up.
/// 4. Run the guest-side network defense (netinit), overlay copy first.
/// 5. Fork the agent (overlay copy first, baked fallback) and idle.
///
/// The agent is forked, not `exec`'d: PID 1 must stay alive to keep the
/// VM up while the agent serves vsock RPC. An input-less idle loop
/// avoids depending on `sleep infinity`.
pub fn oci_init_script() -> String {
    // Note: `mkdir -p /mvm/runtime` is created at injection time too, so
    // the mount point survives even on a read-only rootfs; the runtime
    // `mkdir` here is belt-and-braces for the writable-rootfs case.
    r#"#!/bin/sh
# mvm OCI runtime init. The mvm guest agent is the sole control plane:
# this PID 1 mounts the pseudo-filesystems, brings up guest-side network
# defense, then forks the agent and idles. The OCI image entrypoint runs
# only under the agent (over vsock), never as PID 1.
set -u

mount -t proc     none /proc    2>/dev/null || true
mount -t sysfs    none /sys     2>/dev/null || true
mount -t devtmpfs none /dev     2>/dev/null || true
mkdir -p /dev/pts /dev/shm /run /tmp /mvm/runtime 2>/dev/null || true
mount -t devpts none /dev/pts 2>/dev/null || true
mount -t tmpfs  none /run     2>/dev/null || true
mount -t tmpfs  none /tmp     2>/dev/null || true

# User volumes (machine run --volume). The host encoded
# mvm.uvols=<tag>:<hex(guest_path)>:<ro|rw>:<fs|blk>;... onto the kernel
# cmdline (mvm_core::vm_backend::encode_user_volumes_cmdline); mount each
# virtio-fs share at its guest path. virtio-fs is built into the workload
# kernel, so no module load is needed. Best-effort: a bad mount logs and
# continues rather than wedging PID 1. Disk (blk) volumes are attached as
# block devices for the workload to mount itself. Mirrors the mkGuest init.
MVM_UVOLS=$(sed -n 's/.*\bmvm\.uvols=\([^ ]*\).*/\1/p' /proc/cmdline 2>/dev/null)
if [ -n "$MVM_UVOLS" ]; then
  echo "$MVM_UVOLS" | tr ';' '\n' | while IFS=: read -r utag uhex umode ukind; do
    [ -n "$utag" ] || continue
    [ -n "$uhex" ] || continue
    upath=$(printf '%b' "$(echo "$uhex" | sed 's/../\\x&/g')")
    [ -n "$upath" ] || continue
    if [ "$ukind" = blk ]; then
      echo "mvm-oci-init: user disk volume for '$upath' attached (guest auto-mount of disks not wired)"
      continue
    fi
    mkdir -p "$upath" 2>/dev/null || true
    if [ "$umode" = ro ]; then
      mount -t virtiofs -o ro "$utag" "$upath" \
        && echo "mvm-oci-init: mounted user volume $utag at $upath (ro)" \
        || echo "mvm-oci-init: user volume $utag -> $upath failed (mountpoint must exist on the ro rootfs)"
    else
      mount -t virtiofs "$utag" "$upath" \
        && echo "mvm-oci-init: mounted user volume $utag at $upath (rw)" \
        || echo "mvm-oci-init: user volume $utag -> $upath failed (mountpoint must exist on the ro rootfs)"
    fi
  done
fi

# Guest-side network defense — prefer the overlay-resident netinit.
MVM_NETINIT=
if [ -x /mvm/runtime/netinit ]; then
  MVM_NETINIT=/mvm/runtime/netinit
elif [ -x /usr/local/bin/mvm-guest-netinit ]; then
  MVM_NETINIT=/usr/local/bin/mvm-guest-netinit
fi
if [ -n "$MVM_NETINIT" ]; then
  "$MVM_NETINIT" || echo "mvm-oci-init: netinit exited nonzero; continuing"
fi

# The agent is the control plane. Prefer the overlay-resident agent
# (Firecracker verity overlay); fall back to the baked-in copy
# (libkrun/Vz). Both are exec-tested so a half-attached overlay still
# boots via the baked path rather than agent-less.
MVM_AGENT=
if [ -x /mvm/runtime/agent ]; then
  MVM_AGENT=/mvm/runtime/agent
elif [ -x /usr/local/bin/mvm-guest-agent ]; then
  MVM_AGENT=/usr/local/bin/mvm-guest-agent
fi
if [ -n "$MVM_AGENT" ]; then
  "$MVM_AGENT" &
else
  echo "mvm-oci-init: no mvm guest agent present; control plane unavailable" >&2
fi

# PID 1 idles so the VM stays up while the agent serves vsock RPC.
while :; do
  /bin/sh -c 'sleep 2147483647' 2>/dev/null || sleep 86400 || break
done
"#
    .to_string()
}

/// Inject the mvm runtime into the OCI-unpacked `rootfs_dir`.
///
/// Idempotent: re-running overwrites the injected files. Returns the
/// paths created (the `/init` and the two binary destinations) so the
/// caller can log/verify them.
pub fn inject_mvm_runtime(
    rootfs_dir: &Path,
    bins: &MvmRuntimeBinaries,
) -> Result<InjectedPaths, io::Error> {
    if !rootfs_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "OCI rootfs staging dir does not exist: {}",
                rootfs_dir.display()
            ),
        ));
    }

    // Overlay mount point — present on disk so it survives even when the
    // rootfs is mounted read-only at boot.
    let runtime_dir = rootfs_dir.join("mvm").join("runtime");
    std::fs::create_dir_all(&runtime_dir)?;

    // Minimal markers the agent reads. `variant=dev` keeps the
    // interactive/console surface enabled (a `run --image` is a dev
    // surface); `--prod` refuses mutable OCI references upstream.
    let etc_mvm = rootfs_dir.join("etc").join("mvm");
    std::fs::create_dir_all(&etc_mvm)?;
    write_file(&etc_mvm.join("variant"), b"dev\n", 0o644)?;
    write_file(&etc_mvm.join("name"), b"oci\n", 0o644)?;

    // Baked guest binaries.
    let bin_dir = rootfs_dir.join("usr").join("local").join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let agent_dest = rootfs_dir.join(AGENT_DEST);
    let netinit_dest = rootfs_dir.join(NETINIT_DEST);
    copy_exec(&bins.agent, &agent_dest)?;
    copy_exec(&bins.netinit, &netinit_dest)?;

    // PID 1.
    let init_dest = rootfs_dir.join("init");
    write_file(&init_dest, oci_init_script().as_bytes(), 0o755)?;

    Ok(InjectedPaths {
        init: init_dest,
        agent: agent_dest,
        netinit: netinit_dest,
        runtime_mount_point: runtime_dir,
    })
}

/// Paths written by [`inject_mvm_runtime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedPaths {
    pub init: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub runtime_mount_point: PathBuf,
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    set_mode(path, mode)
}

fn copy_exec(src: &Path, dst: &Path) -> Result<(), io::Error> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Remove an existing destination first so a read-only (0444) cached
    // binary from a prior inject doesn't reject the overwrite.
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst)?;
    set_mode(dst, 0o755)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_script_mounts_pseudofs_and_forks_agent() {
        let s = oci_init_script();
        assert!(s.starts_with("#!/bin/sh"));
        // Pseudo-filesystems the agent + exec'd commands depend on.
        assert!(s.contains("mount -t proc"));
        assert!(s.contains("mount -t sysfs"));
        assert!(s.contains("mount -t devtmpfs"));
        // Overlay mount point.
        assert!(s.contains("/mvm/runtime"));
        // Overlay-preferring agent resolution, baked fallback.
        assert!(s.contains("/mvm/runtime/agent"));
        assert!(s.contains("/usr/local/bin/mvm-guest-agent"));
        // Agent is forked (control plane), not exec'd — PID 1 must idle.
        assert!(s.contains("\"$MVM_AGENT\" &"));
        // Netinit before the agent.
        let netinit_at = s.find("mvm-guest-netinit").expect("netinit referenced");
        let agent_fork_at = s.find("\"$MVM_AGENT\" &").expect("agent fork");
        assert!(
            netinit_at < agent_fork_at,
            "netinit must run before the agent fork"
        );
    }

    #[test]
    fn init_script_mounts_user_volumes_before_the_agent() {
        let s = oci_init_script();
        // Reads the host-encoded cmdline token and mounts each share as virtio-fs.
        assert!(
            s.contains("mvm.uvols="),
            "init must parse the uvols cmdline"
        );
        assert!(
            s.contains("mount -t virtiofs -o ro"),
            "ro shares mount as virtio-fs"
        );
        assert!(
            s.contains("mount -t virtiofs \"$utag\""),
            "rw shares mount as virtio-fs"
        );
        assert!(s.contains("mkdir -p \"$upath\""), "mountpoint is created");
        // Disk volumes are left for the workload, not auto-mounted here.
        assert!(s.contains("guest auto-mount of disks not wired"));
        // Shares mount before the workload agent comes up so the workload sees them.
        let uvols_at = s.find("mvm.uvols=").expect("uvols parse");
        let agent_fork_at = s.find("\"$MVM_AGENT\" &").expect("agent fork");
        assert!(
            uvols_at < agent_fork_at,
            "user volumes must mount before the agent fork"
        );
    }

    fn fake_bins(dir: &Path) -> MvmRuntimeBinaries {
        let agent = dir.join("agent.bin");
        let netinit = dir.join("netinit.bin");
        std::fs::write(&agent, b"\x7fELF-agent").unwrap();
        std::fs::write(&netinit, b"\x7fELF-netinit").unwrap();
        MvmRuntimeBinaries { agent, netinit }
    }

    #[test]
    fn inject_writes_init_binaries_and_mount_point() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        let injected = inject_mvm_runtime(&root, &bins).expect("inject");

        // /init present, executable, is our script.
        let init = std::fs::read_to_string(&injected.init).unwrap();
        assert!(init.contains("mvm OCI runtime init"));
        assert!(is_executable(&injected.init));
        // Binaries copied to the baked path, executable, content-equal.
        assert_eq!(std::fs::read(&injected.agent).unwrap(), b"\x7fELF-agent");
        assert!(is_executable(&injected.agent));
        assert!(is_executable(&injected.netinit));
        // Overlay mount point exists on disk.
        assert!(injected.runtime_mount_point.is_dir());
        assert!(root.join("mvm/runtime").is_dir());
        // Markers.
        assert_eq!(
            std::fs::read_to_string(root.join("etc/mvm/variant")).unwrap(),
            "dev\n"
        );
    }

    #[test]
    fn inject_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        inject_mvm_runtime(&root, &bins).expect("first inject");
        // A second inject (e.g. cache reuse) must not error on existing files.
        let second = inject_mvm_runtime(&root, &bins).expect("second inject");
        assert!(is_executable(&second.agent));
    }

    #[test]
    fn inject_rejects_missing_rootfs_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());
        let err = inject_mvm_runtime(&tmp.path().join("nope"), &bins).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    fn is_executable(p: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    fn is_executable(_p: &Path) -> bool {
        true
    }
}
