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
//! - `/usr/local/bin/mvm-guest-agent`, `/usr/local/bin/mvm-guest-netinit`, and
//!   `/usr/local/bin/mvm-guest-netd` — the cross-compiled guest binaries (the
//!   agent is the sole control plane; netinit installs the guest-side network
//!   defense; netd is the opt-in transparent vsock networking bridge).
//! - `/init` — PID 1. Mounts the pseudo-filesystems, runs netinit, optionally
//!   starts netd, then forks the agent and idles. The OCI image's own entrypoint
//!   never runs as PID 1; it only ever runs *under* the agent, over vsock —
//!   preserving the agent-is-the-only-exec-gate posture.
//! - `/mvm/runtime` — the overlay mount point. On Firecracker the host
//!   attaches a verity-sealed overlay here; the injected `/init` prefers
//!   overlay-resident runtime binaries and falls back to the baked ones, exactly
//!   like a mkGuest rootfs. On backends without an overlay the baked binaries are
//!   used.
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
    /// Static guest transparent-network bridge binary (`mvm-guest-netd`).
    pub netd: PathBuf,
}

/// Where the injected guest binaries land inside the rootfs.
const AGENT_DEST: &str = "usr/local/bin/mvm-guest-agent";
const NETINIT_DEST: &str = "usr/local/bin/mvm-guest-netinit";
const NETD_DEST: &str = "usr/local/bin/mvm-guest-netd";

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
/// 5. If `mvm.netd=1` is present, fork the transparent-network bridge.
/// 6. Fork the agent (overlay copy first, baked fallback) and idle.
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

mvm_cmdline_token() {
  mvm_key="$1"
  for mvm_tok in $(cat /proc/cmdline 2>/dev/null); do
    case "$mvm_tok" in
      "$mvm_key"=*)
        printf '%s' "${mvm_tok#*=}"
        return 0
        ;;
    esac
  done
  return 1
}

# User volumes (machine run --volume). The host encoded
# mvm.uvols=<tag>:<hex(guest_path)>:<ro|rw>:<fs|blk>;... onto the kernel
# cmdline (mvm_core::vm_backend::encode_user_volumes_cmdline); mount each
# virtio-fs share at its guest path. virtio-fs is built into the workload
# kernel, so no module load is needed. Best-effort: a bad mount logs and
# continues rather than wedging PID 1. Disk (blk) volumes are attached as
# block devices for the workload to mount itself. Mirrors the mkGuest init.
MVM_UVOLS=$(mvm_cmdline_token mvm.uvols 2>/dev/null)
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

# Egress CA (TLS-substitution trust). The host encoded
# mvm.egress_ca=pem:<base64-body> onto the kernel cmdline (only when egress
# substitution is configured); reconstruct the PEM under /run/mvm so the
# workload trusts the per-VM egress CA alongside the image's baked roots. Older
# runs may still carry the legacy hex-encoded full PEM; accept both on input
# while the host-side encoder stays compact. The env vars that point a TLS stack
# here are injected into the entrypoint's env host-side (the agent execs it
# under env_clear, so a shell export would not reach it). Absent token => no-op.
# Mirrors the mkGuest egress-ca stage in nix/lib/mk-guest.nix.
MVM_EGRESS_CA_TOKEN=$(mvm_cmdline_token mvm.egress_ca 2>/dev/null)
if [ -n "$MVM_EGRESS_CA_TOKEN" ]; then
  mkdir -p /run/mvm 2>/dev/null || true
  if echo "$MVM_EGRESS_CA_TOKEN" | grep -q '^pem:'; then
    MVM_EGRESS_CA_BODY=${MVM_EGRESS_CA_TOKEN#pem:}
    {
      printf '%s\n' '-----BEGIN CERTIFICATE-----'
      printf '%s' "$MVM_EGRESS_CA_BODY" | sed 's/.\{64\}/&\n/g'
      printf '\n%s\n' '-----END CERTIFICATE-----'
    } > /run/mvm/egress-ca.crt
  else
    printf '%b' "$(echo "$MVM_EGRESS_CA_TOKEN" | sed 's/../\\x&/g')" > /run/mvm/egress-ca.crt
  fi
  mvm_baked=
  for mvm_c in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl/certs/ca-bundle.crt; do
    [ -f "$mvm_c" ] && { mvm_baked="$mvm_c"; break; }
  done
  if [ -n "$mvm_baked" ] && cat "$mvm_baked" /run/mvm/egress-ca.crt > /run/mvm/ca-bundle.crt 2>/dev/null; then
    :
  else
    cp /run/mvm/egress-ca.crt /run/mvm/ca-bundle.crt 2>/dev/null || true
  fi
  chmod 0644 /run/mvm/egress-ca.crt /run/mvm/ca-bundle.crt 2>/dev/null || true
  echo "mvm-oci-init: installed per-VM egress CA"
fi

# Verb grant (plan-bound agent verb capabilities). The host encoded
# mvm.verb_grant=<hex(JSON envelope)> onto the kernel cmdline; decode it to
# the tmpfs so the agent can pin + enforce it before serving RPC. Absent
# token => no-op (byte-identical boot; the agent starts with no grant).
# Mirrors the mkGuest init verb-grant stage in nix/lib/mk-guest.nix.
MVM_VERB_GRANT_HEX=$(mvm_cmdline_token mvm.verb_grant 2>/dev/null)
if [ -n "$MVM_VERB_GRANT_HEX" ]; then
  mkdir -p /run/mvm 2>/dev/null || true
  printf '%b' "$(echo "$MVM_VERB_GRANT_HEX" | sed 's/../\\x&/g')" > /run/mvm/verb-grant.json
  chmod 0644 /run/mvm/verb-grant.json 2>/dev/null || true
  echo "mvm-oci-init: provisioned verb-grant"
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

# Transparent networking needs a writable resolver path. Stage a tmpfs-backed
# resolv.conf under /run/mvm, then bind-mount it over /etc/resolv.conf when the
# image provides that path so ordinary libc DNS keeps reading the writable copy.
mkdir -p /run/mvm 2>/dev/null || true
if [ -e /etc/resolv.conf ]; then
  cp /etc/resolv.conf /run/mvm/resolv.conf 2>/dev/null || : > /run/mvm/resolv.conf
else
  : > /run/mvm/resolv.conf
  fi
cp /run/mvm/resolv.conf /run/mvm/resolv.conf.backup 2>/dev/null || true
if [ ! -e /etc/resolv.conf ]; then
  mkdir -p /run/mvm/etc-shadow 2>/dev/null || true
  cp -a /etc/. /run/mvm/etc-shadow/ 2>/dev/null || true
  if mount -t tmpfs none /etc 2>/dev/null; then
    cp -a /run/mvm/etc-shadow/. /etc/ 2>/dev/null || true
    : > /etc/resolv.conf 2>/dev/null || true
  fi
fi
if [ -e /etc/resolv.conf ]; then
  mount -o bind /run/mvm/resolv.conf /etc/resolv.conf 2>/dev/null || true
fi
export MVM_NET_RESOLV_CONF=/run/mvm/resolv.conf
export MVM_NET_RESOLV_BACKUP=/run/mvm/resolv.conf.backup

# Transparent networking bridge. It configures a TUN/default route, so it is
# strictly opt-in via the backend-provided kernel cmdline token.
MVM_NETD_REQUIRED=0
MVM_NETD_STARTED=0
MVM_NETD_ENABLED=$(mvm_cmdline_token mvm.netd 2>/dev/null)
if [ "$MVM_NETD_ENABLED" = 1 ]; then
  MVM_NETD_REQUIRED=1
  MVM_GUEST_NETD=
  if [ -x /mvm/runtime/netd ]; then
    MVM_GUEST_NETD=/mvm/runtime/netd
  elif [ -x /usr/local/bin/mvm-guest-netd ]; then
    MVM_GUEST_NETD=/usr/local/bin/mvm-guest-netd
  fi
  if [ -n "$MVM_GUEST_NETD" ]; then
    "$MVM_GUEST_NETD" \
      --resolv-conf /run/mvm/resolv.conf \
      --resolv-backup /run/mvm/resolv.conf.backup &
    MVM_GUEST_NETD_PID=$!
    sleep 1
    if kill -0 "$MVM_GUEST_NETD_PID" 2>/dev/null; then
      MVM_NETD_STARTED=1
    else
      echo "mvm-oci-init: mvm guest netd exited during startup; control plane unavailable" >&2
    fi
  else
    echo "mvm-oci-init: mvm.netd=1 but no mvm guest netd present; networking unavailable" >&2
  fi
fi

# The agent is the control plane. Prefer the overlay-resident agent
# (Firecracker verity overlay); fall back to the baked-in copy
# when no overlay is attached. Both are exec-tested so a half-attached overlay
# still boots via the baked path rather than agent-less.
MVM_AGENT=
if [ -x /mvm/runtime/agent ]; then
  MVM_AGENT=/mvm/runtime/agent
elif [ -x /usr/local/bin/mvm-guest-agent ]; then
  MVM_AGENT=/usr/local/bin/mvm-guest-agent
fi
if [ "$MVM_NETD_REQUIRED" = 1 ] && [ "$MVM_NETD_STARTED" != 1 ]; then
  echo "mvm-oci-init: not starting guest agent because transparent networking failed to start" >&2
elif [ -n "$MVM_AGENT" ]; then
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
/// paths created (the `/init` and binary destinations) so the
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

    // Runtime mount points must already exist in the staged tree because the
    // rootfs is mounted read-only at boot and PID 1 cannot create missing
    // mountpoints before mounting proc/sysfs/devtmpfs/tmpfs over them.
    for rel in ["proc", "sys", "dev", "dev/pts", "dev/shm", "run", "tmp"] {
        std::fs::create_dir_all(rootfs_dir.join(rel))?;
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
    let netd_dest = rootfs_dir.join(NETD_DEST);
    copy_exec(&bins.agent, &agent_dest)?;
    copy_exec(&bins.netinit, &netinit_dest)?;
    copy_exec(&bins.netd, &netd_dest)?;

    // PID 1.
    let init_dest = rootfs_dir.join("init");
    write_file(&init_dest, oci_init_script().as_bytes(), 0o755)?;

    Ok(InjectedPaths {
        init: init_dest,
        agent: agent_dest,
        netinit: netinit_dest,
        netd: netd_dest,
        runtime_mount_point: runtime_dir,
    })
}

/// Paths written by [`inject_mvm_runtime`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedPaths {
    pub init: PathBuf,
    pub agent: PathBuf,
    pub netinit: PathBuf,
    pub netd: PathBuf,
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
        // Netd is packaged but only launched when the backend requests it.
        assert!(s.contains("mvm.netd=1"));
        assert!(s.contains("/mvm/runtime/netd"));
        assert!(s.contains("/usr/local/bin/mvm-guest-netd"));
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
    fn init_script_starts_guest_netd_only_when_cmdline_enables_it() {
        let s = oci_init_script();
        assert!(
            s.contains("mvm_cmdline_token()"),
            "init must use a shell-native cmdline token parser"
        );
        assert!(
            s.contains("MVM_NETD_ENABLED=$(mvm_cmdline_token mvm.netd"),
            "init must parse the netd cmdline token"
        );
        assert!(
            s.contains("if [ \"$MVM_NETD_ENABLED\" = 1 ]; then"),
            "netd launch must be opt-in"
        );
        assert!(
            s.contains("\"$MVM_GUEST_NETD\" \\"),
            "netd must run in the background under PID 1"
        );
        assert!(
            s.contains("--resolv-conf /run/mvm/resolv.conf"),
            "netd launch must pass the writable resolver path explicitly"
        );
        assert!(
            s.contains("--resolv-backup /run/mvm/resolv.conf.backup"),
            "netd launch must pass the resolver backup path explicitly"
        );
        assert!(
            s.contains("export MVM_NET_RESOLV_CONF=/run/mvm/resolv.conf"),
            "netd must receive a writable resolver path"
        );
        assert!(
            s.contains("export MVM_NET_RESOLV_BACKUP=/run/mvm/resolv.conf.backup"),
            "netd must receive a writable resolver backup path"
        );
        assert!(
            s.contains("mount -o bind /run/mvm/resolv.conf /etc/resolv.conf"),
            "PID 1 must try to bind-mount the writable resolver over /etc/resolv.conf"
        );
        assert!(
            s.contains("MVM_NETD_REQUIRED=1"),
            "requested netd must become a startup requirement"
        );
        assert!(
            s.contains("kill -0 \"$MVM_GUEST_NETD_PID\""),
            "PID 1 must check that netd survived startup"
        );
        assert!(
            s.contains("not starting guest agent because transparent networking failed"),
            "agent must not start when requested netd is unavailable"
        );
        let netinit_at = s.find("mvm-guest-netinit").expect("netinit referenced");
        let netd_fork_at = s.find("\"$MVM_GUEST_NETD\" \\").expect("netd fork");
        let agent_gate_at = s
            .find("if [ \"$MVM_NETD_REQUIRED\" = 1 ]")
            .expect("agent guarded by netd startup status");
        let agent_fork_at = s.find("\"$MVM_AGENT\" &").expect("agent fork");
        assert!(
            netinit_at < netd_fork_at,
            "netinit must run before netd configures the route"
        );
        assert!(
            netd_fork_at < agent_gate_at && agent_gate_at < agent_fork_at,
            "agent startup must be gated on netd after the netd launch attempt"
        );
    }

    #[test]
    fn init_script_mounts_user_volumes_before_the_agent() {
        let s = oci_init_script();
        // Reads the host-encoded cmdline token and mounts each share as virtio-fs.
        assert!(
            s.contains("MVM_UVOLS=$(mvm_cmdline_token mvm.uvols"),
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

    #[test]
    fn init_script_decodes_verb_grant_before_the_agent() {
        let s = oci_init_script();
        // Decodes the host-encoded cmdline token into the tmpfs the agent
        // reads, so an OCI workload pins + enforces its verb grant (parity
        // with the mkGuest init).
        assert!(
            s.contains("MVM_VERB_GRANT_HEX=$(mvm_cmdline_token mvm.verb_grant"),
            "init must parse the verb_grant cmdline token"
        );
        assert!(
            s.contains("/run/mvm/verb-grant.json"),
            "decoded grant is written where the agent loads it"
        );
        // Must be provisioned before the agent forks, or the agent boots
        // with no grant pinned and enforcement is a no-op.
        let grant_at = s.find("mvm.verb_grant=").expect("verb_grant parse");
        let agent_fork_at = s.find("\"$MVM_AGENT\" &").expect("agent fork");
        assert!(
            grant_at < agent_fork_at,
            "verb grant must be decoded before the agent fork"
        );
    }

    #[test]
    fn init_script_decodes_egress_ca_before_the_agent() {
        let s = oci_init_script();
        // Decodes the per-VM egress CA into the tmpfs bundle the workload's TLS
        // stack trusts (the env vars pointing here are injected host-side).
        assert!(
            s.contains("MVM_EGRESS_CA_TOKEN=$(mvm_cmdline_token mvm.egress_ca"),
            "init must parse the egress_ca cmdline token"
        );
        assert!(
            s.contains("grep -q '^pem:'"),
            "init must accept the compact PEM-body cmdline encoding"
        );
        assert!(
            s.contains("-----BEGIN CERTIFICATE-----"),
            "init must reconstruct PEM armor from the compact encoding"
        );
        assert!(
            s.contains("printf '%b' \"$(echo \"$MVM_EGRESS_CA_TOKEN\" | sed 's/../\\\\x&/g')\" > /run/mvm/egress-ca.crt"),
            "init must keep the legacy hex decoder for older cmdlines"
        );
        assert!(
            s.contains("/run/mvm/ca-bundle.crt"),
            "combined CA bundle is written where the workload's SSL_CERT_FILE points"
        );
        // Written before the agent forks, so the file exists when the agent
        // execs the entrypoint (which the host points at the bundle via env).
        let ca_at = s.find("mvm.egress_ca=").expect("egress_ca parse");
        let agent_fork_at = s.find("\"$MVM_AGENT\" &").expect("agent fork");
        assert!(
            ca_at < agent_fork_at,
            "egress CA must be decoded before the agent fork"
        );
    }

    fn fake_bins(dir: &Path) -> MvmRuntimeBinaries {
        let agent = dir.join("agent.bin");
        let netinit = dir.join("netinit.bin");
        let netd = dir.join("netd.bin");
        std::fs::write(&agent, b"\x7fELF-agent").unwrap();
        std::fs::write(&netinit, b"\x7fELF-netinit").unwrap();
        std::fs::write(&netd, b"\x7fELF-netd").unwrap();
        MvmRuntimeBinaries {
            agent,
            netinit,
            netd,
        }
    }

    #[test]
    fn inject_writes_init_binaries_and_runtime_mountpoints() {
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
        assert_eq!(
            std::fs::read(&injected.netinit).unwrap(),
            b"\x7fELF-netinit"
        );
        assert_eq!(std::fs::read(&injected.netd).unwrap(), b"\x7fELF-netd");
        assert!(is_executable(&injected.agent));
        assert!(is_executable(&injected.netinit));
        assert!(is_executable(&injected.netd));
        // Read-only OCI roots need runtime mountpoints baked in ahead of boot.
        for rel in ["proc", "sys", "dev", "dev/pts", "dev/shm", "run", "tmp"] {
            assert!(root.join(rel).is_dir(), "expected /{rel} mountpoint");
        }
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
