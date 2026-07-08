//! Inject the mvm guest runtime into an OCI-unpacked rootfs.
//!
//! An arbitrary OCI image (alpine, debian, a language base) ships none
//! of the mvm runtime: no guest agent, no `/init` that brings the agent
//! up, no `/mvm/runtime` overlay mount point. Without those, a microVM
//! booted from the image has no vsock control plane.
//!
//! This module is the host-side fix. It runs against the unpacked OCI
//! tree *before* it is sealed into `rootfs.ext4`, baking in:
//!
//! - `/init`, installed from the static `mvm-oci-init` binary, so the
//!   source OCI image does not need `/bin/sh`, busybox, or its own init.
//! - `/usr/lib/mvm/wrappers/oci-entrypoint` plus `/etc/mvm/entrypoint`
//!   when the OCI config declares Entrypoint/Cmd.
//! - `/mvm/runtime`, the shared runtime overlay mount point.
//! - `/etc/mvm/{name,variant}` and, for sealed boots,
//!   `/etc/mvm/verb-trust.json`.
//! - For rootfs-only launch shapes, baked guest binaries under
//!   `/usr/local/bin/`.
//!
//! Runtime-lean launch shapes intentionally do *not* bake the guest runtime
//! helpers into the OCI rootfs; those binaries must come from the shared
//! read-only runtime overlay.

use std::io;
use std::path::{Path, PathBuf};

/// The cross-compiled guest binaries to bake into the rootfs. Produced on the
/// host by [`crate::guest_agent_build`] or unpacked from the published runtime
/// overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MvmRuntimeBinaries {
    /// Static OCI PID 1 (`mvm-oci-init`), installed as `/init`.
    pub oci_init: PathBuf,
    /// Static guest agent binary (`mvm-guest-agent`).
    pub agent: PathBuf,
    /// Static guest netinit binary (`mvm-guest-netinit`).
    pub netinit: PathBuf,
    /// Static guest network tunnel daemon (`mvm-guest-netd`).
    pub netd: PathBuf,
    /// Static guest egress shim (`mvm-egress-client`).
    pub egress_client: PathBuf,
    /// Static OCI entrypoint runner (`mvm-oci-entrypoint`).
    pub entrypoint_runner: PathBuf,
    /// Static verity initramfs PID 1 (`mvm-verity-init`). Not baked into the
    /// rootfs itself; carried here so the guest-binary resolver produces the
    /// full set consistently.
    pub verity_init: PathBuf,
}

/// Shell-free runtime config for an OCI image's declared Entrypoint/Cmd.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OciEntrypointConfig {
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
}

const AGENT_DEST: &str = "usr/local/bin/mvm-guest-agent";
const NETINIT_DEST: &str = "usr/local/bin/mvm-guest-netinit";
const NETD_DEST: &str = "usr/local/bin/mvm-guest-netd";
const EGRESS_CLIENT_DEST: &str = "usr/local/bin/mvm-egress-client";
const ENTRYPOINT_RUNNER_DEST: &str = "usr/lib/mvm/wrappers/oci-entrypoint";
const ENTRYPOINT_MARKER_DEST: &str = "etc/mvm/entrypoint";
const OCI_ENTRYPOINT_CONFIG_DEST: &str = "etc/mvm/oci-entrypoint.json";
const VERB_TRUST_DEST: &str = "etc/mvm/verb-trust.json";

/// Which runtime shape to inject into an OCI-prepared rootfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInjectionProfile {
    /// Rootfs-only launch shape: bake the guest binaries into the tree because
    /// the boot path intentionally does not consume `/mvm/runtime`.
    RootfsOnly,
    /// Overlay-backed launch shape: install only PID 1, entrypoint wrapper,
    /// mountpoints, and markers; the actual guest runtime binaries must come
    /// from the shared read-only runtime overlay.
    RuntimeLean,
}

/// PID-1 init baked into an OCI rootfs so `run --image` has a vsock control
/// plane. POSIX `sh` (busybox `ash` in alpine and friends).
///
/// Contract, in order:
/// 1. Mount `/proc`, `/sys`, `/dev` (+ `devpts`, `tmpfs` for `/run`, `/tmp`).
/// 2. Create the `/mvm/runtime` overlay mount point.
/// 3. Mount each `machine run --volume` host share (`mvm.uvols=` cmdline).
/// 4. Run the guest-side network defense (netinit), overlay copy first.
/// 5. If `mvm.netd=1` is present, fork the transparent-network bridge.
/// 6. Fork the agent (overlay copy first, baked fallback) and idle.
pub fn oci_init_script() -> String {
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
# virtio-fs share at its guest path.
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

# Egress CA (TLS-substitution trust). The host encoded mvm.egress_ca=<hex(PEM)>
# onto the kernel cmdline (only when egress substitution is configured); decode
# it to /run/mvm/ca-bundle.crt so the workload trusts the per-VM egress CA
# alongside the image's baked roots.
MVM_EGRESS_CA_HEX=$(sed -n 's/.*\bmvm\.egress_ca=\([^ ]*\).*/\1/p' /proc/cmdline 2>/dev/null)
if [ -n "$MVM_EGRESS_CA_HEX" ]; then
  mkdir -p /run/mvm 2>/dev/null || true
  printf '%b' "$(echo "$MVM_EGRESS_CA_HEX" | sed 's/../\\x&/g')" > /run/mvm/egress-ca.crt
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
# the tmpfs so the agent can pin + enforce it before serving RPC.
MVM_VERB_GRANT_HEX=$(sed -n 's/.*\bmvm\.verb_grant=\([^ ]*\).*/\1/p' /proc/cmdline 2>/dev/null)
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

# Transparent networking bridge. It configures a TUN/default route, so it is
# strictly opt-in via the backend-provided kernel cmdline token.
MVM_NETD_REQUIRED=0
MVM_NETD_STARTED=0
MVM_NETD_ENABLED=$(sed -n 's/.*\bmvm\.netd=\([^ ]*\).*/\1/p' /proc/cmdline 2>/dev/null)
if [ "$MVM_NETD_ENABLED" = 1 ]; then
  MVM_NETD_REQUIRED=1
  MVM_GUEST_NETD=
  if [ -x /mvm/runtime/netd ]; then
    MVM_GUEST_NETD=/mvm/runtime/netd
  elif [ -x /usr/local/bin/mvm-guest-netd ]; then
    MVM_GUEST_NETD=/usr/local/bin/mvm-guest-netd
  fi
  if [ -n "$MVM_GUEST_NETD" ]; then
    "$MVM_GUEST_NETD" &
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
# (Firecracker verity overlay); fall back to the baked-in copy when no overlay
# is attached.
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

while :; do
  /bin/sh -c 'sleep 2147483647' 2>/dev/null || sleep 86400 || break
done
"#
    .to_string()
}

/// Inject the mvm runtime into the OCI-unpacked `rootfs_dir`.
///
/// Idempotent: re-running overwrites the injected files. Returns the paths
/// written so the caller can verify the resulting rootfs shape.
pub fn inject_mvm_runtime(
    rootfs_dir: &Path,
    bins: &MvmRuntimeBinaries,
    entrypoint: Option<&OciEntrypointConfig>,
    sealed: bool,
    profile: RuntimeInjectionProfile,
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

    for (rel, mode) in [
        ("proc", 0o755),
        ("sys", 0o755),
        ("dev", 0o755),
        ("dev/pts", 0o755),
        ("dev/shm", 0o1777),
        ("run", 0o755),
        ("tmp", 0o1777),
        ("mvm/runtime", 0o755),
        ("usr/lib/mvm/wrappers", 0o755),
    ] {
        ensure_dir(rootfs_dir, rel, mode)?;
    }
    let runtime_dir = rootfs_dir.join("mvm").join("runtime");

    let etc_mvm = rootfs_dir.join("etc").join("mvm");
    std::fs::create_dir_all(&etc_mvm)?;
    let variant: &[u8] = if sealed { b"prod\n" } else { b"dev\n" };
    write_file(&etc_mvm.join("variant"), variant, 0o644)?;
    write_file(&etc_mvm.join("name"), b"oci\n", 0o644)?;

    if sealed {
        let policy = mvm_core::plan::VerbTrustPolicy {
            version: mvm_core::plan::VERB_TRUST_POLICY_VERSION,
            require_grant: true,
            grant_key_source: mvm_core::plan::GrantKeySource::LaunchProvisioned,
        };
        let policy_json = serde_json::to_vec(&policy).map_err(io::Error::other)?;
        write_file(&rootfs_dir.join(VERB_TRUST_DEST), &policy_json, 0o444)?;
    }

    let agent_dest = rootfs_dir.join(AGENT_DEST);
    let netinit_dest = rootfs_dir.join(NETINIT_DEST);
    let netd_dest = rootfs_dir.join(NETD_DEST);
    let egress_client_dest = rootfs_dir.join(EGRESS_CLIENT_DEST);
    if profile == RuntimeInjectionProfile::RootfsOnly {
        let bin_dir = rootfs_dir.join("usr").join("local").join("bin");
        std::fs::create_dir_all(&bin_dir)?;
        copy_exec(&bins.agent, &agent_dest)?;
        copy_exec(&bins.netinit, &netinit_dest)?;
        copy_exec(&bins.netd, &netd_dest)?;
        copy_exec(&bins.egress_client, &egress_client_dest)?;
    } else {
        let _ = std::fs::remove_file(&agent_dest);
        let _ = std::fs::remove_file(&netinit_dest);
        let _ = std::fs::remove_file(&netd_dest);
        let _ = std::fs::remove_file(&egress_client_dest);
    }

    let entrypoint_runner_dest = rootfs_dir.join(ENTRYPOINT_RUNNER_DEST);
    copy_file_with_mode(&bins.entrypoint_runner, &entrypoint_runner_dest, 0o555)?;
    if let Some(entrypoint) = entrypoint
        && !entrypoint.argv.is_empty()
    {
        let entrypoint_json = serde_json::to_vec(entrypoint).map_err(io::Error::other)?;
        write_file(
            &rootfs_dir.join(OCI_ENTRYPOINT_CONFIG_DEST),
            &entrypoint_json,
            0o644,
        )?;
        write_file(
            &rootfs_dir.join(ENTRYPOINT_MARKER_DEST),
            b"/usr/lib/mvm/wrappers/oci-entrypoint\n",
            0o644,
        )?;
    }

    let init_dest = rootfs_dir.join("init");
    copy_exec(&bins.oci_init, &init_dest)?;

    Ok(InjectedPaths {
        init: init_dest,
        agent: agent_dest,
        netinit: netinit_dest,
        netd: netd_dest,
        egress_client: egress_client_dest,
        entrypoint_runner: entrypoint_runner_dest,
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
    pub egress_client: PathBuf,
    pub entrypoint_runner: PathBuf,
    pub runtime_mount_point: PathBuf,
}

fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    set_mode(path, mode)
}

fn ensure_dir(rootfs_dir: &Path, rel: &str, mode: u32) -> Result<(), io::Error> {
    let path = rootfs_dir.join(rel);
    std::fs::create_dir_all(&path)?;
    set_mode(&path, mode)
}

fn copy_exec(src: &Path, dst: &Path) -> Result<(), io::Error> {
    copy_file_with_mode(src, dst, 0o755)
}

fn copy_file_with_mode(src: &Path, dst: &Path, mode: u32) -> Result<(), io::Error> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst)?;
    set_mode(dst, mode)
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn init_script_mounts_pseudofs_and_forks_agent() {
        let s = oci_init_script();
        assert!(s.starts_with("#!/bin/sh"));
        assert!(s.contains("mount -t proc"));
        assert!(s.contains("mount -t sysfs"));
        assert!(s.contains("mount -t devtmpfs"));
        assert!(s.contains("/mvm/runtime"));
        assert!(s.contains("/mvm/runtime/agent"));
        assert!(s.contains("/usr/local/bin/mvm-guest-agent"));
        assert!(s.contains("mvm.netd=1"));
        assert!(s.contains("/mvm/runtime/netd"));
        assert!(s.contains("/usr/local/bin/mvm-guest-netd"));
        assert!(s.contains("\"$MVM_AGENT\" &"));
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
        assert!(s.contains("MVM_NETD_ENABLED=$(sed -n 's/.*\\bmvm\\.netd="));
        assert!(s.contains("if [ \"$MVM_NETD_ENABLED\" = 1 ]; then"));
        assert!(s.contains("\"$MVM_GUEST_NETD\" &"));
        assert!(s.contains("MVM_NETD_REQUIRED=1"));
        assert!(s.contains("kill -0 \"$MVM_GUEST_NETD_PID\""));
        assert!(s.contains("not starting guest agent because transparent networking failed"));
        let netinit_at = s.find("mvm-guest-netinit").expect("netinit referenced");
        let netd_fork_at = s.find("\"$MVM_GUEST_NETD\" &").expect("netd fork");
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
        assert!(s.contains("mvm.uvols="));
        assert!(s.contains("mount -t virtiofs -o ro"));
        assert!(s.contains("mount -t virtiofs \"$utag\""));
        assert!(s.contains("mkdir -p \"$upath\""));
        assert!(s.contains("guest auto-mount of disks not wired"));
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
        assert!(s.contains("mvm.verb_grant="));
        assert!(s.contains("/run/mvm/verb-grant.json"));
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
        assert!(s.contains("mvm.egress_ca="));
        assert!(s.contains("/run/mvm/ca-bundle.crt"));
        let ca_at = s.find("mvm.egress_ca=").expect("egress_ca parse");
        let agent_fork_at = s.find("\"$MVM_AGENT\" &").expect("agent fork");
        assert!(
            ca_at < agent_fork_at,
            "egress CA must be decoded before the agent fork"
        );
    }

    fn fake_bins(dir: &Path) -> MvmRuntimeBinaries {
        let oci_init = dir.join("oci-init.bin");
        let agent = dir.join("agent.bin");
        let netinit = dir.join("netinit.bin");
        let netd = dir.join("netd.bin");
        let egress_client = dir.join("egress-client.bin");
        let entrypoint_runner = dir.join("entrypoint-runner.bin");
        let verity_init = dir.join("verity-init.bin");
        std::fs::write(&oci_init, b"\x7fELF-oci-init").unwrap();
        std::fs::write(&agent, b"\x7fELF-agent").unwrap();
        std::fs::write(&netinit, b"\x7fELF-netinit").unwrap();
        std::fs::write(&netd, b"\x7fELF-netd").unwrap();
        std::fs::write(&egress_client, b"\x7fELF-egress-client").unwrap();
        std::fs::write(&entrypoint_runner, b"\x7fELF-entrypoint-runner").unwrap();
        std::fs::write(&verity_init, b"\x7fELF-verity-init").unwrap();
        MvmRuntimeBinaries {
            oci_init,
            agent,
            netinit,
            netd,
            egress_client,
            entrypoint_runner,
            verity_init,
        }
    }

    #[test]
    fn inject_writes_init_binaries_and_mount_point() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        let entrypoint = OciEntrypointConfig {
            argv: vec![
                "/app/server".to_string(),
                "--port".to_string(),
                "8080".to_string(),
            ],
            env: vec!["FOO=bar".to_string()],
            working_dir: Some("/app".to_string()),
        };

        let injected = inject_mvm_runtime(
            &root,
            &bins,
            Some(&entrypoint),
            false,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .expect("inject");

        assert_eq!(std::fs::read(&injected.init).unwrap(), b"\x7fELF-oci-init");
        assert!(is_executable(&injected.init));
        assert_eq!(std::fs::read(&injected.agent).unwrap(), b"\x7fELF-agent");
        assert!(is_executable(&injected.agent));
        assert_eq!(
            std::fs::read(&injected.netinit).unwrap(),
            b"\x7fELF-netinit"
        );
        assert!(is_executable(&injected.netinit));
        assert_eq!(std::fs::read(&injected.netd).unwrap(), b"\x7fELF-netd");
        assert!(is_executable(&injected.netd));
        assert_eq!(
            std::fs::read(&injected.egress_client).unwrap(),
            b"\x7fELF-egress-client"
        );
        assert!(is_executable(&injected.egress_client));
        assert_eq!(
            std::fs::read(&injected.entrypoint_runner).unwrap(),
            b"\x7fELF-entrypoint-runner"
        );
        assert!(is_executable(&injected.entrypoint_runner));
        assert_eq!(
            std::fs::metadata(&injected.entrypoint_runner)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/mvm/entrypoint")).unwrap(),
            "/usr/lib/mvm/wrappers/oci-entrypoint\n"
        );
        let written_entrypoint: OciEntrypointConfig = serde_json::from_slice(
            &std::fs::read(root.join("etc/mvm/oci-entrypoint.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written_entrypoint, entrypoint);
        assert!(injected.runtime_mount_point.is_dir());
        assert!(root.join("mvm/runtime").is_dir());
        for rel in ["proc", "sys", "dev/pts", "dev/shm", "run", "tmp"] {
            assert!(root.join(rel).is_dir(), "{rel} mountpoint exists");
        }
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

        inject_mvm_runtime(
            &root,
            &bins,
            None,
            false,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .expect("first inject");
        let second = inject_mvm_runtime(
            &root,
            &bins,
            None,
            false,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .expect("second inject");
        assert!(is_executable(&second.agent));
        assert!(is_executable(&second.netd));
        assert!(is_executable(&second.egress_client));
        assert!(!root.join("etc/mvm/entrypoint").exists());
    }

    #[test]
    fn inject_rejects_missing_rootfs_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());
        let err = inject_mvm_runtime(
            &tmp.path().join("nope"),
            &bins,
            None,
            false,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn runtime_lean_profile_skips_baked_guest_binaries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("rootfs");
        std::fs::create_dir_all(&root).unwrap();
        let bins = fake_bins(tmp.path());

        let injected = inject_mvm_runtime(
            &root,
            &bins,
            None,
            false,
            RuntimeInjectionProfile::RuntimeLean,
        )
        .expect("inject");

        assert!(is_executable(&injected.init));
        assert!(is_executable(&injected.entrypoint_runner));
        assert!(injected.runtime_mount_point.is_dir());
        assert!(!injected.agent.exists());
        assert!(!injected.netinit.exists());
        assert!(!injected.netd.exists());
        assert!(!injected.egress_client.exists());
    }

    #[test]
    fn sealed_inject_writes_prod_variant() {
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());

        let dev_root = tmp.path().join("dev-rootfs");
        std::fs::create_dir_all(&dev_root).unwrap();
        inject_mvm_runtime(
            &dev_root,
            &bins,
            None,
            false,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .expect("dev inject");
        assert_eq!(
            std::fs::read_to_string(dev_root.join("etc/mvm/variant")).unwrap(),
            "dev\n"
        );

        let prod_root = tmp.path().join("prod-rootfs");
        std::fs::create_dir_all(&prod_root).unwrap();
        inject_mvm_runtime(
            &prod_root,
            &bins,
            None,
            true,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .expect("prod inject");
        assert_eq!(
            std::fs::read_to_string(prod_root.join("etc/mvm/variant")).unwrap(),
            "prod\n"
        );
    }

    #[test]
    fn sealed_inject_bakes_require_grant_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let bins = fake_bins(tmp.path());

        let dev_root = tmp.path().join("dev-rootfs");
        std::fs::create_dir_all(&dev_root).unwrap();
        inject_mvm_runtime(
            &dev_root,
            &bins,
            None,
            false,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .expect("dev inject");
        assert!(!dev_root.join("etc/mvm/verb-trust.json").exists());

        let prod_root = tmp.path().join("prod-rootfs");
        std::fs::create_dir_all(&prod_root).unwrap();
        inject_mvm_runtime(
            &prod_root,
            &bins,
            None,
            true,
            RuntimeInjectionProfile::RootfsOnly,
        )
        .expect("prod inject");
        let policy_path = prod_root.join("etc/mvm/verb-trust.json");
        assert!(policy_path.is_file());
        assert_eq!(
            std::fs::metadata(&policy_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o444
        );
        let policy: mvm_core::plan::VerbTrustPolicy =
            serde_json::from_slice(&std::fs::read(&policy_path).unwrap()).unwrap();
        assert!(policy.require_grant);
        assert_eq!(policy.version, mvm_core::plan::VERB_TRUST_POLICY_VERSION);
        assert_eq!(
            policy.grant_key_source,
            mvm_core::plan::GrantKeySource::LaunchProvisioned
        );
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
