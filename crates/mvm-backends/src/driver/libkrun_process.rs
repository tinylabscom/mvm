//! Host-process mechanics for the libkrun backend.
//!
//! libkrun's lifecycle delegates to a per-VM `mvm-libkrun-supervisor`
//! subprocess rather than calling libkrun in-process: `krun_start_enter` calls
//! `exit()` on the host process when the guest powers off, so an in-process
//! registry would tear down sibling guests. One process per VM scopes that
//! `exit()` and lets the parent `mvmctl` survive a guest shutdown.
//!
//! This module is the host side of that arrangement — supervisor resolution,
//! PID-file handling, cmdline and disk assembly. The `VmmDriver` half is
//! [`super::libkrun`].
//!
//! The file was called `libkrun_legacy` while the backend split was in
//! progress. Nothing in it is legacy: it is the live path on Linux and on
//! macOS 13-25.

use anyhow::{Context, Result, anyhow};
use libkrun_sys::{BridgeRestartPolicy, KrunContext, SupervisorBaseConfig};
use mvm_core::kernel_format::KernelFormat;
use mvm_core::vm_backend::{StandbySpec, VmStartConfig};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long [`LibkrunBackend::start`] waits for the supervisor to
/// write its PID file before giving up and killing the child. Shared with
/// the libkrun driver, which spawns the same supervisor binary.
pub(crate) const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);
/// After the PID file appears the supervisor still has to bind the
/// per-port vsock listener socket; callers (the console attach,
/// `shell_exec` via `connect_with_auto_start`) race that window and
/// wrongly see the VM as "not running". `start` waits for the
/// agent socket before returning so "ready" actually means reachable. Shared
/// with the libkrun driver's boot path.
pub(crate) const VSOCK_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`LibkrunBackend::stop`] waits after `SIGTERM` before
/// escalating to `SIGKILL`. Tight because libkrun's signal handling
/// under `krun_start_enter` is empirically unreliable — when the
/// supervisor is spawned via `std::process::Command` (the production
/// `mvmctl machine run` path), SIGTERM often doesn't reach the in-supervisor
/// `sigaction` handler before we escalate. The in-supervisor handler
/// (see `libkrun_sys::install_shutdown_handler`) still helps the
/// shell-stop case where SIGTERM is delivered cleanly (~200 ms); in
/// the always-escalate cargo-spawn / launchd path a shorter timeout
/// means `mvmctl stop` returns in 2 s instead of 5 s. Shared with the libkrun
/// driver's `kill` escalation.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(2);
pub const FORCE_KILL_TIMEOUT: Duration = Duration::from_millis(500);

/// Open the per-VM guest-console capture sink. OUTPUT-ONLY by
/// construction (write-only, create+truncate): the guest console
/// streams here and NO host-readable fd is ever attached as console
/// input. The sole interactive path into a guest is the interactive-gated
/// Default kernel cmdline for libkrun-launched guests.
/// `console=hvc0` matches libkrun's virtio-console wiring;
/// `root=/dev/vda rw init=/init` matches Apple Container's
/// boot for the same Nix-built rootfs layout.
pub(crate) const DEFAULT_CMDLINE: &str = "console=hvc0 root=/dev/vda rw init=/init";
pub(crate) const VERITY_CMDLINE: &str = "console=hvc0";

/// Build the supervisor config for one VM, lifting
/// the audit-substrate resolution into the shared `audit_substrate`
/// module so any adopting backend shares one source of truth (and the
/// future `NetworkProvider` trait extraction is mechanical).
///
/// **Do not log** `config.plan_json` or `config.bundle_json` — they
/// may carry secret bindings, env vars, or policy refs that resolve
/// to credentials. They're opaque transport bytes; the supervisor
/// re-verifies the signed envelope before trusting any decoded field.
/// Workload-**independent** KrunContext: kernel + resources + cmdline + vsock wiring +
/// the configured direct-vsock transport. **No rootfs** (the cold path sets the
/// workload rootfs; a prelaunched standby leaves it `None` until claim) and **no
/// user volumes**.
/// Shared verbatim by `build_supervisor_config` (cold) and `standby_base_config` (warm)
/// so the two launch paths can't drift.
pub fn krun_context_base(
    name: &str,
    kernel: &str,
    vcpus: u8,
    mem_mib: u32,
    cmdline: &str,
    state_dir: &Path,
) -> KrunContext {
    // KrunContext::new requires a rootfs arg; we null it immediately — the caller owns
    // the rootfs decision (Some for cold boot, None for a standby).
    let mut krun = KrunContext::new(name, kernel, "")
        .with_resources(vcpus, mem_mib)
        .with_cmdline(cmdline)
        .with_vsock_socket_dir(state_dir.to_string_lossy().into_owned())
        .add_vsock_port(mvm_agentd::vsock::GUEST_AGENT_PORT)
        // Workload exit-code capture (listen=false → host binds).
        .add_host_listen_port(mvm_agentd::vsock::WORKLOAD_EXIT_PORT)
        // Egress substitution channel (listen=false → host binds). Registered
        // unconditionally; fail-closed: when the plan carries no secrets nothing
        // binds the UDS, so a stray guest dial gets ECONNREFUSED.
        .add_host_listen_port(mvm_agentd::vsock::EGRESS_PORT)
        // Host-services broker channel (listen=false → host binds). Registered
        // unconditionally so libkrun proxies the guest's connect; fail-closed:
        // nothing binds the UDS until the per-VM broker subprocess is spawned,
        // so a stray guest dial gets ECONNREFUSED.
        .add_host_listen_port(mvm_agentd::vsock::BROKER_PORT);
    krun.rootfs_path = None;
    // The active libkrun transport is direct-vsock only; keep the workload
    // base aligned with the builder path so no guest-NIC helper can be
    // reopened through a different launch site.
    krun.with_vsock_direct()
}

/// Translate a backend-agnostic [`StandbySpec`] into the `SupervisorBaseConfig`
/// (workload-independent) the prelaunched supervisor reads on stdin. `rootfs_path` stays
/// `None` — the workload rootfs arrives in the attach at claim.
pub fn standby_base_config(spec: &StandbySpec) -> SupervisorBaseConfig {
    let krun = krun_context_base(
        &spec.id,
        &spec.kernel_path,
        spec.vcpus,
        spec.mem_mib,
        DEFAULT_CMDLINE,
        Path::new(&spec.vm_state_dir),
    );
    SupervisorBaseConfig {
        krun,
        vm_state_dir: spec.vm_state_dir.clone(),
        pid_file_name: None,
        signing_key_path: spec.signing_key_path.clone().into(),
        signer_id: spec.signer_id.clone(),
        binding_nonce: spec.binding_nonce.clone(),
        control_socket_path: spec.control_socket.clone().into(),
        bridge_restart_policy: BridgeRestartPolicy::HardFail,
    }
}

pub(crate) fn libkrun_kernel_for_host(kernel: &str) -> Result<(String, KernelFormat)> {
    let path = Path::new(kernel);
    if cfg!(target_arch = "x86_64") && path.exists() {
        let loadable = mvm_vmm::host::fc_kernel::ensure_fc_loadable_kernel(path)
            .with_context(|| format!("preparing x86_64 libkrun-loadable kernel from {kernel}"))?;
        return Ok((loadable.to_string_lossy().into_owned(), KernelFormat::Elf));
    }
    Ok((kernel.to_string(), KernelFormat::Raw))
}

pub fn libkrun_effective_initrd(config: &VmStartConfig) -> Option<PathBuf> {
    config.initrd_path.as_ref().map(PathBuf::from)
}

pub fn libkrun_verity_enabled(config: &VmStartConfig) -> bool {
    config.verity_path.is_some()
        && config.roothash.is_some()
        && libkrun_effective_initrd(config).is_some()
}

pub fn libkrun_runtime_overlay(config: &VmStartConfig) -> Option<(&str, &str, &str)> {
    Some((
        config.runtime_overlay_path.as_deref()?,
        config.runtime_overlay_verity_path.as_deref()?,
        config.runtime_overlay_roothash.as_deref()?,
    ))
}

/// Attach the workload rootfs (plus its dm-verity sidecar and the runtime
/// overlay disk) to `krun`. Verity boots carry `root`/`root-verity` disks
/// and an initramfs; non-verity boots set `rootfs_path` directly and, when a
/// runtime overlay is present, attach it as a plain read-only `/dev/vdb`.
pub fn attach_workload_rootfs(mut krun: KrunContext, config: &VmStartConfig) -> KrunContext {
    if let Some(verity_path) = config
        .verity_path
        .clone()
        .filter(|_| libkrun_verity_enabled(config))
    {
        krun.initramfs_path =
            libkrun_effective_initrd(config).map(|p| p.to_string_lossy().into_owned());
        krun = krun
            .add_disk("root", config.rootfs_path.clone(), true)
            .add_disk("root-verity", verity_path, true);
        if let Some((overlay_path, overlay_verity_path, _)) = libkrun_runtime_overlay(config) {
            krun = krun.add_disk("runtime", overlay_path, true).add_disk(
                "runtime-verity",
                overlay_verity_path,
                true,
            );
        }
    } else {
        krun.rootfs_path = Some(config.rootfs_path.clone());
        // A non-verity dev boot has no initramfs to mount the runtime overlay,
        // so attach it as a plain read-only virtio-blk device. `rootfs_path`
        // takes /dev/vda, so this first extra disk is /dev/vdb — the device the
        // `mvm.runtime_data=` token names for the guest `/init`.
        if let Some(overlay) = mvm_vmm::host::boot_config::non_verity_overlay_ext4(config) {
            krun = krun.add_disk("runtime", overlay.to_string(), true);
        }
    }
    krun
}

/// Attach the user-supplied volumes (`--volume` / `MVM_VOLUMES`) to `krun`.
/// Every volume reaches the guest as virtio-blk. A directory grant keeps its
/// original host path in the signed plan, while `materialized_image` names the
/// ext4 transport that is safe to attach. Tag/id `uvol{idx}` is the
/// coordination key the guest mount manifest uses at the requested guest path.
pub fn attach_user_volumes(mut krun: KrunContext, config: &VmStartConfig) -> Result<KrunContext> {
    for (idx, vol) in config.volumes.iter().enumerate() {
        krun = attach_user_volume(krun, idx, vol);
    }
    Ok(krun)
}

fn attach_user_volume(
    krun: KrunContext,
    index: usize,
    volume: &mvm_core::vm_backend::VmVolume,
) -> KrunContext {
    krun.add_disk(
        format!("uvol{index}"),
        volume.block_source().to_string(),
        volume.read_only,
    )
}

pub fn supervisor_config_dump_path(state_dir: &Path) -> PathBuf {
    state_dir.join("supervisor-config.json")
}

/// The dump is the supervisor's whole configuration — paths, ports, the
/// plan reference — so it is written owner-only, replacing any link at the
/// path rather than writing through it.
pub fn persist_supervisor_config_dump(state_dir: &Path, json: &str) -> Result<()> {
    let path = supervisor_config_dump_path(state_dir);
    mvm_core::util::atomic_io::write_private_ephemeral(&path, json.as_bytes())
        .map_err(|e| anyhow!("write {}: {e}", path.display()))
}

pub fn read_last_bytes_of(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let take = max_bytes.min(len);
    let offset = i64::try_from(take).unwrap_or(i64::MAX).saturating_neg();
    file.seek(SeekFrom::End(offset))?;
    let mut buf = Vec::with_capacity(take as usize);
    file.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub fn diagnose_log_path(label: &str, path: &Path) -> String {
    if !path.exists() {
        return format!("{label}: missing ({})", path.display());
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() == 0 => {
            format!("{label}: present but empty ({})", path.display())
        }
        Ok(_) => match read_last_bytes_of(path, 4096) {
            Ok(tail) => format!("{label}: {}\n{}", path.display(), tail.trim_end()),
            Err(err) => format!(
                "{label}: present but unreadable ({}): {err}",
                path.display()
            ),
        },
        Err(err) => format!(
            "{label}: present but unreadable ({}): {err}",
            path.display()
        ),
    }
}

// ─── helpers ───────────────────────────────────────────────────────

/// Resolve the absolute path to the `mvm-libkrun-supervisor` binary without
/// verifying its freshness — for availability probes and codesign enumeration,
/// not for spawning.
pub fn resolve_supervisor_path() -> Result<PathBuf> {
    mvm_vmm::host::aux_bin::resolve(&libkrun_supervisor_spec())
}

/// Resolve the supervisor and refuse a stale one: the spawn path must not
/// hand a moved-on config contract to a helper built from an older revision.
pub fn resolve_supervisor_path_verified() -> Result<PathBuf> {
    mvm_vmm::host::aux_bin::resolve_verified(&libkrun_supervisor_spec())
}

fn libkrun_supervisor_spec() -> mvm_vmm::host::aux_bin::AuxBin<'static> {
    mvm_vmm::host::aux_bin::AuxBin::new(
        "mvm-libkrun-supervisor",
        "MVM_LIBKRUN_SUPERVISOR_PATH",
        "mvm-hostd",
    )
    .requiring_features(&["libkrun-sys"])
    .signed_with(mvm_vmm::host::codesign::RequiredEntitlement::Hypervisor)
}

pub(crate) fn read_pid(path: &Path) -> Option<libc::pid_t> {
    let s = std::fs::read_to_string(path).ok()?;
    s.trim().parse::<libc::pid_t>().ok()
}

pub(crate) fn pid_alive(pid: libc::pid_t) -> bool {
    mvm_vmm::host::process_liveness::pid_is_alive(pid)
}

pub(crate) fn send_signal(pid: libc::pid_t, sig: libc::c_int) {
    // SAFETY: kill takes integer arguments and touches no memory.
    unsafe { libc::kill(pid, sig) };
}

pub(crate) fn cleanup_vsock_sockets(state_dir: &Path) {
    let control_ports = [
        mvm_agentd::vsock::GUEST_AGENT_PORT,
        mvm_agentd::vsock::WORKLOAD_EXIT_PORT,
        mvm_agentd::vsock::EGRESS_PORT,
        mvm_agentd::vsock::BROKER_PORT,
    ];
    for port in control_ports
        .into_iter()
        .chain(mvm_agentd::vsock::dev_console_data_ports())
    {
        let socket = mvm_core::config::vm_vsock_port_socket_at(state_dir, port);
        let _ = std::fs::remove_file(socket);
    }
}

#[cfg(test)]
mod tests {
    use super::attach_user_volume;
    use libkrun_sys::KrunContext;
    use mvm_core::vm_backend::VmVolume;

    fn context() -> KrunContext {
        KrunContext::new("volume-test", "/kernel", "/rootfs")
    }

    #[test]
    fn materialized_directory_volume_attaches_its_image_as_block() {
        let volume = VmVolume {
            host: "/granted/source".into(),
            guest: "/data".into(),
            read_only: true,
            materialized_image: Some("/state/source.ext4".into()),
            ..VmVolume::default()
        };

        let krun = attach_user_volume(context(), 2, &volume);
        assert_eq!(krun.extra_disks.len(), 1);
        assert_eq!(krun.extra_disks[0].id, "uvol2");
        assert_eq!(krun.extra_disks[0].path, "/state/source.ext4");
        assert!(krun.extra_disks[0].read_only);
        assert!(krun.virtio_fs_mounts.is_empty());
    }

    #[test]
    fn disk_volume_attaches_its_declared_host_image() {
        let volume = VmVolume {
            host: "/images/data.ext4".into(),
            guest: "/data".into(),
            ..VmVolume::default()
        };

        let krun = attach_user_volume(context(), 1, &volume);
        assert_eq!(krun.extra_disks[0].id, "uvol1");
        assert_eq!(krun.extra_disks[0].path, "/images/data.ext4");
    }
}
