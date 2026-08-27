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

use anyhow::{Context, Result, anyhow, bail};
use libkrun_sys::{BridgeRestartPolicy, KrunContext, SupervisorAttachConfig, SupervisorBaseConfig};
use mvm_core::config::vm_console_log;
use mvm_core::kernel_format::KernelFormat;
use mvm_core::vm_backend::{StandbyClaim, StandbyError, StandbySpec, VmStartConfig};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Kernel cmdline token that turns on the authenticated in-guest vsock client.
/// It is also required for declared ingress under outbound deny-all; secret-
/// bearing workloads remain on the host-side substitution endpoint.
pub fn vsock_egress_cmdline_token(config: &VmStartConfig, _state_dir: &Path) -> Option<String> {
    mvm_vmm::host::egress_shared::effective_vsock_egress(config)
        .then(|| "mvm.vsock_egress=1".to_string())
}

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
/// `mvmctl up` path), SIGTERM often doesn't reach the in-supervisor
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

/// Translate a [`StandbyClaim`] into the `SupervisorAttachConfig`, echoing the
/// standby's binding nonce. `plan_json`/`bundle_json` decode to `serde_json::Value`
/// carriers (the same shape `SupervisorConfig.plan` uses).
pub fn standby_attach_config(
    claim: &StandbyClaim,
    binding_nonce: String,
) -> std::result::Result<SupervisorAttachConfig, StandbyError> {
    let plan: serde_json::Value = serde_json::from_str(&claim.plan_json)
        .map_err(|e| StandbyError::ClaimFailed(format!("decode plan_json: {e}")))?;
    let bundle = match &claim.bundle_json {
        Some(b) => Some(
            serde_json::from_str(b)
                .map_err(|e| StandbyError::ClaimFailed(format!("decode bundle_json: {e}")))?,
        ),
        None => None,
    };
    let network_policy = Some(
        serde_json::to_value(&claim.network_policy)
            .map_err(|e| StandbyError::ClaimFailed(format!("encode network_policy: {e}")))?,
    );
    Ok(SupervisorAttachConfig {
        binding_nonce,
        rootfs_path: claim.rootfs_path.clone(),
        tenant_id: claim.tenant_id.clone(),
        audit_dir: claim.audit_dir.clone(),
        gateway_audit_socket: claim.gateway_audit_socket.clone(),
        gateway_events_socket: claim.gateway_events_socket.clone(),
        plan,
        bundle,
        network_policy,
        transparent_terminator_port: claim.start_config.as_ref().map(|config| {
            mvm_vmm::host::egress_redirect::terminator_port_for_vm_name(&config.name)
        }),
    })
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

pub fn libkrun_verity_cmdline_args(config: &VmStartConfig) -> Option<String> {
    let rootfs_hash = config.roothash.as_deref()?;
    let base = format!("mvm.roothash={rootfs_hash} mvm.data=/dev/vdb mvm.hash=/dev/vdc");
    match libkrun_runtime_overlay(config) {
        Some((_, _, overlay_hash)) => Some(format!(
            "{base} mvm.runtime_roothash={overlay_hash} mvm.runtime_data=/dev/vdd mvm.runtime_hash=/dev/vde"
        )),
        None => Some(base),
    }
}

pub fn ensure_libkrun_runtime_source_supported(config: &VmStartConfig) -> Result<()> {
    // A sealed boot (verity metadata present) must be fully verity capable — a
    // missing initrd fails closed rather than downgrading to an unverified root —
    // and carries the dm-verity overlay triple its initramfs mounts. A non-verity
    // dev boot instead mounts a plain read-only overlay from `/dev/vdb`.
    let verity_intended = config.roothash.is_some() || config.verity_path.is_some();
    if verity_intended {
        if !libkrun_verity_enabled(config) {
            bail!(
                "required-overlay libkrun boot requires verity metadata plus an initrd \
                 (`--initrd` or sibling rootfs.initrd)"
            );
        }
        if libkrun_runtime_overlay(config).is_none() {
            bail!("required-overlay libkrun boot requires the runtime overlay artifact triple");
        }
    } else if mvm_vmm::host::boot_config::non_verity_overlay_ext4(config).is_none() {
        bail!(
            "required-overlay libkrun boot requires the runtime overlay artifact triple \
             (a non-verity boot mounts it as a plain read-only /dev/vdb)"
        );
    }
    Ok(())
}

/// Assemble the guest kernel cmdline: the verity or default base string plus
/// every optional token layered on top, in the exact order the guest
/// `/init` expects them.
pub fn build_guest_cmdline(config: &VmStartConfig, state_dir: &Path) -> String {
    // Append the `mvm.uvols=` param so the dev VM's `mvm-host-vm-init`
    // mounts user volumes at their guest paths (no-op when there are
    // none; harmless for workload guests whose `/init` ignores it).
    let mut cmdline = if libkrun_verity_enabled(config) {
        VERITY_CMDLINE.to_string()
    } else {
        DEFAULT_CMDLINE.to_string()
    };
    if let Some(uvols) = mvm_core::vm_backend::encode_user_volumes_cmdline(&config.volumes) {
        cmdline.push(' ');
        cmdline.push_str(&uvols);
    }
    if let Some(token) = mvm_vmm::host::egress_bridge::verb_grant_cmdline_token(&config.name) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    if let Some(token) = mvm_vmm::host::egress_bridge::require_grant_cmdline_token(&config.name) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    if let Some(verity_args) = libkrun_verity_enabled(config)
        .then(|| libkrun_verity_cmdline_args(config))
        .flatten()
    {
        cmdline.push(' ');
        cmdline.push_str(&verity_args);
    }
    // Non-verity boots carry the runtime overlay as a plain read-only
    // `/dev/vdb`; emit the token its `/init` mounts from. Verity boots already
    // emitted the dm-verity variant above.
    if !libkrun_verity_enabled(config)
        && let Some(overlay_args) = mvm_vmm::host::boot_config::build_runtime_overlay_cmdline_args(
            None,
            mvm_vmm::host::boot_config::non_verity_overlay_ext4(config).is_some(),
        )
    {
        cmdline.push(' ');
        cmdline.push_str(&overlay_args);
    }
    // Vsock-only guests have no config drive, so the grant trust anchor rides
    // the cmdline instead.
    if let Some(token) = mvm_vmm::host::egress_bridge::host_signer_pub_cmdline_token(&config.name) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    if let Some(token) = vsock_egress_cmdline_token(config, state_dir) {
        cmdline.push(' ');
        cmdline.push_str(&token);
    }
    cmdline
}

/// Attach the workload rootfs (plus its dm-verity sidecar and the runtime
/// overlay disk) to `krun`. Verity boots carry `root`/`root-verity` disks
/// and an initramfs; non-verity boots set `rootfs_path` directly and, when a
/// runtime overlay is present, attach it as a plain read-only `/dev/vdb`.
pub fn attach_workload_rootfs(mut krun: KrunContext, config: &VmStartConfig) -> KrunContext {
    if libkrun_verity_enabled(config) {
        krun.initramfs_path =
            libkrun_effective_initrd(config).map(|p| p.to_string_lossy().into_owned());
        krun = krun
            .add_disk("root", config.rootfs_path.clone(), true)
            .add_disk(
                "root-verity",
                config
                    .verity_path
                    .clone()
                    .expect("verity-enabled libkrun boot must carry a verity sidecar"),
                true,
            );
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
/// A directory share is a virtio-fs device; a disk image is an extra
/// virtio-blk device. Tag/id `uvol{idx}` is the coordination key the guest
/// mount manifest uses to mount each at its requested guest path. Disk
/// images are sparse-created by the CLI orchestrator before start; a RO
/// disk image is RO at the hypervisor (krun_add_disk takes read_only).
///
/// libkrun's `krun_add_virtiofs` has NO host-side read-only
/// toggle, so a "read-only" virtio-fs share would only be ro by the
/// guest's own mount flag — a compromised guest could remount it rw.
/// Rather than make a false ro promise, refuse it and point at the
/// hypervisor-enforced alternatives. (HVF/Firecracker enforce ro shares
/// natively; this restriction is libkrun-specific.)
pub fn attach_user_volumes(mut krun: KrunContext, config: &VmStartConfig) -> Result<KrunContext> {
    for (idx, vol) in config.volumes.iter().enumerate() {
        let tag = format!("uvol{idx}");
        krun = match vol.kind {
            mvm_core::vm_backend::VmVolumeKind::DirShare => {
                if vol.read_only {
                    bail!(
                        "libkrun cannot enforce a read-only virtio-fs share ('{}' -> '{}'): \
                         krun_add_virtiofs has no host-side read-only toggle, so a compromised \
                         guest could remount it read-write. Use a read-only disk image \
                         (host:/guest:SIZE) for hypervisor-enforced read-only, share it ':rw' if \
                         writes are intended, or run on the HVF backend.",
                        vol.host,
                        vol.guest
                    );
                }
                krun.add_virtio_fs(tag, vol.host.clone())
            }
            mvm_core::vm_backend::VmVolumeKind::Disk => {
                krun.add_disk(tag, vol.host.clone(), vol.read_only)
            }
        };
    }
    Ok(krun)
}

/// Assemble the per-workload [`KrunContext`]: the workload-independent base
/// (kernel + resources + vsock + endpoint), shared verbatim with the standby
/// spawn so the two paths can't drift, plus the cold-path additions —
/// console capture, the workload rootfs, the
/// dev-console data ports, and any user-supplied volumes.
pub fn build_workload_krun_context(
    config: &VmStartConfig,
    kernel: &str,
    kernel_format: KernelFormat,
    vcpus: u8,
    cmdline: &str,
    state_dir: &Path,
) -> Result<KrunContext> {
    let mut krun = krun_context_base(
        &config.name,
        kernel,
        vcpus,
        config.memory_mib,
        cmdline,
        state_dir,
    );
    krun = krun
        .with_kernel_format(kernel_format)
        .with_console_output(vm_console_log(&config.name).display().to_string());
    krun = attach_workload_rootfs(krun, config);

    // A dev-accessible managed machine (`machine run -t` / `machine shell` /
    // `up --console`) pre-opens the interactive-console data range. libkrun
    // binds one host UDS listener per registered port (`listen=true`, host
    // dials → guest's vsock server), so the agent's dynamic
    // `CONSOLE_PORT_BASE + session_id` data port is unreachable unless it was
    // declared here. Left out of `krun_context_base` so the warm-standby base
    // (no `VmStartConfig` yet) stays unchanged.
    if config.dev_console {
        for port in mvm_agentd::vsock::dev_console_data_ports() {
            krun = krun.add_vsock_port(port);
        }
    }

    attach_user_volumes(krun, config)
}

/// Validate the tenant label and resolve the gateway-bridge audit substrate
/// (paths).
///
/// `tenant_id` flows into the per-VM audit-chain path
/// (`workload_audit_path`) that the host-services broker spawns against —
/// even on the legacy/no-bridge path where the substrate stays all-None. So
/// the tenant is validated here regardless of `plan_json`: an unsafe tenant
/// (e.g. a path-traversal label) must be refused before `start()` reaches
/// the broker spawn, independent of whether the gateway bridge is engaged. A
/// path-injection guard, not just the bridge's input check.
///
/// Substrate resolution is gated on `plan_json` — the bridge supervisor's
/// actual input — NOT on `tenant_id`: a substrate without a plan is what the
/// supervisor rejects as "cfg.plan missing on bridge path". An admitted
/// workload carries both `tenant_id` and `plan_json`, so the default
/// workload path reaches the enforcing bridge; dev/builder starts keep
/// `plan_json` absent and stay on the legacy `run_supervisor` path with an
/// all-None substrate. (`compute_audit_substrate` re-validates the tenant —
/// harmless after the guard above.)
pub fn resolve_audit_substrate(
    config: &VmStartConfig,
) -> Result<mvm_vmm::host::audit_substrate::AuditSubstrate> {
    if let Some(tenant) = config.tenant_id.as_deref() {
        mvm_vmm::host::audit_substrate::validate_tenant_id(tenant)?;
    }
    Ok(if config.plan_json.is_some() {
        mvm_vmm::host::audit_substrate::compute_audit_substrate(
            &config.name,
            config.tenant_id.as_deref(),
        )?
    } else {
        mvm_vmm::host::audit_substrate::AuditSubstrate::default()
    })
}

/// Parse the signed-plan + bundle envelopes from `VmStartConfig`.
/// `libkrun_sys::SupervisorConfig` carries them as `Option<serde_json::Value>`
/// so the supervisor can re-verify the envelope without typed coupling
/// to `mvm_core::plan` at the parse boundary.
pub fn parse_plan_and_bundle(
    config: &VmStartConfig,
) -> Result<(Option<serde_json::Value>, Option<serde_json::Value>)> {
    let plan = match config.plan_json.as_deref() {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| anyhow!("parse VmStartConfig.plan_json as JSON: {e}"))?,
        ),
        None => None,
    };
    let bundle = match config.bundle_json.as_deref() {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| anyhow!("parse VmStartConfig.bundle_json as JSON: {e}"))?,
        ),
        None => None,
    };
    Ok((plan, bundle))
}

pub fn supervisor_config_dump_path(state_dir: &Path) -> PathBuf {
    state_dir.join("supervisor-config.json")
}

pub fn persist_supervisor_config_dump(state_dir: &Path, json: &str) -> Result<()> {
    let path = supervisor_config_dump_path(state_dir);
    std::fs::write(&path, json).map_err(|e| anyhow!("write {}: {e}", path.display()))
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

pub fn summarize_supervisor_config(path: &Path) -> String {
    if !path.exists() {
        return format!("supervisor-config.json: missing ({})", path.display());
    }
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(err) => {
            return format!(
                "supervisor-config.json: present but unreadable ({}): {err}",
                path.display()
            );
        }
    };
    if body.trim().is_empty() {
        return format!(
            "supervisor-config.json: present but empty ({})",
            path.display()
        );
    }
    let value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(err) => {
            return format!(
                "supervisor-config.json: present but invalid json ({}): {err}",
                path.display()
            );
        }
    };
    let kernel_path = value
        .pointer("/krun/kernel_path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>");
    let rootfs_path = value
        .pointer("/krun/rootfs_path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>");
    let initramfs_path = value
        .pointer("/krun/initramfs_path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>");
    let networking = value
        .pointer("/krun/networking")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>");
    let disks = value
        .pointer("/krun/disks")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("id").and_then(serde_json::Value::as_str))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let cmdline = value
        .pointer("/krun/cmdline")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>");
    let console_output_path = value
        .pointer("/krun/console_output_path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<none>");
    format!(
        "supervisor-config.json: {}\n  kernel_path={kernel_path}\n  rootfs_path={rootfs_path}\n  initramfs_path={initramfs_path}\n  networking={networking}\n  console_output_path={console_output_path}\n  disks={} [{}]\n  cmdline={cmdline}",
        path.display(),
        disks.len(),
        disks.join(", ")
    )
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

pub fn diagnose_vsock_sockets(state_dir: &Path) -> String {
    let mut sockets = match std::fs::read_dir(state_dir) {
        Ok(entries) => entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let file_name = entry.file_name();
                let name = file_name.to_str()?;
                (name.starts_with("vsock-") && name.ends_with(".sock")).then(|| name.to_string())
            })
            .collect::<Vec<_>>(),
        Err(err) => {
            return format!(
                "vsock sockets: unreadable state dir ({}): {err}",
                state_dir.display()
            );
        }
    };
    sockets.sort();
    if sockets.is_empty() {
        format!("vsock sockets: none under {}", state_dir.display())
    } else {
        format!(
            "vsock sockets under {}: {}",
            state_dir.display(),
            sockets.join(", ")
        )
    }
}

pub fn libkrun_startup_diagnostics(state_dir: &Path) -> String {
    let console_log = state_dir.join("console.log");
    let supervisor_stderr = state_dir.join("supervisor.stderr.log");
    let supervisor_lifecycle = state_dir.join("supervisor.lifecycle.log");
    let supervisor_config = supervisor_config_dump_path(state_dir);
    format!(
        "libkrun vm state dir: {}\n{}\n{}\n{}\n{}\n{}",
        state_dir.display(),
        diagnose_vsock_sockets(state_dir),
        diagnose_log_path("supervisor.lifecycle.log", &supervisor_lifecycle),
        summarize_supervisor_config(&supervisor_config),
        diagnose_log_path("supervisor.stderr.log", &supervisor_stderr),
        diagnose_log_path("console.log", &console_log),
    )
}

// ─── helpers ───────────────────────────────────────────────────────

/// Resolve the absolute path to the `mvm-libkrun-supervisor` binary. Compiled
/// by mvmctl's build script; see [`mvm_vmm::host::aux_bin`] for the search order.
pub fn resolve_supervisor_path() -> Result<PathBuf> {
    mvm_vmm::host::aux_bin::resolve(&mvm_vmm::host::aux_bin::AuxBin {
        bin: "mvm-libkrun-supervisor",
        env_var: "MVM_LIBKRUN_SUPERVISOR_PATH",
    })
}

pub(crate) fn read_pid(path: &Path) -> Option<libc::pid_t> {
    let s = std::fs::read_to_string(path).ok()?;
    s.trim().parse::<libc::pid_t>().ok()
}

pub(crate) fn pid_alive(pid: libc::pid_t) -> bool {
    mvm_vmm::host::process_liveness::pid_is_alive(pid)
}

pub(crate) fn send_signal(pid: libc::pid_t, sig: libc::c_int) {
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
