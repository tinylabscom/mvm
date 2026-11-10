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
use mvm_core::kernel_format::KernelFormat;
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

pub(crate) const VERITY_CMDLINE: &str = "console=hvc0";

pub(crate) fn libkrun_kernel_for_host(kernel: &str) -> Result<(String, KernelFormat)> {
    let path = Path::new(kernel);
    if cfg!(target_arch = "x86_64") && path.exists() {
        let loadable = mvm_vmm::host::fc_kernel::ensure_fc_loadable_kernel(path)
            .with_context(|| format!("preparing x86_64 libkrun-loadable kernel from {kernel}"))?;
        return Ok((loadable.to_string_lossy().into_owned(), KernelFormat::Elf));
    }
    Ok((kernel.to_string(), KernelFormat::Raw))
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
