//! `mvm-hvf-supervisor` — one process per raw-HVF guest.
//!
//! Reads an [`mvm_build::hvf_supervisor::HvfSupervisorConfig`] JSON document on
//! stdin (written by `mvm_backend::hvf`), self-signs the `hypervisor`
//! entitlement, boots the guest via `mvm_backend::hvf::boot_kernel` (which drives
//! the unified `vmm::run` loop), captures its console to the configured log, and
//! writes/removes a PID file so the backend can confirm launch and stop/status
//! the VM. macOS / Apple-silicon only; a stub elsewhere so the workspace links.

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!(
        "mvm-hvf-supervisor runs only on macOS / Apple silicon (Hypervisor.framework); \
         this is a stub build"
    );
    std::process::exit(1);
}

/// Ad-hoc entitlement applied at first launch — `Hypervisor.framework` rejects an
/// unsigned process. Hypervisor-only (vs the vz supervisor's virtualization key).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const HVF_ENTITLEMENTS_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
    \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
    <plist version=\"1.0\"><dict>\n\
    <key>com.apple.security.hypervisor</key><true/>\n\
    </dict></plist>";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exe_has_hypervisor_entitlement(exe: &std::path::Path) -> bool {
    std::process::Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml"])
        .arg(exe)
        .output()
        .map(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout).contains("com.apple.security.hypervisor")
        })
        .unwrap_or(false)
}

/// Self-sign ad-hoc with the hypervisor entitlement, then re-exec. We ship the
/// bin unsigned and HVF rejects it otherwise. `MVM_HVF_SIGNED` breaks the exec
/// loop; `exec()` preserves the pid + the stdin config pipe. A file lock
/// serializes concurrent launches (codesign --force rewrites the shared binary
/// in place). Mirrors `mvm-vz-supervisor`'s `ensure_self_signed`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_self_signed() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if std::env::var("MVM_HVF_SIGNED").as_deref() == Ok("1") {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if exe_has_hypervisor_entitlement(&exe) {
        return;
    }

    let lock = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(std::env::temp_dir().join("mvm-hvf-supervisor.codesign.lock"))
        .ok();
    if let Some(f) = &lock {
        // SAFETY: flock on a valid fd; LOCK_EX blocks until exclusive.
        unsafe {
            libc::flock(f.as_raw_fd(), libc::LOCK_EX);
        }
    }

    if !exe_has_hypervisor_entitlement(&exe) {
        let ent = std::env::temp_dir().join("mvm-hvf-supervisor-entitlements.plist");
        if std::fs::write(&ent, HVF_ENTITLEMENTS_PLIST).is_err() {
            return;
        }
        let output = Command::new("codesign")
            .args(["--sign", "-", "--force", "--entitlements"])
            .arg(&ent)
            .arg(&exe)
            .output();
        let signed = output.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if !signed {
            eprintln!("mvm-hvf-supervisor: ad-hoc codesign failed; VM start may be rejected");
            if let Ok(o) = &output {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stderr = stderr.trim_end();
                if !stderr.is_empty() {
                    eprintln!("{stderr}");
                }
            }
            return;
        }
    }
    drop(lock);

    let err = Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env("MVM_HVF_SIGNED", "1")
        .exec();
    eprintln!("mvm-hvf-supervisor: re-exec after signing failed: {err}");
    std::process::exit(1);
}

/// Set by the SIGTERM/SIGINT handler; `boot_kernel_until`'s watchdog polls it and
/// force-exits the guest so a stop flushes the console + drops the PID file
/// cleanly (vs the kernel being killed mid-run).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve a network policy's host-allowlist entries to IPs (the admission-time
/// DNS pin) so `host:port` rules gate at L4 — mirrors mvm-hostd's gateway-bridge
/// `resolve_bare_dns_pins`. Literal IPs need no lookup; an unresolvable host pins
/// an empty IP set so the projection fails CLOSED (deny) rather than widening.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn resolve_dns_pins(
    np: &mvm_core::policy::network_policy::NetworkPolicy,
) -> mvm_core::policy::dns_pin::DnsPinRegistry {
    use std::net::{IpAddr, ToSocketAddrs};
    let mut reg = mvm_core::policy::dns_pin::DnsPinRegistry::new();
    let Some(rules) = np.resolve_rules() else {
        return reg; // unrestricted: no L4 pin set
    };
    for hp in rules {
        let ips: Vec<IpAddr> = if let Ok(ip) = hp.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            (hp.host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|sa| sa.ip()).collect())
                .unwrap_or_default()
        };
        reg.add(mvm_core::policy::dns_pin::DnsPin::new(
            hp.host,
            ips,
            chrono::Duration::hours(24),
        ));
    }
    reg
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    use std::io::{Read, Write};
    use std::time::Duration;

    use anyhow::Context;
    use mvm_build::hvf_supervisor::HvfSupervisorConfig;

    // Sign + re-exec before anything else (preserves the stdin config pipe).
    ensure_self_signed();

    // Graceful stop: SIGTERM/SIGINT set STOP, which the boot watchdog observes and
    // force-exits the guest (then we flush the console + drop the PID file).
    // SAFETY: installing a trivial async-signal-safe handler (an atomic store).
    unsafe {
        let h = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
    }

    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("read HvfSupervisorConfig from stdin")?;
    let cfg: HvfSupervisorConfig =
        serde_json::from_str(&raw).context("parse HvfSupervisorConfig JSON from stdin")?;

    // Announce launch: the backend polls for this PID file to confirm boot, then
    // reads it to stop/status the VM.
    std::fs::write(&cfg.pid_file, std::process::id().to_string())
        .with_context(|| format!("write pid file {}", cfg.pid_file.display()))?;

    let image = std::fs::read(&cfg.kernel)
        .with_context(|| format!("read kernel {}", cfg.kernel.display()))?;
    let initramfs = cfg
        .initramfs
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read initramfs")?;
    let disk = cfg
        .disk
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .context("read disk")?;
    // timeout_secs == 0 ⇒ persistent: run until stopped (SIGTERM). A multi-year
    // cap backstops a stuck guest. Otherwise it's a bounded run.
    let timeout = if cfg.timeout_secs == 0 {
        Duration::from_secs(10 * 365 * 24 * 60 * 60)
    } else {
        Duration::from_secs(cfg.timeout_secs)
    };

    // Project the VM's network policy into the vsock egress gateway (claim-10,
    // vsock-only egress): resolve any host-allowlist entries to IPs once (the admission-time
    // DNS pin), then project. deny-all / unrestricted need no pins; a host that
    // fails to resolve pins an empty set so the projection fails CLOSED.
    let pins = resolve_dns_pins(&cfg.network_policy);
    let now = chrono::Utc::now().to_rfc3339();
    let egress = mvm_backend::vmm::egress_gate::EgressGate::from_network_policy(
        &cfg.network_policy,
        &pins,
        &now,
    );
    let result = mvm_backend::hvf::boot_kernel_until(
        &image,
        initramfs.as_deref(),
        disk.as_deref(),
        cfg.vsock,
        timeout,
        &STOP,
        mvm_backend::hvf::HostChannels {
            egress,
            agent_socket: cfg.agent_socket.clone(),
            substitution_socket: cfg.substitution_socket.clone(),
        },
    );

    // The VM has stopped. Persist the outputs (console + workload exit code)
    // BEFORE removing the PID file: the backend keys "stopped" on the PID file via
    // status/wait, so dropping it first races a reader to an empty console.
    let r = result.map_err(|e| anyhow::anyhow!("hvf boot failed: {e:?}"))?;
    if let Ok(mut f) = std::fs::File::create(&cfg.console_log) {
        let _ = f.write_all(&r.console);
    }
    // Transient run-to-exit: persist the workload exit code (the backend's `wait`
    // reads this) so it is durable before "stopped" is observable.
    if let Some(code) = r.workload_exit_code {
        let _ = std::fs::write(&cfg.workload_exit, code.to_string());
    }
    let _ = std::fs::remove_file(&cfg.pid_file);
    if let Some(code) = r.workload_exit_code {
        std::process::exit(code);
    }
    Ok(())
}
