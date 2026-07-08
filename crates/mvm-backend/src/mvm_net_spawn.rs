//! Spawn/reap support for the per-VM `mvm-host-netd` authority process.
//!
//! The backend writes the binary's documented JSON config and starts it in
//! `--listen-uds` mode. This keeps `mvm-backend` from linking `mvm-net` while
//! still sharing the same wire contract through serde-compatible `mvm-core`
//! policy and DNS-pin types.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
use mvm_core::policy::network_policy::NetworkPolicy;
use serde_json::json;

pub const HOST_NETD_PID_FILE: &str = "mvm-host-netd.pid";
pub const HOST_NETD_CONFIG_FILE: &str = "mvm-host-netd.json";
pub const HOST_NETD_SOCKET_FILE: &str = "mvm-net-authority.sock";
pub const HOST_NETD_AUDIT_FILE: &str = "mvm-host-netd.audit.jsonl";
/// Guest bridge authority port. Mirrors `mvm-net`'s guest bridge default without
/// linking `mvm-net` into `mvm-backend`.
pub const TRANSPARENT_NET_VSOCK_PORT: u32 = 5254;
pub const DEFAULT_DNS_PIN_TTL: Duration = Duration::from_secs(3600);
pub const HOST_NETD_READY_TIMEOUT: Duration = Duration::from_secs(10);
pub const HOST_NETD_REAP_GRACE_TIMEOUT: Duration = Duration::from_millis(500);

fn resolve_host_netd_path() -> Result<PathBuf> {
    crate::aux_bin::resolve_or_build(&crate::aux_bin::AuxBin {
        bin: "mvm-host-netd",
        package: "mvm-net",
        env_var: "MVM_HOST_NETD_PATH",
        features: &["host-netd"],
        input_roots: &[
            "Cargo.toml",
            "Cargo.lock",
            "crates/mvm-net/Cargo.toml",
            "crates/mvm-net/src",
            "crates/mvm-core/Cargo.toml",
            "crates/mvm-core/src",
        ],
    })
}

pub struct MvmNetSpawnParams<'a> {
    pub vm_name: &'a str,
    pub state_dir: &'a Path,
    pub network_policy: &'a NetworkPolicy,
}

pub fn mvm_net_authority_socket(state_dir: &Path) -> PathBuf {
    state_dir.join(HOST_NETD_SOCKET_FILE)
}

pub fn spawn_mvm_net_authority(params: MvmNetSpawnParams<'_>) -> Result<PathBuf> {
    std::fs::create_dir_all(params.state_dir)
        .with_context(|| format!("create state dir {}", params.state_dir.display()))?;
    let socket = mvm_net_authority_socket(params.state_dir);
    let config_path = params.state_dir.join(HOST_NETD_CONFIG_FILE);
    let audit_path = params.state_dir.join(HOST_NETD_AUDIT_FILE);
    let pid_path = params.state_dir.join(HOST_NETD_PID_FILE);
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&pid_path);

    let now = mvm_core::util::time::utc_now();
    let expires_at = mvm_core::util::time::utc_plus_duration(DEFAULT_DNS_PIN_TTL);
    let dns_pins = resolve_dns_pins(params.network_policy, &now, &expires_at)?;
    let config = host_netd_config_json(params.network_policy, &dns_pins, &now);
    std::fs::write(&config_path, config.to_string())
        .with_context(|| format!("write {}", config_path.display()))?;

    let bin = resolve_host_netd_path()?;
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .with_context(|| format!("open {}", audit_path.display()))?;
    let mut cmd = Command::new(&bin);
    cmd.arg("--config")
        .arg(&config_path)
        .arg("--listen-uds")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(audit_file));
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn {} for {}: {e}", bin.display(), params.vm_name))?;
    let deadline = Instant::now() + HOST_NETD_READY_TIMEOUT;
    loop {
        if socket.exists() {
            std::fs::write(&pid_path, child.id().to_string())
                .with_context(|| format!("write {}", pid_path.display()))?;
            drop(child);
            return Ok(socket);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| anyhow!("poll mvm-host-netd: {e}"))?
        {
            bail!(
                "mvm-host-netd exited before binding {} (status: {status}); see {}",
                socket.display(),
                audit_path.display()
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!(
                "mvm-host-netd did not bind {} within {:?}; killed",
                socket.display(),
                HOST_NETD_READY_TIMEOUT
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn host_netd_config_json(
    network_policy: &NetworkPolicy,
    dns_pins: &DnsPinRegistry,
    now: &str,
) -> serde_json::Value {
    json!({
        "network_policy": network_policy,
        "dns_pins": dns_pins,
        "now": now,
    })
}

fn resolve_dns_pins(
    network_policy: &NetworkPolicy,
    resolved_at: &str,
    expires_at: &str,
) -> Result<DnsPinRegistry> {
    let mut registry = DnsPinRegistry::new();
    let Some(rules) = network_policy.resolve_rules() else {
        return Ok(registry);
    };
    for rule in rules {
        let ips = resolve_rule_ips(&rule.host, rule.port)?;
        registry.add(DnsPin::at(
            rule.host,
            ips,
            resolved_at.to_string(),
            expires_at.to_string(),
        ));
    }
    Ok(registry)
}

fn resolve_rule_ips(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let mut ips: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve network policy host {host:?}"))?
        .map(|addr| addr.ip())
        .collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        bail!("network policy host {host:?} resolved to no IP addresses");
    }
    Ok(ips)
}

pub fn reap_mvm_net_authority(state_dir: &Path) {
    if let Some(pid) = read_pid(&state_dir.join(HOST_NETD_PID_FILE))
        && pid_alive_or_reap(pid)
    {
        terminate_recorded_pid(pid);
    }
    let _ = std::fs::remove_file(state_dir.join(HOST_NETD_PID_FILE));
    let _ = std::fs::remove_file(state_dir.join(HOST_NETD_SOCKET_FILE));
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive_or_reap(pid: libc::pid_t) -> bool {
    if reap_exited_child(pid) {
        return false;
    }
    // SAFETY: signal 0 probes existence/permission without delivering a signal.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn kill(pid: libc::pid_t, sig: libc::c_int) {
    // SAFETY: best-effort signal to a pid this helper recorded.
    unsafe {
        libc::kill(pid, sig);
    }
}

fn terminate_recorded_pid(pid: libc::pid_t) {
    kill(pid, libc::SIGTERM);
    if wait_for_pid_exit(pid, HOST_NETD_REAP_GRACE_TIMEOUT) {
        return;
    }
    kill(pid, libc::SIGKILL);
    let _ = wait_for_pid_exit(pid, HOST_NETD_REAP_GRACE_TIMEOUT);
}

fn wait_for_pid_exit(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !pid_alive_or_reap(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn reap_exited_child(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: waitpid with WNOHANG observes/reaps only this recorded child pid.
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    rc == pid
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::network_policy::HostPort;

    #[test]
    fn config_json_carries_policy_pins_and_timestamp() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("203.0.113.10", 443)]);
        let pins =
            resolve_dns_pins(&policy, "2030-01-01T00:00:00Z", "2030-01-01T01:00:00Z").unwrap();
        let cfg = host_netd_config_json(&policy, &pins, "2030-01-01T00:00:00Z");

        assert_eq!(cfg["network_policy"]["type"], "allowlist");
        assert_eq!(
            cfg["dns_pins"]["pins"]["203.0.113.10"]["ips"][0],
            "203.0.113.10"
        );
        assert_eq!(cfg["now"], "2030-01-01T00:00:00Z");
    }

    #[test]
    fn resolve_dns_pins_pins_direct_ip_allow_list_without_dns() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("2001:db8::10", 8443)]);
        let pins =
            resolve_dns_pins(&policy, "2030-01-01T00:00:00Z", "2030-01-01T01:00:00Z").unwrap();

        let pin = pins.lookup("2001:db8::10").unwrap();
        assert_eq!(pin.ips, vec!["2001:db8::10".parse::<IpAddr>().unwrap()]);
        assert_eq!(pin.ttl_secs(), 3600);
    }

    #[test]
    fn spawn_mvm_net_authority_writes_config_and_records_pid() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!("mvm-host-netd-spawn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub-host-netd.sh");
        std::fs::write(
            &stub,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --config) cfg=\"$2\"; shift 2 ;;\n    --listen-uds) sock=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\ndone\ncp \"$cfg\" \"$cfg.captured\"\ntouch \"$sock\"\nsleep 30\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved = std::env::var_os("MVM_HOST_NETD_PATH");
        unsafe {
            std::env::set_var("MVM_HOST_NETD_PATH", &stub);
        }

        let socket = spawn_mvm_net_authority(MvmNetSpawnParams {
            vm_name: "netd-spawn-test",
            state_dir: &dir,
            network_policy: &NetworkPolicy::allow_list(vec![HostPort::new("203.0.113.10", 443)]),
        })
        .unwrap();

        unsafe {
            match saved {
                Some(value) => std::env::set_var("MVM_HOST_NETD_PATH", value),
                None => std::env::remove_var("MVM_HOST_NETD_PATH"),
            }
        }

        assert_eq!(socket, dir.join(HOST_NETD_SOCKET_FILE));
        assert!(dir.join(HOST_NETD_PID_FILE).is_file());
        let captured =
            std::fs::read_to_string(dir.join(format!("{HOST_NETD_CONFIG_FILE}.captured"))).unwrap();
        let cfg: serde_json::Value = serde_json::from_str(&captured).unwrap();
        assert_eq!(cfg["network_policy"]["type"], "allowlist");
        assert_eq!(
            cfg["dns_pins"]["pins"]["203.0.113.10"]["ips"][0],
            "203.0.113.10"
        );

        reap_mvm_net_authority(&dir);
        assert!(!dir.join(HOST_NETD_PID_FILE).exists());
        assert!(!dir.join(HOST_NETD_SOCKET_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reap_mvm_net_authority_kills_recorded_process_and_cleans_state() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(HOST_NETD_SOCKET_FILE);
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; while :; do sleep 1; done")
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        std::fs::write(dir.path().join(HOST_NETD_PID_FILE), pid.to_string()).unwrap();
        assert!(pid_alive_or_reap(pid), "stub authority should be running");

        reap_mvm_net_authority(dir.path());

        assert!(
            !pid_alive_or_reap(pid),
            "reap must terminate even a SIGTERM-ignoring authority"
        );
        assert!(!dir.path().join(HOST_NETD_PID_FILE).exists());
        assert!(!dir.path().join(HOST_NETD_SOCKET_FILE).exists());
        let _ = child.kill();
        let _ = child.wait();
    }
}
