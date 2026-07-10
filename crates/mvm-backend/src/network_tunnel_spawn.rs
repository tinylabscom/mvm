//! Shared per-VM packet-tunnel worker spawn/reap helpers.
//!
//! The first production tunnel slice keeps one host-owned helper process per
//! VM. It binds the per-port host UDS the backend already exposes to the guest
//! via virtio-vsock, validates the guest's tunnel identity, hands down the
//! host-authored `mvm-net0` config, and then enforces a default-deny packet
//! policy until the admitted forward path lands.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use mvm_core::protocol::network_tunnel::{
    MAX_FRAME_PAYLOAD_LEN, MIN_TUNNEL_MTU, TunnelFeatures, TunnelNetworkConfig, TunnelRuntimeConfig,
};

use crate::aux_bin::{self, AuxBin};
use crate::broker_services_spawn::{
    kill, pid_alive, read_pid, spawn_detached_with_config, wait_for_uds,
};

pub(crate) const NETWORK_TUNNEL_WORKER_PID_FILE: &str = "network-tunnel-worker.pid";
pub(crate) const NETWORK_TUNNEL_AUDIT_JSONL: &str = "network-tunnel.audit.jsonl";
pub(crate) const NETWORK_TUNNEL_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetworkTunnelListener {
    Uds(PathBuf),
    Vsock(u32),
}

pub(crate) struct NetworkTunnelWorkerSpawnParams<'a> {
    pub state_dir: &'a Path,
    pub runtime_config: Option<&'a TunnelRuntimeConfig>,
    pub listener: Option<NetworkTunnelListener>,
    pub host_tun_interface_name: Option<&'a str>,
}

pub(crate) fn spawn_network_tunnel_worker_if_configured(
    params: NetworkTunnelWorkerSpawnParams<'_>,
) -> Result<NetworkTunnelWorkerGuard> {
    let Some(runtime_config) = params.runtime_config else {
        return Ok(NetworkTunnelWorkerGuard::defused());
    };
    runtime_config.validate()?;

    let state_dir = params.state_dir;
    std::fs::create_dir_all(state_dir).map_err(|e| {
        anyhow!(
            "create tunnel worker state dir {}: {e}",
            state_dir.display()
        )
    })?;
    let listener = params.listener.unwrap_or_else(|| {
        NetworkTunnelListener::Uds(mvm_core::config::vm_vsock_port_socket_at(
            state_dir,
            runtime_config.guest_port,
        ))
    });
    let audit_jsonl_path = state_dir.join(NETWORK_TUNNEL_AUDIT_JSONL);
    if let NetworkTunnelListener::Uds(path) = &listener
        && let Some(parent) = path.parent()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create tunnel worker socket dir {}: {e}", parent.display()))?;
    }
    if let Some(parent) = audit_jsonl_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create tunnel worker audit dir {}: {e}", parent.display()))?;
    }

    let config_json =
        build_network_tunnel_worker_config_json(
            &listener,
            &audit_jsonl_path,
            runtime_config,
            params.host_tun_interface_name,
        )?;
    let worker_bin = aux_bin::resolve(&AuxBin {
        bin: "mvm-network-tunnel-worker",
        env_var: "MVM_NETWORK_TUNNEL_WORKER_PATH",
    })?;

    let guard = NetworkTunnelWorkerGuard::armed(state_dir);
    let child = spawn_detached_with_config(&worker_bin, &config_json, "mvm-network-tunnel-worker")?;
    wait_for_listener_ready(
        "mvm-network-tunnel-worker",
        &listener,
        child.id(),
        NETWORK_TUNNEL_READY_TIMEOUT,
    )?;

    let pid_file = state_dir.join(NETWORK_TUNNEL_WORKER_PID_FILE);
    std::fs::write(&pid_file, child.id().to_string())
        .map_err(|e| anyhow!("write {}: {e}", pid_file.display()))?;
    Ok(guard)
}

fn build_network_tunnel_worker_config_json(
    listener: &NetworkTunnelListener,
    audit_jsonl_path: &Path,
    runtime_config: &TunnelRuntimeConfig,
    host_tun_interface_name: Option<&str>,
) -> Result<serde_json::Value> {
    let network_config = derive_network_config(runtime_config)?;
    let accepted_features = accepted_features(runtime_config);
    Ok(serde_json::json!({
        "listener": listener_config_json(listener),
        "audit_jsonl_path": audit_jsonl_path,
        "worker": {
            "expected_session": {
                "tenant_id": runtime_config.session.tenant_id,
                "vm_id": runtime_config.session.vm_id,
                "boot_id": runtime_config.session.boot_id,
                "session_nonce": runtime_config.session.session_nonce,
                "maximum_frame_size": runtime_config.session.maximum_frame_size,
                "accepted_features": accepted_features,
            },
            "network_config": network_config,
            "initial_credit": initial_credit(runtime_config)?,
            "packet_policy": packet_policy_json(host_tun_interface_name),
            "limits": {
                "max_packets": 1024_u64,
                "max_bytes": 8_u64 * 1024 * 1024,
            }
        }
    }))
}

fn packet_policy_json(host_tun_interface_name: Option<&str>) -> serde_json::Value {
    match host_tun_interface_name {
        Some(interface_name) => {
            serde_json::json!({ "kind": "host_tun", "interface_name": interface_name })
        }
        None => serde_json::json!({ "kind": "drop_all" }),
    }
}

fn listener_config_json(listener: &NetworkTunnelListener) -> serde_json::Value {
    match listener {
        NetworkTunnelListener::Uds(path) => {
            serde_json::json!({ "kind": "uds", "path": path })
        }
        NetworkTunnelListener::Vsock(port) => {
            serde_json::json!({ "kind": "vsock", "port": port })
        }
    }
}

fn wait_for_listener_ready(
    what: &str,
    listener: &NetworkTunnelListener,
    pid: u32,
    timeout: Duration,
) -> Result<()> {
    match listener {
        NetworkTunnelListener::Uds(path) => wait_for_uds(what, path, pid, timeout),
        NetworkTunnelListener::Vsock(_port) => wait_for_child_startup(what, pid, timeout),
    }
}

fn wait_for_child_startup(what: &str, pid: u32, timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let startup_window = Duration::from_millis(100);
    let stable_after = std::time::Instant::now() + startup_window.min(timeout);
    let mut backoff = Duration::from_millis(5);
    loop {
        if !pid_alive(pid as libc::pid_t) {
            bail!("{what} exited before startup completed");
        }
        if std::time::Instant::now() >= stable_after {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            kill(pid as libc::pid_t, libc::SIGKILL);
            bail!("{what} did not stay alive long enough to confirm startup");
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(25));
    }
}

fn accepted_features(runtime_config: &TunnelRuntimeConfig) -> TunnelFeatures {
    runtime_config.session.requested_features.clone()
}

fn derive_network_config(runtime_config: &TunnelRuntimeConfig) -> Result<TunnelNetworkConfig> {
    if runtime_config.session.maximum_frame_size < u32::from(MIN_TUNNEL_MTU) {
        return Err(anyhow!(
            "network tunnel frame size {} is smaller than the minimum tunnel MTU {}",
            runtime_config.session.maximum_frame_size,
            MIN_TUNNEL_MTU
        ));
    }
    let mtu = clamp_mtu(runtime_config.session.maximum_frame_size);
    let config = TunnelNetworkConfig {
        interface_name: "mvm-net0".to_string(),
        guest_ipv4: "10.240.0.2".parse().expect("static guest IPv4 is valid"),
        prefix_len: 30,
        gateway_ipv4: "10.240.0.1"
            .parse()
            .expect("static tunnel gateway IPv4 is valid"),
        dns_servers: vec!["10.240.0.1".parse().expect("static tunnel DNS IP is valid")],
        mtu,
    };
    config.validate()?;
    Ok(config)
}

fn clamp_mtu(maximum_frame_size: u32) -> u16 {
    let bounded = maximum_frame_size.min(1500).min(MAX_FRAME_PAYLOAD_LEN);
    u16::try_from(bounded).expect("bounded tunnel MTU fits u16")
}

fn initial_credit(
    runtime_config: &TunnelRuntimeConfig,
) -> Result<mvm_core::protocol::network_tunnel::TunnelCreditUpdate> {
    runtime_config.validate()?;
    Ok(mvm_core::protocol::network_tunnel::TunnelCreditUpdate {
        flow_id: 0,
        bytes: runtime_config.session.maximum_frame_size,
        packets: 1024,
    })
}

pub(crate) struct NetworkTunnelWorkerGuard {
    state_dir: Option<PathBuf>,
}

impl NetworkTunnelWorkerGuard {
    pub(crate) fn armed(state_dir: &Path) -> Self {
        Self {
            state_dir: Some(state_dir.to_path_buf()),
        }
    }

    pub(crate) fn defused() -> Self {
        Self { state_dir: None }
    }

    pub(crate) fn defuse(&mut self) {
        self.state_dir = None;
    }
}

impl Drop for NetworkTunnelWorkerGuard {
    fn drop(&mut self) {
        if let Some(state_dir) = &self.state_dir {
            tracing::warn!(
                state_dir = %state_dir.display(),
                "NetworkTunnelWorkerGuard: reaping orphaned network tunnel worker"
            );
            reap_network_tunnel_worker(state_dir);
        }
    }
}

pub(crate) fn reap_network_tunnel_worker(state_dir: &Path) {
    let pid_file = state_dir.join(NETWORK_TUNNEL_WORKER_PID_FILE);
    if let Some(pid) = read_pid(&pid_file)
        && pid_alive(pid)
    {
        kill(pid, libc::SIGTERM);
    }
    let _ = std::fs::remove_file(&pid_file);
    let _ = std::fs::remove_file(state_dir.join(NETWORK_TUNNEL_AUDIT_JSONL));
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::protocol::network_tunnel::{TunnelFeatures, TunnelSessionConfig};

    fn runtime_config() -> TunnelRuntimeConfig {
        TunnelRuntimeConfig {
            guest_port: 5302,
            session: TunnelSessionConfig {
                tenant_id: "tenant-a".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: TunnelFeatures {
                    ipv4: true,
                    split_control_stream: true,
                    ..TunnelFeatures::default()
                },
                maximum_frame_size: 4096,
            },
        }
    }

    #[test]
    fn derive_network_config_uses_static_guest_and_gateway_shape() {
        let config = derive_network_config(&runtime_config()).unwrap();
        assert_eq!(config.interface_name, "mvm-net0");
        assert_eq!(config.guest_ipv4.to_string(), "10.240.0.2");
        assert_eq!(config.gateway_ipv4.to_string(), "10.240.0.1");
        assert_eq!(config.prefix_len, 30);
        assert_eq!(config.dns_servers.len(), 1);
        assert_eq!(config.dns_servers[0].to_string(), "10.240.0.1");
        assert_eq!(config.mtu, 1500);
    }

    #[test]
    fn derive_network_config_rejects_too_small_frame_size() {
        let err = derive_network_config(&TunnelRuntimeConfig {
            session: TunnelSessionConfig {
                maximum_frame_size: 512,
                ..runtime_config().session
            },
            ..runtime_config()
        })
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("smaller than the minimum tunnel MTU"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_worker_config_json_matches_expected_contract() {
        let listener = NetworkTunnelListener::Uds(PathBuf::from("/run/mvm/vsock/5302.sock"));
        let audit = Path::new("/run/mvm/network-tunnel.audit.jsonl");
        let config =
            build_network_tunnel_worker_config_json(&listener, audit, &runtime_config(), None)
                .unwrap();
        assert_eq!(config["listener"]["kind"], "uds");
        assert_eq!(config["listener"]["path"], "/run/mvm/vsock/5302.sock");
        assert_eq!(
            config["audit_jsonl_path"],
            "/run/mvm/network-tunnel.audit.jsonl"
        );
        assert_eq!(config["worker"]["packet_policy"]["kind"], "drop_all");
        assert_eq!(config["worker"]["initial_credit"]["bytes"], 4096);
        assert_eq!(config["worker"]["initial_credit"]["packets"], 1024);
        assert_eq!(
            config["worker"]["network_config"]["interface_name"],
            "mvm-net0"
        );
        assert_eq!(config["worker"]["expected_session"]["vm_id"], "vm-1");
        assert_eq!(
            config["worker"]["expected_session"]["accepted_features"]["ipv4"],
            true
        );
    }

    #[test]
    fn build_worker_config_json_supports_vsock_listener_contract() {
        let listener = NetworkTunnelListener::Vsock(5302);
        let audit = Path::new("/run/mvm/network-tunnel.audit.jsonl");
        let config =
            build_network_tunnel_worker_config_json(&listener, audit, &runtime_config(), None)
                .unwrap();
        assert_eq!(config["listener"]["kind"], "vsock");
        assert_eq!(config["listener"]["port"], 5302);
    }

    #[test]
    fn build_worker_config_json_supports_host_tun_packet_policy() {
        let listener = NetworkTunnelListener::Vsock(5302);
        let audit = Path::new("/run/mvm/network-tunnel.audit.jsonl");
        let config = build_network_tunnel_worker_config_json(
            &listener,
            audit,
            &runtime_config(),
            Some("mvmht0"),
        )
        .unwrap();
        assert_eq!(config["worker"]["packet_policy"]["kind"], "host_tun");
        assert_eq!(
            config["worker"]["packet_policy"]["interface_name"],
            "mvmht0"
        );
    }
}
