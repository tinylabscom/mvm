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
use mvm_core::policy::dns_pin::{DnsPinRegistry, resolve_network_policy_pins};
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::protocol::network_tunnel::{
    MAX_FRAME_PAYLOAD_LEN, MIN_TUNNEL_MTU, NETWORK_TUNNEL_GUEST_PORT, TunnelFeatures,
    TunnelNetworkConfig, TunnelRuntimeConfig, TunnelSessionConfig,
};

use crate::aux_bin::{self, AuxBin};
use crate::broker_services_spawn::{
    kill, pid_alive, read_pid, spawn_detached_with_config, wait_for_uds,
};

/// Negotiated frame size a launched workload tunnel requests. Bounded well under
/// [`MAX_FRAME_PAYLOAD_LEN`] and above [`MIN_TUNNEL_MTU`]; the guest MTU is
/// clamped down to a routable value from this in [`derive_network_config`].
const LAUNCH_TUNNEL_FRAME_SIZE: u32 = 4096;

/// Fixed prefix for a per-VM host TUN interface name. Kept short so the derived
/// name stays under `IFNAMSIZ` (16, so ≤15 usable bytes).
const HOST_TUN_IFACE_PREFIX: &str = "mvmt";

pub const NETWORK_TUNNEL_WORKER_PID_FILE: &str = "network-tunnel-worker.pid";
pub const NETWORK_TUNNEL_AUDIT_JSONL: &str = "network-tunnel.audit.jsonl";
/// Records the per-VM host TUN interface the worker installed a NAT table for.
/// Persisted at spawn so a later reap — including one after a SIGKILLed worker
/// that never ran its own teardown — can remove the leaked NAT table without
/// re-deriving the name from the VM.
pub const NETWORK_TUNNEL_HOST_IFACE_FILE: &str = "network-tunnel-host-iface";
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
    /// The VM's resolved egress policy. An admitted allow-list (≥1 host rule)
    /// makes the worker an L3 forwarder: the policy's hosts are resolved to an
    /// admission `DnsPinRegistry` and admitted packets forward out a per-VM host
    /// TUN. Deny-all / unrestricted / absent leaves the worker a `drop_all`
    /// default-deny gate.
    pub network_policy: Option<&'a NetworkPolicy>,
    /// Per-VM name the host TUN interface name is derived from. Only consulted
    /// when the policy selects the L3-forward path.
    pub vm_name: &'a str,
}

/// The concrete packet policy the worker is told to enforce, resolved from the
/// launch's egress policy. Owns its data so the JSON assembly borrows from one
/// value instead of threading a registry through every call.
enum WorkerPacketPolicy {
    /// Default-deny: inspect and drop every guest packet.
    DropAll,
    /// Relay every guest packet out a named host TUN, ungated. Retained so the
    /// spawn layer can still emit the worker's ungated `host_tun` contract; the
    /// admitted launch path always resolves to `DropAll` or `L3Forward`.
    #[allow(dead_code)]
    HostTun { interface_name: String },
    /// Gate each guest packet against the admitted policy + pins; forward only
    /// admitted packets out the per-VM host TUN.
    L3Forward {
        policy: NetworkPolicy,
        pins: DnsPinRegistry,
        interface_name: String,
    },
}

/// Choose the worker's packet policy from the launch's egress policy. An
/// admitted allow-list (≥1 concrete host rule) resolves its hosts to pins and
/// selects the L3-forward path out a per-VM host TUN. Every other policy
/// (deny-all, unrestricted, absent) fails closed to `drop_all` — an unrestricted
/// allow-all can't be expressed as a finite pin set, so it never widens the gate.
fn worker_packet_policy(
    network_policy: Option<&NetworkPolicy>,
    vm_name: &str,
) -> WorkerPacketPolicy {
    match network_policy {
        Some(policy)
            if policy
                .resolve_rules()
                .is_some_and(|rules| !rules.is_empty()) =>
        {
            WorkerPacketPolicy::L3Forward {
                pins: resolve_network_policy_pins(policy),
                policy: policy.clone(),
                interface_name: host_tun_interface_name(vm_name),
            }
        }
        _ => WorkerPacketPolicy::DropAll,
    }
}

impl WorkerPacketPolicy {
    /// The per-VM host TUN interface whose NAT table must be reaped if this
    /// worker is orphaned. Only the L3-forward path installs a NAT table, so
    /// only it names an interface to sweep.
    fn nat_interface_name(&self) -> Option<&str> {
        match self {
            WorkerPacketPolicy::L3Forward { interface_name, .. } => Some(interface_name),
            _ => None,
        }
    }
}

/// Derive a stable, `IFNAMSIZ`-valid (≤15 bytes), per-VM host TUN interface
/// name. A fixed prefix plus 40 bits of a deterministic hash of the VM name
/// keeps distinct VMs from colliding while staying within the kernel's cap and
/// the `[A-Za-z0-9_.-]` charset the tunnel worker validates.
pub(crate) fn host_tun_interface_name(vm_name: &str) -> String {
    use std::hash::{Hash, Hasher};
    // `DefaultHasher::new()` seeds with fixed keys, so the name is stable across
    // processes for the same VM (setup/teardown key on it identically).
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    vm_name.hash(&mut hasher);
    // 10 hex digits = 40 bits; prefix(4) + 10 = 14 bytes, under IFNAMSIZ.
    format!(
        "{HOST_TUN_IFACE_PREFIX}{:010x}",
        hasher.finish() & 0x00ff_ffff_ffff
    )
}

/// Launch-time identity for a workload's packet tunnel. `tenant_id` + `vm_id`
/// come from the admitted launch config; `boot_id` + `session_nonce` are minted
/// fresh per boot by the caller and stored once on the launch config so the
/// guest cmdline and the host worker validate against identical values.
pub struct TunnelLaunchIdentity {
    pub tenant_id: String,
    pub vm_id: String,
    pub boot_id: String,
    pub session_nonce: String,
}

/// Derive the packet-tunnel runtime config for a workload launch from its
/// resolved egress policy. Returns `Some` only for an admitted allow-list
/// (≥1 concrete host rule) — the sole posture the raw-L3 forwarding gate can
/// express; deny-all and unrestricted return `None` (no forwarding tunnel).
/// The returned config requests the `ipv4` + `audit_stream` features.
pub fn network_tunnel_for_launch(
    policy: &NetworkPolicy,
    identity: TunnelLaunchIdentity,
) -> Option<TunnelRuntimeConfig> {
    if policy.resolve_rules().is_none_or(|rules| rules.is_empty()) {
        return None;
    }
    Some(TunnelRuntimeConfig {
        guest_port: NETWORK_TUNNEL_GUEST_PORT,
        session: TunnelSessionConfig {
            tenant_id: identity.tenant_id,
            vm_id: identity.vm_id,
            boot_id: identity.boot_id,
            session_nonce: identity.session_nonce,
            requested_features: TunnelFeatures {
                ipv4: true,
                audit_stream: true,
                ..TunnelFeatures::default()
            },
            maximum_frame_size: LAUNCH_TUNNEL_FRAME_SIZE,
        },
    })
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

    let packet_policy = worker_packet_policy(params.network_policy, params.vm_name);
    let config_json = build_network_tunnel_worker_config_json(
        &listener,
        &audit_jsonl_path,
        runtime_config,
        &packet_policy,
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
    // Persist the NAT interface so reap can remove a leaked table if the worker
    // is SIGKILLed before its own teardown runs.
    if let Some(iface) = packet_policy.nat_interface_name() {
        let iface_file = state_dir.join(NETWORK_TUNNEL_HOST_IFACE_FILE);
        std::fs::write(&iface_file, iface)
            .map_err(|e| anyhow!("write {}: {e}", iface_file.display()))?;
    }
    Ok(guard)
}

fn build_network_tunnel_worker_config_json(
    listener: &NetworkTunnelListener,
    audit_jsonl_path: &Path,
    runtime_config: &TunnelRuntimeConfig,
    packet_policy: &WorkerPacketPolicy,
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
            "packet_policy": packet_policy_json(packet_policy),
            "limits": {
                "max_packets": 1024_u64,
                "max_bytes": 8_u64 * 1024 * 1024,
            }
        }
    }))
}

/// The worker's `TunnelPacketPolicy` wire shape. Hand-built (the worker's typed
/// `TunnelPacketPolicy` lives in `mvm-hostd`, above this crate) so it must match
/// that enum's serde exactly: the L3-forward gate serializes as
/// `{"gate": {"policy": .., "pins": ..}, "interface_name": ..}`.
fn packet_policy_json(policy: &WorkerPacketPolicy) -> serde_json::Value {
    match policy {
        WorkerPacketPolicy::DropAll => serde_json::json!({ "kind": "drop_all" }),
        WorkerPacketPolicy::HostTun { interface_name } => {
            serde_json::json!({ "kind": "host_tun", "interface_name": interface_name })
        }
        WorkerPacketPolicy::L3Forward {
            policy,
            pins,
            interface_name,
        } => serde_json::json!({
            "kind": "l3_forward",
            "gate": { "policy": policy, "pins": pins },
            "interface_name": interface_name,
        }),
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
        // Seam: the admission pins aren't threaded into this backend spawn path
        // yet (it only builds drop_all / host_tun policies, which carry no pin
        // registry). When this path grows an l3_forward policy, the host worker
        // fills host_entries from that policy's pins in `HostTunnelWorker::new`.
        host_entries: Vec::new(),
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
    // Remove a NAT table a SIGKILLed / orphaned worker could not tear down. The
    // interface name was persisted at spawn; a missing file means no NAT to
    // reap (drop-all workers install none).
    let iface_file = state_dir.join(NETWORK_TUNNEL_HOST_IFACE_FILE);
    if let Ok(iface) = std::fs::read_to_string(&iface_file) {
        let iface = iface.trim();
        if !iface.is_empty() {
            remove_leaked_nat_table(iface);
        }
    }
    let _ = std::fs::remove_file(&iface_file);
    let _ = std::fs::remove_file(&pid_file);
    let _ = std::fs::remove_file(state_dir.join(NETWORK_TUNNEL_AUDIT_JSONL));
}

/// Compose the argv that removes a leaked per-VM NAT table. Pure so the reap
/// wiring is unit-testable without invoking nft. The table name is the shared
/// source of truth both the host worker (setup/teardown) and this reap derive,
/// so the two can never drift.
fn nft_delete_nat_table_argv(interface_name: &str) -> Vec<String> {
    let table = mvm_core::protocol::network_tunnel::host_tun_nat_table_name(interface_name);
    vec![
        "nft".to_string(),
        "delete".to_string(),
        "table".to_string(),
        "ip".to_string(),
        table,
    ]
}

/// Best-effort removal of a leaked per-VM NAT table. The argv is composed on
/// every platform (keeping the pure composition exercised) but only executed on
/// Linux. The delete is idempotent: a missing table just fails and is ignored,
/// so the reap never errors on a double sweep.
fn remove_leaked_nat_table(interface_name: &str) {
    let argv = nft_delete_nat_table_argv(interface_name);
    exec_nft_delete(&argv);
}

#[cfg(target_os = "linux")]
fn exec_nft_delete(argv: &[String]) {
    let _ = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status();
}

#[cfg(not(target_os = "linux"))]
fn exec_nft_delete(_argv: &[String]) {}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
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
        let config = build_network_tunnel_worker_config_json(
            &listener,
            audit,
            &runtime_config(),
            &WorkerPacketPolicy::DropAll,
        )
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
        let config = build_network_tunnel_worker_config_json(
            &listener,
            audit,
            &runtime_config(),
            &WorkerPacketPolicy::DropAll,
        )
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
            &WorkerPacketPolicy::HostTun {
                interface_name: "mvmht0".to_string(),
            },
        )
        .unwrap();
        assert_eq!(config["worker"]["packet_policy"]["kind"], "host_tun");
        assert_eq!(
            config["worker"]["packet_policy"]["interface_name"],
            "mvmht0"
        );
    }

    /// An allow-list policy resolves to an `l3_forward` worker policy carrying
    /// the policy + resolved pins + a per-VM host TUN interface name. Uses a
    /// literal-IP allow-list so pin resolution needs no live DNS.
    #[test]
    fn worker_config_json_is_l3_forward_with_policy_and_pins() {
        let listener = NetworkTunnelListener::Vsock(5302);
        let audit = Path::new("/run/mvm/network-tunnel.audit.jsonl");
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("93.184.216.34", 443)]);
        let packet_policy = worker_packet_policy(Some(&policy), "vm-1");
        let config = build_network_tunnel_worker_config_json(
            &listener,
            audit,
            &runtime_config(),
            &packet_policy,
        )
        .unwrap();

        let pp = &config["worker"]["packet_policy"];
        assert_eq!(pp["kind"], "l3_forward");
        // The gate carries the admitted policy and its resolved pins.
        assert!(pp["gate"]["policy"].is_object());
        assert_eq!(
            pp["gate"]["pins"]["pins"]["93.184.216.34"]["ips"][0],
            "93.184.216.34"
        );
        // The per-VM host TUN interface name is present + IFNAMSIZ-valid.
        let iface = pp["interface_name"]
            .as_str()
            .expect("interface_name string");
        assert!(iface.starts_with(HOST_TUN_IFACE_PREFIX));
        assert!(iface.len() <= 15, "iface {iface:?} must fit IFNAMSIZ");
    }

    #[test]
    fn worker_packet_policy_defaults_closed_for_deny_all_and_unrestricted() {
        assert!(matches!(
            worker_packet_policy(Some(&NetworkPolicy::deny_all()), "vm-1"),
            WorkerPacketPolicy::DropAll
        ));
        assert!(matches!(
            worker_packet_policy(Some(&NetworkPolicy::unrestricted()), "vm-1"),
            WorkerPacketPolicy::DropAll
        ));
        assert!(matches!(
            worker_packet_policy(None, "vm-1"),
            WorkerPacketPolicy::DropAll
        ));
    }

    #[test]
    fn reap_removes_leaked_nat_table() {
        // The reap sweep composes the exact idempotent nft delete argv from the
        // per-VM interface name, using the shared table-name source of truth.
        let iface = host_tun_interface_name("workload-alpha");
        let expected_table = mvm_core::protocol::network_tunnel::host_tun_nat_table_name(&iface);
        assert_eq!(
            nft_delete_nat_table_argv(&iface),
            vec![
                "nft".to_string(),
                "delete".to_string(),
                "table".to_string(),
                "ip".to_string(),
                expected_table.clone(),
            ]
        );
        assert!(expected_table.starts_with("mvm_tun_nat_"));
    }

    #[test]
    fn reap_clears_persisted_iface_file() {
        // Reap consumes the persisted interface file (best-effort NAT sweep) and
        // removes it so a re-reap is a clean no-op. nft exec is a no-op off Linux.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp =
            std::env::temp_dir().join(format!("mvm-tun-reap-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&tmp).expect("create temp state dir");
        let iface_file = tmp.join(NETWORK_TUNNEL_HOST_IFACE_FILE);
        std::fs::write(&iface_file, host_tun_interface_name("workload-alpha"))
            .expect("write iface file");

        reap_network_tunnel_worker(&tmp);
        assert!(
            !iface_file.exists(),
            "reap must remove the persisted iface file"
        );
        // A second reap on the now-clean dir must not panic.
        reap_network_tunnel_worker(&tmp);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn drop_all_policy_names_no_nat_interface() {
        // Only the L3-forward path installs a NAT table, so drop-all persists no
        // interface and reap has nothing to sweep.
        assert!(
            worker_packet_policy(Some(&NetworkPolicy::deny_all()), "vm-1")
                .nat_interface_name()
                .is_none()
        );
        let l3 = worker_packet_policy(
            Some(&NetworkPolicy::allow_list(vec![HostPort::new(
                "93.184.216.34",
                443,
            )])),
            "vm-1",
        );
        assert!(l3.nat_interface_name().is_some());
    }

    #[test]
    fn host_tun_interface_name_is_stable_and_ifnamsiz_valid() {
        let a = host_tun_interface_name("workload-alpha");
        let b = host_tun_interface_name("workload-alpha");
        let c = host_tun_interface_name("workload-beta");
        assert_eq!(a, b, "same VM name → same interface name");
        assert_ne!(a, c, "distinct VM names → distinct interface names");
        assert!(a.starts_with(HOST_TUN_IFACE_PREFIX));
        assert!(a.len() <= 15);
        assert!(
            a.bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'.' || ch == b'-' || ch == b'_')
        );
    }

    /// An admitted allow-list launch carries a forwarding tunnel with the plan's
    /// identity and the `ipv4` + `audit_stream` features.
    #[test]
    fn allowlist_policy_launch_config_carries_network_tunnel() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("93.184.216.34", 443)]);
        let tunnel = network_tunnel_for_launch(
            &policy,
            TunnelLaunchIdentity {
                tenant_id: "acme".to_string(),
                vm_id: "vm-9".to_string(),
                boot_id: "boot-9".to_string(),
                session_nonce: "nonce-9".to_string(),
            },
        )
        .expect("allow-list launch carries a forwarding tunnel");
        tunnel.validate().expect("derived tunnel config is valid");
        assert_eq!(tunnel.session.tenant_id, "acme");
        assert_eq!(tunnel.session.vm_id, "vm-9");
        assert_eq!(tunnel.session.boot_id, "boot-9");
        assert_eq!(tunnel.session.session_nonce, "nonce-9");
        assert!(tunnel.session.requested_features.ipv4);
        assert!(tunnel.session.requested_features.audit_stream);
    }

    #[test]
    fn deny_all_policy_launch_config_has_no_forwarding_tunnel() {
        let identity = || TunnelLaunchIdentity {
            tenant_id: "acme".to_string(),
            vm_id: "vm-9".to_string(),
            boot_id: "boot-9".to_string(),
            session_nonce: "nonce-9".to_string(),
        };
        // Deny-all and unrestricted both yield no forwarding tunnel: the raw-L3
        // gate admits only pinned IPs, so neither posture is expressible.
        assert!(network_tunnel_for_launch(&NetworkPolicy::deny_all(), identity()).is_none());
        assert!(network_tunnel_for_launch(&NetworkPolicy::unrestricted(), identity()).is_none());
    }

    #[test]
    fn l3_forward_worker_policy_carries_the_admission_pins() {
        // The resolved gate must pin exactly the admitted destination.
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("93.184.216.34", 443)]);
        let WorkerPacketPolicy::L3Forward { pins, policy, .. } =
            worker_packet_policy(Some(&policy), "vm-1")
        else {
            panic!("an allow-list policy must resolve to an L3-forward worker policy");
        };
        let pin = pins.lookup("93.184.216.34").expect("host is pinned");
        assert_eq!(
            pin.ips,
            vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(policy.allows_egress());
    }
}
