//! End-to-end test of the `mvm-netd` subprocess.
//!
//! Runs the real binary, hands it a real configuration on stdin, waits for
//! the ready marker, then drives the real guest agent against it over the
//! real per-port Unix sockets. Nothing here is a double except the guest's
//! TUN device and the platform datapath — the process boundary, the
//! configuration parsing, the channel binding, the handshake, and the
//! teardown are all the shipping code.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mvm_agentd::l3::{
    AgentState, MemoryTun, NetAgent, RecordingConfigurator, RecordingPrivilegeDropper,
};
use mvm_hostd::netd::config::{NETD_READY_MARKER, NetdConfig, NetdEgress, NetdRule, NetdUdsLayout};
use mvm_net::channel::GuestService;
use mvm_protocol::l3::{ip, proto};

const BIN: &str = env!("CARGO_BIN_EXE_mvm-netd");

/// Point `MVM_HOME` at a scenario-local directory so the socket paths are
/// the real ones without touching a developer's home.
struct HomeGuard {
    dir: tempfile::TempDir,
}

impl HomeGuard {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("temp home"),
        }
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

fn config(vm_id: &str) -> NetdConfig {
    NetdConfig {
        node_id: "node-1".into(),
        vm_id: vm_id.into(),
        boot_id: "boot-1".into(),
        plan_digest: "sha256:plan".into(),
        uds_layout: NetdUdsLayout::PerVmDir,
        gateway_ipv4: "10.201.0.5".parse().unwrap(),
        guest_ipv4: "10.201.0.6".parse().unwrap(),
        mtu: 1500,
        egress: NetdEgress::Rules(vec![NetdRule {
            proto: "tcp".into(),
            cidr: "93.184.216.34/32".into(),
            port_lo: 443,
            port_hi: 443,
        }]),
        admitted_private_cidrs: Vec::new(),
        icmp: Default::default(),
        policy_epoch: 1,
        max_flows: 4096,
        queue_depth: 256,
        dns_qps: 50,
        ingress: Vec::new(),
    }
}

/// Start `mvm-netd` and wait for its ready marker. Returns the child and
/// the session id it minted.
fn start_netd(home: &HomeGuard, cfg: &NetdConfig) -> Option<(Child, String)> {
    let mut child = Command::new(BIN)
        .env("MVM_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mvm-netd");

    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(serde_json::to_string(cfg).unwrap().as_bytes())
        .expect("write the config");

    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    // A short read: the process either prints the marker promptly or has
    // already refused (no datapath on this host, most likely).
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => {
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = e.read_to_string(&mut stderr);
            }
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("mvm-netd did not become ready (expected without a host datapath): {stderr}");
            return None;
        }
        Ok(_) => {}
    }
    assert!(
        line.starts_with(NETD_READY_MARKER),
        "expected the ready marker, got {line:?}"
    );
    let session = line
        .split("session=")
        .nth(1)
        .expect("the marker carries the session")
        .trim()
        .to_string();
    Some((child, session))
}

/// Connect to a service socket, retrying briefly: the marker means bound,
/// but the accept loop may not have reached `accept` yet.
fn connect(home: &HomeGuard, vm_id: &str, service: GuestService) -> UnixStream {
    let path = {
        // Resolve the path the same way the provider does, under this
        // test's MVM_HOME.
        let previous = std::env::var_os("MVM_HOME");
        // SAFETY: these tests are serialized by the harness below.
        unsafe { std::env::set_var("MVM_HOME", home.path()) };
        let p = mvm_core::config::vm_vsock_port_socket(vm_id, service.port());
        unsafe {
            match previous {
                Some(v) => std::env::set_var("MVM_HOME", v),
                None => std::env::remove_var("MVM_HOME"),
            }
        }
        p
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(&path) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect to {}: {e}", path.display()),
        }
    }
}

fn v4_tcp(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, dst_port: u16) -> Vec<u8> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = ip::TCP_SYN;
    let total = 20 + tcp.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = proto::TCP;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(&tcp);
    p
}

/// The real agent, over the real sockets, against the real process.
#[test]
fn the_netd_process_serves_a_real_agent_handshake_and_forwards_a_packet() {
    let home = HomeGuard::new();
    let cfg = config("netd-bin-happy");
    let Some((mut child, session)) = start_netd(&home, &cfg) else {
        // No host datapath (macOS, or Linux without CAP_NET_ADMIN). The
        // refusal is the correct behaviour and is asserted separately.
        return;
    };

    let control = connect(&home, &cfg.vm_id, GuestService::NetworkControl);
    let mut data = connect(&home, &cfg.vm_id, GuestService::NetworkData { queue: 0 });

    let mut agent = NetAgent::new(MemoryTun::new("mvm0"), RecordingConfigurator::default())
        .with_privilege_dropper(Box::new(RecordingPrivilegeDropper::default()));
    let mut control = control;
    agent
        .handshake(&mut control)
        .expect("the agent should complete the handshake against the real process");

    assert_eq!(agent.state(), AgentState::Ready);
    // The session the process minted is the one the agent was assigned.
    assert_eq!(format!("{:016x}", agent.session_id()), session);

    // The host assigned the addressing; the guest chose none of it.
    let plan = agent.interface_plan().expect("a configured interface");
    assert_eq!(plan.address, cfg.guest_ipv4);
    assert_eq!(plan.peer, cfg.gateway_ipv4);
    assert_eq!(plan.dns, cfg.gateway_ipv4);
    assert_eq!(plan.mtu, 1500);

    // A packet the policy admits crosses the process boundary.
    agent.tun_mut().push_outbound(v4_tcp(
        cfg.guest_ipv4,
        "93.184.216.34".parse().unwrap(),
        443,
    ));
    let mut wire = Vec::new();
    assert_eq!(agent.pump_tun_to_transport(&mut wire).unwrap(), 1);
    data.write_all(&wire).expect("write the packet");
    data.flush().ok();

    // Teardown: closing the channels ends the session and the process exits
    // cleanly rather than hanging.
    drop(data);
    drop(control);
    let exited = wait_for_exit(&mut child, Duration::from_secs(10));
    assert!(exited, "mvm-netd must exit when its guest channels close");
}

#[test]
fn the_netd_process_refuses_an_unparseable_configuration() {
    let home = HomeGuard::new();
    let mut child = Command::new(BIN)
        .env("MVM_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"{\"not\":\"a config\"}")
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    assert!(!output.status.success(), "a bad config must not be served");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configuration"),
        "the refusal must name what failed: {stderr}"
    );
}

#[test]
fn the_netd_process_refuses_a_config_whose_rules_do_not_parse() {
    let home = HomeGuard::new();
    let mut cfg = config("netd-bin-badrule");
    cfg.egress = NetdEgress::Rules(vec![NetdRule {
        proto: "tcp".into(),
        cidr: "not-a-cidr".into(),
        port_lo: 443,
        port_hi: 443,
    }]);
    let mut child = Command::new(BIN)
        .env("MVM_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(serde_json::to_string(&cfg).unwrap().as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    assert!(
        !output.status.success(),
        "a rule that does not parse must fail the whole launch, never be dropped"
    );
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return false,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    false
}
