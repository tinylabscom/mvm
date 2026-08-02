//! `mvm-netd` — the per-VM L3 tunnel gateway, as a process.
//!
//! One instance per machine boot. Reads its already-admitted configuration
//! on stdin, binds the network control and data guest channels, prints a
//! ready marker so the launch path can start the VM without racing the
//! guest, then serves the tunnel until the machine stops.
//!
//! It is a separate process for the same reason the broker and the
//! substitution endpoint are: it handles bytes a hostile guest controls, so
//! it gets its own address space and its own failure domain. A crash here
//! takes networking down — fail-closed — and nothing else.

use std::io::{BufWriter, Read, Write};

use anyhow::{Context, Result, anyhow};
use mvm_hostd::netd::config::{NETD_READY_MARKER, NetdConfig, NetdUdsLayout};
use mvm_hostd::netd::{
    Gateway, GatewayConfig, GatewayEvent, GatewayState, StaticResolver, UdsGuestChannelProvider,
    host_datapath,
};
use mvm_net::channel::{GuestChannelProvider, GuestService};
use mvm_net::l3::{DnsLimits, FlowLimits};

fn main() {
    if let Err(err) = run() {
        eprintln!("mvm-netd: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .context("reading the netd configuration from stdin")?;
    let config: NetdConfig =
        serde_json::from_str(&raw).context("parsing the netd configuration")?;

    let instance = config.instance();
    let provider = match config.uds_layout {
        NetdUdsLayout::PerVmDir => UdsGuestChannelProvider::per_vm_dir("per-vm-uds"),
        NetdUdsLayout::HvfVsockDir => UdsGuestChannelProvider::hvf(),
    };

    // Bind before anything else: the guest dials as soon as it boots, and
    // the launch path waits on the ready marker below before starting it.
    let mut control = provider
        .bind_service(&instance, GuestService::NetworkControl)
        .with_context(|| format!("binding the network control channel for {}", instance.vm_id))?;
    let mut data = provider
        .bind_service(&instance, GuestService::NetworkData { queue: 0 })
        .with_context(|| format!("binding the network data channel for {}", instance.vm_id))?;

    // The datapath is checked before the ready marker, so an unserveable
    // platform refuses the launch rather than letting the VM boot into a
    // tunnel that will never carry a packet.
    let datapath = host_datapath();
    datapath
        .is_available()
        .map_err(|e| anyhow!("this host cannot serve the l3-vsock datapath: {e}"))?;

    let policy = config.to_policy().context("lowering the network policy")?;
    let ingress = config
        .to_ingress_table()
        .context("lowering the declared ingress mappings")?;

    let mut gateway_config = GatewayConfig::new(
        config.vm_id.clone(),
        config.plan_digest.clone(),
        config.lease(),
        policy,
    );
    gateway_config.instance = instance.clone();
    gateway_config.ingress = ingress;
    gateway_config.queue_depth = config.queue_depth;
    gateway_config.dns_qps = config.dns_qps;
    gateway_config.flow_limits = FlowLimits {
        max_flows: config.max_flows,
        ..FlowLimits::default()
    };
    gateway_config.dns_limits = DnsLimits::default();

    let session = mvm_net::l3::SessionId(mint_session_id(&instance));
    let resolver = std::sync::Arc::new(StaticResolver::new());
    let mut gateway = Gateway::open(gateway_config, session, datapath.as_ref(), resolver)
        .context("opening the gateway")?;

    // Both channels are bound and the gateway holds a datapath: it is now
    // safe to start the VM.
    {
        let stdout = std::io::stdout();
        let mut out = BufWriter::new(stdout.lock());
        writeln!(out, "{NETD_READY_MARKER} session={session}")
            .context("writing the ready marker")?;
        out.flush().context("flushing the ready marker")?;
    }

    // The guest opens control first, then data. Accepting in that order
    // matches the agent and keeps the handshake single-threaded.
    let mut control_conn = control
        .accept()
        .context("accepting the guest's control connection")?;
    let mut data_conn = data
        .accept()
        .context("accepting the guest's data connection")?;

    let result = serve(
        &mut gateway,
        &mut control_conn.stream,
        &mut data_conn.stream,
    );

    // Deterministic teardown on every exit path, including a protocol
    // violation or a dead guest.
    for event in gateway.close() {
        log_event(&event);
    }
    let _ = control.close();
    let _ = data.close();
    let _ = provider.revoke_instance(&instance);
    result
}

/// Drive the tunnel until either side finishes.
fn serve(
    gateway: &mut Gateway,
    control: &mut Box<dyn mvm_net::channel::GuestStream>,
    data: &mut Box<dyn mvm_net::channel::GuestStream>,
) -> Result<()> {
    let mut buf = vec![0u8; mvm_protocol::l3::MAX_WIRE_LEN];
    let start = std::time::Instant::now();

    // Handshake: HELLO on control, CONFIG back, then READY.
    loop {
        let n = control
            .read(&mut buf)
            .context("reading the control channel")?;
        if n == 0 {
            return Ok(());
        }
        let (reply, events) = gateway
            .handle_control_frame(&buf[..n], monotonic_millis(start))
            .context("handling a guest control frame")?;
        for event in &events {
            log_event(event);
        }
        if !reply.is_empty() {
            control
                .write_all(&reply)
                .context("writing the control reply")?;
            control.flush().ok();
        }
        if gateway.state() == GatewayState::Ready {
            break;
        }
        if gateway.state() == GatewayState::Closed {
            return Ok(());
        }
    }

    // Steady state. Reads are blocking and alternate between the data
    // channel and whatever the datapath has for the guest; a production
    // deployment would poll both, which is the obvious next refinement.
    loop {
        let n = match data.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err).context("reading the data channel"),
        };
        let now = monotonic_millis(start);
        match gateway.ingest_data_bytes(&buf[..n], now) {
            Ok(events) => {
                for event in &events {
                    log_event(event);
                }
            }
            Err(err) => {
                // A protocol violation ends the session; it does not take
                // the host down.
                eprintln!("mvm-netd: dropping the tunnel: {err}");
                return Ok(());
            }
        }
        for event in gateway.poll_inbound(now) {
            log_event(&event);
        }
        for frame in gateway.take_guest_frames() {
            data.write_all(&frame).context("writing to the guest")?;
        }
        data.flush().ok();
        gateway.tick(now);
    }
}

/// Milliseconds since the process's reference instant.
///
/// A monotonic source: it cannot jump backwards when the host's wall
/// clock is corrected, which would otherwise make an idle flow look
/// arbitrarily young and defer its expiry.
fn monotonic_millis(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Per-*decision-class* logging. Never a line per packet: the gateway's
/// counters carry volume, and a log line a guest can trigger at line rate
/// is itself a denial of service.
fn log_event(event: &GatewayEvent) {
    match event {
        GatewayEvent::TunnelReady { session } => {
            eprintln!("mvm-netd: tunnel ready, session={session}");
        }
        GatewayEvent::CleanedUp { session } => {
            eprintln!("mvm-netd: session={session} torn down");
        }
        GatewayEvent::MalformedFrame { detail } => {
            eprintln!("mvm-netd: malformed frame: {detail}");
        }
        GatewayEvent::StaleSession => eprintln!("mvm-netd: dropped a stale-session frame"),
        GatewayEvent::DnsDenied { name, reason } => {
            eprintln!("mvm-netd: dns denied name={name} reason={reason}");
        }
        // Admitted flows, denied packets, deliveries, and queue drops are
        // counters, not log lines.
        _ => {}
    }
}

/// Derive a per-boot session id from the host-owned identity.
///
/// The identity already contains a fresh boot id, so hashing it yields a
/// value that is distinct per boot without needing an entropy source in
/// this process. It is a binding check, not a secret.
fn mint_session_id(instance: &mvm_net::channel::VmInstanceIdentity) -> u64 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(instance.node_id.as_bytes());
    hasher.update(b"/");
    hasher.update(instance.vm_id.as_bytes());
    hasher.update(b"@");
    hasher.update(instance.boot_id.as_bytes());
    hasher.update(b"#");
    hasher.update(instance.plan_digest.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let id = u64::from_be_bytes(bytes);
    // Zero is reserved on the wire for "no session yet".
    if id == 0 { 1 } else { id }
}
