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
use std::os::fd::RawFd;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mvm_hostd::netd::config::{NETD_READY_MARKER, NetdConfig, NetdUdsLayout};
use mvm_hostd::netd::{
    Gateway, GatewayConfig, GatewayError, GatewayEvent, GatewayState, StaticResolver,
    UdsGuestChannelProvider, select_host_datapath,
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
    let selection = select_host_datapath();
    selection
        .datapath
        .is_available()
        .map_err(|e| anyhow!("this host cannot serve the l3-vsock datapath: {e}"))?;
    // Logged before anything can refuse for a capability the fallback does
    // not carry, so the substitution is already in the log when the refusal
    // names its consequence.
    if let Some(reason) = &selection.fallback_reason {
        eprintln!("mvm-netd: {reason}");
    }

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
    let mut gateway = Gateway::open(
        gateway_config,
        session,
        selection.datapath.as_ref(),
        resolver,
    )
    .map_err(|err| explain_open_failure(err, selection.fallback_reason.as_deref()))?;

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

    // Fail closed rather than fall back to a blocking read: a transport
    // whose data channel cannot be polled cannot carry inbound traffic to a
    // quiet guest, and a tunnel that only works while the guest talks is
    // worse than one that refuses.
    let data_fd = data_conn.pollable_fd.ok_or_else(|| {
        anyhow!("the guest data channel exposes no descriptor the drive loop can poll")
    })?;

    let start = std::time::Instant::now();
    let result = serve(
        &mut gateway,
        &mut *control_conn.stream,
        &mut *data_conn.stream,
        data_fd,
        &|| monotonic_millis(start),
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

/// Attach the datapath fallback reason to a failure to open the gateway.
///
/// A capability shortfall states what the plan asked for and did not get,
/// which is true and useless on its own: `missing: ["icmp"]` describes a
/// symptom of a substitution the operator was never told about. Whatever
/// caused the fallback goes in the same message as what it cost.
fn explain_open_failure(err: GatewayError, fallback: Option<&str>) -> anyhow::Error {
    match fallback {
        Some(reason) => anyhow!("opening the gateway: {err}\n{reason}"),
        None => anyhow!("opening the gateway: {err}"),
    }
}

/// How long a poll waits before servicing the tunnel anyway.
///
/// The floor on progress, not a latency budget: a datapath with nothing to
/// poll advances only on this tick, and idle flows, DNS bindings, and
/// transport timers must age on elapsed time rather than on the guest
/// happening to transmit.
const TICK_MILLIS: libc::c_int = 50;
const TICK: Duration = Duration::from_millis(TICK_MILLIS as u64);

const GUEST_DATA: mio::Token = mio::Token(0);
const DATAPATH: mio::Token = mio::Token(1);

/// Reads of the guest data channel per readiness pass.
///
/// A guest that streams without pause must not be able to hold the loop
/// inside the drain and starve the datapath and the expiry tick — that is
/// the same starvation this loop exists to remove, pointed the other way.
const MAX_GUEST_READS_PER_PASS: usize = 32;

/// How long the guest may leave the data channel with no room before the
/// tunnel is dropped.
///
/// Measured from the last byte the guest actually accepted, so a slow guest
/// that keeps draining is never penalised; only one that has stopped
/// entirely trips it. Generous against the agent, which polls its own data
/// socket on a one-second timeout and always drains what it finds.
const WRITE_STALL_DEADLINE: Duration = Duration::from_secs(10);

/// Whether the tunnel is still carrying traffic.
#[derive(Debug, PartialEq, Eq)]
enum Session {
    Live,
    Ended,
}

/// What a wait for room on the guest data channel observed.
#[derive(Debug, PartialEq, Eq)]
enum Writability {
    /// There is room now.
    Ready,
    /// The tick expired with no room. Says nothing about the guest's health.
    TimedOut,
    /// The guest end is closed or errored.
    PeerGone,
}

/// What became of a frame handed to the guest.
#[derive(Debug, PartialEq, Eq)]
enum Delivery {
    Sent,
    /// The guest is gone, or has stopped reading for long enough to count as
    /// gone. Either way the session is over.
    GuestGone,
}

/// What a drain of the guest data channel concluded.
#[derive(Debug, PartialEq, Eq)]
enum GuestChannel {
    /// Nothing further to read right now.
    Idle,
    /// The read budget ran out with bytes still waiting.
    Backlogged,
    /// End of stream, or a protocol violation.
    Ended,
}

/// Drive the tunnel until either side finishes.
///
/// `clock` supplies milliseconds. It is a parameter rather than a read of
/// `Instant` inside the loop so that everything time-driven here is a
/// function of the caller's inputs, and a test can advance time without
/// waiting for it.
fn serve(
    gateway: &mut Gateway,
    control: &mut dyn mvm_net::channel::GuestStream,
    data: &mut dyn mvm_net::channel::GuestStream,
    data_fd: RawFd,
    clock: &dyn Fn() -> u64,
) -> Result<()> {
    if handshake(gateway, control, clock)? == Session::Ended {
        return Ok(());
    }
    pump(gateway, data, data_fd, clock)
}

/// HELLO on control, CONFIG back, then READY.
fn handshake(
    gateway: &mut Gateway,
    control: &mut dyn mvm_net::channel::GuestStream,
    clock: &dyn Fn() -> u64,
) -> Result<Session> {
    let mut buf = vec![0u8; mvm_protocol::l3::MAX_WIRE_LEN];
    loop {
        let n = control
            .read(&mut buf)
            .context("reading the control channel")?;
        if n == 0 {
            return Ok(Session::Ended);
        }
        let (reply, events) = gateway
            .handle_control_frame(&buf[..n], clock())
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
        match gateway.state() {
            GatewayState::Ready => return Ok(Session::Live),
            GatewayState::Closed => return Ok(Session::Ended),
            _ => {}
        }
    }
}

/// Steady state: wait until the guest channel or the datapath has work, or
/// the tick expires, then service both.
fn pump(
    gateway: &mut Gateway,
    data: &mut dyn mvm_net::channel::GuestStream,
    data_fd: RawFd,
    clock: &dyn Fn() -> u64,
) -> Result<()> {
    // A readiness-driven read must not block: the whole point is that the
    // loop stays free to service the datapath.
    set_nonblocking(data_fd).context("setting the guest data channel non-blocking")?;

    let mut poll = mio::Poll::new().context("creating the poll set")?;
    let mut events = mio::Events::with_capacity(8);
    poll.registry()
        .register(
            &mut mio::unix::SourceFd(&data_fd),
            GUEST_DATA,
            mio::Interest::READABLE,
        )
        .context("registering the guest data channel")?;

    // Read once, here, while the handle is certainly open. The loop never
    // re-reads it, so it cannot register a descriptor that a close has
    // already released, and it hands back exactly what it registered.
    let datapath_fd = gateway.datapath().readiness_fd();
    if let Some(fd) = datapath_fd {
        poll.registry()
            .register(
                &mut mio::unix::SourceFd(&fd),
                DATAPATH,
                mio::Interest::READABLE,
            )
            .context("registering the datapath")?;
    }

    let outcome = drive(gateway, data, data_fd, &mut poll, &mut events, clock);

    // Deregister before the caller closes the gateway, which closes the
    // datapath handle. A registered descriptor that is then closed is a
    // hazard: the number is free for any later open in this process to
    // reuse, and the loop would start reacting to an unrelated resource.
    if let Some(fd) = datapath_fd {
        let _ = poll.registry().deregister(&mut mio::unix::SourceFd(&fd));
    }
    let _ = poll
        .registry()
        .deregister(&mut mio::unix::SourceFd(&data_fd));
    outcome
}

fn drive(
    gateway: &mut Gateway,
    data: &mut dyn mvm_net::channel::GuestStream,
    data_fd: RawFd,
    poll: &mut mio::Poll,
    events: &mut mio::Events,
    clock: &dyn Fn() -> u64,
) -> Result<()> {
    let mut buf = vec![0u8; mvm_protocol::l3::MAX_WIRE_LEN];
    // Set when the guest still has bytes waiting after its read budget ran
    // out, so the next pass does not wait on readiness that has already
    // been reported and will not be reported again.
    let mut backlogged = false;
    loop {
        let wait = if backlogged { Duration::ZERO } else { TICK };
        match poll.poll(events, Some(wait)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(err).context("polling the guest channel and the datapath");
            }
        }
        let now = clock();

        if backlogged || events.iter().any(|event| event.token() == GUEST_DATA) {
            match drain_guest_data(gateway, data, &mut buf, now)? {
                GuestChannel::Ended => return Ok(()),
                GuestChannel::Backlogged => backlogged = true,
                GuestChannel::Idle => backlogged = false,
            }
        }

        // Before the drain below, because this is what turns a connect the
        // kernel has decided into something there is anything to read: a
        // datapath that translates flows into host sockets advances only
        // when driven, and a guest whose handshake nothing completes waits
        // forever with no error to show for it.
        //
        // Fatal rather than counted. A datapath that cannot be serviced
        // cannot carry traffic, and carrying on would put the tunnel back
        // in the silent-hang state this call exists to remove.
        gateway
            .service_datapath(now)
            .context("servicing the datapath")?;

        // Unconditional, and deliberately not gated on a DATAPATH event: a
        // datapath that reports no descriptor makes progress only here, and
        // a transport's own timers have to be serviced whether or not
        // either side sent anything.
        for event in gateway.poll_inbound(now) {
            log_event(&event);
        }
        for frame in gateway.take_guest_frames() {
            let delivered = write_frame(data, data_fd, &frame, WRITE_STALL_DEADLINE)
                .context("writing to the guest")?;
            if delivered == Delivery::GuestGone {
                return Ok(());
            }
        }
        data.flush().ok();
        gateway.tick(now);
    }
}

/// Read what the guest has queued, up to the per-pass budget.
///
/// Readiness here is edge-triggered, so stopping at the first short read
/// would leave bytes sitting until an event that may never come. The budget
/// is reported back rather than silently dropped, so the caller comes
/// straight back instead of waiting on a readiness edge already spent.
fn drain_guest_data(
    gateway: &mut Gateway,
    data: &mut dyn mvm_net::channel::GuestStream,
    buf: &mut [u8],
    now: u64,
) -> Result<GuestChannel> {
    let mut reads = 0;
    while reads < MAX_GUEST_READS_PER_PASS {
        // Charged before the read, so a signal storm spends the budget the
        // same way traffic does and cannot spin here forever.
        reads += 1;
        let n = match data.read(buf) {
            Ok(0) => return Ok(GuestChannel::Ended),
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(GuestChannel::Idle);
            }
            Err(err) => return Err(err).context("reading the data channel"),
        };
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
                return Ok(GuestChannel::Ended);
            }
        }
    }
    Ok(GuestChannel::Backlogged)
}

/// Write one frame to the guest, waiting for room if it is slow to drain.
///
/// The descriptor is non-blocking for the sake of the read side, so
/// back-pressure surfaces here as `WouldBlock`. Waiting is the only correct
/// answer for a frame already part-written: dropping it would desynchronize
/// the framing, and re-sending it would duplicate bytes.
///
/// `stall_deadline` bounds that wait. A guest that simply stops reading its
/// data socket would otherwise park this loop forever — no inbound service,
/// no expiry tick, and a flow table that fills and then denies every new
/// flow even after the guest recovers. A guest must not be able to choose
/// that, so past the deadline the tunnel is dropped. Progress or teardown,
/// never a wedge.
fn write_frame(
    data: &mut dyn mvm_net::channel::GuestStream,
    data_fd: RawFd,
    frame: &[u8],
    stall_deadline: Duration,
) -> Result<Delivery> {
    let mut sent = 0;
    let mut last_progress = std::time::Instant::now();
    while sent < frame.len() {
        match data.write(&frame[sent..]) {
            Ok(0) => return Err(anyhow!("the guest data channel accepted no bytes")),
            Ok(n) => {
                sent += n;
                last_progress = std::time::Instant::now();
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                match wait_writable(data_fd)? {
                    Writability::Ready => {}
                    Writability::PeerGone => return Ok(Delivery::GuestGone),
                    Writability::TimedOut if last_progress.elapsed() >= stall_deadline => {
                        eprintln!(
                            "mvm-netd: dropping the tunnel: the guest stopped reading its data channel"
                        );
                        return Ok(Delivery::GuestGone);
                    }
                    Writability::TimedOut => {}
                }
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(Delivery::Sent)
}

/// Wait for room on the guest data channel, bounded by the tick.
fn wait_writable(fd: RawFd) -> Result<Writability> {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    // SAFETY: `pollfd` is a live, correctly-sized array of one entry we own,
    // naming a descriptor the caller holds open.
    let rc = unsafe { libc::poll(&mut pollfd, 1, TICK_MILLIS) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(Writability::TimedOut);
        }
        return Err(err).context("waiting for room on the guest data channel");
    }
    if rc == 0 {
        return Ok(Writability::TimedOut);
    }
    // Checked before writability: a closed or errored peer can report both,
    // and treating that as room would spin until the write returns EPIPE.
    if pollfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Ok(Writability::PeerGone);
    }
    Ok(Writability::Ready)
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `fd` is owned by a live stream in the caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same descriptor; F_SETFL takes an int.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use mvm_agentd::l3::{
        AgentState, MemoryTun, NetAgent, RecordingConfigurator, RecordingPrivilegeDropper,
    };
    use mvm_hostd::netd::config::{NetdEgress, NetdRule};
    use mvm_hostd::netd::{
        DatapathError, DatapathHandle, DatapathRequest, ForwardingCapabilities, L3Datapath,
    };
    use mvm_net::channel::GuestStream;
    use mvm_net::l3::{AdmittedPacket, FlowKey};
    use mvm_protocol::l3::proto;

    use super::*;

    /// The remote a guest opened a flow to before going quiet.
    const SERVER: &str = "93.184.216.34";
    const SERVER_PORT: u16 = 443;
    const GUEST_PORT: u16 = 50000;
    /// When the guest's flow was last seen, in the injected clock's units.
    const OPENED_AT_MILLIS: u64 = 1_000;

    /// A datapath whose inbound queue the test owns.
    ///
    /// `LoopbackDatapath` only produces a reply to something the guest sent,
    /// and `Gateway::open` keeps the handle it opens, so neither can stand in
    /// for a server that pushes to a guest which has sent nothing.
    #[derive(Clone, Default)]
    struct QueuedNetwork {
        inbound: Arc<std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>>,
    }

    impl QueuedNetwork {
        /// Queue a packet as though it arrived from the host network.
        fn deliver(&self, packet: Vec<u8>) {
            self.inbound
                .lock()
                .expect("inbound queue")
                .push_back(packet);
        }
    }

    impl L3Datapath for QueuedNetwork {
        fn open(&self, _req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
            Ok(Box::new(self.clone()))
        }

        fn is_available(&self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn capabilities(&self) -> ForwardingCapabilities {
            ForwardingCapabilities::FULL_L3_V4
        }
    }

    impl DatapathHandle for QueuedNetwork {
        fn send_to_network(&mut self, _packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
            Ok(())
        }

        fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError> {
            match self.inbound.lock().expect("inbound queue").pop_front() {
                Some(packet) => {
                    let n = packet.len().min(buf.len());
                    buf[..n].copy_from_slice(&packet[..n]);
                    Ok(n)
                }
                None => Err(DatapathError::Io(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                ))),
            }
        }

        fn close(&mut self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn description(&self) -> String {
            "test-owned host network queue".to_string()
        }
    }

    /// A datapath that only makes progress when it is driven, the way the
    /// selected userspace one does.
    ///
    /// Its packets exist the moment the network produces them, but a guest
    /// cannot see one until a service pass promotes it — which is exactly
    /// where a completed host connect lives before something reads the
    /// kernel's decision about it.
    #[derive(Clone, Default)]
    struct ServicedNetwork {
        state: Arc<std::sync::Mutex<ServicedState>>,
    }

    #[derive(Default)]
    struct ServicedState {
        /// Produced by the network, not yet promoted.
        staged: std::collections::VecDeque<Vec<u8>>,
        readable: std::collections::VecDeque<Vec<u8>>,
        /// Every clock value a service pass was driven with.
        serviced_at: Vec<u64>,
    }

    impl ServicedNetwork {
        fn deliver(&self, packet: Vec<u8>) {
            self.state
                .lock()
                .expect("datapath state")
                .staged
                .push_back(packet);
        }

        fn serviced_at(&self) -> Vec<u64> {
            self.state
                .lock()
                .expect("datapath state")
                .serviced_at
                .clone()
        }
    }

    impl L3Datapath for ServicedNetwork {
        fn open(&self, _req: &DatapathRequest) -> Result<Box<dyn DatapathHandle>, DatapathError> {
            Ok(Box::new(self.clone()))
        }

        fn is_available(&self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn capabilities(&self) -> ForwardingCapabilities {
            ForwardingCapabilities::USERSPACE_SOCKETS
        }
    }

    impl DatapathHandle for ServicedNetwork {
        fn send_to_network(&mut self, _packet: &AdmittedPacket<'_>) -> Result<(), DatapathError> {
            Ok(())
        }

        fn service(&mut self, now_millis: u64) -> Result<(), DatapathError> {
            let mut state = self.state.lock().expect("datapath state");
            state.serviced_at.push(now_millis);
            while let Some(packet) = state.staged.pop_front() {
                state.readable.push_back(packet);
            }
            Ok(())
        }

        fn recv_from_network(&mut self, buf: &mut [u8]) -> Result<usize, DatapathError> {
            match self
                .state
                .lock()
                .expect("datapath state")
                .readable
                .pop_front()
            {
                Some(packet) => {
                    let n = packet.len().min(buf.len());
                    buf[..n].copy_from_slice(&packet[..n]);
                    Ok(n)
                }
                None => Err(DatapathError::Io(std::io::Error::from(
                    std::io::ErrorKind::WouldBlock,
                ))),
            }
        }

        fn close(&mut self) -> Result<(), DatapathError> {
            Ok(())
        }

        fn description(&self) -> String {
            "a datapath that advances only when serviced".to_string()
        }
    }

    fn test_config(vm_id: &str) -> NetdConfig {
        NetdConfig {
            node_id: "node-1".into(),
            vm_id: vm_id.into(),
            boot_id: "boot-1".into(),
            plan_digest: "sha256:plan".into(),
            uds_layout: NetdUdsLayout::PerVmDir,
            gateway_ipv4: "10.201.0.5".parse().expect("gateway address"),
            guest_ipv4: "10.201.0.6".parse().expect("guest address"),
            mtu: 1500,
            egress: NetdEgress::Rules(vec![NetdRule {
                proto: "tcp".into(),
                cidr: format!("{SERVER}/32"),
                port_lo: SERVER_PORT,
                port_hi: SERVER_PORT,
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

    fn open_gateway(config: &NetdConfig, network: &dyn L3Datapath) -> Gateway {
        let instance = config.instance();
        let mut gateway_config = GatewayConfig::new(
            config.vm_id.clone(),
            config.plan_digest.clone(),
            config.lease(),
            config.to_policy().expect("policy"),
        );
        gateway_config.instance = instance.clone();
        gateway_config.ingress = config.to_ingress_table().expect("ingress");
        gateway_config.queue_depth = config.queue_depth;
        gateway_config.dns_qps = config.dns_qps;
        Gateway::open(
            gateway_config,
            mvm_net::l3::SessionId(mint_session_id(&instance)),
            network,
            Arc::new(StaticResolver::new()),
        )
        .expect("opening the gateway")
    }

    /// The flow the guest opened before it went quiet.
    fn quiet_flow() -> FlowKey {
        FlowKey {
            protocol: proto::TCP,
            guest_port: GUEST_PORT,
            remote: SERVER.parse().expect("server address"),
            remote_port: SERVER_PORT,
        }
    }

    /// The server's reply on that flow: return traffic the guest never asked
    /// for a second time.
    fn server_reply(config: &NetdConfig) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&SERVER_PORT.to_be_bytes());
        tcp[2..4].copy_from_slice(&GUEST_PORT.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = mvm_protocol::l3::ip::TCP_ACK;
        let total = 20 + tcp.len();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = proto::TCP;
        let src: std::net::Ipv4Addr = SERVER.parse().expect("server address");
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&config.guest_ipv4.octets());
        packet.extend_from_slice(&tcp);
        packet
    }

    fn guest_agent() -> NetAgent<MemoryTun, RecordingConfigurator> {
        NetAgent::new(MemoryTun::new("mvm0"), RecordingConfigurator::default())
            .with_privilege_dropper(Box::new(RecordingPrivilegeDropper::default()))
    }

    /// Reads a `StreamingGuest` serves before going quiet. Comfortably past
    /// the drain's budget, so `Backlogged` can only mean the budget cut the
    /// drain off first — and removing the budget produces a failed assertion
    /// rather than a test that never returns.
    const STREAMING_GUEST_READS: usize = 64;

    /// A guest that dribbles bytes far faster than the loop wants to read
    /// them. Announces a legal frame length and then never completes it, so
    /// nothing is ever malformed and nothing is ever finished.
    #[derive(Default)]
    struct StreamingGuest {
        reads: usize,
    }

    impl std::io::Read for StreamingGuest {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.reads >= STREAMING_GUEST_READS {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.reads += 1;
            if self.reads == 1 {
                let len = u32::try_from(mvm_protocol::l3::limits::MAX_FRAME_LEN).expect("len");
                buf[..4].copy_from_slice(&len.to_be_bytes());
                return Ok(4);
            }
            buf[0] = 0;
            Ok(1)
        }
    }

    impl std::io::Write for StreamingGuest {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A channel that reports an interrupted syscall far more often than the
    /// drain's budget allows, then goes quiet. Bounded for the same reason
    /// `StreamingGuest` is: an unbounded storm would make the regression
    /// hang instead of fail.
    #[derive(Default)]
    struct SignalStorm {
        reads: usize,
    }

    impl std::io::Read for SignalStorm {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            if self.reads >= STREAMING_GUEST_READS {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.reads += 1;
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        }
    }

    impl std::io::Write for SignalStorm {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The mirror of the defect above: a guest that never pauses must not be
    /// able to hold the loop in the drain and starve the datapath and the
    /// expiry tick.
    #[test]
    fn a_guest_that_never_stops_sending_hands_the_loop_back() {
        let config = test_config("netd-backlog");
        let network = QueuedNetwork::default();
        let mut gateway = open_gateway(&config, &network);
        let mut buf = vec![0u8; mvm_protocol::l3::MAX_WIRE_LEN];

        let drained = drain_guest_data(&mut gateway, &mut StreamingGuest::default(), &mut buf, 0)
            .expect("a guest that keeps sending is not an error");

        assert_eq!(
            drained,
            GuestChannel::Backlogged,
            "the drain must yield on its read budget rather than keep reading \
             until the guest happens to pause"
        );
    }

    /// An interrupted syscall must cost the same budget a real read does.
    /// Uncharged, a signal storm spins in the drain forever and the loop
    /// never reaches the datapath or the tick.
    #[test]
    fn a_signal_storm_cannot_spin_the_drain_forever() {
        let config = test_config("netd-eintr");
        let network = QueuedNetwork::default();
        let mut gateway = open_gateway(&config, &network);
        let mut buf = vec![0u8; mvm_protocol::l3::MAX_WIRE_LEN];

        let drained = drain_guest_data(&mut gateway, &mut SignalStorm::default(), &mut buf, 0)
            .expect("an interrupted read is not an error");

        assert_eq!(
            drained,
            GuestChannel::Backlogged,
            "an interrupted read must be charged against the read budget"
        );
    }

    /// Fill a socket's send buffer so the next write reports `WouldBlock`.
    fn fill_send_buffer(stream: &mut UnixStream) {
        set_nonblocking(stream.as_raw_fd()).expect("non-blocking");
        let junk = vec![0u8; 64 * 1024];
        loop {
            match std::io::Write::write(stream, &junk) {
                Ok(0) => return,
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(err) => panic!("filling the send buffer: {err}"),
            }
        }
    }

    /// A guest that stops reading its data channel must not be able to park
    /// the loop in a write. Everything time-driven — inbound service, flow
    /// expiry — lives after this call, so an unbounded wait here lets a
    /// guest fill the flow table and then deny itself every new flow.
    #[test]
    fn a_guest_that_stops_reading_is_dropped_rather_than_parking_the_loop() {
        let (mut host, guest) = UnixStream::pair().expect("data pair");
        let host_fd = host.as_raw_fd();
        fill_send_buffer(&mut host);

        // Off-thread with a bound, so losing the deadline is a failed
        // assertion rather than a test that never returns.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // The guest end is alive and healthy — it simply never reads.
            let _guest = guest;
            let _ = tx.send(write_frame(&mut host, host_fd, b"a frame", Duration::ZERO));
        });

        let delivered = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the write must give up on its deadline instead of waiting forever")
            .expect("a stalled guest is a dropped tunnel, not a host error");

        assert_eq!(delivered, Delivery::GuestGone);
    }

    /// A half-closed peer must be distinguishable from a slow one: it
    /// reports `POLLHUP` alongside writability, and treating that as room
    /// would spin until the write finally returned `EPIPE`.
    #[test]
    fn a_closed_guest_end_is_reported_as_gone_not_as_room() {
        let (host, guest) = UnixStream::pair().expect("data pair");
        let host_fd = host.as_raw_fd();
        drop(guest);

        assert_eq!(
            wait_writable(host_fd).expect("polling a closed peer is not an error"),
            Writability::PeerGone
        );
    }

    /// A guest that is simply slow, and still reading, is not dropped.
    #[test]
    fn a_guest_with_room_is_written_to_without_waiting() {
        let (mut host, mut guest) = UnixStream::pair().expect("data pair");
        let host_fd = host.as_raw_fd();
        set_nonblocking(host_fd).expect("non-blocking");

        let delivered = write_frame(&mut host, host_fd, b"a frame", Duration::ZERO)
            .expect("writing to a healthy guest");

        assert_eq!(delivered, Delivery::Sent);
        let mut got = [0u8; 7];
        std::io::Read::read_exact(&mut guest, &mut got).expect("the guest receives it");
        assert_eq!(&got, b"a frame");
    }

    /// The defect this pins: the old loop blocked on the guest data channel
    /// and only drained the datapath afterwards, so a server pushing to a
    /// silent guest stalled indefinitely. The guest sends nothing here.
    #[test]
    fn host_to_guest_data_flows_while_the_guest_is_silent() {
        let config = test_config("netd-silent-guest");
        let network = QueuedNetwork::default();
        let mut gateway = open_gateway(&config, &network);
        // The guest opened this flow earlier and then went quiet.
        gateway
            .admitter_mut()
            .flows_mut()
            .observe_outbound(quiet_flow(), 40, OPENED_AT_MILLIS);

        let (host_control, mut guest_control) = UnixStream::pair().expect("control pair");
        let (host_data, mut guest_data) = UnixStream::pair().expect("data pair");
        guest_data
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let data_fd = host_data.as_raw_fd();
        let mut host_control: Box<dyn GuestStream> = Box::new(host_control);
        let mut host_data: Box<dyn GuestStream> = Box::new(host_data);

        let start = std::time::Instant::now();
        let clock = move || monotonic_millis(start);
        let expected = server_reply(&config);

        let (read, served) = std::thread::scope(|scope| {
            let served = scope.spawn(|| {
                serve(
                    &mut gateway,
                    &mut *host_control,
                    &mut *host_data,
                    data_fd,
                    &clock,
                )
            });

            let mut agent = guest_agent();
            agent
                .handshake(&mut guest_control)
                .expect("the guest completes the handshake");
            assert_eq!(agent.state(), AgentState::Ready);

            network.deliver(expected.clone());

            let mut frame = vec![0u8; 4096];
            let read = std::io::Read::read(&mut guest_data, &mut frame).map(|n| {
                frame.truncate(n);
                frame
            });

            drop(guest_data);
            drop(guest_control);
            (read, served.join().expect("the serve thread"))
        });

        served.expect("serve must end cleanly");
        let frame = read.expect("a frame must reach the guest without the guest sending first");
        assert!(!frame.is_empty());
        assert!(
            frame.windows(expected.len()).any(|w| w == expected),
            "the frame the guest received must carry the packet the network delivered"
        );
    }

    /// The clock this loop drives a service pass with. Distinctive, inside
    /// the flow's idle window, and nothing a wall clock could produce, so a
    /// second time source would be visible rather than plausible.
    const SERVICE_CLOCK_MILLIS: u64 = OPENED_AT_MILLIS + 7;

    /// The defect this pins: the selected datapath translates flows into
    /// host sockets, and nothing in the loop drove it. A guest's connect
    /// completed in the kernel and then sat there — no reset, no SYN-ACK,
    /// no error, just a guest waiting forever on a handshake nobody
    /// finished.
    ///
    /// Driven through `serve`, not through a hand-called `service`: a test
    /// that services the handle itself exercises the one thing production
    /// was failing to do, and stays green through the whole defect.
    #[test]
    fn the_loop_services_the_datapath_it_owns() {
        let config = test_config("netd-serviced-datapath");
        let network = ServicedNetwork::default();
        let mut gateway = open_gateway(&config, &network);
        // The guest opened this flow earlier and then went quiet.
        gateway
            .admitter_mut()
            .flows_mut()
            .observe_outbound(quiet_flow(), 40, OPENED_AT_MILLIS);

        let (host_control, mut guest_control) = UnixStream::pair().expect("control pair");
        let (host_data, mut guest_data) = UnixStream::pair().expect("data pair");
        guest_data
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let data_fd = host_data.as_raw_fd();
        let mut host_control: Box<dyn GuestStream> = Box::new(host_control);
        let mut host_data: Box<dyn GuestStream> = Box::new(host_data);

        let clock = || SERVICE_CLOCK_MILLIS;
        let expected = server_reply(&config);

        let (read, served) = std::thread::scope(|scope| {
            let served = scope.spawn(|| {
                serve(
                    &mut gateway,
                    &mut *host_control,
                    &mut *host_data,
                    data_fd,
                    &clock,
                )
            });

            let mut agent = guest_agent();
            agent
                .handshake(&mut guest_control)
                .expect("the guest completes the handshake");
            assert_eq!(agent.state(), AgentState::Ready);

            network.deliver(expected.clone());

            let mut frame = vec![0u8; 4096];
            let read = std::io::Read::read(&mut guest_data, &mut frame).map(|n| {
                frame.truncate(n);
                frame
            });

            drop(guest_data);
            drop(guest_control);
            (read, served.join().expect("the serve thread"))
        });

        served.expect("serve must end cleanly");
        let frame = read.expect(
            "a datapath that advances only when driven must still reach the guest: \
             the loop that owns the handle has to service it",
        );
        assert!(
            frame.windows(expected.len()).any(|w| w == expected),
            "the frame the guest received must carry the packet the network produced"
        );

        let serviced_at = network.serviced_at();
        assert!(
            !serviced_at.is_empty(),
            "the loop must service the datapath"
        );
        assert!(
            serviced_at.iter().all(|&at| at == SERVICE_CLOCK_MILLIS),
            "the service pass must be driven from the loop's own clock, not a \
             second time source: {serviced_at:?}"
        );
    }

    /// Time in the drive loop must come from the injected clock, not from a
    /// count of anything the guest did. A per-frame counter would make a
    /// five-minute idle timeout mean 300,000 frames, and with a silent guest
    /// it would never advance at all — so nothing here would ever expire.
    #[test]
    fn idle_flows_expire_on_the_injected_clock_while_the_guest_is_silent() {
        let config = test_config("netd-injected-clock");
        let network = QueuedNetwork::default();
        let mut gateway = open_gateway(&config, &network);
        gateway
            .admitter_mut()
            .flows_mut()
            .observe_outbound(quiet_flow(), 40, OPENED_AT_MILLIS);

        let (host_control, mut guest_control) = UnixStream::pair().expect("control pair");
        let (host_data, guest_data) = UnixStream::pair().expect("data pair");
        let data_fd = host_data.as_raw_fd();
        let mut host_control: Box<dyn GuestStream> = Box::new(host_control);
        let mut host_data: Box<dyn GuestStream> = Box::new(host_data);

        // A clock the test owns, parked past the flow's idle timeout. Every
        // read of it is counted so the test can tell when the loop has run
        // without sleeping for a guess.
        let reads = Arc::new(AtomicU64::new(0));
        let clock = {
            let reads = Arc::clone(&reads);
            move || {
                reads.fetch_add(1, Ordering::SeqCst);
                OPENED_AT_MILLIS + mvm_net::l3::flow::DEFAULT_TCP_IDLE_MILLIS
            }
        };

        let served = std::thread::scope(|scope| {
            let served = scope.spawn(|| {
                serve(
                    &mut gateway,
                    &mut *host_control,
                    &mut *host_data,
                    data_fd,
                    &clock,
                )
            });

            let mut agent = guest_agent();
            agent
                .handshake(&mut guest_control)
                .expect("the guest completes the handshake");

            // Three further reads of the clock mean at least one full pass of
            // the steady-state loop finished after the handshake.
            let after_handshake = reads.load(Ordering::SeqCst);
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while reads.load(Ordering::SeqCst) < after_handshake + 3 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the drive loop must keep running with the guest silent"
                );
                std::thread::sleep(Duration::from_millis(10));
            }

            drop(guest_data);
            drop(guest_control);
            served.join().expect("the serve thread")
        });

        served.expect("serve must end cleanly");
        assert_eq!(
            gateway.metrics().flows_expired,
            1,
            "the loop must expire the idle flow from the clock it was handed, \
             with no guest frame to count"
        );
    }

    fn icmp_shortfall() -> GatewayError {
        GatewayError::Datapath(DatapathError::CapabilityShortfall {
            backend: "selected forwarding backend",
            missing: vec!["icmp"],
        })
    }

    #[test]
    fn a_capability_refusal_arrives_with_the_substitution_that_caused_it() {
        let msg = format!(
            "{:#}",
            explain_open_failure(icmp_shortfall(), Some("the host fell back because of X"))
        );
        assert!(msg.contains("icmp"), "{msg}");
        assert!(
            msg.contains("the host fell back because of X"),
            "a shortfall names a symptom; without the cause beside it the \
             operator has nothing to act on: {msg}"
        );
    }

    #[test]
    fn a_host_on_its_own_datapath_is_told_no_story_about_a_fallback() {
        let msg = format!("{:#}", explain_open_failure(icmp_shortfall(), None));
        assert!(msg.contains("icmp"), "{msg}");
        assert!(msg.contains("opening the gateway"), "{msg}");
    }
}
