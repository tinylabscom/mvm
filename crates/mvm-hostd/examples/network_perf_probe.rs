//! Release-only host-loopback producer for `xtask network-perf run-probe`.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use mvm_agentd::flowmux::{build_dns_query, decode_udp_addr, encode_udp_addr};
use mvm_agentd::flowmux_sync::{HttpFlowOpen, SyncFlowMux};
use mvm_contract::policy::dns_pin::{DnsPin, DnsPinRegistry};
use mvm_contract::policy::network_policy::{HostPort, NetworkPolicy};
use mvm_contract::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
use mvm_contract::protocol::network_flow::Opcode;
use mvm_contract::substitution::PreparedRequest;
use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use mvm_hostd::keyholder::resolver::LocalResolver;
use mvm_hostd::keyholder::substitution::SubstitutionRegistry;
use mvm_hostd::supervisor::flowmux::registry::RegistryLimits;
use mvm_hostd::supervisor::flowmux::{FlowMuxAccept, FlowMuxSession};
use mvm_hostd::supervisor::network_endpoint_proxy::{
    ForwardError, ForwardResponse, Forwarder, SubstitutionService,
};
use mvm_runtime::vmm::egress_gate::EgressGate;
use xtask::network_perf::{
    BuildLabel, HostLabel, Implementation, MIN_SAMPLES_PER_CASE, NetworkPath, NetworkPerfProbe,
    ProbeCase, SCHEMA_VERSION, SampleMatrix,
};

// The matrix is shared across TCP, UDP, DNS, and typed HTTP.
const PAYLOAD_BYTES: [u64; 2] = [64, 1024];
const CONCURRENCY: [u32; 1] = [1];
const TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<()> {
    if cfg!(debug_assertions) {
        bail!("network performance probes must be built with --release");
    }
    let implementation = implementation_from_env()?;
    let samples = samples_from_env()?;
    let matrix = SampleMatrix {
        payload_bytes: PAYLOAD_BYTES.to_vec(),
        concurrency: CONCURRENCY.to_vec(),
        samples_per_case: samples,
    };
    let mut cases = Vec::new();
    for payload_bytes in PAYLOAD_BYTES {
        let payload = usize::try_from(payload_bytes).context("payload fits usize")?;
        cases
            .push(benchmark_flowmux_tcp(payload, samples).context("benchmark FlowMux opaque TCP")?);
        cases.push(benchmark_flowmux_udp(payload, samples).context("benchmark FlowMux UDP")?);
        cases.push(benchmark_flowmux_dns(payload_bytes, samples).context("benchmark FlowMux DNS")?);
        cases.push(
            benchmark_flowmux_typed_http(payload, samples)
                .context("benchmark FlowMux typed HTTP")?,
        );
    }
    let report = NetworkPerfProbe {
        schema_version: SCHEMA_VERSION,
        implementation,
        host: HostLabel {
            id: required_env("MVM_NETWORK_PERF_HOST_ID")?,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu: required_env("MVM_NETWORK_PERF_CPU")?,
        },
        backend: required_env("MVM_NETWORK_PERF_BACKEND")?,
        storage: required_env("MVM_NETWORK_PERF_STORAGE")?,
        build: BuildLabel {
            profile: "release".into(),
            source_commit: required_env("MVM_NETWORK_PERF_SOURCE_COMMIT")?,
            command: "cargo run --release -p mvm-hostd --features network-perf --example network_perf_probe".into(),
        },
        matrix,
        cases,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn implementation_from_env() -> Result<Implementation> {
    match required_env("MVM_NETWORK_PERF_IMPLEMENTATION")?.as_str() {
        "flow_mux" => Ok(Implementation::FlowMux),
        other => bail!("unknown MVM_NETWORK_PERF_IMPLEMENTATION {other:?}"),
    }
}

fn samples_from_env() -> Result<u32> {
    let samples = required_env("MVM_NETWORK_PERF_SAMPLES")?
        .parse::<u32>()
        .context("MVM_NETWORK_PERF_SAMPLES must be an integer")?;
    if samples < MIN_SAMPLES_PER_CASE {
        bail!("MVM_NETWORK_PERF_SAMPLES must be at least {MIN_SAMPLES_PER_CASE}");
    }
    Ok(samples)
}

fn required_env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn benchmark_flowmux_tcp(payload_bytes: usize, samples: u32) -> Result<ProbeCase> {
    let listener = TcpListener::bind("0.0.0.0:0")?;
    let target = std::net::SocketAddr::new(local_test_ip()?, listener.local_addr()?.port());
    let server = thread::spawn(move || -> std::io::Result<()> {
        for _ in 0..samples {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            let mut body = vec![0; payload_bytes];
            stream.read_exact(&mut body)?;
            stream.write_all(&body)?;
        }
        Ok(())
    });
    let (mut client, host) =
        start_flowmux_session(gate_for_addr(target.ip(), Proto::Tcp, target.port()), None)?;
    let payload = vec![0x5a; payload_bytes];
    let usage = Usage::start()?;
    let elapsed = Instant::now();
    let mut connect = Vec::with_capacity(samples as usize);
    let mut request = Vec::with_capacity(samples as usize);
    for _ in 0..samples {
        let stream_id = client.next_stream_id();
        let started = Instant::now();
        client.send(Opcode::OpenTcp, stream_id, target.to_string().as_bytes())?;
        expect_frame(&mut client, stream_id, Opcode::Opened)?;
        connect.push(micros(started.elapsed()));

        let started = Instant::now();
        client.send(Opcode::Data, stream_id, &payload)?;
        let mut response = Vec::with_capacity(payload_bytes);
        while response.len() < payload_bytes {
            let (opcode, id, body) = client.recv()?;
            if id != stream_id {
                if is_retired_stream_frame(opcode) {
                    continue;
                }
                bail!("FlowMux TCP reply used stream {id}, expected {stream_id}");
            }
            match opcode {
                Opcode::Data => response.extend_from_slice(&body),
                Opcode::WindowUpdate => {}
                other => bail!("unexpected FlowMux TCP reply {other:?}"),
            }
        }
        if response != payload {
            bail!("FlowMux TCP echo changed the payload");
        }
        request.push(micros(started.elapsed()));
        drain_tcp_close(&mut client, stream_id)?;
    }
    drop(client);
    join_flowmux(host)?;
    join_server(server)?;
    ProbeCaseBuilder::new(NetworkPath::OpaqueTcp, payload_bytes)
        .connect_latency(connect)
        .request_latency(request)
        .elapsed(elapsed.elapsed())
        .transferred_bytes(transferred(payload_bytes, samples)?)
        .usage(usage.finish()?)
        .build()
}

fn benchmark_flowmux_udp(payload_bytes: usize, samples: u32) -> Result<ProbeCase> {
    let server_socket = UdpSocket::bind("0.0.0.0:0")?;
    let target = std::net::SocketAddr::new(local_test_ip()?, server_socket.local_addr()?.port());
    server_socket.set_read_timeout(Some(TIMEOUT))?;
    let server = thread::spawn(move || -> std::io::Result<()> {
        let mut body = vec![0; payload_bytes];
        for _ in 0..samples {
            let (len, peer) = server_socket.recv_from(&mut body)?;
            server_socket.send_to(&body[..len], peer)?;
        }
        Ok(())
    });
    let (mut client, host) =
        start_flowmux_session(gate_for_addr(target.ip(), Proto::Udp, target.port()), None)?;
    let payload = vec![0x6b; payload_bytes];
    let usage = Usage::start()?;
    let elapsed = Instant::now();
    let mut request = Vec::with_capacity(samples as usize);
    for sample in 0..samples {
        let stream_id = client.next_stream_id();
        client.send(Opcode::OpenUdp, stream_id, &[])?;
        expect_frame(&mut client, stream_id, Opcode::UdpOpened)
            .with_context(|| format!("open UDP association for sample {sample}"))?;
        let mut datagram = encode_udp_addr(target.ip(), target.port());
        datagram.extend_from_slice(&payload);
        let started = Instant::now();
        client.send(Opcode::UdpSend, stream_id, &datagram)?;
        let body = expect_frame(&mut client, stream_id, Opcode::UdpRecv)
            .with_context(|| format!("receive UDP echo for sample {sample}"))?;
        let (_source, response) = decode_udp_addr(&body)?;
        if response != payload {
            bail!("FlowMux UDP echo changed the payload");
        }
        request.push(micros(started.elapsed()));
        client.send(Opcode::CloseUdp, stream_id, &[])?;
    }
    drop(client);
    join_flowmux(host)?;
    join_server(server)?;
    ProbeCaseBuilder::new(NetworkPath::Udp, payload_bytes)
        .request_latency(request)
        .elapsed(elapsed.elapsed())
        .transferred_bytes(transferred(payload_bytes, samples)?)
        .usage(usage.finish()?)
        .build()
}

fn benchmark_flowmux_dns(payload_bytes: u64, samples: u32) -> Result<ProbeCase> {
    const NAME: &str = "benchmark.test";
    let (mut client, host) = start_flowmux_session(gate_for_dns(NAME), None)?;
    let usage = Usage::start()?;
    let elapsed = Instant::now();
    let mut request = Vec::with_capacity(samples as usize);
    for sample in 0..samples {
        let stream_id = client.next_stream_id();
        let id = u16::try_from(sample).context("DNS sample identifier fits u16")?;
        let query = build_dns_query(NAME, 1, id)?;
        let started = Instant::now();
        client.send(Opcode::Resolve, stream_id, &query)?;
        let response = expect_frame(&mut client, stream_id, Opcode::Resolved)?;
        if response.len() < 12 {
            bail!("FlowMux DNS response was shorter than its header");
        }
        request.push(micros(started.elapsed()));
    }
    drop(client);
    join_flowmux(host)?;
    ProbeCaseBuilder::new(NetworkPath::Dns, usize::try_from(payload_bytes)?)
        .request_latency(request)
        .elapsed(elapsed.elapsed())
        .completed_operations(u64::from(samples))
        .usage(usage.finish()?)
        .build()
}

fn benchmark_flowmux_typed_http(payload_bytes: usize, samples: u32) -> Result<ProbeCase> {
    let (_secret_dir, service) = echo_substitution_service()?;
    let request_wire = WireRequest {
        method: "POST".into(),
        url: "https://fixture.invalid/echo".into(),
        headers: vec![],
        body_b64: B64.encode(vec![0x7c; payload_bytes]),
    };
    let usage = Usage::start()?;
    let elapsed = Instant::now();
    let mut connect = Vec::with_capacity(samples as usize);
    let mut request = Vec::with_capacity(samples as usize);
    let mut bytes = 0_u64;
    let (mut client, host) =
        start_flowmux_session(EgressGate::default_deny(), Some(Arc::clone(&service)))?;
    for _ in 0..samples {
        let started = Instant::now();
        let HttpFlowOpen::Opened(stream_id) = client.open_http()? else {
            bail!("FlowMux typed HTTP fixture refused to open its stream");
        };
        connect.push(micros(started.elapsed()));
        let started = Instant::now();
        let response = client.exchange_open_http(stream_id, &request_wire)?;
        let WireResponse::Ok { body_b64, .. } = response else {
            bail!("FlowMux typed HTTP fixture refused its echo request");
        };
        if B64.decode(&body_b64)? != vec![0x7c; payload_bytes] {
            bail!("FlowMux typed HTTP echo changed the payload");
        }
        bytes = bytes.saturating_add(u64::try_from(request_wire.body_b64.len())?);
        bytes = bytes.saturating_add(u64::try_from(body_b64.len())?);
        request.push(micros(started.elapsed()));
    }
    drop(client);
    join_flowmux(host)?;
    ProbeCaseBuilder::new(NetworkPath::TransformedHttp, payload_bytes)
        .connect_latency(connect)
        .request_latency(request)
        .elapsed(elapsed.elapsed())
        .transferred_bytes(bytes)
        .usage(usage.finish()?)
        .build()
}

struct EchoForwarder;

#[async_trait]
impl Forwarder for EchoForwarder {
    async fn forward(&self, request: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        Ok(ForwardResponse {
            status: 200,
            headers: Vec::new(),
            body: request.body,
        })
    }
}

fn echo_substitution_service() -> Result<(tempfile::TempDir, Arc<SubstitutionService>)> {
    let secret_dir = tempfile::tempdir()?;
    let store: Arc<dyn SecretStore> = Arc::new(FileSecretStore::with_dir(secret_dir.path()));
    let resolver = Arc::new(LocalResolver::new("benchmark", store));
    let service = SubstitutionService::new(
        Arc::new(SubstitutionRegistry::new()),
        resolver,
        Arc::new(EchoForwarder),
    );
    Ok((secret_dir, Arc::new(service)))
}

type FlowMuxHost = thread::JoinHandle<Result<(), mvm_hostd::supervisor::flowmux::FlowMuxError>>;

fn start_flowmux_session(
    gate: EgressGate,
    service: Option<Arc<SubstitutionService>>,
) -> Result<(SyncFlowMux, FlowMuxHost)> {
    let host_key = SigningKey::from_bytes(&[0x31; 32]);
    let guest_key = SigningKey::from_bytes(&[0x72; 32]);
    let host_anchor = host_key.verifying_key();
    let guest_anchor = guest_key.verifying_key();
    let (host_stream, guest_stream) = UnixStream::pair()?;
    let host = thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(mvm_hostd::supervisor::flowmux::FlowMuxError::Transport)?;
        let _entered = runtime.enter();
        let accept = FlowMuxAccept::new(
            "network-perf",
            host_key,
            guest_anchor,
            RegistryLimits::default(),
            gate,
        )
        .with_substitution(service);
        let mut session = FlowMuxSession::accept_with(host_stream, accept)?;
        session.serve()
    });
    let client = SyncFlowMux::handshake(guest_stream, guest_key, &host_anchor)?;
    client.set_read_timeout(TIMEOUT)?;
    Ok((client, host))
}

fn expect_frame(client: &mut SyncFlowMux, stream_id: u32, wanted: Opcode) -> Result<Vec<u8>> {
    loop {
        let (opcode, id, payload) = client.recv()?;
        if id != stream_id && is_retired_stream_frame(opcode) {
            continue;
        }
        if opcode == Opcode::WindowUpdate && id == stream_id {
            continue;
        }
        if id != stream_id || opcode != wanted {
            bail!("expected {wanted:?} on FlowMux stream {stream_id}, got {opcode:?} on {id}");
        }
        return Ok(payload);
    }
}

fn is_retired_stream_frame(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::HalfClose | Opcode::Reset | Opcode::WindowUpdate
    )
}

fn drain_tcp_close(client: &mut SyncFlowMux, stream_id: u32) -> Result<()> {
    loop {
        let (opcode, id, _) = client.recv()?;
        if id != stream_id {
            bail!("FlowMux TCP close used stream {id}, expected {stream_id}");
        }
        match opcode {
            Opcode::WindowUpdate => {}
            Opcode::HalfClose => {
                client.send(Opcode::HalfClose, stream_id, &[])?;
                return Ok(());
            }
            other => bail!("unexpected FlowMux TCP close frame {other:?}"),
        }
    }
}

fn local_test_ip() -> Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("1.1.1.1:80")?;
    let ip = socket.local_addr()?.ip();
    if mvm_contract::policy::network_policy::is_mandatory_deny(ip) {
        bail!("local benchmark IP {ip} is in a mandatory-deny range");
    }
    Ok(ip)
}

fn gate_for_addr(ip: IpAddr, proto: Proto, port: u16) -> EgressGate {
    let net = match ip {
        IpAddr::V4(ip) => ipnet::IpNet::V4(ipnet::Ipv4Net::new(ip, 32).expect("valid /32")),
        IpAddr::V6(ip) => ipnet::IpNet::V6(ipnet::Ipv6Net::new(ip, 128).expect("valid /128")),
    };
    EgressGate::new(CanonicalEgress::Rules(vec![CanonicalRule {
        proto,
        net,
        port_lo: port,
        port_hi: port,
    }]))
}

fn gate_for_dns(name: &str) -> EgressGate {
    let now = "2026-01-01T00:00:00Z";
    let mut pins = DnsPinRegistry::new();
    pins.add(DnsPin::at(
        name,
        vec!["93.184.216.34".parse().expect("fixture IP is valid")],
        now,
        "2099-01-01T00:00:00Z",
    ));
    let policy = NetworkPolicy::allow_list(vec![HostPort::new(name, 53)]);
    EgressGate::from_network_policy(&policy, &pins, now)
}

fn join_flowmux(host: FlowMuxHost) -> Result<()> {
    host.join()
        .map_err(|_| anyhow::anyhow!("FlowMux host fixture panicked"))??;
    Ok(())
}

struct Usage {
    cpu_nanos: u64,
    stop: Arc<AtomicBool>,
    sampler: Option<thread::JoinHandle<Result<u64>>>,
}

struct UsageDelta {
    cpu_nanos: u64,
    peak_rss_bytes: u64,
}

impl Usage {
    fn start() -> Result<Self> {
        let cpu_nanos = process_cpu_nanos()?;
        let stop = Arc::new(AtomicBool::new(false));
        let sampler_stop = Arc::clone(&stop);
        let sampler = thread::spawn(move || sample_peak_rss(&sampler_stop));
        Ok(Self {
            cpu_nanos,
            stop,
            sampler: Some(sampler),
        })
    }

    fn finish(mut self) -> Result<UsageDelta> {
        self.stop.store(true, Ordering::Release);
        if let Some(sampler) = self.sampler.as_ref() {
            sampler.thread().unpark();
        }
        let peak_rss_bytes = self
            .sampler
            .take()
            .context("RSS sampler handle was missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("RSS sampler panicked"))??;
        let cpu_nanos = process_cpu_nanos()?;
        Ok(UsageDelta {
            cpu_nanos: cpu_nanos.saturating_sub(self.cpu_nanos).max(1),
            peak_rss_bytes: peak_rss_bytes.max(1),
        })
    }
}

impl Drop for Usage {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(sampler) = self.sampler.take() {
            sampler.thread().unpark();
            let _ = sampler.join();
        }
    }
}

fn process_cpu_nanos() -> Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` points to writable storage for one `rusage`; libc fills
    // it on success and we do not read it before checking the return value.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read process resource usage");
    }
    // SAFETY: a successful `getrusage` initialized the whole structure.
    let usage = unsafe { usage.assume_init() };
    let user = timeval_nanos(usage.ru_utime)?;
    let system = timeval_nanos(usage.ru_stime)?;
    Ok(user.saturating_add(system))
}

fn sample_peak_rss(stop: &AtomicBool) -> Result<u64> {
    let pid = sysinfo::get_current_pid()
        .map_err(|message| anyhow::anyhow!("identify benchmark process: {message}"))?;
    let mut system = sysinfo::System::new();
    let mut peak = 0_u64;
    loop {
        if !system.refresh_process(pid) {
            bail!("benchmark process disappeared while sampling RSS");
        }
        let rss = system
            .process(pid)
            .context("benchmark process missing after RSS refresh")?
            .memory();
        peak = peak.max(rss);
        if stop.load(Ordering::Acquire) {
            return Ok(peak);
        }
        thread::park_timeout(Duration::from_millis(1));
    }
}

fn timeval_nanos(value: libc::timeval) -> Result<u64> {
    let seconds = u64::try_from(value.tv_sec).context("CPU seconds were negative")?;
    let micros = u64::try_from(value.tv_usec).context("CPU micros were negative")?;
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(micros.saturating_mul(1_000)))
}

struct ProbeCaseBuilder {
    path: NetworkPath,
    payload_bytes: usize,
    connect_latency_micros: Option<Vec<u64>>,
    request_latency_micros: Option<Vec<u64>>,
    elapsed: Option<Duration>,
    transferred_bytes: Option<u64>,
    completed_operations: Option<u64>,
    usage: Option<UsageDelta>,
}

impl ProbeCaseBuilder {
    fn new(path: NetworkPath, payload_bytes: usize) -> Self {
        Self {
            path,
            payload_bytes,
            connect_latency_micros: None,
            request_latency_micros: None,
            elapsed: None,
            transferred_bytes: None,
            completed_operations: None,
            usage: None,
        }
    }

    fn connect_latency(mut self, samples: Vec<u64>) -> Self {
        self.connect_latency_micros = Some(samples);
        self
    }

    fn request_latency(mut self, samples: Vec<u64>) -> Self {
        self.request_latency_micros = Some(samples);
        self
    }

    fn elapsed(mut self, elapsed: Duration) -> Self {
        self.elapsed = Some(elapsed);
        self
    }

    fn transferred_bytes(mut self, bytes: u64) -> Self {
        self.transferred_bytes = Some(bytes);
        self
    }

    fn completed_operations(mut self, operations: u64) -> Self {
        self.completed_operations = Some(operations);
        self
    }

    fn usage(mut self, usage: UsageDelta) -> Self {
        self.usage = Some(usage);
        self
    }

    fn build(self) -> Result<ProbeCase> {
        let usage = self.usage.context("probe case requires resource usage")?;
        Ok(ProbeCase {
            path: self.path,
            payload_bytes: u64::try_from(self.payload_bytes)?,
            concurrency: 1,
            connect_latency_micros: self.connect_latency_micros,
            request_latency_micros: self
                .request_latency_micros
                .context("probe case requires request latency")?,
            elapsed_nanos: u64::try_from(
                self.elapsed
                    .context("probe case requires elapsed time")?
                    .as_nanos(),
            )
            .context("elapsed time fits u64")?,
            transferred_bytes: self.transferred_bytes,
            completed_operations: self.completed_operations,
            cpu_time_nanos: usage.cpu_nanos,
            peak_rss_bytes: usage.peak_rss_bytes,
            bytes_copied: None,
        })
    }
}

fn transferred(payload_bytes: usize, samples: u32) -> Result<u64> {
    u64::try_from(payload_bytes)?
        .checked_mul(u64::from(samples))
        .and_then(|bytes| bytes.checked_mul(2))
        .context("transferred byte count overflow")
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn join_server(server: thread::JoinHandle<std::io::Result<()>>) -> Result<()> {
    server
        .join()
        .map_err(|_| anyhow::anyhow!("loopback fixture panicked"))??;
    Ok(())
}
