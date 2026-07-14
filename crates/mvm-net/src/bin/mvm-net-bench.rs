use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use cpu_time::ProcessTime;
use mvm_net::guest::DEFAULT_GUEST_ADDRESS;
use mvm_net::guest_packet::{
    GuestPacketTranslator, GuestPacketTranslatorConfig, OutboundPacketEvent,
};
use mvm_net::host::{
    AllowAllHostPolicy, HostAuthority, HostTcpConnector, HostTcpEvent, NoopHostAuditSink,
    TcpConnectSpec,
};
use mvm_net::host_runner::{
    HostAuthorityRead, HostAuthorityWire, HostRunnerConfig, run_host_authority_until_blocked,
};
use mvm_net::proto::{
    Capability, CloseFlow, CloseReason, DnsAnswer, DnsName, DnsQuery, DnsRecordData, DnsRecordType,
    DnsResponse, DnsResponseCode, EndpointRole, FlowDirection, FlowId, Hello,
    MAX_STREAM_CHUNK_BYTES, NetMessage, OpenTcp, QueryId, StreamChunk, Target, TransportError,
};

const DEFAULT_LATENCY_ITERATIONS: usize = 50_000;
const DEFAULT_AUTHORITY_ITERATIONS: usize = 50_000;
const DEFAULT_THROUGHPUT_CHUNKS: usize = 4_096;
const DEFAULT_PAYLOAD_BYTES: usize = 4 * 1024;
const DEFAULT_WARMUP_ITERATIONS: usize = 1_024;
const MAX_LATENCY_ITERATIONS: usize = DEFAULT_LATENCY_ITERATIONS;
const MAX_AUTHORITY_ITERATIONS: usize = DEFAULT_AUTHORITY_ITERATIONS;
const MAX_THROUGHPUT_CHUNKS: usize = DEFAULT_THROUGHPUT_CHUNKS;
const MAX_PAYLOAD_BYTES: usize = MAX_STREAM_CHUNK_BYTES;
const MAX_WARMUP_ITERATIONS: usize = DEFAULT_WARMUP_ITERATIONS;
const BENCH_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(198, 19, 0, 1);
const BENCH_SYNTHETIC_HOST: Ipv4Addr = Ipv4Addr::new(198, 19, 0, 42);

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchConfig {
    latency_iterations: usize,
    authority_iterations: usize,
    throughput_chunks: usize,
    payload_bytes: usize,
    warmup_iterations: usize,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            latency_iterations: DEFAULT_LATENCY_ITERATIONS,
            authority_iterations: DEFAULT_AUTHORITY_ITERATIONS,
            throughput_chunks: DEFAULT_THROUGHPUT_CHUNKS,
            payload_bytes: DEFAULT_PAYLOAD_BYTES,
            warmup_iterations: DEFAULT_WARMUP_ITERATIONS,
        }
    }
}

impl BenchConfig {
    fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config = Self::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--latency-iterations" => {
                    config.latency_iterations = parse_bounded_non_zero_usize(
                        args.next(),
                        "--latency-iterations",
                        MAX_LATENCY_ITERATIONS,
                    )?;
                }
                "--authority-iterations" => {
                    config.authority_iterations = parse_bounded_non_zero_usize(
                        args.next(),
                        "--authority-iterations",
                        MAX_AUTHORITY_ITERATIONS,
                    )?;
                }
                "--throughput-chunks" => {
                    config.throughput_chunks = parse_bounded_non_zero_usize(
                        args.next(),
                        "--throughput-chunks",
                        MAX_THROUGHPUT_CHUNKS,
                    )?;
                }
                "--payload-bytes" => {
                    config.payload_bytes = parse_bounded_non_zero_usize(
                        args.next(),
                        "--payload-bytes",
                        MAX_PAYLOAD_BYTES,
                    )?;
                }
                "--warmup-iterations" => {
                    config.warmup_iterations = parse_bounded_non_zero_usize(
                        args.next(),
                        "--warmup-iterations",
                        MAX_WARMUP_ITERATIONS,
                    )?;
                }
                "--help" | "-h" => {
                    return Err(usage());
                }
                other => {
                    return Err(format!("unrecognized argument {other:?}\n\n{}", usage()));
                }
            }
        }
        Ok(config)
    }
}

fn parse_bounded_non_zero_usize(
    value: Option<String>,
    flag: &str,
    max: usize,
) -> Result<usize, String> {
    let value = value.ok_or_else(|| format!("missing value for {flag}\n\n{}", usage()))?;
    let parsed = value
        .parse::<usize>()
        .map_err(|err| format!("invalid value for {flag}: {err}\n\n{}", usage()))?;
    if parsed == 0 {
        return Err(format!("{flag} must be non-zero\n\n{}", usage()));
    }
    if parsed > max {
        return Err(format!(
            "{flag} exceeds the hard maximum ({parsed} > {max})\n\n{}",
            usage()
        ));
    }
    Ok(parsed)
}

fn usage() -> String {
    [
        "Usage: cargo run -p mvm-net --bin mvm-net-bench --features bench -- [options]",
        "",
        "Options:",
        "  --latency-iterations <count>   Guest DNS round-trip iterations",
        "  --authority-iterations <count> Host authority DNS iterations",
        "  --throughput-chunks <count>    Host runner TCP chunks per run",
        "  --payload-bytes <count>        Bytes per benchmarked TCP chunk",
        "  --warmup-iterations <count>    Warm-up iterations before measurement",
    ]
    .join("\n")
}

#[derive(Debug, Clone)]
struct BenchResult {
    name: &'static str,
    operations: usize,
    bytes: usize,
    wall: Duration,
    cpu: Duration,
}

impl BenchResult {
    fn render(&self) -> String {
        let wall_per_op = nanos_per_operation(self.wall, self.operations);
        let cpu_per_op = nanos_per_operation(self.cpu, self.operations);
        let mut line = format!(
            "{:<28} ops={:<8} wall/op={:>10.0}ns cpu/op={:>10.0}ns",
            self.name, self.operations, wall_per_op, cpu_per_op
        );
        if self.bytes > 0 {
            let _ = write!(
                line,
                " bytes={:<10} wall={:>8.1} MiB/s cpu={:>8.1} MiB/s",
                self.bytes,
                mib_per_second(self.bytes, self.wall),
                mib_per_second(self.bytes, self.cpu)
            );
        }
        let _ = write!(line, " cpu/wall={:.2}", duration_ratio(self.cpu, self.wall));
        line
    }
}

fn nanos_per_operation(duration: Duration, operations: usize) -> f64 {
    duration.as_secs_f64() * 1_000_000_000.0 / operations as f64
}

fn mib_per_second(bytes: usize, duration: Duration) -> f64 {
    if duration.is_zero() {
        return f64::INFINITY;
    }
    bytes as f64 / duration.as_secs_f64() / (1024.0 * 1024.0)
}

fn duration_ratio(numerator: Duration, denominator: Duration) -> f64 {
    if denominator.is_zero() {
        return 0.0;
    }
    numerator.as_secs_f64() / denominator.as_secs_f64()
}

fn main() -> Result<(), String> {
    let config = BenchConfig::parse(std::env::args().skip(1))?;

    let guest_packet = build_guest_dns_packet("example.com")?;
    let payload = vec![0x5a; config.payload_bytes];
    warm_up(&config, &guest_packet, &payload)?;

    let guest_dns = bench_guest_dns_round_trip(&config, &guest_packet)?;
    let host_dns = bench_host_authority_dns(&config)?;
    let runner_tcp = bench_host_runner_tcp_stream(&config, &payload)?;

    println!("{}", guest_dns.render());
    println!("{}", host_dns.render());
    println!("{}", runner_tcp.render());
    Ok(())
}

fn warm_up(config: &BenchConfig, guest_packet: &[u8], payload: &[u8]) -> Result<(), String> {
    let warmup = BenchConfig {
        latency_iterations: config.warmup_iterations,
        authority_iterations: config.warmup_iterations,
        throughput_chunks: config.warmup_iterations,
        payload_bytes: payload.len(),
        warmup_iterations: 0,
    };
    let _ = bench_guest_dns_round_trip(&warmup, guest_packet)?;
    let _ = bench_host_authority_dns(&warmup)?;
    let _ = bench_host_runner_tcp_stream(&warmup, payload)?;
    Ok(())
}

fn bench_guest_dns_round_trip(config: &BenchConfig, packet: &[u8]) -> Result<BenchResult, String> {
    let mut translator = GuestPacketTranslator::new(GuestPacketTranslatorConfig::default());
    let mut total_bytes = 0usize;
    let cpu_start = ProcessTime::now();
    let wall_start = Instant::now();
    for _ in 0..config.latency_iterations {
        let events = translator
            .translate_outbound_ipv4(packet)
            .map_err(|err| format!("guest DNS benchmark translation failed: {err}"))?;
        let query = first_dns_query(&events)?;
        let response = DnsResponse {
            query_id: query.query_id,
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name: query.name.clone(),
                record_type: DnsRecordType::A,
                data: DnsRecordData::Ip(IpAddr::V4(BENCH_SYNTHETIC_HOST)),
                ttl_seconds: 30,
            }],
            denial: None,
        };
        let response_packet = translator
            .synthesize_dns_response(&response)
            .map_err(|err| format!("guest DNS benchmark synthesis failed: {err}"))?;
        total_bytes += packet.len() + response_packet.len();
    }
    Ok(BenchResult {
        name: "guest_dns_round_trip",
        operations: config.latency_iterations,
        bytes: total_bytes,
        wall: wall_start.elapsed(),
        cpu: cpu_start.elapsed(),
    })
}

fn first_dns_query(events: &[OutboundPacketEvent]) -> Result<&DnsQuery, String> {
    match events {
        [OutboundPacketEvent::DnsQuery(query)] => Ok(query),
        other => Err(format!(
            "expected exactly one DNS query event, got {other:?}"
        )),
    }
}

fn bench_host_authority_dns(config: &BenchConfig) -> Result<BenchResult, String> {
    let mut authority = HostAuthority::new(
        AllowAllHostPolicy,
        NoopHostAuditSink,
        CountingConnector::default(),
    );
    let name = DnsName::new("example.com").map_err(|err| err.to_string())?;
    let cpu_start = ProcessTime::now();
    let wall_start = Instant::now();
    for query_id in 1..=config.authority_iterations {
        let message = NetMessage::DnsQuery(DnsQuery {
            query_id: QueryId::new(query_id as u64).map_err(|err| err.to_string())?,
            name: name.clone(),
            record_type: DnsRecordType::A,
        });
        let responses = authority
            .handle_message(message)
            .map_err(|err| format!("host authority DNS benchmark failed: {err}"))?;
        if responses.len() != 1 || !matches!(responses[0], NetMessage::DnsResponse(_)) {
            return Err(format!(
                "unexpected host authority DNS responses: {responses:?}"
            ));
        }
    }
    Ok(BenchResult {
        name: "host_authority_dns",
        operations: config.authority_iterations,
        bytes: 0,
        wall: wall_start.elapsed(),
        cpu: cpu_start.elapsed(),
    })
}

fn bench_host_runner_tcp_stream(
    config: &BenchConfig,
    payload: &[u8],
) -> Result<BenchResult, String> {
    let mut authority = HostAuthority::new(
        AllowAllHostPolicy,
        NoopHostAuditSink,
        CountingConnector::default(),
    );
    let flow_id = FlowId::new(1).map_err(|err| err.to_string())?;
    let target = Target::new("api.example.com", 443).map_err(|err| err.to_string())?;
    let mut reads = VecDeque::with_capacity(config.throughput_chunks + 4);
    reads.push_back(HostAuthorityRead::Message(NetMessage::Hello(Hello::new(
        EndpointRole::Guest,
        vec![Capability::Tcp],
    ))));
    reads.push_back(HostAuthorityRead::Message(NetMessage::OpenTcp(
        OpenTcp::new(flow_id, target),
    )));
    for sequence in 0..config.throughput_chunks {
        reads.push_back(HostAuthorityRead::Message(NetMessage::TcpData(
            StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                (sequence * payload.len()) as u64,
                payload.to_vec(),
            ),
        )));
    }
    reads.push_back(HostAuthorityRead::Message(NetMessage::CloseFlow(
        CloseFlow {
            flow_id,
            reason: CloseReason::GuestClosed,
        },
    )));
    reads.push_back(HostAuthorityRead::WouldBlock);
    let mut wire = MemoryWire::with_reads(reads);
    let runner_config = HostRunnerConfig::builder()
        .max_messages_per_run(config.throughput_chunks + 8)
        .build()
        .map_err(|err| err.to_string())?;
    let cpu_start = ProcessTime::now();
    let wall_start = Instant::now();
    let stats = run_host_authority_until_blocked(&mut authority, &mut wire, &runner_config)
        .map_err(|err| format!("host runner TCP benchmark failed: {err}"))?;
    let wall = wall_start.elapsed();
    let cpu = cpu_start.elapsed();
    let expected_reads = config.throughput_chunks + 3;
    if stats.messages_read != expected_reads {
        return Err(format!(
            "unexpected host runner reads: expected {expected_reads}, got {}",
            stats.messages_read
        ));
    }
    let connector = authority.tcp_connector_mut();
    if connector.open_count != 1 {
        return Err(format!(
            "expected exactly one TCP open in benchmark connector, got {}",
            connector.open_count
        ));
    }
    if connector.sent_bytes != config.throughput_chunks * payload.len() {
        return Err(format!(
            "unexpected benchmark connector byte count: expected {}, got {}",
            config.throughput_chunks * payload.len(),
            connector.sent_bytes
        ));
    }
    Ok(BenchResult {
        name: "host_runner_tcp_stream",
        operations: config.throughput_chunks,
        bytes: config.throughput_chunks * payload.len(),
        wall,
        cpu,
    })
}

#[derive(Debug, Default)]
struct MemoryWire {
    reads: VecDeque<HostAuthorityRead>,
    writes: Vec<NetMessage>,
}

impl MemoryWire {
    fn with_reads(reads: VecDeque<HostAuthorityRead>) -> Self {
        Self {
            reads,
            writes: Vec::new(),
        }
    }
}

impl HostAuthorityWire for MemoryWire {
    type Error = &'static str;

    fn receive_message(&mut self) -> Result<HostAuthorityRead, Self::Error> {
        Ok(self.reads.pop_front().unwrap_or(HostAuthorityRead::Closed))
    }

    fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
        self.writes.push(message);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct CountingConnector {
    open_count: usize,
    sent_bytes: usize,
    closed_count: usize,
}

impl HostTcpConnector for CountingConnector {
    fn open(&mut self, _spec: &TcpConnectSpec) -> Result<(), TransportError> {
        self.open_count += 1;
        Ok(())
    }

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
        self.sent_bytes += chunk.bytes.len();
        Ok(())
    }

    fn close(&mut self, _flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        self.closed_count += 1;
        Ok(())
    }

    fn drain_events(&mut self, _max_events: usize) -> Result<Vec<HostTcpEvent>, TransportError> {
        Ok(Vec::new())
    }
}

fn build_guest_dns_packet(name: &str) -> Result<Vec<u8>, String> {
    udp_ipv4_packet(
        49152,
        BENCH_DNS_SERVER,
        53,
        dns_query_payload(0x1234, name, 1).as_slice(),
    )
}

fn dns_query_payload(tx_id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&tx_id.to_be_bytes());
    payload.extend_from_slice(&0x0100u16.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(encode_dns_name(name).as_slice());
    payload.extend_from_slice(&qtype.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

fn udp_ipv4_packet(
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    build_ipv4_packet(
        DEFAULT_GUEST_ADDRESS,
        dst_ip,
        17,
        build_udp_packet(src_port, dst_port, payload)?.as_slice(),
    )
}

fn build_udp_packet(src_port: u16, dst_port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    let total_len = 8usize
        .checked_add(payload.len())
        .ok_or_else(|| "UDP payload length overflow".to_string())?;
    let length = u16::try_from(total_len).map_err(|_| "UDP payload too large".to_string())?;
    let mut udp = Vec::with_capacity(total_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&length.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(payload);
    Ok(udp)
}

fn build_ipv4_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let total_len = 20usize
        .checked_add(payload.len())
        .ok_or_else(|| "IPv4 payload length overflow".to_string())?;
    let total_len = u16::try_from(total_len).map_err(|_| "IPv4 payload too large".to_string())?;
    let mut packet = Vec::with_capacity(total_len as usize);
    packet.push((4u8 << 4) | 5);
    packet.push(0);
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.push(64);
    packet.push(protocol);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());
    let checksum = internet_checksum(packet.as_slice());
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::{
        BenchConfig, MAX_LATENCY_ITERATIONS, MAX_PAYLOAD_BYTES, duration_ratio, mib_per_second,
        nanos_per_operation, parse_bounded_non_zero_usize,
    };
    use std::time::Duration;

    #[test]
    fn parse_rejects_zero_values() {
        let err = parse_bounded_non_zero_usize(
            Some("0".to_string()),
            "--payload-bytes",
            MAX_PAYLOAD_BYTES,
        )
        .expect_err("zero benchmark flag must fail");
        assert!(err.contains("--payload-bytes must be non-zero"));
    }

    #[test]
    fn parse_rejects_oversized_values() {
        let err = parse_bounded_non_zero_usize(
            Some((MAX_PAYLOAD_BYTES + 1).to_string()),
            "--payload-bytes",
            MAX_PAYLOAD_BYTES,
        )
        .expect_err("oversized payload benchmark flag must fail");
        assert!(err.contains("--payload-bytes exceeds the hard maximum"));

        let err = parse_bounded_non_zero_usize(
            Some((MAX_LATENCY_ITERATIONS + 1).to_string()),
            "--latency-iterations",
            MAX_LATENCY_ITERATIONS,
        )
        .expect_err("oversized iteration benchmark flag must fail");
        assert!(err.contains("--latency-iterations exceeds the hard maximum"));
    }

    #[test]
    fn parse_accepts_explicit_values() {
        let parsed = BenchConfig::parse([
            "--latency-iterations".to_string(),
            "5".to_string(),
            "--authority-iterations".to_string(),
            "7".to_string(),
            "--throughput-chunks".to_string(),
            "9".to_string(),
            "--payload-bytes".to_string(),
            "11".to_string(),
            "--warmup-iterations".to_string(),
            "13".to_string(),
        ])
        .expect("benchmark args should parse");
        assert_eq!(
            parsed,
            BenchConfig {
                latency_iterations: 5,
                authority_iterations: 7,
                throughput_chunks: 9,
                payload_bytes: 11,
                warmup_iterations: 13,
            }
        );
    }

    #[test]
    fn metrics_helpers_are_stable() {
        let duration = Duration::from_millis(10);
        assert_eq!(nanos_per_operation(duration, 10), 1_000_000.0);
        assert!(mib_per_second(1024 * 1024, Duration::from_secs(1)) >= 1.0);
        assert_eq!(duration_ratio(Duration::from_millis(5), duration), 0.5);
    }
}
