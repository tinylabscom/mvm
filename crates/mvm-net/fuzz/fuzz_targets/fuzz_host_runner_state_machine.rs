// Fuzz the dependency-light host authority runner seam.
//
// `run_host_authority_until_blocked()` sits between framed authority-wire I/O
// and the host authority state machine. The harness contract is "never panic on
// any read/write cadence". Arbitrary bytes become bounded authority-wire reads,
// write failures, and fake connector drain cadence, and the harness drives the
// real runner over a real `HostAuthority` so read/process/write/drain paths are
// exercised without a live runtime or real sockets.

#![no_main]

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use mvm_net::host::{
    HostAdmission, HostAuditSink, HostAuthority, HostAuthorityConfig, HostNetworkPolicy,
    HostRoute, HostTcpConnector, HostTcpEvent, TcpConnectSpec,
};
use mvm_net::host_runner::{
    HostAuthorityRead, HostAuthorityWire, HostRunnerConfig, run_host_authority_until_blocked,
};
use mvm_net::proto::{
    AlpnProtocol, Capability, CloseFlow, CloseReason, DatagramStatus, Denial, DenialReason,
    DnsName, DnsQuery, DnsRecordType, DnsResponse, DnsResponseCode, EndpointRole, FlowDirection,
    FlowId, Hello, HelloAck, IcmpEchoRequest, IcmpEchoResponse, IcmpEchoStatus, NetMessage,
    OpenTcp, PluginId, QueryId, StreamChunk, Target, TcpOpenResult, TlsTermination,
    TlsTransformRoute, TransportError, UdpDatagram, UdpDelivery,
};

const MAX_STEPS: usize = 64;
const MAX_DRAIN_EVENTS: usize = 4;
const MAX_CHUNK_BYTES: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let split = data.len().min(8);
    let (config_bytes, mut cursor) = data.split_at(split);
    let authority_config = build_authority_config(config_bytes);
    let policy = FuzzPolicy::from_config_bytes(config_bytes);
    let connector = FuzzTcpConnector::from_config_bytes(config_bytes);
    let mut authority =
        match HostAuthority::with_config(authority_config, policy, NoopAuditSink, connector) {
            Ok(authority) => authority,
            Err(_) => return,
        };
    let runner_config = HostRunnerConfig::builder()
        .max_messages_per_run(config_bytes.first().map_or(8usize, |value| usize::from(*value % 16) + 1))
        .build()
        .expect("fuzz host runner config must be valid");
    let mut wire = FuzzWire::default();

    let mut steps = 0usize;
    while !cursor.is_empty() && steps < MAX_STEPS {
        let opcode = cursor[0];
        cursor = &cursor[1..];
        let take = cursor
            .first()
            .map_or(0usize, |len| usize::from(*len).min(cursor.len().saturating_sub(1)));
        let payload = if cursor.is_empty() {
            &[][..]
        } else {
            let payload = &cursor[1..1 + take];
            cursor = &cursor[1 + take..];
            payload
        };
        steps += 1;

        wire.reads
            .push_back(build_wire_read(opcode & 0x07, opcode, payload));
        if opcode & 0x40 != 0 {
            wire.fail_next_send = true;
        }

        let _ = run_host_authority_until_blocked(&mut authority, &mut wire, &runner_config);
    }

    for _ in 0..MAX_DRAIN_EVENTS {
        let _ = run_host_authority_until_blocked(&mut authority, &mut wire, &runner_config);
    }
});

#[derive(Debug, Default)]
struct FuzzWire {
    reads: VecDeque<FuzzWireRead>,
    writes: Vec<NetMessage>,
    fail_next_send: bool,
}

#[derive(Debug)]
enum FuzzWireRead {
    Read(HostAuthorityRead),
    Error,
}

impl HostAuthorityWire for FuzzWire {
    type Error = &'static str;

    fn receive_message(&mut self) -> Result<HostAuthorityRead, Self::Error> {
        match self.reads.pop_front() {
            Some(FuzzWireRead::Read(read)) => Ok(read),
            Some(FuzzWireRead::Error) => Err("fuzz wire read failed"),
            None => Ok(HostAuthorityRead::WouldBlock),
        }
    }

    fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
        if self.fail_next_send {
            self.fail_next_send = false;
            return Err("fuzz wire write failed");
        }
        self.writes.push(message);
        Ok(())
    }
}

#[derive(Debug, Default)]
struct NoopAuditSink;

impl HostAuditSink for NoopAuditSink {
    type Error = &'static str;

    fn record(&mut self, _event: mvm_net::host::HostAuditEvent) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct FuzzPolicy {
    allow_dns: bool,
    allow_tcp: bool,
    allow_udp: bool,
    allow_icmp: bool,
    use_resolved_ip: bool,
}

impl FuzzPolicy {
    fn from_config_bytes(bytes: &[u8]) -> Self {
        let bits = bytes.get(1).copied().unwrap_or(0);
        Self {
            allow_dns: bits & 0x01 == 0,
            allow_tcp: bits & 0x02 == 0,
            allow_udp: bits & 0x04 == 0,
            allow_icmp: bits & 0x08 == 0,
            use_resolved_ip: bits & 0x10 != 0,
        }
    }

    fn allow_with_optional_route(&self) -> HostAdmission {
        if self.use_resolved_ip {
            HostAdmission::allowed_with_route(HostRoute::resolved_ip(IpAddr::V4(
                Ipv4Addr::LOCALHOST,
            )))
        } else {
            HostAdmission::allowed()
        }
    }
}

impl HostNetworkPolicy for FuzzPolicy {
    fn decide_dns(&mut self, _query: &DnsQuery) -> HostAdmission {
        if self.allow_dns {
            HostAdmission::allowed()
        } else {
            HostAdmission::denied(DenialReason::NetworkDisabled)
        }
    }

    fn decide_tcp_open(&mut self, _open: &OpenTcp) -> HostAdmission {
        if self.allow_tcp {
            self.allow_with_optional_route()
        } else {
            HostAdmission::denied(DenialReason::HostNotAllowed)
        }
    }

    fn decide_udp_datagram(&mut self, _datagram: &UdpDatagram) -> HostAdmission {
        if self.allow_udp {
            self.allow_with_optional_route()
        } else {
            HostAdmission::denied(DenialReason::ProtocolNotAllowed)
        }
    }

    fn decide_icmp_echo(&mut self, _request: &IcmpEchoRequest) -> HostAdmission {
        if self.allow_icmp {
            self.allow_with_optional_route()
        } else {
            HostAdmission::denied(DenialReason::ProtocolNotAllowed)
        }
    }
}

#[derive(Debug)]
struct FuzzTcpConnector {
    open_flows: HashSet<FlowId>,
    pending_events: VecDeque<HostTcpEvent>,
    error_detail: HashMap<FlowId, String>,
    activity_detail: HashMap<FlowId, String>,
    fail_open: bool,
    fail_send: bool,
    close_as_reset: bool,
    supports_tls_transform: bool,
    supports_stream_transforms: bool,
}

impl FuzzTcpConnector {
    fn from_config_bytes(bytes: &[u8]) -> Self {
        let bits = bytes.get(2).copied().unwrap_or(0);
        let mut pending_events = VecDeque::new();
        if bits & 0x01 != 0 {
            pending_events.push_back(HostTcpEvent::Data(StreamChunk::new(
                flow_id_from_byte(bytes.get(3).copied().unwrap_or(0)),
                FlowDirection::HostToGuest,
                0,
                bounded_bytes(bytes.get(4..).unwrap_or(&[])),
            )));
        }
        if bits & 0x02 != 0 {
            pending_events.push_back(HostTcpEvent::Close(CloseFlow {
                flow_id: flow_id_from_byte(bytes.get(3).copied().unwrap_or(0)),
                reason: if bits & 0x04 != 0 {
                    CloseReason::TransformError
                } else {
                    CloseReason::HostClosed
                },
            }));
        }
        Self {
            open_flows: HashSet::new(),
            pending_events,
            error_detail: HashMap::new(),
            activity_detail: HashMap::new(),
            fail_open: bits & 0x08 != 0,
            fail_send: bits & 0x10 != 0,
            close_as_reset: bits & 0x20 != 0,
            supports_tls_transform: bits & 0x40 != 0,
            supports_stream_transforms: bits & 0x80 != 0,
        }
    }
}

impl HostTcpConnector for FuzzTcpConnector {
    fn open(&mut self, spec: &TcpConnectSpec) -> Result<(), TransportError> {
        if self.fail_open {
            self.error_detail
                .insert(spec.flow_id(), "fuzz open failure".to_string());
            return Err(TransportError::Refused);
        }
        self.open_flows.insert(spec.flow_id());
        Ok(())
    }

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
        if self.fail_send {
            self.error_detail
                .insert(chunk.flow_id, "fuzz send failure".to_string());
            return Err(TransportError::TimedOut);
        }
        self.activity_detail.insert(
            chunk.flow_id,
            format!("bytes={}", chunk.bytes.len()),
        );
        if chunk.end_stream {
            self.pending_events.push_back(HostTcpEvent::Close(CloseFlow {
                flow_id: chunk.flow_id,
                reason: if self.close_as_reset {
                    CloseReason::ProtocolError
                } else {
                    CloseReason::HostClosed
                },
            }));
        }
        Ok(())
    }

    fn close(&mut self, flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        self.open_flows.remove(&flow_id);
        Ok(())
    }

    fn drain_events(&mut self, max_events: usize) -> Result<Vec<HostTcpEvent>, TransportError> {
        let mut drained = Vec::new();
        for _ in 0..max_events {
            let Some(event) = self.pending_events.pop_front() else {
                break;
            };
            drained.push(event);
        }
        Ok(drained)
    }

    fn supports_tls_transform(&self) -> bool {
        self.supports_tls_transform
    }

    fn supports_stream_transforms(&self) -> bool {
        self.supports_stream_transforms
    }

    fn validate_stream_transforms(
        &self,
        transform_chain: &[PluginId],
        _target_host: Option<&str>,
    ) -> Result<(), String> {
        for plugin in transform_chain {
            match plugin.as_str() {
                "audit" | "metadata-endpoint-deny" | "secret-replacement" | "response-leak-guard" => {}
                _ => {
                    return Err("unsupported stream transform plugin".to_string());
                }
            }
        }
        Ok(())
    }

    fn take_error_detail(&mut self, flow_id: FlowId) -> Option<String> {
        self.error_detail.remove(&flow_id)
    }

    fn take_activity_detail(&mut self, flow_id: FlowId) -> Option<String> {
        self.activity_detail.remove(&flow_id)
    }
}

fn build_authority_config(bytes: &[u8]) -> HostAuthorityConfig {
    HostAuthorityConfig::builder()
        .max_open_flows(bytes.first().map_or(4usize, |value| usize::from(*value % 8) + 1))
        .max_guest_requests_per_window(bytes.get(4).map_or(16usize, |value| usize::from(*value % 32) + 1))
        .guest_request_rate_window(std::time::Duration::from_secs(1))
        .capabilities(capabilities_from_bits(bytes.get(5).copied().unwrap_or(0)))
        .build()
        .expect("fuzz host authority config must be valid")
}

fn build_wire_read(selector: u8, opcode: u8, payload: &[u8]) -> FuzzWireRead {
    match selector % 6 {
        0 => FuzzWireRead::Read(HostAuthorityRead::Message(build_message(opcode, payload))),
        1 => FuzzWireRead::Read(HostAuthorityRead::WouldBlock),
        2 => FuzzWireRead::Read(HostAuthorityRead::Closed),
        3 => FuzzWireRead::Error,
        4 | 5 => FuzzWireRead::Read(HostAuthorityRead::Message(build_message(
            opcode.wrapping_add(selector),
            payload,
        ))),
        _ => FuzzWireRead::Read(HostAuthorityRead::WouldBlock),
    }
}

fn build_message(opcode: u8, payload: &[u8]) -> NetMessage {
    match opcode % 12 {
        0 => NetMessage::Hello(Hello::new(
            if opcode & 1 == 0 {
                EndpointRole::Guest
            } else {
                EndpointRole::Host
            },
            capabilities_from_bits(payload.first().copied().unwrap_or(0)),
        )),
        1 => NetMessage::OpenTcp(build_open_tcp(payload)),
        2 => NetMessage::TcpData(build_stream_chunk(payload)),
        3 => NetMessage::CloseFlow(CloseFlow {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            reason: close_reason_from_byte(payload.get(1).copied().unwrap_or(0)),
        }),
        4 => NetMessage::DnsQuery(DnsQuery {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            name: DnsName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
                .expect("fixed DNS name must be valid"),
            record_type: dns_record_type_from_byte(payload.get(2).copied().unwrap_or(0)),
        }),
        5 => NetMessage::UdpDatagram(UdpDatagram {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            target: Target::new(
                host_for_byte(payload.get(1).copied().unwrap_or(0)),
                port_for_byte(payload.get(2).copied().unwrap_or(0)),
            )
            .expect("fixed UDP target must be valid"),
            direction: if payload.get(3).copied().unwrap_or(0) & 1 == 0 {
                FlowDirection::GuestToHost
            } else {
                FlowDirection::HostToGuest
            },
            bytes: bounded_bytes(payload.get(4..).unwrap_or(&[])),
        }),
        6 => NetMessage::IcmpEchoRequest(IcmpEchoRequest {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            host: mvm_net::proto::HostName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
                .expect("fixed ICMP host must be valid"),
            payload_len: u16::from(payload.get(2).copied().unwrap_or(0)),
        }),
        7 => NetMessage::HelloAck(HelloAck::new(capabilities_from_bits(
            payload.first().copied().unwrap_or(0),
        ))),
        8 => NetMessage::TcpOpenResult(TcpOpenResult::failed(
            flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            transport_error_from_byte(payload.get(1).copied().unwrap_or(0)),
        )),
        9 => NetMessage::DnsResponse(DnsResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            code: DnsResponseCode::Refused,
            answers: Vec::new(),
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        }),
        10 => NetMessage::UdpDelivery(UdpDelivery {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: DatagramStatus::Failed(TransportError::ProtocolError),
        }),
        11 => NetMessage::IcmpEchoResponse(IcmpEchoResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: IcmpEchoStatus::Denied,
            round_trip_micros: None,
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        }),
        _ => NetMessage::HelloAck(HelloAck::new(Vec::new())),
    }
}

fn build_open_tcp(payload: &[u8]) -> OpenTcp {
    let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
    let host = host_for_byte(payload.get(1).copied().unwrap_or(0));
    let port = port_for_byte(payload.get(2).copied().unwrap_or(0));
    let target = Target::new(host, port).expect("fixed target must be valid");
    let mut open = OpenTcp::new(flow_id, target);
    if payload.get(3).copied().unwrap_or(0) & 0x01 != 0 {
        let server_name =
            DnsName::new(host_for_byte(payload.get(4).copied().unwrap_or(0))).expect("fixed DNS name");
        let termination = if payload.get(3).copied().unwrap_or(0) & 0x02 == 0 {
            TlsTermination::TerminateAndReoriginate
        } else {
            TlsTermination::RefusePinnedClient
        };
        let mut route = TlsTransformRoute::new(server_name, termination);
        if payload.get(3).copied().unwrap_or(0) & 0x04 != 0 {
            route = route.with_alpn_protocols(vec![
                AlpnProtocol::new("h2").expect("fixed ALPN must be valid"),
            ]);
        }
        let plugins = plugin_chain_for_byte(payload.get(5).copied().unwrap_or(0));
        if !plugins.is_empty() {
            route = route.with_transform_chain(plugins);
        }
        open = open.with_tls_transform(route);
    }
    open
}

fn build_stream_chunk(payload: &[u8]) -> StreamChunk {
    let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
    let direction = if payload.get(1).copied().unwrap_or(0) & 1 == 0 {
        FlowDirection::GuestToHost
    } else {
        FlowDirection::HostToGuest
    };
    let sequence = u64::from(payload.get(2).copied().unwrap_or(0));
    let chunk = StreamChunk::new(flow_id, direction, sequence, bounded_bytes(payload.get(3..).unwrap_or(&[])));
    if payload.get(1).copied().unwrap_or(0) & 0x02 != 0 {
        return chunk.with_end_stream();
    }
    chunk
}

fn bounded_bytes(payload: &[u8]) -> Vec<u8> {
    payload.iter().copied().take(MAX_CHUNK_BYTES).collect()
}

fn capabilities_from_bits(bits: u8) -> Vec<Capability> {
    let mut capabilities = vec![
        Capability::Dns,
        Capability::Tcp,
        Capability::AuditCorrelation,
        Capability::PolicyDigest,
    ];
    if bits & 0x01 != 0 {
        capabilities.push(Capability::Udp);
    }
    if bits & 0x02 != 0 {
        capabilities.push(Capability::IcmpEcho);
    }
    if bits & 0x04 != 0 {
        capabilities.push(Capability::TlsTransform);
    }
    if bits & 0x08 != 0 {
        capabilities.push(Capability::StreamTransforms);
    }
    capabilities
}

fn plugin_chain_for_byte(value: u8) -> Vec<PluginId> {
    match value % 5 {
        0 => Vec::new(),
        1 => vec![PluginId::new("audit").expect("fixed plugin id must be valid")],
        2 => vec![PluginId::new("metadata-endpoint-deny").expect("fixed plugin id must be valid")],
        3 => vec![PluginId::new("secret-replacement").expect("fixed plugin id must be valid")],
        _ => vec![PluginId::new("response-leak-guard").expect("fixed plugin id must be valid")],
    }
}

fn flow_id_from_byte(value: u8) -> FlowId {
    FlowId::new(u64::from(value) + 1).expect("fuzz flow id must be non-zero")
}

fn query_id_from_byte(value: u8) -> QueryId {
    QueryId::new(u64::from(value) + 1).expect("fuzz query id must be non-zero")
}

fn host_for_byte(value: u8) -> &'static str {
    match value % 5 {
        0 => "example.com",
        1 => "api.example.com",
        2 => "metadata.google.internal",
        3 => "localhost",
        _ => "test.invalid",
    }
}

fn port_for_byte(value: u8) -> u16 {
    match value % 5 {
        0 => 53,
        1 => 80,
        2 => 443,
        3 => 8080,
        _ => 22,
    }
}

fn dns_record_type_from_byte(value: u8) -> DnsRecordType {
    match value % 4 {
        0 => DnsRecordType::A,
        1 => DnsRecordType::Aaaa,
        2 => DnsRecordType::Cname,
        _ => DnsRecordType::Txt,
    }
}

fn transport_error_from_byte(value: u8) -> TransportError {
    match value % 7 {
        0 => TransportError::DnsFailed,
        1 => TransportError::TimedOut,
        2 => TransportError::Refused,
        3 => TransportError::Unreachable,
        4 => TransportError::Reset,
        5 => TransportError::TlsHandshakeFailed,
        _ => TransportError::ProtocolError,
    }
}

fn close_reason_from_byte(value: u8) -> CloseReason {
    match value % 5 {
        0 => CloseReason::GuestClosed,
        1 => CloseReason::HostClosed,
        2 => CloseReason::PolicyDenied,
        3 => CloseReason::ProtocolError,
        _ => CloseReason::TransformError,
    }
}
