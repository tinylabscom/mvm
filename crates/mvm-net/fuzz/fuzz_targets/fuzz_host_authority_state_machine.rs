// Fuzz the dependency-light host authority state machine.
//
// `HostAuthority` is the first host-side runtime boundary after framed guest
// authority messages are decoded. The harness contract is "never panic on any
// message sequence or connector-event cadence". Arbitrary bytes become a
// bounded sequence of guest messages plus connector-side behavior, and the
// harness drives both `handle_message()` and `drain_messages()` over a fake TCP
// connector so open/send/close/drain paths are exercised without real sockets.

#![no_main]

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use mvm_net::host::{
    HostAdmission, HostAuditSink, HostAuthority, HostAuthorityConfig, HostNetworkPolicy,
    HostRoute, HostTcpConnector, HostTcpEvent, TcpConnectSpec,
};
use mvm_net::proto::{
    AlpnProtocol, Capability, CloseFlow, CloseReason, DatagramStatus, Denial, DenialReason,
    DnsName, DnsQuery, DnsRecordType, DnsResponse, DnsResponseCode, EndpointRole, FlowDirection,
    FlowId, Hello, HelloAck, IcmpEchoRequest, IcmpEchoResponse, IcmpEchoStatus, NetMessage,
    OpenTcp, PluginId, QueryId, StreamChunk, Target, TcpOpenResult, TlsTermination,
    TlsTransformRoute, TransportError, UdpDatagram, UdpDelivery,
};

const MAX_STEPS: usize = 64;
const MAX_RESPONSE_DRAINS_PER_STEP: usize = 4;
const MAX_CHUNK_BYTES: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let split = data.len().min(8);
    let (config_bytes, mut cursor) = data.split_at(split);
    let config = build_config(config_bytes);
    let policy = FuzzPolicy::from_config_bytes(config_bytes);
    let connector = FuzzTcpConnector::from_config_bytes(config_bytes);
    let mut authority = match HostAuthority::with_config(config, policy, NoopAuditSink, connector) {
        Ok(authority) => authority,
        Err(_) => return,
    };

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

        if let Some(message) = build_message(opcode, payload) {
            let _ = authority.handle_message(message);
        }

        for drain_index in 0..MAX_RESPONSE_DRAINS_PER_STEP {
            let max_messages = payload
                .get(drain_index)
                .map_or(1usize, |value| usize::from(*value % 8));
            let _ = authority.drain_messages(max_messages);
        }
    }

    for _ in 0..MAX_RESPONSE_DRAINS_PER_STEP {
        let _ = authority.drain_messages(8);
    }
});

fn build_config(bytes: &[u8]) -> HostAuthorityConfig {
    let max_open_flows = bytes.first().map_or(4usize, |value| usize::from(*value % 8) + 1);
    let max_guest_requests_per_window =
        bytes.get(1).map_or(16usize, |value| usize::from(*value % 32) + 1);
    let capabilities = capabilities_from_bits(bytes.get(2).copied().unwrap_or(0));
    HostAuthorityConfig::builder()
        .max_open_flows(max_open_flows)
        .max_guest_requests_per_window(max_guest_requests_per_window)
        .guest_request_rate_window(Duration::from_secs(1))
        .capabilities(capabilities)
        .build()
        .expect("fuzz host authority config must be valid")
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

fn build_message(opcode: u8, payload: &[u8]) -> Option<NetMessage> {
    match opcode % 12 {
        0 => Some(NetMessage::Hello(build_hello(payload))),
        1 => Some(NetMessage::OpenTcp(build_open_tcp(payload))),
        2 => Some(NetMessage::TcpData(build_stream_chunk(payload))),
        3 => Some(NetMessage::CloseFlow(build_close_flow(payload))),
        4 => Some(NetMessage::DnsQuery(build_dns_query(payload))),
        5 => Some(NetMessage::UdpDatagram(build_udp_datagram(payload))),
        6 => Some(NetMessage::IcmpEchoRequest(build_icmp_echo_request(payload))),
        7 => Some(NetMessage::HelloAck(HelloAck::new(capabilities_from_bits(
            payload.first().copied().unwrap_or(0),
        )))),
        8 => Some(NetMessage::TcpOpenResult(TcpOpenResult::failed(
            flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            transport_error_from_byte(payload.get(1).copied().unwrap_or(0)),
        ))),
        9 => Some(NetMessage::DnsResponse(DnsResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            code: DnsResponseCode::Refused,
            answers: Vec::new(),
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        })),
        10 => Some(NetMessage::UdpDelivery(UdpDelivery {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: DatagramStatus::Failed(TransportError::ProtocolError),
        })),
        11 => Some(NetMessage::IcmpEchoResponse(IcmpEchoResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: IcmpEchoStatus::Denied,
            round_trip_micros: None,
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        })),
        _ => None,
    }
}

fn build_hello(payload: &[u8]) -> Hello {
    let role = if payload.first().copied().unwrap_or(0) & 1 == 0 {
        EndpointRole::Guest
    } else {
        EndpointRole::Host
    };
    Hello::new(
        role,
        capabilities_from_bits(payload.get(1).copied().unwrap_or(0)),
    )
}

fn build_open_tcp(payload: &[u8]) -> OpenTcp {
    let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
    let host = host_for_byte(payload.get(1).copied().unwrap_or(0));
    let port = port_for_byte(payload.get(2).copied().unwrap_or(0));
    let target = Target::new(host, port).expect("fixed fuzz target must be valid");
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
    let bytes = payload
        .get(3..)
        .unwrap_or(&[])
        .iter()
        .copied()
        .take(MAX_CHUNK_BYTES)
        .collect::<Vec<_>>();
    let chunk = StreamChunk::new(flow_id, direction, sequence, bytes);
    if payload.get(1).copied().unwrap_or(0) & 0x02 != 0 {
        return chunk.with_end_stream();
    }
    chunk
}

fn build_close_flow(payload: &[u8]) -> CloseFlow {
    CloseFlow {
        flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
        reason: close_reason_from_byte(payload.get(1).copied().unwrap_or(0)),
    }
}

fn build_dns_query(payload: &[u8]) -> DnsQuery {
    DnsQuery {
        query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
        name: DnsName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
            .expect("fixed DNS name must be valid"),
        record_type: dns_record_type_from_byte(payload.get(2).copied().unwrap_or(0)),
    }
}

fn build_udp_datagram(payload: &[u8]) -> UdpDatagram {
    UdpDatagram {
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
        bytes: payload
            .get(4..)
            .unwrap_or(&[])
            .iter()
            .copied()
            .take(MAX_CHUNK_BYTES)
            .collect(),
    }
}

fn build_icmp_echo_request(payload: &[u8]) -> IcmpEchoRequest {
    IcmpEchoRequest {
        query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
        host: mvm_net::proto::HostName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
            .expect("fixed ICMP host must be valid"),
        payload_len: u16::from(payload.get(2).copied().unwrap_or(0)),
    }
}

fn flow_id_from_byte(value: u8) -> FlowId {
    FlowId::new(u64::from(value) + 1).expect("fuzz flow id must be non-zero")
}

fn query_id_from_byte(value: u8) -> QueryId {
    QueryId::new(u64::from(value) + 1).expect("fuzz query id must be non-zero")
}

fn host_for_byte(value: u8) -> &'static str {
    match value % 6 {
        0 => "api.example.com",
        1 => "one.example",
        2 => "two.example",
        3 => "example.com",
        4 => "metadata.google.internal",
        _ => "localhost",
    }
}

fn port_for_byte(value: u8) -> u16 {
    match value % 4 {
        0 => 80,
        1 => 443,
        2 => 8080,
        _ => 53,
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

fn close_reason_from_byte(value: u8) -> CloseReason {
    match value % 5 {
        0 => CloseReason::GuestClosed,
        1 => CloseReason::HostClosed,
        2 => CloseReason::PolicyDenied,
        3 => CloseReason::ProtocolError,
        _ => CloseReason::TransformError,
    }
}

fn transport_error_from_byte(value: u8) -> TransportError {
    match value % 8 {
        0 => TransportError::DnsFailed,
        1 => TransportError::TimedOut,
        2 => TransportError::Refused,
        3 => TransportError::Unreachable,
        4 => TransportError::Reset,
        5 => TransportError::TlsHandshakeFailed,
        6 => TransportError::ProtocolError,
        _ => TransportError::TransformError,
    }
}

fn plugin_chain_for_byte(value: u8) -> Vec<PluginId> {
    match value % 6 {
        0 => Vec::new(),
        1 => vec![PluginId::new("audit").expect("fixed plugin id must be valid")],
        2 => vec![
            PluginId::new("metadata-endpoint-deny").expect("fixed plugin id must be valid"),
        ],
        3 => vec![
            PluginId::new("audit").expect("fixed plugin id must be valid"),
            PluginId::new("metadata-endpoint-deny").expect("fixed plugin id must be valid"),
        ],
        4 => vec![
            PluginId::new("secret-replacement").expect("fixed plugin id must be valid"),
        ],
        _ => vec![
            PluginId::new("response-leak-guard").expect("fixed plugin id must be valid"),
        ],
    }
}

#[derive(Debug, Clone, Copy)]
struct FuzzPolicy {
    allow_dns: bool,
    allow_tcp: bool,
    allow_udp: bool,
    allow_icmp: bool,
    resolved_routes: bool,
}

impl FuzzPolicy {
    fn from_config_bytes(bytes: &[u8]) -> Self {
        let bits = bytes.get(3).copied().unwrap_or(u8::MAX);
        Self {
            allow_dns: bits & 0x01 != 0,
            allow_tcp: bits & 0x02 != 0,
            allow_udp: bits & 0x04 != 0,
            allow_icmp: bits & 0x08 != 0,
            resolved_routes: bits & 0x10 != 0,
        }
    }

    fn allowed_route(&self) -> HostRoute {
        if self.resolved_routes {
            HostRoute::resolved_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else {
            HostRoute::unresolved()
        }
    }
}

impl HostNetworkPolicy for FuzzPolicy {
    fn decide_dns(&mut self, _query: &DnsQuery) -> HostAdmission {
        if self.allow_dns {
            HostAdmission::allowed()
        } else {
            HostAdmission::denied(DenialReason::HostNotAllowed)
        }
    }

    fn decide_tcp_open(&mut self, _open: &OpenTcp) -> HostAdmission {
        if self.allow_tcp {
            HostAdmission::allowed_with_route(self.allowed_route())
        } else {
            HostAdmission::denied(DenialReason::HostNotAllowed)
        }
    }

    fn decide_udp_datagram(&mut self, _datagram: &UdpDatagram) -> HostAdmission {
        if self.allow_udp {
            HostAdmission::allowed_with_route(self.allowed_route())
        } else {
            HostAdmission::denied(DenialReason::HostNotAllowed)
        }
    }

    fn decide_icmp_echo(&mut self, _request: &IcmpEchoRequest) -> HostAdmission {
        if self.allow_icmp {
            HostAdmission::allowed_with_route(self.allowed_route())
        } else {
            HostAdmission::denied(DenialReason::HostNotAllowed)
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct NoopAuditSink;

impl HostAuditSink for NoopAuditSink {
    type Error = std::convert::Infallible;

    fn record(
        &mut self,
        _event: mvm_net::host::HostAuditEvent,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug)]
struct FuzzTcpConnector {
    supports_tls_transform: bool,
    supports_stream_transforms: bool,
    script: Vec<u8>,
    script_offset: usize,
    open_flows: HashSet<FlowId>,
    pending_events: VecDeque<HostTcpEvent>,
    activity_details: HashMap<FlowId, String>,
    error_details: HashMap<FlowId, String>,
}

impl FuzzTcpConnector {
    fn from_config_bytes(bytes: &[u8]) -> Self {
        let flags = bytes.get(4).copied().unwrap_or(0);
        Self {
            supports_tls_transform: flags & 0x01 != 0,
            supports_stream_transforms: flags & 0x02 != 0,
            script: bytes.to_vec(),
            script_offset: 0,
            open_flows: HashSet::new(),
            pending_events: VecDeque::new(),
            activity_details: HashMap::new(),
            error_details: HashMap::new(),
        }
    }

    fn next_action(&mut self) -> u8 {
        if self.script_offset >= self.script.len() {
            return 0;
        }
        let action = self.script[self.script_offset];
        self.script_offset += 1;
        action
    }

    fn maybe_queue_data(&mut self, flow_id: FlowId, action: u8, bytes: Vec<u8>) {
        if action & 0x01 == 0 {
            return;
        }
        let direction = if action & 0x02 == 0 {
            FlowDirection::HostToGuest
        } else {
            FlowDirection::GuestToHost
        };
        let mut chunk = StreamChunk::new(flow_id, direction, u64::from(action), bytes);
        if action & 0x04 != 0 {
            chunk = chunk.with_end_stream();
        }
        self.pending_events.push_back(HostTcpEvent::Data(chunk));
    }

    fn maybe_queue_close(&mut self, flow_id: FlowId, action: u8) {
        if action & 0x08 == 0 {
            return;
        }
        self.pending_events
            .push_back(HostTcpEvent::Close(CloseFlow {
                flow_id,
                reason: close_reason_from_byte(action >> 4),
            }));
    }

    fn known_plugin(plugin_id: &PluginId) -> bool {
        matches!(
            plugin_id.as_str(),
            "audit"
                | "metadata-endpoint-deny"
                | "secret-replacement"
                | "response-leak-guard"
        )
    }
}

impl HostTcpConnector for FuzzTcpConnector {
    fn open(&mut self, spec: &TcpConnectSpec) -> Result<(), TransportError> {
        let action = self.next_action();
        if action & 0x80 != 0 {
            self.error_details.insert(
                spec.flow_id(),
                format!("fuzz-open-error action={action}"),
            );
            return Err(transport_error_from_byte(action));
        }
        self.open_flows.insert(spec.flow_id());
        self.maybe_queue_data(
            spec.flow_id(),
            action,
            vec![action; usize::from((action >> 3) & 0x0f).min(MAX_CHUNK_BYTES)],
        );
        self.maybe_queue_close(spec.flow_id(), action);
        Ok(())
    }

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
        if !self.open_flows.contains(&chunk.flow_id) {
            return Err(TransportError::ProtocolError);
        }
        let action = self.next_action();
        if action & 0x80 != 0 {
            self.error_details.insert(
                chunk.flow_id,
                format!("fuzz-send-error action={action}"),
            );
            return Err(transport_error_from_byte(action));
        }
        if action & 0x10 != 0 {
            self.activity_details.insert(
                chunk.flow_id,
                format!("fuzz-activity action={action} bytes={}", chunk.bytes.len()),
            );
        }
        let bytes = if chunk.bytes.is_empty() {
            vec![action]
        } else {
            chunk.bytes.iter().copied().take(MAX_CHUNK_BYTES).collect()
        };
        self.maybe_queue_data(chunk.flow_id, action, bytes);
        self.maybe_queue_close(chunk.flow_id, action);
        Ok(())
    }

    fn close(&mut self, flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        self.open_flows.remove(&flow_id);
        Ok(())
    }

    fn drain_events(&mut self, max_events: usize) -> Result<Vec<HostTcpEvent>, TransportError> {
        let mut events = Vec::new();
        for _ in 0..max_events {
            let Some(event) = self.pending_events.pop_front() else {
                break;
            };
            events.push(event);
        }
        Ok(events)
    }

    fn supports_tls_transform(&self) -> bool {
        self.supports_tls_transform
    }

    fn supports_stream_transforms(&self) -> bool {
        self.supports_stream_transforms
    }

    fn validate_stream_transforms(
        &self,
        plugin_chain: &[PluginId],
        _target_host: Option<&str>,
    ) -> Result<(), String> {
        if plugin_chain.iter().all(Self::known_plugin) {
            Ok(())
        } else {
            Err("fuzz rejected unknown stream transform plugin".to_string())
        }
    }

    fn take_activity_detail(&mut self, flow_id: FlowId) -> Option<String> {
        self.activity_details.remove(&flow_id)
    }

    fn take_error_detail(&mut self, flow_id: FlowId) -> Option<String> {
        self.error_details.remove(&flow_id)
    }
}
