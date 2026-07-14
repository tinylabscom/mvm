// Fuzz the dependency-light guest pump runtime seam.
//
// `GuestPumpLoop` and `GuestBridgePump` sit between hostile guest packet bytes
// and structured authority messages. The harness contract is "never panic on
// any packet/message cadence". Arbitrary bytes become bounded guest-source
// reads, authority reads, sink failures, and send failures, and the harness
// drives `GuestPumpLoop::tick()` over fake adapters so outbound translation,
// inbound synthesis, and loop bookkeeping are exercised without real TUN/vsock
// I/O.

#![no_main]

use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;
use mvm_net::guest_pump::{
    AuthorityRead, GuestAuthority, GuestAuthorityReceiver, GuestBridgePump, GuestPacketRead,
    GuestPacketSink, GuestPacketSource, GuestPumpLoop, GuestPumpLoopConfig,
};
use mvm_net::proto::{
    Capability, CloseFlow, CloseReason, DatagramStatus, Denial, DenialReason, DnsName, DnsQuery,
    DnsRecordType, DnsResponse, DnsResponseCode, EndpointRole, FlowDirection, FlowId, Hello,
    HelloAck, HostName, IcmpEchoRequest, IcmpEchoResponse, IcmpEchoStatus, NetMessage, OpenTcp,
    PluginId, QueryId, StreamChunk, Target, TcpOpenResult, TlsTermination, TlsTransformRoute,
    TransportError, UdpDatagram, UdpDelivery,
};

const MAX_STEPS: usize = 64;
const MAX_SCRIPT_PAYLOAD_BYTES: usize = 96;

fuzz_target!(|data: &[u8]| {
    let (config_bytes, mut cursor) = data.split_at(data.len().min(2));
    let max_tun_packet_bytes =
        config_bytes.first().map_or(256usize, |value| usize::from(*value).clamp(1, 512));
    let max_authority_messages_per_tick = config_bytes
        .get(1)
        .map_or(4usize, |value| usize::from(*value % 8).max(1));
    let Ok(config) = GuestPumpLoopConfig::builder()
        .max_tun_packet_bytes(max_tun_packet_bytes)
        .max_authority_messages_per_tick(max_authority_messages_per_tick)
        .build()
    else {
        return;
    };

    let mut pump_loop = GuestPumpLoop::new(config);
    let mut pump = GuestBridgePump::new(mvm_net::guest_packet::GuestPacketTranslator::default(), FuzzAuthority::default());
    let mut source = FuzzPacketSource::default();
    let mut sink = FuzzPacketSink::default();

    let mut steps = 0usize;
    while !cursor.is_empty() && steps < MAX_STEPS {
        let header = cursor[0];
        cursor = &cursor[1..];
        let take = cursor
            .first()
            .map_or(0usize, |len| usize::from(*len).min(cursor.len().saturating_sub(1)));
        let payload = if cursor.is_empty() {
            &[][..]
        } else {
            let bounded = take.min(MAX_SCRIPT_PAYLOAD_BYTES);
            let payload = &cursor[1..1 + bounded];
            cursor = &cursor[1 + take..];
            payload
        };
        steps += 1;

        source.events.push_back(build_source_event(header & 0x07, payload));
        pump.authority_mut()
            .incoming
            .push_back(build_authority_event((header >> 3) & 0x07, header, payload));
        if header & 0x40 != 0 {
            sink.fail_next = true;
        }
        if header & 0x80 != 0 {
            pump.authority_mut().send_fail_next = true;
        }

        let _ = pump_loop.tick(&mut pump, &mut source, &mut sink);
    }

    for _ in 0..8 {
        let _ = pump_loop.tick(&mut pump, &mut source, &mut sink);
    }
});

#[derive(Debug, Default)]
struct FuzzAuthority {
    sent: Vec<NetMessage>,
    incoming: VecDeque<FuzzAuthorityEvent>,
    send_fail_next: bool,
}

#[derive(Debug)]
enum FuzzAuthorityEvent {
    Read(AuthorityRead),
    Error,
}

impl GuestAuthority for FuzzAuthority {
    type Error = &'static str;

    fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
        if self.send_fail_next {
            self.send_fail_next = false;
            return Err("fuzz authority send failed");
        }
        self.sent.push(message);
        Ok(())
    }
}

impl GuestAuthorityReceiver for FuzzAuthority {
    fn receive_message(&mut self) -> Result<AuthorityRead, Self::Error> {
        match self.incoming.pop_front() {
            Some(FuzzAuthorityEvent::Read(read)) => Ok(read),
            Some(FuzzAuthorityEvent::Error) => Err("fuzz authority receive failed"),
            None => Ok(AuthorityRead::WouldBlock),
        }
    }
}

#[derive(Debug, Default)]
struct FuzzPacketSource {
    events: VecDeque<FuzzSourceEvent>,
}

#[derive(Debug)]
enum FuzzSourceEvent {
    Packet(Vec<u8>),
    WouldBlock,
    Closed,
    Error,
    InvalidZero,
    InvalidTooLarge,
}

impl GuestPacketSource for FuzzPacketSource {
    type Error = &'static str;

    fn read_packet(&mut self, buffer: &mut [u8]) -> Result<GuestPacketRead, Self::Error> {
        match self.events.pop_front() {
            Some(FuzzSourceEvent::Packet(bytes)) => {
                let read_len = bytes.len().min(buffer.len());
                buffer[..read_len].copy_from_slice(&bytes[..read_len]);
                Ok(GuestPacketRead::Packet { bytes: read_len })
            }
            Some(FuzzSourceEvent::WouldBlock) => Ok(GuestPacketRead::WouldBlock),
            Some(FuzzSourceEvent::Closed) => Ok(GuestPacketRead::Closed),
            Some(FuzzSourceEvent::Error) => Err("fuzz source failed"),
            Some(FuzzSourceEvent::InvalidZero) => Ok(GuestPacketRead::Packet { bytes: 0 }),
            Some(FuzzSourceEvent::InvalidTooLarge) => Ok(GuestPacketRead::Packet {
                bytes: buffer.len().saturating_add(1),
            }),
            None => Ok(GuestPacketRead::WouldBlock),
        }
    }
}

#[derive(Debug, Default)]
struct FuzzPacketSink {
    packets: Vec<Vec<u8>>,
    fail_next: bool,
}

impl GuestPacketSink for FuzzPacketSink {
    type Error = &'static str;

    fn write_packet(&mut self, packet: &[u8]) -> Result<(), Self::Error> {
        if self.fail_next {
            self.fail_next = false;
            return Err("fuzz sink failed");
        }
        self.packets.push(packet.to_vec());
        Ok(())
    }
}

fn build_source_event(selector: u8, payload: &[u8]) -> FuzzSourceEvent {
    match selector % 6 {
        0 => FuzzSourceEvent::Packet(bounded_payload(payload)),
        1 => FuzzSourceEvent::WouldBlock,
        2 => FuzzSourceEvent::Closed,
        3 => FuzzSourceEvent::Error,
        4 => FuzzSourceEvent::InvalidZero,
        5 => FuzzSourceEvent::InvalidTooLarge,
        _ => FuzzSourceEvent::WouldBlock,
    }
}

fn build_authority_event(selector: u8, opcode: u8, payload: &[u8]) -> FuzzAuthorityEvent {
    match selector % 6 {
        0 => FuzzAuthorityEvent::Read(AuthorityRead::Message(build_message(opcode, payload))),
        1 => FuzzAuthorityEvent::Read(AuthorityRead::WouldBlock),
        2 => FuzzAuthorityEvent::Read(AuthorityRead::Closed),
        3 => FuzzAuthorityEvent::Error,
        4 | 5 => FuzzAuthorityEvent::Read(AuthorityRead::Message(build_message(
            opcode.wrapping_add(selector),
            payload,
        ))),
        _ => FuzzAuthorityEvent::Read(AuthorityRead::WouldBlock),
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
        1 => NetMessage::HelloAck(HelloAck::new(capabilities_from_bits(
            payload.first().copied().unwrap_or(0),
        ))),
        2 => NetMessage::DnsResponse(DnsResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            code: dns_response_code_from_byte(payload.get(1).copied().unwrap_or(0)),
            answers: Vec::new(),
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        }),
        3 => {
            let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
            if opcode & 1 == 0 {
                NetMessage::TcpOpenResult(TcpOpenResult::opened(flow_id))
            } else {
                NetMessage::TcpOpenResult(TcpOpenResult::failed(
                    flow_id,
                    transport_error_from_byte(payload.get(1).copied().unwrap_or(0)),
                ))
            }
        }
        4 => NetMessage::TcpData(build_stream_chunk(payload)),
        5 => NetMessage::CloseFlow(CloseFlow {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            reason: close_reason_from_byte(payload.get(1).copied().unwrap_or(0)),
        }),
        6 => NetMessage::UdpDatagram(UdpDatagram {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            target: Target::new(
                host_for_byte(payload.get(1).copied().unwrap_or(0)),
                port_for_byte(payload.get(2).copied().unwrap_or(0)),
            )
            .expect("fixed UDP target must be valid"),
            direction: FlowDirection::HostToGuest,
            bytes: bounded_payload(payload.get(3..).unwrap_or(&[])),
        }),
        7 => NetMessage::UdpDelivery(UdpDelivery {
            flow_id: flow_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: if opcode & 1 == 0 {
                DatagramStatus::Delivered
            } else {
                DatagramStatus::Failed(transport_error_from_byte(
                    payload.get(1).copied().unwrap_or(0),
                ))
            },
        }),
        8 => NetMessage::IcmpEchoResponse(IcmpEchoResponse {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            status: icmp_status_from_byte(payload.get(1).copied().unwrap_or(0)),
            round_trip_micros: Some(u64::from(payload.get(2).copied().unwrap_or(0))),
            denial: Some(Denial::new(DenialReason::NetworkDisabled)),
        }),
        9 => NetMessage::OpenTcp(build_open_tcp(payload)),
        10 => NetMessage::DnsQuery(DnsQuery {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            name: DnsName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
                .expect("fixed DNS name must be valid"),
            record_type: dns_record_type_from_byte(payload.get(2).copied().unwrap_or(0)),
        }),
        11 => NetMessage::IcmpEchoRequest(IcmpEchoRequest {
            query_id: query_id_from_byte(payload.first().copied().unwrap_or(0)),
            host: HostName::new(host_for_byte(payload.get(1).copied().unwrap_or(0)))
                .expect("fixed host name must be valid"),
            payload_len: u16::from(payload.get(2).copied().unwrap_or(0)),
        }),
        _ => NetMessage::HelloAck(HelloAck::new(Vec::new())),
    }
}

fn build_open_tcp(payload: &[u8]) -> OpenTcp {
    let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
    let host = host_for_byte(payload.get(1).copied().unwrap_or(0));
    let port = port_for_byte(payload.get(2).copied().unwrap_or(0));
    let target = Target::new(host, port).expect("fixed TCP target must be valid");
    let mut open = OpenTcp::new(flow_id, target);
    if payload.get(3).copied().unwrap_or(0) & 0x01 != 0 {
        let server_name =
            DnsName::new(host_for_byte(payload.get(4).copied().unwrap_or(0))).expect(
                "fixed server name must be valid",
            );
        let mut route = TlsTransformRoute::new(server_name, TlsTermination::TerminateAndReoriginate);
        if payload.get(3).copied().unwrap_or(0) & 0x02 != 0 {
            route = route.with_transform_chain(plugin_chain_for_byte(
                payload.get(5).copied().unwrap_or(0),
            ));
        }
        open = open.with_tls_transform(route);
    }
    open
}

fn build_stream_chunk(payload: &[u8]) -> StreamChunk {
    let flow_id = flow_id_from_byte(payload.first().copied().unwrap_or(0));
    let direction = if payload.get(1).copied().unwrap_or(0) & 1 == 0 {
        FlowDirection::HostToGuest
    } else {
        FlowDirection::GuestToHost
    };
    let sequence = u64::from(payload.get(2).copied().unwrap_or(0));
    let chunk = StreamChunk::new(flow_id, direction, sequence, bounded_payload(payload.get(3..).unwrap_or(&[])));
    if payload.get(1).copied().unwrap_or(0) & 0x02 != 0 {
        return chunk.with_end_stream();
    }
    chunk
}

fn bounded_payload(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return vec![0];
    }
    payload
        .iter()
        .copied()
        .take(MAX_SCRIPT_PAYLOAD_BYTES)
        .collect()
}

fn capabilities_from_bits(bits: u8) -> Vec<Capability> {
    let mut capabilities = vec![Capability::Dns, Capability::Tcp];
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
    if bits & 0x10 != 0 {
        capabilities.push(Capability::AuditCorrelation);
    }
    if bits & 0x20 != 0 {
        capabilities.push(Capability::PolicyDigest);
    }
    capabilities
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

fn dns_response_code_from_byte(value: u8) -> DnsResponseCode {
    match value % 4 {
        0 => DnsResponseCode::Ok,
        1 => DnsResponseCode::NameError,
        2 => DnsResponseCode::Refused,
        _ => DnsResponseCode::ServerFailure,
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

fn icmp_status_from_byte(value: u8) -> IcmpEchoStatus {
    match value % 4 {
        0 => IcmpEchoStatus::Replied,
        1 => IcmpEchoStatus::Denied,
        2 => IcmpEchoStatus::TimedOut,
        _ => IcmpEchoStatus::Unreachable,
    }
}

fn plugin_chain_for_byte(value: u8) -> Vec<PluginId> {
    match value % 5 {
        0 => Vec::new(),
        1 => vec![PluginId::new("audit").expect("fixed plugin id must be valid")],
        2 => vec![PluginId::new("metadata-endpoint-deny").expect("fixed plugin id must be valid")],
        3 => vec![PluginId::new("secret-replacement").expect("fixed plugin id must be valid")],
        _ => vec![
            PluginId::new("audit").expect("fixed plugin id must be valid"),
            PluginId::new("response-leak-guard").expect("fixed plugin id must be valid"),
        ],
    }
}
