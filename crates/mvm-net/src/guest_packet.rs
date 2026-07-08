//! Dependency-light guest packet translation for the transparent network bridge.
//!
//! The translator handles the TUN boundary: outbound IPv4 packets become
//! protocol events for the host authority, and selected authority responses can
//! be synthesized back into IPv4 packets for the guest. It intentionally does
//! not contain a complete TCP state machine yet; TCP packets are classified into
//! open/data/close events that the next bridge layer will drive.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use crate::guest::{DEFAULT_GUEST_ADDRESS, DEFAULT_HOST_GATEWAY};
use crate::proto::{
    CloseFlow, CloseReason, DnsAnswer, DnsName, DnsQuery, DnsRecordData, DnsRecordType,
    DnsResponse, DnsResponseCode, FlowDirection, FlowId, HostName, IcmpEchoRequest,
    IcmpEchoResponse, IcmpEchoStatus, MAX_STREAM_CHUNK_BYTES, NetMessage, OpenTcp, ProtocolError,
    QueryId, StreamChunk, Target, TcpOpenResult, UdpDatagram,
};

const IPV4_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const TCP_MIN_HEADER_LEN: usize = 20;
const ICMP_ECHO_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const DNS_PORT: u16 = 53;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPV4_TTL: u8 = 64;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_DEFAULT_WINDOW: u16 = 65535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestPacketError {
    PacketTooShort {
        layer: &'static str,
        needed: usize,
        actual: usize,
    },
    UnsupportedIpVersion {
        version: u8,
    },
    InvalidIpv4HeaderLen {
        header_len: usize,
    },
    InvalidIpv4TotalLen {
        total_len: usize,
        header_len: usize,
        actual: usize,
    },
    FragmentedIpv4,
    UnsupportedProtocol {
        protocol: u8,
    },
    InvalidUdpLength {
        declared: usize,
        available: usize,
    },
    InvalidTcpHeaderLen {
        header_len: usize,
        available: usize,
    },
    InvalidDnsQuery {
        reason: &'static str,
    },
    InvalidIcmpEcho {
        reason: &'static str,
    },
    UnsupportedDnsCompression,
    UnsupportedDnsType {
        qtype: u16,
    },
    UnsupportedDnsClass {
        qclass: u16,
    },
    DnsAnswerTypeMismatch,
    NameTooLong {
        name: String,
    },
    LabelTooLong {
        label: String,
    },
    PendingQueryLimit,
    FlowLimit,
    IdExhausted,
    PayloadTooLarge {
        actual: usize,
        max: usize,
    },
    UnexpectedFlowDirection {
        expected: FlowDirection,
        actual: FlowDirection,
    },
    OutOfOrderTcpData {
        expected: u64,
        actual: u64,
    },
    UnknownTcpFlow,
    UnknownDnsQuery {
        query_id: QueryId,
    },
    UnknownIcmpQuery {
        query_id: QueryId,
    },
    Protocol(ProtocolError),
}

impl fmt::Display for GuestPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort {
                layer,
                needed,
                actual,
            } => write!(
                f,
                "{layer} packet too short: need {needed} bytes, got {actual}"
            ),
            Self::UnsupportedIpVersion { version } => {
                write!(f, "unsupported IP version {version}")
            }
            Self::InvalidIpv4HeaderLen { header_len } => {
                write!(f, "invalid IPv4 header length {header_len}")
            }
            Self::InvalidIpv4TotalLen {
                total_len,
                header_len,
                actual,
            } => write!(
                f,
                "invalid IPv4 total length {total_len}; header {header_len}, packet {actual}"
            ),
            Self::FragmentedIpv4 => write!(f, "fragmented IPv4 packets are not supported"),
            Self::UnsupportedProtocol { protocol } => {
                write!(f, "unsupported IPv4 protocol {protocol}")
            }
            Self::InvalidUdpLength {
                declared,
                available,
            } => write!(
                f,
                "invalid UDP length {declared}; only {available} bytes available"
            ),
            Self::InvalidTcpHeaderLen {
                header_len,
                available,
            } => write!(
                f,
                "invalid TCP header length {header_len}; only {available} bytes available"
            ),
            Self::InvalidDnsQuery { reason } => write!(f, "invalid DNS query: {reason}"),
            Self::InvalidIcmpEcho { reason } => write!(f, "invalid ICMP echo packet: {reason}"),
            Self::UnsupportedDnsCompression => {
                write!(f, "compressed DNS names are not supported in guest queries")
            }
            Self::UnsupportedDnsType { qtype } => write!(f, "unsupported DNS qtype {qtype}"),
            Self::UnsupportedDnsClass { qclass } => write!(f, "unsupported DNS qclass {qclass}"),
            Self::DnsAnswerTypeMismatch => write!(f, "DNS answer type and record data mismatch"),
            Self::NameTooLong { name } => write!(f, "DNS name {name:?} is too long"),
            Self::LabelTooLong { label } => write!(f, "DNS label {label:?} is too long"),
            Self::PendingQueryLimit => write!(f, "pending guest network query limit reached"),
            Self::FlowLimit => write!(f, "guest network flow limit reached"),
            Self::IdExhausted => write!(f, "guest network protocol id space exhausted"),
            Self::PayloadTooLarge { actual, max } => {
                write!(f, "payload has {actual} bytes, above maximum {max}")
            }
            Self::UnexpectedFlowDirection { expected, actual } => {
                write!(
                    f,
                    "unexpected flow direction {actual:?}; expected {expected:?}"
                )
            }
            Self::OutOfOrderTcpData { expected, actual } => write!(
                f,
                "out-of-order TCP stream chunk: expected sequence {expected}, got {actual}"
            ),
            Self::UnknownTcpFlow => write!(f, "TCP packet did not match an opened flow"),
            Self::UnknownDnsQuery { query_id } => {
                write!(f, "DNS response for unknown query id {}", query_id.get())
            }
            Self::UnknownIcmpQuery { query_id } => {
                write!(f, "ICMP response for unknown query id {}", query_id.get())
            }
            Self::Protocol(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for GuestPacketError {}

impl From<ProtocolError> for GuestPacketError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPacketTranslatorConfig {
    guest_address: Ipv4Addr,
    gateway_address: Ipv4Addr,
    max_pending_queries: usize,
    max_flows: usize,
}

impl GuestPacketTranslatorConfig {
    pub fn builder() -> GuestPacketTranslatorConfigBuilder {
        GuestPacketTranslatorConfigBuilder::default()
    }

    pub const fn guest_address(&self) -> Ipv4Addr {
        self.guest_address
    }

    pub const fn gateway_address(&self) -> Ipv4Addr {
        self.gateway_address
    }

    pub const fn max_pending_queries(&self) -> usize {
        self.max_pending_queries
    }

    pub const fn max_flows(&self) -> usize {
        self.max_flows
    }
}

impl Default for GuestPacketTranslatorConfig {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default guest packet translator config is valid")
    }
}

#[derive(Debug, Clone)]
pub struct GuestPacketTranslatorConfigBuilder {
    guest_address: Ipv4Addr,
    gateway_address: Ipv4Addr,
    max_pending_queries: usize,
    max_flows: usize,
}

impl Default for GuestPacketTranslatorConfigBuilder {
    fn default() -> Self {
        Self {
            guest_address: DEFAULT_GUEST_ADDRESS,
            gateway_address: DEFAULT_HOST_GATEWAY,
            max_pending_queries: 4096,
            max_flows: 16384,
        }
    }
}

impl GuestPacketTranslatorConfigBuilder {
    pub fn guest_address(mut self, guest_address: Ipv4Addr) -> Self {
        self.guest_address = guest_address;
        self
    }

    pub fn gateway_address(mut self, gateway_address: Ipv4Addr) -> Self {
        self.gateway_address = gateway_address;
        self
    }

    pub fn max_pending_queries(mut self, max_pending_queries: usize) -> Self {
        self.max_pending_queries = max_pending_queries;
        self
    }

    pub fn max_flows(mut self, max_flows: usize) -> Self {
        self.max_flows = max_flows;
        self
    }

    pub fn build(self) -> Result<GuestPacketTranslatorConfig, GuestPacketError> {
        if self.max_pending_queries == 0 {
            return Err(GuestPacketError::PendingQueryLimit);
        }
        if self.max_flows == 0 {
            return Err(GuestPacketError::FlowLimit);
        }
        Ok(GuestPacketTranslatorConfig {
            guest_address: self.guest_address,
            gateway_address: self.gateway_address,
            max_pending_queries: self.max_pending_queries,
            max_flows: self.max_flows,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundPacketEvent {
    DnsQuery(DnsQuery),
    OpenTcp(OpenTcp),
    TcpData(StreamChunk),
    CloseFlow(CloseFlow),
    UdpDatagram(UdpDatagram),
    IcmpEchoRequest(IcmpEchoRequest),
}

impl OutboundPacketEvent {
    pub fn into_message(self) -> NetMessage {
        match self {
            Self::DnsQuery(value) => NetMessage::DnsQuery(value),
            Self::OpenTcp(value) => NetMessage::OpenTcp(value),
            Self::TcpData(value) => NetMessage::TcpData(value),
            Self::CloseFlow(value) => NetMessage::CloseFlow(value),
            Self::UdpDatagram(value) => NetMessage::UdpDatagram(value),
            Self::IcmpEchoRequest(value) => NetMessage::IcmpEchoRequest(value),
        }
    }
}

#[derive(Debug)]
pub struct GuestPacketTranslator {
    config: GuestPacketTranslatorConfig,
    next_query_id: u64,
    next_flow_id: u64,
    pending_dns: HashMap<QueryId, DnsQueryContext>,
    pending_icmp: HashMap<QueryId, IcmpEchoContext>,
    tcp_flows: HashMap<FlowKey, TcpFlowState>,
    tcp_flow_keys: HashMap<FlowId, FlowKey>,
    udp_flows: HashMap<FlowKey, FlowId>,
    synthetic_hosts: HashMap<Ipv4Addr, DnsName>,
}

impl GuestPacketTranslator {
    pub fn new(config: GuestPacketTranslatorConfig) -> Self {
        Self {
            config,
            next_query_id: 1,
            next_flow_id: 1,
            pending_dns: HashMap::new(),
            pending_icmp: HashMap::new(),
            tcp_flows: HashMap::new(),
            tcp_flow_keys: HashMap::new(),
            udp_flows: HashMap::new(),
            synthetic_hosts: HashMap::new(),
        }
    }

    pub fn config(&self) -> &GuestPacketTranslatorConfig {
        &self.config
    }

    pub fn remember_synthetic_host(&mut self, address: Ipv4Addr, host: DnsName) -> Option<DnsName> {
        self.synthetic_hosts.insert(address, host)
    }

    pub fn remember_dns_response(&mut self, response: &DnsResponse) {
        if response.code != DnsResponseCode::Ok {
            return;
        }
        for answer in &response.answers {
            if let DnsRecordData::Ip(IpAddr::V4(address)) = answer.data {
                self.synthetic_hosts.insert(address, answer.name.clone());
            }
        }
    }

    pub fn translate_outbound_ipv4(
        &mut self,
        packet: &[u8],
    ) -> Result<Vec<OutboundPacketEvent>, GuestPacketError> {
        let packet = parse_ipv4(packet)?;
        if packet.src != self.config.guest_address {
            return Ok(Vec::new());
        }
        match packet.protocol {
            IPPROTO_UDP => self.translate_udp(packet),
            IPPROTO_TCP => self.translate_tcp(packet),
            IPPROTO_ICMP => self.translate_icmp(packet),
            protocol => Err(GuestPacketError::UnsupportedProtocol { protocol }),
        }
    }

    pub fn synthesize_dns_response(
        &mut self,
        response: &DnsResponse,
    ) -> Result<Vec<u8>, GuestPacketError> {
        self.remember_dns_response(response);
        let context = self.pending_dns.remove(&response.query_id).ok_or(
            GuestPacketError::UnknownDnsQuery {
                query_id: response.query_id,
            },
        )?;
        let dns_payload = build_dns_response_payload(response, &context)?;
        let udp_payload =
            build_udp_packet(context.dst_port, context.src_port, dns_payload.as_slice())?;
        build_ipv4_packet(
            context.dst_ip,
            context.src_ip,
            IPPROTO_UDP,
            udp_payload.as_slice(),
        )
    }

    pub fn synthesize_icmp_echo_response(
        &mut self,
        response: &IcmpEchoResponse,
    ) -> Result<Option<Vec<u8>>, GuestPacketError> {
        let context = self.pending_icmp.remove(&response.query_id).ok_or(
            GuestPacketError::UnknownIcmpQuery {
                query_id: response.query_id,
            },
        )?;
        if response.status != IcmpEchoStatus::Replied {
            return Ok(None);
        }
        let icmp_payload = build_icmp_echo_reply(&context)?;
        build_ipv4_packet(
            context.dst_ip,
            context.src_ip,
            IPPROTO_ICMP,
            icmp_payload.as_slice(),
        )
        .map(Some)
    }

    pub fn synthesize_tcp_open_result(
        &mut self,
        result: &TcpOpenResult,
    ) -> Result<Vec<u8>, GuestPacketError> {
        match &result.status {
            crate::proto::FlowOpenStatus::Opened => {
                let state = self
                    .tcp_state_mut(result.flow_id)
                    .ok_or(GuestPacketError::UnknownTcpFlow)?;
                let packet = state.build_host_packet(
                    TCP_FLAG_SYN | TCP_FLAG_ACK,
                    state.host_initial_sequence,
                    &[],
                )?;
                state.host_next_sequence = state.host_initial_sequence.wrapping_add(1);
                Ok(packet)
            }
            crate::proto::FlowOpenStatus::Denied(_) | crate::proto::FlowOpenStatus::Failed(_) => {
                let state = self.remove_tcp_flow(result.flow_id)?;
                state.build_host_packet(TCP_FLAG_RST | TCP_FLAG_ACK, 0, &[])
            }
        }
    }

    pub fn synthesize_tcp_data(
        &mut self,
        chunk: &StreamChunk,
    ) -> Result<Option<Vec<u8>>, GuestPacketError> {
        if chunk.direction != FlowDirection::HostToGuest {
            return Err(GuestPacketError::UnexpectedFlowDirection {
                expected: FlowDirection::HostToGuest,
                actual: chunk.direction,
            });
        }
        if chunk.bytes.len() > MAX_STREAM_CHUNK_BYTES {
            return Err(GuestPacketError::PayloadTooLarge {
                actual: chunk.bytes.len(),
                max: MAX_STREAM_CHUNK_BYTES,
            });
        }
        if chunk.bytes.is_empty() && !chunk.end_stream {
            return Ok(None);
        }

        let mut remove_flow = false;
        let packet = {
            let state = self
                .tcp_state_mut(chunk.flow_id)
                .ok_or(GuestPacketError::UnknownTcpFlow)?;
            if chunk.sequence != state.host_stream_offset {
                return Err(GuestPacketError::OutOfOrderTcpData {
                    expected: state.host_stream_offset,
                    actual: chunk.sequence,
                });
            }

            let flags = match (chunk.bytes.is_empty(), chunk.end_stream) {
                (true, true) => TCP_FLAG_FIN | TCP_FLAG_ACK,
                (false, true) => TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ACK,
                (false, false) => TCP_FLAG_PSH | TCP_FLAG_ACK,
                (true, false) => unreachable!("empty non-terminal chunks return above"),
            };
            let packet = state.build_host_packet(flags, state.host_next_sequence, &chunk.bytes)?;
            state.host_next_sequence = advance_tcp_sequence(state.host_next_sequence, &chunk.bytes);
            state.host_stream_offset = state
                .host_stream_offset
                .checked_add(chunk.bytes.len() as u64)
                .ok_or(GuestPacketError::IdExhausted)?;
            if chunk.end_stream {
                state.host_next_sequence = state.host_next_sequence.wrapping_add(1);
                remove_flow = true;
            }
            packet
        };

        if remove_flow {
            self.remove_tcp_flow(chunk.flow_id)?;
        }
        Ok(Some(packet))
    }

    pub fn synthesize_tcp_close(&mut self, close: &CloseFlow) -> Result<Vec<u8>, GuestPacketError> {
        let state = self.remove_tcp_flow(close.flow_id)?;
        let flags = if close.reason == CloseReason::HostClosed {
            TCP_FLAG_FIN | TCP_FLAG_ACK
        } else {
            TCP_FLAG_RST | TCP_FLAG_ACK
        };
        state.build_host_packet(flags, state.host_next_sequence, &[])
    }

    fn translate_udp(
        &mut self,
        packet: Ipv4Packet<'_>,
    ) -> Result<Vec<OutboundPacketEvent>, GuestPacketError> {
        let udp = parse_udp(packet.body)?;
        if packet.dst == self.config.gateway_address && udp.dst_port == DNS_PORT {
            let question = parse_dns_query(udp.payload)?;
            let query_id = self.alloc_query_id()?;
            self.reserve_pending_query()?;
            self.pending_dns.insert(
                query_id,
                DnsQueryContext {
                    tx_id: question.tx_id,
                    src_ip: packet.src,
                    dst_ip: packet.dst,
                    src_port: udp.src_port,
                    dst_port: udp.dst_port,
                    name: question.name.clone(),
                    record_type: question.record_type,
                },
            );
            return Ok(vec![OutboundPacketEvent::DnsQuery(DnsQuery {
                query_id,
                name: question.name,
                record_type: question.record_type,
            })]);
        }

        let key = FlowKey::new(packet.src, udp.src_port, packet.dst, udp.dst_port);
        let flow_id = self.udp_flow_id(key)?;
        let target = self.target_for_ip(packet.dst, udp.dst_port)?;
        Ok(vec![OutboundPacketEvent::UdpDatagram(UdpDatagram {
            flow_id,
            target,
            direction: FlowDirection::GuestToHost,
            bytes: udp.payload.to_vec(),
        })])
    }

    fn translate_tcp(
        &mut self,
        packet: Ipv4Packet<'_>,
    ) -> Result<Vec<OutboundPacketEvent>, GuestPacketError> {
        let tcp = parse_tcp(packet.body)?;
        let key = FlowKey::new(packet.src, tcp.src_port, packet.dst, tcp.dst_port);
        let mut events = Vec::new();

        if tcp.syn() && !tcp.ack() {
            let flow_id = self.tcp_flow_id(key, tcp.sequence)?;
            let target = self.target_for_ip(packet.dst, tcp.dst_port)?;
            events.push(OutboundPacketEvent::OpenTcp(OpenTcp::new(flow_id, target)));
        }

        if !tcp.payload.is_empty() {
            if tcp.payload.len() > MAX_STREAM_CHUNK_BYTES {
                return Err(GuestPacketError::PayloadTooLarge {
                    actual: tcp.payload.len(),
                    max: MAX_STREAM_CHUNK_BYTES,
                });
            }
            let flow_id = self
                .tcp_flows
                .get(&key)
                .map(|state| state.flow_id)
                .ok_or(GuestPacketError::UnknownTcpFlow)?;
            events.push(OutboundPacketEvent::TcpData(StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                u64::from(tcp.sequence),
                tcp.payload.to_vec(),
            )));
        }

        if let Some(state) = self.tcp_flows.get_mut(&key) {
            state.observe_guest_segment(tcp.sequence, tcp.payload.len(), tcp.syn(), tcp.fin());
        }

        if tcp.fin() || tcp.rst() {
            if let Some(state) = self.tcp_flows.remove(&key) {
                self.tcp_flow_keys.remove(&state.flow_id);
                let reason = if tcp.rst() {
                    CloseReason::ProtocolError
                } else {
                    CloseReason::GuestClosed
                };
                events.push(OutboundPacketEvent::CloseFlow(CloseFlow {
                    flow_id: state.flow_id,
                    reason,
                }));
            }
        }

        Ok(events)
    }

    fn translate_icmp(
        &mut self,
        packet: Ipv4Packet<'_>,
    ) -> Result<Vec<OutboundPacketEvent>, GuestPacketError> {
        let echo = parse_icmp_echo_request(packet.body)?;
        let query_id = self.alloc_query_id()?;
        self.reserve_pending_query()?;
        self.pending_icmp.insert(
            query_id,
            IcmpEchoContext {
                src_ip: packet.src,
                dst_ip: packet.dst,
                identifier: echo.identifier,
                sequence: echo.sequence,
                payload: echo.payload.to_vec(),
            },
        );
        let host = self.host_for_ip(packet.dst)?;
        Ok(vec![OutboundPacketEvent::IcmpEchoRequest(
            IcmpEchoRequest {
                query_id,
                host,
                payload_len: echo.payload.len().try_into().map_err(|_| {
                    GuestPacketError::PayloadTooLarge {
                        actual: echo.payload.len(),
                        max: u16::MAX as usize,
                    }
                })?,
            },
        )])
    }

    fn reserve_pending_query(&self) -> Result<(), GuestPacketError> {
        let pending = self.pending_dns.len() + self.pending_icmp.len();
        if pending >= self.config.max_pending_queries {
            return Err(GuestPacketError::PendingQueryLimit);
        }
        Ok(())
    }

    fn reserve_flow(&self) -> Result<(), GuestPacketError> {
        let flows = self.tcp_flows.len() + self.udp_flows.len();
        if flows >= self.config.max_flows {
            return Err(GuestPacketError::FlowLimit);
        }
        Ok(())
    }

    fn alloc_query_id(&mut self) -> Result<QueryId, GuestPacketError> {
        let value = self.next_query_id;
        self.next_query_id = self
            .next_query_id
            .checked_add(1)
            .ok_or(GuestPacketError::IdExhausted)?;
        QueryId::new(value).map_err(GuestPacketError::from)
    }

    fn alloc_flow_id(&mut self) -> Result<FlowId, GuestPacketError> {
        let value = self.next_flow_id;
        self.next_flow_id = self
            .next_flow_id
            .checked_add(1)
            .ok_or(GuestPacketError::IdExhausted)?;
        FlowId::new(value).map_err(GuestPacketError::from)
    }

    fn tcp_flow_id(
        &mut self,
        key: FlowKey,
        guest_syn_sequence: u32,
    ) -> Result<FlowId, GuestPacketError> {
        if let Some(state) = self.tcp_flows.get(&key) {
            return Ok(state.flow_id);
        }
        self.reserve_flow()?;
        let flow_id = self.alloc_flow_id()?;
        self.tcp_flow_keys.insert(flow_id, key);
        self.tcp_flows
            .insert(key, TcpFlowState::new(flow_id, key, guest_syn_sequence));
        Ok(flow_id)
    }

    fn tcp_state_mut(&mut self, flow_id: FlowId) -> Option<&mut TcpFlowState> {
        let key = self.tcp_flow_keys.get(&flow_id)?;
        self.tcp_flows.get_mut(key)
    }

    fn remove_tcp_flow(&mut self, flow_id: FlowId) -> Result<TcpFlowState, GuestPacketError> {
        let key = self
            .tcp_flow_keys
            .remove(&flow_id)
            .ok_or(GuestPacketError::UnknownTcpFlow)?;
        self.tcp_flows
            .remove(&key)
            .ok_or(GuestPacketError::UnknownTcpFlow)
    }

    fn udp_flow_id(&mut self, key: FlowKey) -> Result<FlowId, GuestPacketError> {
        if let Some(flow_id) = self.udp_flows.get(&key).copied() {
            return Ok(flow_id);
        }
        self.reserve_flow()?;
        let flow_id = self.alloc_flow_id()?;
        self.udp_flows.insert(key, flow_id);
        Ok(flow_id)
    }

    fn target_for_ip(&self, address: Ipv4Addr, port: u16) -> Result<Target, GuestPacketError> {
        let host = self.host_for_ip(address)?;
        Target::new(host.as_str(), port).map_err(GuestPacketError::from)
    }

    fn host_for_ip(&self, address: Ipv4Addr) -> Result<HostName, GuestPacketError> {
        if let Some(host) = self.synthetic_hosts.get(&address) {
            return HostName::new(host.as_str()).map_err(GuestPacketError::from);
        }
        HostName::new(address.to_string()).map_err(GuestPacketError::from)
    }
}

impl Default for GuestPacketTranslator {
    fn default() -> Self {
        Self::new(GuestPacketTranslatorConfig::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQueryContext {
    tx_id: u16,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    name: DnsName,
    record_type: DnsRecordType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IcmpEchoContext {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

impl FlowKey {
    const fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpFlowState {
    flow_id: FlowId,
    key: FlowKey,
    guest_next_sequence: u32,
    host_initial_sequence: u32,
    host_next_sequence: u32,
    host_stream_offset: u64,
}

impl TcpFlowState {
    fn new(flow_id: FlowId, key: FlowKey, guest_syn_sequence: u32) -> Self {
        let host_initial_sequence = host_initial_sequence(flow_id);
        Self {
            flow_id,
            key,
            guest_next_sequence: guest_syn_sequence.wrapping_add(1),
            host_initial_sequence,
            host_next_sequence: host_initial_sequence,
            host_stream_offset: 0,
        }
    }

    fn observe_guest_segment(&mut self, sequence: u32, payload_len: usize, syn: bool, fin: bool) {
        let mut consumed = payload_len as u32;
        if syn {
            consumed = consumed.wrapping_add(1);
        }
        if fin {
            consumed = consumed.wrapping_add(1);
        }
        if consumed != 0 {
            self.guest_next_sequence = sequence.wrapping_add(consumed);
        }
    }

    fn build_host_packet(
        &self,
        flags: u8,
        sequence: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, GuestPacketError> {
        let tcp_payload = build_tcp_packet(TcpPacketBuild {
            src_ip: self.key.dst_ip,
            dst_ip: self.key.src_ip,
            src_port: self.key.dst_port,
            dst_port: self.key.src_port,
            sequence,
            ack: self.guest_next_sequence,
            flags,
            payload,
        })?;
        build_ipv4_packet(self.key.dst_ip, self.key.src_ip, IPPROTO_TCP, &tcp_payload)
    }
}

fn host_initial_sequence(flow_id: FlowId) -> u32 {
    0x8000_0000u32.wrapping_add((flow_id.get() as u32).wrapping_mul(65_537))
}

fn advance_tcp_sequence(sequence: u32, payload: &[u8]) -> u32 {
    sequence.wrapping_add(payload.len() as u32)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct Ipv4Packet<'a> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    body: &'a [u8],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct UdpPacket<'a> {
    src_port: u16,
    dst_port: u16,
    payload: &'a [u8],
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct TcpPacket<'a> {
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    ack_number: u32,
    flags: u8,
    payload: &'a [u8],
}

impl TcpPacket<'_> {
    const fn fin(self) -> bool {
        self.flags & TCP_FLAG_FIN != 0
    }

    const fn syn(self) -> bool {
        self.flags & TCP_FLAG_SYN != 0
    }

    const fn rst(self) -> bool {
        self.flags & TCP_FLAG_RST != 0
    }

    const fn ack(self) -> bool {
        self.flags & TCP_FLAG_ACK != 0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct IcmpEchoRequestPacket<'a> {
    identifier: u16,
    sequence: u16,
    payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuestion {
    tx_id: u16,
    name: DnsName,
    record_type: DnsRecordType,
}

fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Packet<'_>, GuestPacketError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(GuestPacketError::PacketTooShort {
            layer: "IPv4",
            needed: IPV4_MIN_HEADER_LEN,
            actual: packet.len(),
        });
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(GuestPacketError::UnsupportedIpVersion { version });
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER_LEN {
        return Err(GuestPacketError::InvalidIpv4HeaderLen { header_len });
    }
    if packet.len() < header_len {
        return Err(GuestPacketError::PacketTooShort {
            layer: "IPv4 header",
            needed: header_len,
            actual: packet.len(),
        });
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len > packet.len() {
        return Err(GuestPacketError::InvalidIpv4TotalLen {
            total_len,
            header_len,
            actual: packet.len(),
        });
    }
    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_fragment & 0x3fff != 0 {
        return Err(GuestPacketError::FragmentedIpv4);
    }
    Ok(Ipv4Packet {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: packet[9],
        body: &packet[header_len..total_len],
    })
}

fn parse_udp(packet: &[u8]) -> Result<UdpPacket<'_>, GuestPacketError> {
    if packet.len() < UDP_HEADER_LEN {
        return Err(GuestPacketError::PacketTooShort {
            layer: "UDP",
            needed: UDP_HEADER_LEN,
            actual: packet.len(),
        });
    }
    let declared = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    if declared < UDP_HEADER_LEN || declared > packet.len() {
        return Err(GuestPacketError::InvalidUdpLength {
            declared,
            available: packet.len(),
        });
    }
    Ok(UdpPacket {
        src_port: u16::from_be_bytes([packet[0], packet[1]]),
        dst_port: u16::from_be_bytes([packet[2], packet[3]]),
        payload: &packet[UDP_HEADER_LEN..declared],
    })
}

fn parse_tcp(packet: &[u8]) -> Result<TcpPacket<'_>, GuestPacketError> {
    if packet.len() < TCP_MIN_HEADER_LEN {
        return Err(GuestPacketError::PacketTooShort {
            layer: "TCP",
            needed: TCP_MIN_HEADER_LEN,
            actual: packet.len(),
        });
    }
    let header_len = usize::from(packet[12] >> 4) * 4;
    if header_len < TCP_MIN_HEADER_LEN || header_len > packet.len() {
        return Err(GuestPacketError::InvalidTcpHeaderLen {
            header_len,
            available: packet.len(),
        });
    }
    Ok(TcpPacket {
        src_port: u16::from_be_bytes([packet[0], packet[1]]),
        dst_port: u16::from_be_bytes([packet[2], packet[3]]),
        sequence: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        ack_number: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        flags: packet[13],
        payload: &packet[header_len..],
    })
}

fn parse_icmp_echo_request(packet: &[u8]) -> Result<IcmpEchoRequestPacket<'_>, GuestPacketError> {
    if packet.len() < ICMP_ECHO_HEADER_LEN {
        return Err(GuestPacketError::PacketTooShort {
            layer: "ICMP echo",
            needed: ICMP_ECHO_HEADER_LEN,
            actual: packet.len(),
        });
    }
    if packet[0] != 8 || packet[1] != 0 {
        return Err(GuestPacketError::InvalidIcmpEcho {
            reason: "not an ICMP echo request",
        });
    }
    Ok(IcmpEchoRequestPacket {
        identifier: u16::from_be_bytes([packet[4], packet[5]]),
        sequence: u16::from_be_bytes([packet[6], packet[7]]),
        payload: &packet[ICMP_ECHO_HEADER_LEN..],
    })
}

fn parse_dns_query(payload: &[u8]) -> Result<DnsQuestion, GuestPacketError> {
    if payload.len() < DNS_HEADER_LEN {
        return Err(GuestPacketError::PacketTooShort {
            layer: "DNS",
            needed: DNS_HEADER_LEN,
            actual: payload.len(),
        });
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return Err(GuestPacketError::InvalidDnsQuery {
            reason: "packet is a DNS response",
        });
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return Err(GuestPacketError::InvalidDnsQuery {
            reason: "missing question",
        });
    }
    let mut pos = DNS_HEADER_LEN;
    let name = parse_dns_name(payload, &mut pos)?;
    if payload.len() < pos + 4 {
        return Err(GuestPacketError::PacketTooShort {
            layer: "DNS question",
            needed: pos + 4,
            actual: payload.len(),
        });
    }
    let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    let qclass = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]);
    if qclass != 1 {
        return Err(GuestPacketError::UnsupportedDnsClass { qclass });
    }
    Ok(DnsQuestion {
        tx_id: u16::from_be_bytes([payload[0], payload[1]]),
        name,
        record_type: record_type_from_qtype(qtype)?,
    })
}

fn parse_dns_name(payload: &[u8], pos: &mut usize) -> Result<DnsName, GuestPacketError> {
    let mut labels = Vec::new();
    loop {
        if *pos >= payload.len() {
            return Err(GuestPacketError::InvalidDnsQuery {
                reason: "unterminated name",
            });
        }
        let len = payload[*pos];
        *pos += 1;
        if len & 0xc0 != 0 {
            return Err(GuestPacketError::UnsupportedDnsCompression);
        }
        if len == 0 {
            break;
        }
        let len = usize::from(len);
        if len > 63 || *pos + len > payload.len() {
            return Err(GuestPacketError::InvalidDnsQuery {
                reason: "invalid label length",
            });
        }
        let label = std::str::from_utf8(&payload[*pos..*pos + len]).map_err(|_| {
            GuestPacketError::InvalidDnsQuery {
                reason: "name label is not UTF-8",
            }
        })?;
        labels.push(label.to_string());
        *pos += len;
    }
    if labels.is_empty() {
        return Err(GuestPacketError::InvalidDnsQuery {
            reason: "root name is not supported",
        });
    }
    DnsName::new(labels.join(".")).map_err(GuestPacketError::from)
}

fn record_type_from_qtype(qtype: u16) -> Result<DnsRecordType, GuestPacketError> {
    match qtype {
        1 => Ok(DnsRecordType::A),
        5 => Ok(DnsRecordType::Cname),
        16 => Ok(DnsRecordType::Txt),
        28 => Ok(DnsRecordType::Aaaa),
        _ => Err(GuestPacketError::UnsupportedDnsType { qtype }),
    }
}

fn qtype_for_record_type(record_type: DnsRecordType) -> u16 {
    match record_type {
        DnsRecordType::A => 1,
        DnsRecordType::Cname => 5,
        DnsRecordType::Txt => 16,
        DnsRecordType::Aaaa => 28,
    }
}

fn build_dns_response_payload(
    response: &DnsResponse,
    context: &DnsQueryContext,
) -> Result<Vec<u8>, GuestPacketError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&context.tx_id.to_be_bytes());
    payload.extend_from_slice(&(0x8180u16 | rcode(response.code)).to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    let answer_count = if response.code == DnsResponseCode::Ok {
        response.answers.len()
    } else {
        0
    };
    let answer_count: u16 =
        answer_count
            .try_into()
            .map_err(|_| GuestPacketError::PayloadTooLarge {
                actual: answer_count,
                max: u16::MAX as usize,
            })?;
    payload.extend_from_slice(&answer_count.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&encode_dns_name(context.name.as_str())?);
    payload.extend_from_slice(&qtype_for_record_type(context.record_type).to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());

    if response.code == DnsResponseCode::Ok {
        for answer in &response.answers {
            append_dns_answer(&mut payload, answer)?;
        }
    }

    Ok(payload)
}

fn append_dns_answer(payload: &mut Vec<u8>, answer: &DnsAnswer) -> Result<(), GuestPacketError> {
    payload.extend_from_slice(&encode_dns_name(answer.name.as_str())?);
    payload.extend_from_slice(&qtype_for_record_type(answer.record_type).to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&answer.ttl_seconds.to_be_bytes());

    let rdata = match (&answer.record_type, &answer.data) {
        (DnsRecordType::A, DnsRecordData::Ip(IpAddr::V4(address))) => address.octets().to_vec(),
        (DnsRecordType::Aaaa, DnsRecordData::Ip(IpAddr::V6(address))) => address.octets().to_vec(),
        (DnsRecordType::Cname, DnsRecordData::Cname(name)) => encode_dns_name(name.as_str())?,
        (DnsRecordType::Txt, DnsRecordData::Txt(value)) => encode_txt_record(value)?,
        _ => return Err(GuestPacketError::DnsAnswerTypeMismatch),
    };
    let rdlen: u16 = rdata
        .len()
        .try_into()
        .map_err(|_| GuestPacketError::PayloadTooLarge {
            actual: rdata.len(),
            max: u16::MAX as usize,
        })?;
    payload.extend_from_slice(&rdlen.to_be_bytes());
    payload.extend_from_slice(&rdata);
    Ok(())
}

fn rcode(code: DnsResponseCode) -> u16 {
    match code {
        DnsResponseCode::Ok => 0,
        DnsResponseCode::NameError => 3,
        DnsResponseCode::Refused => 5,
        DnsResponseCode::ServerFailure => 2,
    }
}

fn encode_dns_name(name: &str) -> Result<Vec<u8>, GuestPacketError> {
    if name.len() > 253 {
        return Err(GuestPacketError::NameTooLong {
            name: name.to_string(),
        });
    }
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            return Err(GuestPacketError::InvalidDnsQuery {
                reason: "empty DNS label",
            });
        }
        if label.len() > 63 {
            return Err(GuestPacketError::LabelTooLong {
                label: label.to_string(),
            });
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

fn encode_txt_record(value: &str) -> Result<Vec<u8>, GuestPacketError> {
    if value.len() > 255 {
        return Err(GuestPacketError::PayloadTooLarge {
            actual: value.len(),
            max: 255,
        });
    }
    let mut out = Vec::with_capacity(value.len() + 1);
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    Ok(out)
}

fn build_icmp_echo_reply(context: &IcmpEchoContext) -> Result<Vec<u8>, GuestPacketError> {
    let mut packet = Vec::with_capacity(ICMP_ECHO_HEADER_LEN + context.payload.len());
    packet.push(0);
    packet.push(0);
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&context.identifier.to_be_bytes());
    packet.extend_from_slice(&context.sequence.to_be_bytes());
    packet.extend_from_slice(&context.payload);
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

#[derive(Debug, Copy, Clone)]
struct TcpPacketBuild<'a> {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    ack: u32,
    flags: u8,
    payload: &'a [u8],
}

fn build_tcp_packet(params: TcpPacketBuild<'_>) -> Result<Vec<u8>, GuestPacketError> {
    let tcp_len = TCP_MIN_HEADER_LEN + params.payload.len();
    let tcp_len: u16 = tcp_len
        .try_into()
        .map_err(|_| GuestPacketError::PayloadTooLarge {
            actual: tcp_len,
            max: u16::MAX as usize,
        })?;
    let mut packet = Vec::with_capacity(usize::from(tcp_len));
    packet.extend_from_slice(&params.src_port.to_be_bytes());
    packet.extend_from_slice(&params.dst_port.to_be_bytes());
    packet.extend_from_slice(&params.sequence.to_be_bytes());
    packet.extend_from_slice(&params.ack.to_be_bytes());
    packet.push(5 << 4);
    packet.push(params.flags);
    packet.extend_from_slice(&TCP_DEFAULT_WINDOW.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(params.payload);

    let mut checksum_input = Vec::with_capacity(12 + packet.len());
    checksum_input.extend_from_slice(&params.src_ip.octets());
    checksum_input.extend_from_slice(&params.dst_ip.octets());
    checksum_input.push(0);
    checksum_input.push(IPPROTO_TCP);
    checksum_input.extend_from_slice(&tcp_len.to_be_bytes());
    checksum_input.extend_from_slice(&packet);
    let checksum = internet_checksum(&checksum_input);
    packet[16..18].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

fn build_udp_packet(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, GuestPacketError> {
    let length = UDP_HEADER_LEN + payload.len();
    let length: u16 = length
        .try_into()
        .map_err(|_| GuestPacketError::PayloadTooLarge {
            actual: length,
            max: u16::MAX as usize,
        })?;
    let mut packet = Vec::with_capacity(usize::from(length));
    packet.extend_from_slice(&src_port.to_be_bytes());
    packet.extend_from_slice(&dst_port.to_be_bytes());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn build_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> Result<Vec<u8>, GuestPacketError> {
    let total_len = IPV4_MIN_HEADER_LEN + payload.len();
    let total_len: u16 = total_len
        .try_into()
        .map_err(|_| GuestPacketError::PayloadTooLarge {
            actual: total_len,
            max: u16::MAX as usize,
        })?;
    let mut packet = vec![0u8; IPV4_MIN_HEADER_LEN];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = IPV4_TTL;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let checksum = internet_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([*byte, 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest::{DEFAULT_GUEST_ADDRESS, DEFAULT_HOST_GATEWAY};
    use crate::proto::{Denial, DenialReason, DnsAnswer, DnsRecordData, DnsResponse};

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const PSH_ACK: u8 = 0x18;
    const FIN_ACK: u8 = 0x11;

    fn translator() -> GuestPacketTranslator {
        GuestPacketTranslator::default()
    }

    fn dns_query_payload(tx_id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&tx_id.to_be_bytes());
        payload.extend_from_slice(&0x0100u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&encode_dns_name(name).unwrap());
        payload.extend_from_slice(&qtype.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload
    }

    fn udp_ipv4_packet(src_port: u16, dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        build_ipv4_packet(
            DEFAULT_GUEST_ADDRESS,
            dst_ip,
            IPPROTO_UDP,
            build_udp_packet(src_port, dst_port, payload)
                .unwrap()
                .as_slice(),
        )
        .unwrap()
    }

    fn tcp_ipv4_packet(dst_ip: Ipv4Addr, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&49152u16.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&7u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(flags);
        tcp.extend_from_slice(&1024u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(payload);
        build_ipv4_packet(DEFAULT_GUEST_ADDRESS, dst_ip, IPPROTO_TCP, &tcp).unwrap()
    }

    fn icmp_echo_ipv4_packet(dst_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut icmp = Vec::new();
        icmp.push(8);
        icmp.push(0);
        icmp.extend_from_slice(&0u16.to_be_bytes());
        icmp.extend_from_slice(&99u16.to_be_bytes());
        icmp.extend_from_slice(&3u16.to_be_bytes());
        icmp.extend_from_slice(payload);
        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        build_ipv4_packet(DEFAULT_GUEST_ADDRESS, dst_ip, IPPROTO_ICMP, &icmp).unwrap()
    }

    fn first_query_id(events: &[OutboundPacketEvent]) -> QueryId {
        match &events[0] {
            OutboundPacketEvent::DnsQuery(query) => query.query_id,
            OutboundPacketEvent::IcmpEchoRequest(request) => request.query_id,
            other => panic!("unexpected event: {other:?}"),
        }
    }

    fn first_flow_id(events: &[OutboundPacketEvent]) -> FlowId {
        match &events[0] {
            OutboundPacketEvent::OpenTcp(open) => open.flow_id,
            other => panic!("unexpected event: {other:?}"),
        }
    }

    fn parse_tcp_response(packet: &[u8]) -> (Ipv4Packet<'_>, TcpPacket<'_>) {
        let ipv4 = parse_ipv4(packet).unwrap();
        assert_eq!(ipv4.protocol, IPPROTO_TCP);
        let tcp = parse_tcp(ipv4.body).unwrap();
        (ipv4, tcp)
    }

    #[test]
    fn dns_query_packet_translates_and_response_synthesizes_packet() {
        let mut translator = translator();
        let query_payload = dns_query_payload(0x1234, "Google.COM", 1);
        let packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &query_payload);

        let events = translator.translate_outbound_ipv4(&packet).unwrap();
        assert_eq!(events.len(), 1);
        let query_id = match &events[0] {
            OutboundPacketEvent::DnsQuery(query) => {
                assert_eq!(query.name.as_str(), "google.com");
                assert_eq!(query.record_type, DnsRecordType::A);
                query.query_id
            }
            other => panic!("unexpected event: {other:?}"),
        };

        let synthetic_ip = Ipv4Addr::new(198, 19, 0, 10);
        let response_packet = translator
            .synthesize_dns_response(&DnsResponse {
                query_id,
                code: DnsResponseCode::Ok,
                answers: vec![DnsAnswer {
                    name: DnsName::new("google.com").unwrap(),
                    record_type: DnsRecordType::A,
                    data: DnsRecordData::Ip(IpAddr::V4(synthetic_ip)),
                    ttl_seconds: 30,
                }],
                denial: None,
            })
            .unwrap();

        let ipv4 = parse_ipv4(&response_packet).unwrap();
        assert_eq!(ipv4.src, DEFAULT_HOST_GATEWAY);
        assert_eq!(ipv4.dst, DEFAULT_GUEST_ADDRESS);
        let udp = parse_udp(ipv4.body).unwrap();
        assert_eq!(udp.src_port, DNS_PORT);
        assert_eq!(udp.dst_port, 40000);
        assert_eq!(&udp.payload[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([udp.payload[6], udp.payload[7]]), 1);

        let syn = tcp_ipv4_packet(synthetic_ip, 443, SYN, &[]);
        let events = translator.translate_outbound_ipv4(&syn).unwrap();
        assert!(matches!(
            &events[0],
            OutboundPacketEvent::OpenTcp(open)
                if open.target.host() == "google.com" && open.target.port() == 443
        ));
    }

    #[test]
    fn tcp_syn_data_and_fin_translate_to_flow_events() {
        let mut translator = translator();
        let target_ip = Ipv4Addr::new(198, 19, 0, 20);
        translator.remember_synthetic_host(target_ip, DnsName::new("api.example.com").unwrap());

        let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
        let events = translator.translate_outbound_ipv4(&syn).unwrap();
        let flow_id = match &events[0] {
            OutboundPacketEvent::OpenTcp(open) => {
                assert_eq!(open.target.host(), "api.example.com");
                open.flow_id
            }
            other => panic!("unexpected event: {other:?}"),
        };

        let ack = tcp_ipv4_packet(target_ip, 443, ACK, &[]);
        assert!(translator.translate_outbound_ipv4(&ack).unwrap().is_empty());

        let data = tcp_ipv4_packet(target_ip, 443, PSH_ACK, b"GET / HTTP/1.1\r\n\r\n");
        let events = translator.translate_outbound_ipv4(&data).unwrap();
        assert!(matches!(
            &events[0],
            OutboundPacketEvent::TcpData(chunk)
                if chunk.flow_id == flow_id
                    && chunk.direction == FlowDirection::GuestToHost
                    && chunk.bytes == b"GET / HTTP/1.1\r\n\r\n"
        ));

        let fin = tcp_ipv4_packet(target_ip, 443, FIN_ACK, &[]);
        let events = translator.translate_outbound_ipv4(&fin).unwrap();
        assert!(matches!(
            &events[0],
            OutboundPacketEvent::CloseFlow(close)
                if close.flow_id == flow_id && close.reason == CloseReason::GuestClosed
        ));
    }

    #[test]
    fn tcp_open_result_synthesizes_syn_ack_and_denial_rst() {
        let target_ip = Ipv4Addr::new(198, 19, 0, 21);
        let mut open_translator = translator();
        let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
        let flow_id = first_flow_id(&open_translator.translate_outbound_ipv4(&syn).unwrap());

        let packet = open_translator
            .synthesize_tcp_open_result(&TcpOpenResult::opened(flow_id))
            .unwrap();
        let (ipv4, tcp) = parse_tcp_response(&packet);
        assert_eq!(ipv4.src, target_ip);
        assert_eq!(ipv4.dst, DEFAULT_GUEST_ADDRESS);
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 49152);
        assert_eq!(tcp.flags, SYN | ACK);
        assert_eq!(tcp.sequence, host_initial_sequence(flow_id));
        assert_eq!(tcp.ack_number, 8);

        let mut denied_translator = translator();
        let denied_flow = first_flow_id(&denied_translator.translate_outbound_ipv4(&syn).unwrap());
        let packet = denied_translator
            .synthesize_tcp_open_result(&TcpOpenResult::denied(
                denied_flow,
                Denial::new(DenialReason::HostNotAllowed),
            ))
            .unwrap();
        let (_, tcp) = parse_tcp_response(&packet);
        assert_eq!(tcp.flags, TCP_FLAG_RST | TCP_FLAG_ACK);
        assert!(matches!(
            denied_translator.synthesize_tcp_data(&StreamChunk::new(
                denied_flow,
                FlowDirection::HostToGuest,
                0,
                b"late".to_vec(),
            )),
            Err(GuestPacketError::UnknownTcpFlow)
        ));
    }

    #[test]
    fn tcp_data_and_close_synthesize_ordered_guest_packets() {
        let target_ip = Ipv4Addr::new(198, 19, 0, 22);
        let mut translator = translator();
        let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
        let flow_id = first_flow_id(&translator.translate_outbound_ipv4(&syn).unwrap());
        translator
            .synthesize_tcp_open_result(&TcpOpenResult::opened(flow_id))
            .unwrap();

        let packet = translator
            .synthesize_tcp_data(&StreamChunk::new(
                flow_id,
                FlowDirection::HostToGuest,
                0,
                b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            ))
            .unwrap()
            .expect("non-empty host chunk should synthesize a TCP packet");
        let (_, tcp) = parse_tcp_response(&packet);
        assert_eq!(tcp.flags, TCP_FLAG_PSH | TCP_FLAG_ACK);
        assert_eq!(tcp.sequence, host_initial_sequence(flow_id).wrapping_add(1));
        assert_eq!(tcp.ack_number, 8);
        assert_eq!(tcp.payload, b"HTTP/1.1 200 OK\r\n\r\n");

        let close_packet = translator
            .synthesize_tcp_close(&CloseFlow {
                flow_id,
                reason: CloseReason::HostClosed,
            })
            .unwrap();
        let (_, close_tcp) = parse_tcp_response(&close_packet);
        assert_eq!(close_tcp.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert_eq!(
            close_tcp.sequence,
            host_initial_sequence(flow_id)
                .wrapping_add(1)
                .wrapping_add(b"HTTP/1.1 200 OK\r\n\r\n".len() as u32)
        );
    }

    #[test]
    fn tcp_host_data_refuses_wrong_direction_and_out_of_order_sequence() {
        let target_ip = Ipv4Addr::new(198, 19, 0, 23);
        let mut translator = translator();
        let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
        let flow_id = first_flow_id(&translator.translate_outbound_ipv4(&syn).unwrap());

        assert!(matches!(
            translator.synthesize_tcp_data(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                b"bad".to_vec(),
            )),
            Err(GuestPacketError::UnexpectedFlowDirection { .. })
        ));
        assert!(matches!(
            translator.synthesize_tcp_data(&StreamChunk::new(
                flow_id,
                FlowDirection::HostToGuest,
                1,
                b"late".to_vec(),
            )),
            Err(GuestPacketError::OutOfOrderTcpData {
                expected: 0,
                actual: 1
            })
        ));
    }

    #[test]
    fn udp_datagram_uses_ip_literal_without_dns_mapping() {
        let mut translator = translator();
        let dst_ip = Ipv4Addr::new(203, 0, 113, 7);
        let packet = udp_ipv4_packet(50000, dst_ip, 123, b"time?");

        let events = translator.translate_outbound_ipv4(&packet).unwrap();
        assert!(matches!(
            &events[0],
            OutboundPacketEvent::UdpDatagram(datagram)
                if datagram.target.host() == "203.0.113.7"
                    && datagram.target.port() == 123
                    && datagram.bytes == b"time?"
        ));
    }

    #[test]
    fn icmp_echo_request_and_response_roundtrip() {
        let mut translator = translator();
        let target_ip = Ipv4Addr::new(198, 19, 0, 30);
        translator.remember_synthetic_host(target_ip, DnsName::new("ping.example.com").unwrap());

        let packet = icmp_echo_ipv4_packet(target_ip, b"hello");
        let events = translator.translate_outbound_ipv4(&packet).unwrap();
        let query_id = first_query_id(&events);
        assert!(matches!(
            &events[0],
            OutboundPacketEvent::IcmpEchoRequest(request)
                if request.host.as_str() == "ping.example.com" && request.payload_len == 5
        ));

        let response_packet = translator
            .synthesize_icmp_echo_response(&IcmpEchoResponse {
                query_id,
                status: IcmpEchoStatus::Replied,
                round_trip_micros: Some(500),
                denial: None,
            })
            .unwrap()
            .expect("replied ICMP response should synthesize a packet");
        let ipv4 = parse_ipv4(&response_packet).unwrap();
        assert_eq!(ipv4.src, target_ip);
        assert_eq!(ipv4.dst, DEFAULT_GUEST_ADDRESS);
        assert_eq!(ipv4.protocol, IPPROTO_ICMP);
        assert_eq!(ipv4.body[0], 0);
        assert_eq!(&ipv4.body[8..], b"hello");
    }

    #[test]
    fn denied_icmp_response_drops_pending_query_without_packet() {
        let mut translator = translator();
        let packet = icmp_echo_ipv4_packet(Ipv4Addr::new(203, 0, 113, 8), b"hello");
        let events = translator.translate_outbound_ipv4(&packet).unwrap();
        let query_id = first_query_id(&events);

        let response = translator
            .synthesize_icmp_echo_response(&IcmpEchoResponse {
                query_id,
                status: IcmpEchoStatus::Denied,
                round_trip_micros: None,
                denial: None,
            })
            .unwrap();
        assert!(response.is_none());
        assert!(matches!(
            translator.synthesize_icmp_echo_response(&IcmpEchoResponse {
                query_id,
                status: IcmpEchoStatus::Replied,
                round_trip_micros: Some(1),
                denial: None,
            }),
            Err(GuestPacketError::UnknownIcmpQuery { .. })
        ));
    }

    #[test]
    fn fragmented_ipv4_is_refused() {
        let payload = dns_query_payload(1, "example.com", 1);
        let mut packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &payload);
        packet[6] = 0x20;

        assert_eq!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::FragmentedIpv4)
        );
    }

    #[test]
    fn malformed_dns_query_is_rejected() {
        let packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &[0; DNS_HEADER_LEN]);

        assert!(matches!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::InvalidDnsQuery { .. })
        ));
    }

    #[test]
    fn config_rejects_zero_limits() {
        assert!(matches!(
            GuestPacketTranslatorConfig::builder()
                .max_pending_queries(0)
                .build(),
            Err(GuestPacketError::PendingQueryLimit)
        ));
        assert!(matches!(
            GuestPacketTranslatorConfig::builder().max_flows(0).build(),
            Err(GuestPacketError::FlowLimit)
        ));
    }
}
