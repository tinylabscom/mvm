//! Dependency-light guest packet translation for the transparent network bridge.
//!
//! The translator handles the TUN boundary: outbound IPv4 packets become
//! protocol events for the host authority, and selected authority responses can
//! be synthesized back into IPv4 packets for the guest. It intentionally does
//! not contain a complete TCP state machine yet; TCP packets are classified into
//! open/data/close events that the next bridge layer will drive.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::guest::{DEFAULT_GUEST_ADDRESS, DEFAULT_HOST_GATEWAY};
use crate::proto::{
    CloseFlow, CloseReason, DnsAnswer, DnsName, DnsQuery, DnsRecordData, DnsRecordType,
    DnsResponse, DnsResponseCode, FlowDirection, FlowId, HostName, IcmpEchoRequest,
    IcmpEchoResponse, IcmpEchoStatus, MAX_STREAM_CHUNK_BYTES, NetMessage, OpenTcp, PluginId,
    ProtocolError, QueryId, StreamChunk, Target, TcpOpenResult, TlsTermination, TlsTransformRoute,
    UdpDatagram,
};

const IPV4_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const TCP_MIN_HEADER_LEN: usize = 20;
const ICMP_ECHO_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const DNS_PORT: u16 = 53;
const AUDIT_PLUGIN_ID: &str = "audit";
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPV4_TTL: u8 = 64;
const METADATA_ENDPOINT_DENY_PLUGIN_ID: &str = "metadata-endpoint-deny";
const DEFAULT_MAX_PENDING_QUERIES: usize = 4096;
const DEFAULT_PENDING_QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_QUERY_TIMEOUT: Duration = DEFAULT_PENDING_QUERY_TIMEOUT;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_DEFAULT_WINDOW: u16 = 65535;
const DEFAULT_MAX_FLOWS: usize = 16384;
const DEFAULT_MAX_SYNTHETIC_HOSTS: usize = 65_534;

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
    InvalidPendingQueryTimeout,
    PendingQueryTimeoutTooLarge {
        actual: Duration,
        max: Duration,
    },
    FlowLimit,
    InvalidSyntheticHostLimit,
    PendingQueryLimitTooLarge {
        actual: usize,
        max: usize,
    },
    FlowLimitTooLarge {
        actual: usize,
        max: usize,
    },
    SyntheticHostLimitTooLarge {
        actual: usize,
        max: usize,
    },
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
    UnknownUdpFlow,
    UnknownOutboundTcpFlow {
        sequence: u32,
        flags: u8,
        payload_len: usize,
    },
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
            Self::InvalidPendingQueryTimeout => {
                write!(f, "guest pending query timeout must be non-zero")
            }
            Self::PendingQueryTimeoutTooLarge { actual, max } => write!(
                f,
                "guest pending query timeout {} ms exceeds hard maximum {} ms",
                actual.as_millis(),
                max.as_millis()
            ),
            Self::FlowLimit => write!(f, "guest network flow limit reached"),
            Self::InvalidSyntheticHostLimit => {
                write!(f, "guest synthetic host mapping limit must be non-zero")
            }
            Self::PendingQueryLimitTooLarge { actual, max } => write!(
                f,
                "guest pending query limit {actual} exceeds hard maximum {max}"
            ),
            Self::FlowLimitTooLarge { actual, max } => {
                write!(f, "guest flow limit {actual} exceeds hard maximum {max}")
            }
            Self::SyntheticHostLimitTooLarge { actual, max } => write!(
                f,
                "guest synthetic host mapping limit {actual} exceeds hard maximum {max}"
            ),
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
            Self::UnknownUdpFlow => write!(f, "UDP datagram did not match an opened flow"),
            Self::UnknownOutboundTcpFlow {
                sequence,
                flags,
                payload_len,
            } => write!(
                f,
                "TCP packet did not match an opened flow (seq={sequence}, flags=0x{flags:02x}, payload_bytes={payload_len})"
            ),
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
    pending_query_timeout: Duration,
    max_flows: usize,
    max_synthetic_hosts: usize,
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

    pub const fn pending_query_timeout(&self) -> Duration {
        self.pending_query_timeout
    }

    pub const fn max_flows(&self) -> usize {
        self.max_flows
    }

    pub const fn max_synthetic_hosts(&self) -> usize {
        self.max_synthetic_hosts
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
    pending_query_timeout: Duration,
    max_flows: usize,
    max_synthetic_hosts: usize,
}

impl Default for GuestPacketTranslatorConfigBuilder {
    fn default() -> Self {
        Self {
            guest_address: DEFAULT_GUEST_ADDRESS,
            gateway_address: DEFAULT_HOST_GATEWAY,
            max_pending_queries: DEFAULT_MAX_PENDING_QUERIES,
            pending_query_timeout: DEFAULT_PENDING_QUERY_TIMEOUT,
            max_flows: DEFAULT_MAX_FLOWS,
            max_synthetic_hosts: DEFAULT_MAX_SYNTHETIC_HOSTS,
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

    pub fn pending_query_timeout(mut self, pending_query_timeout: Duration) -> Self {
        self.pending_query_timeout = pending_query_timeout;
        self
    }

    pub fn max_flows(mut self, max_flows: usize) -> Self {
        self.max_flows = max_flows;
        self
    }

    pub fn max_synthetic_hosts(mut self, max_synthetic_hosts: usize) -> Self {
        self.max_synthetic_hosts = max_synthetic_hosts;
        self
    }

    pub fn build(self) -> Result<GuestPacketTranslatorConfig, GuestPacketError> {
        if self.max_pending_queries == 0 {
            return Err(GuestPacketError::PendingQueryLimit);
        }
        if self.max_pending_queries > DEFAULT_MAX_PENDING_QUERIES {
            return Err(GuestPacketError::PendingQueryLimitTooLarge {
                actual: self.max_pending_queries,
                max: DEFAULT_MAX_PENDING_QUERIES,
            });
        }
        if self.pending_query_timeout.is_zero() {
            return Err(GuestPacketError::InvalidPendingQueryTimeout);
        }
        if self.pending_query_timeout > MAX_PENDING_QUERY_TIMEOUT {
            return Err(GuestPacketError::PendingQueryTimeoutTooLarge {
                actual: self.pending_query_timeout,
                max: MAX_PENDING_QUERY_TIMEOUT,
            });
        }
        if self.max_flows == 0 {
            return Err(GuestPacketError::FlowLimit);
        }
        if self.max_flows > DEFAULT_MAX_FLOWS {
            return Err(GuestPacketError::FlowLimitTooLarge {
                actual: self.max_flows,
                max: DEFAULT_MAX_FLOWS,
            });
        }
        if self.max_synthetic_hosts == 0 {
            return Err(GuestPacketError::InvalidSyntheticHostLimit);
        }
        if self.max_synthetic_hosts > DEFAULT_MAX_SYNTHETIC_HOSTS {
            return Err(GuestPacketError::SyntheticHostLimitTooLarge {
                actual: self.max_synthetic_hosts,
                max: DEFAULT_MAX_SYNTHETIC_HOSTS,
            });
        }
        Ok(GuestPacketTranslatorConfig {
            guest_address: self.guest_address,
            gateway_address: self.gateway_address,
            max_pending_queries: self.max_pending_queries,
            pending_query_timeout: self.pending_query_timeout,
            max_flows: self.max_flows,
            max_synthetic_hosts: self.max_synthetic_hosts,
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
    next_synthetic_host_generation: u64,
    pending_dns: HashMap<QueryId, DnsQueryContext>,
    pending_icmp: HashMap<QueryId, IcmpEchoContext>,
    tcp_flows: HashMap<FlowKey, TcpFlowState>,
    tcp_flow_keys: HashMap<FlowId, FlowKey>,
    closed_tcp_flows: HashMap<FlowKey, ClosedTcpFlowState>,
    closed_tcp_flow_order: VecDeque<FlowKey>,
    udp_flows: HashMap<FlowKey, FlowId>,
    udp_flow_keys: HashMap<FlowId, FlowKey>,
    udp_flow_order: VecDeque<FlowId>,
    closed_udp_flows: HashSet<FlowId>,
    closed_udp_flow_order: VecDeque<FlowId>,
    synthetic_hosts: HashMap<Ipv4Addr, SyntheticHostEntry>,
    synthetic_host_order: VecDeque<SyntheticHostRef>,
}

impl GuestPacketTranslator {
    pub fn new(config: GuestPacketTranslatorConfig) -> Self {
        Self {
            config,
            next_query_id: 1,
            next_flow_id: 1,
            next_synthetic_host_generation: 0,
            pending_dns: HashMap::new(),
            pending_icmp: HashMap::new(),
            tcp_flows: HashMap::new(),
            tcp_flow_keys: HashMap::new(),
            closed_tcp_flows: HashMap::new(),
            closed_tcp_flow_order: VecDeque::new(),
            udp_flows: HashMap::new(),
            udp_flow_keys: HashMap::new(),
            udp_flow_order: VecDeque::new(),
            closed_udp_flows: HashSet::new(),
            closed_udp_flow_order: VecDeque::new(),
            synthetic_hosts: HashMap::new(),
            synthetic_host_order: VecDeque::new(),
        }
    }

    pub fn config(&self) -> &GuestPacketTranslatorConfig {
        &self.config
    }

    pub fn remember_synthetic_host(&mut self, address: Ipv4Addr, host: DnsName) -> Option<DnsName> {
        self.insert_synthetic_host(address, host)
    }

    pub fn remember_dns_response(&mut self, response: &DnsResponse) {
        if response.code != DnsResponseCode::Ok {
            return;
        }
        for answer in &response.answers {
            if let DnsRecordData::Ip(IpAddr::V4(address)) = answer.data {
                self.insert_synthetic_host(address, answer.name.clone());
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
        self.prune_expired_pending_queries(Instant::now());
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
        self.prune_expired_pending_queries(Instant::now());
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

    pub fn synthesize_udp_datagram(
        &mut self,
        datagram: &UdpDatagram,
    ) -> Result<Option<Vec<u8>>, GuestPacketError> {
        if datagram.direction != FlowDirection::HostToGuest {
            return Err(GuestPacketError::UnexpectedFlowDirection {
                expected: FlowDirection::HostToGuest,
                actual: datagram.direction,
            });
        }
        let Some(key) = self.udp_flow_keys.get(&datagram.flow_id).copied() else {
            if self.closed_udp_flows.contains(&datagram.flow_id) {
                return Ok(None);
            }
            return Err(GuestPacketError::UnknownUdpFlow);
        };
        let udp_payload = build_udp_packet(key.dst_port, key.src_port, datagram.bytes.as_slice())?;
        build_ipv4_packet(key.dst_ip, key.src_ip, IPPROTO_UDP, udp_payload.as_slice()).map(Some)
    }

    pub fn apply_udp_delivery(&mut self, delivery: &crate::proto::UdpDelivery) {
        if !matches!(
            delivery.status,
            crate::proto::DatagramStatus::Denied(_) | crate::proto::DatagramStatus::Failed(_)
        ) {
            return;
        }
        self.remove_udp_flow(delivery.flow_id);
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
                (true, false) => TCP_FLAG_ACK,
                (true, true) => TCP_FLAG_FIN | TCP_FLAG_ACK,
                (false, true) => TCP_FLAG_PSH | TCP_FLAG_FIN | TCP_FLAG_ACK,
                (false, false) => TCP_FLAG_PSH | TCP_FLAG_ACK,
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
        // Treat any well-formed UDP/53 packet as DNS, regardless of which
        // resolver IP the image's libc or local stub resolver chose. Some OCI
        // images boot with loopback stub resolvers in /etc/resolv.conf;
        // transparent networking still needs those queries to flow through the
        // hostname policy path instead of being denied as raw UDP to a
        // guest-local stub address.
        if udp.dst_port == DNS_PORT {
            match parse_dns_query(udp.payload) {
                Ok(question) => {
                    let query_id = self.alloc_query_id()?;
                    self.reserve_pending_query()?;
                    self.pending_dns.insert(
                        query_id,
                        DnsQueryContext {
                            created_at: Instant::now(),
                            tx_id: question.tx_id,
                            src_ip: packet.src,
                            dst_ip: packet.dst,
                            src_port: udp.src_port,
                            dst_port: udp.dst_port,
                            name: question.name.clone(),
                            record_type: question.record_type,
                        },
                    );
                    let events = vec![OutboundPacketEvent::DnsQuery(DnsQuery {
                        query_id,
                        name: question.name,
                        record_type: question.record_type,
                    })];
                    return Ok(events);
                }
                // The synthetic-gateway DNS path must still fail closed on
                // malformed DNS instead of silently downgrading to raw UDP.
                Err(err) if packet.dst == self.config.gateway_address => return Err(err),
                Err(_) => {}
            }
        }

        let key = FlowKey::new(packet.src, udp.src_port, packet.dst, udp.dst_port);
        let flow_id = self.udp_flow_id(key)?;
        let target = self.target_for_ip(packet.dst, udp.dst_port)?;
        let events = vec![OutboundPacketEvent::UdpDatagram(UdpDatagram {
            flow_id,
            target,
            direction: FlowDirection::GuestToHost,
            bytes: udp.payload.to_vec(),
        })];
        Ok(events)
    }

    fn translate_tcp(
        &mut self,
        packet: Ipv4Packet<'_>,
    ) -> Result<Vec<OutboundPacketEvent>, GuestPacketError> {
        let tcp = parse_tcp(packet.body)?;
        let key = FlowKey::new(packet.src, tcp.src_port, packet.dst, tcp.dst_port);
        let mut events = Vec::with_capacity(3);

        if tcp.syn() && !tcp.ack() {
            let (flow_id, is_new_flow) = self.tcp_flow_id(key, tcp.sequence)?;
            if is_new_flow {
                let target = self.target_for_ip(packet.dst, tcp.dst_port)?;
                let mut open = OpenTcp::new(flow_id, target);
                if tcp.dst_port == 443
                    && let Some(server_name) = self
                        .synthetic_hosts
                        .get(&packet.dst)
                        .map(|entry| entry.host.clone())
                {
                    open = open.with_tls_transform(
                        TlsTransformRoute::new(
                            server_name,
                            TlsTermination::TerminateAndReoriginate,
                        )
                        .with_transform_chain(default_tls_transform_chain()?),
                    );
                }
                events.push(OutboundPacketEvent::OpenTcp(open));
            }
        }

        if !tcp.payload.is_empty() {
            if tcp.payload.len() > MAX_STREAM_CHUNK_BYTES {
                return Err(GuestPacketError::PayloadTooLarge {
                    actual: tcp.payload.len(),
                    max: MAX_STREAM_CHUNK_BYTES,
                });
            }
            let flow_id = match self.tcp_flows.get(&key).map(|state| state.flow_id) {
                Some(flow_id) => flow_id,
                None if self.matches_closed_tcp_retransmit(
                    key,
                    tcp.sequence,
                    tcp.payload.len(),
                    tcp.fin(),
                ) =>
                {
                    return Ok(Vec::new());
                }
                None if self.closed_tcp_flows.contains_key(&key) => {
                    return Ok(Vec::new());
                }
                None => {
                    return Err(GuestPacketError::UnknownOutboundTcpFlow {
                        sequence: tcp.sequence,
                        flags: tcp.flags,
                        payload_len: tcp.payload.len(),
                    });
                }
            };
            let mut chunk = StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                u64::from(tcp.sequence),
                tcp.payload.to_vec(),
            );
            if tcp.fin() {
                chunk = chunk.with_end_stream();
            }
            events.push(OutboundPacketEvent::TcpData(chunk));
        } else if tcp.fin() {
            let flow_id = match self.tcp_flows.get(&key).map(|state| state.flow_id) {
                Some(flow_id) => flow_id,
                None if self.matches_closed_tcp_retransmit(key, tcp.sequence, 0, true) => {
                    return Ok(Vec::new());
                }
                None if self.closed_tcp_flows.contains_key(&key) => {
                    return Ok(Vec::new());
                }
                None => {
                    return Err(GuestPacketError::UnknownOutboundTcpFlow {
                        sequence: tcp.sequence,
                        flags: tcp.flags,
                        payload_len: 0,
                    });
                }
            };
            events.push(OutboundPacketEvent::TcpData(
                StreamChunk::new(
                    flow_id,
                    FlowDirection::GuestToHost,
                    u64::from(tcp.sequence),
                    Vec::new(),
                )
                .with_end_stream(),
            ));
        }

        if let Some(state) = self.tcp_flows.get_mut(&key) {
            state.observe_guest_segment(tcp.sequence, tcp.payload.len(), tcp.syn(), tcp.fin());
        }

        if tcp.rst() {
            if let Some(state) = self.tcp_flows.remove(&key) {
                self.tcp_flow_keys.remove(&state.flow_id);
                events.push(OutboundPacketEvent::CloseFlow(CloseFlow {
                    flow_id: state.flow_id,
                    reason: CloseReason::ProtocolError,
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
                created_at: Instant::now(),
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

    fn reserve_pending_query(&mut self) -> Result<(), GuestPacketError> {
        self.prune_expired_pending_queries(Instant::now());
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

    fn prune_expired_pending_queries(&mut self, now: Instant) {
        let timeout = self.config.pending_query_timeout();
        self.pending_dns
            .retain(|_, context| now.saturating_duration_since(context.created_at) < timeout);
        self.pending_icmp
            .retain(|_, context| now.saturating_duration_since(context.created_at) < timeout);
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
    ) -> Result<(FlowId, bool), GuestPacketError> {
        if let Some(state) = self.tcp_flows.get(&key) {
            return Ok((state.flow_id, false));
        }
        self.reserve_flow()?;
        let flow_id = self.alloc_flow_id()?;
        self.closed_tcp_flows.remove(&key);
        drop_closed_tcp_flow_refs(&mut self.closed_tcp_flow_order, key);
        self.tcp_flow_keys.insert(flow_id, key);
        self.tcp_flows
            .insert(key, TcpFlowState::new(flow_id, key, guest_syn_sequence));
        Ok((flow_id, true))
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
        let state = self
            .tcp_flows
            .remove(&key)
            .ok_or(GuestPacketError::UnknownTcpFlow)?;
        self.remember_closed_tcp_flow(&state);
        Ok(state)
    }

    fn remember_closed_tcp_flow(&mut self, state: &TcpFlowState) {
        drop_closed_tcp_flow_refs(&mut self.closed_tcp_flow_order, state.key);
        self.closed_tcp_flows
            .insert(state.key, ClosedTcpFlowState::from_tcp_state(state));
        self.closed_tcp_flow_order.push_back(state.key);
        while self.closed_tcp_flows.len() > self.config.max_flows() {
            let Some(oldest) = self.closed_tcp_flow_order.pop_front() else {
                break;
            };
            self.closed_tcp_flows.remove(&oldest);
        }
    }

    fn matches_closed_tcp_retransmit(
        &self,
        key: FlowKey,
        sequence: u32,
        payload_len: usize,
        fin: bool,
    ) -> bool {
        self.closed_tcp_flows
            .get(&key)
            .is_some_and(|closed| closed.matches_retransmit(sequence, payload_len, fin))
    }

    fn udp_flow_id(&mut self, key: FlowKey) -> Result<FlowId, GuestPacketError> {
        if let Some(flow_id) = self.udp_flows.get(&key).copied() {
            return Ok(flow_id);
        }
        self.ensure_udp_flow_capacity()?;
        self.reserve_flow()?;
        let flow_id = self.alloc_flow_id()?;
        self.udp_flows.insert(key, flow_id);
        self.udp_flow_keys.insert(flow_id, key);
        self.udp_flow_order.push_back(flow_id);
        Ok(flow_id)
    }

    fn ensure_udp_flow_capacity(&mut self) -> Result<(), GuestPacketError> {
        while self.tcp_flows.len() + self.udp_flows.len() >= self.config.max_flows() {
            if !self.evict_oldest_udp_flow() {
                return Err(GuestPacketError::FlowLimit);
            }
        }
        Ok(())
    }

    fn evict_oldest_udp_flow(&mut self) -> bool {
        while let Some(flow_id) = self.udp_flow_order.pop_front() {
            if self.remove_udp_flow(flow_id).is_some() {
                return true;
            }
        }
        false
    }

    fn remove_udp_flow(&mut self, flow_id: FlowId) -> Option<FlowKey> {
        let key = self.udp_flow_keys.remove(&flow_id)?;
        self.udp_flows.remove(&key)?;
        drop_udp_flow_refs(&mut self.udp_flow_order, flow_id);
        self.remember_closed_udp_flow(flow_id);
        Some(key)
    }

    fn remember_closed_udp_flow(&mut self, flow_id: FlowId) {
        if self.closed_udp_flows.insert(flow_id) {
            self.closed_udp_flow_order.push_back(flow_id);
        }
        while self.closed_udp_flows.len() > self.config.max_flows() {
            let Some(oldest) = self.closed_udp_flow_order.pop_front() else {
                break;
            };
            self.closed_udp_flows.remove(&oldest);
        }
    }

    fn insert_synthetic_host(&mut self, address: Ipv4Addr, host: DnsName) -> Option<DnsName> {
        if self
            .synthetic_hosts
            .get(&address)
            .is_some_and(|entry| entry.host == host)
        {
            return None;
        }
        let generation = self.next_synthetic_host_generation;
        self.next_synthetic_host_generation = self.next_synthetic_host_generation.wrapping_add(1);
        let host_name = HostName::new(host.as_str())
            .expect("validated DNS name must also be a valid host name");
        let entry = SyntheticHostEntry {
            host: host.clone(),
            host_name,
            generation,
        };
        let previous = self
            .synthetic_hosts
            .insert(address, entry)
            .map(|entry| entry.host);
        drop_synthetic_host_refs(&mut self.synthetic_host_order, address);
        self.synthetic_host_order.push_back(SyntheticHostRef {
            address,
            generation,
        });
        self.enforce_synthetic_host_budget();
        previous
    }

    fn enforce_synthetic_host_budget(&mut self) {
        while self.synthetic_hosts.len() > self.config.max_synthetic_hosts() {
            if !self.evict_oldest_synthetic_host() {
                break;
            }
        }
    }

    fn evict_oldest_synthetic_host(&mut self) -> bool {
        while let Some(next) = self.synthetic_host_order.pop_front() {
            if remove_synthetic_host_if_current(&mut self.synthetic_hosts, next) {
                return true;
            }
        }
        false
    }

    fn target_for_ip(&self, address: Ipv4Addr, port: u16) -> Result<Target, GuestPacketError> {
        if let Some(entry) = self.synthetic_hosts.get(&address) {
            return Target::new(entry.host.as_str(), port).map_err(GuestPacketError::from);
        }
        Target::new(address.to_string(), port).map_err(GuestPacketError::from)
    }

    fn host_for_ip(&self, address: Ipv4Addr) -> Result<HostName, GuestPacketError> {
        if let Some(entry) = self.synthetic_hosts.get(&address) {
            return Ok(entry.host_name.clone());
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
    created_at: Instant,
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
    created_at: Instant,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ClosedTcpFlowState {
    guest_next_sequence: u32,
}

impl ClosedTcpFlowState {
    fn from_tcp_state(state: &TcpFlowState) -> Self {
        Self {
            guest_next_sequence: state.guest_next_sequence,
        }
    }

    fn matches_retransmit(self, sequence: u32, payload_len: usize, fin: bool) -> bool {
        let end_sequence = segment_end_sequence(sequence, payload_len, fin);
        tcp_sequence_lte(sequence, self.guest_next_sequence)
            && tcp_sequence_lte(end_sequence, self.guest_next_sequence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyntheticHostEntry {
    host: DnsName,
    host_name: HostName,
    generation: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct SyntheticHostRef {
    address: Ipv4Addr,
    generation: u64,
}

fn remove_synthetic_host_if_current(
    synthetic_hosts: &mut HashMap<Ipv4Addr, SyntheticHostEntry>,
    next: SyntheticHostRef,
) -> bool {
    if synthetic_hosts
        .get(&next.address)
        .is_some_and(|entry| entry.generation == next.generation)
    {
        synthetic_hosts.remove(&next.address);
        return true;
    }
    false
}

fn drop_synthetic_host_refs(order: &mut VecDeque<SyntheticHostRef>, address: Ipv4Addr) {
    order.retain(|entry| entry.address != address);
}

fn drop_closed_tcp_flow_refs(order: &mut VecDeque<FlowKey>, key: FlowKey) {
    order.retain(|entry| *entry != key);
}

fn drop_udp_flow_refs(order: &mut VecDeque<FlowId>, flow_id: FlowId) {
    order.retain(|entry| *entry != flow_id);
}

fn segment_end_sequence(sequence: u32, payload_len: usize, fin: bool) -> u32 {
    let mut consumed = payload_len as u32;
    if fin {
        consumed = consumed.wrapping_add(1);
    }
    sequence.wrapping_add(consumed)
}

fn tcp_sequence_lte(lhs: u32, rhs: u32) -> bool {
    lhs == rhs || ((lhs.wrapping_sub(rhs) as i32) < 0)
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

fn default_tls_transform_chain() -> Result<Vec<PluginId>, GuestPacketError> {
    Ok(vec![
        PluginId::new(AUDIT_PLUGIN_ID).map_err(GuestPacketError::from)?,
        PluginId::new(METADATA_ENDPOINT_DENY_PLUGIN_ID).map_err(GuestPacketError::from)?,
    ])
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
    let mut name = String::with_capacity(payload.len().saturating_sub(*pos));
    let mut saw_label = false;
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
        if saw_label {
            name.push('.');
        }
        name.push_str(label);
        saw_label = true;
        *pos += len;
    }
    if !saw_label {
        return Err(GuestPacketError::InvalidDnsQuery {
            reason: "root name is not supported",
        });
    }
    DnsName::new(name).map_err(GuestPacketError::from)
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
    let answer_count = if response.code == DnsResponseCode::Ok {
        response.answers.len()
    } else {
        0
    };
    let mut payload =
        Vec::with_capacity(estimated_dns_response_payload_capacity(context, response));
    payload.extend_from_slice(&context.tx_id.to_be_bytes());
    payload.extend_from_slice(&(0x8180u16 | rcode(response.code)).to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
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
    append_dns_name_to(&mut payload, context.name.as_str())?;
    payload.extend_from_slice(&qtype_for_record_type(context.record_type).to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());

    if response.code == DnsResponseCode::Ok {
        for answer in &response.answers {
            append_dns_answer(&mut payload, answer)?;
        }
    }

    Ok(payload)
}

fn estimated_dns_response_payload_capacity(
    context: &DnsQueryContext,
    response: &DnsResponse,
) -> usize {
    let header_len = 12usize;
    let question_len = context.name.as_str().len() + 2 + 4;
    let answers_len = if response.code == DnsResponseCode::Ok {
        response
            .answers
            .iter()
            .map(estimated_dns_answer_len)
            .sum::<usize>()
    } else {
        0
    };
    header_len + question_len + answers_len
}

fn estimated_dns_answer_len(answer: &DnsAnswer) -> usize {
    let name_len = answer.name.as_str().len() + 2;
    let fixed_fields_len = 2 + 2 + 4 + 2;
    let rdata_len = match (&answer.record_type, &answer.data) {
        (DnsRecordType::A, DnsRecordData::Ip(IpAddr::V4(_))) => 4,
        (DnsRecordType::Aaaa, DnsRecordData::Ip(IpAddr::V6(_))) => 16,
        (DnsRecordType::Cname, DnsRecordData::Cname(name)) => name.as_str().len() + 2,
        (DnsRecordType::Txt, DnsRecordData::Txt(value)) => value.len() + 1,
        _ => 0,
    };
    name_len + fixed_fields_len + rdata_len
}

fn append_dns_answer(payload: &mut Vec<u8>, answer: &DnsAnswer) -> Result<(), GuestPacketError> {
    append_dns_name_to(payload, answer.name.as_str())?;
    payload.extend_from_slice(&qtype_for_record_type(answer.record_type).to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&answer.ttl_seconds.to_be_bytes());

    match (&answer.record_type, &answer.data) {
        (DnsRecordType::A, DnsRecordData::Ip(IpAddr::V4(address))) => {
            payload.extend_from_slice(&(address.octets().len() as u16).to_be_bytes());
            payload.extend_from_slice(&address.octets());
            Ok(())
        }
        (DnsRecordType::Aaaa, DnsRecordData::Ip(IpAddr::V6(address))) => {
            payload.extend_from_slice(&(address.octets().len() as u16).to_be_bytes());
            payload.extend_from_slice(&address.octets());
            Ok(())
        }
        (DnsRecordType::Cname, DnsRecordData::Cname(name)) => {
            payload.extend_from_slice(&encoded_dns_name_wire_len(name.as_str()).to_be_bytes());
            append_dns_name_to(payload, name.as_str())?;
            Ok(())
        }
        (DnsRecordType::Txt, DnsRecordData::Txt(value)) => {
            let rdlen = encoded_txt_record_wire_len(value)?;
            payload.extend_from_slice(&rdlen.to_be_bytes());
            payload.push(value.len() as u8);
            payload.extend_from_slice(value.as_bytes());
            Ok(())
        }
        _ => Err(GuestPacketError::DnsAnswerTypeMismatch),
    }
}

fn rcode(code: DnsResponseCode) -> u16 {
    match code {
        DnsResponseCode::Ok => 0,
        DnsResponseCode::NameError => 3,
        DnsResponseCode::Refused => 5,
        DnsResponseCode::ServerFailure => 2,
    }
}

fn append_dns_name_to(out: &mut Vec<u8>, name: &str) -> Result<(), GuestPacketError> {
    if name.len() > 253 {
        return Err(GuestPacketError::NameTooLong {
            name: name.to_string(),
        });
    }
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
    Ok(())
}

fn encoded_dns_name_wire_len(name: &str) -> u16 {
    (name.trim_end_matches('.').len() + 2) as u16
}

#[cfg(test)]
fn encode_dns_name(name: &str) -> Result<Vec<u8>, GuestPacketError> {
    let mut out = Vec::with_capacity(name.len() + 2);
    append_dns_name_to(&mut out, name)?;
    Ok(out)
}

fn encoded_txt_record_wire_len(value: &str) -> Result<u16, GuestPacketError> {
    if value.len() > 255 {
        return Err(GuestPacketError::PayloadTooLarge {
            actual: value.len(),
            max: 255,
        });
    }
    Ok((value.len() + 1) as u16)
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

    let pseudo_header_reserved = [0, IPPROTO_TCP];
    let src_ip = params.src_ip.octets();
    let dst_ip = params.dst_ip.octets();
    let tcp_len_bytes = tcp_len.to_be_bytes();
    let checksum = internet_checksum_segments(&[
        src_ip.as_slice(),
        dst_ip.as_slice(),
        pseudo_header_reserved.as_slice(),
        tcp_len_bytes.as_slice(),
        packet.as_slice(),
    ]);
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
    let mut packet = Vec::with_capacity(usize::from(total_len));
    packet.resize(IPV4_MIN_HEADER_LEN, 0);
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
    finalize_checksum(checksum_words(bytes, 0))
}

fn internet_checksum_segments(segments: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut trailing = None;
    for segment in segments {
        sum = checksum_words_with_trailing_byte(segment, sum, &mut trailing);
    }
    if let Some(byte) = trailing {
        sum += u16::from_be_bytes([byte, 0]) as u32;
    }
    finalize_checksum(sum)
}

fn checksum_words(bytes: &[u8], sum: u32) -> u32 {
    let mut sum = sum;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([*byte, 0]) as u32;
    }
    sum
}

fn checksum_words_with_trailing_byte(bytes: &[u8], sum: u32, trailing: &mut Option<u8>) -> u32 {
    let mut sum = sum;
    let mut offset = 0usize;
    if let Some(byte) = trailing.take() {
        let Some(next) = bytes.first() else {
            *trailing = Some(byte);
            return sum;
        };
        sum += u16::from_be_bytes([byte, *next]) as u32;
        offset = 1;
    }

    let mut chunks = bytes[offset..].chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(byte) = chunks.remainder().first() {
        *trailing = Some(*byte);
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
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
        tcp_ipv4_packet_with_sequence(dst_ip, dst_port, 7, flags, payload)
    }

    fn tcp_ipv4_packet_with_sequence(
        dst_ip: Ipv4Addr,
        dst_port: u16,
        sequence: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&49152u16.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&sequence.to_be_bytes());
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
                if open.target.host() == "google.com"
                    && open.target.port() == 443
                    && open.tls_policy == crate::proto::TlsPolicy::RequiredForTransform
                    && open
                        .tls_transform
                        .as_ref()
                        .is_some_and(|route| {
                            route.server_name.as_str() == "google.com"
                                && route
                                    .transform_chain
                                    .iter()
                                    .map(|plugin| plugin.as_str())
                                    .eq([AUDIT_PLUGIN_ID, METADATA_ENDPOINT_DENY_PLUGIN_ID])
                        })
        ));
    }

    #[test]
    fn encode_dns_name_seeds_capacity_from_input_length() {
        let encoded = encode_dns_name("api.example.com").unwrap();

        assert_eq!(
            encoded,
            vec![
                3, b'a', b'p', b'i', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0,
            ]
        );
        assert!(encoded.capacity() >= "api.example.com".len() + 2);
    }

    #[test]
    fn append_dns_name_to_appends_wire_encoding_without_temporary_vec() {
        let mut out = Vec::with_capacity(32);

        append_dns_name_to(&mut out, "api.example.com").unwrap();

        assert_eq!(
            out,
            vec![
                3, b'a', b'p', b'i', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0,
            ]
        );
    }

    #[test]
    fn parse_dns_name_parses_multi_label_name_and_advances_offset() {
        let payload = encode_dns_name("api.example.com").unwrap();
        let mut pos = 0usize;

        let parsed = parse_dns_name(&payload, &mut pos).unwrap();

        assert_eq!(parsed.as_str(), "api.example.com");
        assert_eq!(pos, payload.len());
    }

    #[test]
    fn parse_dns_name_rejects_root_name() {
        let payload = [0u8];
        let mut pos = 0usize;

        assert_eq!(
            parse_dns_name(&payload, &mut pos),
            Err(GuestPacketError::InvalidDnsQuery {
                reason: "root name is not supported",
            })
        );
    }

    #[test]
    fn build_ipv4_packet_seeds_capacity_from_total_length() {
        let payload = b"payload";
        let packet = build_ipv4_packet(
            DEFAULT_GUEST_ADDRESS,
            DEFAULT_HOST_GATEWAY,
            IPPROTO_UDP,
            payload,
        )
        .unwrap();

        assert!(packet.capacity() >= IPV4_MIN_HEADER_LEN + payload.len());
        assert_eq!(packet.len(), IPV4_MIN_HEADER_LEN + payload.len());
        assert_eq!(&packet[20..], payload);
    }

    #[test]
    fn build_tcp_packet_computes_checksum_without_pseudo_header_copy_semantics_change() {
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let packet = build_tcp_packet(TcpPacketBuild {
            src_ip: DEFAULT_HOST_GATEWAY,
            dst_ip: DEFAULT_GUEST_ADDRESS,
            src_port: 443,
            dst_port: 49152,
            sequence: 7,
            ack: 11,
            flags: PSH_ACK,
            payload,
        })
        .unwrap();

        assert!(packet.capacity() >= TCP_MIN_HEADER_LEN + payload.len());
        let tcp = parse_tcp(&packet).unwrap();
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 49152);
        assert_eq!(tcp.sequence, 7);
        assert_eq!(tcp.ack_number, 11);
        assert_eq!(tcp.flags, PSH_ACK);
        assert_eq!(tcp.payload, payload);

        let mut checksum_input = Vec::with_capacity(12 + packet.len());
        checksum_input.extend_from_slice(&DEFAULT_HOST_GATEWAY.octets());
        checksum_input.extend_from_slice(&DEFAULT_GUEST_ADDRESS.octets());
        checksum_input.push(0);
        checksum_input.push(IPPROTO_TCP);
        checksum_input.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        checksum_input.extend_from_slice(&packet);
        assert_eq!(internet_checksum(&checksum_input), 0);
    }

    #[test]
    fn default_tls_transform_chain_seeds_fixed_builtin_capacity() {
        let chain = default_tls_transform_chain().unwrap();

        assert_eq!(
            chain
                .iter()
                .map(|plugin| plugin.as_str())
                .collect::<Vec<_>>(),
            vec![AUDIT_PLUGIN_ID, METADATA_ENDPOINT_DENY_PLUGIN_ID]
        );
        assert!(chain.capacity() >= 2);
    }

    #[test]
    fn target_for_ip_preserves_synthetic_and_literal_host_semantics_without_host_wrapper() {
        let mut translator = translator();
        let synthetic_ip = Ipv4Addr::new(198, 19, 0, 20);
        translator.remember_synthetic_host(synthetic_ip, DnsName::new("api.example.com").unwrap());

        let synthetic = translator.target_for_ip(synthetic_ip, 443).unwrap();
        let literal = translator
            .target_for_ip(Ipv4Addr::new(198, 19, 0, 21), 8080)
            .unwrap();

        assert_eq!(synthetic.host(), "api.example.com");
        assert_eq!(synthetic.port(), 443);
        assert_eq!(literal.host(), "198.19.0.21");
        assert_eq!(literal.port(), 8080);
    }

    #[test]
    fn host_for_ip_reuses_cached_synthetic_host_name_and_preserves_literal_fallback() {
        let mut translator = translator();
        let synthetic_ip = Ipv4Addr::new(198, 19, 0, 22);
        translator.remember_synthetic_host(synthetic_ip, DnsName::new("ping.example.com").unwrap());

        let synthetic = translator.host_for_ip(synthetic_ip).unwrap();
        let literal = translator
            .host_for_ip(Ipv4Addr::new(198, 19, 0, 23))
            .unwrap();

        assert_eq!(synthetic.as_str(), "ping.example.com");
        assert_eq!(literal.as_str(), "198.19.0.23");
    }

    #[test]
    fn build_dns_response_payload_seeds_capacity_from_question_and_answers() {
        let context = DnsQueryContext {
            created_at: Instant::now(),
            tx_id: 0x1234,
            src_ip: DEFAULT_GUEST_ADDRESS,
            dst_ip: DEFAULT_HOST_GATEWAY,
            src_port: 40000,
            dst_port: DNS_PORT,
            name: DnsName::new("google.com").unwrap(),
            record_type: DnsRecordType::A,
        };
        let response = DnsResponse {
            query_id: QueryId::new(7).unwrap(),
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name: DnsName::new("google.com").unwrap(),
                record_type: DnsRecordType::A,
                data: DnsRecordData::Ip(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 10))),
                ttl_seconds: 30,
            }],
            denial: None,
        };

        let payload = build_dns_response_payload(&response, &context).unwrap();

        assert!(payload.capacity() >= estimated_dns_response_payload_capacity(&context, &response));
        assert_eq!(&payload[0..2], &0x1234u16.to_be_bytes());
    }

    #[test]
    fn append_dns_answer_appends_ipv4_rdata_without_temporary_vector_semantics_change() {
        let mut payload = Vec::new();
        let answer = DnsAnswer {
            name: DnsName::new("google.com").unwrap(),
            record_type: DnsRecordType::A,
            data: DnsRecordData::Ip(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 10))),
            ttl_seconds: 30,
        };

        append_dns_answer(&mut payload, &answer).unwrap();

        assert_eq!(
            &payload[payload.len() - 6..payload.len() - 4],
            &4u16.to_be_bytes()
        );
        assert_eq!(&payload[payload.len() - 4..], &[198, 19, 0, 10]);
    }

    #[test]
    fn append_dns_answer_appends_cname_rdata_without_temporary_vector_semantics_change() {
        let mut payload = Vec::new();
        let answer = DnsAnswer {
            name: DnsName::new("google.com").unwrap(),
            record_type: DnsRecordType::Cname,
            data: DnsRecordData::Cname(DnsName::new("alias.example.com").unwrap()),
            ttl_seconds: 30,
        };

        append_dns_answer(&mut payload, &answer).unwrap();

        let expected = encode_dns_name("alias.example.com").unwrap();
        let rdlen_offset = payload.len() - expected.len() - 2;
        assert_eq!(
            &payload[rdlen_offset..rdlen_offset + 2],
            &(expected.len() as u16).to_be_bytes()
        );
        assert_eq!(&payload[rdlen_offset + 2..], expected.as_slice());
    }

    #[test]
    fn append_dns_answer_appends_txt_rdata_without_temporary_vector_semantics_change() {
        let mut payload = Vec::new();
        let answer = DnsAnswer {
            name: DnsName::new("google.com").unwrap(),
            record_type: DnsRecordType::Txt,
            data: DnsRecordData::Txt("hello".to_string()),
            ttl_seconds: 30,
        };

        append_dns_answer(&mut payload, &answer).unwrap();

        let expected_rdlen = 6u16.to_be_bytes();
        assert_eq!(
            &payload[payload.len() - 8..payload.len() - 6],
            &expected_rdlen
        );
        assert_eq!(payload[payload.len() - 6], 5);
        assert_eq!(&payload[payload.len() - 5..], b"hello");
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
                assert_eq!(
                    open.tls_policy,
                    crate::proto::TlsPolicy::RequiredForTransform
                );
                assert_eq!(
                    open.tls_transform
                        .as_ref()
                        .map(|route| route.server_name.as_str()),
                    Some("api.example.com")
                );
                assert_eq!(
                    open.tls_transform.as_ref().map(|route| {
                        route
                            .transform_chain
                            .iter()
                            .map(|plugin| plugin.as_str())
                            .collect::<Vec<_>>()
                    }),
                    Some(vec![AUDIT_PLUGIN_ID, METADATA_ENDPOINT_DENY_PLUGIN_ID])
                );
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
            OutboundPacketEvent::TcpData(chunk)
                if chunk.flow_id == flow_id
                    && chunk.direction == FlowDirection::GuestToHost
                    && chunk.bytes.is_empty()
                    && chunk.end_stream
        ));
    }

    #[test]
    fn tcp_translate_seeds_bounded_event_vector_capacity() {
        let mut translator = translator();
        let target_ip = Ipv4Addr::new(198, 19, 0, 21);
        translator.remember_synthetic_host(target_ip, DnsName::new("api.example.com").unwrap());

        let syn_with_payload = tcp_ipv4_packet(target_ip, 443, SYN, b"hello");
        let events = translator
            .translate_outbound_ipv4(&syn_with_payload)
            .unwrap();

        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], OutboundPacketEvent::OpenTcp(_)));
        assert!(matches!(&events[1], OutboundPacketEvent::TcpData(_)));
        assert!(events.capacity() >= 3);
    }

    #[test]
    fn duplicate_tcp_syn_reuses_flow_without_emitting_second_open() {
        let mut translator = translator();
        let target_ip = Ipv4Addr::new(198, 19, 0, 25);
        translator.remember_synthetic_host(target_ip, DnsName::new("api.example.com").unwrap());

        let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
        let first_events = translator.translate_outbound_ipv4(&syn).unwrap();
        let flow_id = first_flow_id(&first_events);
        assert!(matches!(
            &first_events[0],
            OutboundPacketEvent::OpenTcp(open)
                if open.flow_id == flow_id && open.target.host() == "api.example.com"
        ));

        let retransmit_events = translator.translate_outbound_ipv4(&syn).unwrap();
        assert!(
            retransmit_events.is_empty(),
            "duplicate SYN should not emit a second OpenTcp event"
        );

        let data = tcp_ipv4_packet(target_ip, 443, PSH_ACK, b"hello");
        let data_events = translator.translate_outbound_ipv4(&data).unwrap();
        assert!(matches!(
            &data_events[0],
            OutboundPacketEvent::TcpData(chunk)
                if chunk.flow_id == flow_id
                    && chunk.direction == FlowDirection::GuestToHost
                    && chunk.bytes == b"hello"
        ));
    }

    #[test]
    fn tcp_fin_with_payload_marks_terminal_stream_chunk_without_dropping_flow() {
        let mut translator = translator();
        let target_ip = Ipv4Addr::new(198, 19, 0, 24);
        let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
        let flow_id = first_flow_id(&translator.translate_outbound_ipv4(&syn).unwrap());

        let fin_with_payload = tcp_ipv4_packet(target_ip, 443, PSH_ACK | FIN_ACK, b"done");
        let events = translator
            .translate_outbound_ipv4(&fin_with_payload)
            .unwrap();
        assert!(matches!(
            &events[0],
            OutboundPacketEvent::TcpData(chunk)
                if chunk.flow_id == flow_id
                    && chunk.direction == FlowDirection::GuestToHost
                    && chunk.bytes == b"done"
                    && chunk.end_stream
        ));

        assert!(matches!(
            translator.synthesize_tcp_data(&StreamChunk::new(
                flow_id,
                FlowDirection::HostToGuest,
                0,
                b"reply".to_vec(),
            )),
            Ok(Some(_))
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
    fn empty_host_chunk_synthesizes_pure_tcp_ack() {
        let target_ip = Ipv4Addr::new(198, 19, 0, 30);
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
                Vec::new(),
            ))
            .unwrap()
            .expect("empty host chunk should synthesize a TCP ACK");
        let (_, tcp) = parse_tcp_response(&packet);
        assert_eq!(tcp.flags, TCP_FLAG_ACK);
        assert_eq!(tcp.sequence, host_initial_sequence(flow_id).wrapping_add(1));
        assert_eq!(tcp.ack_number, 8);
        assert!(tcp.payload.is_empty());
    }

    #[test]
    fn late_guest_retransmit_after_host_close_is_dropped() {
        let target_ip = Ipv4Addr::new(198, 19, 0, 29);
        let mut translator = translator();
        let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
        let flow_id = first_flow_id(&translator.translate_outbound_ipv4(&syn).unwrap());
        translator
            .synthesize_tcp_open_result(&TcpOpenResult::opened(flow_id))
            .unwrap();

        let payload = b"done";
        let fin_with_payload = tcp_ipv4_packet(target_ip, 443, PSH_ACK | FIN_ACK, payload);
        let events = translator
            .translate_outbound_ipv4(&fin_with_payload)
            .unwrap();
        assert!(matches!(
            &events[0],
            OutboundPacketEvent::TcpData(chunk)
                if chunk.flow_id == flow_id
                    && chunk.bytes == payload
                    && chunk.end_stream
        ));

        translator
            .synthesize_tcp_close(&CloseFlow {
                flow_id,
                reason: CloseReason::HostClosed,
            })
            .unwrap();

        let retransmit = translator
            .translate_outbound_ipv4(&fin_with_payload)
            .unwrap();
        assert!(retransmit.is_empty(), "late retransmit should be ignored");

        let partial_retransmit = tcp_ipv4_packet_with_sequence(target_ip, 443, 9, PSH_ACK, b"ne");
        let partial = translator
            .translate_outbound_ipv4(&partial_retransmit)
            .unwrap();
        assert!(
            partial.is_empty(),
            "fully covered partial retransmit should be ignored"
        );

        let post_close_data = tcp_ipv4_packet_with_sequence(target_ip, 443, 12, PSH_ACK, b"later");
        let post_close = translator
            .translate_outbound_ipv4(&post_close_data)
            .unwrap();
        assert!(
            post_close.is_empty(),
            "guest data queued after close should be ignored for recently closed flows"
        );
    }

    #[test]
    fn closed_tcp_flow_budget_evicts_oldest_tombstone_first() {
        let mut translator = GuestPacketTranslator::new(
            GuestPacketTranslatorConfig::builder()
                .max_flows(2)
                .build()
                .unwrap(),
        );

        let first_ip = Ipv4Addr::new(198, 19, 0, 41);
        let second_ip = Ipv4Addr::new(198, 19, 0, 42);
        let third_ip = Ipv4Addr::new(198, 19, 0, 43);

        let first_flow = first_flow_id(
            &translator
                .translate_outbound_ipv4(&tcp_ipv4_packet(first_ip, 443, SYN, &[]))
                .unwrap(),
        );
        translator
            .synthesize_tcp_open_result(&TcpOpenResult::opened(first_flow))
            .unwrap();
        let first_fin = tcp_ipv4_packet(first_ip, 443, PSH_ACK | FIN_ACK, b"one");
        translator.translate_outbound_ipv4(&first_fin).unwrap();
        translator
            .synthesize_tcp_close(&CloseFlow {
                flow_id: first_flow,
                reason: CloseReason::HostClosed,
            })
            .unwrap();

        let second_flow = first_flow_id(
            &translator
                .translate_outbound_ipv4(&tcp_ipv4_packet(second_ip, 443, SYN, &[]))
                .unwrap(),
        );
        translator
            .synthesize_tcp_open_result(&TcpOpenResult::opened(second_flow))
            .unwrap();
        let second_fin = tcp_ipv4_packet(second_ip, 443, PSH_ACK | FIN_ACK, b"two");
        translator.translate_outbound_ipv4(&second_fin).unwrap();
        translator
            .synthesize_tcp_close(&CloseFlow {
                flow_id: second_flow,
                reason: CloseReason::HostClosed,
            })
            .unwrap();

        let third_flow = first_flow_id(
            &translator
                .translate_outbound_ipv4(&tcp_ipv4_packet(third_ip, 443, SYN, &[]))
                .unwrap(),
        );
        translator
            .synthesize_tcp_open_result(&TcpOpenResult::opened(third_flow))
            .unwrap();
        let third_fin = tcp_ipv4_packet(third_ip, 443, PSH_ACK | FIN_ACK, b"tre");
        translator.translate_outbound_ipv4(&third_fin).unwrap();
        translator
            .synthesize_tcp_close(&CloseFlow {
                flow_id: third_flow,
                reason: CloseReason::HostClosed,
            })
            .unwrap();

        assert_eq!(translator.closed_tcp_flows.len(), 2);
        assert_eq!(translator.closed_tcp_flow_order.len(), 2);

        let evicted = translator.translate_outbound_ipv4(&first_fin);
        assert!(
            matches!(
                evicted,
                Err(GuestPacketError::UnknownOutboundTcpFlow { .. })
            ),
            "oldest closed TCP tombstone should be evicted first once the budget is exceeded"
        );
        assert!(
            translator
                .translate_outbound_ipv4(&second_fin)
                .unwrap()
                .is_empty(),
            "newer closed TCP tombstone should still suppress retransmits"
        );
        assert!(
            translator
                .translate_outbound_ipv4(&third_fin)
                .unwrap()
                .is_empty(),
            "most recent closed TCP tombstone should still suppress retransmits"
        );
    }

    #[test]
    fn closed_tcp_flow_reopen_does_not_leave_stale_queue_entries() {
        let target_ip = Ipv4Addr::new(198, 19, 0, 44);
        let mut translator = translator();

        for suffix in 0..16u8 {
            let syn = tcp_ipv4_packet(target_ip, 443, SYN, &[]);
            let flow_id = first_flow_id(&translator.translate_outbound_ipv4(&syn).unwrap());
            translator
                .synthesize_tcp_open_result(&TcpOpenResult::opened(flow_id))
                .unwrap();

            let payload = [suffix];
            let fin = tcp_ipv4_packet(target_ip, 443, PSH_ACK | FIN_ACK, &payload);
            translator.translate_outbound_ipv4(&fin).unwrap();
            translator
                .synthesize_tcp_close(&CloseFlow {
                    flow_id,
                    reason: CloseReason::HostClosed,
                })
                .unwrap();
        }

        assert_eq!(translator.closed_tcp_flows.len(), 1);
        assert_eq!(translator.closed_tcp_flow_order.len(), 1);

        let retransmit = tcp_ipv4_packet(target_ip, 443, PSH_ACK | FIN_ACK, &[15]);
        assert!(
            translator
                .translate_outbound_ipv4(&retransmit)
                .unwrap()
                .is_empty(),
            "the newest tombstone should remain live after repeated reopen/close cycles"
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
    fn udp_datagram_roundtrip_synthesizes_guest_packet() {
        let mut translator = translator();
        let dst_ip = Ipv4Addr::new(198, 19, 0, 44);
        let packet = udp_ipv4_packet(50000, dst_ip, 1234, b"time?");
        let events = translator.translate_outbound_ipv4(&packet).unwrap();
        let flow_id = match &events[0] {
            OutboundPacketEvent::UdpDatagram(datagram) => datagram.flow_id,
            other => panic!("unexpected outbound event: {other:?}"),
        };

        let response = translator
            .synthesize_udp_datagram(&UdpDatagram {
                flow_id,
                target: Target::new("ignored.example", 1234).unwrap(),
                direction: FlowDirection::HostToGuest,
                bytes: b"reply".to_vec(),
            })
            .unwrap();
        let response = response.expect("known UDP flow should synthesize a packet");
        let ipv4 = parse_ipv4(&response).unwrap();
        let udp = parse_udp(ipv4.body).unwrap();
        assert_eq!(ipv4.src, dst_ip);
        assert_eq!(ipv4.dst, DEFAULT_GUEST_ADDRESS);
        assert_eq!(udp.src_port, 1234);
        assert_eq!(udp.dst_port, 50000);
        assert_eq!(udp.payload, b"reply");
    }

    #[test]
    fn udp_flow_budget_evicts_oldest_mapping_and_drops_late_reply() {
        let mut translator = GuestPacketTranslator::new(
            GuestPacketTranslatorConfig::builder()
                .max_flows(1)
                .build()
                .unwrap(),
        );
        let first_ip = Ipv4Addr::new(203, 0, 113, 10);
        let second_ip = Ipv4Addr::new(203, 0, 113, 11);

        let first_packet = udp_ipv4_packet(50000, first_ip, 1234, b"first");
        let first_flow_id = match &translator.translate_outbound_ipv4(&first_packet).unwrap()[0] {
            OutboundPacketEvent::UdpDatagram(datagram) => datagram.flow_id,
            other => panic!("unexpected outbound event: {other:?}"),
        };

        let second_packet = udp_ipv4_packet(50001, second_ip, 1235, b"second");
        let second_flow_id = match &translator.translate_outbound_ipv4(&second_packet).unwrap()[0] {
            OutboundPacketEvent::UdpDatagram(datagram) => datagram.flow_id,
            other => panic!("unexpected outbound event: {other:?}"),
        };
        assert_ne!(first_flow_id, second_flow_id);

        let late_reply = translator
            .synthesize_udp_datagram(&UdpDatagram {
                flow_id: first_flow_id,
                target: Target::new("ignored.example", 1234).unwrap(),
                direction: FlowDirection::HostToGuest,
                bytes: b"late".to_vec(),
            })
            .unwrap();
        assert!(
            late_reply.is_none(),
            "late reply for an evicted UDP flow should be dropped"
        );

        let second_reply = translator
            .synthesize_udp_datagram(&UdpDatagram {
                flow_id: second_flow_id,
                target: Target::new("ignored.example", 1235).unwrap(),
                direction: FlowDirection::HostToGuest,
                bytes: b"reply".to_vec(),
            })
            .unwrap();
        assert!(
            second_reply.is_some(),
            "current UDP flow must still synthesize its reply"
        );
    }

    #[test]
    fn terminal_udp_delivery_removes_mapping_and_allows_new_flow_id() {
        let mut translator = translator();
        let dst_ip = Ipv4Addr::new(203, 0, 113, 12);
        let packet = udp_ipv4_packet(50000, dst_ip, 1234, b"time?");
        let first_flow_id = match &translator.translate_outbound_ipv4(&packet).unwrap()[0] {
            OutboundPacketEvent::UdpDatagram(datagram) => datagram.flow_id,
            other => panic!("unexpected outbound event: {other:?}"),
        };

        translator.apply_udp_delivery(&crate::proto::UdpDelivery {
            flow_id: first_flow_id,
            status: crate::proto::DatagramStatus::Failed(crate::proto::TransportError::TimedOut),
        });

        let next_flow_id = match &translator.translate_outbound_ipv4(&packet).unwrap()[0] {
            OutboundPacketEvent::UdpDatagram(datagram) => datagram.flow_id,
            other => panic!("unexpected outbound event: {other:?}"),
        };
        assert_ne!(
            first_flow_id, next_flow_id,
            "terminal UDP delivery should free the tuple mapping"
        );
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
    fn expired_pending_dns_query_is_pruned_before_capacity_check_and_response() {
        let timeout = Duration::from_secs(1);
        let mut translator = GuestPacketTranslator::new(
            GuestPacketTranslatorConfig::builder()
                .max_pending_queries(1)
                .pending_query_timeout(timeout)
                .build()
                .unwrap(),
        );
        let first_packet = udp_ipv4_packet(
            40000,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(1, "one.example", 1),
        );
        let first_events = translator.translate_outbound_ipv4(&first_packet).unwrap();
        let expired_query_id = first_query_id(&first_events);
        translator
            .pending_dns
            .get_mut(&expired_query_id)
            .expect("pending DNS query")
            .created_at = Instant::now() - timeout - Duration::from_secs(1);

        let second_packet = udp_ipv4_packet(
            40001,
            DEFAULT_HOST_GATEWAY,
            DNS_PORT,
            &dns_query_payload(2, "two.example", 1),
        );
        let second_events = translator.translate_outbound_ipv4(&second_packet).unwrap();
        let second_query_id = first_query_id(&second_events);
        assert_ne!(expired_query_id, second_query_id);
        assert_eq!(translator.pending_dns.len(), 1);
        assert!(!translator.pending_dns.contains_key(&expired_query_id));

        assert!(matches!(
            translator.synthesize_dns_response(&DnsResponse {
                query_id: expired_query_id,
                code: DnsResponseCode::Ok,
                answers: Vec::new(),
                denial: None,
            }),
            Err(GuestPacketError::UnknownDnsQuery { .. })
        ));
    }

    #[test]
    fn expired_pending_icmp_query_is_pruned_before_capacity_check_and_response() {
        let timeout = Duration::from_secs(1);
        let mut translator = GuestPacketTranslator::new(
            GuestPacketTranslatorConfig::builder()
                .max_pending_queries(1)
                .pending_query_timeout(timeout)
                .build()
                .unwrap(),
        );
        let first_events = translator
            .translate_outbound_ipv4(&icmp_echo_ipv4_packet(
                Ipv4Addr::new(198, 19, 0, 81),
                b"one",
            ))
            .unwrap();
        let expired_query_id = first_query_id(&first_events);
        translator
            .pending_icmp
            .get_mut(&expired_query_id)
            .expect("pending ICMP query")
            .created_at = Instant::now() - timeout - Duration::from_secs(1);

        let second_events = translator
            .translate_outbound_ipv4(&icmp_echo_ipv4_packet(
                Ipv4Addr::new(198, 19, 0, 82),
                b"two",
            ))
            .unwrap();
        let second_query_id = first_query_id(&second_events);
        assert_ne!(expired_query_id, second_query_id);
        assert_eq!(translator.pending_icmp.len(), 1);
        assert!(!translator.pending_icmp.contains_key(&expired_query_id));

        assert!(matches!(
            translator.synthesize_icmp_echo_response(&IcmpEchoResponse {
                query_id: expired_query_id,
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
    fn unsupported_ip_version_is_rejected() {
        let payload = dns_query_payload(1, "example.com", 1);
        let mut packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &payload);
        packet[0] = (6 << 4) | 5;

        assert_eq!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::UnsupportedIpVersion { version: 6 })
        );
    }

    #[test]
    fn invalid_ipv4_header_length_is_rejected() {
        let payload = dns_query_payload(1, "example.com", 1);
        let mut packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &payload);
        packet[0] = (4 << 4) | 4;

        assert_eq!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::InvalidIpv4HeaderLen { header_len: 16 })
        );
    }

    #[test]
    fn invalid_ipv4_total_length_is_rejected() {
        let payload = dns_query_payload(1, "example.com", 1);
        let mut packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &payload);
        packet[2..4].copy_from_slice(&(IPV4_MIN_HEADER_LEN as u16 - 1).to_be_bytes());

        assert!(matches!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::InvalidIpv4TotalLen { .. })
        ));
    }

    #[test]
    fn invalid_udp_length_is_rejected() {
        let payload = dns_query_payload(1, "example.com", 1);
        let mut packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &payload);
        let declared_len = u16::from_be_bytes([packet[24], packet[25]]);
        packet[24..26].copy_from_slice(&(declared_len + 32).to_be_bytes());

        assert!(matches!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::InvalidUdpLength { .. })
        ));
    }

    #[test]
    fn invalid_tcp_header_length_is_rejected() {
        let mut packet = tcp_ipv4_packet(Ipv4Addr::new(198, 19, 0, 2), 443, SYN, &[]);
        packet[32] = 4 << 4;

        assert!(matches!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::InvalidTcpHeaderLen { .. })
        ));
    }

    #[test]
    fn compressed_dns_name_is_rejected() {
        let payload = dns_query_payload(1, "example.com", 1);
        let mut packet = udp_ipv4_packet(40000, DEFAULT_HOST_GATEWAY, DNS_PORT, &payload);
        packet[IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + DNS_HEADER_LEN] = 0xc0;

        assert_eq!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::UnsupportedDnsCompression)
        );
    }

    #[test]
    fn invalid_icmp_echo_request_is_rejected() {
        let mut packet = icmp_echo_ipv4_packet(Ipv4Addr::new(203, 0, 113, 8), b"hello");
        packet[20] = 3;

        assert_eq!(
            translator().translate_outbound_ipv4(&packet),
            Err(GuestPacketError::InvalidIcmpEcho {
                reason: "not an ICMP echo request",
            })
        );
    }

    #[test]
    fn dns_query_to_loopback_stub_resolver_still_routes_to_authority() {
        let payload = dns_query_payload(0x2345, "example.com", 1);
        let packet = udp_ipv4_packet(40000, Ipv4Addr::new(127, 0, 0, 1), DNS_PORT, &payload);

        assert!(matches!(
            translator().translate_outbound_ipv4(&packet),
            Ok(events)
                if matches!(
                    events.as_slice(),
                    [OutboundPacketEvent::DnsQuery(query)]
                        if query.name.as_str() == "example.com"
                            && query.record_type == DnsRecordType::A
                )
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
            GuestPacketTranslatorConfig::builder()
                .pending_query_timeout(Duration::ZERO)
                .build(),
            Err(GuestPacketError::InvalidPendingQueryTimeout)
        ));
        assert!(matches!(
            GuestPacketTranslatorConfig::builder()
                .pending_query_timeout(MAX_PENDING_QUERY_TIMEOUT + Duration::from_secs(1))
                .build(),
            Err(GuestPacketError::PendingQueryTimeoutTooLarge {
                actual: _,
                max: MAX_PENDING_QUERY_TIMEOUT
            })
        ));
        assert!(matches!(
            GuestPacketTranslatorConfig::builder().max_flows(0).build(),
            Err(GuestPacketError::FlowLimit)
        ));
        assert!(matches!(
            GuestPacketTranslatorConfig::builder()
                .max_synthetic_hosts(0)
                .build(),
            Err(GuestPacketError::InvalidSyntheticHostLimit)
        ));
        assert!(matches!(
            GuestPacketTranslatorConfig::builder()
                .max_pending_queries(DEFAULT_MAX_PENDING_QUERIES + 1)
                .build(),
            Err(GuestPacketError::PendingQueryLimitTooLarge {
                actual: _,
                max: DEFAULT_MAX_PENDING_QUERIES
            })
        ));
        assert!(matches!(
            GuestPacketTranslatorConfig::builder()
                .max_flows(DEFAULT_MAX_FLOWS + 1)
                .build(),
            Err(GuestPacketError::FlowLimitTooLarge {
                actual: _,
                max: DEFAULT_MAX_FLOWS
            })
        ));
        assert!(matches!(
            GuestPacketTranslatorConfig::builder()
                .max_synthetic_hosts(DEFAULT_MAX_SYNTHETIC_HOSTS + 1)
                .build(),
            Err(GuestPacketError::SyntheticHostLimitTooLarge {
                actual: _,
                max: DEFAULT_MAX_SYNTHETIC_HOSTS
            })
        ));
    }

    #[test]
    fn synthetic_host_replacement_does_not_leave_stale_queue_entries() {
        let mut translator = translator();
        let address = Ipv4Addr::new(198, 19, 0, 10);

        for index in 0..32 {
            translator.remember_synthetic_host(
                address,
                DnsName::new(format!("host-{index}.example.com")).unwrap(),
            );
        }

        assert_eq!(translator.synthetic_hosts.len(), 1);
        assert_eq!(translator.synthetic_host_order.len(), 1);
        assert_eq!(
            translator
                .synthetic_hosts
                .get(&address)
                .map(|entry| entry.host.as_str()),
            Some("host-31.example.com")
        );
    }

    #[test]
    fn udp_flow_removal_does_not_leave_stale_queue_entries() {
        let mut translator = translator();
        let dst_ip = Ipv4Addr::new(203, 0, 113, 12);

        for port in 0..32u16 {
            let packet = udp_ipv4_packet(50000 + port, dst_ip, 1234, b"time?");
            let flow_id = match &translator.translate_outbound_ipv4(&packet).unwrap()[0] {
                OutboundPacketEvent::UdpDatagram(datagram) => datagram.flow_id,
                other => panic!("unexpected outbound event: {other:?}"),
            };
            translator.apply_udp_delivery(&crate::proto::UdpDelivery {
                flow_id,
                status: crate::proto::DatagramStatus::Failed(
                    crate::proto::TransportError::TimedOut,
                ),
            });
        }

        assert!(translator.udp_flows.is_empty());
        assert!(translator.udp_flow_keys.is_empty());
        assert!(translator.udp_flow_order.is_empty());
    }

    #[test]
    fn synthetic_host_map_evicts_oldest_entry_once_budget_is_exceeded() {
        let mut translator = GuestPacketTranslator::new(
            GuestPacketTranslatorConfig::builder()
                .max_synthetic_hosts(2)
                .build()
                .unwrap(),
        );
        let first_ip = Ipv4Addr::new(198, 19, 0, 10);
        let second_ip = Ipv4Addr::new(198, 19, 0, 11);
        let third_ip = Ipv4Addr::new(198, 19, 0, 12);
        translator.remember_synthetic_host(first_ip, DnsName::new("first.example.com").unwrap());
        translator.remember_synthetic_host(second_ip, DnsName::new("second.example.com").unwrap());
        translator.remember_synthetic_host(third_ip, DnsName::new("third.example.com").unwrap());

        let first_syn = tcp_ipv4_packet(first_ip, 443, SYN, &[]);
        let first_events = translator.translate_outbound_ipv4(&first_syn).unwrap();
        assert!(matches!(
            &first_events[0],
            OutboundPacketEvent::OpenTcp(open)
                if open.target.host() == "198.19.0.10"
                    && open.tls_transform.is_none()
        ));

        let second_syn = tcp_ipv4_packet(second_ip, 443, SYN, &[]);
        let second_events = translator.translate_outbound_ipv4(&second_syn).unwrap();
        assert!(matches!(
            &second_events[0],
            OutboundPacketEvent::OpenTcp(open)
                if open.target.host() == "second.example.com"
                    && open
                        .tls_transform
                        .as_ref()
                        .is_some_and(|route| route.server_name.as_str() == "second.example.com")
        ));

        let third_syn = tcp_ipv4_packet(third_ip, 443, SYN, &[]);
        let third_events = translator.translate_outbound_ipv4(&third_syn).unwrap();
        assert!(matches!(
            &third_events[0],
            OutboundPacketEvent::OpenTcp(open)
                if open.target.host() == "third.example.com"
                    && open
                        .tls_transform
                        .as_ref()
                        .is_some_and(|route| route.server_name.as_str() == "third.example.com")
        ));
    }

    #[test]
    fn synthetic_host_refresh_skips_stale_eviction_entries() {
        let mut translator = GuestPacketTranslator::new(
            GuestPacketTranslatorConfig::builder()
                .max_synthetic_hosts(1)
                .build()
                .unwrap(),
        );
        let refreshed_ip = Ipv4Addr::new(198, 19, 0, 20);
        let newest_ip = Ipv4Addr::new(198, 19, 0, 21);
        translator.remember_synthetic_host(refreshed_ip, DnsName::new("old.example.com").unwrap());
        translator
            .remember_synthetic_host(refreshed_ip, DnsName::new("refreshed.example.com").unwrap());
        translator.remember_synthetic_host(newest_ip, DnsName::new("newest.example.com").unwrap());

        let refreshed_syn = tcp_ipv4_packet(refreshed_ip, 443, SYN, &[]);
        let refreshed_events = translator.translate_outbound_ipv4(&refreshed_syn).unwrap();
        assert!(matches!(
            &refreshed_events[0],
            OutboundPacketEvent::OpenTcp(open)
                if open.target.host() == "198.19.0.20"
                    && open.tls_transform.is_none()
        ));

        let newest_syn = tcp_ipv4_packet(newest_ip, 443, SYN, &[]);
        let newest_events = translator.translate_outbound_ipv4(&newest_syn).unwrap();
        assert!(matches!(
            &newest_events[0],
            OutboundPacketEvent::OpenTcp(open)
                if open.target.host() == "newest.example.com"
                    && open
                        .tls_transform
                        .as_ref()
                        .is_some_and(|route| route.server_name.as_str() == "newest.example.com")
        ));
    }
}
