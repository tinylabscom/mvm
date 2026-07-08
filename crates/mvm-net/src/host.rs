//! Host-side transparent networking authority core.
//!
//! This module is a dependency-light admission and state machine. It owns the
//! synthetic DNS map, consults a policy trait before any connector is invoked,
//! and emits audit events for DNS and flow lifecycle decisions. Concrete vsock
//! listeners, host sockets, async runtimes, TLS transforms, and plugin runners
//! plug into these traits from opt-in layers.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(feature = "host-std")]
use std::{
    io::{self, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use crate::proto::{
    Capability, CloseFlow, CloseReason, DatagramStatus, Denial, DenialReason, DnsAnswer, DnsName,
    DnsQuery, DnsRecordData, DnsRecordType, DnsResponse, DnsResponseCode, EndpointRole,
    FlowDirection, FlowId, Hello, HelloAck, IcmpEchoRequest, IcmpEchoResponse, IcmpEchoStatus,
    NetMessage, OpenTcp, ProtocolError, StreamChunk, Target, TcpOpenResult, TransportError,
    UdpDatagram, UdpDelivery,
};

pub const DEFAULT_SYNTHETIC_DNS_BASE: Ipv4Addr = Ipv4Addr::new(198, 19, 0, 1);
pub const DEFAULT_MAX_SYNTHETIC_DNS_ENTRIES: usize = 65_534;
pub const DEFAULT_DNS_TTL_SECONDS: u32 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAuthorityError {
    InvalidConfig(&'static str),
    Protocol(ProtocolError),
    Audit(String),
    SyntheticDnsPoolExhausted { max_entries: usize },
    UnsupportedGuestMessage(&'static str),
}

impl fmt::Display for HostAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid host authority config: {reason}"),
            Self::Protocol(err) => write!(f, "{err}"),
            Self::Audit(err) => write!(f, "host authority audit sink failed: {err}"),
            Self::SyntheticDnsPoolExhausted { max_entries } => write!(
                f,
                "synthetic DNS pool exhausted after {max_entries} admitted entries"
            ),
            Self::UnsupportedGuestMessage(message) => {
                write!(
                    f,
                    "guest message {message} is not supported by the host authority"
                )
            }
        }
    }
}

impl std::error::Error for HostAuthorityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(err) => Some(err),
            Self::InvalidConfig(_)
            | Self::Audit(_)
            | Self::SyntheticDnsPoolExhausted { .. }
            | Self::UnsupportedGuestMessage(_) => None,
        }
    }
}

impl From<ProtocolError> for HostAuthorityError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAuthorityConfig {
    synthetic_dns_base: Ipv4Addr,
    max_synthetic_dns_entries: usize,
    dns_ttl_seconds: u32,
    capabilities: Vec<Capability>,
}

impl HostAuthorityConfig {
    pub fn builder() -> HostAuthorityConfigBuilder {
        HostAuthorityConfigBuilder::default()
    }

    pub const fn synthetic_dns_base(&self) -> Ipv4Addr {
        self.synthetic_dns_base
    }

    pub const fn max_synthetic_dns_entries(&self) -> usize {
        self.max_synthetic_dns_entries
    }

    pub const fn dns_ttl_seconds(&self) -> u32 {
        self.dns_ttl_seconds
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
}

impl Default for HostAuthorityConfig {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("default host authority config is valid")
    }
}

#[derive(Debug, Clone)]
pub struct HostAuthorityConfigBuilder {
    synthetic_dns_base: Ipv4Addr,
    max_synthetic_dns_entries: usize,
    dns_ttl_seconds: u32,
    capabilities: Vec<Capability>,
}

impl Default for HostAuthorityConfigBuilder {
    fn default() -> Self {
        Self {
            synthetic_dns_base: DEFAULT_SYNTHETIC_DNS_BASE,
            max_synthetic_dns_entries: DEFAULT_MAX_SYNTHETIC_DNS_ENTRIES,
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            capabilities: vec![
                Capability::Dns,
                Capability::Tcp,
                Capability::AuditCorrelation,
                Capability::PolicyDigest,
            ],
        }
    }
}

impl HostAuthorityConfigBuilder {
    pub fn synthetic_dns_base(mut self, synthetic_dns_base: Ipv4Addr) -> Self {
        self.synthetic_dns_base = synthetic_dns_base;
        self
    }

    pub fn max_synthetic_dns_entries(mut self, max_synthetic_dns_entries: usize) -> Self {
        self.max_synthetic_dns_entries = max_synthetic_dns_entries;
        self
    }

    pub fn dns_ttl_seconds(mut self, dns_ttl_seconds: u32) -> Self {
        self.dns_ttl_seconds = dns_ttl_seconds;
        self
    }

    pub fn capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn build(self) -> Result<HostAuthorityConfig, HostAuthorityError> {
        if self.max_synthetic_dns_entries == 0 {
            return Err(HostAuthorityError::InvalidConfig(
                "max_synthetic_dns_entries must be non-zero",
            ));
        }
        if self.dns_ttl_seconds == 0 {
            return Err(HostAuthorityError::InvalidConfig(
                "dns_ttl_seconds must be non-zero",
            ));
        }
        let max_offset: u32 = (self.max_synthetic_dns_entries - 1)
            .try_into()
            .map_err(|_| {
                HostAuthorityError::InvalidConfig(
                    "max_synthetic_dns_entries must fit in the IPv4 address space",
                )
            })?;
        if add_ipv4_offset(self.synthetic_dns_base, max_offset).is_none() {
            return Err(HostAuthorityError::InvalidConfig(
                "synthetic DNS range exceeds the IPv4 address space",
            ));
        }
        Ok(HostAuthorityConfig {
            synthetic_dns_base: self.synthetic_dns_base,
            max_synthetic_dns_entries: self.max_synthetic_dns_entries,
            dns_ttl_seconds: self.dns_ttl_seconds,
            capabilities: self.capabilities,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAdmission {
    Allowed(HostRoute),
    Denied(Denial),
}

impl HostAdmission {
    pub const fn allowed() -> Self {
        Self::Allowed(HostRoute::unresolved())
    }

    pub const fn allowed_with_route(route: HostRoute) -> Self {
        Self::Allowed(route)
    }

    pub fn denied(reason: DenialReason) -> Self {
        Self::Denied(Denial::new(reason))
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct HostRoute {
    upstream_ip: Option<IpAddr>,
}

impl HostRoute {
    pub const fn unresolved() -> Self {
        Self { upstream_ip: None }
    }

    pub const fn resolved_ip(upstream_ip: IpAddr) -> Self {
        Self {
            upstream_ip: Some(upstream_ip),
        }
    }

    pub const fn upstream_ip(self) -> Option<IpAddr> {
        self.upstream_ip
    }
}

pub trait HostNetworkPolicy {
    fn decide_dns(&mut self, query: &DnsQuery) -> HostAdmission;

    fn decide_tcp_open(&mut self, open: &OpenTcp) -> HostAdmission;

    fn decide_udp_datagram(&mut self, datagram: &UdpDatagram) -> HostAdmission;

    fn decide_icmp_echo(&mut self, request: &IcmpEchoRequest) -> HostAdmission;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllHostPolicy;

impl HostNetworkPolicy for DenyAllHostPolicy {
    fn decide_dns(&mut self, _query: &DnsQuery) -> HostAdmission {
        HostAdmission::denied(DenialReason::NetworkDisabled)
    }

    fn decide_tcp_open(&mut self, _open: &OpenTcp) -> HostAdmission {
        HostAdmission::denied(DenialReason::NetworkDisabled)
    }

    fn decide_udp_datagram(&mut self, _datagram: &UdpDatagram) -> HostAdmission {
        HostAdmission::denied(DenialReason::NetworkDisabled)
    }

    fn decide_icmp_echo(&mut self, _request: &IcmpEchoRequest) -> HostAdmission {
        HostAdmission::denied(DenialReason::NetworkDisabled)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllHostPolicy;

impl HostNetworkPolicy for AllowAllHostPolicy {
    fn decide_dns(&mut self, _query: &DnsQuery) -> HostAdmission {
        HostAdmission::allowed()
    }

    fn decide_tcp_open(&mut self, _open: &OpenTcp) -> HostAdmission {
        HostAdmission::allowed()
    }

    fn decide_udp_datagram(&mut self, _datagram: &UdpDatagram) -> HostAdmission {
        HostAdmission::allowed()
    }

    fn decide_icmp_echo(&mut self, _request: &IcmpEchoRequest) -> HostAdmission {
        HostAdmission::allowed()
    }
}

pub trait HostAuditSink {
    type Error: fmt::Display;

    fn record(&mut self, event: HostAuditEvent) -> Result<(), Self::Error>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopHostAuditSink;

impl HostAuditSink for NoopHostAuditSink {
    type Error = std::convert::Infallible;

    fn record(&mut self, _event: HostAuditEvent) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "event", rename_all = "snake_case"))]
pub enum HostAuditEvent {
    HandshakeAccepted {
        guest_capabilities: Vec<Capability>,
        accepted_capabilities: Vec<Capability>,
    },
    DnsAllowed {
        query_id: u64,
        name: String,
        record_type: DnsRecordType,
    },
    DnsDenied {
        query_id: u64,
        name: String,
        record_type: DnsRecordType,
        denial: Denial,
    },
    DnsAnswered {
        query_id: u64,
        name: String,
        address: Ipv4Addr,
        ttl_seconds: u32,
    },
    TcpOpenAllowed {
        flow_id: u64,
        host: String,
        port: u16,
        upstream_ip: Option<IpAddr>,
    },
    TcpOpenDenied {
        flow_id: u64,
        host: String,
        port: u16,
        denial: Denial,
    },
    TcpOpenFailed {
        flow_id: u64,
        host: String,
        port: u16,
        upstream_ip: Option<IpAddr>,
        error: TransportError,
    },
    TcpBytesForwarded {
        flow_id: u64,
        bytes: usize,
        end_stream: bool,
    },
    FlowClosed {
        flow_id: u64,
        reason: CloseReason,
    },
    UdpDenied {
        flow_id: u64,
        host: String,
        port: u16,
        denial: Denial,
    },
    UdpUnsupported {
        flow_id: u64,
        host: String,
        port: u16,
    },
    IcmpDenied {
        query_id: u64,
        host: String,
        denial: Denial,
    },
    IcmpUnsupported {
        query_id: u64,
        host: String,
    },
}

pub trait HostTcpConnector {
    fn open(
        &mut self,
        flow_id: FlowId,
        target: &Target,
        route: &HostRoute,
    ) -> Result<(), TransportError>;

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError>;

    fn close(&mut self, flow_id: FlowId, reason: CloseReason) -> Result<(), TransportError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingTcpConnector;

impl HostTcpConnector for RefusingTcpConnector {
    fn open(
        &mut self,
        _flow_id: FlowId,
        _target: &Target,
        _route: &HostRoute,
    ) -> Result<(), TransportError> {
        Err(TransportError::ProtocolError)
    }

    fn send(&mut self, _chunk: &StreamChunk) -> Result<(), TransportError> {
        Err(TransportError::ProtocolError)
    }

    fn close(&mut self, _flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        Ok(())
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StdTcpConnectorConfig {
    connect_timeout: Option<Duration>,
}

#[cfg(feature = "host-std")]
impl StdTcpConnectorConfig {
    pub fn builder() -> StdTcpConnectorConfigBuilder {
        StdTcpConnectorConfigBuilder::default()
    }

    pub const fn connect_timeout(&self) -> Option<Duration> {
        self.connect_timeout
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Clone, Default)]
pub struct StdTcpConnectorConfigBuilder {
    connect_timeout: Option<Duration>,
}

#[cfg(feature = "host-std")]
impl StdTcpConnectorConfigBuilder {
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = Some(connect_timeout);
        self
    }

    pub fn build(self) -> StdTcpConnectorConfig {
        StdTcpConnectorConfig {
            connect_timeout: self.connect_timeout,
        }
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Default)]
pub struct StdTcpConnector {
    config: StdTcpConnectorConfig,
    streams: HashMap<FlowId, TcpStream>,
}

#[cfg(feature = "host-std")]
impl StdTcpConnector {
    pub fn new() -> Self {
        Self::with_config(StdTcpConnectorConfig::default())
    }

    pub fn with_config(config: StdTcpConnectorConfig) -> Self {
        Self {
            config,
            streams: HashMap::new(),
        }
    }

    pub fn config(&self) -> &StdTcpConnectorConfig {
        &self.config
    }

    pub fn open_flow_count(&self) -> usize {
        self.streams.len()
    }

    fn connect_target(
        &self,
        target: &Target,
        route: &HostRoute,
    ) -> Result<TcpStream, TransportError> {
        if let Some(ip) = route.upstream_ip() {
            return self.connect_addr(SocketAddr::new(ip, target.port()));
        }
        let mut last_error = None;
        for addr in (target.host(), target.port())
            .to_socket_addrs()
            .map_err(map_tcp_io_error)?
        {
            match self.connect_addr(addr) {
                Ok(stream) => return Ok(stream),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.unwrap_or(TransportError::DnsFailed))
    }

    fn connect_addr(&self, addr: SocketAddr) -> Result<TcpStream, TransportError> {
        match self.config.connect_timeout() {
            Some(timeout) => TcpStream::connect_timeout(&addr, timeout),
            None => TcpStream::connect(addr),
        }
        .map_err(map_tcp_io_error)
    }
}

#[cfg(feature = "host-std")]
impl HostTcpConnector for StdTcpConnector {
    fn open(
        &mut self,
        flow_id: FlowId,
        target: &Target,
        route: &HostRoute,
    ) -> Result<(), TransportError> {
        if self.streams.contains_key(&flow_id) {
            return Err(TransportError::ProtocolError);
        }
        let stream = self.connect_target(target, route)?;
        stream.set_nodelay(true).map_err(map_tcp_io_error)?;
        self.streams.insert(flow_id, stream);
        Ok(())
    }

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
        let stream = self
            .streams
            .get_mut(&chunk.flow_id)
            .ok_or(TransportError::ProtocolError)?;
        stream.write_all(&chunk.bytes).map_err(map_tcp_io_error)?;
        if chunk.end_stream {
            stream.shutdown(Shutdown::Write).map_err(map_tcp_io_error)?;
        }
        Ok(())
    }

    fn close(&mut self, flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        if let Some(stream) = self.streams.remove(&flow_id) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        Ok(())
    }
}

#[cfg(feature = "host-std")]
fn map_tcp_io_error(err: io::Error) -> TransportError {
    match err.kind() {
        io::ErrorKind::ConnectionRefused => TransportError::Refused,
        io::ErrorKind::ConnectionReset => TransportError::Reset,
        io::ErrorKind::TimedOut => TransportError::TimedOut,
        io::ErrorKind::NotFound | io::ErrorKind::InvalidInput => TransportError::DnsFailed,
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof => TransportError::Reset,
        _ => TransportError::Unreachable,
    }
}

#[derive(Debug, Clone)]
pub struct SyntheticDnsMap {
    base: Ipv4Addr,
    max_entries: usize,
    by_name: HashMap<DnsName, Ipv4Addr>,
    by_address: HashMap<Ipv4Addr, DnsName>,
}

impl SyntheticDnsMap {
    pub fn new(base: Ipv4Addr, max_entries: usize) -> Result<Self, HostAuthorityError> {
        HostAuthorityConfig::builder()
            .synthetic_dns_base(base)
            .max_synthetic_dns_entries(max_entries)
            .build()?;
        Ok(Self {
            base,
            max_entries,
            by_name: HashMap::new(),
            by_address: HashMap::new(),
        })
    }

    pub fn address_for_name(&mut self, name: &DnsName) -> Result<Ipv4Addr, HostAuthorityError> {
        if let Some(address) = self.by_name.get(name) {
            return Ok(*address);
        }
        if self.by_name.len() >= self.max_entries {
            return Err(HostAuthorityError::SyntheticDnsPoolExhausted {
                max_entries: self.max_entries,
            });
        }
        let offset: u32 = self.by_name.len().try_into().map_err(|_| {
            HostAuthorityError::InvalidConfig(
                "synthetic DNS map length must fit in the IPv4 address space",
            )
        })?;
        let address = add_ipv4_offset(self.base, offset).ok_or({
            HostAuthorityError::SyntheticDnsPoolExhausted {
                max_entries: self.max_entries,
            }
        })?;
        self.by_name.insert(name.clone(), address);
        self.by_address.insert(address, name.clone());
        Ok(address)
    }

    pub fn name_for_address(&self, address: Ipv4Addr) -> Option<&DnsName> {
        self.by_address.get(&address)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[derive(Debug)]
pub struct HostAuthority<P, A, T> {
    config: HostAuthorityConfig,
    dns: SyntheticDnsMap,
    policy: P,
    audit: A,
    tcp: T,
    open_tcp_flows: HashMap<FlowId, Target>,
}

impl<P, A, T> HostAuthority<P, A, T>
where
    P: HostNetworkPolicy,
    A: HostAuditSink,
    T: HostTcpConnector,
{
    pub fn new(policy: P, audit: A, tcp: T) -> Self {
        Self::with_config(HostAuthorityConfig::default(), policy, audit, tcp)
            .expect("default host authority config is valid")
    }

    pub fn with_config(
        config: HostAuthorityConfig,
        policy: P,
        audit: A,
        tcp: T,
    ) -> Result<Self, HostAuthorityError> {
        let dns = SyntheticDnsMap::new(
            config.synthetic_dns_base(),
            config.max_synthetic_dns_entries(),
        )?;
        Ok(Self {
            config,
            dns,
            policy,
            audit,
            tcp,
            open_tcp_flows: HashMap::new(),
        })
    }

    pub fn config(&self) -> &HostAuthorityConfig {
        &self.config
    }

    pub fn dns_map(&self) -> &SyntheticDnsMap {
        &self.dns
    }

    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.policy
    }

    pub fn audit_mut(&mut self) -> &mut A {
        &mut self.audit
    }

    pub fn tcp_connector_mut(&mut self) -> &mut T {
        &mut self.tcp
    }

    pub fn handle_message(
        &mut self,
        message: NetMessage,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        match message {
            NetMessage::Hello(hello) => self.handle_hello(hello),
            NetMessage::OpenTcp(open) => self.handle_open_tcp(open),
            NetMessage::TcpData(chunk) => self.handle_tcp_data(chunk),
            NetMessage::CloseFlow(close) => self.handle_close_flow(close),
            NetMessage::DnsQuery(query) => self.handle_dns_query(query),
            NetMessage::UdpDatagram(datagram) => self.handle_udp_datagram(datagram),
            NetMessage::IcmpEchoRequest(request) => self.handle_icmp_echo(request),
            NetMessage::HelloAck(_) => Err(HostAuthorityError::UnsupportedGuestMessage("HelloAck")),
            NetMessage::TcpOpenResult(_) => {
                Err(HostAuthorityError::UnsupportedGuestMessage("TcpOpenResult"))
            }
            NetMessage::DnsResponse(_) => {
                Err(HostAuthorityError::UnsupportedGuestMessage("DnsResponse"))
            }
            NetMessage::UdpDelivery(_) => {
                Err(HostAuthorityError::UnsupportedGuestMessage("UdpDelivery"))
            }
            NetMessage::IcmpEchoResponse(_) => Err(HostAuthorityError::UnsupportedGuestMessage(
                "IcmpEchoResponse",
            )),
        }
    }

    fn handle_hello(&mut self, hello: Hello) -> Result<Vec<NetMessage>, HostAuthorityError> {
        hello.validate()?;
        if hello.role != EndpointRole::Guest {
            return Err(HostAuthorityError::UnsupportedGuestMessage(
                "Hello with non-guest role",
            ));
        }
        let accepted_capabilities = accepted_capabilities(&hello.capabilities, &self.config);
        self.record(HostAuditEvent::HandshakeAccepted {
            guest_capabilities: hello.capabilities,
            accepted_capabilities: accepted_capabilities.clone(),
        })?;
        Ok(vec![NetMessage::HelloAck(HelloAck::new(
            accepted_capabilities,
        ))])
    }

    fn handle_dns_query(&mut self, query: DnsQuery) -> Result<Vec<NetMessage>, HostAuthorityError> {
        match self.policy.decide_dns(&query) {
            HostAdmission::Denied(denial) => {
                self.record(HostAuditEvent::DnsDenied {
                    query_id: query.query_id.get(),
                    name: query.name.as_str().to_string(),
                    record_type: query.record_type,
                    denial: denial.clone(),
                })?;
                Ok(vec![NetMessage::DnsResponse(DnsResponse {
                    query_id: query.query_id,
                    code: DnsResponseCode::Refused,
                    answers: Vec::new(),
                    denial: Some(denial),
                })])
            }
            HostAdmission::Allowed(_) => {
                self.record(HostAuditEvent::DnsAllowed {
                    query_id: query.query_id.get(),
                    name: query.name.as_str().to_string(),
                    record_type: query.record_type,
                })?;
                let response = self.allowed_dns_response(query)?;
                Ok(vec![NetMessage::DnsResponse(response)])
            }
        }
    }

    fn allowed_dns_response(&mut self, query: DnsQuery) -> Result<DnsResponse, HostAuthorityError> {
        if query.record_type != DnsRecordType::A {
            return Ok(DnsResponse {
                query_id: query.query_id,
                code: DnsResponseCode::Ok,
                answers: Vec::new(),
                denial: None,
            });
        }
        let address = self.dns.address_for_name(&query.name)?;
        self.record(HostAuditEvent::DnsAnswered {
            query_id: query.query_id.get(),
            name: query.name.as_str().to_string(),
            address,
            ttl_seconds: self.config.dns_ttl_seconds(),
        })?;
        Ok(DnsResponse {
            query_id: query.query_id,
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name: query.name,
                record_type: DnsRecordType::A,
                data: DnsRecordData::Ip(IpAddr::V4(address)),
                ttl_seconds: self.config.dns_ttl_seconds(),
            }],
            denial: None,
        })
    }

    fn handle_open_tcp(&mut self, open: OpenTcp) -> Result<Vec<NetMessage>, HostAuthorityError> {
        let flow_id = open.flow_id;
        let target = open.target.clone();
        match self.policy.decide_tcp_open(&open) {
            HostAdmission::Denied(denial) => {
                self.record(HostAuditEvent::TcpOpenDenied {
                    flow_id: flow_id.get(),
                    host: target.host().to_string(),
                    port: target.port(),
                    denial: denial.clone(),
                })?;
                Ok(vec![NetMessage::TcpOpenResult(TcpOpenResult::denied(
                    flow_id, denial,
                ))])
            }
            HostAdmission::Allowed(route) => {
                self.record(HostAuditEvent::TcpOpenAllowed {
                    flow_id: flow_id.get(),
                    host: target.host().to_string(),
                    port: target.port(),
                    upstream_ip: route.upstream_ip(),
                })?;
                match self.tcp.open(flow_id, &target, &route) {
                    Ok(()) => {
                        self.open_tcp_flows.insert(flow_id, target.clone());
                        Ok(vec![NetMessage::TcpOpenResult(TcpOpenResult::opened(
                            flow_id,
                        ))])
                    }
                    Err(error) => {
                        self.record(HostAuditEvent::TcpOpenFailed {
                            flow_id: flow_id.get(),
                            host: target.host().to_string(),
                            port: target.port(),
                            upstream_ip: route.upstream_ip(),
                            error,
                        })?;
                        Ok(vec![NetMessage::TcpOpenResult(TcpOpenResult::failed(
                            flow_id, error,
                        ))])
                    }
                }
            }
        }
    }

    fn handle_tcp_data(
        &mut self,
        chunk: StreamChunk,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        if chunk.direction != FlowDirection::GuestToHost {
            return Ok(vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: chunk.flow_id,
                reason: CloseReason::ProtocolError,
            })]);
        }
        if !self.open_tcp_flows.contains_key(&chunk.flow_id) {
            return Ok(vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: chunk.flow_id,
                reason: CloseReason::ProtocolError,
            })]);
        }
        match self.tcp.send(&chunk) {
            Ok(()) => {
                self.record(HostAuditEvent::TcpBytesForwarded {
                    flow_id: chunk.flow_id.get(),
                    bytes: chunk.bytes.len(),
                    end_stream: chunk.end_stream,
                })?;
                if chunk.end_stream {
                    self.open_tcp_flows.remove(&chunk.flow_id);
                    self.record(HostAuditEvent::FlowClosed {
                        flow_id: chunk.flow_id.get(),
                        reason: CloseReason::GuestClosed,
                    })?;
                }
                Ok(Vec::new())
            }
            Err(_) => {
                self.open_tcp_flows.remove(&chunk.flow_id);
                Ok(vec![NetMessage::CloseFlow(CloseFlow {
                    flow_id: chunk.flow_id,
                    reason: CloseReason::HostClosed,
                })])
            }
        }
    }

    fn handle_close_flow(
        &mut self,
        close: CloseFlow,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        if self.open_tcp_flows.remove(&close.flow_id).is_some() {
            let _ = self.tcp.close(close.flow_id, close.reason);
            self.record(HostAuditEvent::FlowClosed {
                flow_id: close.flow_id.get(),
                reason: close.reason,
            })?;
        }
        Ok(Vec::new())
    }

    fn handle_udp_datagram(
        &mut self,
        datagram: UdpDatagram,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        match self.policy.decide_udp_datagram(&datagram) {
            HostAdmission::Denied(denial) => {
                self.record(HostAuditEvent::UdpDenied {
                    flow_id: datagram.flow_id.get(),
                    host: datagram.target.host().to_string(),
                    port: datagram.target.port(),
                    denial: denial.clone(),
                })?;
                Ok(vec![NetMessage::UdpDelivery(UdpDelivery {
                    flow_id: datagram.flow_id,
                    status: DatagramStatus::Denied(denial),
                })])
            }
            HostAdmission::Allowed(_) => {
                self.record(HostAuditEvent::UdpUnsupported {
                    flow_id: datagram.flow_id.get(),
                    host: datagram.target.host().to_string(),
                    port: datagram.target.port(),
                })?;
                Ok(vec![NetMessage::UdpDelivery(UdpDelivery {
                    flow_id: datagram.flow_id,
                    status: DatagramStatus::Failed(TransportError::ProtocolError),
                })])
            }
        }
    }

    fn handle_icmp_echo(
        &mut self,
        request: IcmpEchoRequest,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        match self.policy.decide_icmp_echo(&request) {
            HostAdmission::Denied(denial) => {
                self.record(HostAuditEvent::IcmpDenied {
                    query_id: request.query_id.get(),
                    host: request.host.as_str().to_string(),
                    denial: denial.clone(),
                })?;
                Ok(vec![NetMessage::IcmpEchoResponse(IcmpEchoResponse {
                    query_id: request.query_id,
                    status: IcmpEchoStatus::Denied,
                    round_trip_micros: None,
                    denial: Some(denial),
                })])
            }
            HostAdmission::Allowed(_) => {
                self.record(HostAuditEvent::IcmpUnsupported {
                    query_id: request.query_id.get(),
                    host: request.host.as_str().to_string(),
                })?;
                Ok(vec![NetMessage::IcmpEchoResponse(IcmpEchoResponse {
                    query_id: request.query_id,
                    status: IcmpEchoStatus::Unreachable,
                    round_trip_micros: None,
                    denial: None,
                })])
            }
        }
    }

    fn record(&mut self, event: HostAuditEvent) -> Result<(), HostAuthorityError> {
        self.audit
            .record(event)
            .map_err(|err| HostAuthorityError::Audit(err.to_string()))
    }
}

fn accepted_capabilities(guest: &[Capability], config: &HostAuthorityConfig) -> Vec<Capability> {
    config
        .capabilities()
        .iter()
        .copied()
        .filter(|capability| guest.contains(capability))
        .collect()
}

fn add_ipv4_offset(base: Ipv4Addr, offset: u32) -> Option<Ipv4Addr> {
    u32::from(base).checked_add(offset).map(Ipv4Addr::from)
}

#[cfg(feature = "host-mvm-core")]
#[derive(Debug, Clone)]
pub struct MvmCoreNetworkPolicy {
    egress: mvm_core::policy::projection::CanonicalEgress,
    pins: mvm_core::policy::dns_pin::DnsPinRegistry,
}

#[cfg(feature = "host-mvm-core")]
impl MvmCoreNetworkPolicy {
    pub fn from_network_policy(
        policy: &mvm_core::policy::network_policy::NetworkPolicy,
        pins: mvm_core::policy::dns_pin::DnsPinRegistry,
        now: &str,
    ) -> Result<Self, mvm_core::policy::projection::ProjectionError> {
        let egress = mvm_core::policy::projection::canonicalize_network_policy(policy, &pins, now)?;
        Ok(Self { egress, pins })
    }

    pub fn fail_closed() -> Self {
        Self {
            egress: mvm_core::policy::projection::CanonicalEgress::Rules(Vec::new()),
            pins: mvm_core::policy::dns_pin::DnsPinRegistry::new(),
        }
    }

    pub fn egress(&self) -> &mvm_core::policy::projection::CanonicalEgress {
        &self.egress
    }

    pub fn pins(&self) -> &mvm_core::policy::dns_pin::DnsPinRegistry {
        &self.pins
    }

    fn decide_host_port(
        &self,
        proto: mvm_core::policy::projection::Proto,
        host: &str,
        port: u16,
    ) -> HostAdmission {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return if self.egress.permits(&proto, ip, port) {
                HostAdmission::allowed_with_route(HostRoute::resolved_ip(ip))
            } else {
                HostAdmission::denied(DenialReason::HostNotAllowed)
            };
        }
        let Some(pin) = self.pins.lookup(host) else {
            return HostAdmission::denied(DenialReason::HostNotAllowed);
        };
        pin.ips
            .iter()
            .copied()
            .find(|ip| self.egress.permits(&proto, *ip, port))
            .map(|ip| HostAdmission::allowed_with_route(HostRoute::resolved_ip(ip)))
            .unwrap_or_else(|| HostAdmission::denied(DenialReason::HostNotAllowed))
    }

    fn has_admitted_pin(&self, host: &str) -> bool {
        self.pins
            .lookup(host)
            .is_some_and(|pin| !pin.ips.is_empty())
    }
}

#[cfg(feature = "host-mvm-core")]
impl HostNetworkPolicy for MvmCoreNetworkPolicy {
    fn decide_dns(&mut self, query: &DnsQuery) -> HostAdmission {
        match self.egress {
            mvm_core::policy::projection::CanonicalEgress::Unrestricted => {
                if self.has_admitted_pin(query.name.as_str()) {
                    HostAdmission::allowed()
                } else {
                    HostAdmission::denied(DenialReason::HostNotAllowed)
                }
            }
            mvm_core::policy::projection::CanonicalEgress::Rules(_) => {
                if self.has_admitted_pin(query.name.as_str()) {
                    HostAdmission::allowed()
                } else {
                    HostAdmission::denied(DenialReason::HostNotAllowed)
                }
            }
        }
    }

    fn decide_tcp_open(&mut self, open: &OpenTcp) -> HostAdmission {
        self.decide_host_port(
            mvm_core::policy::projection::Proto::Tcp,
            open.target.host(),
            open.target.port(),
        )
    }

    fn decide_udp_datagram(&mut self, datagram: &UdpDatagram) -> HostAdmission {
        self.decide_host_port(
            mvm_core::policy::projection::Proto::Udp,
            datagram.target.host(),
            datagram.target.port(),
        )
    }

    fn decide_icmp_echo(&mut self, _request: &IcmpEchoRequest) -> HostAdmission {
        HostAdmission::denied(DenialReason::ProtocolNotAllowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        DnsRecordType, FlowDirection, FlowId, FlowOpenStatus, HostName, QueryId, TlsPolicy,
        UdpDatagram,
    };

    fn query_id(value: u64) -> QueryId {
        QueryId::new(value).unwrap()
    }

    fn flow_id(value: u64) -> FlowId {
        FlowId::new(value).unwrap()
    }

    fn dns_query(name: &str) -> DnsQuery {
        DnsQuery {
            query_id: query_id(7),
            name: DnsName::new(name).unwrap(),
            record_type: DnsRecordType::A,
        }
    }

    fn open_tcp(host: &str, port: u16) -> OpenTcp {
        OpenTcp::new(flow_id(11), Target::new(host, port).unwrap())
            .with_tls_policy(TlsPolicy::HostDecision)
    }

    #[derive(Debug, Clone)]
    struct StaticPolicy {
        dns: HostAdmission,
        tcp: HostAdmission,
        udp: HostAdmission,
        icmp: HostAdmission,
    }

    impl StaticPolicy {
        fn allow_all() -> Self {
            Self {
                dns: HostAdmission::allowed(),
                tcp: HostAdmission::allowed(),
                udp: HostAdmission::allowed(),
                icmp: HostAdmission::allowed(),
            }
        }

        fn deny_all(reason: DenialReason) -> Self {
            let denial = HostAdmission::denied(reason);
            Self {
                dns: denial.clone(),
                tcp: denial.clone(),
                udp: denial.clone(),
                icmp: denial,
            }
        }
    }

    impl HostNetworkPolicy for StaticPolicy {
        fn decide_dns(&mut self, _query: &DnsQuery) -> HostAdmission {
            self.dns.clone()
        }

        fn decide_tcp_open(&mut self, _open: &OpenTcp) -> HostAdmission {
            self.tcp.clone()
        }

        fn decide_udp_datagram(&mut self, _datagram: &UdpDatagram) -> HostAdmission {
            self.udp.clone()
        }

        fn decide_icmp_echo(&mut self, _request: &IcmpEchoRequest) -> HostAdmission {
            self.icmp.clone()
        }
    }

    #[derive(Debug, Default)]
    struct VecAudit {
        events: Vec<HostAuditEvent>,
    }

    impl HostAuditSink for VecAudit {
        type Error = std::convert::Infallible;

        fn record(&mut self, event: HostAuditEvent) -> Result<(), Self::Error> {
            self.events.push(event);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct FailingAudit;

    impl HostAuditSink for FailingAudit {
        type Error = &'static str;

        fn record(&mut self, _event: HostAuditEvent) -> Result<(), Self::Error> {
            Err("audit unavailable")
        }
    }

    #[derive(Debug)]
    struct RecordingTcpConnector {
        opens: Vec<(u64, String, u16, HostRoute)>,
        sends: Vec<(u64, Vec<u8>, bool)>,
        closes: Vec<(u64, CloseReason)>,
        open_result: Result<(), TransportError>,
        send_result: Result<(), TransportError>,
    }

    impl Default for RecordingTcpConnector {
        fn default() -> Self {
            Self {
                opens: Vec::new(),
                sends: Vec::new(),
                closes: Vec::new(),
                open_result: Ok(()),
                send_result: Ok(()),
            }
        }
    }

    impl RecordingTcpConnector {
        fn with_open_result(open_result: Result<(), TransportError>) -> Self {
            Self {
                open_result,
                ..Self::default()
            }
        }
    }

    impl HostTcpConnector for RecordingTcpConnector {
        fn open(
            &mut self,
            flow_id: FlowId,
            target: &Target,
            _route: &HostRoute,
        ) -> Result<(), TransportError> {
            self.opens.push((
                flow_id.get(),
                target.host().to_string(),
                target.port(),
                *_route,
            ));
            self.open_result
        }

        fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
            self.sends
                .push((chunk.flow_id.get(), chunk.bytes.clone(), chunk.end_stream));
            self.send_result
        }

        fn close(&mut self, flow_id: FlowId, reason: CloseReason) -> Result<(), TransportError> {
            self.closes.push((flow_id.get(), reason));
            Ok(())
        }
    }

    fn authority(
        policy: StaticPolicy,
    ) -> HostAuthority<StaticPolicy, VecAudit, RecordingTcpConnector> {
        HostAuthority::new(
            policy,
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
    }

    #[test]
    fn handshake_accepts_only_configured_guest_capabilities() {
        let mut authority = authority(StaticPolicy::allow_all());
        let responses = authority
            .handle_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns, Capability::Udp, Capability::PolicyDigest],
            )))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::HelloAck(HelloAck::new(vec![
                Capability::Dns,
                Capability::PolicyDigest
            ]))]
        );
        assert_eq!(
            authority.audit_mut().events,
            vec![HostAuditEvent::HandshakeAccepted {
                guest_capabilities: vec![
                    Capability::Dns,
                    Capability::Udp,
                    Capability::PolicyDigest
                ],
                accepted_capabilities: vec![Capability::Dns, Capability::PolicyDigest],
            }]
        );
    }

    #[test]
    fn denied_dns_returns_refused_without_allocating_synthetic_ip() {
        let mut authority = authority(StaticPolicy::deny_all(DenialReason::HostNotAllowed));
        let responses = authority
            .handle_message(NetMessage::DnsQuery(dns_query("Example.COM.")))
            .unwrap();

        match responses.as_slice() {
            [NetMessage::DnsResponse(response)] => {
                assert_eq!(response.code, DnsResponseCode::Refused);
                assert!(response.answers.is_empty());
                assert!(matches!(
                    response.denial,
                    Some(Denial {
                        reason: DenialReason::HostNotAllowed,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(authority.dns_map().is_empty());
    }

    #[test]
    fn allowed_dns_allocates_stable_synthetic_a_records() {
        let mut authority = authority(StaticPolicy::allow_all());
        let first = authority
            .handle_message(NetMessage::DnsQuery(dns_query("Example.COM.")))
            .unwrap();
        let second = authority
            .handle_message(NetMessage::DnsQuery(dns_query("example.com")))
            .unwrap();

        let first_ip = dns_response_ip(&first);
        let second_ip = dns_response_ip(&second);
        assert_eq!(first_ip, Ipv4Addr::new(198, 19, 0, 1));
        assert_eq!(second_ip, first_ip);
        assert_eq!(authority.dns_map().len(), 1);
        assert_eq!(
            authority
                .dns_map()
                .name_for_address(first_ip)
                .map(DnsName::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn synthetic_dns_pool_exhaustion_fails_closed() {
        let config = HostAuthorityConfig::builder()
            .synthetic_dns_base(Ipv4Addr::new(198, 19, 0, 1))
            .max_synthetic_dns_entries(1)
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
        .unwrap();

        authority
            .handle_message(NetMessage::DnsQuery(dns_query("one.example")))
            .unwrap();
        let err = authority
            .handle_message(NetMessage::DnsQuery(dns_query("two.example")))
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::SyntheticDnsPoolExhausted { max_entries: 1 }
        ));
    }

    #[test]
    fn denied_tcp_open_does_not_call_connector() {
        let mut authority = authority(StaticPolicy::deny_all(DenialReason::HostNotAllowed));
        let responses = authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        assert!(authority.tcp_connector_mut().opens.is_empty());
        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::HostNotAllowed,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn allowed_tcp_open_invokes_connector_after_policy_allows() {
        let mut authority = authority(StaticPolicy::allow_all());
        let responses = authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        assert_eq!(
            authority.tcp_connector_mut().opens,
            vec![(
                11,
                "api.example.com".to_string(),
                443,
                HostRoute::unresolved()
            )]
        );
        assert_eq!(
            responses,
            vec![NetMessage::TcpOpenResult(TcpOpenResult::opened(flow_id(
                11
            )))]
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::TcpOpenAllowed {
                    flow_id: 11,
                    host: "api.example.com".to_string(),
                    port: 443,
                    upstream_ip: None,
                })
        );
    }

    #[test]
    fn connector_failure_reports_tcp_open_failure_without_tracking_flow() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::with_open_result(Err(TransportError::Refused)),
        );
        let responses = authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert_eq!(
                    result.status,
                    FlowOpenStatus::Failed(TransportError::Refused)
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
        let data = StreamChunk::new(
            flow_id(11),
            FlowDirection::GuestToHost,
            0,
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        );
        let close = authority.handle_message(NetMessage::TcpData(data)).unwrap();
        assert_eq!(
            close,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::ProtocolError,
            })]
        );
    }

    #[test]
    fn tcp_data_and_close_are_forwarded_only_for_open_flows() {
        let mut authority = authority(StaticPolicy::allow_all());
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        let data = StreamChunk::new(
            flow_id(11),
            FlowDirection::GuestToHost,
            0,
            b"hello".to_vec(),
        );
        assert_eq!(
            authority.handle_message(NetMessage::TcpData(data)).unwrap(),
            Vec::<NetMessage>::new()
        );
        assert_eq!(
            authority.tcp_connector_mut().sends,
            vec![(11, b"hello".to_vec(), false)]
        );

        assert_eq!(
            authority
                .handle_message(NetMessage::CloseFlow(CloseFlow {
                    flow_id: flow_id(11),
                    reason: CloseReason::GuestClosed,
                }))
                .unwrap(),
            Vec::<NetMessage>::new()
        );
        assert_eq!(
            authority.tcp_connector_mut().closes,
            vec![(11, CloseReason::GuestClosed)]
        );
    }

    #[test]
    fn wrong_direction_tcp_data_fails_closed_without_connector_send() {
        let mut authority = authority(StaticPolicy::allow_all());
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        let data = StreamChunk::new(flow_id(11), FlowDirection::HostToGuest, 0, b"bad".to_vec());
        let responses = authority.handle_message(NetMessage::TcpData(data)).unwrap();

        assert_eq!(authority.tcp_connector_mut().sends, Vec::new());
        assert_eq!(
            responses,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::ProtocolError,
            })]
        );
    }

    #[test]
    fn unsupported_allowed_udp_and_icmp_return_explicit_failures() {
        let mut authority = authority(StaticPolicy::allow_all());
        let udp = UdpDatagram {
            flow_id: flow_id(21),
            target: Target::new("dns.example", 53).unwrap(),
            direction: FlowDirection::GuestToHost,
            bytes: vec![1, 2, 3],
        };
        let udp_responses = authority
            .handle_message(NetMessage::UdpDatagram(udp))
            .unwrap();
        assert_eq!(
            udp_responses,
            vec![NetMessage::UdpDelivery(UdpDelivery {
                flow_id: flow_id(21),
                status: DatagramStatus::Failed(TransportError::ProtocolError),
            })]
        );

        let icmp = IcmpEchoRequest {
            query_id: query_id(22),
            host: HostName::new("example.com").unwrap(),
            payload_len: 56,
        };
        let icmp_responses = authority
            .handle_message(NetMessage::IcmpEchoRequest(icmp))
            .unwrap();
        assert_eq!(
            icmp_responses,
            vec![NetMessage::IcmpEchoResponse(IcmpEchoResponse {
                query_id: query_id(22),
                status: IcmpEchoStatus::Unreachable,
                round_trip_micros: None,
                denial: None,
            })]
        );
    }

    #[test]
    fn invalid_config_rejects_empty_dns_pool_and_overflowing_range() {
        assert!(matches!(
            HostAuthorityConfig::builder()
                .max_synthetic_dns_entries(0)
                .build(),
            Err(HostAuthorityError::InvalidConfig(_))
        ));
        assert!(matches!(
            HostAuthorityConfig::builder()
                .synthetic_dns_base(Ipv4Addr::new(255, 255, 255, 255))
                .max_synthetic_dns_entries(2)
                .build(),
            Err(HostAuthorityError::InvalidConfig(_))
        ));
    }

    #[test]
    fn audit_failure_prevents_tcp_connector_open() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            FailingAudit,
            RecordingTcpConnector::default(),
        );
        let err = authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap_err();

        assert!(
            matches!(err, HostAuthorityError::Audit(message) if message == "audit unavailable")
        );
        assert!(authority.tcp_connector_mut().opens.is_empty());
    }

    #[cfg(feature = "host-mvm-core")]
    #[test]
    fn mvm_core_policy_adapter_returns_pinned_tcp_route() {
        use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};

        let mut pins = DnsPinRegistry::new();
        pins.add(DnsPin::at(
            "api.example.com",
            vec!["203.0.113.10".parse().unwrap()],
            "2026-07-08T00:00:00Z",
            "2026-07-09T00:00:00Z",
        ));
        let mut policy = MvmCoreNetworkPolicy::from_network_policy(
            &NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            pins,
            "2026-07-08T12:00:00Z",
        )
        .unwrap();

        assert!(
            policy
                .decide_dns(&dns_query("api.example.com"))
                .is_allowed()
        );
        assert_eq!(
            policy.decide_tcp_open(&open_tcp("api.example.com", 443)),
            HostAdmission::allowed_with_route(HostRoute::resolved_ip(
                "203.0.113.10".parse().unwrap()
            ))
        );
        assert!(matches!(
            policy.decide_tcp_open(&open_tcp("api.example.com", 80)),
            HostAdmission::Denied(Denial {
                reason: DenialReason::HostNotAllowed,
                ..
            })
        ));
    }

    #[cfg(feature = "host-mvm-core")]
    #[test]
    fn mvm_core_policy_adapter_fails_closed_without_required_pin() {
        use mvm_core::policy::dns_pin::DnsPinRegistry;
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        use mvm_core::policy::projection::ProjectionError;

        let err = MvmCoreNetworkPolicy::from_network_policy(
            &NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            DnsPinRegistry::new(),
            "2026-07-08T12:00:00Z",
        )
        .unwrap_err();

        assert!(matches!(err, ProjectionError::MissingPin { host } if host == "api.example.com"));
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_uses_resolved_route_and_forwards_bytes() {
        use std::io::Read;
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let (mut stream, peer) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            (peer.ip(), bytes)
        });

        let mut connector = StdTcpConnector::new();
        let route = HostRoute::resolved_ip("127.0.0.1".parse().unwrap());
        let target = Target::new("route-should-win.invalid", port).unwrap();
        connector.open(flow_id(31), &target, &route).unwrap();
        connector
            .send(&StreamChunk::new(
                flow_id(31),
                FlowDirection::GuestToHost,
                0,
                b"hello".to_vec(),
            ))
            .unwrap();
        connector
            .send(
                &StreamChunk::new(flow_id(31), FlowDirection::GuestToHost, 5, Vec::new())
                    .with_end_stream(),
            )
            .unwrap();
        connector
            .close(flow_id(31), CloseReason::GuestClosed)
            .unwrap();

        let (peer_ip, bytes) = join.join().unwrap();
        assert_eq!(peer_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(bytes, b"hello");
        assert_eq!(connector.open_flow_count(), 0);
    }

    fn dns_response_ip(messages: &[NetMessage]) -> Ipv4Addr {
        match messages {
            [NetMessage::DnsResponse(response)] => match response.answers.as_slice() {
                [
                    DnsAnswer {
                        data: DnsRecordData::Ip(IpAddr::V4(address)),
                        ..
                    },
                ] => *address,
                other => panic!("unexpected DNS answers: {other:?}"),
            },
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
