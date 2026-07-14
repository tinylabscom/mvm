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
use std::time::{Duration, Instant};
#[cfg(feature = "host-std")]
use std::{
    borrow::Cow,
    collections::VecDeque,
    io::{self, Read, Write},
    net::{Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    ops::ControlFlow,
    path::Path,
    process::Command,
};

use crate::proto::{
    Capability, CloseFlow, CloseReason, DatagramStatus, Denial, DenialReason, DnsAnswer, DnsName,
    DnsQuery, DnsRecordData, DnsRecordType, DnsResponse, DnsResponseCode, EndpointRole,
    FlowDirection, FlowId, Hello, HelloAck, IcmpEchoRequest, IcmpEchoResponse, IcmpEchoStatus,
    MAX_ENDPOINT_CAPABILITIES, NetMessage, OpenTcp, ProtocolError, QueryId, StreamChunk, Target,
    TcpOpenResult, TlsPolicy, TlsTransformRoute, TransportError, UdpDatagram, UdpDelivery,
};
pub const DEFAULT_SYNTHETIC_DNS_BASE: Ipv4Addr = Ipv4Addr::new(198, 19, 0, 1);
pub const DEFAULT_MAX_SYNTHETIC_DNS_ENTRIES: usize = 65_534;
pub const MAX_SYNTHETIC_DNS_ENTRIES: usize = DEFAULT_MAX_SYNTHETIC_DNS_ENTRIES;
pub const DEFAULT_DNS_TTL_SECONDS: u32 = 30;
pub const MAX_DNS_TTL_SECONDS: u32 = DEFAULT_DNS_TTL_SECONDS;
pub const DEFAULT_MAX_OPEN_FLOWS: usize = 16_384;
pub const MAX_OPEN_FLOWS: usize = DEFAULT_MAX_OPEN_FLOWS;
pub const DEFAULT_MAX_GUEST_REQUESTS_PER_WINDOW: usize = 4_096;
pub const MAX_GUEST_REQUESTS_PER_WINDOW: usize = DEFAULT_MAX_GUEST_REQUESTS_PER_WINDOW;
pub const DEFAULT_GUEST_REQUEST_RATE_WINDOW: Duration = Duration::from_secs(1);
pub const MAX_GUEST_REQUEST_RATE_WINDOW: Duration = DEFAULT_GUEST_REQUEST_RATE_WINDOW;
pub const DEFAULT_UDP_READ_TIMEOUT: Duration = Duration::from_millis(1);
pub const MAX_UDP_READ_TIMEOUT: Duration = DEFAULT_UDP_READ_TIMEOUT;
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_TCP_IDLE_TIMEOUT: Duration = DEFAULT_TCP_IDLE_TIMEOUT;
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_UDP_IDLE_TIMEOUT: Duration = DEFAULT_UDP_IDLE_TIMEOUT;
#[cfg(feature = "host-std")]
pub const DEFAULT_STD_TCP_READ_TIMEOUT: Duration = Duration::from_millis(1);
#[cfg(feature = "host-std")]
pub const MAX_STD_TCP_CONNECT_TIMEOUT: Duration = DEFAULT_TCP_IDLE_TIMEOUT;
#[cfg(feature = "host-std")]
pub const MAX_STD_TCP_READ_TIMEOUT: Duration = DEFAULT_TCP_IDLE_TIMEOUT;
#[cfg(feature = "host-std")]
pub const DEFAULT_MAX_RESOLVED_TARGET_ADDRS: usize = 64;
#[cfg(feature = "host-std")]
pub const MAX_RESOLVED_TARGET_ADDRS: usize = DEFAULT_MAX_RESOLVED_TARGET_ADDRS;
#[cfg(feature = "host-std")]
const ICMP_ECHO_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(feature = "host-std")]
const STD_UDP_READ_BUFFER_BYTES: usize = crate::proto::MAX_STREAM_CHUNK_BYTES;
#[cfg(feature = "host-std")]
pub const DEFAULT_MAX_ICMP_ERROR_DETAIL_BYTES: usize = 8 * 1024;
#[cfg(feature = "host-std")]
pub const MAX_ICMP_ERROR_DETAIL_BYTES: usize = DEFAULT_MAX_ICMP_ERROR_DETAIL_BYTES;
pub const DEFAULT_MAX_HOST_AUDIT_DETAIL_BYTES: usize = 8 * 1024;
pub const MAX_HOST_AUDIT_DETAIL_BYTES: usize = DEFAULT_MAX_HOST_AUDIT_DETAIL_BYTES;

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
    max_open_flows: usize,
    max_guest_requests_per_window: usize,
    guest_request_rate_window: Duration,
    udp_read_timeout: Duration,
    tcp_idle_timeout: Duration,
    udp_idle_timeout: Duration,
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

    pub const fn max_open_flows(&self) -> usize {
        self.max_open_flows
    }

    pub const fn max_guest_requests_per_window(&self) -> usize {
        self.max_guest_requests_per_window
    }

    pub const fn guest_request_rate_window(&self) -> Duration {
        self.guest_request_rate_window
    }

    pub const fn udp_read_timeout(&self) -> Duration {
        self.udp_read_timeout
    }

    pub const fn tcp_idle_timeout(&self) -> Duration {
        self.tcp_idle_timeout
    }

    pub const fn udp_idle_timeout(&self) -> Duration {
        self.udp_idle_timeout
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
    max_open_flows: usize,
    max_guest_requests_per_window: usize,
    guest_request_rate_window: Duration,
    udp_read_timeout: Duration,
    tcp_idle_timeout: Duration,
    udp_idle_timeout: Duration,
    capabilities: Vec<Capability>,
}

impl Default for HostAuthorityConfigBuilder {
    fn default() -> Self {
        Self {
            synthetic_dns_base: DEFAULT_SYNTHETIC_DNS_BASE,
            max_synthetic_dns_entries: DEFAULT_MAX_SYNTHETIC_DNS_ENTRIES,
            dns_ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
            max_open_flows: DEFAULT_MAX_OPEN_FLOWS,
            max_guest_requests_per_window: DEFAULT_MAX_GUEST_REQUESTS_PER_WINDOW,
            guest_request_rate_window: DEFAULT_GUEST_REQUEST_RATE_WINDOW,
            udp_read_timeout: DEFAULT_UDP_READ_TIMEOUT,
            tcp_idle_timeout: DEFAULT_TCP_IDLE_TIMEOUT,
            udp_idle_timeout: DEFAULT_UDP_IDLE_TIMEOUT,
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

    pub fn max_open_flows(mut self, max_open_flows: usize) -> Self {
        self.max_open_flows = max_open_flows;
        self
    }

    pub fn max_guest_requests_per_window(mut self, max_guest_requests_per_window: usize) -> Self {
        self.max_guest_requests_per_window = max_guest_requests_per_window;
        self
    }

    pub fn guest_request_rate_window(mut self, guest_request_rate_window: Duration) -> Self {
        self.guest_request_rate_window = guest_request_rate_window;
        self
    }

    pub fn udp_read_timeout(mut self, udp_read_timeout: Duration) -> Self {
        self.udp_read_timeout = udp_read_timeout;
        self
    }

    pub fn tcp_idle_timeout(mut self, tcp_idle_timeout: Duration) -> Self {
        self.tcp_idle_timeout = tcp_idle_timeout;
        self
    }

    pub fn udp_idle_timeout(mut self, udp_idle_timeout: Duration) -> Self {
        self.udp_idle_timeout = udp_idle_timeout;
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
        if self.max_synthetic_dns_entries > MAX_SYNTHETIC_DNS_ENTRIES {
            return Err(HostAuthorityError::InvalidConfig(
                "max_synthetic_dns_entries exceeds the hard maximum",
            ));
        }
        if self.dns_ttl_seconds == 0 {
            return Err(HostAuthorityError::InvalidConfig(
                "dns_ttl_seconds must be non-zero",
            ));
        }
        if self.dns_ttl_seconds > MAX_DNS_TTL_SECONDS {
            return Err(HostAuthorityError::InvalidConfig(
                "dns_ttl_seconds exceeds the hard maximum",
            ));
        }
        if self.max_open_flows == 0 {
            return Err(HostAuthorityError::InvalidConfig(
                "max_open_flows must be non-zero",
            ));
        }
        if self.max_open_flows > MAX_OPEN_FLOWS {
            return Err(HostAuthorityError::InvalidConfig(
                "max_open_flows exceeds the hard maximum",
            ));
        }
        if self.max_guest_requests_per_window == 0 {
            return Err(HostAuthorityError::InvalidConfig(
                "max_guest_requests_per_window must be non-zero",
            ));
        }
        if self.max_guest_requests_per_window > MAX_GUEST_REQUESTS_PER_WINDOW {
            return Err(HostAuthorityError::InvalidConfig(
                "max_guest_requests_per_window exceeds the hard maximum",
            ));
        }
        if self.guest_request_rate_window.is_zero() {
            return Err(HostAuthorityError::InvalidConfig(
                "guest_request_rate_window must be non-zero",
            ));
        }
        if self.guest_request_rate_window > MAX_GUEST_REQUEST_RATE_WINDOW {
            return Err(HostAuthorityError::InvalidConfig(
                "guest_request_rate_window exceeds the hard maximum",
            ));
        }
        if self.udp_read_timeout.is_zero() {
            return Err(HostAuthorityError::InvalidConfig(
                "udp_read_timeout must be non-zero",
            ));
        }
        if self.udp_read_timeout > MAX_UDP_READ_TIMEOUT {
            return Err(HostAuthorityError::InvalidConfig(
                "udp_read_timeout exceeds the hard maximum",
            ));
        }
        if self.tcp_idle_timeout.is_zero() {
            return Err(HostAuthorityError::InvalidConfig(
                "tcp_idle_timeout must be non-zero",
            ));
        }
        if self.tcp_idle_timeout > MAX_TCP_IDLE_TIMEOUT {
            return Err(HostAuthorityError::InvalidConfig(
                "tcp_idle_timeout exceeds the hard maximum",
            ));
        }
        if self.udp_idle_timeout.is_zero() {
            return Err(HostAuthorityError::InvalidConfig(
                "udp_idle_timeout must be non-zero",
            ));
        }
        if self.udp_idle_timeout > MAX_UDP_IDLE_TIMEOUT {
            return Err(HostAuthorityError::InvalidConfig(
                "udp_idle_timeout exceeds the hard maximum",
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
        let capabilities = dedupe_capabilities(self.capabilities);
        if capabilities.len() > MAX_ENDPOINT_CAPABILITIES {
            return Err(HostAuthorityError::InvalidConfig(
                "capabilities exceed the protocol handshake maximum",
            ));
        }
        Ok(HostAuthorityConfig {
            synthetic_dns_base: self.synthetic_dns_base,
            max_synthetic_dns_entries: self.max_synthetic_dns_entries,
            dns_ttl_seconds: self.dns_ttl_seconds,
            max_open_flows: self.max_open_flows,
            max_guest_requests_per_window: self.max_guest_requests_per_window,
            guest_request_rate_window: self.guest_request_rate_window,
            udp_read_timeout: self.udp_read_timeout,
            tcp_idle_timeout: self.tcp_idle_timeout,
            udp_idle_timeout: self.udp_idle_timeout,
            capabilities,
        })
    }
}

fn dedupe_capabilities(capabilities: Vec<Capability>) -> Vec<Capability> {
    let mut deduped = Vec::with_capacity(capabilities.len());
    for capability in capabilities {
        if !deduped.contains(&capability) {
            deduped.push(capability);
        }
    }
    deduped
}

#[derive(Debug, Clone)]
struct FixedWindowRateLimiter {
    max_requests: usize,
    window: Duration,
    window_started: Instant,
    used_requests: usize,
}

impl FixedWindowRateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            window_started: Instant::now(),
            used_requests: 0,
        }
    }

    fn try_acquire(&mut self) -> bool {
        if self.window_started.elapsed() >= self.window {
            self.window_started = Instant::now();
            self.used_requests = 0;
        }
        if self.used_requests >= self.max_requests {
            return false;
        }
        self.used_requests += 1;
        true
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectSpec {
    flow_id: FlowId,
    target: Target,
    route: HostRoute,
    tls_policy: TlsPolicy,
    tls_transform: Option<TlsTransformRoute>,
}

impl TcpConnectSpec {
    pub fn from_open(open: &OpenTcp, route: HostRoute) -> Self {
        Self {
            flow_id: open.flow_id,
            target: open.target.clone(),
            route,
            tls_policy: open.tls_policy,
            tls_transform: open.tls_transform.clone(),
        }
    }

    pub fn from_owned_open(open: OpenTcp, route: HostRoute) -> Self {
        Self {
            flow_id: open.flow_id,
            target: open.target,
            route,
            tls_policy: open.tls_policy,
            tls_transform: open.tls_transform,
        }
    }

    pub const fn flow_id(&self) -> FlowId {
        self.flow_id
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub const fn route(&self) -> HostRoute {
        self.route
    }

    pub const fn tls_policy(&self) -> TlsPolicy {
        self.tls_policy
    }

    pub fn tls_transform(&self) -> Option<&TlsTransformRoute> {
        self.tls_transform.as_ref()
    }

    pub fn requires_tls_transform(&self) -> bool {
        matches!(self.tls_policy, TlsPolicy::RequiredForTransform) || self.tls_transform.is_some()
    }
}

#[derive(Debug, Clone)]
struct OpenTcpFlowState {
    last_activity: Instant,
}

#[cfg(feature = "host-std")]
struct UdpFailureAudit {
    host: String,
    port: u16,
    upstream_ip: Option<IpAddr>,
    bytes: usize,
    error: TransportError,
    error_detail: Option<String>,
}

#[cfg(feature = "host-std")]
impl UdpFailureAudit {
    fn from_target(
        target: &Target,
        upstream_ip: Option<IpAddr>,
        bytes: usize,
        error: TransportError,
        error_detail: Option<String>,
    ) -> Self {
        let (host, port) = target.host_and_port();
        Self {
            host: host.to_owned(),
            port,
            upstream_ip,
            bytes,
            error,
            error_detail,
        }
    }

    fn from_host_port(
        host: String,
        port: u16,
        upstream_ip: Option<IpAddr>,
        bytes: usize,
        error: TransportError,
        error_detail: Option<String>,
    ) -> Self {
        Self {
            host,
            port,
            upstream_ip,
            bytes,
            error,
            error_detail,
        }
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
        error_detail: Option<String>,
    },
    TcpBytesForwarded {
        flow_id: u64,
        sequence: u64,
        bytes: usize,
        end_stream: bool,
        detail: Option<String>,
    },
    TcpForwardFailed {
        flow_id: u64,
        bytes: usize,
        end_stream: bool,
        error: TransportError,
        error_detail: Option<String>,
    },
    TcpBytesReturned {
        flow_id: u64,
        sequence: u64,
        bytes: usize,
        end_stream: bool,
        detail: Option<String>,
    },
    FlowClosed {
        flow_id: u64,
        reason: CloseReason,
        error_detail: Option<String>,
    },
    UdpDenied {
        flow_id: u64,
        host: String,
        port: u16,
        denial: Denial,
    },
    UdpForwarded {
        flow_id: u64,
        host: String,
        port: u16,
        upstream_ip: Option<IpAddr>,
        bytes: usize,
    },
    UdpReturned {
        flow_id: u64,
        host: String,
        port: u16,
        upstream_ip: Option<IpAddr>,
        bytes: usize,
    },
    UdpFailed {
        flow_id: u64,
        host: String,
        port: u16,
        upstream_ip: Option<IpAddr>,
        bytes: usize,
        error: TransportError,
        error_detail: Option<String>,
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
    IcmpReplied {
        query_id: u64,
        host: String,
        upstream_ip: Option<IpAddr>,
        round_trip_micros: Option<u64>,
    },
    IcmpFailed {
        query_id: u64,
        host: String,
        upstream_ip: Option<IpAddr>,
        status: IcmpEchoStatus,
        error_detail: Option<String>,
    },
    IcmpUnsupported {
        query_id: u64,
        host: String,
    },
}

pub trait HostTcpConnector {
    fn open(&mut self, spec: &TcpConnectSpec) -> Result<(), TransportError>;

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError>;

    fn close(&mut self, flow_id: FlowId, reason: CloseReason) -> Result<(), TransportError>;

    fn drain_events(&mut self, max_events: usize) -> Result<Vec<HostTcpEvent>, TransportError>;

    fn supports_tls_transform(&self) -> bool {
        false
    }

    fn supports_stream_transforms(&self) -> bool {
        false
    }

    fn validate_stream_transforms(
        &self,
        _plugin_chain: &[crate::proto::PluginId],
        _target_host: Option<&str>,
    ) -> Result<(), String> {
        Ok(())
    }

    fn take_activity_detail(&mut self, _flow_id: FlowId) -> Option<String> {
        None
    }

    fn take_error_detail(&mut self, _flow_id: FlowId) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTcpEvent {
    Data(StreamChunk),
    Close(CloseFlow),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingTcpConnector;

impl HostTcpConnector for RefusingTcpConnector {
    fn open(&mut self, _spec: &TcpConnectSpec) -> Result<(), TransportError> {
        Err(TransportError::ProtocolError)
    }

    fn send(&mut self, _chunk: &StreamChunk) -> Result<(), TransportError> {
        Err(TransportError::ProtocolError)
    }

    fn close(&mut self, _flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        Ok(())
    }

    fn drain_events(&mut self, _max_events: usize) -> Result<Vec<HostTcpEvent>, TransportError> {
        Ok(Vec::new())
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdTcpConnectorConfig {
    connect_timeout: Option<Duration>,
    read_timeout: Duration,
    max_open_flows: usize,
}

#[cfg(feature = "host-std")]
impl StdTcpConnectorConfig {
    pub fn builder() -> StdTcpConnectorConfigBuilder {
        StdTcpConnectorConfigBuilder::default()
    }

    pub const fn connect_timeout(&self) -> Option<Duration> {
        self.connect_timeout
    }

    pub const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    pub const fn max_open_flows(&self) -> usize {
        self.max_open_flows
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdTcpConnectorConfigError {
    ZeroConnectTimeout,
    ConnectTimeoutTooLarge { actual: Duration, max: Duration },
    ZeroReadTimeout,
    ReadTimeoutTooLarge { actual: Duration, max: Duration },
    ZeroMaxOpenFlows,
    MaxOpenFlowsTooLarge { actual: usize, max: usize },
}

#[cfg(feature = "host-std")]
impl fmt::Display for StdTcpConnectorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroConnectTimeout => write!(f, "connect timeout must be non-zero"),
            Self::ConnectTimeoutTooLarge { actual, max } => {
                write!(
                    f,
                    "connect timeout exceeds the hard maximum ({} ms > {} ms)",
                    actual.as_millis(),
                    max.as_millis()
                )
            }
            Self::ZeroReadTimeout => write!(f, "read timeout must be non-zero"),
            Self::ReadTimeoutTooLarge { actual, max } => {
                write!(
                    f,
                    "read timeout exceeds the hard maximum ({} ms > {} ms)",
                    actual.as_millis(),
                    max.as_millis()
                )
            }
            Self::ZeroMaxOpenFlows => write!(f, "max open flows must be non-zero"),
            Self::MaxOpenFlowsTooLarge { actual, max } => {
                write!(
                    f,
                    "max open flows exceeds the hard maximum ({actual} > {max})"
                )
            }
        }
    }
}

#[cfg(feature = "host-std")]
impl std::error::Error for StdTcpConnectorConfigError {}

#[cfg(feature = "host-std")]
impl Default for StdTcpConnectorConfig {
    fn default() -> Self {
        StdTcpConnectorConfigBuilder::default()
            .build()
            .expect("default std tcp connector config is valid")
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Clone)]
pub struct StdTcpConnectorConfigBuilder {
    connect_timeout: Option<Duration>,
    read_timeout: Duration,
    max_open_flows: usize,
}

#[cfg(feature = "host-std")]
impl Default for StdTcpConnectorConfigBuilder {
    fn default() -> Self {
        Self {
            connect_timeout: None,
            read_timeout: DEFAULT_STD_TCP_READ_TIMEOUT,
            max_open_flows: DEFAULT_MAX_OPEN_FLOWS,
        }
    }
}

#[cfg(feature = "host-std")]
impl StdTcpConnectorConfigBuilder {
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = Some(connect_timeout);
        self
    }

    pub fn read_timeout(mut self, read_timeout: Duration) -> Self {
        self.read_timeout = read_timeout;
        self
    }

    pub fn max_open_flows(mut self, max_open_flows: usize) -> Self {
        self.max_open_flows = max_open_flows;
        self
    }

    pub fn build(self) -> Result<StdTcpConnectorConfig, StdTcpConnectorConfigError> {
        if self
            .connect_timeout
            .is_some_and(|timeout| timeout.is_zero())
        {
            return Err(StdTcpConnectorConfigError::ZeroConnectTimeout);
        }
        if let Some(connect_timeout) = self.connect_timeout
            && connect_timeout > MAX_STD_TCP_CONNECT_TIMEOUT
        {
            return Err(StdTcpConnectorConfigError::ConnectTimeoutTooLarge {
                actual: connect_timeout,
                max: MAX_STD_TCP_CONNECT_TIMEOUT,
            });
        }
        if self.read_timeout.is_zero() {
            return Err(StdTcpConnectorConfigError::ZeroReadTimeout);
        }
        if self.read_timeout > MAX_STD_TCP_READ_TIMEOUT {
            return Err(StdTcpConnectorConfigError::ReadTimeoutTooLarge {
                actual: self.read_timeout,
                max: MAX_STD_TCP_READ_TIMEOUT,
            });
        }
        if self.max_open_flows == 0 {
            return Err(StdTcpConnectorConfigError::ZeroMaxOpenFlows);
        }
        if self.max_open_flows > MAX_OPEN_FLOWS {
            return Err(StdTcpConnectorConfigError::MaxOpenFlowsTooLarge {
                actual: self.max_open_flows,
                max: MAX_OPEN_FLOWS,
            });
        }
        Ok(StdTcpConnectorConfig {
            connect_timeout: self.connect_timeout,
            read_timeout: self.read_timeout,
            max_open_flows: self.max_open_flows,
        })
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug)]
struct StdTcpFlowState {
    stream: TcpStream,
    host_sequence: u64,
    guest_stream: GuestStreamTracker,
    pending_guest_ack: bool,
    read_buffer: Vec<u8>,
}

#[cfg(feature = "host-std")]
#[derive(Debug)]
struct StdUdpFlowState {
    socket: UdpSocket,
    target: Target,
    route: HostRoute,
    last_activity: Instant,
    read_buffer: Vec<u8>,
}

#[cfg(feature = "host-std")]
const STD_TCP_READ_BUFFER_BYTES: usize = 8 * 1024;

#[cfg(feature = "host-std")]
#[derive(Debug, Default)]
pub struct StdTcpConnector {
    config: StdTcpConnectorConfig,
    streams: HashMap<FlowId, StdTcpFlowState>,
    flow_order: VecDeque<FlowId>,
}

#[cfg(feature = "host-std")]
impl StdTcpConnector {
    pub fn new() -> Self {
        Self::with_config(StdTcpConnectorConfig::default())
    }

    pub fn with_config(config: StdTcpConnectorConfig) -> Self {
        let flow_capacity = initial_std_tcp_connector_flow_capacity(&config);
        Self {
            config,
            streams: HashMap::with_capacity(flow_capacity),
            flow_order: VecDeque::with_capacity(flow_capacity),
        }
    }

    pub fn config(&self) -> &StdTcpConnectorConfig {
        &self.config
    }

    pub fn open_flow_count(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(feature = "host-std")]
fn initial_std_tcp_connector_flow_capacity(config: &StdTcpConnectorConfig) -> usize {
    config.max_open_flows()
}

#[cfg(feature = "host-std")]
impl HostTcpConnector for StdTcpConnector {
    fn open(&mut self, spec: &TcpConnectSpec) -> Result<(), TransportError> {
        if spec.requires_tls_transform() {
            return Err(TransportError::TlsHandshakeFailed);
        }
        if !self.streams.contains_key(&spec.flow_id())
            && self.streams.len() >= self.config.max_open_flows()
        {
            return Err(TransportError::Refused);
        }
        let flow_id = spec.flow_id();
        if self.streams.contains_key(&flow_id) {
            return Err(TransportError::ProtocolError);
        }
        let stream = connect_target_with_config(&self.config, spec.target(), spec.route())?;
        stream.set_nodelay(true).map_err(map_tcp_io_error)?;
        stream
            .set_read_timeout(Some(self.config.read_timeout()))
            .map_err(map_tcp_io_error)?;
        self.streams.insert(
            flow_id,
            StdTcpFlowState {
                stream,
                host_sequence: 0,
                guest_stream: GuestStreamTracker::default(),
                pending_guest_ack: false,
                read_buffer: vec![0u8; STD_TCP_READ_BUFFER_BYTES],
            },
        );
        self.flow_order.push_back(flow_id);
        Ok(())
    }

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
        let state = self
            .streams
            .get_mut(&chunk.flow_id)
            .ok_or(TransportError::ProtocolError)?;
        let action = state.guest_stream.observe(chunk)?;
        if !chunk.bytes.is_empty() {
            state.pending_guest_ack = true;
        }
        if matches!(action, GuestChunkAction::Ignore) {
            return Ok(());
        }
        state
            .stream
            .write_all(&chunk.bytes)
            .map_err(map_tcp_io_error)?;
        if chunk.end_stream {
            state
                .stream
                .shutdown(Shutdown::Write)
                .map_err(map_tcp_io_error)?;
        }
        Ok(())
    }

    fn close(&mut self, flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        if let Some(state) = self.streams.remove(&flow_id) {
            let _ = state.stream.shutdown(Shutdown::Both);
        }
        drop_flow_order_refs(&mut self.flow_order, flow_id);
        Ok(())
    }

    fn drain_events(&mut self, max_events: usize) -> Result<Vec<HostTcpEvent>, TransportError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        if self.streams.is_empty() {
            self.flow_order.clear();
            return Ok(Vec::new());
        }

        let mut events = Vec::with_capacity(max_events);
        let mut scanned = 0usize;
        let max_scan = self.flow_order.len();
        while scanned < max_scan && events.len() < max_events {
            let Some(flow_id) = self.flow_order.pop_front() else {
                break;
            };
            scanned += 1;
            if !self.streams.contains_key(&flow_id) {
                continue;
            }
            if let Some(event) = self.drain_flow_event(flow_id)? {
                let remove_flow = matches!(event, HostTcpEvent::Close(_));
                events.push(event);
                if remove_flow {
                    drop_flow_order_refs(&mut self.flow_order, flow_id);
                } else {
                    self.flow_order.push_back(flow_id);
                }
            } else {
                self.flow_order.push_back(flow_id);
            }
        }
        Ok(events)
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestChunkAction {
    Ignore,
    Forward,
}

#[cfg(feature = "host-std")]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestStreamTracker {
    next_sequence: Option<u64>,
    write_closed: bool,
}

#[cfg(feature = "host-std")]
impl GuestStreamTracker {
    pub(crate) fn observe(
        &mut self,
        chunk: &StreamChunk,
    ) -> Result<GuestChunkAction, TransportError> {
        let chunk_len: u64 = chunk
            .bytes
            .len()
            .try_into()
            .map_err(|_| TransportError::ProtocolError)?;
        let chunk_end = chunk
            .sequence
            .checked_add(chunk_len)
            .ok_or(TransportError::ProtocolError)?;
        if self.write_closed {
            return if self
                .next_sequence
                .is_some_and(|expected| chunk_end <= expected)
            {
                Ok(GuestChunkAction::Ignore)
            } else {
                Err(TransportError::ProtocolError)
            };
        }

        let action = match self.next_sequence {
            None => GuestChunkAction::Forward,
            Some(expected) if chunk.sequence == expected => GuestChunkAction::Forward,
            Some(expected) if chunk_end <= expected => GuestChunkAction::Ignore,
            Some(_) => return Err(TransportError::ProtocolError),
        };

        if action == GuestChunkAction::Forward {
            self.next_sequence = Some(chunk_end);
            if chunk.end_stream {
                self.write_closed = true;
            }
        }
        Ok(action)
    }
}

#[cfg(feature = "host-std")]
impl StdTcpConnector {
    fn drain_flow_event(
        &mut self,
        flow_id: FlowId,
    ) -> Result<Option<HostTcpEvent>, TransportError> {
        let mut remove_flow = false;
        let event = {
            let Some(state) = self.streams.get_mut(&flow_id) else {
                return Ok(None);
            };
            if state.pending_guest_ack {
                state.pending_guest_ack = false;
                return Ok(Some(host_guest_ack_event(flow_id, state.host_sequence)));
            }
            loop {
                match state.stream.read(state.read_buffer.as_mut_slice()) {
                    Ok(0) => {
                        remove_flow = true;
                        break Some(host_closed_tcp_event(flow_id));
                    }
                    Ok(bytes) => {
                        let sequence = state.host_sequence;
                        state.host_sequence = state
                            .host_sequence
                            .checked_add(bytes as u64)
                            .ok_or(TransportError::ProtocolError)?;
                        break Some(HostTcpEvent::Data(StreamChunk::new(
                            flow_id,
                            FlowDirection::HostToGuest,
                            sequence,
                            state.read_buffer[..bytes].to_vec(),
                        )));
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err)
                        if matches!(
                            err.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break None;
                    }
                    Err(_) => {
                        remove_flow = true;
                        break Some(host_closed_tcp_event(flow_id));
                    }
                }
            }
        };

        if remove_flow {
            self.streams.remove(&flow_id);
        }
        Ok(event)
    }
}

#[cfg(feature = "host-std")]
pub(crate) fn connect_target_with_config(
    config: &StdTcpConnectorConfig,
    target: &Target,
    route: HostRoute,
) -> Result<TcpStream, TransportError> {
    let mut last_error = None;
    if let Some(stream) = resolve_target_addrs_with(target, route, |addr| {
        match connect_addr_with_config(config, addr) {
            Ok(stream) => ControlFlow::Break(stream),
            Err(err) => {
                last_error = Some(err);
                ControlFlow::Continue(())
            }
        }
    })? {
        return Ok(stream);
    }
    Err(last_error.unwrap_or(TransportError::DnsFailed))
}

#[cfg(feature = "host-std")]
fn resolve_target_addrs_with<T>(
    target: &Target,
    route: HostRoute,
    mut handle: impl FnMut(SocketAddr) -> ControlFlow<T>,
) -> Result<Option<T>, TransportError> {
    if let Some(ip) = route.upstream_ip() {
        return Ok(match handle(SocketAddr::new(ip, target.port())) {
            ControlFlow::Break(result) => Some(result),
            ControlFlow::Continue(()) => None,
        });
    }
    let resolved = (target.host(), target.port())
        .to_socket_addrs()
        .map_err(map_tcp_io_error)?;
    match for_each_bounded_resolved_target_addr(resolved, handle).map_err(map_tcp_io_error)? {
        ControlFlow::Break(result) => Ok(Some(result)),
        ControlFlow::Continue(()) => Ok(None),
    }
}

#[cfg(all(feature = "host-std", test))]
fn collect_resolved_target_addrs(
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> io::Result<Vec<SocketAddr>> {
    let mut collected = Vec::with_capacity(MAX_RESOLVED_TARGET_ADDRS);
    let _ = for_each_bounded_resolved_target_addr(addrs, |addr| {
        collected.push(addr);
        ControlFlow::<()>::Continue(())
    })?;
    Ok(collected)
}

#[cfg(feature = "host-std")]
fn for_each_bounded_resolved_target_addr<T>(
    addrs: impl IntoIterator<Item = SocketAddr>,
    mut handle: impl FnMut(SocketAddr) -> ControlFlow<T>,
) -> io::Result<ControlFlow<T>> {
    for (count, addr) in addrs.into_iter().enumerate() {
        if count >= MAX_RESOLVED_TARGET_ADDRS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resolved target address count exceeded configured budget",
            ));
        }
        match handle(addr) {
            ControlFlow::Break(result) => return Ok(ControlFlow::Break(result)),
            ControlFlow::Continue(()) => {}
        }
    }
    Ok(ControlFlow::Continue(()))
}

#[cfg(feature = "host-std")]
fn connect_addr_with_config(
    config: &StdTcpConnectorConfig,
    addr: SocketAddr,
) -> Result<TcpStream, TransportError> {
    match config.connect_timeout() {
        Some(timeout) => TcpStream::connect_timeout(&addr, timeout),
        None => TcpStream::connect(addr),
    }
    .map_err(map_tcp_io_error)
}

#[cfg(feature = "host-std")]
fn bind_udp_target(
    target: &Target,
    route: HostRoute,
    read_timeout: Duration,
) -> io::Result<UdpSocket> {
    let mut last_error = None;
    if let Some(socket) = resolve_target_addrs_with(target, route, |addr| {
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        match UdpSocket::bind(bind_addr) {
            Ok(socket) => match socket.connect(addr) {
                Ok(()) => match socket.set_read_timeout(Some(read_timeout)) {
                    Ok(()) => ControlFlow::Break(socket),
                    Err(err) => {
                        last_error = Some(err);
                        ControlFlow::Continue(())
                    }
                },
                Err(err) => {
                    last_error = Some(err);
                    ControlFlow::Continue(())
                }
            },
            Err(err) => {
                last_error = Some(err);
                ControlFlow::Continue(())
            }
        }
    })
    .map_err(host_transport_io_error)?
    {
        return Ok(socket);
    }
    Err(last_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
}

#[cfg(feature = "host-std")]
fn host_transport_io_error(err: TransportError) -> io::Error {
    let kind = match err {
        TransportError::DnsFailed => io::ErrorKind::NotFound,
        TransportError::TimedOut => io::ErrorKind::TimedOut,
        TransportError::Refused => io::ErrorKind::ConnectionRefused,
        TransportError::Reset => io::ErrorKind::ConnectionReset,
        TransportError::Unreachable => io::ErrorKind::AddrNotAvailable,
        TransportError::TlsHandshakeFailed
        | TransportError::ProtocolError
        | TransportError::TransformError => io::ErrorKind::InvalidInput,
    };
    io::Error::from(kind)
}

#[cfg(feature = "host-std")]
pub(crate) fn map_tcp_io_error(err: io::Error) -> TransportError {
    match err.kind() {
        io::ErrorKind::ConnectionRefused => TransportError::Refused,
        io::ErrorKind::ConnectionReset => TransportError::Reset,
        io::ErrorKind::TimedOut => TransportError::TimedOut,
        io::ErrorKind::NotFound | io::ErrorKind::InvalidInput => TransportError::DnsFailed,
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof => TransportError::Reset,
        _ => TransportError::Unreachable,
    }
}

#[cfg(feature = "host-std")]
pub(crate) fn summarize_tls_records(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 {
        return None;
    }

    let mut offset = 0usize;
    let mut summary = String::with_capacity(estimated_tls_record_summary_capacity(bytes));
    let mut record_count = 0usize;
    while offset + 5 <= bytes.len() && record_count < 4 {
        let typ = bytes[offset];
        let version = u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]);
        let len = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
        let body_start = offset + 5;
        let Some(body_end) = body_start.checked_add(len) else {
            break;
        };
        if body_end > bytes.len() {
            break;
        }

        let label = match typ {
            0x14 => "change_cipher_spec",
            0x15 => "alert",
            0x16 => "handshake",
            0x17 => "application_data",
            other => {
                let mut single =
                    String::with_capacity("tls_record type=0x00 version=0x0000 len=".len() + 20);
                single.push_str("tls_record type=0x");
                append_u8_hex_digits(&mut single, other);
                single.push_str(" version=0x");
                append_u16_hex_digits(&mut single, version);
                single.push_str(" len=");
                append_usize_decimal(&mut single, len);
                return Some(single);
            }
        };

        if record_count > 0 {
            summary.push(' ');
        }
        summary.push_str(label);
        summary.push_str("(version=0x");
        append_u16_hex_digits(&mut summary, version);
        summary.push_str(",len=");
        append_usize_decimal(&mut summary, len);
        if typ == 0x15 && len >= 2 {
            let level = bytes[body_start];
            let desc = bytes[body_start + 1];
            summary.push_str(",level=");
            summary.push_str(tls_alert_level_name(level));
            summary.push_str(",description=");
            summary.push_str(tls_alert_description_name(desc));
        }
        summary.push(')');
        record_count += 1;
        offset = body_end;
    }

    if record_count == 0 {
        None
    } else {
        Some(summary)
    }
}

#[cfg(feature = "host-std")]
fn estimated_tls_record_summary_capacity(bytes: &[u8]) -> usize {
    let max_records = (bytes.len() / 5).clamp(1, 4);
    max_records * ("application_data(version=0x0000,len=65535,alert=255/255)".len() + 1)
}

#[cfg(feature = "host-std")]
fn append_u8_hex_digits(formatted: &mut String, value: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    formatted.push(HEX[((value >> 4) & 0x0f) as usize] as char);
    formatted.push(HEX[(value & 0x0f) as usize] as char);
}

#[cfg(feature = "host-std")]
fn append_u16_hex_digits(formatted: &mut String, value: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    formatted.push(HEX[((value >> 12) & 0x0f) as usize] as char);
    formatted.push(HEX[((value >> 8) & 0x0f) as usize] as char);
    formatted.push(HEX[((value >> 4) & 0x0f) as usize] as char);
    formatted.push(HEX[(value & 0x0f) as usize] as char);
}

#[cfg(feature = "host-std")]
fn append_usize_decimal(formatted: &mut String, value: usize) {
    if value == 0 {
        formatted.push('0');
        return;
    }
    let mut digits = [0u8; usize::BITS as usize];
    let mut len = 0usize;
    let mut remaining = value;
    while remaining > 0 {
        digits[len] = (remaining % 10) as u8;
        remaining /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        formatted.push((b'0' + digits[len]) as char);
    }
}

#[cfg(feature = "host-std")]
fn tls_alert_level_name(level: u8) -> &'static str {
    match level {
        1 => "warning",
        2 => "fatal",
        _ => "unknown",
    }
}

#[cfg(feature = "host-std")]
fn tls_alert_description_name(desc: u8) -> &'static str {
    match desc {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown",
    }
}

#[derive(Debug, Clone)]
pub struct SyntheticDnsMap {
    base: Ipv4Addr,
    max_entries: usize,
    ttl: Duration,
    next_offset: u32,
    by_name: HashMap<DnsName, SyntheticDnsEntry>,
    by_address: HashMap<Ipv4Addr, DnsName>,
}

#[derive(Debug, Clone)]
struct SyntheticDnsEntry {
    address: Ipv4Addr,
    resolved_at: Instant,
}

impl SyntheticDnsMap {
    pub fn new(
        base: Ipv4Addr,
        max_entries: usize,
        ttl: Duration,
    ) -> Result<Self, HostAuthorityError> {
        HostAuthorityConfig::builder()
            .synthetic_dns_base(base)
            .max_synthetic_dns_entries(max_entries)
            .build()?;
        Ok(Self {
            base,
            max_entries,
            ttl,
            next_offset: 0,
            by_name: HashMap::new(),
            by_address: HashMap::new(),
        })
    }

    pub fn address_for_name(&mut self, name: &DnsName) -> Result<Ipv4Addr, HostAuthorityError> {
        let now = Instant::now();
        self.prune_expired(now);
        if let Some(entry) = self.by_name.get_mut(name) {
            entry.resolved_at = now;
            return Ok(entry.address);
        }
        if self.by_name.len() >= self.max_entries {
            return Err(HostAuthorityError::SyntheticDnsPoolExhausted {
                max_entries: self.max_entries,
            });
        }
        let address = self.allocate_address()?;
        self.by_name.insert(
            name.clone(),
            SyntheticDnsEntry {
                address,
                resolved_at: now,
            },
        );
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

    fn prune_expired(&mut self, now: Instant) {
        let mut expired_addresses = Vec::with_capacity(self.by_name.len());
        self.by_name.retain(|_, entry| {
            let expired = now.saturating_duration_since(entry.resolved_at) >= self.ttl;
            if expired {
                expired_addresses.push(entry.address);
            }
            !expired
        });
        for address in expired_addresses {
            self.by_address.remove(&address);
        }
    }

    fn allocate_address(&mut self) -> Result<Ipv4Addr, HostAuthorityError> {
        let max_entries: u32 = self.max_entries.try_into().map_err(|_| {
            HostAuthorityError::InvalidConfig(
                "synthetic DNS map length must fit in the IPv4 address space",
            )
        })?;
        for _ in 0..max_entries {
            let offset = self.next_offset;
            self.next_offset = (self.next_offset + 1) % max_entries;
            let address = add_ipv4_offset(self.base, offset).ok_or({
                HostAuthorityError::SyntheticDnsPoolExhausted {
                    max_entries: self.max_entries,
                }
            })?;
            if !self.by_address.contains_key(&address) {
                return Ok(address);
            }
        }
        Err(HostAuthorityError::SyntheticDnsPoolExhausted {
            max_entries: self.max_entries,
        })
    }
}

#[derive(Debug)]
pub struct HostAuthority<P, A, T> {
    config: HostAuthorityConfig,
    dns: SyntheticDnsMap,
    policy: P,
    audit: A,
    tcp: T,
    guest_request_rate_limiter: FixedWindowRateLimiter,
    open_tcp_flows: HashMap<FlowId, OpenTcpFlowState>,
    #[cfg(feature = "host-std")]
    open_udp_flows: HashMap<FlowId, StdUdpFlowState>,
    #[cfg(feature = "host-std")]
    udp_flow_order: VecDeque<FlowId>,
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
            Duration::from_secs(u64::from(config.dns_ttl_seconds())),
        )?;
        let guest_request_rate_limiter = FixedWindowRateLimiter::new(
            config.max_guest_requests_per_window(),
            config.guest_request_rate_window(),
        );
        Ok(Self {
            config,
            dns,
            policy,
            audit,
            tcp,
            guest_request_rate_limiter,
            open_tcp_flows: HashMap::new(),
            #[cfg(feature = "host-std")]
            open_udp_flows: HashMap::new(),
            #[cfg(feature = "host-std")]
            udp_flow_order: VecDeque::new(),
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

    pub fn open_flow_count(&self) -> usize {
        self.open_tcp_flows.len() + {
            #[cfg(feature = "host-std")]
            {
                self.open_udp_flows.len()
            }
            #[cfg(not(feature = "host-std"))]
            {
                0
            }
        }
    }

    pub fn audit_mut(&mut self) -> &mut A {
        &mut self.audit
    }

    pub fn tcp_connector_mut(&mut self) -> &mut T {
        &mut self.tcp
    }

    fn prune_idle_tcp_flows(&mut self) -> Result<(), HostAuthorityError> {
        if self.open_tcp_flows.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        let idle_timeout = self.config.tcp_idle_timeout();
        while let Some(flow_id) = self.open_tcp_flows.iter().find_map(|(flow_id, state)| {
            (now.saturating_duration_since(state.last_activity) >= idle_timeout).then_some(*flow_id)
        }) {
            let _ = self.close_tcp_flow(flow_id, CloseReason::HostClosed, None)?;
        }
        Ok(())
    }

    fn emit_idle_tcp_flow_closures(
        &mut self,
        max_messages: usize,
        messages: &mut Vec<NetMessage>,
    ) -> Result<(), HostAuthorityError> {
        if max_messages == 0 || self.open_tcp_flows.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        let idle_timeout = self.config.tcp_idle_timeout();
        for _ in 0..max_messages {
            let Some(flow_id) = self.open_tcp_flows.iter().find_map(|(flow_id, state)| {
                (now.saturating_duration_since(state.last_activity) >= idle_timeout)
                    .then_some(*flow_id)
            }) else {
                break;
            };
            if let Some(message) = self.close_tcp_flow(
                flow_id,
                CloseReason::HostClosed,
                Some(CloseReason::HostClosed),
            )? {
                messages.push(message);
            }
        }
        Ok(())
    }

    fn record_closed_tcp_flow_after_removal(
        &mut self,
        flow_id: FlowId,
        audit_reason: CloseReason,
    ) -> Result<(), HostAuthorityError> {
        let _ = self.tcp.close(flow_id, audit_reason);
        let error_detail = self.tcp.take_error_detail(flow_id);
        self.record(HostAuditEvent::FlowClosed {
            flow_id: flow_id.get(),
            reason: audit_reason,
            error_detail,
        })?;
        Ok(())
    }

    fn close_tcp_flow(
        &mut self,
        flow_id: FlowId,
        audit_reason: CloseReason,
        message_reason: Option<CloseReason>,
    ) -> Result<Option<NetMessage>, HostAuthorityError> {
        if self.open_tcp_flows.remove(&flow_id).is_none() {
            return Ok(None);
        }
        self.record_closed_tcp_flow_after_removal(flow_id, audit_reason)?;
        Ok(message_reason.map(|reason| closed_tcp_message(flow_id, reason)))
    }

    #[cfg(feature = "host-std")]
    fn remove_udp_flow(&mut self, flow_id: FlowId) -> Option<StdUdpFlowState> {
        let state = self.open_udp_flows.remove(&flow_id)?;
        drop_flow_order_refs(&mut self.udp_flow_order, flow_id);
        Some(state)
    }

    #[cfg(feature = "host-std")]
    fn record_udp_failure(
        &mut self,
        flow_id: FlowId,
        target: &Target,
        upstream_ip: Option<IpAddr>,
        bytes: usize,
        error: TransportError,
        error_detail: Option<String>,
    ) -> Result<(), HostAuthorityError> {
        self.record_udp_failure_details(
            flow_id,
            UdpFailureAudit::from_target(target, upstream_ip, bytes, error, error_detail),
        )
    }

    #[cfg(feature = "host-std")]
    fn record_udp_failure_details(
        &mut self,
        flow_id: FlowId,
        audit: UdpFailureAudit,
    ) -> Result<(), HostAuthorityError> {
        self.record(HostAuditEvent::UdpFailed {
            flow_id: flow_id.get(),
            host: audit.host,
            port: audit.port,
            upstream_ip: audit.upstream_ip,
            bytes: audit.bytes,
            error: audit.error,
            error_detail: audit.error_detail,
        })
    }

    #[cfg(feature = "host-std")]
    fn prune_idle_udp_flows(&mut self) -> Result<(), HostAuthorityError> {
        if self.open_udp_flows.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        let idle_timeout = self.config.udp_idle_timeout();
        while let Some(flow_id) = self.open_udp_flows.iter().find_map(|(flow_id, state)| {
            (now.saturating_duration_since(state.last_activity) >= idle_timeout).then_some(*flow_id)
        }) {
            let Some(state) = self.remove_udp_flow(flow_id) else {
                continue;
            };
            self.record_udp_failure(
                flow_id,
                &state.target,
                state.route.upstream_ip(),
                0,
                TransportError::TimedOut,
                Some("UDP flow idle timeout expired".to_string()),
            )?;
        }
        Ok(())
    }

    pub fn handle_message(
        &mut self,
        message: NetMessage,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        message.validate()?;
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

    pub fn drain_messages(
        &mut self,
        max_messages: usize,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        if max_messages == 0 {
            return Ok(Vec::new());
        }
        let mut messages = Vec::with_capacity(max_messages);
        self.emit_idle_tcp_flow_closures(max_messages, &mut messages)?;
        if messages.len() >= max_messages {
            return Ok(messages);
        }
        let events = self
            .tcp
            .drain_events(max_messages - messages.len())
            .map_err(|_| HostAuthorityError::UnsupportedGuestMessage("connector drain failure"))?;
        for event in events {
            match event {
                HostTcpEvent::Data(chunk) => {
                    if chunk.direction != FlowDirection::HostToGuest {
                        messages.push(
                            self.force_close_flow(chunk.flow_id, CloseReason::ProtocolError)?,
                        );
                        continue;
                    }
                    if !self.open_tcp_flows.contains_key(&chunk.flow_id) {
                        continue;
                    }
                    if let Some(state) = self.open_tcp_flows.get_mut(&chunk.flow_id) {
                        state.last_activity = Instant::now();
                    }
                    let activity_detail = self.tcp.take_activity_detail(chunk.flow_id);
                    self.record(HostAuditEvent::TcpBytesReturned {
                        flow_id: chunk.flow_id.get(),
                        sequence: chunk.sequence,
                        bytes: chunk.bytes.len(),
                        end_stream: chunk.end_stream,
                        detail: merge_detail(tcp_return_detail(&chunk.bytes), activity_detail),
                    })?;
                    messages.push(NetMessage::TcpData(chunk));
                }
                HostTcpEvent::Close(close) => {
                    if self.open_tcp_flows.contains_key(&close.flow_id)
                        && let Some(message) =
                            self.close_tcp_flow(close.flow_id, close.reason, Some(close.reason))?
                    {
                        messages.push(message);
                    }
                }
            }
        }
        #[cfg(feature = "host-std")]
        if messages.len() < max_messages {
            self.drain_udp_messages(max_messages - messages.len(), &mut messages)?;
        }
        Ok(messages)
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
        if let Some(denial) = self.take_guest_request_rate_limit_denial() {
            return self.denied_dns_query(query, denial);
        }
        match self.policy.decide_dns(&query) {
            HostAdmission::Denied(denial) => self.denied_dns_query(query, denial),
            HostAdmission::Allowed(_) => {
                let response = self.allowed_dns_response(query)?;
                Ok(vec![NetMessage::DnsResponse(response)])
            }
        }
    }

    fn allowed_dns_response(&mut self, query: DnsQuery) -> Result<DnsResponse, HostAuthorityError> {
        let DnsQuery {
            query_id,
            name,
            record_type,
        } = query;
        let answered_name = name.as_str().to_owned();
        self.record(HostAuditEvent::DnsAllowed {
            query_id: query_id.get(),
            name: answered_name.clone(),
            record_type,
        })?;
        if record_type != DnsRecordType::A {
            return Ok(DnsResponse {
                query_id,
                code: DnsResponseCode::Ok,
                answers: Vec::new(),
                denial: None,
            });
        }
        let address = self.dns.address_for_name(&name)?;
        self.record(HostAuditEvent::DnsAnswered {
            query_id: query_id.get(),
            name: answered_name,
            address,
            ttl_seconds: self.config.dns_ttl_seconds(),
        })?;
        Ok(DnsResponse {
            query_id,
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name,
                record_type: DnsRecordType::A,
                data: DnsRecordData::Ip(IpAddr::V4(address)),
                ttl_seconds: self.config.dns_ttl_seconds(),
            }],
            denial: None,
        })
    }

    fn handle_open_tcp(&mut self, open: OpenTcp) -> Result<Vec<NetMessage>, HostAuthorityError> {
        open.validate()?;
        let flow_id = open.flow_id;
        if let Some(denial) = self.take_guest_request_rate_limit_denial() {
            let (host, port) = open.target.into_host_and_port();
            return self.denied_tcp_open(flow_id, host, port, denial);
        }
        match self.policy.decide_tcp_open(&open) {
            HostAdmission::Denied(denial) => {
                let (host, port) = open.target.into_host_and_port();
                self.denied_tcp_open(flow_id, host, port, denial)
            }
            HostAdmission::Allowed(route) => {
                self.prune_idle_tcp_flows()?;
                #[cfg(feature = "host-std")]
                self.prune_idle_udp_flows()?;
                let connect_spec = TcpConnectSpec::from_owned_open(open, route);
                if let Some(denial) = self.validate_tcp_connect_spec(&connect_spec) {
                    let (host, port) = connect_spec.target().host_and_port();
                    let host = host.to_owned();
                    return self.denied_tcp_open(flow_id, host, port, denial);
                }
                if !self.open_tcp_flows.contains_key(&flow_id)
                    && self.open_flow_count() >= self.config.max_open_flows()
                {
                    let denial = open_flow_limit_denial();
                    let (host, port) = connect_spec.target().host_and_port();
                    let host = host.to_owned();
                    return self.denied_tcp_open(flow_id, host, port, denial);
                }
                let (host, port) = {
                    let (host, port) = connect_spec.target().host_and_port();
                    (host.to_owned(), port)
                };
                self.record(HostAuditEvent::TcpOpenAllowed {
                    flow_id: flow_id.get(),
                    host,
                    port,
                    upstream_ip: route.upstream_ip(),
                })?;
                match self.tcp.open(&connect_spec) {
                    Ok(()) => {
                        self.open_tcp_flows.insert(
                            flow_id,
                            OpenTcpFlowState {
                                last_activity: Instant::now(),
                            },
                        );
                        Ok(vec![NetMessage::TcpOpenResult(TcpOpenResult::opened(
                            flow_id,
                        ))])
                    }
                    Err(error) => {
                        let error_detail = self.tcp.take_error_detail(flow_id);
                        let failure_host = connect_spec.target().host().to_owned();
                        self.record(HostAuditEvent::TcpOpenFailed {
                            flow_id: flow_id.get(),
                            host: failure_host,
                            port,
                            upstream_ip: route.upstream_ip(),
                            error,
                            error_detail,
                        })?;
                        Ok(vec![NetMessage::TcpOpenResult(TcpOpenResult::failed(
                            flow_id, error,
                        ))])
                    }
                }
            }
        }
    }

    fn validate_tcp_connect_spec(&self, spec: &TcpConnectSpec) -> Option<Denial> {
        match (spec.tls_policy(), spec.tls_transform()) {
            (TlsPolicy::BypassForOpaqueTcp, Some(_)) => Some(
                Denial::new(DenialReason::TransformRequired)
                    .with_safe_detail("opaque TCP bypass cannot carry a TLS transform route"),
            ),
            (TlsPolicy::RequiredForTransform, None) => Some(
                Denial::new(DenialReason::TransformRequired)
                    .with_safe_detail("TLS transform route missing for required transform flow"),
            ),
            (_, Some(route)) if !route.alpn_protocols.is_empty() => Some(
                Denial::new(DenialReason::ProtocolNotAllowed).with_safe_detail(
                    "ALPN negotiation is not supported for transformed TLS flows",
                ),
            ),
            (_, Some(_)) | (TlsPolicy::RequiredForTransform, Some(_))
                if !self.tcp.supports_tls_transform() =>
            {
                Some(
                    Denial::new(DenialReason::TlsRequired)
                        .with_safe_detail("host TCP connector cannot terminate TLS for this flow"),
                )
            }
            (_, Some(route))
                if !route.transform_chain.is_empty() && !self.tcp.supports_stream_transforms() =>
            {
                Some(Denial::new(DenialReason::PluginDenied).with_safe_detail(
                    "host TCP connector cannot execute TLS transform plugins for this flow",
                ))
            }
            (_, Some(route)) if !route.transform_chain.is_empty() => self
                .tcp
                .validate_stream_transforms(
                    &route.transform_chain,
                    Some(route.server_name.as_str()),
                )
                .err()
                .map(|err| Denial::new(DenialReason::PluginDenied).with_safe_detail(err)),
            _ => None,
        }
    }

    fn handle_tcp_data(
        &mut self,
        chunk: StreamChunk,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        if chunk.direction != FlowDirection::GuestToHost {
            return Ok(protocol_error_tcp_close(chunk.flow_id));
        }
        if !self.open_tcp_flows.contains_key(&chunk.flow_id) {
            return Ok(protocol_error_tcp_close(chunk.flow_id));
        }
        let now = Instant::now();
        let current_flow_idle = self
            .open_tcp_flows
            .get(&chunk.flow_id)
            .is_some_and(|state| {
                now.saturating_duration_since(state.last_activity) >= self.config.tcp_idle_timeout()
            });
        if current_flow_idle {
            return self
                .close_tcp_flow(
                    chunk.flow_id,
                    CloseReason::HostClosed,
                    Some(CloseReason::HostClosed),
                )
                .map(option_message_vec);
        }
        match self.tcp.send(&chunk) {
            Ok(()) => {
                if let Some(state) = self.open_tcp_flows.get_mut(&chunk.flow_id) {
                    state.last_activity = Instant::now();
                }
                let detail = self.tcp.take_activity_detail(chunk.flow_id);
                self.record(HostAuditEvent::TcpBytesForwarded {
                    flow_id: chunk.flow_id.get(),
                    sequence: chunk.sequence,
                    bytes: chunk.bytes.len(),
                    end_stream: chunk.end_stream,
                    detail,
                })?;
                Ok(Vec::new())
            }
            Err(error) => {
                let error_detail = self.tcp.take_error_detail(chunk.flow_id);
                let reason = match error {
                    TransportError::TlsHandshakeFailed | TransportError::TransformError => {
                        CloseReason::TransformError
                    }
                    _ => CloseReason::HostClosed,
                };
                self.record(HostAuditEvent::TcpForwardFailed {
                    flow_id: chunk.flow_id.get(),
                    bytes: chunk.bytes.len(),
                    end_stream: chunk.end_stream,
                    error,
                    error_detail,
                })?;
                self.close_tcp_flow(chunk.flow_id, reason, Some(reason))
                    .map(option_message_vec)
            }
        }
    }

    fn handle_close_flow(
        &mut self,
        close: CloseFlow,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        let _ = self.close_tcp_flow(close.flow_id, close.reason, None)?;
        Ok(Vec::new())
    }

    fn handle_udp_datagram(
        &mut self,
        datagram: UdpDatagram,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        if datagram.direction != FlowDirection::GuestToHost {
            return Ok(protocol_error_udp_delivery(datagram.flow_id));
        }
        if let Some(denial) = self.take_guest_request_rate_limit_denial() {
            let (host, port) = datagram.target.into_host_and_port();
            return self.denied_udp_datagram(datagram.flow_id, host, port, denial);
        }
        match self.policy.decide_udp_datagram(&datagram) {
            HostAdmission::Denied(denial) => {
                let (host, port) = datagram.target.into_host_and_port();
                self.denied_udp_datagram(datagram.flow_id, host, port, denial)
            }
            #[cfg(feature = "host-std")]
            HostAdmission::Allowed(route) => {
                self.prune_idle_tcp_flows()?;
                self.prune_idle_udp_flows()?;
                if !self.open_udp_flows.contains_key(&datagram.flow_id)
                    && self.open_flow_count() >= self.config.max_open_flows()
                {
                    let denial = open_flow_limit_denial();
                    let (host, port) = datagram.target.host_and_port();
                    let host = host.to_owned();
                    return self.denied_udp_datagram(datagram.flow_id, host, port, denial);
                }
                let bytes = datagram.bytes.len();
                match self.forward_udp_datagram(&datagram, route) {
                    Ok(()) => {
                        let (host, port) = datagram.target.host_and_port();
                        let host = host.to_owned();
                        self.record(HostAuditEvent::UdpForwarded {
                            flow_id: datagram.flow_id.get(),
                            host,
                            port,
                            upstream_ip: route.upstream_ip(),
                            bytes,
                        })?;
                        Ok(Vec::new())
                    }
                    Err((error, error_detail)) => {
                        self.record_udp_failure(
                            datagram.flow_id,
                            &datagram.target,
                            route.upstream_ip(),
                            bytes,
                            error,
                            Some(error_detail),
                        )?;
                        let _ = self.remove_udp_flow(datagram.flow_id);
                        Ok(vec![failed_udp_delivery(datagram.flow_id, error)])
                    }
                }
            }
            #[cfg(not(feature = "host-std"))]
            HostAdmission::Allowed(_) => {
                let (host, port) = datagram.target.into_host_and_port();
                self.record(HostAuditEvent::UdpUnsupported {
                    flow_id: datagram.flow_id.get(),
                    host,
                    port,
                })?;
                Ok(protocol_error_udp_delivery(datagram.flow_id))
            }
        }
    }

    #[cfg(feature = "host-std")]
    fn forward_udp_datagram(
        &mut self,
        datagram: &UdpDatagram,
        route: HostRoute,
    ) -> Result<(), (TransportError, String)> {
        if let std::collections::hash_map::Entry::Vacant(entry) =
            self.open_udp_flows.entry(datagram.flow_id)
        {
            let socket = bind_udp_target(&datagram.target, route, self.config.udp_read_timeout())
                .map_err(|err| {
                let detail = err.to_string();
                (map_tcp_io_error(err), detail)
            })?;
            entry.insert(StdUdpFlowState {
                socket,
                target: datagram.target.clone(),
                route,
                last_activity: Instant::now(),
                read_buffer: vec![0u8; STD_UDP_READ_BUFFER_BYTES],
            });
            self.udp_flow_order.push_back(datagram.flow_id);
        }
        let state = self
            .open_udp_flows
            .get_mut(&datagram.flow_id)
            .expect("UDP flow state must exist after insertion");
        if state.target != datagram.target {
            return Err((
                TransportError::ProtocolError,
                "UDP flow id was reused with a different target".to_string(),
            ));
        }
        if state.route != route {
            return Err((
                TransportError::ProtocolError,
                "UDP flow id was reused with a different admitted route".to_string(),
            ));
        }
        state
            .socket
            .send(datagram.bytes.as_slice())
            .map_err(|err| {
                let detail = err.to_string();
                (map_tcp_io_error(err), detail)
            })?;
        state.last_activity = Instant::now();
        Ok(())
    }

    #[cfg(feature = "host-std")]
    fn drain_udp_messages(
        &mut self,
        max_messages: usize,
        messages: &mut Vec<NetMessage>,
    ) -> Result<(), HostAuthorityError> {
        self.prune_idle_udp_flows()?;
        if max_messages == 0 {
            return Ok(());
        }
        if self.open_udp_flows.is_empty() {
            self.udp_flow_order.clear();
            return Ok(());
        }
        let mut failed_flows = Vec::with_capacity(self.udp_flow_order.len());
        let mut scanned = 0usize;
        let max_scan = self.udp_flow_order.len();
        while scanned < max_scan && messages.len() < max_messages {
            let Some(flow_id) = self.udp_flow_order.pop_front() else {
                break;
            };
            scanned += 1;
            let Some(state) = self.open_udp_flows.get_mut(&flow_id) else {
                continue;
            };
            let route = state.route;
            match state.socket.recv(state.read_buffer.as_mut_slice()) {
                Ok(bytes) => {
                    let buffer = state.read_buffer[..bytes].to_vec();
                    state.last_activity = Instant::now();
                    let (host, port) = state.target.host_and_port();
                    let host = host.to_owned();
                    let message = NetMessage::UdpDatagram(UdpDatagram {
                        flow_id,
                        target: state.target.clone(),
                        direction: FlowDirection::HostToGuest,
                        bytes: buffer,
                    });
                    let _ = state;
                    self.record(HostAuditEvent::UdpReturned {
                        flow_id: flow_id.get(),
                        host,
                        port,
                        upstream_ip: route.upstream_ip(),
                        bytes,
                    })?;
                    messages.push(message);
                    self.udp_flow_order.push_back(flow_id);
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    self.udp_flow_order.push_back(flow_id);
                }
                Err(err) => {
                    let error_detail = err.to_string();
                    let error = map_tcp_io_error(err);
                    let (host, port) = state.target.host_and_port();
                    let host = host.to_owned();
                    let _ = state;
                    self.record_udp_failure_details(
                        flow_id,
                        UdpFailureAudit::from_host_port(
                            host,
                            port,
                            route.upstream_ip(),
                            0,
                            error,
                            Some(error_detail),
                        ),
                    )?;
                    messages.push(failed_udp_delivery(flow_id, error));
                    failed_flows.push(flow_id);
                }
            }
        }
        for flow_id in failed_flows {
            let _ = self.remove_udp_flow(flow_id);
        }
        Ok(())
    }

    fn handle_icmp_echo(
        &mut self,
        request: IcmpEchoRequest,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        if let Some(denial) = self.take_guest_request_rate_limit_denial() {
            let host = request.host.into_string();
            return self.denied_icmp_echo(request.query_id, host, denial);
        }
        match self.policy.decide_icmp_echo(&request) {
            HostAdmission::Denied(denial) => {
                let host = request.host.into_string();
                self.denied_icmp_echo(request.query_id, host, denial)
            }
            #[cfg(feature = "host-std")]
            HostAdmission::Allowed(route) => {
                let IcmpEchoExecution {
                    status,
                    round_trip_micros,
                    error_detail,
                } = execute_icmp_echo(route, &request);
                let query_id = request.query_id;
                let host = request.host.into_string();
                match status {
                    IcmpEchoStatus::Replied => {
                        self.record(HostAuditEvent::IcmpReplied {
                            query_id: query_id.get(),
                            host,
                            upstream_ip: route.upstream_ip(),
                            round_trip_micros,
                        })?;
                    }
                    status => {
                        self.record(HostAuditEvent::IcmpFailed {
                            query_id: query_id.get(),
                            host,
                            upstream_ip: route.upstream_ip(),
                            status,
                            error_detail,
                        })?;
                    }
                }
                Ok(vec![icmp_echo_response(
                    query_id,
                    status,
                    round_trip_micros,
                    None,
                )])
            }
            #[cfg(not(feature = "host-std"))]
            HostAdmission::Allowed(_route) => {
                let query_id = request.query_id;
                let host = request.host.into_string();
                self.record(HostAuditEvent::IcmpUnsupported {
                    query_id: query_id.get(),
                    host,
                })?;
                Ok(vec![unsupported_icmp_response(query_id)])
            }
        }
    }

    fn record(&mut self, event: HostAuditEvent) -> Result<(), HostAuthorityError> {
        self.audit
            .record(clamp_host_audit_event_details(event))
            .map_err(|err| HostAuthorityError::Audit(err.to_string()))
    }

    fn denied_tcp_open(
        &mut self,
        flow_id: FlowId,
        host: String,
        port: u16,
        denial: Denial,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        self.record(HostAuditEvent::TcpOpenDenied {
            flow_id: flow_id.get(),
            host,
            port,
            denial: denial.clone(),
        })?;
        Ok(vec![NetMessage::TcpOpenResult(TcpOpenResult::denied(
            flow_id, denial,
        ))])
    }

    fn denied_dns_query(
        &mut self,
        query: DnsQuery,
        denial: Denial,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        let DnsQuery {
            query_id,
            name,
            record_type,
        } = query;
        self.record(HostAuditEvent::DnsDenied {
            query_id: query_id.get(),
            name: name.into_string(),
            record_type,
            denial: denial.clone(),
        })?;
        Ok(vec![NetMessage::DnsResponse(DnsResponse {
            query_id,
            code: DnsResponseCode::Refused,
            answers: Vec::new(),
            denial: Some(denial),
        })])
    }

    fn denied_udp_datagram(
        &mut self,
        flow_id: FlowId,
        host: String,
        port: u16,
        denial: Denial,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        self.record(HostAuditEvent::UdpDenied {
            flow_id: flow_id.get(),
            host,
            port,
            denial: denial.clone(),
        })?;
        Ok(vec![NetMessage::UdpDelivery(UdpDelivery {
            flow_id,
            status: DatagramStatus::Denied(denial),
        })])
    }

    fn denied_icmp_echo(
        &mut self,
        query_id: QueryId,
        host: String,
        denial: Denial,
    ) -> Result<Vec<NetMessage>, HostAuthorityError> {
        self.record(HostAuditEvent::IcmpDenied {
            query_id: query_id.get(),
            host,
            denial: denial.clone(),
        })?;
        Ok(vec![icmp_echo_response(
            query_id,
            IcmpEchoStatus::Denied,
            None,
            Some(denial),
        )])
    }

    fn force_close_flow(
        &mut self,
        flow_id: FlowId,
        reason: CloseReason,
    ) -> Result<NetMessage, HostAuthorityError> {
        self.open_tcp_flows.remove(&flow_id);
        let _ = self.tcp.close(flow_id, reason);
        let error_detail = self.tcp.take_error_detail(flow_id);
        self.record(HostAuditEvent::FlowClosed {
            flow_id: flow_id.get(),
            reason,
            error_detail,
        })?;
        Ok(closed_tcp_message(flow_id, reason))
    }

    fn take_guest_request_rate_limit_denial(&mut self) -> Option<Denial> {
        if self.guest_request_rate_limiter.try_acquire() {
            None
        } else {
            Some(guest_request_rate_limit_denial())
        }
    }
}

#[cfg(feature = "host-std")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct IcmpEchoExecution {
    status: IcmpEchoStatus,
    round_trip_micros: Option<u64>,
    error_detail: Option<String>,
}

#[cfg(feature = "host-std")]
fn execute_icmp_echo(route: HostRoute, request: &IcmpEchoRequest) -> IcmpEchoExecution {
    let target = icmp_ping_target(route, request);
    let mut command = ping_command(target.as_ref(), request.payload_len);
    command
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(std::process::Stdio::null());
    let output = match command.output() {
        Ok(output) => output,
        Err(err) => {
            return IcmpEchoExecution {
                status: IcmpEchoStatus::Unreachable,
                round_trip_micros: None,
                error_detail: Some(clamp_icmp_detail_string(err.to_string())),
            };
        }
    };
    let detail = ping_output_detail(&output);
    if output.status.success() {
        return IcmpEchoExecution {
            status: IcmpEchoStatus::Replied,
            round_trip_micros: parse_ping_round_trip_micros(&detail),
            error_detail: None,
        };
    }
    let status = classify_failed_ping(&detail);
    IcmpEchoExecution {
        status,
        round_trip_micros: None,
        error_detail: normalized_ping_detail(detail),
    }
}

#[cfg(feature = "host-std")]
fn icmp_ping_target<'a>(route: HostRoute, request: &'a IcmpEchoRequest) -> Cow<'a, str> {
    route
        .upstream_ip()
        .map(|ip| Cow::Owned(ip.to_string()))
        .unwrap_or_else(|| Cow::Borrowed(request.host.as_str()))
}

#[cfg(feature = "host-std")]
fn ping_command(target: &str, payload_len: u16) -> Command {
    let ping_path = ["/sbin/ping", "/bin/ping"]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .unwrap_or("ping");
    let mut command = Command::new(ping_path);
    command
        .arg("-c")
        .arg("1")
        .arg("-s")
        .arg(payload_len.to_string());
    #[cfg(target_os = "macos")]
    {
        command
            .arg("-t")
            .arg(ICMP_ECHO_TIMEOUT.as_secs().to_string())
            .arg("-W")
            .arg(ICMP_ECHO_TIMEOUT.as_millis().to_string());
    }
    #[cfg(not(target_os = "macos"))]
    {
        command
            .arg("-w")
            .arg(ICMP_ECHO_TIMEOUT.as_secs().to_string())
            .arg("-W")
            .arg(ICMP_ECHO_TIMEOUT.as_secs().to_string());
    }
    command.arg(target);
    command
}

#[cfg(feature = "host-std")]
fn ping_output_detail(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut detail = String::with_capacity(stdout.len() + stderr.len());
    detail.push_str(stdout.as_ref());
    detail.push_str(stderr.as_ref());
    detail
}

#[cfg(feature = "host-std")]
fn normalized_ping_detail(mut detail: String) -> Option<String> {
    let trimmed = detail.trim();
    if trimmed.is_empty() {
        None
    } else {
        let trimmed_len = trimmed.len();
        let start = detail.len() - detail.trim_start().len();
        if start > 0 {
            detail.replace_range(..start, "");
        }
        detail.truncate(trimmed_len);
        Some(clamp_icmp_detail_string(detail))
    }
}

#[cfg(feature = "host-std")]
fn clamp_icmp_detail_string(mut detail: String) -> String {
    if detail.len() <= MAX_ICMP_ERROR_DETAIL_BYTES {
        return detail;
    }
    let mut end = MAX_ICMP_ERROR_DETAIL_BYTES;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    detail
}

#[cfg(feature = "host-std")]
fn classify_failed_ping(detail: &str) -> IcmpEchoStatus {
    if contains_ascii_case_insensitive(detail, "request timeout")
        || contains_ascii_case_insensitive(detail, "100.0% packet loss")
        || contains_ascii_case_insensitive(detail, "100% packet loss")
        || contains_ascii_case_insensitive(detail, "timed out")
    {
        return IcmpEchoStatus::TimedOut;
    }
    IcmpEchoStatus::Unreachable
}

#[cfg(feature = "host-std")]
fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(feature = "host-std")]
fn parse_ping_round_trip_micros(detail: &str) -> Option<u64> {
    for token in detail.split_whitespace() {
        if let Some(value) = token.strip_prefix("time=") {
            return parse_ping_time_micros(value);
        }
    }
    for line in detail.lines() {
        if let Some((_, times)) = line.split_once(" = ") {
            if line.contains("round-trip") || line.contains("rtt ") {
                let avg = times.split('/').nth(1).unwrap_or(times);
                return parse_ping_time_micros(avg.trim_end_matches(" ms"));
            }
        }
    }
    None
}

#[cfg(feature = "host-std")]
fn parse_ping_time_micros(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let raw = raw.strip_suffix("ms").unwrap_or(raw).trim_end();
    let (whole_millis, fractional_millis) = match raw.split_once('.') {
        Some((whole, fractional)) => (whole, fractional),
        None => (raw, ""),
    };
    let whole_millis = whole_millis.parse::<u64>().ok()?;
    let mut micros = whole_millis.checked_mul(1000)?;
    let mut fractional_digits = fractional_millis.bytes();
    for scale in [100_u64, 10, 1] {
        let Some(digit) = fractional_digits.next() else {
            return Some(micros);
        };
        if !digit.is_ascii_digit() {
            return None;
        }
        micros = micros.checked_add(u64::from(digit - b'0') * scale)?;
    }
    if let Some(rounding_digit) = fractional_digits.next() {
        if !rounding_digit.is_ascii_digit() {
            return None;
        }
        if rounding_digit >= b'5' {
            micros = micros.checked_add(1)?;
        }
    }
    if fractional_digits.all(|digit| digit.is_ascii_digit()) {
        Some(micros)
    } else {
        None
    }
}

#[cfg(feature = "host-std")]
fn tcp_return_detail(bytes: &[u8]) -> Option<String> {
    summarize_tls_records(bytes)
}

#[cfg(not(feature = "host-std"))]
fn tcp_return_detail(_bytes: &[u8]) -> Option<String> {
    None
}

fn merge_detail(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(mut left), Some(right)) if !right.is_empty() => {
            let additional_len = 2 + right.len();
            left.reserve(additional_len);
            left.push_str("; ");
            left.push_str(&right);
            Some(left)
        }
        (Some(left), _) => Some(left),
        (_, Some(right)) if !right.is_empty() => Some(right),
        _ => None,
    }
}

#[cfg(feature = "host-std")]
fn drop_flow_order_refs(order: &mut VecDeque<FlowId>, flow_id: FlowId) {
    order.retain(|entry| *entry != flow_id);
}

fn option_message_vec(message: Option<NetMessage>) -> Vec<NetMessage> {
    match message {
        Some(message) => vec![message],
        None => Vec::new(),
    }
}

fn closed_tcp_message(flow_id: FlowId, reason: CloseReason) -> NetMessage {
    NetMessage::CloseFlow(CloseFlow { flow_id, reason })
}

#[cfg(feature = "host-std")]
fn host_closed_tcp_event(flow_id: FlowId) -> HostTcpEvent {
    HostTcpEvent::Close(CloseFlow {
        flow_id,
        reason: CloseReason::HostClosed,
    })
}

#[cfg(feature = "host-std")]
fn host_guest_ack_event(flow_id: FlowId, sequence: u64) -> HostTcpEvent {
    HostTcpEvent::Data(StreamChunk::new(
        flow_id,
        FlowDirection::HostToGuest,
        sequence,
        Vec::new(),
    ))
}

fn protocol_error_tcp_close(flow_id: FlowId) -> Vec<NetMessage> {
    vec![closed_tcp_message(flow_id, CloseReason::ProtocolError)]
}

fn failed_udp_delivery(flow_id: FlowId, error: TransportError) -> NetMessage {
    NetMessage::UdpDelivery(UdpDelivery {
        flow_id,
        status: DatagramStatus::Failed(error),
    })
}

fn protocol_error_udp_delivery(flow_id: FlowId) -> Vec<NetMessage> {
    vec![failed_udp_delivery(flow_id, TransportError::ProtocolError)]
}

fn icmp_echo_response(
    query_id: QueryId,
    status: IcmpEchoStatus,
    round_trip_micros: Option<u64>,
    denial: Option<Denial>,
) -> NetMessage {
    NetMessage::IcmpEchoResponse(IcmpEchoResponse {
        query_id,
        status,
        round_trip_micros,
        denial,
    })
}

#[cfg(not(feature = "host-std"))]
fn unsupported_icmp_response(query_id: QueryId) -> NetMessage {
    icmp_echo_response(query_id, IcmpEchoStatus::Unreachable, None, None)
}

fn clamp_host_audit_event_details(event: HostAuditEvent) -> HostAuditEvent {
    match event {
        HostAuditEvent::TcpOpenFailed {
            flow_id,
            host,
            port,
            upstream_ip,
            error,
            error_detail,
        } => HostAuditEvent::TcpOpenFailed {
            flow_id,
            host,
            port,
            upstream_ip,
            error,
            error_detail: clamp_host_audit_detail_option(error_detail),
        },
        HostAuditEvent::TcpBytesForwarded {
            flow_id,
            sequence,
            bytes,
            end_stream,
            detail,
        } => HostAuditEvent::TcpBytesForwarded {
            flow_id,
            sequence,
            bytes,
            end_stream,
            detail: clamp_host_audit_detail_option(detail),
        },
        HostAuditEvent::TcpForwardFailed {
            flow_id,
            bytes,
            end_stream,
            error,
            error_detail,
        } => HostAuditEvent::TcpForwardFailed {
            flow_id,
            bytes,
            end_stream,
            error,
            error_detail: clamp_host_audit_detail_option(error_detail),
        },
        HostAuditEvent::TcpBytesReturned {
            flow_id,
            sequence,
            bytes,
            end_stream,
            detail,
        } => HostAuditEvent::TcpBytesReturned {
            flow_id,
            sequence,
            bytes,
            end_stream,
            detail: clamp_host_audit_detail_option(detail),
        },
        HostAuditEvent::FlowClosed {
            flow_id,
            reason,
            error_detail,
        } => HostAuditEvent::FlowClosed {
            flow_id,
            reason,
            error_detail: clamp_host_audit_detail_option(error_detail),
        },
        HostAuditEvent::UdpFailed {
            flow_id,
            host,
            port,
            upstream_ip,
            bytes,
            error,
            error_detail,
        } => HostAuditEvent::UdpFailed {
            flow_id,
            host,
            port,
            upstream_ip,
            bytes,
            error,
            error_detail: clamp_host_audit_detail_option(error_detail),
        },
        HostAuditEvent::IcmpFailed {
            query_id,
            host,
            upstream_ip,
            status,
            error_detail,
        } => HostAuditEvent::IcmpFailed {
            query_id,
            host,
            upstream_ip,
            status,
            error_detail: clamp_host_audit_detail_option(error_detail),
        },
        other => other,
    }
}

fn clamp_host_audit_detail_option(detail: Option<String>) -> Option<String> {
    detail.map(clamp_host_audit_detail_string)
}

fn clamp_host_audit_detail_string(mut detail: String) -> String {
    if detail.len() <= MAX_HOST_AUDIT_DETAIL_BYTES {
        return detail;
    }
    let mut end = MAX_HOST_AUDIT_DETAIL_BYTES;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    detail
}

fn open_flow_limit_denial() -> Denial {
    Denial::new(DenialReason::ResourceLimit)
        .with_safe_detail("host open-flow limit reached for this microVM")
}

fn guest_request_rate_limit_denial() -> Denial {
    Denial::new(DenialReason::RateLimited)
        .with_safe_detail("per-VM guest request rate limit exceeded")
}

fn accepted_capabilities(guest: &[Capability], config: &HostAuthorityConfig) -> Vec<Capability> {
    let mut accepted = Vec::with_capacity(config.capabilities().len().min(guest.len()));
    for capability in config.capabilities().iter().copied() {
        if guest.contains(&capability) {
            accepted.push(capability);
        }
    }
    accepted
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

    fn decide_icmp_echo(&mut self, request: &IcmpEchoRequest) -> HostAdmission {
        let Some(pin) = self.pins.lookup(request.host.as_str()) else {
            return HostAdmission::denied(DenialReason::HostNotAllowed);
        };
        pin.ips
            .first()
            .copied()
            .map(|ip| HostAdmission::allowed_with_route(HostRoute::resolved_ip(ip)))
            .unwrap_or_else(|| HostAdmission::denied(DenialReason::HostNotAllowed))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
    use std::path::Path;

    use super::*;
    use crate::proto::{
        AlpnProtocol, DatagramStatus, DnsRecordType, FlowDirection, FlowId, FlowOpenStatus,
        HostName, PluginId, QueryId, TlsPolicy, TlsTermination, UdpDatagram,
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

    fn loopback_bind_supported<F, T>(bind: F, target: &str) -> Option<T>
    where
        F: FnOnce() -> std::io::Result<T>,
    {
        match bind() {
            Ok(value) => Some(value),
            Err(err)
                if err.kind() == std::io::ErrorKind::PermissionDenied
                    || err.raw_os_error() == Some(1) =>
            {
                None
            }
            Err(err) => panic!("unexpected loopback bind failure for {target}: {err}"),
        }
    }

    fn bind_loopback_udp_socket() -> Option<UdpSocket> {
        loopback_bind_supported(
            || UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)),
            "127.0.0.1:0/udp",
        )
    }

    fn bind_loopback_tcp_listener() -> Option<TcpListener> {
        loopback_bind_supported(|| TcpListener::bind(("127.0.0.1", 0)), "127.0.0.1:0/tcp")
    }

    fn icmp_echo_supported() -> bool {
        let ping_path = ["/sbin/ping", "/bin/ping"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .unwrap_or("ping");
        match Command::new(ping_path)
            .arg("-c")
            .arg("1")
            .arg("-s")
            .arg("0")
            .arg("127.0.0.1")
            .stdin(std::process::Stdio::null())
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    return true;
                }
                let detail = ping_output_detail(&output);
                !(detail.contains("Operation not permitted")
                    || detail.contains("operation not permitted"))
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::PermissionDenied
                    || err.raw_os_error() == Some(1) =>
            {
                false
            }
            Err(err) => panic!("unexpected ping probe failure: {err}"),
        }
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
        opens: Vec<TcpConnectSpec>,
        sends: Vec<(u64, Vec<u8>, bool)>,
        closes: Vec<(u64, CloseReason)>,
        drains: VecDeque<Vec<HostTcpEvent>>,
        open_result: Result<(), TransportError>,
        send_result: Result<(), TransportError>,
        stream_transform_config: crate::stream_transform::StreamTransformConfig,
        activity_detail: Option<String>,
        error_detail: Option<String>,
        close_error_detail: Option<String>,
    }

    impl Default for RecordingTcpConnector {
        fn default() -> Self {
            Self {
                opens: Vec::new(),
                sends: Vec::new(),
                closes: Vec::new(),
                drains: VecDeque::new(),
                open_result: Ok(()),
                send_result: Ok(()),
                stream_transform_config: crate::stream_transform::StreamTransformConfig::default(),
                activity_detail: None,
                error_detail: None,
                close_error_detail: None,
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

        fn with_drains(drains: impl IntoIterator<Item = Vec<HostTcpEvent>>) -> Self {
            Self {
                drains: drains.into_iter().collect(),
                ..Self::default()
            }
        }

        #[cfg(feature = "host-tls")]
        fn with_stream_transform_config(
            stream_transform_config: crate::stream_transform::StreamTransformConfig,
        ) -> Self {
            Self {
                stream_transform_config,
                ..Self::default()
            }
        }
    }

    impl HostTcpConnector for RecordingTcpConnector {
        fn open(&mut self, spec: &TcpConnectSpec) -> Result<(), TransportError> {
            self.opens.push(spec.clone());
            self.open_result
        }

        fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
            self.sends
                .push((chunk.flow_id.get(), chunk.bytes.clone(), chunk.end_stream));
            self.send_result
        }

        fn close(&mut self, flow_id: FlowId, reason: CloseReason) -> Result<(), TransportError> {
            self.closes.push((flow_id.get(), reason));
            if let Some(detail) = self.close_error_detail.take() {
                self.error_detail = Some(detail);
            }
            Ok(())
        }

        fn drain_events(
            &mut self,
            _max_events: usize,
        ) -> Result<Vec<HostTcpEvent>, TransportError> {
            Ok(self.drains.pop_front().unwrap_or_default())
        }

        fn supports_tls_transform(&self) -> bool {
            true
        }

        fn supports_stream_transforms(&self) -> bool {
            true
        }

        fn validate_stream_transforms(
            &self,
            plugin_chain: &[crate::proto::PluginId],
            target_host: Option<&str>,
        ) -> Result<(), String> {
            crate::stream_transform::StreamTransformChain::validate_plugin_ids_with_config_for_target(
                plugin_chain,
                &self.stream_transform_config,
                target_host,
            )
            .map_err(|err| err.to_string())
        }

        fn take_activity_detail(&mut self, _flow_id: FlowId) -> Option<String> {
            self.activity_detail.take()
        }

        fn take_error_detail(&mut self, _flow_id: FlowId) -> Option<String> {
            self.error_detail.take()
        }
    }

    fn authority_with_connector<C: HostTcpConnector>(
        policy: StaticPolicy,
        tcp: C,
    ) -> HostAuthority<StaticPolicy, VecAudit, C> {
        HostAuthority::new(policy, VecAudit::default(), tcp)
    }

    fn authority(
        policy: StaticPolicy,
    ) -> HostAuthority<StaticPolicy, VecAudit, RecordingTcpConnector> {
        authority_with_connector(policy, RecordingTcpConnector::default())
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
    fn handshake_rejects_overlong_guest_capability_list() {
        let mut authority = authority(StaticPolicy::allow_all());
        let err = authority
            .handle_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![
                    Capability::Dns,
                    Capability::Tcp,
                    Capability::Udp,
                    Capability::IcmpEcho,
                    Capability::TlsTransform,
                    Capability::StreamTransforms,
                    Capability::AuditCorrelation,
                    Capability::PolicyDigest,
                    Capability::Dns,
                ],
            )))
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "hello capabilities has 9 entries; maximum is 8"
        );
    }

    #[test]
    fn tcp_open_rejects_overlong_tls_transform_alpn_list() {
        let mut authority = authority(StaticPolicy::allow_all());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_alpn_protocols(
                (0..(crate::proto::MAX_TLS_TRANSFORM_ALPN_PROTOCOLS + 1))
                    .map(|index| AlpnProtocol::new(format!("proto-{index}")).unwrap())
                    .collect(),
            ),
        );

        let err = authority
            .handle_message(NetMessage::OpenTcp(open))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform ALPN protocols has 9 entries; maximum is 8"
        );
    }

    #[test]
    fn tcp_open_rejects_overlong_tls_transform_chain_before_connector_validation() {
        let mut authority = authority(StaticPolicy::allow_all());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(
                (0..(crate::proto::MAX_TLS_TRANSFORM_CHAIN_ENTRIES + 1))
                    .map(|index| PluginId::new(format!("plugin-{index}")).unwrap())
                    .collect(),
            ),
        );

        let err = authority
            .handle_message(NetMessage::OpenTcp(open))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin chain has 9 entries; maximum is 8"
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
    fn expired_synthetic_dns_entry_is_pruned_before_pool_exhaustion() {
        let config = HostAuthorityConfig::builder()
            .synthetic_dns_base(Ipv4Addr::new(198, 19, 0, 1))
            .max_synthetic_dns_entries(1)
            .dns_ttl_seconds(1)
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
        .unwrap();

        let first = authority
            .handle_message(NetMessage::DnsQuery(dns_query("one.example")))
            .unwrap();
        let first_ip = dns_response_ip(&first);
        authority
            .dns
            .by_name
            .get_mut(&DnsName::new("one.example").unwrap())
            .expect("first synthetic DNS entry should exist")
            .resolved_at = Instant::now() - Duration::from_secs(2);

        let second = authority
            .handle_message(NetMessage::DnsQuery(dns_query("two.example")))
            .unwrap();
        let second_ip = dns_response_ip(&second);

        assert_eq!(first_ip, second_ip);
        assert_eq!(authority.dns_map().len(), 1);
        assert_eq!(
            authority
                .dns_map()
                .name_for_address(second_ip)
                .map(DnsName::as_str),
            Some("two.example")
        );
    }

    #[test]
    fn expired_synthetic_dns_hole_reuses_freed_address_without_collision() {
        let config = HostAuthorityConfig::builder()
            .synthetic_dns_base(Ipv4Addr::new(198, 19, 0, 1))
            .max_synthetic_dns_entries(2)
            .dns_ttl_seconds(1)
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
        .unwrap();

        let first = authority
            .handle_message(NetMessage::DnsQuery(dns_query("one.example")))
            .unwrap();
        let second = authority
            .handle_message(NetMessage::DnsQuery(dns_query("two.example")))
            .unwrap();
        let first_ip = dns_response_ip(&first);
        let second_ip = dns_response_ip(&second);
        assert_ne!(first_ip, second_ip);

        authority
            .dns
            .by_name
            .get_mut(&DnsName::new("one.example").unwrap())
            .expect("first synthetic DNS entry should exist")
            .resolved_at = Instant::now() - Duration::from_secs(2);

        let third = authority
            .handle_message(NetMessage::DnsQuery(dns_query("three.example")))
            .unwrap();
        let third_ip = dns_response_ip(&third);

        assert_eq!(third_ip, first_ip);
        assert_eq!(authority.dns_map().len(), 2);
        assert_eq!(
            authority
                .dns_map()
                .name_for_address(second_ip)
                .map(DnsName::as_str),
            Some("two.example")
        );
        assert_eq!(
            authority
                .dns_map()
                .name_for_address(third_ip)
                .map(DnsName::as_str),
            Some("three.example")
        );
    }

    #[test]
    fn host_authority_config_rejects_zero_open_flow_limit() {
        let err = HostAuthorityConfig::builder()
            .max_open_flows(0)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("max_open_flows must be non-zero")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_open_flow_limit() {
        let err = HostAuthorityConfig::builder()
            .max_open_flows(MAX_OPEN_FLOWS + 1)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("max_open_flows exceeds the hard maximum")
        ));
    }

    #[test]
    fn host_authority_config_rejects_zero_guest_request_rate_limit() {
        let err = HostAuthorityConfig::builder()
            .max_guest_requests_per_window(0)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("max_guest_requests_per_window must be non-zero")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_guest_request_rate_limit() {
        let err = HostAuthorityConfig::builder()
            .max_guest_requests_per_window(MAX_GUEST_REQUESTS_PER_WINDOW + 1)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig(
                "max_guest_requests_per_window exceeds the hard maximum"
            )
        ));
    }

    #[test]
    fn host_authority_config_rejects_zero_guest_request_rate_window() {
        let err = HostAuthorityConfig::builder()
            .guest_request_rate_window(Duration::ZERO)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("guest_request_rate_window must be non-zero")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_guest_request_rate_window() {
        let err = HostAuthorityConfig::builder()
            .guest_request_rate_window(MAX_GUEST_REQUEST_RATE_WINDOW + Duration::from_millis(1))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("guest_request_rate_window exceeds the hard maximum")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_synthetic_dns_entry_limit() {
        let err = HostAuthorityConfig::builder()
            .max_synthetic_dns_entries(MAX_SYNTHETIC_DNS_ENTRIES + 1)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("max_synthetic_dns_entries exceeds the hard maximum")
        ));
    }

    #[test]
    fn host_authority_config_rejects_zero_dns_ttl() {
        let err = HostAuthorityConfig::builder()
            .dns_ttl_seconds(0)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("dns_ttl_seconds must be non-zero")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_dns_ttl() {
        let err = HostAuthorityConfig::builder()
            .dns_ttl_seconds(MAX_DNS_TTL_SECONDS + 1)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("dns_ttl_seconds exceeds the hard maximum")
        ));
    }

    #[test]
    fn host_authority_config_rejects_zero_udp_read_timeout() {
        let err = HostAuthorityConfig::builder()
            .udp_read_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("udp_read_timeout must be non-zero")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_udp_read_timeout() {
        let err = HostAuthorityConfig::builder()
            .udp_read_timeout(MAX_UDP_READ_TIMEOUT + Duration::from_millis(1))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("udp_read_timeout exceeds the hard maximum")
        ));
    }

    #[test]
    fn host_authority_config_rejects_zero_tcp_idle_timeout() {
        let err = HostAuthorityConfig::builder()
            .tcp_idle_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("tcp_idle_timeout must be non-zero")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_tcp_idle_timeout() {
        let err = HostAuthorityConfig::builder()
            .tcp_idle_timeout(MAX_TCP_IDLE_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("tcp_idle_timeout exceeds the hard maximum")
        ));
    }

    #[test]
    fn host_authority_config_rejects_zero_udp_idle_timeout() {
        let err = HostAuthorityConfig::builder()
            .udp_idle_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("udp_idle_timeout must be non-zero")
        ));
    }

    #[test]
    fn host_authority_config_rejects_oversized_udp_idle_timeout() {
        let err = HostAuthorityConfig::builder()
            .udp_idle_timeout(MAX_UDP_IDLE_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostAuthorityError::InvalidConfig("udp_idle_timeout exceeds the hard maximum")
        ));
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_config_rejects_zero_connect_timeout() {
        let err = StdTcpConnectorConfig::builder()
            .connect_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(err, StdTcpConnectorConfigError::ZeroConnectTimeout);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_config_rejects_oversized_connect_timeout() {
        let err = StdTcpConnectorConfig::builder()
            .connect_timeout(MAX_STD_TCP_CONNECT_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            StdTcpConnectorConfigError::ConnectTimeoutTooLarge {
                actual: MAX_STD_TCP_CONNECT_TIMEOUT + Duration::from_secs(1),
                max: MAX_STD_TCP_CONNECT_TIMEOUT,
            }
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_config_rejects_zero_read_timeout() {
        let err = StdTcpConnectorConfig::builder()
            .read_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(err, StdTcpConnectorConfigError::ZeroReadTimeout);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_config_rejects_oversized_read_timeout() {
        let err = StdTcpConnectorConfig::builder()
            .read_timeout(MAX_STD_TCP_READ_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            StdTcpConnectorConfigError::ReadTimeoutTooLarge {
                actual: MAX_STD_TCP_READ_TIMEOUT + Duration::from_secs(1),
                max: MAX_STD_TCP_READ_TIMEOUT,
            }
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_config_rejects_zero_open_flow_limit() {
        let err = StdTcpConnectorConfig::builder()
            .max_open_flows(0)
            .build()
            .unwrap_err();

        assert_eq!(err, StdTcpConnectorConfigError::ZeroMaxOpenFlows);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_config_rejects_oversized_open_flow_limit() {
        let err = StdTcpConnectorConfig::builder()
            .max_open_flows(MAX_OPEN_FLOWS + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            StdTcpConnectorConfigError::MaxOpenFlowsTooLarge {
                actual: MAX_OPEN_FLOWS + 1,
                max: MAX_OPEN_FLOWS,
            }
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_seeds_bounded_flow_storage_capacity_from_config() {
        let connector = StdTcpConnector::with_config(
            StdTcpConnectorConfig::builder()
                .max_open_flows(3)
                .build()
                .unwrap(),
        );

        assert!(connector.streams.capacity() >= 3);
        assert!(connector.flow_order.capacity() >= 3);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn collect_resolved_target_addrs_rejects_oversized_resolution_result_set() {
        let addrs = (0..=MAX_RESOLVED_TARGET_ADDRS)
            .map(|index| {
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    u16::try_from(index + 1).expect("test port fits in u16"),
                )
            })
            .collect::<Vec<_>>();

        let err = collect_resolved_target_addrs(addrs).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "resolved target address count exceeded configured budget"
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn collect_resolved_target_addrs_accepts_budget_sized_resolution_result_set() {
        let addrs = (0..MAX_RESOLVED_TARGET_ADDRS)
            .map(|index| {
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    u16::try_from(index + 1).expect("test port fits in u16"),
                )
            })
            .collect::<Vec<_>>();

        let collected = collect_resolved_target_addrs(addrs.clone()).unwrap();

        assert_eq!(collected, addrs);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn collect_resolved_target_addrs_seeds_capacity_from_resolution_budget() {
        let addrs = (0..2usize)
            .map(|index| {
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    u16::try_from(index + 1).expect("test port fits in u16"),
                )
            })
            .collect::<Vec<_>>();

        let collected = collect_resolved_target_addrs(addrs).unwrap();

        assert_eq!(collected.capacity(), MAX_RESOLVED_TARGET_ADDRS);
    }

    #[test]
    fn host_authority_config_deduplicates_capabilities_preserving_order() {
        let config = HostAuthorityConfig::builder()
            .capabilities(vec![
                Capability::PolicyDigest,
                Capability::Dns,
                Capability::Dns,
                Capability::Tcp,
                Capability::PolicyDigest,
            ])
            .build()
            .unwrap();

        assert_eq!(
            config.capabilities(),
            &[Capability::PolicyDigest, Capability::Dns, Capability::Tcp]
        );
    }

    #[test]
    fn accepted_capabilities_seeds_capacity_from_handshake_bounds() {
        let config = HostAuthorityConfig::builder()
            .capabilities(vec![
                Capability::Dns,
                Capability::PolicyDigest,
                Capability::StreamTransforms,
            ])
            .build()
            .unwrap();
        let guest = vec![Capability::Dns, Capability::PolicyDigest];

        let accepted = accepted_capabilities(&guest, &config);

        assert_eq!(accepted, guest);
        assert!(accepted.capacity() >= guest.len());
    }

    #[test]
    fn dns_query_is_denied_when_guest_request_rate_limit_is_reached() {
        let config = HostAuthorityConfig::builder()
            .max_guest_requests_per_window(1)
            .guest_request_rate_window(MAX_GUEST_REQUEST_RATE_WINDOW)
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
        let responses = authority
            .handle_message(NetMessage::DnsQuery(DnsQuery {
                query_id: query_id(8),
                name: DnsName::new("two.example").unwrap(),
                record_type: DnsRecordType::A,
            }))
            .unwrap();

        match responses.as_slice() {
            [NetMessage::DnsResponse(response)] => {
                assert_eq!(response.query_id, query_id(8));
                assert_eq!(response.code, DnsResponseCode::Refused);
                assert!(matches!(
                    response.denial,
                    Some(Denial {
                        reason: DenialReason::RateLimited,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn allowed_dns_query_records_allowed_and_answered_audit_events() {
        let mut authority = authority(StaticPolicy::allow_all());

        let responses = authority
            .handle_message(NetMessage::DnsQuery(dns_query("api.example.com")))
            .unwrap();

        let address = dns_response_ip(&responses);
        assert_eq!(
            authority.audit_mut().events,
            vec![
                HostAuditEvent::DnsAllowed {
                    query_id: 7,
                    name: "api.example.com".to_string(),
                    record_type: DnsRecordType::A,
                },
                HostAuditEvent::DnsAnswered {
                    query_id: 7,
                    name: "api.example.com".to_string(),
                    address,
                    ttl_seconds: DEFAULT_DNS_TTL_SECONDS,
                },
            ]
        );
    }

    #[test]
    fn allowed_non_a_dns_query_records_only_allowed_audit_event() {
        let mut authority = authority(StaticPolicy::allow_all());

        let responses = authority
            .handle_message(NetMessage::DnsQuery(DnsQuery {
                query_id: query_id(8),
                name: DnsName::new("api.example.com").unwrap(),
                record_type: DnsRecordType::Txt,
            }))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::DnsResponse(DnsResponse {
                query_id: query_id(8),
                code: DnsResponseCode::Ok,
                answers: Vec::new(),
                denial: None,
            })]
        );
        assert_eq!(
            authority.audit_mut().events,
            vec![HostAuditEvent::DnsAllowed {
                query_id: 8,
                name: "api.example.com".to_string(),
                record_type: DnsRecordType::Txt,
            }]
        );
    }

    #[test]
    fn guest_request_rate_limit_resets_after_window_expires() {
        let config = HostAuthorityConfig::builder()
            .max_guest_requests_per_window(1)
            .guest_request_rate_window(Duration::from_millis(5))
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
        std::thread::sleep(Duration::from_millis(20));
        let responses = authority
            .handle_message(NetMessage::DnsQuery(DnsQuery {
                query_id: query_id(9),
                name: DnsName::new("two.example").unwrap(),
                record_type: DnsRecordType::A,
            }))
            .unwrap();

        match responses.as_slice() {
            [NetMessage::DnsResponse(response)] => {
                assert_eq!(response.query_id, query_id(9));
                assert_eq!(response.code, DnsResponseCode::Ok);
                assert!(response.denial.is_none());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn tcp_open_is_denied_when_guest_request_rate_limit_is_reached() {
        let config = HostAuthorityConfig::builder()
            .max_guest_requests_per_window(1)
            .guest_request_rate_window(MAX_GUEST_REQUEST_RATE_WINDOW)
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
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        let responses = authority
            .handle_message(NetMessage::OpenTcp(
                OpenTcp::new(flow_id(12), Target::new("files.example.com", 443).unwrap())
                    .with_tls_policy(TlsPolicy::HostDecision),
            ))
            .unwrap();

        assert_eq!(authority.tcp_connector_mut().opens.len(), 1);
        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(12));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::RateLimited,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn udp_datagram_is_denied_when_guest_request_rate_limit_is_reached() {
        let config = HostAuthorityConfig::builder()
            .max_guest_requests_per_window(1)
            .guest_request_rate_window(MAX_GUEST_REQUEST_RATE_WINDOW)
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
        let responses = authority
            .handle_message(NetMessage::UdpDatagram(UdpDatagram {
                flow_id: flow_id(22),
                target: Target::new("dns.example.com", 53).unwrap(),
                direction: FlowDirection::GuestToHost,
                bytes: b"payload".to_vec(),
            }))
            .unwrap();

        match responses.as_slice() {
            [NetMessage::UdpDelivery(delivery)] => {
                assert_eq!(delivery.flow_id, flow_id(22));
                assert!(matches!(
                    delivery.status,
                    DatagramStatus::Denied(Denial {
                        reason: DenialReason::RateLimited,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn icmp_echo_is_denied_when_guest_request_rate_limit_is_reached() {
        let config = HostAuthorityConfig::builder()
            .max_guest_requests_per_window(1)
            .guest_request_rate_window(MAX_GUEST_REQUEST_RATE_WINDOW)
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
        let responses = authority
            .handle_message(NetMessage::IcmpEchoRequest(IcmpEchoRequest {
                query_id: query_id(22),
                host: HostName::new("example.com").unwrap(),
                payload_len: 56,
            }))
            .unwrap();

        match responses.as_slice() {
            [NetMessage::IcmpEchoResponse(response)] => {
                assert_eq!(response.query_id, query_id(22));
                assert_eq!(response.status, IcmpEchoStatus::Denied);
                assert!(matches!(
                    response.denial,
                    Some(Denial {
                        reason: DenialReason::RateLimited,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn denied_icmp_echo_returns_denied_response() {
        let mut authority = authority(StaticPolicy::deny_all(DenialReason::HostNotAllowed));
        let responses = authority
            .handle_message(NetMessage::IcmpEchoRequest(IcmpEchoRequest {
                query_id: query_id(24),
                host: HostName::new("example.com").unwrap(),
                payload_len: 56,
            }))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::IcmpEchoResponse(IcmpEchoResponse {
                query_id: query_id(24),
                status: IcmpEchoStatus::Denied,
                round_trip_micros: None,
                denial: Some(Denial::new(DenialReason::HostNotAllowed)),
            })]
        );
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
            vec![TcpConnectSpec::from_open(
                &open_tcp("api.example.com", 443),
                HostRoute::unresolved(),
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
    fn tcp_open_failure_records_allowed_then_failed_audit_events() {
        let mut authority = authority_with_connector(
            StaticPolicy::allow_all(),
            RecordingTcpConnector {
                open_result: Err(TransportError::TimedOut),
                error_detail: Some("connect timeout".to_string()),
                ..RecordingTcpConnector::default()
            },
        );

        let responses = authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::TcpOpenResult(TcpOpenResult::failed(
                flow_id(11),
                TransportError::TimedOut,
            ))]
        );
        assert_eq!(
            authority.audit_mut().events,
            vec![
                HostAuditEvent::TcpOpenAllowed {
                    flow_id: 11,
                    host: "api.example.com".to_string(),
                    port: 443,
                    upstream_ip: None,
                },
                HostAuditEvent::TcpOpenFailed {
                    flow_id: 11,
                    host: "api.example.com".to_string(),
                    port: 443,
                    upstream_ip: None,
                    error: TransportError::TimedOut,
                    error_detail: Some("connect timeout".to_string()),
                },
            ]
        );
    }

    #[test]
    fn tcp_open_is_denied_when_host_open_flow_limit_is_reached() {
        let config = HostAuthorityConfig::builder()
            .max_open_flows(1)
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
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        let responses = authority
            .handle_message(NetMessage::OpenTcp(
                OpenTcp::new(flow_id(12), Target::new("files.example.com", 443).unwrap())
                    .with_tls_policy(TlsPolicy::HostDecision),
            ))
            .unwrap();

        assert_eq!(authority.tcp_connector_mut().opens.len(), 1);
        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(12));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::ResourceLimit,
                        ..
                    })
                ));
                let FlowOpenStatus::Denied(denial) = &result.status else {
                    panic!("unexpected status: {:?}", result.status);
                };
                assert_eq!(
                    denial.safe_detail.as_deref(),
                    Some("host open-flow limit reached for this microVM")
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn expired_tcp_flow_is_pruned_before_new_tcp_open_limit_check() {
        let config = HostAuthorityConfig::builder()
            .max_open_flows(1)
            .tcp_idle_timeout(Duration::from_millis(10))
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
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        authority
            .open_tcp_flows
            .get_mut(&flow_id(11))
            .expect("first TCP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let responses = authority
            .handle_message(NetMessage::OpenTcp(
                OpenTcp::new(flow_id(12), Target::new("files.example.com", 443).unwrap())
                    .with_tls_policy(TlsPolicy::HostDecision),
            ))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::TcpOpenResult(TcpOpenResult::opened(flow_id(
                12
            )))]
        );
        assert!(!authority.open_tcp_flows.contains_key(&flow_id(11)));
        assert!(authority.open_tcp_flows.contains_key(&flow_id(12)));
        assert_eq!(
            authority.tcp_connector_mut().closes,
            vec![(11, CloseReason::HostClosed)]
        );
    }

    #[test]
    fn expired_tcp_flow_prune_preserves_close_time_detail_in_flow_closed_audit() {
        let config = HostAuthorityConfig::builder()
            .max_open_flows(1)
            .tcp_idle_timeout(Duration::from_millis(10))
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                close_error_detail: Some("idle-prune-close-detail".to_string()),
                ..RecordingTcpConnector::default()
            },
        )
        .unwrap();
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        authority
            .open_tcp_flows
            .get_mut(&flow_id(11))
            .expect("first TCP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let responses = authority
            .handle_message(NetMessage::OpenTcp(
                OpenTcp::new(flow_id(12), Target::new("files.example.com", 443).unwrap())
                    .with_tls_policy(TlsPolicy::HostDecision),
            ))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::TcpOpenResult(TcpOpenResult::opened(flow_id(
                12
            )))]
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::FlowClosed {
                    flow_id: 11,
                    reason: CloseReason::HostClosed,
                    error_detail: Some("idle-prune-close-detail".to_string()),
                })
        );
    }

    #[test]
    fn expired_tcp_flow_send_returns_host_closed() {
        let config = HostAuthorityConfig::builder()
            .tcp_idle_timeout(Duration::from_millis(10))
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
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        authority
            .open_tcp_flows
            .get_mut(&flow_id(11))
            .expect("TCP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let responses = authority
            .handle_message(NetMessage::TcpData(StreamChunk::new(
                flow_id(11),
                FlowDirection::GuestToHost,
                0,
                b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            )))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::HostClosed,
            })]
        );
        assert!(!authority.open_tcp_flows.contains_key(&flow_id(11)));
        assert_eq!(
            authority.tcp_connector_mut().closes,
            vec![(11, CloseReason::HostClosed)]
        );
    }

    #[test]
    fn drain_messages_closes_idle_tcp_flow() {
        let config = HostAuthorityConfig::builder()
            .tcp_idle_timeout(Duration::from_millis(10))
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
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        authority
            .open_tcp_flows
            .get_mut(&flow_id(11))
            .expect("TCP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let drained = authority.drain_messages(4).unwrap();

        assert_eq!(
            drained,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::HostClosed,
            })]
        );
        assert!(!authority.open_tcp_flows.contains_key(&flow_id(11)));
        assert_eq!(
            authority.tcp_connector_mut().closes,
            vec![(11, CloseReason::HostClosed)]
        );
    }

    #[test]
    fn drain_messages_idle_tcp_close_preserves_close_time_detail_in_flow_closed_audit() {
        let config = HostAuthorityConfig::builder()
            .tcp_idle_timeout(Duration::from_millis(10))
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                close_error_detail: Some("idle-drain-close-detail".to_string()),
                ..RecordingTcpConnector::default()
            },
        )
        .unwrap();
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        authority
            .open_tcp_flows
            .get_mut(&flow_id(11))
            .expect("TCP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let drained = authority.drain_messages(4).unwrap();

        assert_eq!(
            drained,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::HostClosed,
            })]
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::FlowClosed {
                    flow_id: 11,
                    reason: CloseReason::HostClosed,
                    error_detail: Some("idle-drain-close-detail".to_string()),
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
    fn tls_transform_flow_is_denied_when_connector_cannot_terminate_tls() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RefusingTcpConnector,
        );
        let open = open_tcp("api.example.com", 443).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            crate::proto::TlsTermination::TerminateAndReoriginate,
        ));
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::TlsRequired,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn required_tls_transform_without_route_is_denied_fail_closed() {
        let mut authority = authority(StaticPolicy::allow_all());
        let open =
            open_tcp("api.example.com", 443).with_tls_policy(TlsPolicy::RequiredForTransform);
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::TransformRequired,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn transformed_tls_route_with_alpn_is_denied_fail_closed() {
        let mut authority = authority(StaticPolicy::allow_all());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_alpn_protocols(vec![AlpnProtocol::new("h2").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::ProtocolNotAllowed,
                        ..
                    })
                ));
                let FlowOpenStatus::Denied(denial) = &result.status else {
                    panic!("unexpected status: {:?}", result.status);
                };
                assert_eq!(
                    denial.safe_detail.as_deref(),
                    Some("ALPN negotiation is not supported for transformed TLS flows")
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn transformed_tls_route_with_audit_plugin_chain_is_admitted() {
        let mut authority = authority(StaticPolicy::allow_all());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("audit").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert_eq!(result.status, FlowOpenStatus::Opened);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn transformed_tls_route_with_metadata_endpoint_deny_plugin_is_admitted() {
        let mut authority = authority(StaticPolicy::allow_all());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert_eq!(result.status, FlowOpenStatus::Opened);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn transformed_tls_route_with_target_ambiguous_secret_replacement_is_denied_at_admission() {
        let connector = RecordingTcpConnector::with_stream_transform_config(
            crate::stream_transform::StreamTransformConfig::default()
                .with_secret_replacement_bindings([
                    mvm_core::policy::secret_binding::SecretBinding::new(
                        "OPENAI_API_KEY",
                        "api.example.com",
                    )
                    .with_value("sk-live-1"),
                    mvm_core::policy::secret_binding::SecretBinding::new(
                        "OPENAI_API_KEY",
                        "*.example.com",
                    )
                    .with_value("sk-live-2"),
                ])
                .expect("secret replacement config is structurally valid"),
        );
        let mut authority = authority_with_connector(StaticPolicy::allow_all(), connector);
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::PluginDenied,
                        ..
                    })
                ));
                let FlowOpenStatus::Denied(denial) = &result.status else {
                    panic!("unexpected status: {:?}", result.status);
                };
                assert_eq!(
                    denial.safe_detail.as_deref(),
                    Some(
                        "TLS transform plugin secret-replacement denied the flow: multiple secret replacement bindings resolve to placeholder mvm-managed:OPENAI_API_KEY for target host api.example.com"
                    )
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(
            authority.tcp.opens.is_empty(),
            "admission should deny before connector open is attempted"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn transformed_tls_route_with_no_bound_secret_for_target_is_denied_at_admission() {
        let connector = RecordingTcpConnector::with_stream_transform_config(
            crate::stream_transform::StreamTransformConfig::default()
                .with_secret_replacement_bindings([
                    mvm_core::policy::secret_binding::SecretBinding::new(
                        "OPENAI_API_KEY",
                        "other.example.com",
                    )
                    .with_value("sk-live-12345"),
                ])
                .expect("secret replacement config is structurally valid"),
        );
        let mut authority = authority_with_connector(StaticPolicy::allow_all(), connector);
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::PluginDenied,
                        ..
                    })
                ));
                let FlowOpenStatus::Denied(denial) = &result.status else {
                    panic!("unexpected status: {:?}", result.status);
                };
                assert_eq!(
                    denial.safe_detail.as_deref(),
                    Some(
                        "TLS transform plugin secret-replacement denied the flow: no secret replacement bindings are configured for target host api.example.com"
                    )
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(
            authority.tcp.opens.is_empty(),
            "admission should deny before connector open is attempted"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn transformed_tls_route_with_no_secret_replacement_config_is_denied_at_admission() {
        let mut authority =
            authority_with_connector(StaticPolicy::allow_all(), RecordingTcpConnector::default());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::PluginDenied,
                        ..
                    })
                ));
                let FlowOpenStatus::Denied(denial) = &result.status else {
                    panic!("unexpected status: {:?}", result.status);
                };
                assert_eq!(
                    denial.safe_detail.as_deref(),
                    Some(
                        "TLS transform plugin secret-replacement denied the flow: no secret replacement bindings are configured"
                    )
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(
            authority.tcp.opens.is_empty(),
            "admission should deny before connector open is attempted"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn transformed_tls_route_with_no_response_leak_guard_config_is_denied_at_admission() {
        let mut authority =
            authority_with_connector(StaticPolicy::allow_all(), RecordingTcpConnector::default());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("response-leak-guard").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::PluginDenied,
                        ..
                    })
                ));
                let FlowOpenStatus::Denied(denial) = &result.status else {
                    panic!("unexpected status: {:?}", result.status);
                };
                assert_eq!(
                    denial.safe_detail.as_deref(),
                    Some(
                        "TLS transform plugin response-leak-guard denied the flow: no known secret values are configured for response leak guard"
                    )
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }

        assert!(
            authority.tcp.opens.is_empty(),
            "admission should deny before connector open is attempted"
        );
    }

    #[test]
    fn transformed_tls_route_with_unknown_plugin_is_denied_fail_closed() {
        let mut authority = authority(StaticPolicy::allow_all());
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("definitely-unknown").unwrap()]),
        );
        let responses = authority.handle_message(NetMessage::OpenTcp(open)).unwrap();

        match responses.as_slice() {
            [NetMessage::TcpOpenResult(result)] => {
                assert_eq!(result.flow_id, flow_id(11));
                assert!(matches!(
                    result.status,
                    FlowOpenStatus::Denied(Denial {
                        reason: DenialReason::PluginDenied,
                        ..
                    })
                ));
                let FlowOpenStatus::Denied(denial) = &result.status else {
                    panic!("unexpected status: {:?}", result.status);
                };
                assert_eq!(
                    denial.safe_detail.as_deref(),
                    Some("unknown TLS transform plugin definitely-unknown")
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn transformed_tls_route_with_overlong_plugin_chain_is_denied_fail_closed() {
        let mut authority = authority(StaticPolicy::allow_all());
        let plugin_chain: Vec<_> = (0..9).map(|_| PluginId::new("audit").unwrap()).collect();
        let open = open_tcp("api.example.com", 443).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                crate::proto::TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(plugin_chain),
        );
        let err = authority
            .handle_message(NetMessage::OpenTcp(open))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin chain has 9 entries; maximum is 8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn transformed_tls_route_with_overlong_auto_appended_response_leak_guard_config_is_denied_fail_closed()
     {
        let err = crate::stream_transform::StreamTransformConfig::default()
            .with_response_leak_guard_secret_values((0..129).map(|index| format!("secret-{index}")))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: response leak guard config has 129 secret values; maximum is 128"
        );
    }

    #[test]
    fn tcp_data_rejects_overlong_payload_before_connector_send() {
        let mut authority = authority(StaticPolicy::allow_all());
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();
        let err = authority
            .handle_message(NetMessage::TcpData(StreamChunk::new(
                flow_id(11),
                FlowDirection::GuestToHost,
                0,
                vec![0; crate::proto::MAX_STREAM_CHUNK_BYTES + 1],
            )))
            .unwrap_err();

        assert_eq!(
            err,
            HostAuthorityError::Protocol(ProtocolError::ValueTooLong {
                field: "TCP stream chunk payload",
                bytes: crate::proto::MAX_STREAM_CHUNK_BYTES + 1,
                max: crate::proto::MAX_STREAM_CHUNK_BYTES,
            })
        );
        assert!(authority.tcp_connector_mut().sends.is_empty());
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
    fn tls_forward_failure_is_audited_and_closes_with_transform_reason() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                send_result: Err(TransportError::TlsHandshakeFailed),
                error_detail: Some("peer does not support any known cipher suites".to_string()),
                ..RecordingTcpConnector::default()
            },
        );
        authority
            .handle_message(NetMessage::OpenTcp(
                open_tcp("api.example.com", 443).with_tls_transform(TlsTransformRoute::new(
                    DnsName::new("api.example.com").unwrap(),
                    crate::proto::TlsTermination::TerminateAndReoriginate,
                )),
            ))
            .unwrap();

        let responses = authority
            .handle_message(NetMessage::TcpData(StreamChunk::new(
                flow_id(11),
                FlowDirection::GuestToHost,
                0,
                b"clienthello".to_vec(),
            )))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::TransformError,
            })]
        );
        assert_eq!(
            authority.audit_mut().events,
            vec![
                HostAuditEvent::TcpOpenAllowed {
                    flow_id: 11,
                    host: "api.example.com".to_string(),
                    port: 443,
                    upstream_ip: None,
                },
                HostAuditEvent::TcpForwardFailed {
                    flow_id: 11,
                    bytes: 11,
                    end_stream: false,
                    error: TransportError::TlsHandshakeFailed,
                    error_detail: Some("peer does not support any known cipher suites".to_string()),
                },
                HostAuditEvent::FlowClosed {
                    flow_id: 11,
                    reason: CloseReason::TransformError,
                    error_detail: None,
                },
            ]
        );
        assert_eq!(
            authority.tcp_connector_mut().closes,
            vec![(11, CloseReason::TransformError)]
        );
    }

    #[test]
    fn tls_forward_failure_preserves_close_time_detail_in_flow_closed_audit() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                send_result: Err(TransportError::TlsHandshakeFailed),
                error_detail: Some("forward-error-detail".to_string()),
                close_error_detail: Some("close-time-detail".to_string()),
                ..RecordingTcpConnector::default()
            },
        );
        authority
            .handle_message(NetMessage::OpenTcp(
                open_tcp("api.example.com", 443).with_tls_transform(TlsTransformRoute::new(
                    DnsName::new("api.example.com").unwrap(),
                    crate::proto::TlsTermination::TerminateAndReoriginate,
                )),
            ))
            .unwrap();

        let responses = authority
            .handle_message(NetMessage::TcpData(StreamChunk::new(
                flow_id(11),
                FlowDirection::GuestToHost,
                0,
                b"clienthello".to_vec(),
            )))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::TransformError,
            })]
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::TcpForwardFailed {
                    flow_id: 11,
                    bytes: 11,
                    end_stream: false,
                    error: TransportError::TlsHandshakeFailed,
                    error_detail: Some("forward-error-detail".to_string()),
                })
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::FlowClosed {
                    flow_id: 11,
                    reason: CloseReason::TransformError,
                    error_detail: Some("close-time-detail".to_string()),
                })
        );
    }

    #[test]
    fn tcp_forward_failure_audit_detail_is_clamped_to_host_audit_budget() {
        let oversized_detail = "x".repeat(MAX_HOST_AUDIT_DETAIL_BYTES + 1);
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                send_result: Err(TransportError::TlsHandshakeFailed),
                error_detail: Some(oversized_detail),
                ..RecordingTcpConnector::default()
            },
        );
        authority
            .handle_message(NetMessage::OpenTcp(
                open_tcp("api.example.com", 443).with_tls_transform(TlsTransformRoute::new(
                    DnsName::new("api.example.com").unwrap(),
                    crate::proto::TlsTermination::TerminateAndReoriginate,
                )),
            ))
            .unwrap();

        let responses = authority
            .handle_message(NetMessage::TcpData(StreamChunk::new(
                flow_id(11),
                FlowDirection::GuestToHost,
                0,
                b"clienthello".to_vec(),
            )))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::TransformError,
            })]
        );
        let event = authority
            .audit_mut()
            .events
            .iter()
            .find_map(|event| match event {
                HostAuditEvent::TcpForwardFailed {
                    flow_id,
                    error_detail,
                    ..
                } if *flow_id == 11 => error_detail.clone(),
                _ => None,
            })
            .expect("forward failure audit event should carry clamped detail");
        assert_eq!(event.len(), MAX_HOST_AUDIT_DETAIL_BYTES);
        assert!(event.chars().all(|ch| ch == 'x'));
    }

    #[test]
    fn tcp_return_audit_detail_is_clamped_to_host_audit_budget() {
        let oversized_detail = "x".repeat(MAX_HOST_AUDIT_DETAIL_BYTES + 1);
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                drains: VecDeque::from([vec![HostTcpEvent::Data(StreamChunk::new(
                    flow_id(11),
                    FlowDirection::HostToGuest,
                    0,
                    b"abc".to_vec(),
                ))]]),
                activity_detail: Some(oversized_detail),
                ..RecordingTcpConnector::default()
            },
        );
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        let drained = authority.drain_messages(4).unwrap();

        assert_eq!(
            drained,
            vec![NetMessage::TcpData(StreamChunk::new(
                flow_id(11),
                FlowDirection::HostToGuest,
                0,
                b"abc".to_vec(),
            ))]
        );
        let event = authority
            .audit_mut()
            .events
            .iter()
            .find_map(|event| match event {
                HostAuditEvent::TcpBytesReturned {
                    flow_id,
                    detail: Some(detail),
                    ..
                } if *flow_id == 11 => Some(detail.clone()),
                _ => None,
            })
            .expect("returned-bytes audit event should carry clamped detail");
        assert_eq!(event.len(), MAX_HOST_AUDIT_DETAIL_BYTES);
        assert!(event.chars().all(|ch| ch == 'x'));
    }

    #[test]
    fn flow_closed_audit_error_detail_is_clamped_to_host_audit_budget() {
        let oversized_detail = "é".repeat(MAX_HOST_AUDIT_DETAIL_BYTES + 1);
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                error_detail: Some(oversized_detail),
                ..RecordingTcpConnector::default()
            },
        );
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        let responses = authority
            .handle_message(NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::HostClosed,
            }))
            .unwrap();

        assert!(responses.is_empty());
        let event = authority
            .audit_mut()
            .events
            .iter()
            .find_map(|event| match event {
                HostAuditEvent::FlowClosed {
                    flow_id,
                    error_detail: Some(detail),
                    ..
                } if *flow_id == 11 => Some(detail.clone()),
                _ => None,
            })
            .expect("flow-closed audit event should carry clamped detail");
        assert!(event.len() <= MAX_HOST_AUDIT_DETAIL_BYTES);
        assert!(event.chars().all(|ch| ch == 'é'));
        assert!(event.is_char_boundary(event.len()));
    }

    #[test]
    fn flow_closed_audit_records_detail_materialized_during_connector_close() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                close_error_detail: Some("close-generated-detail".to_string()),
                ..RecordingTcpConnector::default()
            },
        );
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        let responses = authority
            .handle_message(NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::HostClosed,
            }))
            .unwrap();

        assert!(responses.is_empty());
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::FlowClosed {
                    flow_id: 11,
                    reason: CloseReason::HostClosed,
                    error_detail: Some("close-generated-detail".to_string()),
                })
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn udp_datagram_is_denied_when_host_open_flow_limit_is_reached() {
        let config = HostAuthorityConfig::builder()
            .max_open_flows(1)
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
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        let responses = authority
            .handle_message(NetMessage::UdpDatagram(UdpDatagram {
                flow_id: flow_id(22),
                target: Target::new("dns.example.com", 53).unwrap(),
                direction: FlowDirection::GuestToHost,
                bytes: b"payload".to_vec(),
            }))
            .unwrap();

        match responses.as_slice() {
            [NetMessage::UdpDelivery(delivery)] => {
                assert_eq!(delivery.flow_id, flow_id(22));
                assert!(matches!(
                    delivery.status,
                    DatagramStatus::Denied(Denial {
                        reason: DenialReason::ResourceLimit,
                        ..
                    })
                ));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn expired_udp_flow_is_pruned_before_new_udp_flow_limit_check() {
        let Some(listener) = bind_loopback_udp_socket() else {
            return;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let config = HostAuthorityConfig::builder()
            .max_open_flows(1)
            .udp_idle_timeout(Duration::from_millis(10))
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
        .unwrap();

        let first = UdpDatagram {
            flow_id: flow_id(21),
            target: Target::new("127.0.0.1", port).unwrap(),
            direction: FlowDirection::GuestToHost,
            bytes: b"first".to_vec(),
        };
        assert!(
            authority
                .handle_message(NetMessage::UdpDatagram(first))
                .unwrap()
                .is_empty()
        );
        authority
            .open_udp_flows
            .get_mut(&flow_id(21))
            .expect("first UDP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let second = UdpDatagram {
            flow_id: flow_id(22),
            target: Target::new("127.0.0.1", port).unwrap(),
            direction: FlowDirection::GuestToHost,
            bytes: b"second".to_vec(),
        };
        let responses = authority
            .handle_message(NetMessage::UdpDatagram(second))
            .unwrap();

        assert!(responses.is_empty());
        assert_eq!(authority.open_udp_flows.len(), 1);
        assert!(!authority.open_udp_flows.contains_key(&flow_id(21)));
        assert!(authority.open_udp_flows.contains_key(&flow_id(22)));
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::UdpFailed {
                    flow_id: 21,
                    host: "127.0.0.1".to_string(),
                    port,
                    upstream_ip: None,
                    bytes: 0,
                    error: TransportError::TimedOut,
                    error_detail: Some("UDP flow idle timeout expired".to_string()),
                })
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn expired_udp_flow_is_pruned_before_tcp_open_limit_check() {
        let Some(listener) = bind_loopback_udp_socket() else {
            return;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let config = HostAuthorityConfig::builder()
            .max_open_flows(1)
            .udp_idle_timeout(Duration::from_millis(10))
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
        .unwrap();

        let udp = UdpDatagram {
            flow_id: flow_id(21),
            target: Target::new("127.0.0.1", port).unwrap(),
            direction: FlowDirection::GuestToHost,
            bytes: b"payload".to_vec(),
        };
        assert!(
            authority
                .handle_message(NetMessage::UdpDatagram(udp))
                .unwrap()
                .is_empty()
        );
        authority
            .open_udp_flows
            .get_mut(&flow_id(21))
            .expect("UDP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let responses = authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        assert_eq!(
            responses,
            vec![NetMessage::TcpOpenResult(TcpOpenResult::opened(flow_id(
                11
            )))]
        );
        assert!(authority.open_udp_flows.is_empty());
        assert!(authority.open_tcp_flows.contains_key(&flow_id(11)));
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn drain_messages_prunes_idle_udp_flows() {
        let Some(listener) = bind_loopback_udp_socket() else {
            return;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let config = HostAuthorityConfig::builder()
            .udp_idle_timeout(Duration::from_millis(10))
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
        .unwrap();

        let udp = UdpDatagram {
            flow_id: flow_id(21),
            target: Target::new("127.0.0.1", port).unwrap(),
            direction: FlowDirection::GuestToHost,
            bytes: b"payload".to_vec(),
        };
        assert!(
            authority
                .handle_message(NetMessage::UdpDatagram(udp))
                .unwrap()
                .is_empty()
        );
        authority
            .open_udp_flows
            .get_mut(&flow_id(21))
            .expect("UDP flow should exist")
            .last_activity = Instant::now() - Duration::from_millis(50);

        let drained = authority.drain_messages(4).unwrap();

        assert!(drained.is_empty());
        assert!(authority.open_udp_flows.is_empty());
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::UdpFailed {
                    flow_id: 21,
                    host: "127.0.0.1".to_string(),
                    port,
                    upstream_ip: None,
                    bytes: 0,
                    error: TransportError::TimedOut,
                    error_detail: Some("UDP flow idle timeout expired".to_string()),
                })
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn drain_udp_messages_prunes_stale_udp_flow_order_refs() {
        let mut authority = authority(StaticPolicy::allow_all());
        authority.udp_flow_order.push_back(flow_id(41));
        authority.udp_flow_order.push_back(flow_id(41));

        let drained = authority.drain_messages(4).unwrap();

        assert!(drained.is_empty());
        assert!(authority.udp_flow_order.is_empty());
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn guest_stream_tracker_ignores_full_retransmit_and_rejects_gap() {
        let mut tracker = GuestStreamTracker::default();
        let first = StreamChunk::new(
            flow_id(11),
            FlowDirection::GuestToHost,
            100,
            b"clienthello".to_vec(),
        );
        assert_eq!(tracker.observe(&first), Ok(GuestChunkAction::Forward));
        assert_eq!(tracker.observe(&first), Ok(GuestChunkAction::Ignore));

        let gap = StreamChunk::new(
            flow_id(11),
            FlowDirection::GuestToHost,
            200,
            b"future".to_vec(),
        );
        assert_eq!(tracker.observe(&gap), Err(TransportError::ProtocolError));
    }

    #[test]
    fn authority_drains_host_tcp_data_and_close_for_open_flows() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::with_drains([vec![
                HostTcpEvent::Data(StreamChunk::new(
                    flow_id(11),
                    FlowDirection::HostToGuest,
                    0,
                    b"HTTP".to_vec(),
                )),
                HostTcpEvent::Close(CloseFlow {
                    flow_id: flow_id(11),
                    reason: CloseReason::HostClosed,
                }),
            ]]),
        );
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        let drained = authority.drain_messages(8).unwrap();

        assert_eq!(
            drained,
            vec![
                NetMessage::TcpData(StreamChunk::new(
                    flow_id(11),
                    FlowDirection::HostToGuest,
                    0,
                    b"HTTP".to_vec(),
                )),
                NetMessage::CloseFlow(CloseFlow {
                    flow_id: flow_id(11),
                    reason: CloseReason::HostClosed,
                }),
            ]
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::TcpBytesReturned {
                    flow_id: 11,
                    sequence: 0,
                    bytes: 4,
                    end_stream: false,
                    detail: None,
                })
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::FlowClosed {
                    flow_id: 11,
                    reason: CloseReason::HostClosed,
                    error_detail: None,
                })
        );
    }

    #[test]
    fn authority_drains_connector_close_with_close_time_detail_in_flow_closed_audit() {
        let mut authority = HostAuthority::new(
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector {
                drains: VecDeque::from([vec![HostTcpEvent::Close(CloseFlow {
                    flow_id: flow_id(11),
                    reason: CloseReason::HostClosed,
                })]]),
                close_error_detail: Some("connector-close-detail".to_string()),
                ..RecordingTcpConnector::default()
            },
        );
        authority
            .handle_message(NetMessage::OpenTcp(open_tcp("api.example.com", 443)))
            .unwrap();

        let drained = authority.drain_messages(4).unwrap();

        assert_eq!(
            drained,
            vec![NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(11),
                reason: CloseReason::HostClosed,
            })]
        );
        assert!(
            authority
                .audit_mut()
                .events
                .contains(&HostAuditEvent::FlowClosed {
                    flow_id: 11,
                    reason: CloseReason::HostClosed,
                    error_detail: Some("connector-close-detail".to_string()),
                })
        );
    }

    #[cfg(not(feature = "host-std"))]
    #[test]
    fn unsupported_allowed_udp_returns_protocol_failure() {
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
    }

    #[test]
    fn wrong_direction_udp_datagram_fails_closed_with_protocol_error() {
        let mut authority = authority(StaticPolicy::allow_all());
        let udp = UdpDatagram {
            flow_id: flow_id(21),
            target: Target::new("dns.example", 53).unwrap(),
            direction: FlowDirection::HostToGuest,
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
    }

    #[test]
    fn denied_udp_datagram_returns_denial_without_forwarding() {
        let mut authority = authority(StaticPolicy::deny_all(DenialReason::NetworkDisabled));
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
                status: DatagramStatus::Denied(Denial::new(DenialReason::NetworkDisabled)),
            })]
        );
    }

    #[test]
    fn udp_datagram_rejects_overlong_payload_before_policy_or_forwarding() {
        let mut authority = authority(StaticPolicy::allow_all());
        let err = authority
            .handle_message(NetMessage::UdpDatagram(UdpDatagram {
                flow_id: flow_id(21),
                target: Target::new("dns.example", 53).unwrap(),
                direction: FlowDirection::GuestToHost,
                bytes: vec![0; crate::proto::MAX_STREAM_CHUNK_BYTES + 1],
            }))
            .unwrap_err();

        assert_eq!(
            err,
            HostAuthorityError::Protocol(ProtocolError::ValueTooLong {
                field: "UDP datagram payload",
                bytes: crate::proto::MAX_STREAM_CHUNK_BYTES + 1,
                max: crate::proto::MAX_STREAM_CHUNK_BYTES,
            })
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn allowed_udp_datagram_roundtrip_returns_host_response_bytes() {
        use std::thread;
        use std::time::Duration;

        let Some(listener) = bind_loopback_udp_socket() else {
            return;
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (bytes, addr) = listener.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..bytes], b"time?");
            listener.send_to(b"pong", addr).unwrap();
        });

        let mut authority = authority(StaticPolicy::allow_all());
        let udp = UdpDatagram {
            flow_id: flow_id(21),
            target: Target::new("127.0.0.1", port).unwrap(),
            direction: FlowDirection::GuestToHost,
            bytes: b"time?".to_vec(),
        };
        let responses = authority
            .handle_message(NetMessage::UdpDatagram(udp))
            .unwrap();
        assert!(responses.is_empty());

        let mut drained = Vec::new();
        for _ in 0..100 {
            drained = authority.drain_messages(4).unwrap();
            if !drained.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            drained,
            vec![NetMessage::UdpDatagram(UdpDatagram {
                flow_id: flow_id(21),
                target: Target::new("127.0.0.1", port).unwrap(),
                direction: FlowDirection::HostToGuest,
                bytes: b"pong".to_vec(),
            })]
        );
        assert!(authority.audit_mut().events.iter().any(|event| matches!(
            event,
            HostAuditEvent::UdpForwarded {
                flow_id,
                bytes,
                ..
            } if *flow_id == 21 && *bytes == 5
        )));
        assert!(authority.audit_mut().events.iter().any(|event| matches!(
            event,
            HostAuditEvent::UdpReturned {
                flow_id,
                bytes,
                ..
            } if *flow_id == 21 && *bytes == 4
        )));
        assert_eq!(
            authority
                .open_udp_flows
                .get(&flow_id(21))
                .expect("UDP flow should stay open after a successful reply")
                .read_buffer
                .len(),
            STD_UDP_READ_BUFFER_BYTES
        );
        join.join().unwrap();
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn udp_drain_failure_emits_failed_delivery_audit_and_reclaims_flow() {
        use std::thread;
        use std::time::Duration;

        let Some(unused) = bind_loopback_udp_socket() else {
            return;
        };
        let port = unused.local_addr().unwrap().port();
        drop(unused);

        let config = HostAuthorityConfig::builder()
            .udp_read_timeout(DEFAULT_UDP_READ_TIMEOUT)
            .build()
            .unwrap();
        let mut authority = HostAuthority::with_config(
            config,
            StaticPolicy::allow_all(),
            VecAudit::default(),
            RecordingTcpConnector::default(),
        )
        .unwrap();
        let udp = UdpDatagram {
            flow_id: flow_id(21),
            target: Target::new("127.0.0.1", port).unwrap(),
            direction: FlowDirection::GuestToHost,
            bytes: b"probe".to_vec(),
        };
        let responses = authority
            .handle_message(NetMessage::UdpDatagram(udp))
            .unwrap();
        assert!(responses.is_empty());
        assert!(authority.open_udp_flows.contains_key(&flow_id(21)));

        let mut drained = Vec::new();
        for _ in 0..100 {
            drained = authority.drain_messages(4).unwrap();
            if !drained.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        match drained.as_slice() {
            [
                NetMessage::UdpDelivery(UdpDelivery {
                    flow_id: delivery_flow_id,
                    status,
                }),
            ] => {
                assert_eq!(*delivery_flow_id, flow_id(21));
                assert!(matches!(
                    status,
                    DatagramStatus::Failed(
                        TransportError::Refused
                            | TransportError::Reset
                            | TransportError::Unreachable
                    )
                ));
            }
            other => panic!("unexpected UDP drain result: {other:?}"),
        }
        assert!(!authority.open_udp_flows.contains_key(&flow_id(21)));
        assert!(authority.audit_mut().events.iter().any(|event| matches!(
            event,
            HostAuditEvent::UdpFailed {
                flow_id,
                host,
                port: audit_port,
                bytes,
                error,
                error_detail: Some(_),
                ..
            } if *flow_id == 21
                && host == "127.0.0.1"
                && *audit_port == port
                && *bytes == 0
                && matches!(
                    error,
                    TransportError::Refused
                        | TransportError::Reset
                        | TransportError::Unreachable
                )
        )));
    }

    #[cfg(not(feature = "host-std"))]
    #[test]
    fn allowed_icmp_without_host_std_returns_unreachable() {
        let mut authority = authority(StaticPolicy::allow_all());
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

    #[cfg(feature = "host-std")]
    #[test]
    fn allowed_icmp_loopback_replies() {
        if !icmp_echo_supported() {
            return;
        }
        let mut authority = authority(StaticPolicy::allow_all());
        let icmp = IcmpEchoRequest {
            query_id: query_id(22),
            host: HostName::new("127.0.0.1").unwrap(),
            payload_len: 8,
        };
        let icmp_responses = authority
            .handle_message(NetMessage::IcmpEchoRequest(icmp))
            .unwrap();
        match icmp_responses.as_slice() {
            [
                NetMessage::IcmpEchoResponse(IcmpEchoResponse {
                    query_id: response_query_id,
                    status: IcmpEchoStatus::Replied,
                    round_trip_micros: _,
                    denial: None,
                }),
            ] => {
                assert_eq!(*response_query_id, query_id(22));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(authority.audit_mut().events.iter().any(|event| matches!(
            event,
            HostAuditEvent::IcmpReplied {
                query_id: 22,
                host,
                upstream_ip: None,
                round_trip_micros: _,
            } if host == "127.0.0.1"
        )));
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
        assert_eq!(
            policy.decide_icmp_echo(&IcmpEchoRequest {
                query_id: query_id(33),
                host: HostName::new("api.example.com").unwrap(),
                payload_len: 8,
            }),
            HostAdmission::allowed_with_route(HostRoute::resolved_ip(
                "203.0.113.10".parse().unwrap()
            ))
        );
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
        use std::thread;

        let Some(listener) = bind_loopback_tcp_listener() else {
            return;
        };
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
        connector
            .open(&TcpConnectSpec::from_open(
                &OpenTcp::new(flow_id(31), target.clone()),
                route,
            ))
            .unwrap();
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

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_emits_ack_event_after_guest_data() {
        use std::io::Read;
        use std::thread;
        use std::time::Duration;

        let Some(listener) = bind_loopback_tcp_listener() else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            thread::sleep(Duration::from_millis(20));
        });

        let mut connector = StdTcpConnector::with_config(
            StdTcpConnectorConfig::builder()
                .read_timeout(Duration::from_millis(5))
                .build()
                .expect("std tcp connector config is valid"),
        );
        let route = HostRoute::resolved_ip("127.0.0.1".parse().unwrap());
        let target = Target::new("route-should-win.invalid", port).unwrap();
        connector
            .open(&TcpConnectSpec::from_open(
                &OpenTcp::new(flow_id(32), target),
                route,
            ))
            .unwrap();
        connector
            .send(&StreamChunk::new(
                flow_id(32),
                FlowDirection::GuestToHost,
                0,
                b"hello".to_vec(),
            ))
            .unwrap();

        let events = connector.drain_events(4).unwrap();
        assert_eq!(
            events,
            vec![HostTcpEvent::Data(StreamChunk::new(
                flow_id(32),
                FlowDirection::HostToGuest,
                0,
                Vec::new(),
            ))]
        );

        connector
            .close(flow_id(32), CloseReason::GuestClosed)
            .unwrap();
        join.join().unwrap();
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_reuses_read_buffer_after_host_response() {
        use std::io::{Read, Write};
        use std::thread;
        use std::time::Duration;

        let Some(listener) = bind_loopback_tcp_listener() else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hello");
            thread::sleep(Duration::from_millis(20));
            stream.write_all(b"world").unwrap();
        });

        let mut connector = StdTcpConnector::with_config(
            StdTcpConnectorConfig::builder()
                .read_timeout(Duration::from_millis(5))
                .build()
                .expect("std tcp connector config is valid"),
        );
        let route = HostRoute::resolved_ip("127.0.0.1".parse().unwrap());
        let target = Target::new("route-should-win.invalid", port).unwrap();
        connector
            .open(&TcpConnectSpec::from_open(
                &OpenTcp::new(flow_id(35), target),
                route,
            ))
            .unwrap();
        connector
            .send(&StreamChunk::new(
                flow_id(35),
                FlowDirection::GuestToHost,
                0,
                b"hello".to_vec(),
            ))
            .unwrap();

        let mut events = Vec::new();
        for _ in 0..100 {
            events = connector.drain_events(4).unwrap();
            if events.iter().any(|event| {
                matches!(
                    event,
                    HostTcpEvent::Data(chunk)
                        if chunk.flow_id == flow_id(35)
                            && chunk.direction == FlowDirection::HostToGuest
                            && chunk.bytes == b"world"
                )
            }) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(events.iter().any(|event| {
            matches!(
                event,
                HostTcpEvent::Data(chunk)
                    if chunk.flow_id == flow_id(35)
                        && chunk.direction == FlowDirection::HostToGuest
                        && chunk.bytes == b"world"
            )
        }));
        assert_eq!(
            connector
                .streams
                .get(&flow_id(35))
                .expect("TCP flow should stay open after a successful reply")
                .read_buffer
                .len(),
            STD_TCP_READ_BUFFER_BYTES
        );

        connector
            .close(flow_id(35), CloseReason::GuestClosed)
            .unwrap();
        join.join().unwrap();
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_close_removes_flow_order_refs_for_closed_flow() {
        use std::thread;

        let Some(listener) = bind_loopback_tcp_listener() else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let mut connector = StdTcpConnector::new();
        let route = HostRoute::resolved_ip("127.0.0.1".parse().unwrap());
        let target = Target::new("route-should-win.invalid", port).unwrap();
        connector
            .open(&TcpConnectSpec::from_open(
                &OpenTcp::new(flow_id(33), target),
                route,
            ))
            .unwrap();
        connector.flow_order.push_back(flow_id(33));

        connector
            .close(flow_id(33), CloseReason::GuestClosed)
            .unwrap();

        assert!(connector.flow_order.is_empty());
        join.join().unwrap();
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_drain_events_prunes_stale_flow_order_refs() {
        let mut connector = StdTcpConnector::new();
        connector.flow_order.push_back(flow_id(34));
        connector.flow_order.push_back(flow_id(34));

        let events = connector.drain_events(4).unwrap();

        assert!(events.is_empty());
        assert!(connector.flow_order.is_empty());
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn std_tcp_connector_defensively_denies_when_open_flow_limit_is_reached() {
        use std::thread;
        use std::time::Duration;

        let Some(listener) = bind_loopback_tcp_listener() else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let _accepted = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(50));
        });

        let mut connector = StdTcpConnector::with_config(
            StdTcpConnectorConfig::builder()
                .read_timeout(Duration::from_millis(5))
                .max_open_flows(1)
                .build()
                .expect("std tcp connector config is valid"),
        );
        let route = HostRoute::resolved_ip("127.0.0.1".parse().unwrap());
        let target = Target::new("route-should-win.invalid", port).unwrap();
        connector
            .open(&TcpConnectSpec::from_open(
                &OpenTcp::new(flow_id(40), target.clone()),
                route,
            ))
            .unwrap();

        assert_eq!(
            connector.open(&TcpConnectSpec::from_open(
                &OpenTcp::new(flow_id(41), target),
                route,
            )),
            Err(TransportError::Refused)
        );
        assert_eq!(connector.open_flow_count(), 1);

        connector
            .close(flow_id(40), CloseReason::HostClosed)
            .unwrap();
        join.join().unwrap();
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn failed_ping_output_classifies_timeout() {
        assert_eq!(
            classify_failed_ping("Request timeout for icmp_seq 0\n100.0% packet loss"),
            IcmpEchoStatus::TimedOut
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn failed_ping_output_classifies_unreachable() {
        assert_eq!(
            classify_failed_ping("ping: cannot resolve bad.example: Unknown host"),
            IcmpEchoStatus::Unreachable
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn failed_ping_output_classifies_timeout_case_insensitively_without_lowercasing() {
        assert_eq!(
            classify_failed_ping("ReQuEsT TiMeOuT for icmp_seq 0\n100.0% PACKET LOSS"),
            IcmpEchoStatus::TimedOut
        );
        assert_eq!(
            classify_failed_ping("ping: sendmsg: Operation TiMeD OuT"),
            IcmpEchoStatus::TimedOut
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn ping_output_detail_combines_stdout_and_stderr_into_one_buffer() {
        use std::os::unix::process::ExitStatusExt;

        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(1),
            stdout: b"stdout detail\n".to_vec(),
            stderr: b"stderr detail".to_vec(),
        };

        assert_eq!(ping_output_detail(&output), "stdout detail\nstderr detail");
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn icmp_ping_target_borrows_hostname_without_upstream_pin() {
        let request = IcmpEchoRequest {
            query_id: query_id(21),
            host: HostName::new("api.example.com").unwrap(),
            payload_len: 56,
        };

        assert_eq!(
            icmp_ping_target(HostRoute::unresolved(), &request),
            Cow::Borrowed("api.example.com")
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn icmp_ping_target_uses_pinned_upstream_ip_when_present() {
        let request = IcmpEchoRequest {
            query_id: query_id(21),
            host: HostName::new("api.example.com").unwrap(),
            payload_len: 56,
        };

        assert_eq!(
            icmp_ping_target(
                HostRoute::resolved_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                &request
            ),
            Cow::<str>::Owned("203.0.113.9".to_string())
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn normalized_ping_detail_truncates_oversized_output() {
        let oversized = "x".repeat(MAX_ICMP_ERROR_DETAIL_BYTES + 1);
        let detail = normalized_ping_detail(oversized).expect("detail should remain present");
        assert_eq!(detail.len(), MAX_ICMP_ERROR_DETAIL_BYTES);
        assert!(detail.chars().all(|ch| ch == 'x'));
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn normalized_ping_detail_preserves_utf8_boundaries_when_truncating() {
        let oversized = "é".repeat(MAX_ICMP_ERROR_DETAIL_BYTES / 2 + 1);
        let detail = normalized_ping_detail(oversized).expect("detail should remain present");
        assert!(detail.len() <= MAX_ICMP_ERROR_DETAIL_BYTES);
        assert!(std::str::from_utf8(detail.as_bytes()).is_ok());
        assert!(detail.chars().all(|ch| ch == 'é'));
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn normalized_ping_detail_trims_in_place_before_clamping() {
        let detail = normalized_ping_detail("  timeout detail  \n".to_string())
            .expect("trimmed detail should remain present");
        assert_eq!(detail, "timeout detail");
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn normalized_ping_detail_preserves_capacity_when_trimming_boundaries() {
        let mut input = String::with_capacity(64);
        input.push_str("  timeout detail  \n");
        let initial_capacity = input.capacity();

        let detail = normalized_ping_detail(input).expect("trimmed detail should remain present");

        assert_eq!(detail, "timeout detail");
        assert_eq!(detail.capacity(), initial_capacity);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn summarize_tls_records_formats_multiple_records_without_vector_join() {
        let bytes = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // handshake empty
            0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x30, // fatal unknown_ca alert
        ];

        let summary = summarize_tls_records(&bytes).expect("TLS record summary");

        assert_eq!(
            summary,
            "handshake(version=0x0303,len=0) alert(version=0x0303,len=2,level=fatal,description=unknown_ca)"
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn summarize_tls_records_limits_summary_to_first_four_records() {
        let bytes = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00,
            0x00, 0x16, 0x03, 0x03, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x00,
        ];

        let summary = summarize_tls_records(&bytes).expect("TLS record summary");

        assert_eq!(summary.matches("handshake(").count(), 4);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn ping_round_trip_parser_handles_reply_and_summary_formats() {
        assert_eq!(
            parse_ping_round_trip_micros(
                "64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.042 ms"
            ),
            Some(42)
        );
        assert_eq!(
            parse_ping_round_trip_micros(
                "round-trip min/avg/max/stddev = 0.042/0.057/0.071/0.000 ms"
            ),
            Some(57)
        );
        assert_eq!(
            parse_ping_round_trip_micros("rtt min/avg/max/mdev = 0.042/0.057/0.071/0.000 ms"),
            Some(57)
        );
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn parse_ping_time_micros_rounds_fourth_fractional_digit_without_float_parse() {
        assert_eq!(parse_ping_time_micros("1.2344 ms"), Some(1234));
        assert_eq!(parse_ping_time_micros("1.2345 ms"), Some(1235));
        assert_eq!(parse_ping_time_micros("7ms"), Some(7000));
        assert_eq!(parse_ping_time_micros("bad"), None);
    }

    #[cfg(feature = "host-std")]
    #[test]
    fn merge_detail_preserves_left_buffer_when_capacity_is_sufficient() {
        let mut left = String::with_capacity(16);
        left.push_str("tls");
        let initial_ptr = left.as_ptr();

        let merged = merge_detail(Some(left), Some("audit".to_string())).expect("merged detail");

        assert_eq!(merged, "tls; audit");
        assert_eq!(merged.as_ptr(), initial_ptr);
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
