//! Versioned messages for the guest-to-host networking channel.

use std::fmt;
use std::net::IpAddr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};

pub const PROTOCOL_MAGIC: &str = "mvm.net";
pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };
pub const MAX_STREAM_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_ENDPOINT_CAPABILITIES: usize = 8;
pub const MAX_TLS_TRANSFORM_ALPN_PROTOCOLS: usize = 8;
pub const MAX_TLS_TRANSFORM_CHAIN_ENTRIES: usize = 8;
pub const MAX_HOST_NAME_BYTES: usize = 255;
pub const MAX_DNS_NAME_BYTES: usize = 253;
pub const MAX_DNS_RESPONSE_ANSWERS: usize = 64;
pub const MAX_DNS_TXT_RECORD_BYTES: usize = 255;
pub const MAX_DNS_TTL_SECONDS: u32 = 30;
pub const MAX_CORRELATION_ID_BYTES: usize = 128;
pub const MAX_TRACE_ID_BYTES: usize = 128;
pub const MAX_SPAN_ID_BYTES: usize = 128;
pub const MAX_POLICY_DIGEST_BYTES: usize = 128;
pub const MAX_PLUGIN_ID_BYTES: usize = 64;
pub const MAX_ALPN_PROTOCOL_BYTES: usize = 255;
pub const MAX_DENIAL_SAFE_DETAIL_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    BadMagic {
        received: String,
    },
    IncompatibleVersion {
        received: ProtocolVersion,
    },
    TooManyCapabilities {
        field: &'static str,
        count: usize,
        max: usize,
    },
    TooManyItems {
        field: &'static str,
        count: usize,
        max: usize,
    },
    ValueTooLong {
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    EmptyHost,
    EmptyName,
    EmptyValue {
        field: &'static str,
    },
    ZeroPort,
    ZeroId,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic { received } => {
                write!(f, "unsupported mvm-net protocol magic {received:?}")
            }
            Self::IncompatibleVersion { received } => {
                write!(
                    f,
                    "unsupported mvm-net protocol version {}.{}",
                    received.major, received.minor
                )
            }
            Self::TooManyCapabilities { field, count, max } => {
                write!(f, "{field} has {count} entries; maximum is {max}")
            }
            Self::TooManyItems { field, count, max } => {
                write!(f, "{field} has {count} entries; maximum is {max}")
            }
            Self::ValueTooLong { field, bytes, max } => {
                write!(f, "{field} is {bytes} bytes; maximum is {max}")
            }
            Self::InvalidValue { field, reason } => {
                write!(f, "{field} is invalid: {reason}")
            }
            Self::EmptyHost => write!(f, "network target host cannot be empty"),
            Self::EmptyName => write!(f, "DNS name cannot be empty"),
            Self::EmptyValue { field } => write!(f, "{field} cannot be empty"),
            Self::ZeroPort => write!(f, "network target port cannot be zero"),
            Self::ZeroId => write!(f, "protocol identifiers cannot be zero"),
        }
    }
}

impl std::error::Error for ProtocolError {}

fn validate_max_len(value: &str, field: &'static str, max: usize) -> Result<(), ProtocolError> {
    if value.len() > max {
        return Err(ProtocolError::ValueTooLong {
            field,
            bytes: value.len(),
            max,
        });
    }
    Ok(())
}

fn validate_max_bytes(bytes: &[u8], field: &'static str, max: usize) -> Result<(), ProtocolError> {
    if bytes.len() > max {
        return Err(ProtocolError::ValueTooLong {
            field,
            bytes: bytes.len(),
            max,
        });
    }
    Ok(())
}

fn trim_non_empty(value: impl Into<String>, field: &'static str) -> Result<String, ProtocolError> {
    let value = value.into().trim().to_string();
    if value.is_empty() {
        return Err(ProtocolError::EmptyValue { field });
    }
    Ok(value)
}

fn trim_non_empty_bounded(
    value: impl Into<String>,
    field: &'static str,
    max: usize,
) -> Result<String, ProtocolError> {
    let value = trim_non_empty(value, field)?;
    validate_max_len(&value, field, max)?;
    Ok(value)
}

fn truncate_to_char_boundary(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }

    let mut end = 0usize;
    for (index, ch) in value.char_indices() {
        let next = index + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    value[..end].to_string()
}

fn canonical_host(value: impl Into<String>) -> Result<String, ProtocolError> {
    let value = value
        .into()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if value.is_empty() {
        return Err(ProtocolError::EmptyHost);
    }
    validate_max_len(&value, "host", MAX_HOST_NAME_BYTES)?;
    Ok(value)
}

fn canonical_dns_name(value: impl Into<String>) -> Result<String, ProtocolError> {
    let value = value
        .into()
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if value.is_empty() {
        return Err(ProtocolError::EmptyName);
    }
    validate_max_len(&value, "DNS name", MAX_DNS_NAME_BYTES)?;
    validate_dns_name_labels(&value, "DNS name")?;
    Ok(value)
}

fn validate_dns_name_labels(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    for label in value.split('.') {
        if label.is_empty() {
            return Err(ProtocolError::InvalidValue {
                field,
                reason: "DNS labels must not be empty",
            });
        }
        if label.len() > 63 {
            return Err(ProtocolError::InvalidValue {
                field,
                reason: "DNS labels must be 63 bytes or shorter",
            });
        }
    }
    Ok(())
}

fn validate_capability_count(
    capabilities: &[Capability],
    field: &'static str,
) -> Result<(), ProtocolError> {
    if capabilities.len() > MAX_ENDPOINT_CAPABILITIES {
        return Err(ProtocolError::TooManyCapabilities {
            field,
            count: capabilities.len(),
            max: MAX_ENDPOINT_CAPABILITIES,
        });
    }
    Ok(())
}

fn validate_item_count<T>(
    items: &[T],
    field: &'static str,
    max: usize,
) -> Result<(), ProtocolError> {
    if items.len() > max {
        return Err(ProtocolError::TooManyItems {
            field,
            count: items.len(),
            max,
        });
    }
    Ok(())
}

#[cfg(feature = "serde")]
macro_rules! impl_string_newtype_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub fn is_compatible_with(self, other: Self) -> bool {
        self.major == CURRENT_VERSION.major && self.major == other.major
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Hello {
    pub magic: String,
    pub version: ProtocolVersion,
    pub role: EndpointRole,
    pub capabilities: Vec<Capability>,
}

impl Hello {
    pub fn new(role: EndpointRole, capabilities: Vec<Capability>) -> Self {
        Self {
            magic: PROTOCOL_MAGIC.to_string(),
            version: CURRENT_VERSION,
            role,
            capabilities,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::BadMagic {
                received: self.magic.clone(),
            });
        }
        if !self.version.is_compatible_with(CURRENT_VERSION) {
            return Err(ProtocolError::IncompatibleVersion {
                received: self.version,
            });
        }
        validate_capability_count(&self.capabilities, "hello capabilities")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct HelloAck {
    pub version: ProtocolVersion,
    pub accepted_capabilities: Vec<Capability>,
}

impl HelloAck {
    pub fn new(accepted_capabilities: Vec<Capability>) -> Self {
        Self {
            version: CURRENT_VERSION,
            accepted_capabilities,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if !self.version.is_compatible_with(CURRENT_VERSION) {
            return Err(ProtocolError::IncompatibleVersion {
                received: self.version,
            });
        }
        validate_capability_count(&self.accepted_capabilities, "hello-ack capabilities")?;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EndpointRole {
    Guest,
    Host,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Capability {
    Dns,
    Tcp,
    Udp,
    IcmpEcho,
    TlsTransform,
    StreamTransforms,
    AuditCorrelation,
    PolicyDigest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct FlowId(u64);

impl FlowId {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        NonZeroProtocolId::new(value).map(|id| Self(id.get()))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[cfg(feature = "serde")]
impl Serialize for FlowId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for FlowId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct QueryId(u64);

impl QueryId {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        NonZeroProtocolId::new(value).map(|id| Self(id.get()))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[cfg(feature = "serde")]
impl Serialize for QueryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for QueryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct NonZeroProtocolId(u64);

impl NonZeroProtocolId {
    fn new(value: u64) -> Result<Self, ProtocolError> {
        if value == 0 {
            return Err(ProtocolError::ZeroId);
        }
        Ok(Self(value))
    }

    const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostName(String);

impl HostName {
    pub fn new(host: impl Into<String>) -> Result<Self, ProtocolError> {
        canonical_host(host).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(HostName);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName(String);

impl DnsName {
    pub fn new(name: impl Into<String>) -> Result<Self, ProtocolError> {
        canonical_dns_name(name).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(DnsName);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CorrelationId(String);

impl CorrelationId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        trim_non_empty_bounded(value, "correlation id", MAX_CORRELATION_ID_BYTES).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(CorrelationId);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TraceId(String);

impl TraceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        trim_non_empty_bounded(value, "trace id", MAX_TRACE_ID_BYTES).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(TraceId);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpanId(String);

impl SpanId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        trim_non_empty_bounded(value, "span id", MAX_SPAN_ID_BYTES).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(SpanId);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyDigest(String);

impl PolicyDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        trim_non_empty_bounded(value, "policy digest", MAX_POLICY_DIGEST_BYTES).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(PolicyDigest);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PluginId(String);

impl PluginId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        trim_non_empty_bounded(value, "plugin id", MAX_PLUGIN_ID_BYTES).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(PluginId);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlpnProtocol(String);

impl AlpnProtocol {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        trim_non_empty_bounded(value, "ALPN protocol", MAX_ALPN_PROTOCOL_BYTES).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl_string_newtype_serde!(AlpnProtocol);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    host: HostName,
    port: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ProtocolError> {
        if port == 0 {
            return Err(ProtocolError::ZeroPort);
        }
        Ok(Self {
            host: HostName::new(host)?,
            port,
        })
    }

    pub fn host(&self) -> &str {
        self.host.as_str()
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn host_and_port(&self) -> (&str, u16) {
        (self.host(), self.port)
    }

    pub fn into_host_and_port(self) -> (String, u16) {
        (self.host.into_string(), self.port)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Target {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Target", 2)?;
        state.serialize_field("host", self.host())?;
        state.serialize_field("port", &self.port())?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Target {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireTarget {
            host: String,
            port: u16,
        }

        let wire = WireTarget::deserialize(deserializer)?;
        Self::new(wire.host, wire.port).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub parent_span_id: Option<SpanId>,
}

impl TraceContext {
    pub fn new(trace_id: TraceId, span_id: SpanId) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: None,
        }
    }

    pub fn with_parent_span_id(mut self, parent_span_id: SpanId) -> Self {
        self.parent_span_id = Some(parent_span_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct FrameMeta {
    pub correlation_id: CorrelationId,
    pub policy_digest: PolicyDigest,
    pub trace: Option<TraceContext>,
}

impl FrameMeta {
    pub fn new(correlation_id: CorrelationId, policy_digest: PolicyDigest) -> Self {
        Self {
            correlation_id,
            policy_digest,
            trace: None,
        }
    }

    pub fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = Some(trace);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct NetFrame {
    pub meta: FrameMeta,
    pub message: NetMessage,
}

impl NetFrame {
    pub fn new(meta: FrameMeta, message: NetMessage) -> Self {
        Self { meta, message }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum NetMessage {
    Hello(Hello),
    HelloAck(HelloAck),
    OpenTcp(OpenTcp),
    TcpOpenResult(TcpOpenResult),
    TcpData(StreamChunk),
    CloseFlow(CloseFlow),
    DnsQuery(DnsQuery),
    DnsResponse(DnsResponse),
    UdpDatagram(UdpDatagram),
    UdpDelivery(UdpDelivery),
    IcmpEchoRequest(IcmpEchoRequest),
    IcmpEchoResponse(IcmpEchoResponse),
}

impl NetMessage {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Hello(hello) => hello.validate(),
            Self::HelloAck(ack) => ack.validate(),
            Self::OpenTcp(open) => open.validate(),
            Self::TcpData(chunk) => chunk.validate(),
            Self::DnsResponse(response) => response.validate(),
            Self::UdpDatagram(datagram) => datagram.validate(),
            Self::TcpOpenResult(_)
            | Self::CloseFlow(_)
            | Self::DnsQuery(_)
            | Self::UdpDelivery(_)
            | Self::IcmpEchoRequest(_)
            | Self::IcmpEchoResponse(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct OpenTcp {
    pub flow_id: FlowId,
    pub target: Target,
    pub tls_policy: TlsPolicy,
    pub tls_transform: Option<TlsTransformRoute>,
}

impl OpenTcp {
    pub fn new(flow_id: FlowId, target: Target) -> Self {
        Self {
            flow_id,
            target,
            tls_policy: TlsPolicy::HostDecision,
            tls_transform: None,
        }
    }

    pub fn with_tls_policy(mut self, tls_policy: TlsPolicy) -> Self {
        self.tls_policy = tls_policy;
        self
    }

    pub fn with_tls_transform(mut self, tls_transform: TlsTransformRoute) -> Self {
        self.tls_policy = TlsPolicy::RequiredForTransform;
        self.tls_transform = Some(tls_transform);
        self
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if let Some(route) = &self.tls_transform {
            route.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlsPolicy {
    HostDecision,
    BypassForOpaqueTcp,
    RequiredForTransform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TlsTransformRoute {
    pub server_name: DnsName,
    pub alpn_protocols: Vec<AlpnProtocol>,
    pub transform_chain: Vec<PluginId>,
    pub termination: TlsTermination,
}

impl TlsTransformRoute {
    pub fn new(server_name: DnsName, termination: TlsTermination) -> Self {
        Self {
            server_name,
            alpn_protocols: Vec::new(),
            transform_chain: Vec::new(),
            termination,
        }
    }

    pub fn with_alpn_protocols(mut self, alpn_protocols: Vec<AlpnProtocol>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    pub fn with_transform_chain(mut self, transform_chain: Vec<PluginId>) -> Self {
        self.transform_chain = transform_chain;
        self
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_item_count(
            &self.alpn_protocols,
            "TLS transform ALPN protocols",
            MAX_TLS_TRANSFORM_ALPN_PROTOCOLS,
        )?;
        validate_item_count(
            &self.transform_chain,
            "TLS transform plugin chain",
            MAX_TLS_TRANSFORM_CHAIN_ENTRIES,
        )?;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlsTermination {
    TerminateAndReoriginate,
    RefusePinnedClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TcpOpenResult {
    pub flow_id: FlowId,
    pub status: FlowOpenStatus,
}

impl TcpOpenResult {
    pub fn opened(flow_id: FlowId) -> Self {
        Self {
            flow_id,
            status: FlowOpenStatus::Opened,
        }
    }

    pub fn denied(flow_id: FlowId, denial: Denial) -> Self {
        Self {
            flow_id,
            status: FlowOpenStatus::Denied(denial),
        }
    }

    pub fn failed(flow_id: FlowId, error: TransportError) -> Self {
        Self {
            flow_id,
            status: FlowOpenStatus::Failed(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FlowOpenStatus {
    Opened,
    Denied(Denial),
    Failed(TransportError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Denial {
    pub reason: DenialReason,
    pub safe_detail: Option<String>,
}

impl Denial {
    pub fn new(reason: DenialReason) -> Self {
        Self {
            reason,
            safe_detail: None,
        }
    }

    pub fn with_safe_detail(mut self, safe_detail: impl Into<String>) -> Self {
        let safe_detail = safe_detail.into().trim().to_string();
        if !safe_detail.is_empty() {
            let clamped = truncate_to_char_boundary(&safe_detail, MAX_DENIAL_SAFE_DETAIL_BYTES);
            self.safe_detail = Some(clamped);
        }
        self
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DenialReason {
    NetworkDisabled,
    HostNotAllowed,
    PortNotAllowed,
    ProtocolNotAllowed,
    TlsRequired,
    TransformRequired,
    RateLimited,
    ResourceLimit,
    PluginDenied,
    InvalidTarget,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransportError {
    DnsFailed,
    TimedOut,
    Refused,
    Unreachable,
    Reset,
    TlsHandshakeFailed,
    ProtocolError,
    TransformError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct StreamChunk {
    pub flow_id: FlowId,
    pub direction: FlowDirection,
    pub sequence: u64,
    pub bytes: Vec<u8>,
    pub end_stream: bool,
}

impl StreamChunk {
    pub fn new(flow_id: FlowId, direction: FlowDirection, sequence: u64, bytes: Vec<u8>) -> Self {
        Self {
            flow_id,
            direction,
            sequence,
            bytes,
            end_stream: false,
        }
    }

    pub fn with_end_stream(mut self) -> Self {
        self.end_stream = true;
        self
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_max_bytes(
            &self.bytes,
            "TCP stream chunk payload",
            MAX_STREAM_CHUNK_BYTES,
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FlowDirection {
    GuestToHost,
    HostToGuest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct CloseFlow {
    pub flow_id: FlowId,
    pub reason: CloseReason,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CloseReason {
    GuestClosed,
    HostClosed,
    PolicyDenied,
    ProtocolError,
    TransformError,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DnsQuery {
    pub query_id: QueryId,
    pub name: DnsName,
    pub record_type: DnsRecordType,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DnsResponse {
    pub query_id: QueryId,
    pub code: DnsResponseCode,
    pub answers: Vec<DnsAnswer>,
    pub denial: Option<Denial>,
}

impl DnsResponse {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_item_count(
            &self.answers,
            "DNS response answers",
            MAX_DNS_RESPONSE_ANSWERS,
        )?;
        for answer in &self.answers {
            answer.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DnsResponseCode {
    Ok,
    NameError,
    Refused,
    ServerFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct DnsAnswer {
    pub name: DnsName,
    pub record_type: DnsRecordType,
    pub data: DnsRecordData,
    pub ttl_seconds: u32,
}

impl DnsAnswer {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.ttl_seconds > MAX_DNS_TTL_SECONDS {
            return Err(ProtocolError::InvalidValue {
                field: "DNS answer TTL",
                reason: "exceeds hard maximum",
            });
        }
        match (&self.record_type, &self.data) {
            (DnsRecordType::A, DnsRecordData::Ip(IpAddr::V4(_)))
            | (DnsRecordType::Aaaa, DnsRecordData::Ip(IpAddr::V6(_)))
            | (DnsRecordType::Cname, DnsRecordData::Cname(_)) => {}
            (DnsRecordType::Txt, DnsRecordData::Txt(value)) => {
                validate_max_len(value, "DNS TXT record", MAX_DNS_TXT_RECORD_BYTES)?;
            }
            _ => {
                return Err(ProtocolError::InvalidValue {
                    field: "DNS answer data",
                    reason: "record type does not match answer data",
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DnsRecordData {
    Ip(IpAddr),
    Cname(DnsName),
    Txt(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct UdpDatagram {
    pub flow_id: FlowId,
    pub target: Target,
    pub direction: FlowDirection,
    pub bytes: Vec<u8>,
}

impl UdpDatagram {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_max_bytes(&self.bytes, "UDP datagram payload", MAX_STREAM_CHUNK_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct UdpDelivery {
    pub flow_id: FlowId,
    pub status: DatagramStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DatagramStatus {
    Delivered,
    Denied(Denial),
    Failed(TransportError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct IcmpEchoRequest {
    pub query_id: QueryId,
    pub host: HostName,
    pub payload_len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct IcmpEchoResponse {
    pub query_id: QueryId,
    pub status: IcmpEchoStatus,
    pub round_trip_micros: Option<u64>,
    pub denial: Option<Denial>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum IcmpEchoStatus {
    Replied,
    Denied,
    TimedOut,
    Unreachable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow_id() -> FlowId {
        FlowId::new(42).unwrap()
    }

    fn target() -> Target {
        Target::new("API.Example.COM.", 443).unwrap()
    }

    #[cfg(feature = "serde")]
    fn query_id() -> QueryId {
        QueryId::new(9).unwrap()
    }

    #[cfg(feature = "serde")]
    fn denial() -> Denial {
        Denial::new(DenialReason::HostNotAllowed).with_safe_detail("host denied by policy")
    }

    #[test]
    fn hello_validates_magic_and_version() {
        let hello = Hello::new(
            EndpointRole::Guest,
            vec![Capability::Dns, Capability::Tcp, Capability::PolicyDigest],
        );
        assert!(hello.validate().is_ok());

        let mut wrong_magic = hello.clone();
        wrong_magic.magic = "other".to_string();
        assert!(matches!(
            wrong_magic.validate(),
            Err(ProtocolError::BadMagic { .. })
        ));

        let mut wrong_version = hello;
        wrong_version.version = ProtocolVersion::new(2, 0);
        assert!(matches!(
            wrong_version.validate(),
            Err(ProtocolError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn hello_ack_validates_version() {
        let ack = HelloAck::new(vec![Capability::Dns]);
        assert!(ack.validate().is_ok());

        let ack = HelloAck {
            version: ProtocolVersion::new(2, 0),
            accepted_capabilities: vec![Capability::Dns],
        };
        assert!(matches!(
            ack.validate(),
            Err(ProtocolError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn hello_rejects_overlong_capability_list() {
        let hello = Hello::new(
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
        );

        assert_eq!(
            hello.validate(),
            Err(ProtocolError::TooManyCapabilities {
                field: "hello capabilities",
                count: 9,
                max: MAX_ENDPOINT_CAPABILITIES,
            })
        );
    }

    #[test]
    fn hello_ack_rejects_overlong_capability_list() {
        let ack = HelloAck::new(vec![
            Capability::Dns,
            Capability::Tcp,
            Capability::Udp,
            Capability::IcmpEcho,
            Capability::TlsTransform,
            Capability::StreamTransforms,
            Capability::AuditCorrelation,
            Capability::PolicyDigest,
            Capability::Dns,
        ]);

        assert_eq!(
            ack.validate(),
            Err(ProtocolError::TooManyCapabilities {
                field: "hello-ack capabilities",
                count: 9,
                max: MAX_ENDPOINT_CAPABILITIES,
            })
        );
    }

    #[test]
    fn protocol_ids_reject_zero() {
        assert_eq!(FlowId::new(0), Err(ProtocolError::ZeroId));
        assert_eq!(QueryId::new(0), Err(ProtocolError::ZeroId));
        assert_eq!(FlowId::new(7).unwrap().get(), 7);
    }

    #[test]
    fn target_rejects_empty_host_and_zero_port() {
        assert_eq!(Target::new(" ", 443), Err(ProtocolError::EmptyHost));
        assert_eq!(Target::new("example.com", 0), Err(ProtocolError::ZeroPort));
        let target = Target::new(" API.Example.COM. ", 443).unwrap();
        assert_eq!(target.host(), "api.example.com");
        assert_eq!(target.port(), 443);
    }

    #[test]
    fn target_exposes_borrowed_and_owned_host_port_views() {
        let target = Target::new(" API.Example.COM. ", 443).unwrap();

        assert_eq!(target.host_and_port(), ("api.example.com", 443));
        assert_eq!(
            target.into_host_and_port(),
            ("api.example.com".to_string(), 443)
        );
    }

    #[test]
    fn dns_names_are_canonicalized_for_policy_matching() {
        let name = DnsName::new("API.Example.COM.").unwrap();
        assert_eq!(name.as_str(), "api.example.com");
    }

    #[test]
    fn target_rejects_overlong_host() {
        let host = "a".repeat(MAX_HOST_NAME_BYTES + 1);
        assert_eq!(
            Target::new(host, 443),
            Err(ProtocolError::ValueTooLong {
                field: "host",
                bytes: MAX_HOST_NAME_BYTES + 1,
                max: MAX_HOST_NAME_BYTES,
            })
        );
    }

    #[test]
    fn dns_name_rejects_overlong_value() {
        let name = "a".repeat(MAX_DNS_NAME_BYTES + 1);
        assert_eq!(
            DnsName::new(name),
            Err(ProtocolError::ValueTooLong {
                field: "DNS name",
                bytes: MAX_DNS_NAME_BYTES + 1,
                max: MAX_DNS_NAME_BYTES,
            })
        );
    }

    #[test]
    fn dns_name_rejects_empty_or_overlong_labels() {
        assert_eq!(
            DnsName::new("example..com"),
            Err(ProtocolError::InvalidValue {
                field: "DNS name",
                reason: "DNS labels must not be empty",
            })
        );

        let label = "a".repeat(64);
        assert_eq!(
            DnsName::new(format!("{label}.com")),
            Err(ProtocolError::InvalidValue {
                field: "DNS name",
                reason: "DNS labels must be 63 bytes or shorter",
            })
        );
    }

    #[test]
    fn identifiers_reject_overlong_values() {
        let correlation = "c".repeat(MAX_CORRELATION_ID_BYTES + 1);
        assert_eq!(
            CorrelationId::new(correlation),
            Err(ProtocolError::ValueTooLong {
                field: "correlation id",
                bytes: MAX_CORRELATION_ID_BYTES + 1,
                max: MAX_CORRELATION_ID_BYTES,
            })
        );

        let trace = "t".repeat(MAX_TRACE_ID_BYTES + 1);
        assert_eq!(
            TraceId::new(trace),
            Err(ProtocolError::ValueTooLong {
                field: "trace id",
                bytes: MAX_TRACE_ID_BYTES + 1,
                max: MAX_TRACE_ID_BYTES,
            })
        );

        let span = "s".repeat(MAX_SPAN_ID_BYTES + 1);
        assert_eq!(
            SpanId::new(span),
            Err(ProtocolError::ValueTooLong {
                field: "span id",
                bytes: MAX_SPAN_ID_BYTES + 1,
                max: MAX_SPAN_ID_BYTES,
            })
        );

        let digest = "d".repeat(MAX_POLICY_DIGEST_BYTES + 1);
        assert_eq!(
            PolicyDigest::new(digest),
            Err(ProtocolError::ValueTooLong {
                field: "policy digest",
                bytes: MAX_POLICY_DIGEST_BYTES + 1,
                max: MAX_POLICY_DIGEST_BYTES,
            })
        );
    }

    #[test]
    fn plugin_and_alpn_identifiers_reject_overlong_values() {
        let plugin = "p".repeat(MAX_PLUGIN_ID_BYTES + 1);
        assert_eq!(
            PluginId::new(plugin),
            Err(ProtocolError::ValueTooLong {
                field: "plugin id",
                bytes: MAX_PLUGIN_ID_BYTES + 1,
                max: MAX_PLUGIN_ID_BYTES,
            })
        );

        let alpn = "a".repeat(MAX_ALPN_PROTOCOL_BYTES + 1);
        assert_eq!(
            AlpnProtocol::new(alpn),
            Err(ProtocolError::ValueTooLong {
                field: "ALPN protocol",
                bytes: MAX_ALPN_PROTOCOL_BYTES + 1,
                max: MAX_ALPN_PROTOCOL_BYTES,
            })
        );
    }

    #[test]
    fn frame_meta_carries_audit_correlation() {
        let meta = FrameMeta::new(
            CorrelationId::new("flow-open-1").unwrap(),
            PolicyDigest::new("sha256:abc").unwrap(),
        )
        .with_trace(
            TraceContext::new(
                TraceId::new("trace-1").unwrap(),
                SpanId::new("span-2").unwrap(),
            )
            .with_parent_span_id(SpanId::new("span-1").unwrap()),
        );

        assert_eq!(meta.correlation_id.as_str(), "flow-open-1");
        assert_eq!(meta.policy_digest.as_str(), "sha256:abc");
        assert_eq!(
            meta.trace
                .as_ref()
                .and_then(|trace| trace.parent_span_id.as_ref())
                .map(SpanId::as_str),
            Some("span-1")
        );
    }

    #[test]
    fn tcp_open_can_route_tls_transform_chain() {
        let route = TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        )
        .with_alpn_protocols(vec![AlpnProtocol::new("h2").unwrap()])
        .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]);
        let open = OpenTcp::new(flow_id(), target()).with_tls_transform(route);

        assert_eq!(open.tls_policy, TlsPolicy::RequiredForTransform);
        assert_eq!(
            open.tls_transform
                .as_ref()
                .and_then(|route| route.transform_chain.first())
                .map(PluginId::as_str),
            Some("secret-replacement")
        );
        assert!(open.validate().is_ok());
    }

    #[test]
    fn tls_transform_route_rejects_overlong_alpn_list() {
        let route = TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        )
        .with_alpn_protocols(
            (0..(MAX_TLS_TRANSFORM_ALPN_PROTOCOLS + 1))
                .map(|index| AlpnProtocol::new(format!("proto-{index}")).unwrap())
                .collect(),
        );

        assert_eq!(
            route.validate(),
            Err(ProtocolError::TooManyItems {
                field: "TLS transform ALPN protocols",
                count: MAX_TLS_TRANSFORM_ALPN_PROTOCOLS + 1,
                max: MAX_TLS_TRANSFORM_ALPN_PROTOCOLS,
            })
        );
    }

    #[test]
    fn tls_transform_route_rejects_overlong_transform_chain() {
        let route = TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        )
        .with_transform_chain(
            (0..(MAX_TLS_TRANSFORM_CHAIN_ENTRIES + 1))
                .map(|index| PluginId::new(format!("plugin-{index}")).unwrap())
                .collect(),
        );

        assert_eq!(
            route.validate(),
            Err(ProtocolError::TooManyItems {
                field: "TLS transform plugin chain",
                count: MAX_TLS_TRANSFORM_CHAIN_ENTRIES + 1,
                max: MAX_TLS_TRANSFORM_CHAIN_ENTRIES,
            })
        );
    }

    #[test]
    fn stream_chunk_rejects_overlong_payload() {
        let chunk = StreamChunk::new(
            flow_id(),
            FlowDirection::GuestToHost,
            0,
            vec![0; MAX_STREAM_CHUNK_BYTES + 1],
        );

        assert_eq!(
            chunk.validate(),
            Err(ProtocolError::ValueTooLong {
                field: "TCP stream chunk payload",
                bytes: MAX_STREAM_CHUNK_BYTES + 1,
                max: MAX_STREAM_CHUNK_BYTES,
            })
        );
        assert_eq!(
            NetMessage::TcpData(chunk).validate(),
            Err(ProtocolError::ValueTooLong {
                field: "TCP stream chunk payload",
                bytes: MAX_STREAM_CHUNK_BYTES + 1,
                max: MAX_STREAM_CHUNK_BYTES,
            })
        );
    }

    #[test]
    fn udp_datagram_rejects_overlong_payload() {
        let datagram = UdpDatagram {
            flow_id: flow_id(),
            target: target(),
            direction: FlowDirection::GuestToHost,
            bytes: vec![0; MAX_STREAM_CHUNK_BYTES + 1],
        };

        assert_eq!(
            datagram.validate(),
            Err(ProtocolError::ValueTooLong {
                field: "UDP datagram payload",
                bytes: MAX_STREAM_CHUNK_BYTES + 1,
                max: MAX_STREAM_CHUNK_BYTES,
            })
        );
        assert_eq!(
            NetMessage::UdpDatagram(datagram).validate(),
            Err(ProtocolError::ValueTooLong {
                field: "UDP datagram payload",
                bytes: MAX_STREAM_CHUNK_BYTES + 1,
                max: MAX_STREAM_CHUNK_BYTES,
            })
        );
    }

    #[test]
    fn dns_response_rejects_overlong_answer_list() {
        let response = DnsResponse {
            query_id: QueryId::new(9).unwrap(),
            code: DnsResponseCode::Ok,
            answers: (0..(MAX_DNS_RESPONSE_ANSWERS + 1))
                .map(|_| DnsAnswer {
                    name: DnsName::new("example.com").unwrap(),
                    record_type: DnsRecordType::A,
                    data: DnsRecordData::Ip(IpAddr::V4("198.19.0.2".parse().unwrap())),
                    ttl_seconds: 30,
                })
                .collect(),
            denial: None,
        };

        assert_eq!(
            response.validate(),
            Err(ProtocolError::TooManyItems {
                field: "DNS response answers",
                count: MAX_DNS_RESPONSE_ANSWERS + 1,
                max: MAX_DNS_RESPONSE_ANSWERS,
            })
        );
    }

    #[test]
    fn dns_txt_record_rejects_overlong_value() {
        let response = DnsResponse {
            query_id: QueryId::new(9).unwrap(),
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name: DnsName::new("example.com").unwrap(),
                record_type: DnsRecordType::Txt,
                data: DnsRecordData::Txt("x".repeat(MAX_DNS_TXT_RECORD_BYTES + 1)),
                ttl_seconds: 30,
            }],
            denial: None,
        };

        assert_eq!(
            response.validate(),
            Err(ProtocolError::ValueTooLong {
                field: "DNS TXT record",
                bytes: MAX_DNS_TXT_RECORD_BYTES + 1,
                max: MAX_DNS_TXT_RECORD_BYTES,
            })
        );
    }

    #[test]
    fn dns_answer_rejects_record_type_mismatch() {
        let response = DnsResponse {
            query_id: QueryId::new(9).unwrap(),
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name: DnsName::new("example.com").unwrap(),
                record_type: DnsRecordType::A,
                data: DnsRecordData::Txt("not-an-ip".to_string()),
                ttl_seconds: 30,
            }],
            denial: None,
        };

        assert_eq!(
            response.validate(),
            Err(ProtocolError::InvalidValue {
                field: "DNS answer data",
                reason: "record type does not match answer data",
            })
        );
    }

    #[test]
    fn dns_answer_rejects_oversized_ttl() {
        let response = DnsResponse {
            query_id: QueryId::new(9).unwrap(),
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name: DnsName::new("example.com").unwrap(),
                record_type: DnsRecordType::A,
                data: DnsRecordData::Ip(IpAddr::V4("198.19.0.2".parse().unwrap())),
                ttl_seconds: MAX_DNS_TTL_SECONDS + 1,
            }],
            denial: None,
        };

        assert_eq!(
            response.validate(),
            Err(ProtocolError::InvalidValue {
                field: "DNS answer TTL",
                reason: "exceeds hard maximum",
            })
        );
    }

    #[test]
    fn denial_details_are_trimmed_and_empty_details_ignored() {
        let empty = Denial::new(DenialReason::NetworkDisabled).with_safe_detail(" ");
        assert_eq!(empty.safe_detail, None);

        let detailed = Denial::new(DenialReason::HostNotAllowed).with_safe_detail(" denied ");
        assert_eq!(detailed.safe_detail.as_deref(), Some("denied"));

        let overlong = Denial::new(DenialReason::HostNotAllowed)
            .with_safe_detail("x".repeat(MAX_DENIAL_SAFE_DETAIL_BYTES + 1));
        assert_eq!(
            overlong.safe_detail.as_ref().map(String::len),
            Some(MAX_DENIAL_SAFE_DETAIL_BYTES)
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn net_frame_roundtrips_through_json() {
        let meta = FrameMeta::new(
            CorrelationId::new("corr-1").unwrap(),
            PolicyDigest::new("sha256:policy").unwrap(),
        );
        let msg = NetMessage::OpenTcp(
            OpenTcp::new(flow_id(), target()).with_tls_transform(
                TlsTransformRoute::new(
                    DnsName::new("api.example.com").unwrap(),
                    TlsTermination::TerminateAndReoriginate,
                )
                .with_alpn_protocols(vec![AlpnProtocol::new("http/1.1").unwrap()])
                .with_transform_chain(vec![PluginId::new("audit").unwrap()]),
            ),
        );
        let frame = NetFrame::new(meta, msg);

        let json = serde_json::to_string(&frame).unwrap();
        let decoded: NetFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn dns_response_roundtrips_ip_answers() {
        let response = NetMessage::DnsResponse(DnsResponse {
            query_id: query_id(),
            code: DnsResponseCode::Ok,
            answers: vec![DnsAnswer {
                name: DnsName::new("google.com").unwrap(),
                record_type: DnsRecordType::A,
                data: DnsRecordData::Ip("142.250.72.14".parse().unwrap()),
                ttl_seconds: MAX_DNS_TTL_SECONDS,
            }],
            denial: None,
        });
        let json = serde_json::to_string(&response).unwrap();
        let decoded: NetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn tcp_udp_icmp_families_roundtrip_through_json() {
        let messages = vec![
            NetMessage::TcpOpenResult(TcpOpenResult::denied(flow_id(), denial())),
            NetMessage::TcpData(StreamChunk::new(
                flow_id(),
                FlowDirection::GuestToHost,
                1,
                b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            )),
            NetMessage::CloseFlow(CloseFlow {
                flow_id: flow_id(),
                reason: CloseReason::HostClosed,
            }),
            NetMessage::UdpDatagram(UdpDatagram {
                flow_id: flow_id(),
                target: Target::new("dns.example.com", 53).unwrap(),
                direction: FlowDirection::GuestToHost,
                bytes: vec![1, 2, 3],
            }),
            NetMessage::UdpDelivery(UdpDelivery {
                flow_id: flow_id(),
                status: DatagramStatus::Delivered,
            }),
            NetMessage::IcmpEchoRequest(IcmpEchoRequest {
                query_id: query_id(),
                host: HostName::new("Google.COM.").unwrap(),
                payload_len: 56,
            }),
            NetMessage::IcmpEchoResponse(IcmpEchoResponse {
                query_id: query_id(),
                status: IcmpEchoStatus::Denied,
                round_trip_micros: None,
                denial: Some(denial()),
            }),
        ];

        for message in messages {
            let json = serde_json::to_string(&message).unwrap();
            let decoded: NetMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, message);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_rejects_invalid_invariant_types() {
        assert!(serde_json::from_str::<FlowId>("0").is_err());
        assert!(serde_json::from_str::<QueryId>("0").is_err());
        assert!(serde_json::from_str::<HostName>(r#""""#).is_err());
        assert!(serde_json::from_str::<DnsName>(r#""""#).is_err());
        assert!(serde_json::from_str::<CorrelationId>(r#""""#).is_err());
        assert!(serde_json::from_str::<TraceId>(r#""""#).is_err());
        assert!(serde_json::from_str::<SpanId>(r#""""#).is_err());
        assert!(serde_json::from_str::<PolicyDigest>(r#""""#).is_err());
        assert!(serde_json::from_str::<PluginId>(r#""""#).is_err());
        assert!(serde_json::from_str::<AlpnProtocol>(r#""""#).is_err());
        assert!(serde_json::from_str::<Target>(r#"{"host":"","port":443}"#).is_err());
        assert!(serde_json::from_str::<Target>(r#"{"host":"example.com","port":0}"#).is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_rejects_unknown_fields_by_message_family() {
        assert!(
            serde_json::from_str::<NetFrame>(
                r#"{
                    "meta":{"correlation_id":"c","policy_digest":"p","trace":null},
                    "message":{"Hello":{"magic":"mvm.net","version":{"major":1,"minor":0},"role":"Guest","capabilities":[]}},
                    "extra":true
                }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<OpenTcp>(
                r#"{
                    "flow_id":1,
                    "target":{"host":"example.com","port":443},
                    "tls_policy":"HostDecision",
                    "tls_transform":null,
                    "extra":true
                }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<DnsQuery>(
                r#"{"query_id":1,"name":"example.com","record_type":"A","extra":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<UdpDatagram>(
                r#"{
                    "flow_id":1,
                    "target":{"host":"example.com","port":53},
                    "direction":"GuestToHost",
                    "bytes":[1],
                    "extra":true
                }"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<IcmpEchoRequest>(
                r#"{"query_id":1,"host":"example.com","payload_len":56,"extra":true}"#
            )
            .is_err()
        );
    }
}
