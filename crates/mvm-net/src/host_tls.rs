use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::fmt;
#[cfg(any(not(feature = "host-tls-boring"), test))]
use std::io::Cursor;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;

#[cfg(feature = "host-tls-boring")]
use boring::pkey::{PKey, Private};
#[cfg(feature = "host-tls-boring")]
use boring::ssl::{
    ErrorCode as BoringErrorCode, HandshakeError as BoringHandshakeError, MidHandshakeSslStream,
    ShutdownResult, Ssl, SslAcceptor, SslMethod, SslStream, SslStreamBuilder, SslVerifyMode,
    SslVersion,
};
#[cfg(feature = "host-tls-boring")]
use boring::x509::X509;
use mvm_core::crypto::egress_ca::VmIntermediate;
#[cfg(any(not(feature = "host-tls-boring"), test))]
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::host::{
    DEFAULT_MAX_OPEN_FLOWS, GuestChunkAction, GuestStreamTracker, HostTcpConnector, HostTcpEvent,
    MAX_OPEN_FLOWS, StdTcpConnectorConfig, TcpConnectSpec, connect_target_with_config,
    map_tcp_io_error, summarize_tls_records,
};
use crate::proto::{
    CloseFlow, CloseReason, DnsName, FlowDirection, FlowId, PluginId, StreamChunk, TlsTermination,
    TransportError,
};
use crate::stream_transform::{
    StreamTransformChain, StreamTransformConfig, StreamTransformDirection,
};

const TLS_READ_BUFFER_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_PENDING_GUEST_TLS_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_TLS_FLOW_DETAIL_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_RETAINED_TLS_FLOW_DETAILS: usize = DEFAULT_MAX_OPEN_FLOWS;
pub const MAX_PENDING_GUEST_TLS_BYTES: usize = DEFAULT_MAX_PENDING_GUEST_TLS_BYTES;
pub const MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES: usize =
    DEFAULT_MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES;
pub const MAX_TLS_FLOW_DETAIL_BYTES: usize = DEFAULT_MAX_TLS_FLOW_DETAIL_BYTES;
pub const MAX_RETAINED_TLS_FLOW_DETAILS: usize = DEFAULT_MAX_RETAINED_TLS_FLOW_DETAILS;
const GUEST_TLS_BACKLOG_EXCEEDED_DETAIL: &str =
    "guest-facing TLS backlog exceeded configured pending-byte budget";
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const TLS_HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0b;
const TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE: u8 = 0x0c;
const TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST: u8 = 0x0d;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE: u8 = 0x0e;
const MAX_CLIENT_HELLO_SUMMARY_LIST_VALUES: usize = 8;
const MAX_CLIENT_HELLO_SUMMARY_SNI_BYTES: usize = 256;
pub const MAX_UPSTREAM_ROOT_PEM_BYTES: usize = 1024 * 1024;
pub const MAX_UPSTREAM_ROOT_CERTIFICATES: usize = 256;
pub const MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES: usize = 256 * 1024;
pub const MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES: usize = 64 * 1024;
pub const MAX_GUEST_INTERMEDIATE_CERTIFICATES: usize = 8;
const MAX_USIZE_DECIMAL_DIGITS: usize = usize::MAX.ilog10() as usize + 1;

type GuestTlsTextError = Cow<'static, str>;
type HostTlsConfigText = Cow<'static, str>;

const fn initial_tls_buffer_capacity(max_pending_bytes: usize) -> usize {
    if max_pending_bytes < TLS_READ_BUFFER_BYTES {
        max_pending_bytes
    } else {
        TLS_READ_BUFFER_BYTES
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct HostTlsIntermediate {
    cert_pem: String,
    key_pem: String,
}

impl HostTlsIntermediate {
    pub fn new(cert_pem: impl Into<String>, key_pem: impl Into<String>) -> Self {
        Self {
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
        }
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
}

impl fmt::Debug for HostTlsIntermediate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostTlsIntermediate")
            .field("cert_pem", &"<intermediate cert>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HostTlsUpstreamRoots {
    #[default]
    Native,
    PemBundle(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostTlsConfigError {
    MissingGuestIntermediate,
    MissingUpstreamRoots,
    EmptyGuestIntermediateCert,
    EmptyGuestIntermediateKey,
    GuestIntermediateCertPemTooLarge { actual: usize, max: usize },
    GuestIntermediateKeyPemTooLarge { actual: usize, max: usize },
    TooManyGuestIntermediateCertificates { actual: usize, max: usize },
    EmptyUpstreamRootPem,
    UpstreamRootPemTooLarge { actual: usize, max: usize },
    TooManyUpstreamRootCertificates { actual: usize, max: usize },
    InvalidStreamTransformConfig(String),
    ZeroMaxOpenFlows,
    MaxOpenFlowsTooLarge { actual: usize, max: usize },
    ZeroMaxPendingGuestTlsBytes,
    MaxPendingGuestTlsBytesTooLarge { actual: usize, max: usize },
    ZeroMaxPendingUpstreamTlsPlaintextBytes,
    MaxPendingUpstreamTlsPlaintextBytesTooLarge { actual: usize, max: usize },
    ZeroMaxTlsFlowDetailBytes,
    MaxTlsFlowDetailBytesTooLarge { actual: usize, max: usize },
    ZeroMaxRetainedTlsFlowDetails,
    MaxRetainedTlsFlowDetailsTooLarge { actual: usize, max: usize },
    InvalidGuestIntermediate(HostTlsConfigText),
    InvalidUpstreamRoots(HostTlsConfigText),
    NativeRootLoad(HostTlsConfigText),
}

impl fmt::Display for HostTlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingGuestIntermediate => write!(f, "guest TLS intermediate is required"),
            Self::MissingUpstreamRoots => {
                write!(f, "upstream TLS roots must be configured explicitly")
            }
            Self::EmptyGuestIntermediateCert => {
                write!(f, "guest TLS intermediate certificate must not be empty")
            }
            Self::EmptyGuestIntermediateKey => {
                write!(f, "guest TLS intermediate private key must not be empty")
            }
            Self::GuestIntermediateCertPemTooLarge { actual, max } => {
                write!(
                    f,
                    "guest TLS intermediate certificate PEM exceeds byte budget ({actual} > {max})"
                )
            }
            Self::GuestIntermediateKeyPemTooLarge { actual, max } => {
                write!(
                    f,
                    "guest TLS intermediate private key PEM exceeds byte budget ({actual} > {max})"
                )
            }
            Self::TooManyGuestIntermediateCertificates { actual, max } => {
                write!(
                    f,
                    "guest TLS intermediate certificate chain exceeds certificate budget ({actual} > {max})"
                )
            }
            Self::EmptyUpstreamRootPem => {
                write!(f, "upstream TLS root PEM bundle must not be empty")
            }
            Self::UpstreamRootPemTooLarge { actual, max } => {
                write!(
                    f,
                    "upstream TLS root PEM bundle exceeds byte budget ({actual} > {max})"
                )
            }
            Self::TooManyUpstreamRootCertificates { actual, max } => {
                write!(
                    f,
                    "upstream TLS root PEM bundle exceeds certificate budget ({actual} > {max})"
                )
            }
            Self::InvalidStreamTransformConfig(reason) => {
                write!(f, "invalid TLS stream transform config: {reason}")
            }
            Self::ZeroMaxOpenFlows => write!(f, "max open flows must be non-zero"),
            Self::MaxOpenFlowsTooLarge { actual, max } => {
                write!(
                    f,
                    "max open flows exceeds the hard maximum ({actual} > {max})"
                )
            }
            Self::ZeroMaxPendingGuestTlsBytes => {
                write!(f, "max pending guest TLS bytes must be non-zero")
            }
            Self::MaxPendingGuestTlsBytesTooLarge { actual, max } => {
                write!(
                    f,
                    "max pending guest TLS bytes exceeds the hard maximum ({actual} > {max})"
                )
            }
            Self::ZeroMaxPendingUpstreamTlsPlaintextBytes => {
                write!(
                    f,
                    "max pending upstream TLS plaintext bytes must be non-zero"
                )
            }
            Self::MaxPendingUpstreamTlsPlaintextBytesTooLarge { actual, max } => {
                write!(
                    f,
                    "max pending upstream TLS plaintext bytes exceeds the hard maximum ({actual} > {max})"
                )
            }
            Self::ZeroMaxTlsFlowDetailBytes => {
                write!(f, "max TLS flow detail bytes must be non-zero")
            }
            Self::MaxTlsFlowDetailBytesTooLarge { actual, max } => {
                write!(
                    f,
                    "max TLS flow detail bytes exceeds the hard maximum ({actual} > {max})"
                )
            }
            Self::ZeroMaxRetainedTlsFlowDetails => {
                write!(f, "max retained TLS flow details must be non-zero")
            }
            Self::MaxRetainedTlsFlowDetailsTooLarge { actual, max } => {
                write!(
                    f,
                    "max retained TLS flow details exceeds the hard maximum ({actual} > {max})"
                )
            }
            Self::InvalidGuestIntermediate(reason) => {
                write!(f, "invalid guest TLS intermediate: {reason}")
            }
            Self::InvalidUpstreamRoots(reason) => {
                write!(f, "invalid upstream TLS roots: {reason}")
            }
            Self::NativeRootLoad(reason) => {
                write!(f, "failed to configure native TLS verifier: {reason}")
            }
        }
    }
}

impl std::error::Error for HostTlsConfigError {}

fn invalid_guest_intermediate_owned(err: impl fmt::Display) -> HostTlsConfigError {
    HostTlsConfigError::InvalidGuestIntermediate(HostTlsConfigText::Owned(err.to_string()))
}

fn invalid_guest_intermediate_borrowed(detail: &'static str) -> HostTlsConfigError {
    HostTlsConfigError::InvalidGuestIntermediate(HostTlsConfigText::Borrowed(detail))
}

fn invalid_upstream_roots_owned(err: impl fmt::Display) -> HostTlsConfigError {
    HostTlsConfigError::InvalidUpstreamRoots(HostTlsConfigText::Owned(err.to_string()))
}

fn invalid_upstream_roots_borrowed(detail: &'static str) -> HostTlsConfigError {
    HostTlsConfigError::InvalidUpstreamRoots(HostTlsConfigText::Borrowed(detail))
}

fn native_root_load_owned(err: impl fmt::Display) -> HostTlsConfigError {
    HostTlsConfigError::NativeRootLoad(HostTlsConfigText::Owned(err.to_string()))
}

fn upstream_server_name(
    server_name: &DnsName,
) -> Result<ServerName<'static>, rustls::pki_types::InvalidDnsNameError> {
    ServerName::try_from(server_name.clone().into_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTlsConnectorConfig {
    tcp: StdTcpConnectorConfig,
    guest_intermediate: HostTlsIntermediate,
    upstream_roots: HostTlsUpstreamRoots,
    stream_transforms: StreamTransformConfig,
    max_open_flows: usize,
    max_pending_guest_tls_bytes: usize,
    max_pending_upstream_tls_plaintext_bytes: usize,
    max_tls_flow_detail_bytes: usize,
    max_retained_tls_flow_details: usize,
}

impl HostTlsConnectorConfig {
    pub fn builder() -> HostTlsConnectorConfigBuilder {
        HostTlsConnectorConfigBuilder::default()
    }

    pub fn tcp(&self) -> &StdTcpConnectorConfig {
        &self.tcp
    }

    pub fn guest_intermediate(&self) -> &HostTlsIntermediate {
        &self.guest_intermediate
    }

    pub fn upstream_roots(&self) -> &HostTlsUpstreamRoots {
        &self.upstream_roots
    }

    pub fn stream_transforms(&self) -> &StreamTransformConfig {
        &self.stream_transforms
    }

    pub const fn max_pending_guest_tls_bytes(&self) -> usize {
        self.max_pending_guest_tls_bytes
    }

    pub const fn max_open_flows(&self) -> usize {
        self.max_open_flows
    }

    pub const fn max_pending_upstream_tls_plaintext_bytes(&self) -> usize {
        self.max_pending_upstream_tls_plaintext_bytes
    }

    pub const fn max_tls_flow_detail_bytes(&self) -> usize {
        self.max_tls_flow_detail_bytes
    }

    pub const fn max_retained_tls_flow_details(&self) -> usize {
        self.max_retained_tls_flow_details
    }
}

#[derive(Debug, Clone)]
pub struct HostTlsConnectorConfigBuilder {
    tcp: StdTcpConnectorConfig,
    guest_intermediate: Option<HostTlsIntermediate>,
    upstream_roots: Option<HostTlsUpstreamRoots>,
    stream_transforms: StreamTransformConfig,
    max_open_flows: usize,
    max_pending_guest_tls_bytes: usize,
    max_pending_upstream_tls_plaintext_bytes: usize,
    max_tls_flow_detail_bytes: usize,
    max_retained_tls_flow_details: usize,
}

impl Default for HostTlsConnectorConfigBuilder {
    fn default() -> Self {
        Self {
            tcp: StdTcpConnectorConfig::default(),
            guest_intermediate: None,
            upstream_roots: None,
            stream_transforms: StreamTransformConfig::default(),
            max_open_flows: DEFAULT_MAX_OPEN_FLOWS,
            max_pending_guest_tls_bytes: DEFAULT_MAX_PENDING_GUEST_TLS_BYTES,
            max_pending_upstream_tls_plaintext_bytes:
                DEFAULT_MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES,
            max_tls_flow_detail_bytes: DEFAULT_MAX_TLS_FLOW_DETAIL_BYTES,
            max_retained_tls_flow_details: DEFAULT_MAX_RETAINED_TLS_FLOW_DETAILS,
        }
    }
}

impl HostTlsConnectorConfigBuilder {
    pub fn tcp(mut self, tcp: StdTcpConnectorConfig) -> Self {
        self.tcp = tcp;
        self
    }

    pub fn guest_intermediate(mut self, guest_intermediate: HostTlsIntermediate) -> Self {
        self.guest_intermediate = Some(guest_intermediate);
        self
    }

    pub fn upstream_roots(mut self, upstream_roots: HostTlsUpstreamRoots) -> Self {
        self.upstream_roots = Some(upstream_roots);
        self
    }

    pub fn stream_transforms(mut self, stream_transforms: StreamTransformConfig) -> Self {
        self.stream_transforms = stream_transforms;
        self
    }

    pub fn max_open_flows(mut self, max_open_flows: usize) -> Self {
        self.max_open_flows = max_open_flows;
        self
    }

    pub fn max_pending_guest_tls_bytes(mut self, max_pending_guest_tls_bytes: usize) -> Self {
        self.max_pending_guest_tls_bytes = max_pending_guest_tls_bytes;
        self
    }

    pub fn max_pending_upstream_tls_plaintext_bytes(
        mut self,
        max_pending_upstream_tls_plaintext_bytes: usize,
    ) -> Self {
        self.max_pending_upstream_tls_plaintext_bytes = max_pending_upstream_tls_plaintext_bytes;
        self
    }

    pub fn max_tls_flow_detail_bytes(mut self, max_tls_flow_detail_bytes: usize) -> Self {
        self.max_tls_flow_detail_bytes = max_tls_flow_detail_bytes;
        self
    }

    pub fn max_retained_tls_flow_details(mut self, max_retained_tls_flow_details: usize) -> Self {
        self.max_retained_tls_flow_details = max_retained_tls_flow_details;
        self
    }

    pub fn build(self) -> Result<HostTlsConnectorConfig, HostTlsConfigError> {
        let guest_intermediate = self
            .guest_intermediate
            .ok_or(HostTlsConfigError::MissingGuestIntermediate)?;
        let upstream_roots = self
            .upstream_roots
            .ok_or(HostTlsConfigError::MissingUpstreamRoots)?;
        validate_guest_intermediate(&guest_intermediate)?;
        validate_upstream_roots(&upstream_roots)?;
        self.stream_transforms
            .validate()
            .map_err(|err| HostTlsConfigError::InvalidStreamTransformConfig(err.to_string()))?;
        if self.max_open_flows == 0 {
            return Err(HostTlsConfigError::ZeroMaxOpenFlows);
        }
        if self.max_open_flows > MAX_OPEN_FLOWS {
            return Err(HostTlsConfigError::MaxOpenFlowsTooLarge {
                actual: self.max_open_flows,
                max: MAX_OPEN_FLOWS,
            });
        }
        if self.max_pending_guest_tls_bytes == 0 {
            return Err(HostTlsConfigError::ZeroMaxPendingGuestTlsBytes);
        }
        if self.max_pending_guest_tls_bytes > MAX_PENDING_GUEST_TLS_BYTES {
            return Err(HostTlsConfigError::MaxPendingGuestTlsBytesTooLarge {
                actual: self.max_pending_guest_tls_bytes,
                max: MAX_PENDING_GUEST_TLS_BYTES,
            });
        }
        if self.max_pending_upstream_tls_plaintext_bytes == 0 {
            return Err(HostTlsConfigError::ZeroMaxPendingUpstreamTlsPlaintextBytes);
        }
        if self.max_pending_upstream_tls_plaintext_bytes > MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES
        {
            return Err(
                HostTlsConfigError::MaxPendingUpstreamTlsPlaintextBytesTooLarge {
                    actual: self.max_pending_upstream_tls_plaintext_bytes,
                    max: MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES,
                },
            );
        }
        if self.max_tls_flow_detail_bytes == 0 {
            return Err(HostTlsConfigError::ZeroMaxTlsFlowDetailBytes);
        }
        if self.max_tls_flow_detail_bytes > MAX_TLS_FLOW_DETAIL_BYTES {
            return Err(HostTlsConfigError::MaxTlsFlowDetailBytesTooLarge {
                actual: self.max_tls_flow_detail_bytes,
                max: MAX_TLS_FLOW_DETAIL_BYTES,
            });
        }
        if self.max_retained_tls_flow_details == 0 {
            return Err(HostTlsConfigError::ZeroMaxRetainedTlsFlowDetails);
        }
        if self.max_retained_tls_flow_details > MAX_RETAINED_TLS_FLOW_DETAILS {
            return Err(HostTlsConfigError::MaxRetainedTlsFlowDetailsTooLarge {
                actual: self.max_retained_tls_flow_details,
                max: MAX_RETAINED_TLS_FLOW_DETAILS,
            });
        }
        Ok(HostTlsConnectorConfig {
            tcp: self.tcp,
            guest_intermediate,
            upstream_roots,
            stream_transforms: self.stream_transforms,
            max_open_flows: self.max_open_flows,
            max_pending_guest_tls_bytes: self.max_pending_guest_tls_bytes,
            max_pending_upstream_tls_plaintext_bytes: self.max_pending_upstream_tls_plaintext_bytes,
            max_tls_flow_detail_bytes: self.max_tls_flow_detail_bytes,
            max_retained_tls_flow_details: self.max_retained_tls_flow_details,
        })
    }
}

#[derive(Debug)]
enum GuestTlsServer {
    #[cfg(not(feature = "host-tls-boring"))]
    Rustls(RustlsGuestTlsServer),
    #[cfg(feature = "host-tls-boring")]
    Boring(BoringGuestTlsServer),
}

impl GuestTlsServer {
    fn new(
        intermediate: &VmIntermediate,
        sni: &str,
        max_pending_guest_tls_bytes: usize,
    ) -> Result<Self, HostTlsConfigError> {
        #[cfg(feature = "host-tls-boring")]
        {
            Ok(Self::Boring(BoringGuestTlsServer::new(
                intermediate,
                sni,
                max_pending_guest_tls_bytes,
            )?))
        }
        #[cfg(not(feature = "host-tls-boring"))]
        {
            Ok(Self::Rustls(RustlsGuestTlsServer::new(
                intermediate,
                sni,
                max_pending_guest_tls_bytes,
            )?))
        }
    }

    fn feed_tls(&mut self, bytes: &[u8]) -> Result<(), GuestTlsTextError> {
        match self {
            #[cfg(not(feature = "host-tls-boring"))]
            Self::Rustls(server) => server.feed_tls(bytes),
            #[cfg(feature = "host-tls-boring")]
            Self::Boring(server) => server.feed_tls(bytes),
        }
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(not(feature = "host-tls-boring"))]
            Self::Rustls(server) => server.read_plaintext(buf),
            #[cfg(feature = "host-tls-boring")]
            Self::Boring(server) => server.read_plaintext(buf),
        }
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> Result<(), GuestTlsTextError> {
        match self {
            #[cfg(not(feature = "host-tls-boring"))]
            Self::Rustls(server) => server.write_plaintext(buf),
            #[cfg(feature = "host-tls-boring")]
            Self::Boring(server) => server.write_plaintext(buf),
        }
    }

    fn send_close_notify(&mut self) -> Result<(), GuestTlsTextError> {
        match self {
            #[cfg(not(feature = "host-tls-boring"))]
            Self::Rustls(server) => server.send_close_notify(),
            #[cfg(feature = "host-tls-boring")]
            Self::Boring(server) => server.send_close_notify(),
        }
    }

    fn take_tls_bytes(&mut self) -> Result<Vec<u8>, GuestTlsTextError> {
        match self {
            #[cfg(not(feature = "host-tls-boring"))]
            Self::Rustls(server) => server.take_tls_bytes(),
            #[cfg(feature = "host-tls-boring")]
            Self::Boring(server) => server.take_tls_bytes(),
        }
    }

    fn is_established(&self) -> bool {
        match self {
            #[cfg(not(feature = "host-tls-boring"))]
            Self::Rustls(server) => server.is_established(),
            #[cfg(feature = "host-tls-boring")]
            Self::Boring(server) => server.is_established(),
        }
    }
}

#[cfg(not(feature = "host-tls-boring"))]
#[derive(Debug)]
struct RustlsGuestTlsServer {
    conn: rustls::ServerConnection,
    outbound: Vec<u8>,
}

#[cfg(not(feature = "host-tls-boring"))]
impl RustlsGuestTlsServer {
    fn new(
        intermediate: &VmIntermediate,
        sni: &str,
        max_pending_guest_tls_bytes: usize,
    ) -> Result<Self, HostTlsConfigError> {
        let config = server_config_for_sni(intermediate, sni)?;
        let conn = rustls::ServerConnection::new(Arc::new(config))
            .map_err(invalid_guest_intermediate_owned)?;
        Ok(Self {
            conn,
            outbound: Vec::with_capacity(initial_tls_buffer_capacity(max_pending_guest_tls_bytes)),
        })
    }

    fn feed_tls(&mut self, bytes: &[u8]) -> Result<(), GuestTlsTextError> {
        let mut cursor = Cursor::new(bytes);
        while (cursor.position() as usize) < bytes.len() {
            let read = self
                .conn
                .read_tls(&mut cursor)
                .map_err(|err| GuestTlsTextError::Owned(err.to_string()))?;
            if read == 0 {
                break;
            }
        }
        self.conn
            .process_new_packets()
            .map_err(|err| GuestTlsTextError::Owned(err.to_string()))?;
        Ok(())
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.conn.reader().read(buf)
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> Result<(), GuestTlsTextError> {
        self.conn
            .writer()
            .write_all(buf)
            .map_err(|err| GuestTlsTextError::Owned(err.to_string()))
    }

    fn send_close_notify(&mut self) -> Result<(), GuestTlsTextError> {
        self.conn.send_close_notify();
        Ok(())
    }

    fn take_tls_bytes(&mut self) -> Result<Vec<u8>, GuestTlsTextError> {
        while self.conn.wants_write() {
            self.conn
                .write_tls(&mut self.outbound)
                .map_err(|err| GuestTlsTextError::Owned(err.to_string()))?;
        }
        Ok(self.take_outbound_bytes())
    }

    fn is_established(&self) -> bool {
        !self.conn.is_handshaking()
    }

    fn take_outbound_bytes(&mut self) -> Vec<u8> {
        let capacity = self.outbound.capacity();
        std::mem::replace(&mut self.outbound, Vec::with_capacity(capacity))
    }
}

#[cfg(feature = "host-tls-boring")]
#[derive(Debug, Default)]
struct BufferedTlsIo {
    inbound: Vec<u8>,
    inbound_offset: usize,
    outbound: Vec<u8>,
    max_buffered_bytes: usize,
}

#[cfg(feature = "host-tls-boring")]
impl BufferedTlsIo {
    fn new(max_buffered_bytes: usize) -> Self {
        Self {
            inbound: Vec::with_capacity(initial_tls_buffer_capacity(max_buffered_bytes)),
            inbound_offset: 0,
            outbound: Vec::with_capacity(initial_tls_buffer_capacity(max_buffered_bytes)),
            max_buffered_bytes,
        }
    }

    fn push_inbound(&mut self, bytes: &[u8]) -> Result<(), GuestTlsTextError> {
        let next_len = self.pending_inbound_len().checked_add(bytes.len()).ok_or(
            GuestTlsTextError::Borrowed(GUEST_TLS_BACKLOG_EXCEEDED_DETAIL),
        )?;
        if next_len > self.max_buffered_bytes {
            return Err(GuestTlsTextError::Borrowed(
                GUEST_TLS_BACKLOG_EXCEEDED_DETAIL,
            ));
        }
        self.inbound.extend_from_slice(bytes);
        Ok(())
    }

    fn drain_outbound(&mut self) -> Vec<u8> {
        let capacity = self.outbound.capacity();
        std::mem::replace(&mut self.outbound, Vec::with_capacity(capacity))
    }

    fn pending_inbound_len(&self) -> usize {
        self.inbound.len().saturating_sub(self.inbound_offset)
    }

    fn compact_inbound(&mut self) {
        if self.inbound_offset == 0 {
            return;
        }
        if self.inbound_offset >= self.inbound.len() {
            self.inbound.clear();
            self.inbound_offset = 0;
            return;
        }
        self.inbound.copy_within(self.inbound_offset.., 0);
        self.inbound
            .truncate(self.inbound.len() - self.inbound_offset);
        self.inbound_offset = 0;
    }
}

#[cfg(feature = "host-tls-boring")]
impl Read for BufferedTlsIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.inbound_offset >= self.inbound.len() {
            self.compact_inbound();
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS input not ready",
            ));
        }
        let available = &self.inbound[self.inbound_offset..];
        let len = available.len().min(buf.len());
        buf[..len].copy_from_slice(&available[..len]);
        self.inbound_offset = self
            .inbound_offset
            .checked_add(len)
            .expect("buffer offset addition cannot overflow");
        self.compact_inbound();
        Ok(len)
    }
}

#[cfg(feature = "host-tls-boring")]
impl Write for BufferedTlsIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let next_len = self
            .outbound
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::other(GUEST_TLS_BACKLOG_EXCEEDED_DETAIL))?;
        if next_len > self.max_buffered_bytes {
            return Err(io::Error::other(GUEST_TLS_BACKLOG_EXCEEDED_DETAIL));
        }
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "host-tls-boring")]
#[derive(Debug)]
enum BoringGuestTlsState {
    Handshaking(MidHandshakeSslStream<BufferedTlsIo>),
    Established(SslStream<BufferedTlsIo>),
}

#[cfg(feature = "host-tls-boring")]
#[derive(Debug)]
struct BoringGuestTlsServer {
    state: Option<BoringGuestTlsState>,
}

#[cfg(feature = "host-tls-boring")]
impl BoringGuestTlsServer {
    fn new(
        intermediate: &VmIntermediate,
        sni: &str,
        max_pending_guest_tls_bytes: usize,
    ) -> Result<Self, HostTlsConfigError> {
        let acceptor = boring_acceptor_for_sni(intermediate, sni)?;
        let ssl = Ssl::new(acceptor.context()).map_err(invalid_guest_intermediate_owned)?;
        let mid = SslStreamBuilder::new(ssl, BufferedTlsIo::new(max_pending_guest_tls_bytes))
            .setup_accept();
        let mut server = Self {
            state: Some(BoringGuestTlsState::Handshaking(mid)),
        };
        server
            .drive_handshake()
            .map_err(HostTlsConfigError::InvalidGuestIntermediate)?;
        Ok(server)
    }

    fn feed_tls(&mut self, bytes: &[u8]) -> Result<(), GuestTlsTextError> {
        self.io_mut().push_inbound(bytes)?;
        self.drive_handshake()
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.drive_handshake().map_err(io::Error::other)?;
        let Some(BoringGuestTlsState::Established(stream)) = self.state.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS handshake in progress",
            ));
        };
        match stream.ssl_read(buf) {
            Ok(bytes) => Ok(bytes),
            Err(err) if matches!(err.code(), BoringErrorCode::ZERO_RETURN) => Ok(0),
            Err(err)
                if matches!(
                    err.code(),
                    BoringErrorCode::WANT_READ | BoringErrorCode::WANT_WRITE
                ) =>
            {
                Err(io::Error::new(io::ErrorKind::WouldBlock, err.to_string()))
            }
            Err(err) => Err(io::Error::other(err)),
        }
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> Result<(), GuestTlsTextError> {
        self.drive_handshake()?;
        let mut offset = 0usize;
        while offset < buf.len() {
            let result = {
                let Some(BoringGuestTlsState::Established(stream)) = self.state.as_mut() else {
                    return Err(GuestTlsTextError::Borrowed(
                        "guest TLS handshake did not complete",
                    ));
                };
                stream.ssl_write(&buf[offset..])
            };
            match result {
                Ok(0) => {
                    return Err(GuestTlsTextError::Borrowed(
                        "guest TLS write produced zero bytes",
                    ));
                }
                Ok(written) => {
                    offset = offset
                        .checked_add(written)
                        .ok_or(GuestTlsTextError::Borrowed(
                            "guest TLS write offset overflowed",
                        ))?;
                }
                Err(err)
                    if matches!(
                        err.code(),
                        BoringErrorCode::WANT_READ | BoringErrorCode::WANT_WRITE
                    ) =>
                {
                    self.drive_handshake()?;
                }
                Err(err) => return Err(normalize_boring_budget_error(err.to_string())),
            }
        }
        Ok(())
    }

    fn send_close_notify(&mut self) -> Result<(), GuestTlsTextError> {
        self.drive_handshake()?;
        loop {
            let result = {
                let Some(BoringGuestTlsState::Established(stream)) = self.state.as_mut() else {
                    return Ok(());
                };
                stream.shutdown()
            };
            match result {
                Ok(ShutdownResult::Sent | ShutdownResult::Received) => return Ok(()),
                Err(err)
                    if matches!(
                        err.code(),
                        BoringErrorCode::WANT_READ | BoringErrorCode::WANT_WRITE
                    ) =>
                {
                    self.drive_handshake()?;
                }
                Err(err) => return Err(normalize_boring_budget_error(err.to_string())),
            }
        }
    }

    fn take_tls_bytes(&mut self) -> Result<Vec<u8>, GuestTlsTextError> {
        self.drive_handshake()?;
        Ok(self.io_mut().drain_outbound())
    }

    fn is_established(&self) -> bool {
        matches!(self.state, Some(BoringGuestTlsState::Established(_)))
    }

    fn drive_handshake(&mut self) -> Result<(), GuestTlsTextError> {
        loop {
            let Some(state) = self.state.take() else {
                return Err(GuestTlsTextError::Borrowed(
                    "guest TLS state unexpectedly missing",
                ));
            };
            match state {
                BoringGuestTlsState::Handshaking(mid) => match mid.handshake() {
                    Ok(stream) => {
                        self.state = Some(BoringGuestTlsState::Established(stream));
                        continue;
                    }
                    Err(BoringHandshakeError::WouldBlock(mid)) => {
                        self.state = Some(BoringGuestTlsState::Handshaking(mid));
                        return Ok(());
                    }
                    Err(BoringHandshakeError::Failure(mid)) => {
                        let detail = normalize_boring_budget_error(mid.error().to_string());
                        self.state = Some(BoringGuestTlsState::Handshaking(mid));
                        return Err(detail);
                    }
                    Err(BoringHandshakeError::SetupFailure(err)) => {
                        return Err(normalize_boring_budget_error(err.to_string()));
                    }
                },
                established @ BoringGuestTlsState::Established(_) => {
                    self.state = Some(established);
                    return Ok(());
                }
            }
        }
    }

    fn io_mut(&mut self) -> &mut BufferedTlsIo {
        match self
            .state
            .as_mut()
            .expect("guest TLS state should be present")
        {
            BoringGuestTlsState::Handshaking(mid) => mid.get_mut(),
            BoringGuestTlsState::Established(stream) => stream.get_mut(),
        }
    }
}

#[derive(Debug)]
struct TlsFlowState {
    max_pending_guest_tls_bytes: usize,
    max_pending_upstream_tls_plaintext_bytes: usize,
    max_tls_flow_detail_bytes: usize,
    flow_id: FlowId,
    guest_stream: GuestStreamTracker,
    guest_tls: GuestTlsServer,
    stream_transforms: StreamTransformChain,
    upstream: TcpStream,
    upstream_tls: rustls::ClientConnection,
    host_sequence: u64,
    pending_guest_bytes: Vec<u8>,
    pending_upstream_plaintext: Vec<u8>,
    pending_guest_ack: bool,
    pending_activity_detail: Option<String>,
    close_pending: bool,
    upstream_shutdown_requested: bool,
    close_detail: Option<String>,
    last_error_detail: Option<String>,
    guest_hello_summary: Option<String>,
    last_guest_record_summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainedDetailKind {
    Activity,
    Error,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetainedDetailRef {
    flow_id: FlowId,
    kind: RetainedDetailKind,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RetainedFlowDetail {
    detail: String,
    generation: u64,
}

#[derive(Debug)]
pub struct TlsTerminatingTcpConnector {
    config: HostTlsConnectorConfig,
    guest_intermediate: VmIntermediate,
    upstream_client_config: Arc<rustls::ClientConfig>,
    flows: HashMap<FlowId, TlsFlowState>,
    flow_order: VecDeque<FlowId>,
    pending_activity_details: HashMap<FlowId, RetainedFlowDetail>,
    pending_error_details: HashMap<FlowId, RetainedFlowDetail>,
    pending_close_details: HashMap<FlowId, RetainedFlowDetail>,
    pending_detail_order: VecDeque<RetainedDetailRef>,
    next_detail_generation: u64,
}

impl TlsTerminatingTcpConnector {
    pub fn with_config(config: HostTlsConnectorConfig) -> Result<Self, HostTlsConfigError> {
        let guest_intermediate = VmIntermediate::from_pem(
            config.guest_intermediate().cert_pem(),
            config.guest_intermediate().key_pem(),
        )
        .map_err(invalid_guest_intermediate_owned)?;
        let upstream_client_config = Arc::new(upstream_client_config(config.upstream_roots())?);
        let flow_capacity = initial_tls_connector_flow_capacity(&config);
        let retained_detail_capacity = initial_tls_connector_retained_detail_capacity(&config);
        Ok(Self {
            config,
            guest_intermediate,
            upstream_client_config,
            flows: HashMap::with_capacity(flow_capacity),
            flow_order: VecDeque::with_capacity(flow_capacity),
            pending_activity_details: HashMap::with_capacity(retained_detail_capacity),
            pending_error_details: HashMap::with_capacity(retained_detail_capacity),
            pending_close_details: HashMap::with_capacity(retained_detail_capacity),
            pending_detail_order: VecDeque::with_capacity(retained_detail_capacity),
            next_detail_generation: 0,
        })
    }

    pub fn config(&self) -> &HostTlsConnectorConfig {
        &self.config
    }

    fn open_flow(&mut self, spec: &TcpConnectSpec) -> Result<TlsFlowState, TransportError> {
        let route = spec.tls_transform().ok_or(TransportError::ProtocolError)?;
        if route.termination != TlsTermination::TerminateAndReoriginate {
            return Err(self.record_open_error_text_borrowed(
                spec.flow_id(),
                "TLS connector only supports terminate-and-reoriginate transformed routes",
                TransportError::TransformError,
            ));
        }
        if !route.alpn_protocols.is_empty() {
            return Err(self.record_open_error_text_borrowed(
                spec.flow_id(),
                "ALPN negotiation is not supported for transformed TLS flows",
                TransportError::TransformError,
            ));
        }
        let stream_transforms = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &route.transform_chain,
            self.config.stream_transforms(),
            Some(route.server_name.as_str()),
        )
        .map_err(|err| {
            self.record_open_error(spec.flow_id(), err, TransportError::TransformError)
        })?;
        let server_name = upstream_server_name(&route.server_name).map_err(|err| {
            self.record_open_error(spec.flow_id(), err, TransportError::TlsHandshakeFailed)
        })?;
        let guest_tls = GuestTlsServer::new(
            &self.guest_intermediate,
            route.server_name.as_str(),
            self.config.max_pending_guest_tls_bytes(),
        )
        .map_err(|err| {
            self.record_open_error(spec.flow_id(), err, TransportError::TlsHandshakeFailed)
        })?;
        let upstream = connect_target_with_config(self.config.tcp(), spec.target(), spec.route())?;
        upstream.set_nodelay(true).map_err(map_tcp_io_error)?;
        upstream
            .set_read_timeout(Some(self.config.tcp().read_timeout()))
            .map_err(map_tcp_io_error)?;
        let upstream_tls =
            rustls::ClientConnection::new(Arc::clone(&self.upstream_client_config), server_name)
                .map_err(|err| {
                    self.record_open_error(spec.flow_id(), err, TransportError::TlsHandshakeFailed)
                })?;
        Ok(TlsFlowState {
            max_pending_guest_tls_bytes: self.config.max_pending_guest_tls_bytes(),
            max_pending_upstream_tls_plaintext_bytes: self
                .config
                .max_pending_upstream_tls_plaintext_bytes(),
            max_tls_flow_detail_bytes: self.config.max_tls_flow_detail_bytes(),
            flow_id: spec.flow_id(),
            guest_stream: GuestStreamTracker::default(),
            guest_tls,
            stream_transforms,
            upstream,
            upstream_tls,
            host_sequence: 0,
            pending_guest_bytes: Vec::with_capacity(initial_tls_buffer_capacity(
                self.config.max_pending_guest_tls_bytes(),
            )),
            pending_upstream_plaintext: Vec::with_capacity(initial_tls_buffer_capacity(
                self.config.max_pending_upstream_tls_plaintext_bytes(),
            )),
            pending_guest_ack: false,
            pending_activity_detail: None,
            close_pending: false,
            upstream_shutdown_requested: false,
            close_detail: None,
            last_error_detail: None,
            guest_hello_summary: None,
            last_guest_record_summary: None,
        })
    }

    fn record_open_error(
        &mut self,
        flow_id: FlowId,
        err: impl fmt::Display,
        error: TransportError,
    ) -> TransportError {
        self.store_retained_detail(RetainedDetailKind::Error, flow_id, err.to_string());
        error
    }

    fn record_open_error_text_borrowed(
        &mut self,
        flow_id: FlowId,
        detail: &str,
        error: TransportError,
    ) -> TransportError {
        self.store_retained_detail_borrowed(RetainedDetailKind::Error, flow_id, detail);
        error
    }

    fn store_retained_detail(&mut self, kind: RetainedDetailKind, flow_id: FlowId, detail: String) {
        self.store_retained_detail_clamped(
            kind,
            flow_id,
            clamp_detail_string(detail, self.config.max_tls_flow_detail_bytes()),
        );
    }

    fn store_retained_detail_borrowed(
        &mut self,
        kind: RetainedDetailKind,
        flow_id: FlowId,
        detail: &str,
    ) {
        self.store_retained_detail_clamped(
            kind,
            flow_id,
            clamp_detail_text(detail, self.config.max_tls_flow_detail_bytes()),
        );
    }

    fn store_retained_detail_clamped(
        &mut self,
        kind: RetainedDetailKind,
        flow_id: FlowId,
        detail: String,
    ) {
        let generation = self.next_detail_generation;
        self.next_detail_generation = self.next_detail_generation.wrapping_add(1);
        let retained = RetainedFlowDetail { detail, generation };
        drop_retained_detail_refs(&mut self.pending_detail_order, flow_id, kind);
        self.pending_detail_order.push_back(RetainedDetailRef {
            flow_id,
            kind,
            generation,
        });
        match kind {
            RetainedDetailKind::Activity => {
                self.pending_activity_details.insert(flow_id, retained);
            }
            RetainedDetailKind::Error => {
                self.pending_error_details.insert(flow_id, retained);
            }
            RetainedDetailKind::Close => {
                self.pending_close_details.insert(flow_id, retained);
            }
        }
        self.enforce_retained_detail_budget();
    }

    fn retain_removed_flow_close_detail(&mut self, flow_id: FlowId, state: &mut TlsFlowState) {
        if let Some(detail) = state.take_detail() {
            self.store_retained_detail(RetainedDetailKind::Close, flow_id, detail);
        }
    }

    fn retain_flow_activity_detail(&mut self, flow_id: FlowId, detail: Option<String>) {
        if let Some(detail) = detail {
            self.store_retained_detail(RetainedDetailKind::Activity, flow_id, detail);
        }
    }

    fn enforce_retained_detail_budget(&mut self) {
        while self.retained_detail_count() > self.config.max_retained_tls_flow_details() {
            if !self.evict_oldest_retained_detail() {
                break;
            }
        }
    }

    fn retained_detail_count(&self) -> usize {
        self.pending_activity_details.len()
            + self.pending_error_details.len()
            + self.pending_close_details.len()
    }

    fn evict_oldest_retained_detail(&mut self) -> bool {
        while let Some(next) = self.pending_detail_order.pop_front() {
            let removed = match next.kind {
                RetainedDetailKind::Activity => {
                    remove_retained_detail_if_current(&mut self.pending_activity_details, next)
                }
                RetainedDetailKind::Error => {
                    remove_retained_detail_if_current(&mut self.pending_error_details, next)
                }
                RetainedDetailKind::Close => {
                    remove_retained_detail_if_current(&mut self.pending_close_details, next)
                }
            };
            if removed {
                return true;
            }
        }
        false
    }

    fn take_retained_detail(
        &mut self,
        flow_id: FlowId,
        kind: RetainedDetailKind,
    ) -> Option<String> {
        let detail = match kind {
            RetainedDetailKind::Activity => self.pending_activity_details.remove(&flow_id),
            RetainedDetailKind::Error => self.pending_error_details.remove(&flow_id),
            RetainedDetailKind::Close => self.pending_close_details.remove(&flow_id),
        }?;
        drop_retained_detail_refs(&mut self.pending_detail_order, flow_id, kind);
        Some(detail.detail)
    }

    fn take_retained_error_or_close_detail(&mut self, flow_id: FlowId) -> Option<String> {
        self.take_retained_detail(flow_id, RetainedDetailKind::Error)
            .or_else(|| self.take_retained_detail(flow_id, RetainedDetailKind::Close))
    }

    fn append_retained_activity_detail(&mut self, flow_id: FlowId, detail: &mut Option<String>) {
        let _ = append_detail(
            detail,
            self.take_retained_detail(flow_id, RetainedDetailKind::Activity),
            self.config.max_tls_flow_detail_bytes(),
        );
    }

    fn take_flow_error_detail(&mut self, flow_id: FlowId) -> Option<String> {
        self.take_retained_error_or_close_detail(flow_id)
            .or_else(|| {
                self.flows
                    .get_mut(&flow_id)
                    .and_then(TlsFlowState::take_detail)
            })
    }
}

fn initial_tls_connector_flow_capacity(config: &HostTlsConnectorConfig) -> usize {
    config.max_open_flows()
}

fn initial_tls_connector_retained_detail_capacity(config: &HostTlsConnectorConfig) -> usize {
    config.max_retained_tls_flow_details()
}

impl HostTcpConnector for TlsTerminatingTcpConnector {
    fn open(&mut self, spec: &TcpConnectSpec) -> Result<(), TransportError> {
        if !spec.requires_tls_transform() {
            return Err(self.record_open_error_text_borrowed(
                spec.flow_id(),
                "TLS connector requires a transformed TLS route",
                TransportError::ProtocolError,
            ));
        }
        if self.flows.contains_key(&spec.flow_id()) {
            return Err(self.record_open_error_text_borrowed(
                spec.flow_id(),
                "TLS connector already tracks this flow id",
                TransportError::ProtocolError,
            ));
        }
        if self.flows.len() >= self.config.max_open_flows() {
            self.store_retained_detail_borrowed(
                RetainedDetailKind::Error,
                spec.flow_id(),
                "TLS connector open-flow budget exceeded configured max-open-flows cap",
            );
            return Err(TransportError::Refused);
        }
        let flow = self.open_flow(spec)?;
        self.flows.insert(spec.flow_id(), flow);
        self.flow_order.push_back(spec.flow_id());
        Ok(())
    }

    fn send(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
        let state = self
            .flows
            .get_mut(&chunk.flow_id)
            .ok_or(TransportError::ProtocolError)?;
        let result = state.ingest_guest_chunk(chunk);
        let detail = state.take_activity_detail();
        self.retain_flow_activity_detail(chunk.flow_id, detail);
        result
    }

    fn close(&mut self, flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
        if let Some(mut state) = self.flows.remove(&flow_id) {
            let _ = state.finish_stream_transforms();
            self.retain_removed_flow_close_detail(flow_id, &mut state);
            let _ = state.upstream.shutdown(Shutdown::Both);
        }
        drop_flow_order_refs(&mut self.flow_order, flow_id);
        Ok(())
    }

    fn drain_events(&mut self, max_events: usize) -> Result<Vec<HostTcpEvent>, TransportError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        if self.flows.is_empty() {
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

            let Some(state) = self.flows.get_mut(&flow_id) else {
                continue;
            };

            let event = match state.drain_event() {
                Ok(event) => event,
                Err(err) => {
                    self.flow_order.push_back(flow_id);
                    return Err(err);
                }
            };
            let detail = state.take_activity_detail();
            self.retain_flow_activity_detail(flow_id, detail);

            match event {
                Some(HostTcpEvent::Close(close)) => {
                    let _ = close;
                    if let Some(mut state) = self.flows.remove(&flow_id) {
                        self.retain_removed_flow_close_detail(flow_id, &mut state);
                    }
                }
                Some(event) => {
                    events.push(event);
                    self.flow_order.push_back(flow_id);
                }
                None => {
                    self.flow_order.push_back(flow_id);
                }
            }
        }
        Ok(events)
    }

    fn supports_tls_transform(&self) -> bool {
        true
    }

    fn supports_stream_transforms(&self) -> bool {
        true
    }

    fn validate_stream_transforms(
        &self,
        plugin_chain: &[PluginId],
        target_host: Option<&str>,
    ) -> Result<(), String> {
        StreamTransformChain::validate_plugin_ids_with_config_for_target(
            plugin_chain,
            self.config.stream_transforms(),
            target_host,
        )
        .map_err(|err| err.to_string())
    }

    fn take_activity_detail(&mut self, flow_id: FlowId) -> Option<String> {
        self.take_retained_detail(flow_id, RetainedDetailKind::Activity)
    }

    fn take_error_detail(&mut self, flow_id: FlowId) -> Option<String> {
        let mut detail = self.take_flow_error_detail(flow_id);
        self.append_retained_activity_detail(flow_id, &mut detail);
        detail
    }
}

impl TlsFlowState {
    fn ingest_guest_chunk(&mut self, chunk: &StreamChunk) -> Result<(), TransportError> {
        if self.close_pending {
            return Err(TransportError::ProtocolError);
        }
        let action = self.guest_stream.observe(chunk)?;
        if !chunk.bytes.is_empty() {
            self.pending_guest_ack = true;
        }
        if matches!(action, GuestChunkAction::Ignore) {
            return Ok(());
        }
        if !chunk.bytes.is_empty() {
            self.record_guest_chunk_summaries(&chunk.bytes);
            self.guest_tls
                .feed_tls(&chunk.bytes)
                .map_err(|err| self.classify_guest_tls_error(err))?;
            self.forward_guest_plaintext()?;
            self.flush_upstream_tls()?;
            self.flush_guest_tls()?;
        }
        if chunk.end_stream {
            self.send_guest_close_notify()?;
            self.request_upstream_shutdown()?;
        }
        Ok(())
    }

    fn drain_event(&mut self) -> Result<Option<HostTcpEvent>, TransportError> {
        self.flush_guest_tls()?;
        if let Some(event) = self.pending_guest_event_or_close()? {
            return Ok(Some(event));
        }
        self.read_upstream()?;
        self.flush_guest_tls()?;
        if let Some(event) = self.pending_guest_event_or_close()? {
            return Ok(Some(event));
        }
        Ok(None)
    }

    fn read_upstream(&mut self) -> Result<(), TransportError> {
        let read = match self.upstream_tls.read_tls(&mut self.upstream) {
            Ok(read) => read,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(());
            }
            Err(err) => return Err(map_tcp_io_error(err)),
        };
        if read == 0 {
            self.note_upstream_eof();
            self.schedule_guest_close()?;
            return Ok(());
        }
        self.upstream_tls
            .process_new_packets()
            .map_err(|err| self.record_tls_handshake_error(err))?;
        self.flush_pending_upstream_plaintext()?;
        self.flush_upstream_tls()?;
        self.maybe_finish_upstream_shutdown()?;
        self.forward_upstream_plaintext()?;
        Ok(())
    }

    fn forward_guest_plaintext(&mut self) -> Result<(), TransportError> {
        let mut buffer = [0u8; TLS_READ_BUFFER_BYTES];
        loop {
            match self.guest_tls.read_plaintext(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(bytes) => {
                    let transformed = self
                        .stream_transforms
                        .process(StreamTransformDirection::GuestToUpstream, &buffer[..bytes])
                        .map_err(|err| self.record_transform_error(err))?;
                    self.append_pending_activity_detail(transformed.detail())?;
                    self.write_or_queue_upstream_plaintext(transformed.bytes())?;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(self.record_transform_error(err)),
            }
        }
    }

    fn forward_upstream_plaintext(&mut self) -> Result<(), TransportError> {
        let mut buffer = [0u8; TLS_READ_BUFFER_BYTES];
        loop {
            match self.upstream_tls.reader().read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(bytes) => {
                    let transformed = self
                        .stream_transforms
                        .process(StreamTransformDirection::UpstreamToGuest, &buffer[..bytes])
                        .map_err(|err| self.record_transform_error(err))?;
                    self.append_pending_activity_detail(transformed.detail())?;
                    self.write_guest_plaintext(transformed.bytes())?;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(self.record_transform_error(err)),
            }
        }
    }

    fn flush_guest_tls(&mut self) -> Result<(), TransportError> {
        let bytes = self
            .guest_tls
            .take_tls_bytes()
            .map_err(|err| self.record_transform_error(err))?;
        if !bytes.is_empty() {
            let guest_bytes =
                split_guest_server_handshake_records(bytes, self.guest_tls.is_established());
            self.queue_guest_tls_bytes(&guest_bytes)?;
        }
        Ok(())
    }

    fn flush_upstream_tls(&mut self) -> Result<(), TransportError> {
        while self.upstream_tls.wants_write() {
            self.upstream_tls
                .write_tls(&mut self.upstream)
                .map_err(map_tcp_io_error)?;
        }
        Ok(())
    }

    fn pending_guest_event(&mut self) -> Result<Option<HostTcpEvent>, TransportError> {
        if self.pending_guest_bytes.is_empty() {
            if self.pending_guest_ack {
                self.pending_guest_ack = false;
                return Ok(Some(host_guest_ack_event(self.flow_id, self.host_sequence)));
            }
            return Ok(None);
        }
        let bytes = self.take_pending_guest_bytes();
        let sequence = self.host_sequence;
        self.host_sequence = self
            .host_sequence
            .checked_add(bytes.len() as u64)
            .ok_or(TransportError::ProtocolError)?;
        Ok(Some(HostTcpEvent::Data(StreamChunk::new(
            self.flow_id,
            FlowDirection::HostToGuest,
            sequence,
            bytes,
        ))))
    }

    fn take_pending_guest_bytes(&mut self) -> Vec<u8> {
        std::mem::replace(
            &mut self.pending_guest_bytes,
            Vec::with_capacity(initial_tls_buffer_capacity(
                self.max_pending_guest_tls_bytes,
            )),
        )
    }

    fn pending_guest_event_or_close(&mut self) -> Result<Option<HostTcpEvent>, TransportError> {
        if let Some(event) = self.pending_guest_event()? {
            return Ok(Some(event));
        }
        if self.close_pending {
            return Ok(Some(host_closed_tcp_event(self.flow_id)));
        }
        Ok(None)
    }

    fn note_upstream_eof(&mut self) {
        if self.last_error_detail.is_some() {
            return;
        }
        self.store_last_error_detail(format_upstream_eof_detail(
            self.upstream_tls.is_handshaking(),
            self.guest_tls.is_established(),
            self.pending_guest_bytes.len(),
            self.pending_upstream_plaintext.len(),
            self.last_guest_record_summary.as_deref().unwrap_or("none"),
        ));
    }

    fn record_guest_chunk_summaries(&mut self, bytes: &[u8]) {
        self.last_guest_record_summary = summarize_tls_records(bytes)
            .map(|detail| clamp_detail_string(detail, self.max_tls_flow_detail_bytes));
        if self.guest_hello_summary.is_none() {
            self.guest_hello_summary = summarize_client_hello(bytes)
                .map(|detail| clamp_detail_string(detail, self.max_tls_flow_detail_bytes));
        }
    }

    fn append_pending_activity_detail(
        &mut self,
        detail: Option<&str>,
    ) -> Result<(), TransportError> {
        if !append_detail_str(
            &mut self.pending_activity_detail,
            detail,
            self.max_tls_flow_detail_bytes,
        ) {
            return Err(self.record_transform_error_text_borrowed(
                "transformed-flow detail exceeded configured byte budget",
            ));
        }
        Ok(())
    }

    fn append_close_detail(&mut self, detail: Option<String>) -> Result<(), TransportError> {
        if !append_detail(
            &mut self.close_detail,
            detail,
            self.max_tls_flow_detail_bytes,
        ) {
            return Err(self.record_transform_error_text_borrowed(
                "transformed-flow detail exceeded configured byte budget",
            ));
        }
        Ok(())
    }

    fn send_guest_close_notify(&mut self) -> Result<(), TransportError> {
        self.guest_tls
            .send_close_notify()
            .map_err(|err| self.record_transform_error(err))?;
        self.flush_guest_tls()
    }

    fn write_guest_plaintext(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.guest_tls
            .write_plaintext(bytes)
            .map_err(|err| self.record_transform_error(err))
    }

    fn schedule_guest_close(&mut self) -> Result<(), TransportError> {
        if self.close_pending {
            return Ok(());
        }
        self.flush_upstream_finish_bytes()?;
        self.send_guest_close_notify()?;
        self.finish_stream_transforms()?;
        self.close_pending = true;
        Ok(())
    }

    fn record_tls_handshake_error(&mut self, err: impl fmt::Display) -> TransportError {
        self.record_tls_handshake_error_text(err.to_string())
    }

    fn store_last_error_detail_borrowed(&mut self, detail: &str) {
        self.last_error_detail = Some(clamp_detail_text(detail, self.max_tls_flow_detail_bytes));
    }

    fn store_last_error_detail(&mut self, detail: String) {
        self.last_error_detail = Some(clamp_detail_string(detail, self.max_tls_flow_detail_bytes));
    }

    fn record_tls_handshake_error_text(&mut self, err_text: String) -> TransportError {
        if let Some(detail) = self
            .guest_certificate_rejection_detail()
            .or_else(|| guest_certificate_rejection_from_error(&err_text))
        {
            self.store_last_error_detail_borrowed(detail);
        } else {
            self.store_last_error_detail(err_text);
        }
        TransportError::TlsHandshakeFailed
    }

    fn classify_guest_tls_error(&mut self, err: impl fmt::Display) -> TransportError {
        if let Some(detail) = self.guest_certificate_rejection_detail() {
            self.store_last_error_detail_borrowed(detail);
            return TransportError::TlsHandshakeFailed;
        }
        let detail = err.to_string();
        if detail == GUEST_TLS_BACKLOG_EXCEEDED_DETAIL {
            return self.record_transform_error_text(detail);
        }
        self.record_tls_handshake_error_text(detail)
    }

    fn record_transform_error(&mut self, err: impl fmt::Display) -> TransportError {
        self.record_transform_error_text(err.to_string())
    }

    fn record_transform_error_text_borrowed(&mut self, detail: &str) -> TransportError {
        self.store_last_error_detail_borrowed(detail);
        TransportError::TransformError
    }

    fn record_transform_error_text(&mut self, detail: String) -> TransportError {
        self.store_last_error_detail(detail);
        TransportError::TransformError
    }

    fn take_detail(&mut self) -> Option<String> {
        let mut detail = self.last_error_detail.take();
        let _ = append_detail(
            &mut detail,
            self.pending_activity_detail.take(),
            self.max_tls_flow_detail_bytes,
        );
        let _ = append_detail(
            &mut detail,
            self.close_detail.take(),
            self.max_tls_flow_detail_bytes,
        );
        detail
            .or_else(|| self.last_guest_record_summary.take())
            .or_else(|| self.guest_hello_summary.take())
    }

    fn guest_certificate_rejection_detail(&self) -> Option<&'static str> {
        let summary = self.last_guest_record_summary.as_deref()?;
        let description = guest_certificate_alert_description(summary)?;
        guest_certificate_rejection_detail_text(description)
    }

    fn take_activity_detail(&mut self) -> Option<String> {
        self.pending_activity_detail.take()
    }

    fn checked_pending_buffer_len(
        &mut self,
        current_len: usize,
        added_len: usize,
        max_len: usize,
        overflow_detail: &str,
        exceeded_detail: &str,
    ) -> Result<usize, TransportError> {
        let next_len = current_len
            .checked_add(added_len)
            .ok_or_else(|| self.record_transform_error_text_borrowed(overflow_detail))?;
        if next_len > max_len {
            return Err(self.record_transform_error_text_borrowed(exceeded_detail));
        }
        Ok(next_len)
    }

    fn queue_guest_tls_bytes(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let _ = self.checked_pending_buffer_len(
            self.pending_guest_bytes.len(),
            bytes.len(),
            self.max_pending_guest_tls_bytes,
            "guest-facing TLS backlog length overflowed host accounting",
            "guest-facing TLS backlog exceeded configured pending-byte budget",
        )?;
        self.pending_guest_bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn queue_upstream_plaintext(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let _ = self.checked_pending_buffer_len(
            self.pending_upstream_plaintext.len(),
            bytes.len(),
            self.max_pending_upstream_tls_plaintext_bytes,
            "upstream TLS plaintext backlog length overflowed host accounting",
            "upstream TLS plaintext backlog exceeded configured pending-byte budget",
        )?;
        self.pending_upstream_plaintext.extend_from_slice(bytes);
        Ok(())
    }

    fn write_or_queue_upstream_plaintext(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if self.upstream_tls.is_handshaking() || !self.pending_upstream_plaintext.is_empty() {
            self.queue_upstream_plaintext(bytes)?;
            return self.flush_pending_upstream_plaintext();
        }
        self.upstream_tls
            .writer()
            .write_all(bytes)
            .map_err(|err| self.record_transform_error(err))
    }

    fn flush_pending_upstream_plaintext(&mut self) -> Result<(), TransportError> {
        if self.pending_upstream_plaintext.is_empty() || self.upstream_tls.is_handshaking() {
            return Ok(());
        }
        let bytes = self.take_pending_upstream_plaintext();
        self.upstream_tls
            .writer()
            .write_all(&bytes)
            .map_err(|err| self.record_transform_error(err))
    }

    fn take_pending_upstream_plaintext(&mut self) -> Vec<u8> {
        std::mem::replace(
            &mut self.pending_upstream_plaintext,
            Vec::with_capacity(initial_tls_buffer_capacity(
                self.max_pending_upstream_tls_plaintext_bytes,
            )),
        )
    }

    fn request_upstream_shutdown(&mut self) -> Result<(), TransportError> {
        self.upstream_shutdown_requested = true;
        self.maybe_finish_upstream_shutdown()
    }

    fn maybe_finish_upstream_shutdown(&mut self) -> Result<(), TransportError> {
        if !self.upstream_shutdown_requested {
            return Ok(());
        }
        if self.upstream_tls.is_handshaking() || !self.pending_upstream_plaintext.is_empty() {
            return Ok(());
        }
        self.upstream_tls.send_close_notify();
        self.flush_upstream_tls()?;
        self.upstream
            .shutdown(Shutdown::Write)
            .map_err(map_tcp_io_error)?;
        self.upstream_shutdown_requested = false;
        Ok(())
    }

    fn flush_upstream_finish_bytes(&mut self) -> Result<(), TransportError> {
        let chunk = self
            .stream_transforms
            .finish_direction(StreamTransformDirection::UpstreamToGuest)
            .map_err(|err| self.record_transform_error(err))?;
        self.append_pending_activity_detail(chunk.detail())?;
        if chunk.bytes().is_empty() {
            return Ok(());
        }
        self.write_guest_plaintext(chunk.bytes())?;
        self.flush_guest_tls()
    }

    fn finish_stream_transforms(&mut self) -> Result<(), TransportError> {
        let detail = self
            .stream_transforms
            .finish()
            .map_err(|err| self.record_transform_error(err))?;
        self.append_close_detail(detail)
    }
}

fn guest_certificate_alert_description(summary: &str) -> Option<&'static str> {
    const ALERTS: [&str; 5] = [
        "bad_certificate",
        "unsupported_certificate",
        "certificate_unknown",
        "unknown_ca",
        "access_denied",
    ];
    if !summary.contains("alert(") || !summary.contains("level=fatal") {
        return None;
    }
    ALERTS
        .into_iter()
        .find(|description| summary_contains_alert_description(summary, description))
}

fn summary_contains_alert_description(summary: &str, description: &str) -> bool {
    let Some(index) = summary.find("description=") else {
        return false;
    };
    let suffix = &summary[index + "description=".len()..];
    suffix.strip_prefix(description).is_some_and(|remainder| {
        remainder.is_empty() || remainder.starts_with(',') || remainder.starts_with(')')
    })
}

fn guest_certificate_rejection_from_error(err: &str) -> Option<&'static str> {
    let description = if err.contains("UnknownCA") {
        "unknown_ca"
    } else if err.contains("CertificateUnknown") {
        "certificate_unknown"
    } else if err.contains("BadCertificate") {
        "bad_certificate"
    } else if err.contains("UnsupportedCertificate") {
        "unsupported_certificate"
    } else if err.contains("AccessDenied") {
        "access_denied"
    } else {
        return None;
    };
    guest_certificate_rejection_detail_text(description)
}

fn format_upstream_eof_detail(
    upstream_handshaking: bool,
    guest_tls_established: bool,
    pending_guest_tls_bytes: usize,
    pending_upstream_plaintext_bytes: usize,
    last_guest_record: &str,
) -> String {
    let mut detail = String::with_capacity(
        "upstream EOF while upstream_handshaking=, guest_tls_established=, pending_guest_tls_bytes=, pending_upstream_plaintext_bytes=, last_guest_record="
            .len()
            + last_guest_record.len()
            + 64,
    );
    detail.push_str("upstream EOF while upstream_handshaking=");
    append_bool_text(&mut detail, upstream_handshaking);
    detail.push_str(", guest_tls_established=");
    append_bool_text(&mut detail, guest_tls_established);
    detail.push_str(", pending_guest_tls_bytes=");
    append_usize_decimal(&mut detail, pending_guest_tls_bytes);
    detail.push_str(", pending_upstream_plaintext_bytes=");
    append_usize_decimal(&mut detail, pending_upstream_plaintext_bytes);
    detail.push_str(", last_guest_record=");
    detail.push_str(last_guest_record);
    detail
}

fn host_closed_tcp_event(flow_id: FlowId) -> HostTcpEvent {
    HostTcpEvent::Close(CloseFlow {
        flow_id,
        reason: CloseReason::HostClosed,
    })
}

fn host_guest_ack_event(flow_id: FlowId, sequence: u64) -> HostTcpEvent {
    HostTcpEvent::Data(StreamChunk::new(
        flow_id,
        FlowDirection::HostToGuest,
        sequence,
        Vec::new(),
    ))
}

fn guest_certificate_rejection_detail_text(description: &str) -> Option<&'static str> {
    match description {
        "bad_certificate" => Some(
            "guest refused transformed TLS certificate (bad_certificate); likely certificate pinning or missing guest trust",
        ),
        "unsupported_certificate" => Some(
            "guest refused transformed TLS certificate (unsupported_certificate); likely certificate pinning or missing guest trust",
        ),
        "certificate_unknown" => Some(
            "guest refused transformed TLS certificate (certificate_unknown); likely certificate pinning or missing guest trust",
        ),
        "unknown_ca" => Some(
            "guest refused transformed TLS certificate (unknown_ca); likely certificate pinning or missing guest trust",
        ),
        "access_denied" => Some(
            "guest refused transformed TLS certificate (access_denied); likely certificate pinning or missing guest trust",
        ),
        _ => None,
    }
}

fn append_detail(slot: &mut Option<String>, next: Option<String>, max_bytes: usize) -> bool {
    let Some(next) = next.filter(|detail| !detail.is_empty()) else {
        return true;
    };
    match slot {
        Some(_) => append_detail_str(slot, Some(&next), max_bytes),
        None => {
            if next.len() > max_bytes {
                return false;
            }
            *slot = Some(next);
            true
        }
    }
}

fn append_detail_str(slot: &mut Option<String>, next: Option<&str>, max_bytes: usize) -> bool {
    let Some(next) = next.filter(|detail| !detail.is_empty()) else {
        return true;
    };
    match slot {
        Some(existing) => {
            let Some(combined_len) = existing
                .len()
                .checked_add(2)
                .and_then(|len| len.checked_add(next.len()))
            else {
                return false;
            };
            if combined_len > max_bytes {
                return false;
            }
            let additional_len = 2 + next.len();
            existing.reserve(additional_len);
            existing.push_str("; ");
            existing.push_str(next);
        }
        None => {
            if next.len() > max_bytes {
                return false;
            }
            *slot = Some(copy_detail_text(next));
        }
    }
    true
}

fn remove_retained_detail_if_current(
    details: &mut HashMap<FlowId, RetainedFlowDetail>,
    next: RetainedDetailRef,
) -> bool {
    if details
        .get(&next.flow_id)
        .is_some_and(|detail| detail.generation == next.generation)
    {
        details.remove(&next.flow_id);
        return true;
    }
    false
}

fn drop_retained_detail_refs(
    order: &mut VecDeque<RetainedDetailRef>,
    flow_id: FlowId,
    kind: RetainedDetailKind,
) {
    order.retain(|entry| !(entry.flow_id == flow_id && entry.kind == kind));
}

fn drop_flow_order_refs(order: &mut VecDeque<FlowId>, flow_id: FlowId) {
    order.retain(|entry| *entry != flow_id);
}

fn clamp_detail_string(mut detail: String, max_bytes: usize) -> String {
    if detail.len() <= max_bytes {
        return detail;
    }
    let mut end = max_bytes;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    detail
}

fn clamp_detail_text(detail: &str, max_bytes: usize) -> String {
    if detail.len() <= max_bytes {
        return copy_detail_text(detail);
    }
    let mut end = max_bytes;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    copy_detail_text(&detail[..end])
}

fn copy_detail_text(detail: &str) -> String {
    let mut owned = String::with_capacity(detail.len());
    owned.push_str(detail);
    owned
}

#[cfg(feature = "host-tls-boring")]
fn normalize_boring_budget_error(detail: String) -> GuestTlsTextError {
    if detail.contains(GUEST_TLS_BACKLOG_EXCEEDED_DETAIL) {
        return GuestTlsTextError::Borrowed(GUEST_TLS_BACKLOG_EXCEEDED_DETAIL);
    }
    GuestTlsTextError::Owned(detail)
}

fn split_guest_server_handshake_records(bytes: Vec<u8>, guest_tls_established: bool) -> Vec<u8> {
    if guest_tls_established || bytes.len() < 5 {
        return bytes;
    }

    let mut offset = 0usize;
    let mut out: Option<Vec<u8>> = None;
    while offset + 5 <= bytes.len() {
        let typ = bytes[offset];
        let version = [bytes[offset + 1], bytes[offset + 2]];
        let len = u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
        let body_start = offset + 5;
        let Some(body_end) = body_start.checked_add(len) else {
            return bytes;
        };
        if body_end > bytes.len() {
            return bytes;
        }

        let record = &bytes[offset..body_end];
        if typ != TLS_RECORD_TYPE_HANDSHAKE {
            if let Some(out) = out.as_mut() {
                out.extend_from_slice(record);
            }
            offset = body_end;
            continue;
        }

        match split_plaintext_server_handshake_record(version, &bytes[body_start..body_end]) {
            Some(split_records) => {
                let additional = split_records.len().saturating_sub(record.len());
                let out = out.get_or_insert_with(|| {
                    let mut out = Vec::with_capacity(bytes.len() + additional);
                    out.extend_from_slice(&bytes[..offset]);
                    out
                });
                out.extend_from_slice(&split_records);
            }
            None => {
                if let Some(out) = out.as_mut() {
                    out.extend_from_slice(record);
                }
            }
        }
        offset = body_end;
    }

    if offset != bytes.len() {
        return bytes;
    }
    out.unwrap_or(bytes)
}

fn split_plaintext_server_handshake_record(version: [u8; 2], body: &[u8]) -> Option<Vec<u8>> {
    let message_count = count_plaintext_server_handshake_messages(body)?;
    if message_count <= 1 {
        return None;
    }

    let mut offset = 0usize;
    let mut split = Vec::with_capacity(estimated_split_plaintext_server_handshake_record_len(
        body.len(),
        message_count,
    )?);
    while offset + 4 <= body.len() {
        let msg_len = ((body[offset + 1] as usize) << 16)
            | ((body[offset + 2] as usize) << 8)
            | body[offset + 3] as usize;
        let header_len = 4usize;
        let total_len = header_len.checked_add(msg_len)?;
        let body_end = offset.checked_add(total_len)?;
        if body_end > body.len() {
            return None;
        }
        split.push(TLS_RECORD_TYPE_HANDSHAKE);
        split.extend_from_slice(&version);
        split.extend_from_slice(&(total_len as u16).to_be_bytes());
        split.extend_from_slice(&body[offset..body_end]);
        offset = body_end;
    }
    if offset != body.len() {
        return None;
    }
    Some(split)
}

fn count_plaintext_server_handshake_messages(body: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    let mut messages = 0usize;
    while offset + 4 <= body.len() {
        let handshake_type = body[offset];
        if !is_plaintext_server_handshake_type(handshake_type) {
            return None;
        }
        let msg_len = ((body[offset + 1] as usize) << 16)
            | ((body[offset + 2] as usize) << 8)
            | body[offset + 3] as usize;
        let total_len = 4usize.checked_add(msg_len)?;
        let body_end = offset.checked_add(total_len)?;
        if body_end > body.len() {
            return None;
        }
        offset = body_end;
        messages = messages.checked_add(1)?;
    }
    if offset != body.len() {
        return None;
    }
    Some(messages)
}

fn estimated_split_plaintext_server_handshake_record_len(
    body_len: usize,
    message_count: usize,
) -> Option<usize> {
    body_len.checked_add(message_count.checked_mul(5)?)
}

fn is_plaintext_server_handshake_type(handshake_type: u8) -> bool {
    matches!(
        handshake_type,
        TLS_HANDSHAKE_TYPE_SERVER_HELLO
            | TLS_HANDSHAKE_TYPE_CERTIFICATE
            | TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
            | TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST
            | TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    )
}

fn summarize_client_hello(buf: &[u8]) -> Option<String> {
    let mut c = TlsCursor::new(buf);
    if c.u8()? != 0x16 {
        return None;
    }
    c.skip(2)?;
    let record_len = c.u16()? as usize;
    let record = c.take(record_len)?;
    let mut h = TlsCursor::new(record);
    if h.u8()? != 0x01 {
        return None;
    }
    let hello_len = h.u24()? as usize;
    let hello = h.take(hello_len)?;
    let mut b = TlsCursor::new(hello);
    let legacy_version = b.u16()?;
    b.skip(32)?;
    let session_id_len = b.u8()? as usize;
    b.skip(session_id_len)?;
    let cipher_suites_len = b.u16()? as usize;
    let cipher_suites = parse_u16_list_summary(b.take(cipher_suites_len)?)?;
    let compression_methods_len = b.u8()? as usize;
    b.skip(compression_methods_len)?;
    let extensions_len = b.u16()? as usize;
    let extensions = b.take(extensions_len)?;
    let mut sni = None;
    let mut supported_groups = None;
    let mut e = TlsCursor::new(extensions);
    while e.remaining() >= 4 {
        let ext_type = e.u16()?;
        let ext_len = e.u16()? as usize;
        let ext_body = e.take(ext_len)?;
        match ext_type {
            0x0000 => sni = parse_server_name_list(ext_body),
            0x000a => supported_groups = parse_supported_groups_summary(ext_body),
            _ => {}
        }
    }
    let cipher_suites_len = estimated_hex_list_summary_len(&cipher_suites);
    let supported_groups_len = supported_groups
        .as_ref()
        .map_or("<none>".len(), estimated_hex_list_summary_len);
    let mut summary = String::with_capacity(
        "client_hello legacy_version=0x sni= cipher_suites= supported_groups=".len()
            + 4
            + sni.unwrap_or("<none>").len()
            + cipher_suites_len
            + supported_groups_len
            + 2,
    );
    summary.push_str("client_hello legacy_version=0x");
    append_u16_hex_digits(&mut summary, legacy_version);
    summary.push_str(" sni=");
    summary.push_str(sni.unwrap_or("<none>"));
    summary.push_str(" cipher_suites=");
    summary.push('[');
    append_hex_list_summary(&mut summary, &cipher_suites);
    summary.push(']');
    summary.push_str(" supported_groups=");
    if let Some(groups) = supported_groups.as_ref() {
        summary.push('[');
        append_hex_list_summary(&mut summary, groups);
        summary.push(']');
    } else {
        summary.push_str("<none>");
    }
    Some(summary)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct U16ListSummary {
    values: Vec<u16>,
    total_count: usize,
}

fn parse_u16_list_summary(bytes: &[u8]) -> Option<U16ListSummary> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let total_count = bytes.len() / 2;
    let mut values = Vec::with_capacity(total_count.min(MAX_CLIENT_HELLO_SUMMARY_LIST_VALUES));
    for chunk in bytes.chunks_exact(2) {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        if values.len() < MAX_CLIENT_HELLO_SUMMARY_LIST_VALUES {
            values.push(value);
        }
    }
    Some(U16ListSummary {
        values,
        total_count,
    })
}

fn parse_supported_groups_summary(data: &[u8]) -> Option<U16ListSummary> {
    let mut cursor = TlsCursor::new(data);
    let groups_len = cursor.u16()? as usize;
    parse_u16_list_summary(cursor.take(groups_len)?)
}

fn parse_server_name_list(data: &[u8]) -> Option<&str> {
    let mut cursor = TlsCursor::new(data);
    let list_len = cursor.u16()? as usize;
    let list = cursor.take(list_len)?;
    let mut names = TlsCursor::new(list);
    while names.remaining() >= 3 {
        let name_type = names.u8()?;
        let name_len = names.u16()? as usize;
        let name = names.take(name_len)?;
        if name_type == 0x00 {
            return bounded_utf8_prefix(name, MAX_CLIENT_HELLO_SUMMARY_SNI_BYTES);
        }
    }
    None
}

fn bounded_utf8_prefix(bytes: &[u8], max_bytes: usize) -> Option<&str> {
    if bytes.len() <= max_bytes {
        return std::str::from_utf8(bytes).ok();
    }
    let end = match std::str::from_utf8(&bytes[..max_bytes]) {
        Ok(_) => max_bytes,
        Err(err) => err.valid_up_to(),
    };
    std::str::from_utf8(&bytes[..end]).ok()
}

#[cfg(test)]
fn format_hex_list_summary(summary: &U16ListSummary) -> String {
    let mut formatted = String::with_capacity(estimated_hex_list_summary_len(summary));
    formatted.push('[');
    append_hex_list_summary(&mut formatted, summary);
    formatted.push(']');
    formatted
}

fn estimated_hex_list_summary_len(summary: &U16ListSummary) -> usize {
    let rendered_values = summary.values.len().saturating_mul("0x0000".len());
    let commas_between_values = summary.values.len().saturating_sub(1);
    let more_suffix = if summary.total_count > summary.values.len() {
        let more_count = summary.total_count - summary.values.len();
        let more_digits = more_count.ilog10() as usize + 1;
        let leading_comma = usize::from(!summary.values.is_empty());
        leading_comma + "+ more".len() + more_digits
    } else {
        0
    };
    rendered_values + commas_between_values + more_suffix + 2
}

fn append_hex_list_summary(formatted: &mut String, summary: &U16ListSummary) {
    for (index, value) in summary.values.iter().enumerate() {
        if index > 0 {
            formatted.push(',');
        }
        append_u16_hex(formatted, *value);
    }
    if summary.total_count > summary.values.len() {
        if !summary.values.is_empty() {
            formatted.push(',');
        }
        formatted.push('+');
        append_usize_decimal(formatted, summary.total_count - summary.values.len());
        formatted.push_str(" more");
    }
}

fn append_u16_hex(formatted: &mut String, value: u16) {
    formatted.push_str("0x");
    append_u16_hex_digits(formatted, value);
}

fn append_u16_hex_digits(formatted: &mut String, value: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    formatted.push(HEX[((value >> 12) & 0x0f) as usize] as char);
    formatted.push(HEX[((value >> 8) & 0x0f) as usize] as char);
    formatted.push(HEX[((value >> 4) & 0x0f) as usize] as char);
    formatted.push(HEX[(value & 0x0f) as usize] as char);
}

fn append_usize_decimal(formatted: &mut String, value: usize) {
    if value == 0 {
        formatted.push('0');
        return;
    }
    let mut digits = [0u8; MAX_USIZE_DECIMAL_DIGITS];
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

fn append_bool_text(formatted: &mut String, value: bool) {
    if value {
        formatted.push_str("true");
    } else {
        formatted.push_str("false");
    }
}

struct TlsCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlsCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(((self.u8()? as u16) << 8) | self.u8()? as u16)
    }

    fn u24(&mut self) -> Option<u32> {
        Some(((self.u8()? as u32) << 16) | ((self.u8()? as u32) << 8) | self.u8()? as u32)
    }

    fn skip(&mut self, bytes: usize) -> Option<()> {
        let end = self.pos.checked_add(bytes)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    fn take(&mut self, bytes: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(bytes)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
}

fn load_pem_upstream_roots(bundle: &str) -> Result<rustls::RootCertStore, HostTlsConfigError> {
    let mut store = rustls::RootCertStore::empty();
    for cert in collect_pem_certs_bounded(bundle, MAX_UPSTREAM_ROOT_CERTIFICATES)
        .map_err(map_upstream_root_pem_collection_error)?
    {
        store.add(cert).map_err(invalid_upstream_roots_owned)?;
    }
    Ok(store)
}

pub(crate) fn validate_upstream_roots(
    upstream_roots: &HostTlsUpstreamRoots,
) -> Result<(), HostTlsConfigError> {
    if let HostTlsUpstreamRoots::PemBundle(bundle) = upstream_roots {
        validate_upstream_root_pem_bundle(bundle)?;
    }
    Ok(())
}

pub(crate) fn validate_guest_intermediate(
    guest_intermediate: &HostTlsIntermediate,
) -> Result<(), HostTlsConfigError> {
    if guest_intermediate.cert_pem.trim().is_empty() {
        return Err(HostTlsConfigError::EmptyGuestIntermediateCert);
    }
    if guest_intermediate.key_pem.trim().is_empty() {
        return Err(HostTlsConfigError::EmptyGuestIntermediateKey);
    }
    if guest_intermediate.cert_pem.len() > MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES {
        return Err(HostTlsConfigError::GuestIntermediateCertPemTooLarge {
            actual: guest_intermediate.cert_pem.len(),
            max: MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES,
        });
    }
    if guest_intermediate.key_pem.len() > MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES {
        return Err(HostTlsConfigError::GuestIntermediateKeyPemTooLarge {
            actual: guest_intermediate.key_pem.len(),
            max: MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES,
        });
    }
    collect_pem_certs_bounded(
        &guest_intermediate.cert_pem,
        MAX_GUEST_INTERMEDIATE_CERTIFICATES,
    )
    .map_err(map_guest_intermediate_pem_collection_error)?;
    Ok(())
}

fn validate_upstream_root_pem_bundle(bundle: &str) -> Result<(), HostTlsConfigError> {
    if bundle.trim().is_empty() {
        return Err(HostTlsConfigError::EmptyUpstreamRootPem);
    }
    if bundle.len() > MAX_UPSTREAM_ROOT_PEM_BYTES {
        return Err(HostTlsConfigError::UpstreamRootPemTooLarge {
            actual: bundle.len(),
            max: MAX_UPSTREAM_ROOT_PEM_BYTES,
        });
    }
    collect_pem_certs_bounded(bundle, MAX_UPSTREAM_ROOT_CERTIFICATES)
        .map_err(map_upstream_root_pem_collection_error)?;
    Ok(())
}

fn upstream_client_config(
    roots: &HostTlsUpstreamRoots,
) -> Result<rustls::ClientConfig, HostTlsConfigError> {
    let builder = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions are valid");
    match roots {
        HostTlsUpstreamRoots::Native => builder
            .with_platform_verifier()
            .map_err(native_root_load_owned)
            .map(|builder| builder.with_no_client_auth()),
        HostTlsUpstreamRoots::PemBundle(bundle) => {
            let roots = load_pem_upstream_roots(bundle)?;
            Ok(builder.with_root_certificates(roots).with_no_client_auth())
        }
    }
}

#[cfg(any(not(feature = "host-tls-boring"), test))]
fn server_config_for_sni(
    intermediate: &VmIntermediate,
    sni: &str,
) -> Result<rustls::ServerConfig, HostTlsConfigError> {
    let leaf = intermediate
        .mint_leaf(sni)
        .map_err(invalid_guest_intermediate_owned)?;
    let mut chain = collect_pem_certs_bounded(&leaf.cert_pem, MAX_GUEST_INTERMEDIATE_CERTIFICATES)
        .map_err(map_guest_intermediate_pem_collection_error)?;
    chain.extend(
        collect_pem_certs_bounded(intermediate.cert_pem(), MAX_GUEST_INTERMEDIATE_CERTIFICATES)
            .map_err(map_guest_intermediate_pem_collection_error)?,
    );
    let key = pem_private_key(&leaf.key_pem).map_err(invalid_guest_intermediate_owned)?;
    rustls::ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .map_err(invalid_guest_intermediate_owned)?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(invalid_guest_intermediate_owned)
}

#[cfg(feature = "host-tls-boring")]
fn boring_acceptor_for_sni(
    intermediate: &VmIntermediate,
    sni: &str,
) -> Result<SslAcceptor, HostTlsConfigError> {
    let leaf = intermediate
        .mint_leaf(sni)
        .map_err(invalid_guest_intermediate_owned)?;
    let mut chain =
        X509::stack_from_pem(leaf.cert_pem.as_bytes()).map_err(invalid_guest_intermediate_owned)?;
    chain.extend(
        X509::stack_from_pem(intermediate.cert_pem().as_bytes())
            .map_err(invalid_guest_intermediate_owned)?,
    );
    let Some((leaf_cert, extra_chain)) = chain.split_first() else {
        return Err(invalid_guest_intermediate_borrowed(
            "minted guest leaf chain was empty",
        ));
    };
    let key = PKey::<Private>::private_key_from_pem(leaf.key_pem.as_bytes())
        .map_err(invalid_guest_intermediate_owned)?;
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .map_err(invalid_guest_intermediate_owned)?;
    acceptor.set_verify(SslVerifyMode::NONE);
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(invalid_guest_intermediate_owned)?;
    acceptor
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .map_err(invalid_guest_intermediate_owned)?;
    acceptor
        .set_curves_list("P-256:X25519")
        .map_err(invalid_guest_intermediate_owned)?;
    acceptor
        .set_certificate(leaf_cert)
        .map_err(invalid_guest_intermediate_owned)?;
    acceptor
        .set_private_key(&key)
        .map_err(invalid_guest_intermediate_owned)?;
    for cert in extra_chain {
        acceptor
            .add_extra_chain_cert(cert.clone())
            .map_err(invalid_guest_intermediate_owned)?;
    }
    acceptor
        .check_private_key()
        .map_err(invalid_guest_intermediate_owned)?;
    Ok(acceptor.build())
}

#[derive(Debug)]
enum PemCertCollectionError {
    Empty,
    Parse(io::Error),
    TooMany { actual: usize, max: usize },
}

fn collect_pem_certs_bounded(
    pem: &str,
    max_certificates: usize,
) -> Result<Vec<CertificateDer<'static>>, PemCertCollectionError> {
    let mut certs =
        Vec::with_capacity(count_pem_certificate_markers_bounded(pem, max_certificates));
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        certs.push(cert.map_err(|err| PemCertCollectionError::Parse(io::Error::other(err)))?);
        if certs.len() > max_certificates {
            return Err(PemCertCollectionError::TooMany {
                actual: certs.len(),
                max: max_certificates,
            });
        }
    }
    if certs.is_empty() {
        return Err(PemCertCollectionError::Empty);
    }
    Ok(certs)
}

fn count_pem_certificate_markers_bounded(pem: &str, max_markers: usize) -> usize {
    pem.match_indices("-----BEGIN CERTIFICATE-----")
        .take(max_markers)
        .count()
}

fn map_guest_intermediate_pem_collection_error(err: PemCertCollectionError) -> HostTlsConfigError {
    match err {
        PemCertCollectionError::Empty => {
            invalid_guest_intermediate_borrowed("PEM bundle did not contain any certificate")
        }
        PemCertCollectionError::Parse(err) => invalid_guest_intermediate_owned(err),
        PemCertCollectionError::TooMany { actual, max } => {
            HostTlsConfigError::TooManyGuestIntermediateCertificates { actual, max }
        }
    }
}

fn map_upstream_root_pem_collection_error(err: PemCertCollectionError) -> HostTlsConfigError {
    match err {
        PemCertCollectionError::Empty => {
            invalid_upstream_roots_borrowed("PEM bundle did not contain any certificate")
        }
        PemCertCollectionError::Parse(err) => invalid_upstream_roots_owned(err),
        PemCertCollectionError::TooMany { actual, max } => {
            HostTlsConfigError::TooManyUpstreamRootCertificates { actual, max }
        }
    }
}

#[cfg(test)]
fn pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, io::Error> {
    collect_pem_certs_bounded(pem, usize::MAX).map_err(|err| match err {
        PemCertCollectionError::Empty => io::Error::new(
            io::ErrorKind::InvalidData,
            "PEM bundle did not contain any certificate",
        ),
        PemCertCollectionError::Parse(err) => err,
        PemCertCollectionError::TooMany { .. } => io::Error::new(
            io::ErrorKind::InvalidData,
            "PEM bundle exceeded configured certificate budget",
        ),
    })
}

#[cfg(any(not(feature = "host-tls-boring"), test))]
fn pem_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, io::Error> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    use mvm_core::crypto::egress_ca::EgressCa;
    use mvm_core::ingress_redaction::REDACTION_MASK;
    use mvm_core::policy::secret_binding::SecretBinding;

    use super::*;
    use crate::host::HostRoute;
    use crate::proto::{DnsName, OpenTcp, PluginId, Target, TlsTransformRoute};

    fn oversized_pem_bundle(cert_pem: &str) -> String {
        let repeats = (MAX_UPSTREAM_ROOT_PEM_BYTES / cert_pem.len()) + 1;
        cert_pem.repeat(repeats)
    }

    fn overlong_cert_count_bundle(cert_pem: &str) -> String {
        cert_pem.repeat(MAX_UPSTREAM_ROOT_CERTIFICATES + 1)
    }

    fn oversized_guest_intermediate_cert_bundle(cert_pem: &str) -> String {
        let repeats = (MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES / cert_pem.len()) + 1;
        cert_pem.repeat(repeats)
    }

    fn oversized_guest_intermediate_key_pem(key_pem: &str) -> String {
        let repeats = (MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES / key_pem.len()) + 1;
        key_pem.repeat(repeats)
    }

    fn overlong_guest_intermediate_cert_count_bundle(cert_pem: &str) -> String {
        cert_pem.repeat(MAX_GUEST_INTERMEDIATE_CERTIFICATES + 1)
    }

    #[test]
    fn parse_u16_list_summary_caps_retained_values_but_preserves_total_count() {
        let bytes: Vec<u8> = (0..(MAX_CLIENT_HELLO_SUMMARY_LIST_VALUES as u16 + 4))
            .flat_map(|value| value.to_be_bytes())
            .collect();

        let summary = parse_u16_list_summary(&bytes).unwrap();

        assert_eq!(
            summary.values,
            (0..MAX_CLIENT_HELLO_SUMMARY_LIST_VALUES as u16).collect::<Vec<_>>()
        );
        assert_eq!(
            summary.total_count,
            MAX_CLIENT_HELLO_SUMMARY_LIST_VALUES + 4
        );
    }

    #[test]
    fn parse_u16_list_summary_rejects_odd_length_input() {
        assert_eq!(parse_u16_list_summary(&[0x00, 0x01, 0x02]), None);
    }

    #[test]
    fn format_hex_list_summary_preserves_prefix_and_more_suffix() {
        let summary = U16ListSummary {
            values: vec![0x0001, 0x0002, 0x0003],
            total_count: 5,
        };

        assert_eq!(
            format_hex_list_summary(&summary),
            "[0x0001,0x0002,0x0003,+2 more]"
        );
    }

    #[test]
    fn summarize_client_hello_preserves_exact_summary_output() {
        let record = test_client_hello_record(b"api.example.com");

        assert_eq!(
            summarize_client_hello(&record).as_deref(),
            Some(
                "client_hello legacy_version=0x0303 sni=api.example.com cipher_suites=[0x1301,0x1302] supported_groups=[0x0017,0x001d]"
            )
        );
    }

    #[test]
    fn format_upstream_eof_detail_preserves_exact_output() {
        assert_eq!(
            format_upstream_eof_detail(true, false, 17, 23, "handshake(version=0x0303,len=42)"),
            "upstream EOF while upstream_handshaking=true, guest_tls_established=false, pending_guest_tls_bytes=17, pending_upstream_plaintext_bytes=23, last_guest_record=handshake(version=0x0303,len=42)"
        );
    }

    #[test]
    fn upstream_server_name_matches_owned_string_conversion() {
        let dns_name = DnsName::new("api.example.com").unwrap();

        assert_eq!(
            upstream_server_name(&dns_name).unwrap(),
            ServerName::try_from("api.example.com".to_string()).unwrap()
        );
    }

    #[test]
    fn guest_certificate_rejection_detail_text_preserves_exact_output() {
        assert_eq!(
            guest_certificate_rejection_detail_text("unknown_ca"),
            Some(
                "guest refused transformed TLS certificate (unknown_ca); likely certificate pinning or missing guest trust"
            )
        );
    }

    #[test]
    fn guest_certificate_rejection_detail_text_rejects_unknown_description() {
        assert_eq!(guest_certificate_rejection_detail_text("other_alert"), None);
    }

    #[test]
    fn summary_contains_alert_description_matches_exact_alert_field_without_allocating() {
        let summary = "alert(version=0x0303,len=2,level=fatal,description=unknown_ca)";
        assert!(summary_contains_alert_description(summary, "unknown_ca"));
        assert!(!summary_contains_alert_description(summary, "unknown"));
        assert!(!summary_contains_alert_description(
            summary,
            "certificate_unknown"
        ));
    }

    #[test]
    fn guest_certificate_alert_description_returns_matching_fatal_certificate_alert() {
        let summary = "alert(version=0x0303,len=2,level=fatal,description=certificate_unknown)";
        assert_eq!(
            guest_certificate_alert_description(summary),
            Some("certificate_unknown")
        );
        assert_eq!(
            guest_certificate_alert_description(
                "alert(version=0x0303,len=2,level=warning,description=certificate_unknown)"
            ),
            None
        );
    }

    #[test]
    fn guest_certificate_rejection_from_error_maps_unknown_ca_detail() {
        assert_eq!(
            guest_certificate_rejection_from_error("InvalidCertificate(UnknownCA)"),
            Some(
                "guest refused transformed TLS certificate (unknown_ca); likely certificate pinning or missing guest trust"
            )
        );
    }

    #[test]
    fn guest_certificate_rejection_from_error_ignores_unmatched_errors() {
        assert_eq!(
            guest_certificate_rejection_from_error("peer closed connection"),
            None
        );
    }

    #[test]
    fn parse_server_name_list_truncates_retained_sni_to_summary_budget() {
        let server_name = "a".repeat(MAX_CLIENT_HELLO_SUMMARY_SNI_BYTES + 7);
        let mut payload = Vec::new();
        let list_len = 1 + 2 + server_name.len();
        payload.extend_from_slice(&(list_len as u16).to_be_bytes());
        payload.push(0x00);
        payload.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        payload.extend_from_slice(server_name.as_bytes());

        let parsed = parse_server_name_list(&payload).unwrap();

        assert_eq!(parsed.len(), MAX_CLIENT_HELLO_SUMMARY_SNI_BYTES);
        assert_eq!(parsed, "a".repeat(MAX_CLIENT_HELLO_SUMMARY_SNI_BYTES));
    }

    #[test]
    fn bounded_utf8_prefix_borrows_exact_prefix_without_owned_copy() {
        let bytes = b"api.example.com";
        let parsed = bounded_utf8_prefix(bytes, 64).unwrap();

        assert_eq!(parsed, "api.example.com");
        assert_eq!(parsed.as_ptr(), bytes.as_ptr());
    }

    #[test]
    fn bounded_utf8_prefix_preserves_utf8_boundary_when_truncated() {
        let parsed = bounded_utf8_prefix("alpha🙂beta".as_bytes(), 7).unwrap();

        assert_eq!(parsed, "alpha");
    }

    #[test]
    fn bounded_utf8_prefix_returns_empty_prefix_for_truncated_invalid_leading_byte() {
        let parsed = bounded_utf8_prefix(&[0xff, b'a', b'b'], 1).unwrap();

        assert_eq!(parsed, "");
    }

    #[test]
    fn split_guest_server_handshake_records_reuses_input_buffer_when_unchanged() {
        let bytes = vec![0x17, 0x03, 0x03, 0x00, 0x01, 0xaa];
        let original_ptr = bytes.as_ptr();

        let split = split_guest_server_handshake_records(bytes, false);

        assert_eq!(split, vec![0x17, 0x03, 0x03, 0x00, 0x01, 0xaa]);
        assert_eq!(split.as_ptr(), original_ptr);
    }

    #[test]
    fn split_guest_server_handshake_records_rewrites_multi_message_server_flight() {
        let mut bytes = vec![TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x08];
        bytes.extend_from_slice(&[TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE, 0x00, 0x00, 0x00]);
        bytes.extend_from_slice(&[TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE, 0x00, 0x00, 0x00]);
        let original_ptr = bytes.as_ptr();

        let split = split_guest_server_handshake_records(bytes, false);

        let summary = summarize_tls_records(&split).unwrap();
        assert_eq!(summary.matches("handshake(").count(), 2);
        assert_ne!(split.as_ptr(), original_ptr);
    }

    #[test]
    fn count_plaintext_server_handshake_messages_counts_complete_server_flight() {
        let body = [
            TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE,
            0x00,
            0x00,
            0x00,
            TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE,
            0x00,
            0x00,
            0x00,
        ];

        let count = count_plaintext_server_handshake_messages(&body);

        assert_eq!(count, Some(2));
        assert_eq!(
            estimated_split_plaintext_server_handshake_record_len(body.len(), count.unwrap()),
            Some(body.len() + 10)
        );
    }

    #[test]
    fn count_plaintext_server_handshake_messages_rejects_truncated_body() {
        let body = [TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE, 0x00, 0x00, 0x04, 0x01];

        assert_eq!(count_plaintext_server_handshake_messages(&body), None);
    }

    #[test]
    fn clamp_detail_text_truncates_without_owned_input() {
        let detail = clamp_detail_text("abcdef", 4);

        assert_eq!(detail, "abcd");
    }

    #[test]
    fn clamp_detail_text_preserves_utf8_boundaries() {
        let detail = clamp_detail_text("alpha🙂beta", 7);

        assert_eq!(detail, "alpha");
    }

    #[test]
    fn append_detail_str_appends_borrowed_detail_without_preclone() {
        let mut detail = Some("prefix".to_string());

        assert!(append_detail_str(&mut detail, Some("suffix"), 32));

        assert_eq!(detail.as_deref(), Some("prefix; suffix"));
    }

    #[test]
    fn append_detail_str_preserves_existing_buffer_when_capacity_is_sufficient() {
        let mut existing = String::with_capacity(16);
        existing.push_str("prefix");
        let initial_ptr = existing.as_ptr();
        let mut detail = Some(existing);

        assert!(append_detail_str(&mut detail, Some("suffix"), 32));

        let detail = detail.expect("detail should remain present");
        assert_eq!(detail, "prefix; suffix");
        assert_eq!(detail.as_ptr(), initial_ptr);
    }

    #[test]
    fn append_detail_str_rejects_over_budget_borrowed_detail() {
        let mut detail = Some("prefix".to_string());

        assert!(!append_detail_str(&mut detail, Some("suffix"), 12));

        assert_eq!(detail.as_deref(), Some("prefix"));
    }

    #[test]
    fn append_detail_moves_owned_detail_without_copy_when_slot_is_empty() {
        let owned = String::from("suffix");
        let initial_ptr = owned.as_ptr();
        let mut detail = None;

        assert!(append_detail(&mut detail, Some(owned), 32));

        let detail = detail.expect("detail should be present");
        assert_eq!(detail, "suffix");
        assert_eq!(detail.as_ptr(), initial_ptr);
    }

    #[test]
    fn append_usize_decimal_formats_usize_max() {
        let mut formatted = String::new();

        append_usize_decimal(&mut formatted, usize::MAX);

        assert_eq!(formatted, usize::MAX.to_string());
    }

    #[cfg(not(feature = "host-tls-boring"))]
    #[test]
    fn rustls_guest_tls_server_take_tls_bytes_preserves_buffer_capacity() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let mut server =
            RustlsGuestTlsServer::new(&guest_intermediate, "api.example.com", 4096).unwrap();
        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();
        let mut client_hello = Vec::new();
        guest_tls.write_tls(&mut client_hello).unwrap();

        server.outbound = Vec::with_capacity(4096);
        let initial_capacity = server.outbound.capacity();

        server.feed_tls(&client_hello).unwrap();
        let initial_ptr = server.outbound.as_ptr();
        let tls_bytes = server.take_tls_bytes().unwrap();

        assert!(!tls_bytes.is_empty());
        assert_eq!(tls_bytes.as_ptr(), initial_ptr);
        assert!(server.outbound.is_empty());
        assert_eq!(server.outbound.capacity(), initial_capacity);
    }

    #[cfg(not(feature = "host-tls-boring"))]
    #[test]
    fn rustls_guest_tls_server_seeds_bounded_outbound_capacity() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let server =
            RustlsGuestTlsServer::new(&guest_intermediate, "api.example.com", 1024).unwrap();

        assert_eq!(
            server.outbound.capacity(),
            initial_tls_buffer_capacity(1024)
        );
    }

    #[cfg(feature = "host-tls-boring")]
    #[test]
    fn buffered_tls_io_compacts_unread_tail_in_place_after_partial_read() {
        let mut io = BufferedTlsIo::new(32);
        io.push_inbound(b"abcdef").unwrap();

        let mut buf = [0u8; 2];
        let read = io.read(&mut buf).unwrap();

        assert_eq!(read, 2);
        assert_eq!(&buf, b"ab");
        assert_eq!(io.pending_inbound_len(), 4);
        assert_eq!(io.inbound, b"cdef");
        assert_eq!(io.inbound_offset, 0);
    }

    #[cfg(feature = "host-tls-boring")]
    #[test]
    fn buffered_tls_io_clears_inbound_state_after_full_read() {
        let mut io = BufferedTlsIo::new(32);
        io.push_inbound(b"abc").unwrap();

        let mut buf = [0u8; 3];
        let read = io.read(&mut buf).unwrap();

        assert_eq!(read, 3);
        assert_eq!(&buf, b"abc");
        assert_eq!(io.pending_inbound_len(), 0);
        assert!(io.inbound.is_empty());
        assert_eq!(io.inbound_offset, 0);
    }

    #[cfg(feature = "host-tls-boring")]
    #[test]
    fn buffered_tls_io_drain_outbound_preserves_buffer_capacity() {
        let mut io = BufferedTlsIo::new(32);
        io.outbound = Vec::with_capacity(24);
        io.outbound.extend_from_slice(b"server-flight");
        let initial_capacity = io.outbound.capacity();
        let initial_ptr = io.outbound.as_ptr();

        let drained = io.drain_outbound();

        assert_eq!(drained, b"server-flight");
        assert_eq!(drained.as_ptr(), initial_ptr);
        assert!(io.outbound.is_empty());
        assert_eq!(io.outbound.capacity(), initial_capacity);
    }

    #[cfg(feature = "host-tls-boring")]
    #[test]
    fn buffered_tls_io_seeds_bounded_inbound_and_outbound_capacity() {
        let io = BufferedTlsIo::new(1024);

        assert_eq!(io.inbound.capacity(), initial_tls_buffer_capacity(1024));
        assert_eq!(io.outbound.capacity(), initial_tls_buffer_capacity(1024));
    }

    #[test]
    fn collect_pem_certs_bounded_rejects_oversized_upstream_root_bundle_during_collection() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = collect_pem_certs_bounded(
            &overlong_cert_count_bundle(guest_intermediate.cert_pem()),
            MAX_UPSTREAM_ROOT_CERTIFICATES,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            PemCertCollectionError::TooMany {
                actual: _,
                max: MAX_UPSTREAM_ROOT_CERTIFICATES,
            }
        ));
    }

    #[test]
    fn collect_pem_certs_bounded_accepts_budget_sized_upstream_root_bundle() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let certs = collect_pem_certs_bounded(
            &guest_intermediate
                .cert_pem()
                .repeat(MAX_UPSTREAM_ROOT_CERTIFICATES),
            MAX_UPSTREAM_ROOT_CERTIFICATES,
        )
        .unwrap();

        assert_eq!(certs.len(), MAX_UPSTREAM_ROOT_CERTIFICATES);
    }

    #[test]
    fn collect_pem_certs_bounded_seeds_capacity_from_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let certs = collect_pem_certs_bounded(
            &guest_intermediate
                .cert_pem()
                .repeat(MAX_GUEST_INTERMEDIATE_CERTIFICATES),
            MAX_GUEST_INTERMEDIATE_CERTIFICATES,
        )
        .unwrap();

        assert_eq!(certs.len(), MAX_GUEST_INTERMEDIATE_CERTIFICATES);
        assert!(certs.capacity() >= MAX_GUEST_INTERMEDIATE_CERTIFICATES);
    }

    #[test]
    fn count_pem_certificate_markers_bounded_caps_at_requested_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let pem = guest_intermediate.cert_pem().repeat(8);

        assert_eq!(count_pem_certificate_markers_bounded(&pem, 0), 0);
        assert_eq!(count_pem_certificate_markers_bounded(&pem, 3), 3);
        assert_eq!(count_pem_certificate_markers_bounded(&pem, 16), 8);
    }

    #[test]
    fn pem_certs_accepts_guest_intermediate_under_unbounded_test_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let certs = pem_certs(guest_intermediate.cert_pem()).unwrap();

        assert!(!certs.is_empty());
    }

    #[test]
    fn empty_guest_intermediate_pem_collection_error_uses_borrowed_detail() {
        let err = map_guest_intermediate_pem_collection_error(PemCertCollectionError::Empty);

        assert_eq!(
            err,
            HostTlsConfigError::InvalidGuestIntermediate(Cow::Borrowed(
                "PEM bundle did not contain any certificate",
            ))
        );
    }

    #[test]
    fn empty_upstream_root_pem_collection_error_uses_borrowed_detail() {
        let err = map_upstream_root_pem_collection_error(PemCertCollectionError::Empty);

        assert_eq!(
            err,
            HostTlsConfigError::InvalidUpstreamRoots(Cow::Borrowed(
                "PEM bundle did not contain any certificate",
            ))
        );
    }

    fn test_host_tls_connector_builder(
        guest_intermediate: &VmIntermediate,
    ) -> HostTlsConnectorConfigBuilder {
        HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::Native)
    }

    fn test_client_hello_record(server_name: &[u8]) -> Vec<u8> {
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&((server_name.len() + 3) as u16).to_be_bytes());
        sni_body.push(0x00);
        sni_body.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        sni_body.extend_from_slice(server_name);

        let mut supported_groups_body = Vec::new();
        supported_groups_body.extend_from_slice(&4u16.to_be_bytes());
        supported_groups_body.extend_from_slice(&0x0017u16.to_be_bytes());
        supported_groups_body.extend_from_slice(&0x001du16.to_be_bytes());

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_body);
        extensions.extend_from_slice(&0x000au16.to_be_bytes());
        extensions.extend_from_slice(&(supported_groups_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&supported_groups_body);

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&4u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&0x1302u16.to_be_bytes());
        hello.push(0x01);
        hello.push(0x00);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hello_len = hello.len() as u32;
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&0x0303u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn open_test_tls_flow_state(
        max_tls_flow_detail_bytes: usize,
    ) -> (TlsFlowState, thread::JoinHandle<()>) {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
        });
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_tls_flow_detail_bytes(max_tls_flow_detail_bytes)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(1).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        let spec =
            TcpConnectSpec::from_open(&open, HostRoute::resolved_ip("127.0.0.1".parse().unwrap()));
        let state = connector.open_flow(&spec).unwrap();
        (state, join)
    }

    #[test]
    fn connector_rejects_missing_guest_intermediate() {
        let err = HostTlsConnectorConfig::builder().build().unwrap_err();
        assert_eq!(err, HostTlsConfigError::MissingGuestIntermediate);
    }

    #[test]
    fn connector_rejects_missing_upstream_roots() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .build()
            .unwrap_err();
        assert_eq!(err, HostTlsConfigError::MissingUpstreamRoots);
    }

    #[test]
    fn connector_rejects_zero_pending_guest_tls_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_pending_guest_tls_bytes(0)
            .build()
            .unwrap_err();

        assert_eq!(err, HostTlsConfigError::ZeroMaxPendingGuestTlsBytes);
    }

    #[test]
    fn connector_rejects_zero_open_flow_limit() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_open_flows(0)
            .build()
            .unwrap_err();

        assert_eq!(err, HostTlsConfigError::ZeroMaxOpenFlows);
    }

    #[test]
    fn connector_rejects_oversized_open_flow_limit() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_open_flows(MAX_OPEN_FLOWS + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            HostTlsConfigError::MaxOpenFlowsTooLarge {
                actual: MAX_OPEN_FLOWS + 1,
                max: MAX_OPEN_FLOWS,
            }
        );
    }

    #[test]
    fn connector_rejects_zero_pending_upstream_tls_plaintext_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_pending_upstream_tls_plaintext_bytes(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            HostTlsConfigError::ZeroMaxPendingUpstreamTlsPlaintextBytes
        );
    }

    #[test]
    fn connector_rejects_oversized_pending_guest_tls_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_pending_guest_tls_bytes(MAX_PENDING_GUEST_TLS_BYTES + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            HostTlsConfigError::MaxPendingGuestTlsBytesTooLarge {
                actual: MAX_PENDING_GUEST_TLS_BYTES + 1,
                max: MAX_PENDING_GUEST_TLS_BYTES,
            }
        );
    }

    #[test]
    fn connector_rejects_oversized_guest_intermediate_cert_pem() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .guest_intermediate(HostTlsIntermediate::new(
                oversized_guest_intermediate_cert_bundle(guest_intermediate.cert_pem()),
                guest_intermediate.key_pem(),
            ))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostTlsConfigError::GuestIntermediateCertPemTooLarge {
                actual: _,
                max: MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES
            }
        ));
    }

    #[test]
    fn connector_rejects_oversized_guest_intermediate_key_pem() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                oversized_guest_intermediate_key_pem(&guest_intermediate.key_pem()),
            ))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostTlsConfigError::GuestIntermediateKeyPemTooLarge {
                actual: _,
                max: MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES
            }
        ));
    }

    #[test]
    fn connector_rejects_guest_intermediate_with_too_many_certificates() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .guest_intermediate(HostTlsIntermediate::new(
                overlong_guest_intermediate_cert_count_bundle(guest_intermediate.cert_pem()),
                guest_intermediate.key_pem(),
            ))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostTlsConfigError::TooManyGuestIntermediateCertificates {
                actual: _,
                max: MAX_GUEST_INTERMEDIATE_CERTIFICATES
            }
        ));
    }

    #[test]
    fn connector_rejects_zero_tls_flow_detail_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_tls_flow_detail_bytes(0)
            .build()
            .unwrap_err();

        assert_eq!(err, HostTlsConfigError::ZeroMaxTlsFlowDetailBytes);
    }

    #[test]
    fn connector_rejects_oversized_pending_upstream_tls_plaintext_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_pending_upstream_tls_plaintext_bytes(MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            HostTlsConfigError::MaxPendingUpstreamTlsPlaintextBytesTooLarge {
                actual: MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES + 1,
                max: MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES,
            }
        );
    }

    #[test]
    fn connector_rejects_oversized_tls_flow_detail_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_tls_flow_detail_bytes(MAX_TLS_FLOW_DETAIL_BYTES + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            HostTlsConfigError::MaxTlsFlowDetailBytesTooLarge {
                actual: MAX_TLS_FLOW_DETAIL_BYTES + 1,
                max: MAX_TLS_FLOW_DETAIL_BYTES,
            }
        );
    }

    #[test]
    fn connector_rejects_oversized_upstream_root_pem_bundle() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(oversized_pem_bundle(
                guest_intermediate.cert_pem(),
            )))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostTlsConfigError::UpstreamRootPemTooLarge {
                actual: _,
                max: MAX_UPSTREAM_ROOT_PEM_BYTES
            }
        ));
    }

    #[test]
    fn connector_rejects_upstream_root_bundle_with_too_many_certificates() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(overlong_cert_count_bundle(
                guest_intermediate.cert_pem(),
            )))
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            HostTlsConfigError::TooManyUpstreamRootCertificates {
                actual: _,
                max: MAX_UPSTREAM_ROOT_CERTIFICATES
            }
        ));
    }

    #[test]
    fn connector_rejects_zero_retained_tls_flow_detail_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_retained_tls_flow_details(0)
            .build()
            .unwrap_err();

        assert_eq!(err, HostTlsConfigError::ZeroMaxRetainedTlsFlowDetails);
    }

    #[test]
    fn connector_rejects_oversized_retained_tls_flow_detail_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let err = test_host_tls_connector_builder(&guest_intermediate)
            .max_retained_tls_flow_details(MAX_RETAINED_TLS_FLOW_DETAILS + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err,
            HostTlsConfigError::MaxRetainedTlsFlowDetailsTooLarge {
                actual: MAX_RETAINED_TLS_FLOW_DETAILS + 1,
                max: MAX_RETAINED_TLS_FLOW_DETAILS,
            }
        );
    }

    #[test]
    fn tls_connector_evicts_oldest_retained_open_error_detail_when_budget_is_exceeded() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_retained_tls_flow_details(2)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let target = Target::new("api.example.com", 443).unwrap();

        for flow in 1..=3 {
            let flow_id = FlowId::new(flow).unwrap();
            let open = OpenTcp::new(flow_id, target.clone()).with_tls_transform(
                TlsTransformRoute::new(
                    DnsName::new("api.example.com").unwrap(),
                    TlsTermination::TerminateAndReoriginate,
                )
                .with_transform_chain(vec![PluginId::new("unknown-test-plugin").unwrap()]),
            );
            let spec = TcpConnectSpec::from_open(&open, HostRoute::unresolved());
            assert_eq!(connector.open(&spec), Err(TransportError::TransformError));
        }

        assert_eq!(connector.take_error_detail(FlowId::new(1).unwrap()), None);
        assert!(
            connector
                .take_error_detail(FlowId::new(2).unwrap())
                .is_some_and(|detail| detail.contains("unknown-test-plugin")),
            "second retained detail should still be present"
        );
        assert!(
            connector
                .take_error_detail(FlowId::new(3).unwrap())
                .is_some_and(|detail| detail.contains("unknown-test-plugin")),
            "third retained detail should still be present"
        );
    }

    #[test]
    fn tls_connector_replaces_retained_detail_without_growing_stale_queue_entries() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_retained_tls_flow_details(4)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(1).unwrap();

        for index in 0..32 {
            connector.store_retained_detail(
                RetainedDetailKind::Activity,
                flow_id,
                format!("activity-{index}"),
            );
        }

        assert_eq!(connector.pending_activity_details.len(), 1);
        assert!(connector.pending_error_details.is_empty());
        assert!(connector.pending_close_details.is_empty());
        assert_eq!(connector.pending_detail_order.len(), 1);
        assert_eq!(
            connector.take_activity_detail(flow_id).as_deref(),
            Some("activity-31")
        );
        assert!(connector.pending_detail_order.is_empty());
    }

    #[test]
    fn tls_connector_take_error_detail_drains_retained_activity_detail_for_same_flow() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_retained_tls_flow_details(4)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(1).unwrap();

        connector.store_retained_detail(
            RetainedDetailKind::Activity,
            flow_id,
            "activity-detail".to_string(),
        );
        connector.store_retained_detail(
            RetainedDetailKind::Error,
            flow_id,
            "error-detail".to_string(),
        );

        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("error-detail; activity-detail")
        );
        assert!(connector.pending_activity_details.is_empty());
        assert!(connector.pending_error_details.is_empty());
        assert!(connector.pending_close_details.is_empty());
        assert!(connector.pending_detail_order.is_empty());
    }

    #[test]
    fn tls_connector_take_error_detail_prefers_retained_error_before_close() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_retained_tls_flow_details(4)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(1).unwrap();

        connector.store_retained_detail(
            RetainedDetailKind::Close,
            flow_id,
            "close-detail".to_string(),
        );
        connector.store_retained_detail(
            RetainedDetailKind::Error,
            flow_id,
            "error-detail".to_string(),
        );
        connector.store_retained_detail(
            RetainedDetailKind::Activity,
            flow_id,
            "activity-detail".to_string(),
        );

        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("error-detail; activity-detail")
        );
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("close-detail")
        );
        assert!(connector.pending_activity_details.is_empty());
        assert!(connector.pending_error_details.is_empty());
        assert!(connector.pending_close_details.is_empty());
        assert!(connector.pending_detail_order.is_empty());
    }

    #[test]
    fn tls_connector_seeds_bounded_flow_storage_capacity_from_config() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_open_flows(3)
            .build()
            .unwrap();
        let connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        assert!(connector.flows.capacity() >= 3);
        assert!(connector.flow_order.capacity() >= 3);
    }

    #[test]
    fn tls_connector_seeds_bounded_retained_detail_storage_capacity_from_config() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_retained_tls_flow_details(5)
            .build()
            .unwrap();
        let connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        assert!(connector.pending_activity_details.capacity() >= 5);
        assert!(connector.pending_error_details.capacity() >= 5);
        assert!(connector.pending_close_details.capacity() >= 5);
        assert!(connector.pending_detail_order.capacity() >= 5);
    }

    #[test]
    fn tls_connector_close_removes_flow_order_refs_for_closed_flow() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(77).unwrap();

        connector.flow_order.push_back(flow_id);
        connector.flow_order.push_back(flow_id);
        connector.close(flow_id, CloseReason::HostClosed).unwrap();

        assert!(connector.flow_order.is_empty());
    }

    #[test]
    fn tls_connector_drain_events_prunes_stale_flow_order_refs() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(78).unwrap();

        connector.flow_order.push_back(flow_id);
        connector.flow_order.push_back(flow_id);

        let events = connector.drain_events(4).unwrap();
        assert!(events.is_empty());
        assert!(connector.flow_order.is_empty());
    }

    #[test]
    fn tls_connector_retained_detail_boundary_clamps_oversized_ascii_detail() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_tls_flow_detail_bytes(8)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(1).unwrap();

        connector.store_retained_detail(RetainedDetailKind::Error, flow_id, "x".repeat(9));

        let detail = connector
            .take_error_detail(flow_id)
            .expect("retained error detail recorded");
        assert_eq!(detail.len(), 8);
        assert!(detail.chars().all(|ch| ch == 'x'));
    }

    #[test]
    fn tls_connector_retained_detail_boundary_preserves_utf8_when_truncating() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_tls_flow_detail_bytes(9)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(1).unwrap();

        connector.store_retained_detail(RetainedDetailKind::Close, flow_id, "é".repeat(6));

        let detail = connector
            .take_error_detail(flow_id)
            .expect("retained close detail recorded");
        assert!(detail.len() <= 9);
        assert!(detail.chars().all(|ch| ch == 'é'));
        assert!(detail.is_char_boundary(detail.len()));
    }

    #[test]
    fn tls_connector_borrowed_retained_detail_boundary_preserves_utf8_when_truncating() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = test_host_tls_connector_builder(&guest_intermediate)
            .max_tls_flow_detail_bytes(9)
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(1).unwrap();

        connector.store_retained_detail_borrowed(RetainedDetailKind::Error, flow_id, "éééééé");

        let detail = connector
            .take_error_detail(flow_id)
            .expect("retained error detail recorded");
        assert!(detail.len() <= 9);
        assert!(detail.chars().all(|ch| ch == 'é'));
        assert!(detail.is_char_boundary(detail.len()));
    }

    #[test]
    fn tls_connector_defensively_denies_when_open_flow_limit_is_reached() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let _accepted = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(50));
        });

        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(
            HostTlsConnectorConfig::builder()
                .guest_intermediate(HostTlsIntermediate::new(
                    guest_intermediate.cert_pem(),
                    guest_intermediate.key_pem(),
                ))
                .upstream_roots(HostTlsUpstreamRoots::Native)
                .max_open_flows(1)
                .build()
                .unwrap(),
        )
        .unwrap();
        let route = HostRoute::resolved_ip("127.0.0.1".parse().unwrap());
        let target = Target::new("api.example.com", port).unwrap();
        let open = |flow| {
            TcpConnectSpec::from_open(
                &OpenTcp::new(flow, target.clone()).with_tls_transform(TlsTransformRoute::new(
                    DnsName::new("api.example.com").unwrap(),
                    TlsTermination::TerminateAndReoriginate,
                )),
                route,
            )
        };

        connector.open(&open(FlowId::new(101).unwrap())).unwrap();
        let second_flow = FlowId::new(102).unwrap();
        assert_eq!(
            connector.open(&open(second_flow)),
            Err(TransportError::Refused)
        );
        assert_eq!(
            connector.take_error_detail(second_flow).as_deref(),
            Some("TLS connector open-flow budget exceeded configured max-open-flows cap")
        );

        connector
            .close(FlowId::new(101).unwrap(), CloseReason::HostClosed)
            .unwrap();
        join.join().unwrap();
    }

    #[test]
    fn connector_rejects_overlong_secret_replacement_binding_config() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings((0..257).map(|index| {
                SecretBinding::new(format!("KEY_{index}"), "api.example.com").with_value("secret")
            }))
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement config has 257 bindings; maximum is 256"
        );
    }

    #[test]
    fn connector_rejects_overlong_response_leak_guard_secret_value_config() {
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values((0..129).map(|index| format!("secret-{index}")))
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: response leak guard config has 129 secret values; maximum is 128"
        );
    }

    #[test]
    fn connector_rejects_duplicate_response_leak_guard_secret_values() {
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["sk-live-12345", "sk-live-12345"])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: duplicate response leak guard secret values are not allowed"
        );
    }

    #[test]
    fn tls_connector_accepts_native_upstream_verifier() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let config = test_host_tls_connector_builder(&guest_intermediate)
            .build()
            .unwrap();
        let connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        assert_eq!(
            connector.config().upstream_roots(),
            &HostTlsUpstreamRoots::Native
        );
    }

    #[test]
    fn validate_stream_transforms_rejects_overlong_response_leak_guard_secret_value() {
        let too_long_secret = "x".repeat(64 * 1024 + 1);
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values([too_long_secret])
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: known secret value exceeds response leak guard buffering budget"
        );
    }

    #[test]
    fn tls_connector_terminates_guest_tls_and_reoriginates_upstream_tls() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(7).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("audit").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        assert_eq!(
            connector.take_activity_detail(flow_id).as_deref(),
            Some("plugin=audit direction=guest_to_upstream chunk_bytes=4 totals=4/0")
        );
        guest_sequence += request_len;
        let mut response = [0u8; 4];
        let mut received = false;
        for _ in 0..128 {
            let saw_detail =
                drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                    .unwrap();
            if saw_detail {
                assert_eq!(
                    connector.take_activity_detail(flow_id).as_deref(),
                    Some("plugin=audit direction=upstream_to_guest chunk_bytes=4 totals=4/4")
                );
            }
            match guest_tls.reader().read_exact(&mut response) {
                Ok(()) => {
                    received = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("failed to read guest TLS response: {err}"),
            }
        }
        assert!(
            received,
            "guest TLS client did not receive upstream response"
        );
        assert_eq!(&response, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn tls_flow_state_take_pending_upstream_plaintext_moves_buffer_without_copy_and_reseeds_capacity()
     {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);
        state.pending_upstream_plaintext = Vec::with_capacity(32);
        state.pending_upstream_plaintext.extend_from_slice(b"ping");
        let initial_capacity = state.pending_upstream_plaintext.capacity();
        let initial_ptr = state.pending_upstream_plaintext.as_ptr();

        let bytes = state.take_pending_upstream_plaintext();

        assert_eq!(bytes, b"ping");
        assert_eq!(bytes.as_ptr(), initial_ptr);
        assert!(state.pending_upstream_plaintext.is_empty());
        assert_eq!(
            state.pending_upstream_plaintext.capacity(),
            initial_tls_buffer_capacity(state.max_pending_upstream_tls_plaintext_bytes)
        );
        assert_ne!(
            state.pending_upstream_plaintext.capacity(),
            initial_capacity
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_open_seeds_bounded_pending_buffer_capacity() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .max_pending_guest_tls_bytes(1024)
            .max_pending_upstream_tls_plaintext_bytes(2048)
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(31).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        let spec =
            TcpConnectSpec::from_open(&open, HostRoute::resolved_ip("127.0.0.1".parse().unwrap()));

        let state = connector.open_flow(&spec).unwrap();

        assert_eq!(
            state.pending_guest_bytes.capacity(),
            initial_tls_buffer_capacity(1024)
        );
        assert_eq!(
            state.pending_upstream_plaintext.capacity(),
            initial_tls_buffer_capacity(2048)
        );

        drop(state);
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_fails_closed_when_transform_detail_exceeds_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            if tls.read_exact(&mut request).is_ok() {
                assert_eq!(&request, b"ping");
            }
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .max_tls_flow_detail_bytes(60)
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(7).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("audit").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("transformed-flow detail exceeded configured byte budget")
        );
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_ignores_duplicate_guest_retransmit() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(19).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut client_hello = Vec::new();
        guest_tls.write_tls(&mut client_hello).unwrap();
        let mut guest_sequence = client_hello.len() as u64;
        let initial =
            StreamChunk::new(flow_id, FlowDirection::GuestToHost, 0, client_hello.clone());
        connector.send(&initial).unwrap();
        connector.send(&initial).unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        guest_sequence += request_len;

        let mut response = [0u8; 4];
        let mut received = false;
        for _ in 0..128 {
            drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                .unwrap();
            match guest_tls.reader().read_exact(&mut response) {
                Ok(()) => {
                    received = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("failed to read guest TLS response: {err}"),
            }
        }
        assert!(
            received,
            "guest TLS client did not receive upstream response"
        );
        assert_eq!(&response, b"pong");
        server.join().unwrap();
    }

    #[cfg(not(feature = "host-tls-boring"))]
    #[test]
    fn tls_connector_denies_when_guest_tls_backlog_exceeds_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .max_pending_guest_tls_bytes(1)
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut client_hello = Vec::new();
        guest_tls.write_tls(&mut client_hello).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                client_hello,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("guest-facing TLS backlog exceeded configured pending-byte budget")
        );
        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[cfg(feature = "host-tls-boring")]
    #[test]
    fn tls_connector_boring_denies_when_guest_tls_inbound_buffer_exceeds_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .max_pending_guest_tls_bytes(1)
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut client_hello = Vec::new();
        guest_tls.write_tls(&mut client_hello).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                client_hello,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(GUEST_TLS_BACKLOG_EXCEEDED_DETAIL)
        );
        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[cfg(feature = "host-tls-boring")]
    #[test]
    fn tls_connector_boring_denies_when_guest_tls_outbound_buffer_exceeds_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();
        let mut client_hello = Vec::new();
        guest_tls.write_tls(&mut client_hello).unwrap();

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .max_pending_guest_tls_bytes(client_hello.len())
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(41).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                client_hello,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(GUEST_TLS_BACKLOG_EXCEEDED_DETAIL)
        );
        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[cfg(not(feature = "host-tls-boring"))]
    #[test]
    fn tls_connector_denies_when_upstream_tls_plaintext_backlog_exceeds_budget() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .max_pending_upstream_tls_plaintext_bytes(1)
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(41).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("upstream TLS plaintext backlog exceeded configured pending-byte budget")
        );
        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[cfg(not(feature = "host-tls-boring"))]
    #[test]
    fn tls_connector_handles_fragmented_tls12_guest_handshake_and_data() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"pong").unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(41).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();
        let mut guest_sequence = 0u64;

        let mut outbound = Vec::new();
        guest_tls.write_tls(&mut outbound).unwrap();
        send_guest_bytes_fragmented(
            &mut connector,
            flow_id,
            &mut guest_sequence,
            &outbound,
            &[17, 5, 9],
        )
        .unwrap();

        for _ in 0..256 {
            drive_guest_tls_handshake_fragmented(
                &mut connector,
                &mut guest_tls,
                flow_id,
                &mut guest_sequence,
            )
            .unwrap();
            if !guest_tls.is_handshaking() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            !guest_tls.is_handshaking(),
            "guest TLS handshake did not complete after fragmented flights"
        );

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        send_guest_bytes_fragmented(
            &mut connector,
            flow_id,
            &mut guest_sequence,
            &request_bytes,
            &[1, 2, 3, 5],
        )
        .unwrap();

        let mut response = [0u8; 4];
        let mut received = false;
        for _ in 0..256 {
            drive_guest_tls_handshake_fragmented(
                &mut connector,
                &mut guest_tls,
                flow_id,
                &mut guest_sequence,
            )
            .unwrap();
            match guest_tls.reader().read_exact(&mut response) {
                Ok(()) => {
                    received = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("failed to read guest TLS response: {err}"),
            }
        }
        assert!(
            received,
            "guest TLS client did not receive fragmented-response roundtrip"
        );
        assert_eq!(&response, b"pong");
        server.join().unwrap();
    }

    #[cfg(not(feature = "host-tls-boring"))]
    #[test]
    fn tls_connector_splits_initial_server_handshake_records_for_guest_compatibility() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(43).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut client_hello = Vec::new();
        guest_tls.write_tls(&mut client_hello).unwrap();
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                client_hello,
            ))
            .unwrap();

        let events = connector.drain_events(8).unwrap();
        let first_chunk = events
            .into_iter()
            .find_map(|event| match event {
                HostTcpEvent::Data(chunk) if !chunk.bytes.is_empty() => Some(chunk),
                _ => None,
            })
            .expect("guest-facing TLS handshake chunk");
        let summary = summarize_tls_records(&first_chunk.bytes).expect("TLS record summary");
        assert!(
            summary.matches("handshake(").count() > 1,
            "expected split server handshake records, got: {summary}"
        );
        assert!(
            summary.contains("len=4"),
            "expected ServerHelloDone-sized record in summary, got: {summary}"
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_rejects_alpn_route_defensively() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(23).unwrap();
        let target = Target::new("api.example.com", 443).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_alpn_protocols(vec![crate::proto::AlpnProtocol::new("h2").unwrap()]),
        );

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();
        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("ALPN negotiation is not supported for transformed TLS flows")
        );
    }

    #[test]
    fn tls_connector_rejects_missing_transform_route_with_retained_detail() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(229).unwrap();
        let open = OpenTcp::new(flow_id, Target::new("api.example.com", 443).unwrap());

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();
        assert_eq!(err, TransportError::ProtocolError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("TLS connector requires a transformed TLS route")
        );
    }

    #[test]
    fn tls_connector_rejects_non_terminating_route_defensively() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(230).unwrap();
        let target = Target::new("api.example.com", 443).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::RefusePinnedClient,
        ));

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();
        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("TLS connector only supports terminate-and-reoriginate transformed routes")
        );
    }

    #[test]
    fn tls_connector_protocol_error_helper_records_duplicate_flow_detail() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(231).unwrap();
        let err = connector.record_open_error_text_borrowed(
            flow_id,
            "TLS connector already tracks this flow id",
            TransportError::ProtocolError,
        );
        assert_eq!(err, TransportError::ProtocolError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("TLS connector already tracks this flow id")
        );
    }

    #[test]
    fn tls_flow_state_transform_error_borrowed_helper_clamps_detail() {
        let (mut state, join) = open_test_tls_flow_state(9);

        let err = state.record_transform_error_text_borrowed("éééééé");

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(state.take_detail().as_deref(), Some("éééé"));
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_tls_handshake_error_prefers_certificate_rejection_detail() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);

        let err =
            state.record_tls_handshake_error_text("InvalidCertificate(UnknownCA)".to_string());

        assert_eq!(err, TransportError::TlsHandshakeFailed);
        assert_eq!(
            state.take_detail().as_deref(),
            guest_certificate_rejection_detail_text("unknown_ca")
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_classify_guest_tls_error_uses_alert_summary_before_formatting() {
        struct PanicDisplay;

        impl fmt::Display for PanicDisplay {
            fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!(
                    "display should not be formatted when alert summary already identifies the certificate rejection"
                );
            }
        }

        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);
        state.last_guest_record_summary =
            Some("alert(version=0x0303,len=2,level=fatal,description=unknown_ca)".to_string());

        let err = state.classify_guest_tls_error(PanicDisplay);

        assert_eq!(err, TransportError::TlsHandshakeFailed);
        assert_eq!(
            state.take_detail().as_deref(),
            guest_certificate_rejection_detail_text("unknown_ca")
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_note_upstream_eof_uses_shared_error_detail_storage() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);
        state.pending_guest_bytes = vec![0u8; 17];
        state.pending_upstream_plaintext = vec![0u8; 23];
        state.last_guest_record_summary = Some("handshake(version=0x0303,len=42)".to_string());

        state.note_upstream_eof();

        assert_eq!(
            state.take_detail().as_deref(),
            Some(format_upstream_eof_detail(
                true,
                false,
                17,
                23,
                "handshake(version=0x0303,len=42)",
            )
            .as_str())
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_pending_activity_detail_helper_preserves_overflow_error() {
        let (mut state, join) = open_test_tls_flow_state(80);
        state.pending_activity_detail = Some("alpha".to_string());
        let overflow = "b".repeat(80);

        let err = state.append_pending_activity_detail(Some(overflow.as_str()));

        assert_eq!(err, Err(TransportError::TransformError));
        assert_eq!(
            state.take_detail().as_deref(),
            Some("transformed-flow detail exceeded configured byte budget; alpha")
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_close_detail_helper_preserves_overflow_error() {
        let (mut state, join) = open_test_tls_flow_state(80);
        state.close_detail = Some("omega".to_string());
        let overflow = "c".repeat(80);

        let err = state.append_close_detail(Some(overflow));

        assert_eq!(err, Err(TransportError::TransformError));
        assert_eq!(
            state.take_detail().as_deref(),
            Some("transformed-flow detail exceeded configured byte budget; omega")
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_pending_buffer_len_helper_preserves_exceeded_budget_detail() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);

        let err = state.checked_pending_buffer_len(
            4,
            3,
            6,
            "guest-facing TLS backlog length overflowed host accounting",
            "guest-facing TLS backlog exceeded configured pending-byte budget",
        );

        assert_eq!(err, Err(TransportError::TransformError));
        assert_eq!(
            state.take_detail().as_deref(),
            Some("guest-facing TLS backlog exceeded configured pending-byte budget")
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_pending_buffer_len_helper_preserves_overflow_detail() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);

        let err = state.checked_pending_buffer_len(
            usize::MAX,
            1,
            usize::MAX,
            "upstream TLS plaintext backlog length overflowed host accounting",
            "upstream TLS plaintext backlog exceeded configured pending-byte budget",
        );

        assert_eq!(err, Err(TransportError::TransformError));
        assert_eq!(
            state.take_detail().as_deref(),
            Some("upstream TLS plaintext backlog length overflowed host accounting")
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_send_guest_close_notify_stages_guest_tls_bytes() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);

        state.send_guest_close_notify().unwrap();

        assert!(!state.pending_guest_bytes.is_empty());
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_write_guest_plaintext_accepts_empty_payload() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);

        state.write_guest_plaintext(&[]).unwrap();

        assert!(state.pending_guest_bytes.is_empty());
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_record_guest_chunk_summaries_keeps_first_client_hello_summary() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);
        let first = test_client_hello_record(b"api.example.com");
        let second = vec![0x17, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03];

        state.record_guest_chunk_summaries(&first);
        let first_hello_summary = state.guest_hello_summary.clone();
        state.record_guest_chunk_summaries(&second);

        assert_eq!(
            state.last_guest_record_summary.as_deref(),
            summarize_tls_records(&second).as_deref()
        );
        assert_eq!(
            state.guest_hello_summary.as_deref(),
            first_hello_summary.as_deref()
        );
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_pending_guest_event_or_close_prefers_ack_before_host_close() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);
        state.pending_guest_ack = true;
        state.close_pending = true;

        let event = state
            .pending_guest_event_or_close()
            .expect("helper should not fail")
            .expect("ack event should be present");

        assert_eq!(
            event,
            HostTcpEvent::Data(StreamChunk::new(
                state.flow_id,
                FlowDirection::HostToGuest,
                0,
                Vec::new(),
            ))
        );
        assert!(state.close_pending);
        join.join().unwrap();
    }

    #[test]
    fn tls_flow_state_pending_guest_event_moves_buffer_without_copy_and_preserves_capacity() {
        let (mut state, join) = open_test_tls_flow_state(MAX_TLS_FLOW_DETAIL_BYTES);
        state.pending_guest_bytes = Vec::with_capacity(32);
        state.pending_guest_bytes.extend_from_slice(b"pong");
        let initial_capacity = state.pending_guest_bytes.capacity();
        let initial_ptr = state.pending_guest_bytes.as_ptr();

        let event = state
            .pending_guest_event()
            .expect("helper should not fail")
            .expect("guest data event should be present");

        let HostTcpEvent::Data(chunk) = event else {
            panic!("expected guest data event");
        };
        assert_eq!(chunk.flow_id, state.flow_id);
        assert_eq!(chunk.direction, FlowDirection::HostToGuest);
        assert_eq!(chunk.sequence, 0);
        assert_eq!(chunk.bytes, b"pong");
        assert_eq!(chunk.bytes.as_ptr(), initial_ptr);
        assert!(state.pending_guest_bytes.is_empty());
        assert_eq!(
            state.pending_guest_bytes.capacity(),
            initial_tls_buffer_capacity(state.max_pending_guest_tls_bytes)
        );
        assert_ne!(state.pending_guest_bytes.capacity(), initial_capacity);
        join.join().unwrap();
    }

    #[test]
    fn tls_connector_host_closed_event_helper_returns_host_close() {
        assert_eq!(
            host_closed_tcp_event(FlowId::new(233).unwrap()),
            HostTcpEvent::Close(CloseFlow {
                flow_id: FlowId::new(233).unwrap(),
                reason: CloseReason::HostClosed,
            })
        );
    }

    #[test]
    fn tls_connector_open_error_helper_records_transform_detail() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(232).unwrap();
        let err = connector.record_open_error(
            flow_id,
            "TLS transform plugin chain has 9 entries; maximum is 8",
            TransportError::TransformError,
        );
        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("TLS transform plugin chain has 9 entries; maximum is 8")
        );
    }

    #[test]
    fn tls_connector_rejects_overlong_plugin_chain_defensively() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(24).unwrap();
        let target = Target::new("api.example.com", 443).unwrap();
        let plugin_chain: Vec<_> = (0..9).map(|_| PluginId::new("audit").unwrap()).collect();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(plugin_chain),
        );

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();
        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some("TLS transform plugin chain has 9 entries; maximum is 8")
        );
    }

    #[test]
    fn tls_connector_rejects_secret_replacement_without_bound_secret_for_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_secret_replacement_bindings([SecretBinding::new(
                        "OPENAI_API_KEY",
                        "other.example.com",
                    )
                    .with_value("sk-live-12345")])
                    .expect("secret replacement config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(29).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();
        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin secret-replacement denied the flow: no secret replacement bindings are configured for target host api.example.com"
            )
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn tls_connector_rejects_duplicate_secret_replacement_placeholders_for_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_secret_replacement_bindings([
                        SecretBinding::new("OPENAI_API_KEY", "api.example.com")
                            .with_value("sk-live-1"),
                        SecretBinding::new("OPENAI_API_KEY", "*.example.com")
                            .with_value("sk-live-2"),
                    ])
                    .expect("secret replacement config is structurally valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(30).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();
        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin secret-replacement denied the flow: multiple secret replacement bindings resolve to placeholder mvm-managed:OPENAI_API_KEY for target host api.example.com"
            )
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn tls_connector_rejects_response_leak_guard_without_secret_config() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();
        let flow_id = FlowId::new(31).unwrap();
        let target = Target::new("api.example.com", 443).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("response-leak-guard").unwrap()]),
        );

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();
        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin response-leak-guard denied the flow: no known secret values are configured for response leak guard"
            )
        );
    }

    #[test]
    fn tls_connector_response_leak_guard_redacts_upstream_plaintext() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"echo sk-live-12345").unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_response_leak_guard_secret_values(["sk-live-12345"])
                    .expect("response leak guard config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(37).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("response-leak-guard").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        guest_sequence += request_len;

        let expected = format!("echo {}", String::from_utf8_lossy(REDACTION_MASK));
        let mut response = vec![0u8; expected.len()];
        let mut received = false;
        for _ in 0..128 {
            let saw_host_payload =
                drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                    .unwrap();
            if saw_host_payload {
                let detail = connector
                    .take_activity_detail(flow_id)
                    .expect("activity detail recorded");
                assert!(detail.contains("plugin=response-leak-guard redacted_hits=1"));
            }
            match guest_tls.reader().read_exact(&mut response) {
                Ok(()) => {
                    received = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("failed to read guest TLS response: {err}"),
            }
        }
        assert!(
            received,
            "guest TLS client did not receive redacted response"
        );
        assert_eq!(String::from_utf8(response).unwrap(), expected);
        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        let detail = connector.take_error_detail(flow_id).unwrap();
        assert!(detail.contains("plugin=response-leak-guard total_redacted_hits=1"));
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_response_leak_guard_redacts_split_upstream_secret() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"echo sk-l").unwrap();
            tls.flush().unwrap();
            thread::sleep(Duration::from_millis(10));
            tls.write_all(b"ive-12345 from upstream").unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_response_leak_guard_secret_values(["sk-live-12345"])
                    .expect("response leak guard config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(44).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("response-leak-guard").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        guest_sequence += request_len;

        let expected = format!(
            "echo {} from upstream",
            String::from_utf8_lossy(REDACTION_MASK)
        );
        let mut response = Vec::new();
        let mut received = false;
        for _ in 0..128 {
            let saw_host_payload =
                drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                    .unwrap();
            if saw_host_payload && let Some(detail) = connector.take_activity_detail(flow_id) {
                assert!(detail.contains("plugin=response-leak-guard redacted_hits=1"));
            }
            let mut buffer = [0u8; 64];
            loop {
                match guest_tls.reader().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes) => {
                        response.extend_from_slice(&buffer[..bytes]);
                        if response.len() >= expected.len() {
                            received = true;
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => panic!("failed to read guest TLS response: {err}"),
                }
            }
            if received {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            received,
            "guest TLS client did not receive redacted split response"
        );
        assert_eq!(String::from_utf8(response).unwrap(), expected);
        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        let detail = connector.take_error_detail(flow_id).unwrap();
        assert!(detail.contains("plugin=response-leak-guard total_redacted_hits=1"));
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_close_surfaces_response_leak_guard_finalization_denial_for_retained_tail() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let (close_tx, close_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"echo sk-live-12").unwrap();
            tls.flush().unwrap();
            close_rx.recv().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_response_leak_guard_secret_values(["sk-live-12345"])
                    .expect("response leak guard config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(39).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("response-leak-guard").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        guest_sequence += request_len;

        let mut observed_host_payload = false;
        for _ in 0..128 {
            if drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                .unwrap()
            {
                observed_host_payload = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            observed_host_payload,
            "host did not observe the partial upstream payload before explicit close"
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin response-leak-guard denied the flow: response leak guard still has retained upstream plaintext; directional finalization is required before flow finalization"
            )
        );

        close_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_auto_appends_response_leak_guard_to_baseline_chain() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"echo sk-live-12345").unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_response_leak_guard_secret_values(["sk-live-12345"])
                    .expect("response leak guard config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(38).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![
                PluginId::new("audit").unwrap(),
                PluginId::new("metadata-endpoint-deny").unwrap(),
            ]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        guest_sequence += request_len;

        let expected = format!("echo {}", String::from_utf8_lossy(REDACTION_MASK));
        let mut response = vec![0u8; expected.len()];
        let mut received = false;
        for _ in 0..128 {
            let saw_host_payload =
                drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                    .unwrap();
            if saw_host_payload {
                let detail = connector
                    .take_activity_detail(flow_id)
                    .expect("activity detail recorded");
                assert!(detail.contains("plugin=response-leak-guard redacted_hits=1"));
            }
            match guest_tls.reader().read_exact(&mut response) {
                Ok(()) => {
                    received = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("failed to read guest TLS response: {err}"),
            }
        }
        assert!(received);
        assert_eq!(String::from_utf8(response).unwrap(), expected);
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_secret_replacement_rewrites_guest_plaintext_before_upstream() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let expected = b"authorization=sk-live-12345";
            let mut request = vec![0u8; expected.len()];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(request, expected);
            tls.write_all(b"ok").unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_secret_replacement_bindings([SecretBinding::new(
                        "OPENAI_API_KEY",
                        "api.example.com",
                    )
                    .with_value("sk-live-12345")])
                    .expect("secret replacement config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(39).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"authorization=mvm-managed:OPENAI_API_KEY")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        guest_sequence += request_len;

        assert_eq!(
            connector.take_activity_detail(flow_id).as_deref(),
            Some("plugin=secret-replacement substituted_hits=1 chunk_bytes=40")
        );

        let mut response = [0u8; 2];
        let mut received = false;
        for _ in 0..128 {
            let _ = drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                .unwrap();
            match guest_tls.reader().read_exact(&mut response) {
                Ok(()) => {
                    received = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("failed to read guest TLS response: {err}"),
            }
        }
        assert!(
            received,
            "guest TLS client did not receive upstream response"
        );
        assert_eq!(&response, b"ok");

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        let detail = connector.take_error_detail(flow_id).unwrap();
        assert!(detail.contains("plugin=secret-replacement total_substituted_hits=1"));
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_secret_replacement_rewrites_placeholder_split_across_guest_chunks() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let expected = b"authorization=sk-live-12345";
            let mut request = vec![0u8; expected.len()];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(request, expected);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_secret_replacement_bindings([SecretBinding::new(
                        "OPENAI_API_KEY",
                        "api.example.com",
                    )
                    .with_value("sk-live-12345")])
                    .expect("secret replacement config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(139).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"authorization=mvm-managed:OPENAI_")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;
        assert_eq!(connector.take_activity_detail(flow_id), None);

        guest_tls.writer().write_all(b"API_KEY").unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap();

        assert_eq!(
            connector.take_activity_detail(flow_id).as_deref(),
            Some("plugin=secret-replacement substituted_hits=1 chunk_bytes=7")
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_close_surfaces_incomplete_split_secret_placeholder_detail() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_secret_replacement_bindings([SecretBinding::new(
                        "OPENAI_API_KEY",
                        "api.example.com",
                    )
                    .with_value("sk-live-12345")])
                    .expect("secret replacement config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(140).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("secret-replacement").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"authorization=mvm-managed:OPENAI_")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin secret-replacement denied the flow: guest plaintext ended with an incomplete managed secret placeholder"
            )
        );
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_auto_appends_secret_replacement_to_baseline_chain() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let expected = b"authorization=sk-live-12345";
            let mut request = vec![0u8; expected.len()];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(request, expected);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_secret_replacement_bindings([SecretBinding::new(
                        "OPENAI_API_KEY",
                        "api.example.com",
                    )
                    .with_value("sk-live-12345")])
                    .expect("secret replacement config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![
                PluginId::new("audit").unwrap(),
                PluginId::new("metadata-endpoint-deny").unwrap(),
            ]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"authorization=mvm-managed:OPENAI_API_KEY")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        let _ = request_len;

        let detail = connector
            .take_activity_detail(flow_id)
            .expect("activity detail recorded");
        assert!(detail.contains("plugin=secret-replacement substituted_hits=1"));
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_auto_runs_secret_replacement_before_metadata_endpoint_deny() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .stream_transforms(
                StreamTransformConfig::default()
                    .with_secret_replacement_bindings([SecretBinding::new(
                        "OPENAI_API_KEY",
                        "api.example.com",
                    )
                    .with_value("metadata.google.internal")])
                    .expect("secret replacement config is valid"),
            )
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(401).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: mvm-managed:OPENAI_API_KEY\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_passthroughs_non_http_binary_plaintext() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut request = [0u8; 9];
            tls.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"\x16\x03\x01binary");
            tls.write_all(&request).unwrap();
            tls.flush().unwrap();
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"\x16\x03\x01binary").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();
        guest_sequence += request_len;

        let mut response = [0u8; 9];
        let mut received = false;
        for _ in 0..128 {
            drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                .unwrap();
            match guest_tls.reader().read_exact(&mut response) {
                Ok(()) => {
                    received = true;
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(err) => panic!("failed to read guest TLS response: {err}"),
            }
        }
        assert!(received, "guest did not receive echoed non-http plaintext");
        assert_eq!(&response, b"\x16\x03\x01binary");

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_proxy_style_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let request_len = request_bytes.len() as u64;
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();
        let _ = request_len;

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_decimal_dword_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(59).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://2852039166/latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_percent_encoded_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(401).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata%2egoogle%2einternal/computeMetadata/v1/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_encoded_userinfo_delimiter_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(405).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata.google.internal%40api.example.com/computeMetadata/v1/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: encoded userinfo delimiter in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_raw_userinfo_delimiter_request_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4051).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata.google.internal@api.example.com/computeMetadata/v1/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: raw userinfo delimiter in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_percent_encoding_request_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(407).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://169.254.169.254%zz/latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid percent-encoding in request target authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_unescaped_zone_id_request_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4071).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[fe80::1%eth0]/latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid percent-encoding in request target authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_percent_encoding_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: 169.254.169.254%zz\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid percent-encoding in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_missing_host_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40815).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET http:///latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: missing host in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_control_character_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40816).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata.google.internal%00evil/latest HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: control character in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_dot_only_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40817).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET http://./latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: missing host in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_colon_bearing_hostname_request_target_authority()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40818).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata.google.internal:80:90/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid colon-bearing authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_empty_label_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40819).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata..google.internal/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: empty label in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_overlong_label_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40820).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        let host = format!("{}.google.internal", "a".repeat(64));
        let request = format!(
            "GET http://{host}/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
        );
        guest_tls.writer().write_all(request.as_bytes()).unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: overlong label in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_oversized_request_target_authority_host() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40821).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        let host = format!(
            "{}.{}.{}.{}.{}.example.com",
            "a".repeat(50),
            "b".repeat(50),
            "c".repeat(50),
            "d".repeat(50),
            "e".repeat(50)
        );
        let request = format!(
            "GET http://{host}/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
        );
        guest_tls.writer().write_all(request.as_bytes()).unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: authority host exceeds maximum length"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_character_request_target_authority_host()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40822).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata_google.internal/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid character in authority host label"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_scheme_in_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408221).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET 1http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid URI scheme in request target authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_edge_hyphen_request_target_authority_host() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408222).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://-metadata.google.internal/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: edge hyphen in authority host label"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_whitespace_in_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408223).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata.google.internal%20evil/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: whitespace in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_bracketed_hostname_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40823).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[metadata.google.internal]/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: bracketed authority must contain an IPv6-style IP literal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_bracketed_ipv4_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40824).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[169.254.169.254]/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: bracketed authority must contain an IPv6-style IP literal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_missing_closing_bracket_request_target_authority()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408241).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: missing closing bracket in bracketed authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_suffix_after_bracket_request_target_authority()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408242).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[169.254.169.254]metadata/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid suffix after bracketed authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_empty_port_after_bracket_request_target_authority()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408243).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[169.254.169.254]:/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid suffix after bracketed authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_numeric_port_request_target_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(408244).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://169.254.169.254:abc/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid non-numeric port in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_duplicate_host_headers() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40825).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET / HTTP/1.1\r\nHost: api.example.com\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request contains multiple Host headers"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_malformed_request_line() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40826).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1 EXTRA\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_malformed_header_line() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40827).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header line is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_orphaned_header_continuation_line() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40828).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\n metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header continuation is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_empty_header_name() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40829).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\n: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header name is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_whitespace_in_header_name() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40830).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost : metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header name contains whitespace"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_character_in_header_name() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40831).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHo(st: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header name contains invalid character"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_malformed_http1_version() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40832).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1XYZ\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_utf8_request_head() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40833).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: metadata.\xffgoogle.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_host_header_metadata_hostname() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40834).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_extension_method_host_header_metadata_hostname()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40834).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"PROPFIND /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_extension_method_host_header_metadata_hostname()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40836).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PROPFIND /computeMetadata/v1/ HT")
            .unwrap();
        let mut first_request_bytes = Vec::new();
        guest_tls.write_tls(&mut first_request_bytes).unwrap();
        let first_request_len = first_request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_request_bytes,
            ))
            .unwrap();
        guest_sequence += first_request_len;

        guest_tls
            .writer()
            .write_all(b"TP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_request_bytes = Vec::new();
        guest_tls.write_tls(&mut second_request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_extension_method_prefix_host_header_metadata_hostname()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40837).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"PROPFIND ").unwrap();
        let mut first_request_bytes = Vec::new();
        guest_tls.write_tls(&mut first_request_bytes).unwrap();
        let first_request_len = first_request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_request_bytes,
            ))
            .unwrap();
        guest_sequence += first_request_len;

        guest_tls
            .writer()
            .write_all(b"/computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_request_bytes = Vec::new();
        guest_tls.write_tls(&mut second_request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_extension_method_without_space_host_header_metadata_hostname()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40840).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"PROPFI").unwrap();
        let mut first_request_bytes = Vec::new();
        guest_tls.write_tls(&mut first_request_bytes).unwrap();
        let first_request_len = first_request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_request_bytes,
            ))
            .unwrap();
        guest_sequence += first_request_len;

        guest_tls
            .writer()
            .write_all(
                b"ND /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut second_request_bytes = Vec::new();
        guest_tls.write_tls(&mut second_request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_long_split_extension_method_without_space_host_header_metadata_hostname()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40841).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"EXTREMELYLONGCUSTOMMETHODPREFIXTOKEN")
            .unwrap();
        let mut first_request_bytes = Vec::new();
        guest_tls.write_tls(&mut first_request_bytes).unwrap();
        let first_request_len = first_request_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_request_bytes,
            ))
            .unwrap();
        guest_sequence += first_request_len;

        guest_tls
            .writer()
            .write_all(
                b"CONTINUED /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut second_request_bytes = Vec::new();
        guest_tls.write_tls(&mut second_request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_tab_separated_request_line() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40842).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET\t/computeMetadata/v1/\tHTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_utf8_extension_method_request_line() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40837).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"PROPFIND /\xffcomputeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_non_utf8_invalid_method_with_target_only()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40831).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PROP\xffFIND /computeMetadata/v1/ ")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_utf8_extension_method_with_truncated_version()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40828).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        let mut next_guest_sequence = guest_sequence;
        drain_host_events(
            &mut connector,
            &mut guest_tls,
            flow_id,
            &mut next_guest_sequence,
        )
        .unwrap();

        guest_tls
            .writer()
            .write_all(
                b"PROP\xffFIND /computeMetadata/v1/ HTTP/\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                next_guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_extension_method_request_line_missing_version() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40830).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        let mut next_guest_sequence = guest_sequence;
        drain_host_events(
            &mut connector,
            &mut guest_tls,
            flow_id,
            &mut next_guest_sequence,
        )
        .unwrap();

        guest_tls
            .writer()
            .write_all(b"PROPFIND /computeMetadata/v1/\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                next_guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_extension_method_request_line_with_truncated_version()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40829).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        let mut next_guest_sequence = guest_sequence;
        drain_host_events(
            &mut connector,
            &mut guest_tls,
            flow_id,
            &mut next_guest_sequence,
        )
        .unwrap();

        guest_tls
            .writer()
            .write_all(
                b"PROPFIND /computeMetadata/v1/ HTTP/\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                next_guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_extension_method_request_line_with_non_http_version_token()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40826).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        let mut next_guest_sequence = guest_sequence;
        drain_host_events(
            &mut connector,
            &mut guest_tls,
            flow_id,
            &mut next_guest_sequence,
        )
        .unwrap();

        guest_tls
            .writer()
            .write_all(
                b"PROPFIND /computeMetadata/v1/ XYZ\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                next_guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_extension_method_request_line_with_non_http_version_token_no_terminator_first_chunk()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40823).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PROPFIND /computeMetadata/v1/ XYZ")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_utf8_extension_method_with_non_http_version_token()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40825).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        let mut next_guest_sequence = guest_sequence;
        drain_host_events(
            &mut connector,
            &mut guest_tls,
            flow_id,
            &mut next_guest_sequence,
        )
        .unwrap();

        guest_tls
            .writer()
            .write_all(
                b"PROP\xffFIND /computeMetadata/v1/ XYZ\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                next_guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_utf8_extension_method_request_line_missing_version()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40824).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        let mut next_guest_sequence = guest_sequence;
        drain_host_events(
            &mut connector,
            &mut guest_tls,
            flow_id,
            &mut next_guest_sequence,
        )
        .unwrap();

        guest_tls
            .writer()
            .write_all(
                b"PROP\xffFIND /computeMetadata/v1/\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                next_guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_utf8_extension_method_with_non_http_version_token_no_terminator_first_chunk()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40822).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PROP\xffFIND /computeMetadata/v1/ XYZ")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_request_head_with_leading_blank_line() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40836).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"\r\nGET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_tab_separated_request_line() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40835).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET\t/computeMetadata/v1/\tHT")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"TP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_invalid_extension_method_token() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40834).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PROP(FIND /computeMetadata/v1/ HT")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"TP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_invalid_extension_method_prefix() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40833).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"PROP(FIND ").unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"/computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_invalid_extension_method_with_target_only()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40832).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PROP(FIND /computeMetadata/v1/ ")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_invalid_extension_method_with_target_only_no_terminator()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40827).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PROP(FIND /computeMetadata/v1/ ")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_http2_prior_knowledge_preface() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40838).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext HTTP/2 prior-knowledge preface is unsupported for metadata inspection"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_http2_prior_knowledge_preface_with_following_bytes()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40839).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nextra")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext HTTP/2 prior-knowledge preface is unsupported for metadata inspection"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_method_token() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(40835).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GE(T /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_unescaped_zone_id_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4081).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [fe80::1%eth0]\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid percent-encoding in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_path_delimiter_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4082).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: metadata.google.internal/latest\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: path delimiter in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_encoded_path_delimiter_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4083).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: metadata.google.internal%2flatest\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: path delimiter in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_encoded_userinfo_delimiter_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(406).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal%40api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: encoded userinfo delimiter in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_raw_userinfo_delimiter_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4082).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal@api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: raw userinfo delimiter in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_control_character_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4084).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: metadata.google.internal%00evil\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: control character in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_missing_host_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4085).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: :443\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: missing host in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_dot_only_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4086).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: .\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: missing host in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_bracketed_hostname_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4087).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: [metadata.google.internal]\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: bracketed authority must contain an IPv6-style IP literal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_bracketed_ipv4_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4088).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254]\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: bracketed authority must contain an IPv6-style IP literal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_colon_bearing_hostname_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4089).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal:80:90\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid colon-bearing authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_missing_closing_bracket_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4090).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: missing closing bracket in bracketed authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_suffix_after_bracket_host_header_authority()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4091).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254]metadata\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid suffix after bracketed authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_empty_port_after_bracket_host_header_authority()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4092).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254]:\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid suffix after bracketed authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_non_numeric_port_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4093).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254:abc\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid non-numeric port in authority"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_empty_label_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4094).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata..google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: empty label in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_overlong_label_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4095).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        let host = format!("{}.google.internal", "a".repeat(64));
        let request = format!("GET /computeMetadata/v1/ HTTP/1.1\r\nHost: {host}\r\n\r\n");
        guest_tls.writer().write_all(request.as_bytes()).unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: overlong label in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_oversized_host_header_authority_host() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4096).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        let host = format!(
            "{}.{}.{}.{}.{}.example.com",
            "a".repeat(50),
            "b".repeat(50),
            "c".repeat(50),
            "d".repeat(50),
            "e".repeat(50)
        );
        let request = format!("GET /computeMetadata/v1/ HTTP/1.1\r\nHost: {host}\r\n\r\n");
        guest_tls.writer().write_all(request.as_bytes()).unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: authority host exceeds maximum length"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_invalid_character_host_header_authority_host() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4097).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata_google.internal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid character in authority host label"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_edge_hyphen_host_header_authority_host() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4098).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal-\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: edge hyphen in authority host label"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_whitespace_host_header_authority() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4099).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal evil\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: whitespace in authority host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_percent_encoded_host_header_metadata_hostname() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4100).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata%2egoogle%2einternal\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_percent_encoded_host_header_metadata_hostname_with_port()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4101).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata%2egoogle%2einternal%3a80\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_ipv4_mapped_host_header_metadata_ip() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4102).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [::ffff:169.254.169.254]\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_zone_scoped_link_local_host_header_metadata_ip()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4103).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [fe80::1%25eth0]\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP fe80::1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_unbracketed_ipv6_with_port_host_header_metadata_ip()
     {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4104).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: ::ffff:169.254.169.254:80\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_hex_host_header_metadata_ip() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4105).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 0xA9FEA9FE\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_percent_encoded_metadata_request_with_port() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(402).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://metadata%2egoogle%2einternal%3a80/computeMetadata/v1/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_percent_encoded_path_delimiter_metadata_request()
    {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(403).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://169.254.169.254%2Flatest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_backslash_path_delimiter_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(404).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://169.254.169.254\\latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_ipv4_mapped_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(60).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[::ffff:169.254.169.254]/latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_zone_scoped_link_local_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(61).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET http://[fe80::1%25eth0]/latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP fe80::1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_unbracketed_ipv6_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(62).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"CONNECT ::ffff:169.254.169.254:80 HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_lf_only_host_header_metadata_hostname() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4106).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\nHost: metadata.google.internal\nMetadata-Flavor: Google\n\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_folded_host_header_metadata_hostname() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4107).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost:\r\n metadata.google.internal\r\nMetadata-Flavor: Google\r\n\r\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_host_header_metadata_hostname() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4108).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metada")
            .unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"ta.google.internal\r\nMetadata-Flavor: Google\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_connect_to_localhost() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4109).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"CONNECT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: localhost control-plane host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_connect_to_loopback_ipv6() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4110).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"CONNECT [::1]:8080 HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP ::1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_connect_to_loopback_ipv4() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4117).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 127.0.0.1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_loopback_ipv6_absolute_form_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4113).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET http://[::1]/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP ::1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_absolute_form_localhost_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4115).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET http://localhost/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: localhost control-plane host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_absolute_form_loopback_ipv4_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4116).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 127.0.0.1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_localhost_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4111).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: localhost control-plane host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_loopback_ipv6_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4112).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP ::1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_loopback_ipv4_host_header() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4114).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 127.0.0.1"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_split_connect_target() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(4110).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"CONNE").unwrap();
        let mut first_bytes = Vec::new();
        guest_tls.write_tls(&mut first_bytes).unwrap();
        let first_len = first_bytes.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                first_bytes,
            ))
            .unwrap();
        guest_sequence += first_len;

        guest_tls
            .writer()
            .write_all(b"CT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n")
            .unwrap();
        let mut second_bytes = Vec::new();
        guest_tls.write_tls(&mut second_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                second_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: localhost control-plane host"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_metadata_endpoint_deny_blocks_lf_only_folded_host_header_metadata_request() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(58).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("metadata-endpoint-deny").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls
            .writer()
            .write_all(
                b"GET /computeMetadata/v1/ HTTP/1.1\nHost:\n metadata.google.internal\nMetadata-Flavor: Google\n\n",
            )
            .unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_plugin_panic_denial_detail_during_plaintext_transform() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(42).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("panic-process-test").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin panic-process-test denied the flow: plugin panicked during plaintext transform"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_plugin_panic_denial_detail_during_initialization() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(420).unwrap();
        let target = Target::new("api.example.com", 443).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("panic-construct-test").unwrap()]),
        );

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin panic-construct-test denied the flow: plugin panicked during initialization"
            )
        );
    }

    #[test]
    fn tls_connector_surfaces_plugin_panic_denial_detail_during_directional_finalization() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let (close_tx, close_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            close_rx.recv().unwrap();
            let _ = stream.shutdown(Shutdown::Write);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(422).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("panic-finish-direction-test").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        while guest_tls.is_handshaking() {
            drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                .unwrap();
        }

        close_tx.send(()).unwrap();
        let err = connector.drain_events(8).unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin panic-finish-direction-test denied the flow: plugin panicked during directional finalization"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_plugin_timeout_denial_detail_during_flow_finalization() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(43).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("slow-finish-test").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin slow-finish-test denied the flow: plugin exceeded timeout budget during flow finalization"
            )
        );
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_plugin_timeout_denial_detail_during_initialization() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(421).unwrap();
        let target = Target::new("api.example.com", 443).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("slow-construct-test").unwrap()]),
        );

        let err = connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin slow-construct-test denied the flow: plugin exceeded timeout budget during initialization"
            )
        );
    }

    #[test]
    fn tls_connector_surfaces_plugin_timeout_denial_detail_during_directional_finalization() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let (close_tx, close_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            close_rx.recv().unwrap();
            let _ = stream.shutdown(Shutdown::Write);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(423).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("slow-finish-direction-test").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        while guest_tls.is_handshaking() {
            drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                .unwrap();
        }

        close_tx.send(()).unwrap();
        let err = connector.drain_events(8).unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin slow-finish-direction-test denied the flow: plugin exceeded timeout budget during directional finalization"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_plugin_buffer_budget_denial_detail_during_plaintext_transform() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(44).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("over-buffer-process-test").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ping").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        let err = connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin over-buffer-process-test denied the flow: plugin buffered plaintext beyond configured budget during transform"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_plugin_buffer_budget_denial_detail_during_flow_finalization() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut stream = stream;
            let mut observed = Vec::new();
            let _ = stream.read_to_end(&mut observed);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(45).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![PluginId::new("over-buffer-finish-test").unwrap()]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence).unwrap();

        guest_tls.writer().write_all(b"ok").unwrap();
        let mut request_bytes = Vec::new();
        guest_tls.write_tls(&mut request_bytes).unwrap();
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                guest_sequence,
                request_bytes,
            ))
            .unwrap();

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin over-buffer-finish-test denied the flow: plugin buffered plaintext beyond configured budget during finalization"
            )
        );
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_plugin_buffer_budget_denial_detail_during_directional_finalization() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let (close_tx, close_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            close_rx.recv().unwrap();
            let _ = stream.shutdown(Shutdown::Write);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                guest_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(46).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(
            TlsTransformRoute::new(
                DnsName::new("api.example.com").unwrap(),
                TlsTermination::TerminateAndReoriginate,
            )
            .with_transform_chain(vec![
                PluginId::new("over-buffer-finish-direction-test").unwrap(),
            ]),
        );
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                for cert in pem_certs(guest_intermediate.cert_pem()).unwrap() {
                    roots.add(cert).unwrap();
                }
                roots
            })
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();
        while guest_tls.is_handshaking() {
            drain_host_events(&mut connector, &mut guest_tls, flow_id, &mut guest_sequence)
                .unwrap();
        }

        close_tx.send(()).unwrap();
        let err = connector.drain_events(8).unwrap_err();

        assert_eq!(err, TransportError::TransformError);
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "TLS transform plugin over-buffer-finish-direction-test denied the flow: plugin buffered plaintext beyond configured budget during directional finalization"
            )
        );

        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn tls_connector_surfaces_guest_certificate_rejection_detail() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();

        let upstream_dir = tempfile::tempdir().unwrap();
        let upstream_ca = EgressCa::load_or_init_at(upstream_dir.path()).unwrap();
        let upstream_intermediate = upstream_ca
            .mint_vm_intermediate(&["api.example.com"])
            .unwrap();
        let upstream_cfg =
            Arc::new(server_config_for_sni(&upstream_intermediate, "api.example.com").unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let conn = rustls::ServerConnection::new(upstream_cfg).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut buf = [0u8; 1];
            let _ = tls.read(&mut buf);
        });

        let config = HostTlsConnectorConfig::builder()
            .guest_intermediate(HostTlsIntermediate::new(
                guest_intermediate.cert_pem(),
                guest_intermediate.key_pem(),
            ))
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(
                upstream_intermediate.cert_pem().to_string(),
            ))
            .tcp(
                StdTcpConnectorConfig::builder()
                    .read_timeout(Duration::from_millis(5))
                    .build()
                    .expect("std tcp connector config is valid"),
            )
            .build()
            .unwrap();
        let mut connector = TlsTerminatingTcpConnector::with_config(config).unwrap();

        let flow_id = FlowId::new(31).unwrap();
        let target = Target::new("api.example.com", upstream_port).unwrap();
        let open = OpenTcp::new(flow_id, target).with_tls_transform(TlsTransformRoute::new(
            DnsName::new("api.example.com").unwrap(),
            TlsTermination::TerminateAndReoriginate,
        ));
        connector
            .open(&TcpConnectSpec::from_open(
                &open,
                HostRoute::resolved_ip("127.0.0.1".parse().unwrap()),
            ))
            .unwrap();

        let guest_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        );
        let server_name = ServerName::try_from("api.example.com".to_string()).unwrap();
        let mut guest_tls = rustls::ClientConnection::new(guest_cfg, server_name).unwrap();

        let mut guest_to_host = Vec::new();
        guest_tls.write_tls(&mut guest_to_host).unwrap();
        let mut guest_sequence = guest_to_host.len() as u64;
        connector
            .send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                0,
                guest_to_host,
            ))
            .unwrap();

        let mut handshake_failed = false;
        for _ in 0..128 {
            let events = connector.drain_events(8).unwrap();
            if events.is_empty() {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            for event in events {
                let HostTcpEvent::Data(chunk) = event else {
                    continue;
                };
                if chunk.bytes.is_empty() {
                    continue;
                }
                let mut cursor = Cursor::new(chunk.bytes);
                let _ = guest_tls.read_tls(&mut cursor).unwrap();
                let err = guest_tls.process_new_packets().unwrap_err();
                assert!(err.to_string().contains("UnknownIssuer"));
                if guest_tls.wants_write() {
                    let mut outbound = Vec::new();
                    guest_tls.write_tls(&mut outbound).unwrap();
                    if outbound.is_empty() {
                        continue;
                    }
                    let sequence = guest_sequence;
                    guest_sequence = guest_sequence.checked_add(outbound.len() as u64).unwrap();
                    let send_err = connector
                        .send(&StreamChunk::new(
                            flow_id,
                            FlowDirection::GuestToHost,
                            sequence,
                            outbound,
                        ))
                        .unwrap_err();
                    assert_eq!(send_err, TransportError::TlsHandshakeFailed);
                    handshake_failed = true;
                }
                if handshake_failed {
                    break;
                }
            }
            if handshake_failed {
                break;
            }
        }

        assert!(
            handshake_failed,
            "guest did not reject transformed certificate"
        );
        assert_eq!(
            connector.take_error_detail(flow_id).as_deref(),
            Some(
                "guest refused transformed TLS certificate (unknown_ca); likely certificate pinning or missing guest trust"
            )
        );
        connector.close(flow_id, CloseReason::HostClosed).unwrap();
        server.join().unwrap();
    }

    fn drain_host_events(
        connector: &mut TlsTerminatingTcpConnector,
        guest_tls: &mut rustls::ClientConnection,
        flow_id: FlowId,
        guest_sequence: &mut u64,
    ) -> Result<bool, TransportError> {
        let mut saw_host_payload = false;
        for _ in 0..128 {
            let events = connector.drain_events(8)?;
            if events.is_empty() {
                return Ok(saw_host_payload);
            }
            for event in events {
                match event {
                    HostTcpEvent::Data(chunk) => {
                        if chunk.bytes.is_empty() {
                            continue;
                        }
                        saw_host_payload = true;
                        let mut cursor = Cursor::new(chunk.bytes);
                        let _ = guest_tls.read_tls(&mut cursor).unwrap();
                        guest_tls.process_new_packets().unwrap();
                    }
                    HostTcpEvent::Close(_) => return Ok(saw_host_payload),
                }
            }
            while guest_tls.wants_write() {
                let mut outbound = Vec::new();
                guest_tls.write_tls(&mut outbound).unwrap();
                if outbound.is_empty() {
                    break;
                }
                let sequence = *guest_sequence;
                *guest_sequence = guest_sequence
                    .checked_add(outbound.len() as u64)
                    .ok_or(TransportError::ProtocolError)?;
                connector.send(&StreamChunk::new(
                    flow_id,
                    FlowDirection::GuestToHost,
                    sequence,
                    outbound,
                ))?;
            }
        }
        Ok(saw_host_payload)
    }

    #[cfg(not(feature = "host-tls-boring"))]
    fn drive_guest_tls_handshake_fragmented(
        connector: &mut TlsTerminatingTcpConnector,
        guest_tls: &mut rustls::ClientConnection,
        flow_id: FlowId,
        guest_sequence: &mut u64,
    ) -> Result<(), TransportError> {
        let events = connector.drain_events(8)?;
        for event in events {
            match event {
                HostTcpEvent::Data(chunk) => {
                    if chunk.bytes.is_empty() {
                        continue;
                    }
                    let mut cursor = Cursor::new(chunk.bytes);
                    let _ = guest_tls.read_tls(&mut cursor).unwrap();
                    guest_tls.process_new_packets().unwrap();
                }
                HostTcpEvent::Close(_) => return Ok(()),
            }
        }
        while guest_tls.wants_write() {
            let mut outbound = Vec::new();
            guest_tls.write_tls(&mut outbound).unwrap();
            if outbound.is_empty() {
                break;
            }
            send_guest_bytes_fragmented(
                connector,
                flow_id,
                guest_sequence,
                &outbound,
                &[1, 7, 13],
            )?;
        }
        Ok(())
    }

    #[cfg(not(feature = "host-tls-boring"))]
    fn send_guest_bytes_fragmented(
        connector: &mut TlsTerminatingTcpConnector,
        flow_id: FlowId,
        guest_sequence: &mut u64,
        bytes: &[u8],
        fragment_pattern: &[usize],
    ) -> Result<(), TransportError> {
        assert!(
            !fragment_pattern.is_empty(),
            "fragment pattern must not be empty"
        );
        let mut offset = 0usize;
        let mut index = 0usize;
        while offset < bytes.len() {
            let pattern_len = fragment_pattern[index % fragment_pattern.len()];
            let len = pattern_len.max(1).min(bytes.len() - offset);
            let sequence = *guest_sequence;
            *guest_sequence = guest_sequence
                .checked_add(len as u64)
                .ok_or(TransportError::ProtocolError)?;
            connector.send(&StreamChunk::new(
                flow_id,
                FlowDirection::GuestToHost,
                sequence,
                bytes[offset..offset + len].to_vec(),
            ))?;
            offset += len;
            index = index
                .checked_add(1)
                .expect("fragment pattern index increment cannot overflow");
        }
        Ok(())
    }
}
