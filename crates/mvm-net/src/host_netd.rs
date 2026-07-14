//! Host transparent networking daemon entry-point support.
//!
//! The binary wrapper stays tiny. This module owns JSON config loading, manual
//! argument/env parsing, structured audit emission, and binding the host
//! authority to stdio-framed protocol streams.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::host::{
    DEFAULT_GUEST_REQUEST_RATE_WINDOW, DEFAULT_MAX_GUEST_REQUESTS_PER_WINDOW,
    DEFAULT_MAX_OPEN_FLOWS, HostAuditEvent, HostAuditSink, HostAuthority, HostAuthorityConfig,
    HostAuthorityError, HostTcpConnector,
};
use crate::host::{MvmCoreNetworkPolicy, StdTcpConnector, StdTcpConnectorConfig};
use crate::host_runner::{
    HostAuthorityWire, HostRunnerConfig, HostRunnerError, HostRunnerOutcome, HostRunnerStats,
    SplitJsonHostWire, run_host_authority_until_blocked,
};
use crate::host_tls::{
    DEFAULT_MAX_PENDING_GUEST_TLS_BYTES, DEFAULT_MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES,
    DEFAULT_MAX_RETAINED_TLS_FLOW_DETAILS, DEFAULT_MAX_TLS_FLOW_DETAIL_BYTES, HostTlsConfigError,
    HostTlsConnectorConfig, HostTlsIntermediate, HostTlsUpstreamRoots, TlsTerminatingTcpConnector,
};
use crate::proto::Capability;
use crate::stream_transform::StreamTransformConfig;
use crate::wire_json::{JsonWireConfig, JsonWireError, LengthPrefixedJsonAuthority};

pub const ENV_CONFIG: &str = "MVM_NET_HOST_CONFIG";
pub const ENV_LISTEN_UDS: &str = "MVM_NET_HOST_LISTEN_UDS";
const HOST_NETD_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(5);

const USAGE: &str = "\
mvm-host-netd [OPTIONS]

Host transparent networking authority. It either accepts one Unix-domain
socket connection or reads length-prefixed JSON mvm-net frames from stdin,
writes length-prefixed responses to the peer/stdout, and emits structured
JSON audit events to stderr.

Options:
  --config PATH       JSON host-netd config file
  --listen-uds PATH   Bind PATH and accept one authority stream
  -h, --help

Environment:
  MVM_NET_HOST_CONFIG
  MVM_NET_HOST_LISTEN_UDS

Command-line options override environment values.
";

#[derive(Debug)]
pub enum HostNetdError {
    HelpRequested,
    UnknownArgument(String),
    MissingValue(String),
    MissingConfigPath,
    Io {
        context: &'static str,
        source: io::Error,
    },
    Json {
        context: &'static str,
        source: serde_json::Error,
    },
    Config(&'static str),
    TlsConfig(String),
    AuditConfig(&'static str),
    Runner(HostRunnerError),
    WireConfig(JsonWireError),
    PolicyProjection(mvm_core::policy::projection::ProjectionError),
}

impl fmt::Display for HostNetdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelpRequested => write!(f, "{USAGE}"),
            Self::UnknownArgument(arg) => write!(f, "unknown argument {arg:?}"),
            Self::MissingValue(arg) => write!(f, "missing value for {arg}"),
            Self::MissingConfigPath => write!(f, "missing host netd config path"),
            Self::Io { context, source } => write!(f, "{context}: {source}"),
            Self::Json { context, source } => write!(f, "{context}: {source}"),
            Self::Config(reason) => write!(f, "invalid host netd config: {reason}"),
            Self::TlsConfig(reason) => write!(f, "invalid host TLS config: {reason}"),
            Self::AuditConfig(reason) => write!(f, "invalid host netd audit config: {reason}"),
            Self::Runner(err) => write!(f, "{err}"),
            Self::WireConfig(err) => write!(f, "invalid wire config: {err}"),
            Self::PolicyProjection(err) => write!(f, "invalid network policy projection: {err}"),
        }
    }
}

impl std::error::Error for HostNetdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Runner(err) => Some(err),
            Self::WireConfig(err) => Some(err),
            Self::PolicyProjection(err) => Some(err),
            Self::HelpRequested
            | Self::UnknownArgument(_)
            | Self::MissingValue(_)
            | Self::MissingConfigPath
            | Self::Config(_)
            | Self::AuditConfig(_)
            | Self::TlsConfig(_) => None,
        }
    }
}

impl From<HostRunnerError> for HostNetdError {
    fn from(value: HostRunnerError) -> Self {
        Self::Runner(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNetdLaunchConfig {
    config_path: PathBuf,
    listen_uds: Option<PathBuf>,
}

impl HostNetdLaunchConfig {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            config_path: config_path.into(),
            listen_uds: None,
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn listen_uds(&self) -> Option<&Path> {
        self.listen_uds.as_deref()
    }

    fn with_listen_uds(mut self, listen_uds: impl Into<PathBuf>) -> Self {
        self.listen_uds = Some(listen_uds.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNetdAuditChainConfig {
    path: PathBuf,
    signing_key_path: PathBuf,
    tenant: String,
    vm_name: String,
}

impl HostNetdAuditChainConfig {
    pub fn builder() -> HostNetdAuditChainConfigBuilder {
        HostNetdAuditChainConfigBuilder::default()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn signing_key_path(&self) -> &Path {
        &self.signing_key_path
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn vm_name(&self) -> &str {
        &self.vm_name
    }
}

#[derive(Debug, Default, Clone)]
pub struct HostNetdAuditChainConfigBuilder {
    path: Option<PathBuf>,
    signing_key_path: Option<PathBuf>,
    tenant: Option<String>,
    vm_name: Option<String>,
}

impl HostNetdAuditChainConfigBuilder {
    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn signing_key_path(mut self, signing_key_path: impl Into<PathBuf>) -> Self {
        self.signing_key_path = Some(signing_key_path.into());
        self
    }

    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    pub fn vm_name(mut self, vm_name: impl Into<String>) -> Self {
        self.vm_name = Some(vm_name.into());
        self
    }

    pub fn build(self) -> Result<HostNetdAuditChainConfig, HostNetdError> {
        let path = self
            .path
            .ok_or(HostNetdError::AuditConfig("audit chain path is required"))?;
        if path.as_os_str().is_empty() {
            return Err(HostNetdError::AuditConfig(
                "audit chain path must not be empty",
            ));
        }
        let signing_key_path = self.signing_key_path.ok_or(HostNetdError::AuditConfig(
            "audit chain signing key path is required",
        ))?;
        if signing_key_path.as_os_str().is_empty() {
            return Err(HostNetdError::AuditConfig(
                "audit chain signing key path must not be empty",
            ));
        }
        let tenant = self
            .tenant
            .ok_or(HostNetdError::AuditConfig("audit chain tenant is required"))?;
        {
            let trimmed_tenant = tenant.trim();
            if trimmed_tenant.is_empty() {
                return Err(HostNetdError::AuditConfig(
                    "audit chain tenant must not be empty",
                ));
            }
            if mvm_core::naming::validate_id(trimmed_tenant, "tenant").is_err() {
                return Err(HostNetdError::AuditConfig(
                    "audit chain tenant must be a lowercase 1-63 character tenant id",
                ));
            }
        }
        let tenant = trim_owned_if_needed(tenant);
        let vm_name = self.vm_name.ok_or(HostNetdError::AuditConfig(
            "audit chain vm_name is required",
        ))?;
        {
            let trimmed_vm_name = vm_name.trim();
            if trimmed_vm_name.is_empty() {
                return Err(HostNetdError::AuditConfig(
                    "audit chain vm_name must not be empty",
                ));
            }
            if mvm_core::naming::validate_vm_name(trimmed_vm_name).is_err() {
                return Err(HostNetdError::AuditConfig(
                    "audit chain vm_name must be a valid VM name",
                ));
            }
        }
        let vm_name = trim_owned_if_needed(vm_name);
        Ok(HostNetdAuditChainConfig {
            path,
            signing_key_path,
            tenant,
            vm_name,
        })
    }
}

fn trim_owned_if_needed(value: String) -> String {
    if value.len() == value.trim().len() {
        value
    } else {
        value.trim().to_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNetdConfig {
    network_policy: mvm_core::policy::network_policy::NetworkPolicy,
    dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry,
    now: String,
    tls_intermediate: Option<HostTlsIntermediate>,
    upstream_roots: HostTlsUpstreamRoots,
    stream_transforms: StreamTransformConfig,
    audit_chain: Option<HostNetdAuditChainConfig>,
    synthetic_dns_base: Ipv4Addr,
    max_synthetic_dns_entries: usize,
    dns_ttl_seconds: u32,
    max_open_flows: usize,
    max_guest_requests_per_window: usize,
    guest_request_rate_window: Duration,
    udp_read_timeout: Duration,
    tcp_idle_timeout: Duration,
    udp_idle_timeout: Duration,
    tcp_connect_timeout: Option<Duration>,
    tcp_read_timeout: Duration,
    max_pending_guest_tls_bytes: usize,
    max_pending_upstream_tls_plaintext_bytes: usize,
    max_tls_flow_detail_bytes: usize,
    max_retained_tls_flow_details: usize,
    runner_config: HostRunnerConfig,
    wire_config: JsonWireConfig,
}

impl HostNetdConfig {
    pub fn builder() -> HostNetdConfigBuilder {
        HostNetdConfigBuilder::default()
    }

    pub fn network_policy(&self) -> &mvm_core::policy::network_policy::NetworkPolicy {
        &self.network_policy
    }

    pub fn dns_pins(&self) -> &mvm_core::policy::dns_pin::DnsPinRegistry {
        &self.dns_pins
    }

    pub fn now(&self) -> &str {
        &self.now
    }

    pub fn tls_intermediate(&self) -> Option<&HostTlsIntermediate> {
        self.tls_intermediate.as_ref()
    }

    pub fn upstream_roots(&self) -> &HostTlsUpstreamRoots {
        &self.upstream_roots
    }

    pub fn stream_transforms(&self) -> &StreamTransformConfig {
        &self.stream_transforms
    }

    pub fn audit_chain(&self) -> Option<&HostNetdAuditChainConfig> {
        self.audit_chain.as_ref()
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

    pub const fn tcp_connect_timeout(&self) -> Option<Duration> {
        self.tcp_connect_timeout
    }

    pub const fn tcp_read_timeout(&self) -> Duration {
        self.tcp_read_timeout
    }

    pub const fn max_pending_guest_tls_bytes(&self) -> usize {
        self.max_pending_guest_tls_bytes
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

    pub fn runner_config(&self) -> &HostRunnerConfig {
        &self.runner_config
    }

    pub fn wire_config(&self) -> &JsonWireConfig {
        &self.wire_config
    }

    fn policy_adapter(&self) -> Result<MvmCoreNetworkPolicy, HostNetdError> {
        MvmCoreNetworkPolicy::from_network_policy(
            &self.network_policy,
            self.dns_pins.clone(),
            &self.now,
        )
        .map_err(HostNetdError::PolicyProjection)
    }
}

#[derive(Debug, Default, Clone)]
pub struct HostNetdConfigBuilder {
    network_policy: Option<mvm_core::policy::network_policy::NetworkPolicy>,
    dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry,
    now: Option<String>,
    tls_intermediate: Option<HostTlsIntermediate>,
    upstream_roots: Option<HostTlsUpstreamRoots>,
    stream_transforms: StreamTransformConfig,
    audit_chain: Option<HostNetdAuditChainConfig>,
    synthetic_dns_base: Option<Ipv4Addr>,
    max_synthetic_dns_entries: Option<usize>,
    dns_ttl_seconds: Option<u32>,
    max_open_flows: Option<usize>,
    max_guest_requests_per_window: Option<usize>,
    guest_request_rate_window: Option<Duration>,
    udp_read_timeout: Option<Duration>,
    tcp_idle_timeout: Option<Duration>,
    udp_idle_timeout: Option<Duration>,
    tcp_connect_timeout: Option<Duration>,
    tcp_read_timeout: Option<Duration>,
    max_pending_guest_tls_bytes: Option<usize>,
    max_pending_upstream_tls_plaintext_bytes: Option<usize>,
    max_tls_flow_detail_bytes: Option<usize>,
    max_retained_tls_flow_details: Option<usize>,
    max_messages_per_run: Option<usize>,
    max_wire_frame_bytes: Option<usize>,
}

impl HostNetdConfigBuilder {
    pub fn network_policy(
        mut self,
        network_policy: mvm_core::policy::network_policy::NetworkPolicy,
    ) -> Self {
        self.network_policy = Some(network_policy);
        self
    }

    pub fn dns_pins(mut self, dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry) -> Self {
        self.dns_pins = dns_pins;
        self
    }

    pub fn now(mut self, now: impl Into<String>) -> Self {
        self.now = Some(now.into());
        self
    }

    pub fn tls_intermediate(mut self, tls_intermediate: HostTlsIntermediate) -> Self {
        self.tls_intermediate = Some(tls_intermediate);
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

    pub fn audit_chain(mut self, audit_chain: HostNetdAuditChainConfig) -> Self {
        self.audit_chain = Some(audit_chain);
        self
    }

    pub fn synthetic_dns_base(mut self, synthetic_dns_base: Ipv4Addr) -> Self {
        self.synthetic_dns_base = Some(synthetic_dns_base);
        self
    }

    pub fn max_synthetic_dns_entries(mut self, max_synthetic_dns_entries: usize) -> Self {
        self.max_synthetic_dns_entries = Some(max_synthetic_dns_entries);
        self
    }

    pub fn dns_ttl_seconds(mut self, dns_ttl_seconds: u32) -> Self {
        self.dns_ttl_seconds = Some(dns_ttl_seconds);
        self
    }

    pub fn max_open_flows(mut self, max_open_flows: usize) -> Self {
        self.max_open_flows = Some(max_open_flows);
        self
    }

    pub fn max_guest_requests_per_window(mut self, max_guest_requests_per_window: usize) -> Self {
        self.max_guest_requests_per_window = Some(max_guest_requests_per_window);
        self
    }

    pub fn guest_request_rate_window(mut self, guest_request_rate_window: Duration) -> Self {
        self.guest_request_rate_window = Some(guest_request_rate_window);
        self
    }

    pub fn udp_read_timeout(mut self, udp_read_timeout: Duration) -> Self {
        self.udp_read_timeout = Some(udp_read_timeout);
        self
    }

    pub fn tcp_idle_timeout(mut self, tcp_idle_timeout: Duration) -> Self {
        self.tcp_idle_timeout = Some(tcp_idle_timeout);
        self
    }

    pub fn udp_idle_timeout(mut self, udp_idle_timeout: Duration) -> Self {
        self.udp_idle_timeout = Some(udp_idle_timeout);
        self
    }

    pub fn tcp_connect_timeout(mut self, tcp_connect_timeout: Duration) -> Self {
        self.tcp_connect_timeout = Some(tcp_connect_timeout);
        self
    }

    pub fn tcp_read_timeout(mut self, tcp_read_timeout: Duration) -> Self {
        self.tcp_read_timeout = Some(tcp_read_timeout);
        self
    }

    pub fn max_pending_guest_tls_bytes(mut self, max_pending_guest_tls_bytes: usize) -> Self {
        self.max_pending_guest_tls_bytes = Some(max_pending_guest_tls_bytes);
        self
    }

    pub fn max_pending_upstream_tls_plaintext_bytes(
        mut self,
        max_pending_upstream_tls_plaintext_bytes: usize,
    ) -> Self {
        self.max_pending_upstream_tls_plaintext_bytes =
            Some(max_pending_upstream_tls_plaintext_bytes);
        self
    }

    pub fn max_tls_flow_detail_bytes(mut self, max_tls_flow_detail_bytes: usize) -> Self {
        self.max_tls_flow_detail_bytes = Some(max_tls_flow_detail_bytes);
        self
    }

    pub fn max_retained_tls_flow_details(mut self, max_retained_tls_flow_details: usize) -> Self {
        self.max_retained_tls_flow_details = Some(max_retained_tls_flow_details);
        self
    }

    pub fn max_messages_per_run(mut self, max_messages_per_run: usize) -> Self {
        self.max_messages_per_run = Some(max_messages_per_run);
        self
    }

    pub fn max_wire_frame_bytes(mut self, max_wire_frame_bytes: usize) -> Self {
        self.max_wire_frame_bytes = Some(max_wire_frame_bytes);
        self
    }

    pub fn build(self) -> Result<HostNetdConfig, HostNetdError> {
        let network_policy = self
            .network_policy
            .ok_or(HostNetdError::Config("network_policy is required"))?;
        let now = self.now.ok_or(HostNetdError::Config("now is required"))?;
        if now.trim().is_empty() {
            return Err(HostNetdError::Config("now must not be empty"));
        }
        if let Some(ref tls_intermediate) = self.tls_intermediate {
            validate_tls_intermediate(tls_intermediate).map_err(map_host_tls_config_error)?;
        }
        let upstream_roots = match (&self.tls_intermediate, self.upstream_roots) {
            (Some(_), None) => {
                return Err(HostNetdError::TlsConfig(
                    "upstream TLS roots must be configured explicitly".to_string(),
                ));
            }
            (_, Some(upstream_roots)) => upstream_roots,
            (None, None) => HostTlsUpstreamRoots::default(),
        };
        validate_upstream_roots(&upstream_roots).map_err(map_host_tls_config_error)?;
        self.stream_transforms
            .validate()
            .map_err(|err| HostNetdError::TlsConfig(err.to_string()))?;
        let authority_defaults = HostAuthorityConfig::default();
        let synthetic_dns_base = self
            .synthetic_dns_base
            .unwrap_or(authority_defaults.synthetic_dns_base());
        let max_synthetic_dns_entries = self
            .max_synthetic_dns_entries
            .unwrap_or(authority_defaults.max_synthetic_dns_entries());
        let dns_ttl_seconds = self
            .dns_ttl_seconds
            .unwrap_or(authority_defaults.dns_ttl_seconds());
        validate_synthetic_dns_settings(
            synthetic_dns_base,
            max_synthetic_dns_entries,
            dns_ttl_seconds,
        )
        .map_err(map_host_authority_config_error)?;
        let max_open_flows = self.max_open_flows.unwrap_or(DEFAULT_MAX_OPEN_FLOWS);
        if max_open_flows == 0 {
            return Err(HostNetdError::Config("max_open_flows must be non-zero"));
        }
        if max_open_flows > crate::host::MAX_OPEN_FLOWS {
            return Err(HostNetdError::Config(
                "max_open_flows exceeds the hard maximum",
            ));
        }
        let max_guest_requests_per_window = self
            .max_guest_requests_per_window
            .unwrap_or(DEFAULT_MAX_GUEST_REQUESTS_PER_WINDOW);
        if max_guest_requests_per_window == 0 {
            return Err(HostNetdError::Config(
                "max_guest_requests_per_window must be non-zero",
            ));
        }
        if max_guest_requests_per_window > crate::host::MAX_GUEST_REQUESTS_PER_WINDOW {
            return Err(HostNetdError::Config(
                "max_guest_requests_per_window exceeds the hard maximum",
            ));
        }
        let guest_request_rate_window = self
            .guest_request_rate_window
            .unwrap_or(DEFAULT_GUEST_REQUEST_RATE_WINDOW);
        if guest_request_rate_window.is_zero() {
            return Err(HostNetdError::Config(
                "guest_request_rate_window must be non-zero",
            ));
        }
        if guest_request_rate_window > crate::host::MAX_GUEST_REQUEST_RATE_WINDOW {
            return Err(HostNetdError::Config(
                "guest_request_rate_window exceeds the hard maximum",
            ));
        }
        let udp_read_timeout = self
            .udp_read_timeout
            .unwrap_or(authority_defaults.udp_read_timeout());
        if udp_read_timeout.is_zero() {
            return Err(HostNetdError::Config("udp_read_timeout must be non-zero"));
        }
        if udp_read_timeout > crate::host::MAX_UDP_READ_TIMEOUT {
            return Err(HostNetdError::Config(
                "udp_read_timeout exceeds the hard maximum",
            ));
        }
        let tcp_idle_timeout = self
            .tcp_idle_timeout
            .unwrap_or(authority_defaults.tcp_idle_timeout());
        if tcp_idle_timeout.is_zero() {
            return Err(HostNetdError::Config("tcp_idle_timeout must be non-zero"));
        }
        if tcp_idle_timeout > crate::host::MAX_TCP_IDLE_TIMEOUT {
            return Err(HostNetdError::Config(
                "tcp_idle_timeout exceeds the hard maximum",
            ));
        }
        let udp_idle_timeout = self
            .udp_idle_timeout
            .unwrap_or(authority_defaults.udp_idle_timeout());
        if udp_idle_timeout.is_zero() {
            return Err(HostNetdError::Config("udp_idle_timeout must be non-zero"));
        }
        if udp_idle_timeout > crate::host::MAX_UDP_IDLE_TIMEOUT {
            return Err(HostNetdError::Config(
                "udp_idle_timeout exceeds the hard maximum",
            ));
        }
        let tcp_connect_timeout = match self.tcp_connect_timeout {
            Some(timeout) if timeout.is_zero() => {
                return Err(HostNetdError::Config(
                    "tcp_connect_timeout must be non-zero",
                ));
            }
            Some(timeout) if timeout > crate::host::MAX_STD_TCP_CONNECT_TIMEOUT => {
                return Err(HostNetdError::Config(
                    "tcp_connect_timeout exceeds the hard maximum",
                ));
            }
            Some(timeout) => Some(timeout),
            None => StdTcpConnectorConfig::default().connect_timeout(),
        };
        let tcp_read_timeout = self
            .tcp_read_timeout
            .unwrap_or(StdTcpConnectorConfig::default().read_timeout());
        if tcp_read_timeout.is_zero() {
            return Err(HostNetdError::Config("tcp_read_timeout must be non-zero"));
        }
        if tcp_read_timeout > crate::host::MAX_STD_TCP_READ_TIMEOUT {
            return Err(HostNetdError::Config(
                "tcp_read_timeout exceeds the hard maximum",
            ));
        }
        let max_pending_guest_tls_bytes = self
            .max_pending_guest_tls_bytes
            .unwrap_or(DEFAULT_MAX_PENDING_GUEST_TLS_BYTES);
        if max_pending_guest_tls_bytes == 0 {
            return Err(HostNetdError::Config(
                "max_pending_guest_tls_bytes must be non-zero",
            ));
        }
        if max_pending_guest_tls_bytes > crate::host_tls::MAX_PENDING_GUEST_TLS_BYTES {
            return Err(HostNetdError::Config(
                "max_pending_guest_tls_bytes exceeds the hard maximum",
            ));
        }
        let max_pending_upstream_tls_plaintext_bytes = self
            .max_pending_upstream_tls_plaintext_bytes
            .unwrap_or(DEFAULT_MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES);
        if max_pending_upstream_tls_plaintext_bytes == 0 {
            return Err(HostNetdError::Config(
                "max_pending_upstream_tls_plaintext_bytes must be non-zero",
            ));
        }
        if max_pending_upstream_tls_plaintext_bytes
            > crate::host_tls::MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES
        {
            return Err(HostNetdError::Config(
                "max_pending_upstream_tls_plaintext_bytes exceeds the hard maximum",
            ));
        }
        let max_tls_flow_detail_bytes = self
            .max_tls_flow_detail_bytes
            .unwrap_or(DEFAULT_MAX_TLS_FLOW_DETAIL_BYTES);
        if max_tls_flow_detail_bytes == 0 {
            return Err(HostNetdError::Config(
                "max_tls_flow_detail_bytes must be non-zero",
            ));
        }
        if max_tls_flow_detail_bytes > crate::host_tls::MAX_TLS_FLOW_DETAIL_BYTES {
            return Err(HostNetdError::Config(
                "max_tls_flow_detail_bytes exceeds the hard maximum",
            ));
        }
        let max_retained_tls_flow_details = self
            .max_retained_tls_flow_details
            .unwrap_or(DEFAULT_MAX_RETAINED_TLS_FLOW_DETAILS);
        if max_retained_tls_flow_details == 0 {
            return Err(HostNetdError::Config(
                "max_retained_tls_flow_details must be non-zero",
            ));
        }
        if max_retained_tls_flow_details > crate::host_tls::MAX_RETAINED_TLS_FLOW_DETAILS {
            return Err(HostNetdError::Config(
                "max_retained_tls_flow_details exceeds the hard maximum",
            ));
        }
        let mut runner_builder = HostRunnerConfig::builder();
        if let Some(value) = self.max_messages_per_run {
            runner_builder = runner_builder.max_messages_per_run(value);
        }
        let mut wire_builder = JsonWireConfig::builder();
        if let Some(value) = self.max_wire_frame_bytes {
            wire_builder = wire_builder.max_frame_bytes(value);
        }
        Ok(HostNetdConfig {
            network_policy,
            dns_pins: self.dns_pins,
            now,
            tls_intermediate: self.tls_intermediate,
            upstream_roots,
            stream_transforms: self.stream_transforms,
            audit_chain: self.audit_chain,
            synthetic_dns_base,
            max_synthetic_dns_entries,
            dns_ttl_seconds,
            max_open_flows,
            max_guest_requests_per_window,
            guest_request_rate_window,
            udp_read_timeout,
            tcp_idle_timeout,
            udp_idle_timeout,
            tcp_connect_timeout,
            tcp_read_timeout,
            max_pending_guest_tls_bytes,
            max_pending_upstream_tls_plaintext_bytes,
            max_tls_flow_detail_bytes,
            max_retained_tls_flow_details,
            runner_config: runner_builder.build()?,
            wire_config: wire_builder.build().map_err(HostNetdError::WireConfig)?,
        })
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNetdAuditChainConfigFile {
    path: PathBuf,
    signing_key_path: PathBuf,
    tenant: String,
    vm_name: String,
}

impl HostNetdAuditChainConfigFile {
    fn into_config(self) -> Result<HostNetdAuditChainConfig, HostNetdError> {
        HostNetdAuditChainConfig::builder()
            .path(self.path)
            .signing_key_path(self.signing_key_path)
            .tenant(self.tenant)
            .vm_name(self.vm_name)
            .build()
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HostNetdUpstreamRootsConfigFile {
    Native,
    PemBundle { pem: String },
}

impl HostNetdUpstreamRootsConfigFile {
    fn into_config(self) -> HostTlsUpstreamRoots {
        match self {
            Self::Native => HostTlsUpstreamRoots::Native,
            Self::PemBundle { pem } => HostTlsUpstreamRoots::PemBundle(pem),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostNetdConfigFile {
    network_policy: mvm_core::policy::network_policy::NetworkPolicy,
    #[serde(default)]
    dns_pins: mvm_core::policy::dns_pin::DnsPinRegistry,
    now: String,
    #[serde(default)]
    tls_intermediate: Option<HostTlsIntermediate>,
    #[serde(default)]
    upstream_roots: Option<HostNetdUpstreamRootsConfigFile>,
    #[serde(default)]
    stream_transforms: StreamTransformConfig,
    #[serde(default)]
    audit_chain: Option<HostNetdAuditChainConfigFile>,
    #[serde(default)]
    synthetic_dns_base: Option<Ipv4Addr>,
    #[serde(default)]
    max_synthetic_dns_entries: Option<usize>,
    #[serde(default)]
    dns_ttl_seconds: Option<u32>,
    #[serde(default)]
    max_open_flows: Option<usize>,
    #[serde(default)]
    max_guest_requests_per_window: Option<usize>,
    #[serde(default)]
    guest_request_rate_window_millis: Option<u64>,
    #[serde(default)]
    udp_read_timeout_millis: Option<u64>,
    #[serde(default)]
    tcp_idle_timeout_millis: Option<u64>,
    #[serde(default)]
    udp_idle_timeout_millis: Option<u64>,
    #[serde(default)]
    tcp_connect_timeout_millis: Option<u64>,
    #[serde(default)]
    tcp_read_timeout_millis: Option<u64>,
    #[serde(default)]
    max_pending_guest_tls_bytes: Option<usize>,
    #[serde(default)]
    max_pending_upstream_tls_plaintext_bytes: Option<usize>,
    #[serde(default)]
    max_tls_flow_detail_bytes: Option<usize>,
    #[serde(default)]
    max_retained_tls_flow_details: Option<usize>,
    #[serde(default)]
    max_messages_per_run: Option<usize>,
    #[serde(default)]
    max_wire_frame_bytes: Option<usize>,
}

impl HostNetdConfigFile {
    fn into_config(self) -> Result<HostNetdConfig, HostNetdError> {
        let mut builder = HostNetdConfig::builder()
            .network_policy(self.network_policy)
            .dns_pins(self.dns_pins)
            .now(self.now)
            .stream_transforms(self.stream_transforms);
        if let Some(value) = self.tls_intermediate {
            builder = builder.tls_intermediate(value);
        }
        if let Some(value) = self.upstream_roots {
            builder = builder.upstream_roots(value.into_config());
        }
        if let Some(value) = self.audit_chain {
            builder = builder.audit_chain(value.into_config()?);
        }
        if let Some(value) = self.synthetic_dns_base {
            builder = builder.synthetic_dns_base(value);
        }
        if let Some(value) = self.max_synthetic_dns_entries {
            builder = builder.max_synthetic_dns_entries(value);
        }
        if let Some(value) = self.dns_ttl_seconds {
            builder = builder.dns_ttl_seconds(value);
        }
        if let Some(value) = self.max_open_flows {
            builder = builder.max_open_flows(value);
        }
        if let Some(value) = self.max_guest_requests_per_window {
            builder = builder.max_guest_requests_per_window(value);
        }
        if let Some(value) = self.guest_request_rate_window_millis {
            builder = builder.guest_request_rate_window(Duration::from_millis(value));
        }
        if let Some(value) = self.udp_read_timeout_millis {
            builder = builder.udp_read_timeout(Duration::from_millis(value));
        }
        if let Some(value) = self.tcp_idle_timeout_millis {
            builder = builder.tcp_idle_timeout(Duration::from_millis(value));
        }
        if let Some(value) = self.udp_idle_timeout_millis {
            builder = builder.udp_idle_timeout(Duration::from_millis(value));
        }
        if let Some(value) = self.tcp_connect_timeout_millis {
            builder = builder.tcp_connect_timeout(Duration::from_millis(value));
        }
        if let Some(value) = self.tcp_read_timeout_millis {
            builder = builder.tcp_read_timeout(Duration::from_millis(value));
        }
        if let Some(value) = self.max_pending_guest_tls_bytes {
            builder = builder.max_pending_guest_tls_bytes(value);
        }
        if let Some(value) = self.max_pending_upstream_tls_plaintext_bytes {
            builder = builder.max_pending_upstream_tls_plaintext_bytes(value);
        }
        if let Some(value) = self.max_tls_flow_detail_bytes {
            builder = builder.max_tls_flow_detail_bytes(value);
        }
        if let Some(value) = self.max_retained_tls_flow_details {
            builder = builder.max_retained_tls_flow_details(value);
        }
        if let Some(value) = self.max_messages_per_run {
            builder = builder.max_messages_per_run(value);
        }
        if let Some(value) = self.max_wire_frame_bytes {
            builder = builder.max_wire_frame_bytes(value);
        }
        builder.build()
    }
}

pub fn usage() -> &'static str {
    USAGE
}

pub fn launch_config_from_args_and_env<Args, Arg, Env, Key, Value>(
    args: Args,
    env: Env,
) -> Result<HostNetdLaunchConfig, HostNetdError>
where
    Args: IntoIterator<Item = Arg>,
    Arg: Into<String>,
    Env: IntoIterator<Item = (Key, Value)>,
    Key: AsRef<str>,
    Value: Into<String>,
{
    let mut config_path = None;
    let mut listen_uds = None;
    for (key, value) in env {
        match key.as_ref() {
            ENV_CONFIG => config_path = Some(PathBuf::from(value.into())),
            ENV_LISTEN_UDS => listen_uds = Some(PathBuf::from(value.into())),
            _ => {}
        }
    }

    let mut args = args.into_iter().map(Into::into).peekable();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Err(HostNetdError::HelpRequested);
        }
        let value = if let Some((flag, value)) = arg.split_once('=') {
            match flag {
                "--config" | "--listen-uds" => value.to_string(),
                _ => return Err(HostNetdError::UnknownArgument(flag.to_string())),
            }
        } else if arg == "--config" || arg == "--listen-uds" {
            args.next()
                .ok_or_else(|| HostNetdError::MissingValue(arg.clone()))?
        } else {
            return Err(HostNetdError::UnknownArgument(arg));
        };
        if arg.starts_with("--listen-uds") {
            listen_uds = Some(PathBuf::from(value));
        } else {
            config_path = Some(PathBuf::from(value));
        }
    }

    let config = match config_path {
        Some(path) if !path.as_os_str().is_empty() => Ok(HostNetdLaunchConfig::new(path)),
        Some(_) | None => Err(HostNetdError::MissingConfigPath),
    }?;
    match listen_uds {
        Some(path) if !path.as_os_str().is_empty() => Ok(config.with_listen_uds(path)),
        Some(_) => Err(HostNetdError::Config("listen-uds path must not be empty")),
        None => Ok(config),
    }
}

pub fn load_config_file(path: &Path) -> Result<HostNetdConfig, HostNetdError> {
    let contents = std::fs::read_to_string(path).map_err(|source| HostNetdError::Io {
        context: "failed to read host netd config",
        source,
    })?;
    config_from_json_str(&contents)
}

pub fn config_from_json_str(contents: &str) -> Result<HostNetdConfig, HostNetdError> {
    let config: HostNetdConfigFile =
        serde_json::from_str(contents).map_err(|source| HostNetdError::Json {
            context: "failed to decode host netd config",
            source,
        })?;
    config.into_config()
}

pub fn run_host_netd_stdio(config: &HostNetdConfig) -> Result<HostRunnerStats, HostNetdError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_host_netd_on_stdio_parts(
        config,
        stdin.lock(),
        stdout.lock(),
        ConfiguredHostAuditSink::new(config, stderr.lock())?,
    )
}

pub fn run_host_netd_listen_uds(
    config: &HostNetdConfig,
    path: &Path,
) -> Result<HostRunnerStats, HostNetdError> {
    let stderr = io::stderr();
    run_host_netd_listen_uds_with_audit(
        config,
        path,
        ConfiguredHostAuditSink::new(config, stderr.lock())?,
    )
}

pub fn run_host_netd_listen_uds_with_audit<A>(
    config: &HostNetdConfig,
    path: &Path,
    audit: A,
) -> Result<HostRunnerStats, HostNetdError>
where
    A: HostAuditSink,
{
    if path.as_os_str().is_empty() {
        return Err(HostNetdError::Config("listen-uds path must not be empty"));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|source| HostNetdError::Io {
            context: "failed to create host netd socket directory",
            source,
        })?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(HostNetdError::Io {
                context: "failed to remove stale host netd socket",
                source,
            });
        }
    }
    let listener = UnixListener::bind(path).map_err(|source| HostNetdError::Io {
        context: "failed to bind host netd socket",
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| HostNetdError::Io {
                context: "failed to chmod host netd socket",
                source,
            },
        )?;
    }
    let (stream, _) = listener.accept().map_err(|source| HostNetdError::Io {
        context: "failed to accept host netd socket",
        source,
    })?;
    configure_host_netd_stream(&stream)?;
    run_host_netd_on_stream(config, stream, audit)
}

pub fn run_host_netd_on_stream<A>(
    config: &HostNetdConfig,
    stream: UnixStream,
    audit: A,
) -> Result<HostRunnerStats, HostNetdError>
where
    A: HostAuditSink,
{
    let mut wire = LengthPrefixedJsonAuthority::with_config(stream, config.wire_config().clone());
    serve_host_netd_with_wire(
        config,
        audit,
        ConfiguredHostTcpConnector::from_config(config)?,
        &mut wire,
    )
}

pub fn run_host_netd_on_stdio_parts<R, W, A>(
    config: &HostNetdConfig,
    reader: R,
    writer: W,
    audit: A,
) -> Result<HostRunnerStats, HostNetdError>
where
    R: Read,
    W: Write,
    A: HostAuditSink,
{
    let mut wire = SplitJsonHostWire::with_config(reader, writer, config.wire_config().clone());
    serve_host_netd_with_wire(
        config,
        audit,
        ConfiguredHostTcpConnector::from_config(config)?,
        &mut wire,
    )
}

pub fn run_host_netd_with_wire<A, T, W>(
    config: &HostNetdConfig,
    audit: A,
    tcp: T,
    wire: &mut W,
) -> Result<HostRunnerStats, HostNetdError>
where
    A: HostAuditSink,
    T: HostTcpConnector,
    W: HostAuthorityWire,
{
    let policy = config.policy_adapter()?;
    let mut authority = HostAuthority::with_config(
        authority_config_for_tcp_connector(config, &tcp),
        policy,
        audit,
        tcp,
    )
    .expect("host netd authority config is valid");
    run_host_authority_until_blocked(&mut authority, wire, config.runner_config())
        .map_err(HostNetdError::Runner)
}

fn serve_host_netd_with_wire<A, T, W>(
    config: &HostNetdConfig,
    audit: A,
    tcp: T,
    wire: &mut W,
) -> Result<HostRunnerStats, HostNetdError>
where
    A: HostAuditSink,
    T: HostTcpConnector,
    W: HostAuthorityWire,
{
    let policy = config.policy_adapter()?;
    let mut authority = HostAuthority::with_config(
        authority_config_for_tcp_connector(config, &tcp),
        policy,
        audit,
        tcp,
    )
    .expect("host netd authority config is valid");
    let mut totals = HostRunnerStats {
        messages_read: 0,
        messages_written: 0,
        outcome: HostRunnerOutcome::WouldBlock,
    };
    loop {
        let stats = run_host_authority_until_blocked(&mut authority, wire, config.runner_config())
            .map_err(HostNetdError::Runner)?;
        totals.messages_read += stats.messages_read;
        totals.messages_written += stats.messages_written;
        match stats.outcome {
            HostRunnerOutcome::Closed => {
                totals.outcome = HostRunnerOutcome::Closed;
                return Ok(totals);
            }
            HostRunnerOutcome::MaxMessages => continue,
            HostRunnerOutcome::WouldBlock => {
                if stats.messages_read == 0 && stats.messages_written == 0 {
                    std::thread::sleep(HOST_NETD_IDLE_POLL_INTERVAL);
                }
                continue;
            }
        }
    }
}

fn configure_host_netd_stream(stream: &UnixStream) -> Result<(), HostNetdError> {
    stream
        .set_read_timeout(Some(HOST_NETD_IDLE_POLL_INTERVAL))
        .map_err(|source| HostNetdError::Io {
            context: "failed to configure host netd socket read timeout",
            source,
        })
}

fn authority_config_for_tcp_connector<T>(config: &HostNetdConfig, tcp: &T) -> HostAuthorityConfig
where
    T: HostTcpConnector,
{
    let mut capabilities = vec![
        Capability::Dns,
        Capability::Tcp,
        Capability::AuditCorrelation,
        Capability::PolicyDigest,
    ];
    if tcp.supports_tls_transform() {
        capabilities.push(Capability::TlsTransform);
    }
    if tcp.supports_stream_transforms() {
        capabilities.push(Capability::StreamTransforms);
    }
    HostAuthorityConfig::builder()
        .synthetic_dns_base(config.synthetic_dns_base())
        .max_synthetic_dns_entries(config.max_synthetic_dns_entries())
        .dns_ttl_seconds(config.dns_ttl_seconds())
        .max_open_flows(config.max_open_flows())
        .max_guest_requests_per_window(config.max_guest_requests_per_window())
        .guest_request_rate_window(config.guest_request_rate_window())
        .udp_read_timeout(config.udp_read_timeout())
        .tcp_idle_timeout(config.tcp_idle_timeout())
        .udp_idle_timeout(config.udp_idle_timeout())
        .capabilities(capabilities)
        .build()
        .expect("host netd authority config is valid")
}

fn tcp_connector_config(config: &HostNetdConfig) -> StdTcpConnectorConfig {
    let mut builder = StdTcpConnectorConfig::builder()
        .read_timeout(config.tcp_read_timeout())
        .max_open_flows(config.max_open_flows());
    if let Some(timeout) = config.tcp_connect_timeout() {
        builder = builder.connect_timeout(timeout);
    }
    builder
        .build()
        .expect("host netd std tcp connector config is valid")
}

#[derive(Debug)]
pub enum JsonLineAuditError {
    Io(io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for JsonLineAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "audit I/O failed: {err}"),
            Self::Json(err) => write!(f, "audit JSON encode failed: {err}"),
        }
    }
}

impl std::error::Error for JsonLineAuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
        }
    }
}

impl From<io::Error> for JsonLineAuditError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for JsonLineAuditError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug)]
pub struct JsonLineAuditSink<W> {
    writer: W,
}

impl<W> JsonLineAuditSink<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W> HostAuditSink for JsonLineAuditSink<W>
where
    W: Write,
{
    type Error = JsonLineAuditError;

    fn record(&mut self, event: HostAuditEvent) -> Result<(), Self::Error> {
        serde_json::to_writer(&mut self.writer, &event)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SignedAuditChainEntry {
    timestamp: String,
    tenant: String,
    plan_id: String,
    plan_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bundle_version: Option<u32>,
    image_name: String,
    image_sha256: String,
    event: String,
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct SignedAuditChainEnvelope {
    entry: SignedAuditChainEntry,
    prev_hash: String,
    signature: String,
}

const UNBOUND_PLAN_ID: &str = "00000000-0000-0000-0000-000000000000";
const UNBOUND_IMAGE_NAME: &str = "<unbound>";
const UNBOUND_IMAGE_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const HOST_SIGNER_SECRET_KEY_BYTES: usize = 32;

#[derive(Debug)]
pub enum SignedHostAuditSinkError {
    Io(io::Error),
    Json(serde_json::Error),
    Config(&'static str),
}

impl fmt::Display for SignedHostAuditSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "signed audit I/O failed: {err}"),
            Self::Json(err) => write!(f, "signed audit JSON encode failed: {err}"),
            Self::Config(reason) => write!(f, "signed audit config failed: {reason}"),
        }
    }
}

impl std::error::Error for SignedHostAuditSinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::Config(_) => None,
        }
    }
}

impl From<io::Error> for SignedHostAuditSinkError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for SignedHostAuditSinkError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug)]
struct SignedHostAuditSink<W> {
    writer: W,
    signing_key: SigningKey,
    tenant: String,
    vm_name: String,
    prev_hash: [u8; 32],
}

impl SignedHostAuditSink<File> {
    fn open(config: &HostNetdAuditChainConfig) -> Result<Self, HostNetdError> {
        if let Some(parent) = config.path().parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|source| HostNetdError::Io {
                context: "failed to create signed transparent-net audit directory",
                source,
            })?;
        }
        let prev_hash =
            restore_audit_chain_cursor(config.path()).map_err(|source| HostNetdError::Io {
                context: "failed to restore transparent-net audit chain cursor",
                source,
            })?;
        let writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(config.path())
            .map_err(|source| HostNetdError::Io {
                context: "failed to open transparent-net audit chain file",
                source,
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(config.path(), std::fs::Permissions::from_mode(0o600))
                .map_err(|source| HostNetdError::Io {
                    context: "failed to chmod transparent-net audit chain file",
                    source,
                })?;
        }
        let signing_key = load_host_signing_key(config.signing_key_path())?;
        Ok(Self {
            writer,
            signing_key,
            tenant: config.tenant().to_string(),
            vm_name: config.vm_name().to_string(),
            prev_hash,
        })
    }
}

impl<W> HostAuditSink for SignedHostAuditSink<W>
where
    W: Write,
{
    type Error = SignedHostAuditSinkError;

    fn record(&mut self, event: HostAuditEvent) -> Result<(), Self::Error> {
        let entry = signed_audit_entry_from_host_event(&event, &self.tenant, &self.vm_name)?;
        let entry_bytes = serde_json::to_vec(&entry)?;
        let mut to_sign = entry_bytes;
        to_sign.extend_from_slice(&self.prev_hash);
        let signature: Signature = self.signing_key.sign(&to_sign);

        let envelope = SignedAuditChainEnvelope {
            entry,
            prev_hash: URL_SAFE_NO_PAD.encode(self.prev_hash),
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        let line = serde_json::to_string(&envelope)?;
        writeln!(self.writer, "{line}")?;
        self.writer.flush()?;
        self.prev_hash = hash_audit_chain_line(line.as_bytes());
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfiguredHostAuditSinkError {
    Json(JsonLineAuditError),
    Signed(SignedHostAuditSinkError),
}

impl fmt::Display for ConfiguredHostAuditSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "{err}"),
            Self::Signed(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ConfiguredHostAuditSinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
            Self::Signed(err) => Some(err),
        }
    }
}

#[derive(Debug)]
struct ConfiguredHostAuditSink<W> {
    json: JsonLineAuditSink<W>,
    signed: Option<SignedHostAuditSink<File>>,
}

impl<W> ConfiguredHostAuditSink<W>
where
    W: Write,
{
    fn new(config: &HostNetdConfig, writer: W) -> Result<Self, HostNetdError> {
        let signed = match config.audit_chain() {
            Some(audit_chain) => Some(SignedHostAuditSink::open(audit_chain)?),
            None => None,
        };
        Ok(Self {
            json: JsonLineAuditSink::new(writer),
            signed,
        })
    }
}

impl<W> HostAuditSink for ConfiguredHostAuditSink<W>
where
    W: Write,
{
    type Error = ConfiguredHostAuditSinkError;

    fn record(&mut self, event: HostAuditEvent) -> Result<(), Self::Error> {
        if let Some(signed) = self.signed.as_mut() {
            signed
                .record(event.clone())
                .map_err(ConfiguredHostAuditSinkError::Signed)?;
        }
        self.json
            .record(event)
            .map_err(ConfiguredHostAuditSinkError::Json)
    }
}

fn signed_audit_entry_from_host_event(
    event: &HostAuditEvent,
    tenant: &str,
    vm_name: &str,
) -> Result<SignedAuditChainEntry, SignedHostAuditSinkError> {
    let serde_json::Value::Object(object) = serde_json::to_value(event)? else {
        return Err(SignedHostAuditSinkError::Config(
            "host audit event did not encode as an object",
        ));
    };
    let Some(event_tag) = object.get("event").and_then(serde_json::Value::as_str) else {
        return Err(SignedHostAuditSinkError::Config(
            "host audit event is missing its tag",
        ));
    };
    let signed_event = format_signed_audit_event(event_tag);
    let raw_event = event_tag.to_owned();

    let mut labels = std::collections::BTreeMap::from([
        ("category".to_string(), "flow".to_string()),
        ("transport".to_string(), "transparent_net".to_string()),
        ("vm_name".to_string(), vm_name.to_string()),
        ("raw_event".to_string(), raw_event),
    ]);
    for (key, value) in object {
        if key == "event" {
            continue;
        }
        flatten_signed_audit_labels(&key, &value, &mut labels)?;
    }

    Ok(SignedAuditChainEntry {
        timestamp: mvm_core::util::time::utc_now(),
        tenant: tenant.to_string(),
        plan_id: UNBOUND_PLAN_ID.to_string(),
        plan_version: 0,
        bundle_id: None,
        bundle_version: None,
        image_name: UNBOUND_IMAGE_NAME.to_string(),
        image_sha256: UNBOUND_IMAGE_SHA256.to_string(),
        event: signed_event,
        labels,
    })
}

fn flatten_signed_audit_labels(
    prefix: &str,
    value: &serde_json::Value,
    labels: &mut std::collections::BTreeMap<String, String>,
) -> Result<(), SignedHostAuditSinkError> {
    let mut prefix_buf = String::with_capacity(prefix.len() + 16);
    prefix_buf.push_str(prefix);
    flatten_signed_audit_labels_inner(&mut prefix_buf, value, labels)
}

fn flatten_signed_audit_labels_inner(
    prefix: &mut String,
    value: &serde_json::Value,
    labels: &mut std::collections::BTreeMap<String, String>,
) -> Result<(), SignedHostAuditSinkError> {
    match value {
        serde_json::Value::Null => Ok(()),
        serde_json::Value::Bool(boolean) => {
            labels.insert(prefix.clone(), boolean.to_string());
            Ok(())
        }
        serde_json::Value::Number(number) => {
            labels.insert(prefix.clone(), number.to_string());
            Ok(())
        }
        serde_json::Value::String(text) => {
            labels.insert(prefix.clone(), text.clone());
            Ok(())
        }
        serde_json::Value::Array(values) => {
            labels.insert(prefix.clone(), serde_json::to_string(values)?);
            Ok(())
        }
        serde_json::Value::Object(values) => {
            for (key, nested) in values {
                let original_len = prefix.len();
                prefix.push('.');
                prefix.push_str(key);
                flatten_signed_audit_labels_inner(prefix, nested, labels)?;
                prefix.truncate(original_len);
            }
            Ok(())
        }
    }
}

fn format_signed_audit_event(event_tag: &str) -> String {
    let mut event = String::with_capacity("flow.transparent_net.".len() + event_tag.len());
    event.push_str("flow.transparent_net.");
    event.push_str(event_tag);
    event
}

fn restore_audit_chain_cursor(path: &Path) -> io::Result<[u8; 32]> {
    if !path.exists() {
        return Ok([0u8; 32]);
    }
    let content = std::fs::read_to_string(path)?;
    let last = content.lines().rfind(|line| !line.is_empty());
    Ok(last.map_or([0u8; 32], |line| hash_audit_chain_line(line.as_bytes())))
}

fn hash_audit_chain_line(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn load_host_signing_key(path: &Path) -> Result<SigningKey, HostNetdError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path).map_err(|source| HostNetdError::Io {
            context: "failed to stat transparent-net audit signing key",
            source,
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(HostNetdError::AuditConfig(
                "transparent-net audit signing key must have mode 0600",
            ));
        }
    }

    let key_bytes = std::fs::read(path).map_err(|source| HostNetdError::Io {
        context: "failed to read transparent-net audit signing key",
        source,
    })?;
    if key_bytes.len() != HOST_SIGNER_SECRET_KEY_BYTES {
        return Err(HostNetdError::AuditConfig(
            "transparent-net audit signing key must be 32 bytes",
        ));
    }
    let key_array: [u8; HOST_SIGNER_SECRET_KEY_BYTES] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| HostNetdError::AuditConfig("transparent-net audit signing key is invalid"))?;
    Ok(SigningKey::from_bytes(&key_array))
}

#[derive(Debug)]
enum ConfiguredHostTcpConnector {
    Std(StdTcpConnector),
    Tls(Box<TlsTerminatingTcpConnector>),
}

impl ConfiguredHostTcpConnector {
    fn from_config(config: &HostNetdConfig) -> Result<Self, HostNetdError> {
        let tcp_config = tcp_connector_config(config);
        match config.tls_intermediate() {
            Some(intermediate) => {
                let config = HostTlsConnectorConfig::builder()
                    .tcp(tcp_config)
                    .guest_intermediate(intermediate.clone())
                    .upstream_roots(config.upstream_roots().clone())
                    .stream_transforms(config.stream_transforms().clone())
                    .max_open_flows(config.max_open_flows())
                    .max_pending_guest_tls_bytes(config.max_pending_guest_tls_bytes())
                    .max_pending_upstream_tls_plaintext_bytes(
                        config.max_pending_upstream_tls_plaintext_bytes(),
                    )
                    .max_tls_flow_detail_bytes(config.max_tls_flow_detail_bytes())
                    .max_retained_tls_flow_details(config.max_retained_tls_flow_details())
                    .build()
                    .map_err(map_host_tls_config_error)?;
                let connector = TlsTerminatingTcpConnector::with_config(config)
                    .map_err(map_host_tls_config_error)?;
                Ok(Self::Tls(Box::new(connector)))
            }
            None => Ok(Self::Std(StdTcpConnector::with_config(tcp_config))),
        }
    }
}

impl HostTcpConnector for ConfiguredHostTcpConnector {
    fn open(
        &mut self,
        spec: &crate::host::TcpConnectSpec,
    ) -> Result<(), crate::proto::TransportError> {
        match self {
            Self::Std(connector) => connector.open(spec),
            Self::Tls(connector) => connector.open(spec),
        }
    }

    fn send(
        &mut self,
        chunk: &crate::proto::StreamChunk,
    ) -> Result<(), crate::proto::TransportError> {
        match self {
            Self::Std(connector) => connector.send(chunk),
            Self::Tls(connector) => connector.send(chunk),
        }
    }

    fn close(
        &mut self,
        flow_id: crate::proto::FlowId,
        reason: crate::proto::CloseReason,
    ) -> Result<(), crate::proto::TransportError> {
        match self {
            Self::Std(connector) => connector.close(flow_id, reason),
            Self::Tls(connector) => connector.close(flow_id, reason),
        }
    }

    fn drain_events(
        &mut self,
        max_events: usize,
    ) -> Result<Vec<crate::host::HostTcpEvent>, crate::proto::TransportError> {
        match self {
            Self::Std(connector) => connector.drain_events(max_events),
            Self::Tls(connector) => connector.drain_events(max_events),
        }
    }

    fn supports_tls_transform(&self) -> bool {
        match self {
            Self::Std(connector) => connector.supports_tls_transform(),
            Self::Tls(connector) => connector.supports_tls_transform(),
        }
    }

    fn supports_stream_transforms(&self) -> bool {
        match self {
            Self::Std(connector) => connector.supports_stream_transforms(),
            Self::Tls(connector) => connector.supports_stream_transforms(),
        }
    }

    fn validate_stream_transforms(
        &self,
        plugin_chain: &[crate::proto::PluginId],
        target_host: Option<&str>,
    ) -> Result<(), String> {
        match self {
            Self::Std(connector) => connector.validate_stream_transforms(plugin_chain, target_host),
            Self::Tls(connector) => connector.validate_stream_transforms(plugin_chain, target_host),
        }
    }

    fn take_activity_detail(&mut self, flow_id: crate::proto::FlowId) -> Option<String> {
        match self {
            Self::Std(connector) => connector.take_activity_detail(flow_id),
            Self::Tls(connector) => connector.take_activity_detail(flow_id),
        }
    }

    fn take_error_detail(&mut self, flow_id: crate::proto::FlowId) -> Option<String> {
        match self {
            Self::Std(connector) => connector.take_error_detail(flow_id),
            Self::Tls(connector) => connector.take_error_detail(flow_id),
        }
    }
}

fn map_host_tls_config_error(err: HostTlsConfigError) -> HostNetdError {
    HostNetdError::TlsConfig(err.to_string())
}

fn validate_synthetic_dns_settings(
    synthetic_dns_base: Ipv4Addr,
    max_synthetic_dns_entries: usize,
    dns_ttl_seconds: u32,
) -> Result<(), HostAuthorityError> {
    HostAuthorityConfig::builder()
        .synthetic_dns_base(synthetic_dns_base)
        .max_synthetic_dns_entries(max_synthetic_dns_entries)
        .dns_ttl_seconds(dns_ttl_seconds)
        .build()
        .map(|_| ())
}

fn validate_upstream_roots(
    upstream_roots: &HostTlsUpstreamRoots,
) -> Result<(), HostTlsConfigError> {
    crate::host_tls::validate_upstream_roots(upstream_roots)
}

fn validate_tls_intermediate(
    tls_intermediate: &HostTlsIntermediate,
) -> Result<(), HostTlsConfigError> {
    crate::host_tls::validate_guest_intermediate(tls_intermediate)
}

fn map_host_authority_config_error(err: HostAuthorityError) -> HostNetdError {
    match err {
        HostAuthorityError::InvalidConfig(reason) => HostNetdError::Config(reason),
        _ => unreachable!("host authority config validation only returns InvalidConfig"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_core::crypto::egress_ca::EgressCa;
    use mvm_verify::verify_audit_chain_bytes;

    use super::*;
    use crate::host::{NoopHostAuditSink, RefusingTcpConnector};
    use crate::host_runner::{HostRunnerOutcome, HostRunnerStats};
    use crate::proto::{
        Capability, CloseReason, EndpointRole, FlowDirection, FlowId, Hello, HelloAck, NetMessage,
        StreamChunk, TransportError,
    };
    use crate::wire_json::{JsonWireRead, LengthPrefixedJsonAuthority};

    const NOW: &str = "2030-01-01T00:00:00Z";

    fn uds_tempdir() -> tempfile::TempDir {
        let base = if cfg!(target_os = "macos") {
            Path::new("/private/tmp")
        } else {
            Path::new("/tmp")
        };
        tempfile::Builder::new()
            .prefix("mvm-netd-uds-")
            .tempdir_in(base)
            .expect("create UDS tempdir")
    }

    fn uds_bind_supported(dir: &Path) -> bool {
        let probe = dir.join("uds-bind-probe.sock");
        match std::os::unix::net::UnixListener::bind(&probe) {
            Ok(listener) => {
                drop(listener);
                let _ = std::fs::remove_file(&probe);
                true
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::PermissionDenied
                    || err.raw_os_error() == Some(1) =>
            {
                false
            }
            Err(err) => panic!(
                "unexpected UDS bind probe failure at {}: {err}",
                probe.display()
            ),
        }
    }

    fn deny_all_config() -> HostNetdConfig {
        HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .build()
            .unwrap()
    }

    fn unrestricted_config() -> HostNetdConfig {
        HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .build()
            .unwrap()
    }

    fn unrestricted_config_with_synthetic_dns_limit(limit: usize) -> HostNetdConfig {
        HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .max_synthetic_dns_entries(limit)
            .build()
            .unwrap()
    }

    fn unrestricted_config_with_synthetic_dns_settings(
        synthetic_dns_base: Ipv4Addr,
        max_synthetic_dns_entries: usize,
        dns_ttl_seconds: u32,
    ) -> HostNetdConfig {
        HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .synthetic_dns_base(synthetic_dns_base)
            .max_synthetic_dns_entries(max_synthetic_dns_entries)
            .dns_ttl_seconds(dns_ttl_seconds)
            .build()
            .unwrap()
    }

    fn test_tls_intermediate() -> HostTlsIntermediate {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        HostTlsIntermediate::new(guest_intermediate.cert_pem(), guest_intermediate.key_pem())
    }

    fn write_test_signing_key(dir: &Path) -> (PathBuf, VerifyingKey) {
        let key = SigningKey::from_bytes(&[7u8; HOST_SIGNER_SECRET_KEY_BYTES]);
        let path = dir.join("host-signer.ed25519");
        std::fs::write(&path, key.to_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (path, key.verifying_key())
    }

    fn signed_audit_config(
        dir: &Path,
        tenant: &str,
        vm_name: &str,
    ) -> (HostNetdConfig, PathBuf, VerifyingKey) {
        let (signing_key_path, verifying_key) = write_test_signing_key(dir);
        let audit_path = dir.join("transparent-net.audit.chain.jsonl");
        let audit_chain = HostNetdAuditChainConfig::builder()
            .path(&audit_path)
            .signing_key_path(signing_key_path)
            .tenant(tenant)
            .vm_name(vm_name)
            .build()
            .unwrap();
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .audit_chain(audit_chain)
            .build()
            .unwrap();
        (config, audit_path, verifying_key)
    }

    #[derive(Debug, Default)]
    struct MemoryWire {
        reads: VecDeque<crate::host_runner::HostAuthorityRead>,
        writes: Vec<NetMessage>,
    }

    impl MemoryWire {
        fn with_reads(
            reads: impl IntoIterator<Item = crate::host_runner::HostAuthorityRead>,
        ) -> Self {
            Self {
                reads: reads.into_iter().collect(),
                writes: Vec::new(),
            }
        }
    }

    impl HostAuthorityWire for MemoryWire {
        type Error = &'static str;

        fn receive_message(
            &mut self,
        ) -> Result<crate::host_runner::HostAuthorityRead, Self::Error> {
            Ok(self
                .reads
                .pop_front()
                .unwrap_or(crate::host_runner::HostAuthorityRead::Closed))
        }

        fn send_message(&mut self, message: NetMessage) -> Result<(), Self::Error> {
            self.writes.push(message);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct DelayedDrainConnector {
        drains: VecDeque<Vec<crate::host::HostTcpEvent>>,
    }

    impl DelayedDrainConnector {
        fn with_drains(drains: impl IntoIterator<Item = Vec<crate::host::HostTcpEvent>>) -> Self {
            Self {
                drains: drains.into_iter().collect(),
            }
        }
    }

    impl HostTcpConnector for DelayedDrainConnector {
        fn open(&mut self, _spec: &crate::host::TcpConnectSpec) -> Result<(), TransportError> {
            Ok(())
        }

        fn send(&mut self, _chunk: &StreamChunk) -> Result<(), TransportError> {
            Ok(())
        }

        fn close(&mut self, _flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
            Ok(())
        }

        fn drain_events(
            &mut self,
            _max_events: usize,
        ) -> Result<Vec<crate::host::HostTcpEvent>, TransportError> {
            Ok(self.drains.pop_front().unwrap_or_default())
        }
    }

    #[test]
    fn launch_config_prefers_cli_path_over_env_path() {
        let config = launch_config_from_args_and_env(
            ["--config", "/tmp/cli.json"],
            [
                (ENV_CONFIG, "/tmp/env.json"),
                (ENV_LISTEN_UDS, "/tmp/env.sock"),
            ],
        )
        .unwrap();

        assert_eq!(config.config_path(), Path::new("/tmp/cli.json"));
        assert_eq!(config.listen_uds(), Some(Path::new("/tmp/env.sock")));
    }

    #[test]
    fn launch_config_prefers_cli_listen_socket_over_env_socket() {
        let config = launch_config_from_args_and_env(
            ["--config=/tmp/cfg.json", "--listen-uds", "/tmp/cli.sock"],
            [(ENV_LISTEN_UDS, "/tmp/env.sock")],
        )
        .unwrap();

        assert_eq!(config.listen_uds(), Some(Path::new("/tmp/cli.sock")));
    }

    #[test]
    fn launch_config_rejects_empty_path() {
        let err =
            launch_config_from_args_and_env(["--config="], std::iter::empty::<(&str, &str)>())
                .unwrap_err();

        assert!(matches!(err, HostNetdError::MissingConfigPath));
    }

    #[test]
    fn config_json_rejects_unknown_fields() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "extra": true
            }"#,
        )
        .unwrap_err();

        assert!(matches!(err, HostNetdError::Json { .. }));
    }

    #[test]
    fn config_builder_rejects_zero_frame_bound() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_wire_frame_bytes(0)
            .build()
            .unwrap_err();

        assert!(matches!(err, HostNetdError::WireConfig(_)));
    }

    #[test]
    fn config_builder_rejects_oversized_wire_frame_bound() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_wire_frame_bytes(crate::wire_json::MAX_JSON_WIRE_FRAME_BYTES + 1)
            .build()
            .unwrap_err();

        assert!(matches!(err, HostNetdError::WireConfig(_)));
    }

    #[test]
    fn config_builder_rejects_oversized_runner_message_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_messages_per_run(crate::host_runner::MAX_HOST_MESSAGES_PER_RUN + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host runner config: max_messages_per_run exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_synthetic_dns_entry_limit() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_synthetic_dns_entries(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_synthetic_dns_entries must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_synthetic_dns_entry_limit() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_synthetic_dns_entries(crate::host::MAX_SYNTHETIC_DNS_ENTRIES + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_synthetic_dns_entries exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_dns_ttl() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .dns_ttl_seconds(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: dns_ttl_seconds must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_dns_ttl() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .dns_ttl_seconds(crate::host::MAX_DNS_TTL_SECONDS + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: dns_ttl_seconds exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_out_of_range_synthetic_dns_settings() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .synthetic_dns_base(Ipv4Addr::new(255, 255, 255, 255))
            .max_synthetic_dns_entries(2)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: synthetic DNS range exceeds the IPv4 address space"
        );
    }

    #[test]
    fn config_builder_rejects_empty_upstream_root_pem() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .upstream_roots(HostTlsUpstreamRoots::PemBundle("   ".to_string()))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: upstream TLS root PEM bundle must not be empty"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_upstream_root_pem() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let repeats = (crate::host_tls::MAX_UPSTREAM_ROOT_PEM_BYTES
            / guest_intermediate.cert_pem().len())
            + 1;
        let oversized_bundle = guest_intermediate.cert_pem().repeat(repeats);

        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(oversized_bundle))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: upstream TLS root PEM bundle exceeds byte budget ({} > {})",
                guest_intermediate.cert_pem().len() * repeats,
                crate::host_tls::MAX_UPSTREAM_ROOT_PEM_BYTES
            )
        );
    }

    #[test]
    fn config_builder_rejects_upstream_root_bundle_with_too_many_certificates() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let overlong_bundle = guest_intermediate
            .cert_pem()
            .repeat(crate::host_tls::MAX_UPSTREAM_ROOT_CERTIFICATES + 1);

        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(overlong_bundle))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: upstream TLS root PEM bundle exceeds certificate budget ({} > {})",
                crate::host_tls::MAX_UPSTREAM_ROOT_CERTIFICATES + 1,
                crate::host_tls::MAX_UPSTREAM_ROOT_CERTIFICATES
            )
        );
    }

    #[test]
    fn config_builder_rejects_missing_upstream_roots_for_tls_termination() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tls_intermediate(test_tls_intermediate())
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: upstream TLS roots must be configured explicitly"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_guest_intermediate_cert_pem() {
        let tls_intermediate = test_tls_intermediate();
        let repeats = (crate::host_tls::MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES
            / tls_intermediate.cert_pem().len())
            + 1;
        let oversized_cert_pem = tls_intermediate.cert_pem().repeat(repeats);

        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tls_intermediate(HostTlsIntermediate::new(
                oversized_cert_pem,
                tls_intermediate.key_pem(),
            ))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: guest TLS intermediate certificate PEM exceeds byte budget ({} > {})",
                tls_intermediate.cert_pem().len() * repeats,
                crate::host_tls::MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES
            )
        );
    }

    #[test]
    fn config_builder_rejects_oversized_guest_intermediate_key_pem() {
        let tls_intermediate = test_tls_intermediate();
        let repeats = (crate::host_tls::MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES
            / tls_intermediate.key_pem().len())
            + 1;
        let oversized_key_pem = tls_intermediate.key_pem().repeat(repeats);

        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tls_intermediate(HostTlsIntermediate::new(
                tls_intermediate.cert_pem(),
                oversized_key_pem,
            ))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: guest TLS intermediate private key PEM exceeds byte budget ({} > {})",
                tls_intermediate.key_pem().len() * repeats,
                crate::host_tls::MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES
            )
        );
    }

    #[test]
    fn config_builder_rejects_guest_intermediate_with_too_many_certificates() {
        let tls_intermediate = test_tls_intermediate();
        let overlong_cert_pem = tls_intermediate
            .cert_pem()
            .repeat(crate::host_tls::MAX_GUEST_INTERMEDIATE_CERTIFICATES + 1);

        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tls_intermediate(HostTlsIntermediate::new(
                overlong_cert_pem,
                tls_intermediate.key_pem(),
            ))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: guest TLS intermediate certificate chain exceeds certificate budget ({} > {})",
                crate::host_tls::MAX_GUEST_INTERMEDIATE_CERTIFICATES + 1,
                crate::host_tls::MAX_GUEST_INTERMEDIATE_CERTIFICATES
            )
        );
    }

    #[test]
    fn config_builder_rejects_zero_open_flow_limit() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_open_flows(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_open_flows must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_open_flow_limit() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_open_flows(crate::host::MAX_OPEN_FLOWS + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_open_flows exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_guest_request_rate_limit() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_guest_requests_per_window(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_guest_requests_per_window must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_guest_request_rate_limit() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_guest_requests_per_window(crate::host::MAX_GUEST_REQUESTS_PER_WINDOW + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_guest_requests_per_window exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_guest_request_rate_window() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .guest_request_rate_window(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: guest_request_rate_window must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_guest_request_rate_window() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .guest_request_rate_window(
                crate::host::MAX_GUEST_REQUEST_RATE_WINDOW + Duration::from_millis(1),
            )
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: guest_request_rate_window exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_udp_read_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .udp_read_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_read_timeout must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_udp_read_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .udp_read_timeout(crate::host::MAX_UDP_READ_TIMEOUT + Duration::from_millis(1))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_read_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_tcp_idle_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tcp_idle_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_idle_timeout must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_tcp_idle_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tcp_idle_timeout(crate::host::MAX_TCP_IDLE_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_idle_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_udp_idle_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .udp_idle_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_idle_timeout must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_udp_idle_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .udp_idle_timeout(crate::host::MAX_UDP_IDLE_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_idle_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_tcp_connect_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tcp_connect_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_connect_timeout must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_tcp_connect_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tcp_connect_timeout(crate::host::MAX_STD_TCP_CONNECT_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_connect_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_tcp_read_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tcp_read_timeout(Duration::ZERO)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_read_timeout must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_tcp_read_timeout() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .tcp_read_timeout(crate::host::MAX_STD_TCP_READ_TIMEOUT + Duration::from_secs(1))
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_read_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_pending_guest_tls_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_pending_guest_tls_bytes(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_guest_tls_bytes must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_pending_guest_tls_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_pending_guest_tls_bytes(crate::host_tls::MAX_PENDING_GUEST_TLS_BYTES + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_guest_tls_bytes exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_pending_upstream_tls_plaintext_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_pending_upstream_tls_plaintext_bytes(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_upstream_tls_plaintext_bytes must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_pending_upstream_tls_plaintext_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_pending_upstream_tls_plaintext_bytes(
                crate::host_tls::MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES + 1,
            )
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_upstream_tls_plaintext_bytes exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_tls_flow_detail_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_tls_flow_detail_bytes(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_tls_flow_detail_bytes must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_tls_flow_detail_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_tls_flow_detail_bytes(crate::host_tls::MAX_TLS_FLOW_DETAIL_BYTES + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_tls_flow_detail_bytes exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_zero_retained_tls_flow_detail_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_retained_tls_flow_details(0)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_retained_tls_flow_details must be non-zero"
        );
    }

    #[test]
    fn config_builder_rejects_oversized_retained_tls_flow_detail_budget() {
        let err = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::deny_all())
            .now(NOW)
            .max_retained_tls_flow_details(crate::host_tls::MAX_RETAINED_TLS_FLOW_DETAILS + 1)
            .build()
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_retained_tls_flow_details exceeds the hard maximum"
        );
    }

    #[test]
    fn config_builder_rejects_overlong_secret_replacement_binding_config() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings((0..257).map(|index| {
                mvm_core::policy::secret_binding::SecretBinding::new(
                    format!("KEY_{index}"),
                    "api.example.com",
                )
                .with_value("secret")
            }))
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement config has 257 bindings; maximum is 256"
        );
    }

    #[test]
    fn config_json_rejects_zero_open_flow_limit() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "max_open_flows": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_open_flows must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_open_flow_limit() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_open_flows": {}
            }}"#,
            crate::host::MAX_OPEN_FLOWS + 1
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_open_flows exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_oversized_wire_frame_bound() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_wire_frame_bytes": {}
            }}"#,
            crate::wire_json::MAX_JSON_WIRE_FRAME_BYTES + 1
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid wire config: invalid json wire config: max_frame_bytes exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_oversized_runner_message_budget() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_messages_per_run": {}
            }}"#,
            crate::host_runner::MAX_HOST_MESSAGES_PER_RUN + 1
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host runner config: max_messages_per_run exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_synthetic_dns_entry_limit() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "max_synthetic_dns_entries": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_synthetic_dns_entries must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_synthetic_dns_entry_limit() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_synthetic_dns_entries": {}
            }}"#,
            crate::host::MAX_SYNTHETIC_DNS_ENTRIES + 1
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_synthetic_dns_entries exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_dns_ttl() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "dns_ttl_seconds": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: dns_ttl_seconds must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_dns_ttl() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "dns_ttl_seconds": {}
            }}"#,
            crate::host::MAX_DNS_TTL_SECONDS + 1
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: dns_ttl_seconds exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_out_of_range_synthetic_dns_settings() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "synthetic_dns_base": "255.255.255.255",
              "max_synthetic_dns_entries": 2
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: synthetic DNS range exceeds the IPv4 address space"
        );
    }

    #[test]
    fn config_json_rejects_empty_upstream_root_pem() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "upstream_roots": {
                "type": "pem_bundle",
                "pem": "   "
              }
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: upstream TLS root PEM bundle must not be empty"
        );
    }

    #[test]
    fn config_json_rejects_missing_upstream_roots_for_tls_termination() {
        let tls_intermediate = test_tls_intermediate();
        let cert_pem = serde_json::to_string(tls_intermediate.cert_pem()).unwrap();
        let key_pem = serde_json::to_string(tls_intermediate.key_pem()).unwrap();
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "tls_intermediate": {{
                "cert_pem": {cert_pem},
                "key_pem": {key_pem}
              }}
            }}"#
        );

        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: upstream TLS roots must be configured explicitly"
        );
    }

    #[test]
    fn config_json_rejects_oversized_upstream_root_pem() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let repeats = (crate::host_tls::MAX_UPSTREAM_ROOT_PEM_BYTES
            / guest_intermediate.cert_pem().len())
            + 1;
        let oversized_bundle =
            serde_json::to_string(&guest_intermediate.cert_pem().repeat(repeats)).unwrap();

        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "upstream_roots": {{
                "type": "pem_bundle",
                "pem": {oversized_bundle}
              }}
            }}"#
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: upstream TLS root PEM bundle exceeds byte budget ({} > {})",
                guest_intermediate.cert_pem().len() * repeats,
                crate::host_tls::MAX_UPSTREAM_ROOT_PEM_BYTES
            )
        );
    }

    #[test]
    fn config_json_rejects_upstream_root_bundle_with_too_many_certificates() {
        let cert_dir = tempfile::tempdir().unwrap();
        let guest_ca = EgressCa::load_or_init_at(cert_dir.path()).unwrap();
        let guest_intermediate = guest_ca.mint_vm_intermediate(&["api.example.com"]).unwrap();
        let overlong_bundle = serde_json::to_string(
            &guest_intermediate
                .cert_pem()
                .repeat(crate::host_tls::MAX_UPSTREAM_ROOT_CERTIFICATES + 1),
        )
        .unwrap();

        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "upstream_roots": {{
                "type": "pem_bundle",
                "pem": {overlong_bundle}
              }}
            }}"#
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: upstream TLS root PEM bundle exceeds certificate budget ({} > {})",
                crate::host_tls::MAX_UPSTREAM_ROOT_CERTIFICATES + 1,
                crate::host_tls::MAX_UPSTREAM_ROOT_CERTIFICATES
            )
        );
    }

    #[test]
    fn config_json_rejects_oversized_guest_intermediate_cert_pem() {
        let tls_intermediate = test_tls_intermediate();
        let repeats = (crate::host_tls::MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES
            / tls_intermediate.cert_pem().len())
            + 1;
        let oversized_cert_pem =
            serde_json::to_string(&tls_intermediate.cert_pem().repeat(repeats)).unwrap();
        let key_pem = serde_json::to_string(tls_intermediate.key_pem()).unwrap();

        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "tls_intermediate": {{
                "cert_pem": {oversized_cert_pem},
                "key_pem": {key_pem}
              }}
            }}"#
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: guest TLS intermediate certificate PEM exceeds byte budget ({} > {})",
                tls_intermediate.cert_pem().len() * repeats,
                crate::host_tls::MAX_GUEST_INTERMEDIATE_CERT_PEM_BYTES
            )
        );
    }

    #[test]
    fn config_json_rejects_oversized_guest_intermediate_key_pem() {
        let tls_intermediate = test_tls_intermediate();
        let repeats = (crate::host_tls::MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES
            / tls_intermediate.key_pem().len())
            + 1;
        let cert_pem = serde_json::to_string(tls_intermediate.cert_pem()).unwrap();
        let oversized_key_pem =
            serde_json::to_string(&tls_intermediate.key_pem().repeat(repeats)).unwrap();

        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "tls_intermediate": {{
                "cert_pem": {cert_pem},
                "key_pem": {oversized_key_pem}
              }}
            }}"#
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: guest TLS intermediate private key PEM exceeds byte budget ({} > {})",
                tls_intermediate.key_pem().len() * repeats,
                crate::host_tls::MAX_GUEST_INTERMEDIATE_KEY_PEM_BYTES
            )
        );
    }

    #[test]
    fn config_json_rejects_guest_intermediate_with_too_many_certificates() {
        let tls_intermediate = test_tls_intermediate();
        let overlong_cert_pem = serde_json::to_string(
            &tls_intermediate
                .cert_pem()
                .repeat(crate::host_tls::MAX_GUEST_INTERMEDIATE_CERTIFICATES + 1),
        )
        .unwrap();
        let key_pem = serde_json::to_string(tls_intermediate.key_pem()).unwrap();

        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "tls_intermediate": {{
                "cert_pem": {overlong_cert_pem},
                "key_pem": {key_pem}
              }}
            }}"#
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: guest TLS intermediate certificate chain exceeds certificate budget ({} > {})",
                crate::host_tls::MAX_GUEST_INTERMEDIATE_CERTIFICATES + 1,
                crate::host_tls::MAX_GUEST_INTERMEDIATE_CERTIFICATES
            )
        );
    }

    #[test]
    fn config_json_rejects_zero_pending_guest_tls_budget() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "max_pending_guest_tls_bytes": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_guest_tls_bytes must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_pending_guest_tls_budget() {
        let err = config_from_json_str(&format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_pending_guest_tls_bytes": {}
            }}"#,
            crate::host_tls::MAX_PENDING_GUEST_TLS_BYTES + 1
        ))
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_guest_tls_bytes exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_pending_upstream_tls_plaintext_budget() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "max_pending_upstream_tls_plaintext_bytes": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_upstream_tls_plaintext_bytes must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_pending_upstream_tls_plaintext_budget() {
        let err = config_from_json_str(&format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_pending_upstream_tls_plaintext_bytes": {}
            }}"#,
            crate::host_tls::MAX_PENDING_UPSTREAM_TLS_PLAINTEXT_BYTES + 1
        ))
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_pending_upstream_tls_plaintext_bytes exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_tls_flow_detail_budget() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "max_tls_flow_detail_bytes": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_tls_flow_detail_bytes must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_tls_flow_detail_budget() {
        let err = config_from_json_str(&format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_tls_flow_detail_bytes": {}
            }}"#,
            crate::host_tls::MAX_TLS_FLOW_DETAIL_BYTES + 1
        ))
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_tls_flow_detail_bytes exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_retained_tls_flow_detail_budget() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "max_retained_tls_flow_details": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_retained_tls_flow_details must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_retained_tls_flow_detail_budget() {
        let err = config_from_json_str(&format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_retained_tls_flow_details": {}
            }}"#,
            crate::host_tls::MAX_RETAINED_TLS_FLOW_DETAILS + 1
        ))
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_retained_tls_flow_details exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_overlong_response_leak_guard_secret_value_config() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "response_leak_guard_secret_values":
                        (0..129).map(|index| format!("secret-{index}")).collect::<Vec<_>>(),
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin response-leak-guard denied the flow: response leak guard config has 129 secret values; maximum is 128"
        );
    }

    #[test]
    fn config_json_rejects_empty_response_leak_guard_secret_value() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "response_leak_guard_secret_values": [""],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin response-leak-guard denied the flow: response leak guard secret values must not be empty"
        );
    }

    #[test]
    fn config_json_rejects_empty_secret_replacement_binding_name() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "",
                            "target_host": "api.example.com",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement binding name must not be empty"
        );
    }

    #[test]
    fn config_json_rejects_secret_replacement_binding_name_with_surrounding_whitespace() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": " OPENAI_API_KEY ",
                            "target_host": "api.example.com",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement binding name must not contain surrounding whitespace"
        );
    }

    #[test]
    fn config_json_rejects_empty_secret_replacement_target_host() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "OPENAI_API_KEY",
                            "target_host": "",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement target host must not be empty"
        );
    }

    #[test]
    fn config_json_rejects_empty_secret_replacement_explicit_value() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "OPENAI_API_KEY",
                            "target_host": "api.example.com",
                            "value": ""
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement binding OPENAI_API_KEY must not resolve to an empty value"
        );
    }

    #[test]
    fn config_json_rejects_secret_replacement_target_host_with_surrounding_whitespace() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "OPENAI_API_KEY",
                            "target_host": " api.example.com ",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement target host must not contain surrounding whitespace"
        );
    }

    #[test]
    fn config_json_rejects_malformed_secret_replacement_target_host_wildcard() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "OPENAI_API_KEY",
                            "target_host": "api.*.example.com",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement target host wildcard must appear only as a leading *."
        );
    }

    #[test]
    fn config_json_rejects_secret_replacement_target_host_with_invalid_label_characters() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "OPENAI_API_KEY",
                            "target_host": "api_exam!ple.com",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement target host labels must contain only ASCII letters, digits, or -"
        );
    }

    #[test]
    fn config_json_rejects_secret_replacement_target_host_with_edge_hyphen_label() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "OPENAI_API_KEY",
                            "target_host": "-api.example.com",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement target host labels must not start or end with -"
        );
    }

    #[test]
    fn config_json_rejects_overlong_secret_replacement_target_host() {
        let host = format!(
            "{}.example.com",
            "x".repeat(crate::proto::MAX_HOST_NAME_BYTES)
        );
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": "OPENAI_API_KEY",
                            "target_host": host,
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement target host is {} bytes; maximum is {}",
                format!(
                    "{}.example.com",
                    "x".repeat(crate::proto::MAX_HOST_NAME_BYTES)
                )
                .len(),
                crate::proto::MAX_HOST_NAME_BYTES,
            )
        );
    }

    #[test]
    fn config_json_rejects_overlong_secret_replacement_placeholder() {
        let binding_name = "x".repeat(
            crate::stream_transform::MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES
                - mvm_core::policy::secret_binding::PLACEHOLDER_PREFIX.len()
                + 1,
        );
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "secret_replacement_bindings": [
                        {
                            "env_var": binding_name,
                            "target_host": "api.example.com",
                            "value": "secret"
                        }
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "invalid host TLS config: TLS transform plugin secret-replacement denied the flow: secret replacement placeholder for {} is {} bytes; maximum is {}",
                "x".repeat(
                    crate::stream_transform::MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES
                        - mvm_core::policy::secret_binding::PLACEHOLDER_PREFIX.len()
                        + 1
                ),
                crate::stream_transform::MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES + 1,
                crate::stream_transform::MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES,
            )
        );
    }

    #[test]
    fn config_json_rejects_overlong_response_leak_guard_secret_value() {
        let err = config_from_json_str(
            &serde_json::json!({
                "network_policy": mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                "now": NOW,
                "stream_transforms": {
                    "response_leak_guard_secret_values": [
                        "x".repeat(crate::stream_transform::RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES + 1),
                    ],
                }
            })
            .to_string(),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host TLS config: TLS transform plugin response-leak-guard denied the flow: known secret value exceeds response leak guard buffering budget"
        );
    }

    #[test]
    fn config_json_rejects_zero_guest_request_rate_limit() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "max_guest_requests_per_window": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_guest_requests_per_window must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_guest_request_rate_limit() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "max_guest_requests_per_window": {}
            }}"#,
            crate::host::MAX_GUEST_REQUESTS_PER_WINDOW + 1
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: max_guest_requests_per_window exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_guest_request_rate_window() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "guest_request_rate_window_millis": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: guest_request_rate_window must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_guest_request_rate_window() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "guest_request_rate_window_millis": {}
            }}"#,
            (crate::host::MAX_GUEST_REQUEST_RATE_WINDOW + Duration::from_millis(1)).as_millis()
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: guest_request_rate_window exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_udp_read_timeout() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "udp_read_timeout_millis": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_read_timeout must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_udp_read_timeout() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "udp_read_timeout_millis": {}
            }}"#,
            (crate::host::MAX_UDP_READ_TIMEOUT + Duration::from_millis(1)).as_millis()
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_read_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_tcp_idle_timeout() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "tcp_idle_timeout_millis": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_idle_timeout must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_tcp_idle_timeout() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "tcp_idle_timeout_millis": {}
            }}"#,
            (crate::host::MAX_TCP_IDLE_TIMEOUT + Duration::from_secs(1)).as_millis()
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_idle_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_udp_idle_timeout() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "udp_idle_timeout_millis": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_idle_timeout must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_udp_idle_timeout() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "udp_idle_timeout_millis": {}
            }}"#,
            (crate::host::MAX_UDP_IDLE_TIMEOUT + Duration::from_secs(1)).as_millis()
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: udp_idle_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_tcp_connect_timeout() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "tcp_connect_timeout_millis": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_connect_timeout must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_tcp_connect_timeout() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "tcp_connect_timeout_millis": {}
            }}"#,
            (crate::host::MAX_STD_TCP_CONNECT_TIMEOUT + Duration::from_secs(1)).as_millis()
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_connect_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_zero_tcp_read_timeout() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "tcp_read_timeout_millis": 0
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_read_timeout must be non-zero"
        );
    }

    #[test]
    fn config_json_rejects_oversized_tcp_read_timeout() {
        let json = format!(
            r#"{{
              "network_policy": {{"type":"preset","preset":"none"}},
              "now": "2030-01-01T00:00:00Z",
              "tcp_read_timeout_millis": {}
            }}"#,
            (crate::host::MAX_STD_TCP_READ_TIMEOUT + Duration::from_secs(1)).as_millis()
        );
        let err = config_from_json_str(&json).unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd config: tcp_read_timeout exceeds the hard maximum"
        );
    }

    #[test]
    fn config_json_rejects_empty_audit_chain_tenant() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "audit_chain": {
                "path": "/tmp/mvm-host-netd.audit.chain.jsonl",
                "signing_key_path": "/tmp/host-signer.ed25519",
                "tenant": "   ",
                "vm_name": "vm-test"
              }
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd audit config: audit chain tenant must not be empty"
        );
    }

    #[test]
    fn config_json_rejects_invalid_audit_chain_tenant_shape() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "audit_chain": {
                "path": "/tmp/mvm-host-netd.audit.chain.jsonl",
                "signing_key_path": "/tmp/host-signer.ed25519",
                "tenant": "Tenant_01",
                "vm_name": "vm-test"
              }
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd audit config: audit chain tenant must be a lowercase 1-63 character tenant id"
        );
    }

    #[test]
    fn config_json_rejects_invalid_audit_chain_vm_name_shape() {
        let err = config_from_json_str(
            r#"{
              "network_policy": {"type":"preset","preset":"none"},
              "now": "2030-01-01T00:00:00Z",
              "audit_chain": {
                "path": "/tmp/mvm-host-netd.audit.chain.jsonl",
                "signing_key_path": "/tmp/host-signer.ed25519",
                "tenant": "local",
                "vm_name": "VM_TEST"
              }
            }"#,
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "invalid host netd audit config: audit chain vm_name must be a valid VM name"
        );
    }

    #[test]
    fn audit_chain_config_builder_reuses_untrimmed_owned_tenant_and_vm_name() {
        let tenant = String::from("local");
        let vm_name = String::from("vm-test");
        let tenant_ptr = tenant.as_ptr();
        let vm_name_ptr = vm_name.as_ptr();

        let config = HostNetdAuditChainConfig::builder()
            .path("/tmp/mvm-host-netd.audit.chain.jsonl")
            .signing_key_path("/tmp/host-signer.ed25519")
            .tenant(tenant)
            .vm_name(vm_name)
            .build()
            .unwrap();

        assert_eq!(config.tenant(), "local");
        assert_eq!(config.vm_name(), "vm-test");
        assert_eq!(config.tenant().as_ptr(), tenant_ptr);
        assert_eq!(config.vm_name().as_ptr(), vm_name_ptr);
    }

    #[test]
    fn audit_chain_config_builder_trims_surrounding_whitespace_before_storing() {
        let config = HostNetdAuditChainConfig::builder()
            .path("/tmp/mvm-host-netd.audit.chain.jsonl")
            .signing_key_path("/tmp/host-signer.ed25519")
            .tenant("  local  ")
            .vm_name("  vm-test  ")
            .build()
            .unwrap();

        assert_eq!(config.tenant(), "local");
        assert_eq!(config.vm_name(), "vm-test");
    }

    #[test]
    fn host_netd_stdio_processes_hello_and_writes_structured_audit() {
        let mut encoded = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
        encoded
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();

        let mut output = Cursor::new(Vec::new());
        let mut audit = Vec::new();
        let stats = run_host_netd_on_stdio_parts(
            &deny_all_config(),
            Cursor::new(encoded.into_inner().into_inner()),
            &mut output,
            JsonLineAuditSink::new(&mut audit),
        )
        .unwrap();

        assert_eq!(
            stats,
            HostRunnerStats {
                messages_read: 1,
                messages_written: 1,
                outcome: HostRunnerOutcome::Closed,
            }
        );
        let mut decoded = LengthPrefixedJsonAuthority::new(Cursor::new(output.into_inner()));
        assert!(matches!(
            decoded.read_message().unwrap(),
            JsonWireRead::Message(NetMessage::HelloAck(_))
        ));
        let audit_line = std::str::from_utf8(&audit).unwrap();
        let audit_json: serde_json::Value = serde_json::from_str(audit_line.trim()).unwrap();
        assert_eq!(audit_json["event"], "handshake_accepted");
        assert_eq!(audit_json["guest_capabilities"][0], "Dns");
    }

    #[test]
    fn host_netd_stdio_processes_hello_and_writes_verifiable_signed_audit_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (config, audit_path, verifying_key) =
            signed_audit_config(dir.path(), "local", "signed-audit-test");

        let mut encoded = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
        encoded
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();

        let mut output = Cursor::new(Vec::new());
        let mut audit = Vec::new();
        let stats = run_host_netd_on_stdio_parts(
            &config,
            Cursor::new(encoded.into_inner().into_inner()),
            &mut output,
            ConfiguredHostAuditSink::new(&config, &mut audit).unwrap(),
        )
        .unwrap();

        assert_eq!(
            stats,
            HostRunnerStats {
                messages_read: 1,
                messages_written: 1,
                outcome: HostRunnerOutcome::Closed,
            }
        );
        let chain = std::fs::read_to_string(&audit_path).unwrap();
        let verified = verify_audit_chain_bytes(&chain, &verifying_key).unwrap();
        assert_eq!(verified.count, 1);
        assert_eq!(
            verified.entries[0].event,
            "flow.transparent_net.handshake_accepted"
        );
        assert_eq!(verified.entries[0].tenant, "local");

        let envelope: serde_json::Value = serde_json::from_str(chain.trim()).unwrap();
        assert_eq!(envelope["entry"]["labels"]["vm_name"], "signed-audit-test");
        assert_eq!(
            envelope["entry"]["labels"]["raw_event"],
            "handshake_accepted"
        );
        assert_eq!(envelope["entry"]["labels"]["category"], "flow");
        assert_eq!(envelope["entry"]["labels"]["transport"], "transparent_net");
    }

    #[test]
    fn signed_audit_label_flattener_preserves_nested_prefixes() {
        let value = serde_json::json!({
            "allowed": true,
            "meta": {
                "host": "api.example.com",
                "port": 443
            }
        });
        let mut labels = std::collections::BTreeMap::new();

        flatten_signed_audit_labels("event", &value, &mut labels).unwrap();

        assert_eq!(labels["event.allowed"], "true");
        assert_eq!(labels["event.meta.host"], "api.example.com");
        assert_eq!(labels["event.meta.port"], "443");
    }

    #[test]
    fn host_netd_listen_uds_accepts_one_authority_stream() {
        let dir = uds_tempdir();
        if !uds_bind_supported(dir.path()) {
            return;
        }
        let socket = dir.path().join("netd.sock");
        let config = deny_all_config();
        let server_socket = socket.clone();
        let server = std::thread::spawn(move || {
            let mut audit = Vec::new();
            let stats = run_host_netd_listen_uds_with_audit(
                &config,
                &server_socket,
                JsonLineAuditSink::new(&mut audit),
            )
            .unwrap();
            (stats, audit)
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !socket.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "host netd socket was not bound"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let mut client = LengthPrefixedJsonAuthority::new(
            UnixStream::connect(&socket).expect("connect to host netd socket"),
        );
        client
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();
        assert!(matches!(
            client.read_message().unwrap(),
            JsonWireRead::Message(NetMessage::HelloAck(_))
        ));
        drop(client);

        let (stats, audit) = server.join().unwrap();
        assert_eq!(stats.messages_read, 1);
        assert_eq!(stats.messages_written, 1);
        let audit_line = std::str::from_utf8(&audit).unwrap();
        let audit_json: serde_json::Value = serde_json::from_str(audit_line.trim()).unwrap();
        assert_eq!(audit_json["event"], "handshake_accepted");
    }

    #[test]
    fn host_netd_wire_runner_uses_configured_policy_adapter() {
        let mut encoded = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
        encoded
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Dns],
            )))
            .unwrap();
        let input = Cursor::new(encoded.into_inner().into_inner());
        let output = Cursor::new(Vec::new());
        let mut wire = SplitJsonHostWire::new(input, output);

        let stats = run_host_netd_with_wire(
            &deny_all_config(),
            NoopHostAuditSink,
            RefusingTcpConnector,
            &mut wire,
        )
        .unwrap();

        assert_eq!(stats.messages_read, 1);
        assert_eq!(stats.messages_written, 1);
    }

    #[test]
    fn host_netd_threads_configured_synthetic_dns_limit_into_authority_config() {
        let config = unrestricted_config_with_synthetic_dns_limit(1);

        assert_eq!(config.max_synthetic_dns_entries(), 1);
        assert_eq!(
            authority_config_for_tcp_connector(&config, &RefusingTcpConnector)
                .max_synthetic_dns_entries(),
            1
        );
    }

    #[test]
    fn host_netd_threads_configured_synthetic_dns_settings_into_authority_config() {
        let synthetic_dns_base = Ipv4Addr::new(198, 19, 0, 10);
        let config = unrestricted_config_with_synthetic_dns_settings(
            synthetic_dns_base,
            4,
            crate::host::MAX_DNS_TTL_SECONDS,
        );

        let authority_config = authority_config_for_tcp_connector(&config, &RefusingTcpConnector);

        assert_eq!(config.synthetic_dns_base(), synthetic_dns_base);
        assert_eq!(config.max_synthetic_dns_entries(), 4);
        assert_eq!(config.dns_ttl_seconds(), crate::host::MAX_DNS_TTL_SECONDS);
        assert_eq!(authority_config.synthetic_dns_base(), synthetic_dns_base);
        assert_eq!(authority_config.max_synthetic_dns_entries(), 4);
        assert_eq!(
            authority_config.dns_ttl_seconds(),
            crate::host::MAX_DNS_TTL_SECONDS
        );
    }

    #[test]
    fn host_netd_threads_configured_udp_read_timeout_into_authority_config() {
        let udp_read_timeout = crate::host::MAX_UDP_READ_TIMEOUT;
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .udp_read_timeout(udp_read_timeout)
            .build()
            .unwrap();

        let authority_config = authority_config_for_tcp_connector(&config, &RefusingTcpConnector);

        assert_eq!(config.udp_read_timeout(), udp_read_timeout);
        assert_eq!(authority_config.udp_read_timeout(), udp_read_timeout);
    }

    #[test]
    fn host_netd_threads_configured_tcp_idle_timeout_into_authority_config() {
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .tcp_idle_timeout(Duration::from_millis(23))
            .build()
            .unwrap();

        let authority_config = authority_config_for_tcp_connector(&config, &RefusingTcpConnector);

        assert_eq!(config.tcp_idle_timeout(), Duration::from_millis(23));
        assert_eq!(
            authority_config.tcp_idle_timeout(),
            Duration::from_millis(23)
        );
    }

    #[test]
    fn host_netd_threads_configured_udp_idle_timeout_into_authority_config() {
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .udp_idle_timeout(Duration::from_millis(19))
            .build()
            .unwrap();

        let authority_config = authority_config_for_tcp_connector(&config, &RefusingTcpConnector);

        assert_eq!(config.udp_idle_timeout(), Duration::from_millis(19));
        assert_eq!(
            authority_config.udp_idle_timeout(),
            Duration::from_millis(19)
        );
    }

    #[test]
    fn host_netd_threads_configured_upstream_roots_into_tls_connector() {
        let tls_intermediate = test_tls_intermediate();
        let pem_bundle = tls_intermediate.cert_pem().to_string();
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .tls_intermediate(tls_intermediate)
            .upstream_roots(HostTlsUpstreamRoots::PemBundle(pem_bundle.clone()))
            .build()
            .unwrap();

        assert_eq!(
            config.upstream_roots(),
            &HostTlsUpstreamRoots::PemBundle(pem_bundle.clone())
        );
        match ConfiguredHostTcpConnector::from_config(&config).unwrap() {
            ConfiguredHostTcpConnector::Tls(connector) => {
                assert_eq!(
                    connector.config().upstream_roots(),
                    &HostTlsUpstreamRoots::PemBundle(pem_bundle)
                );
            }
            ConfiguredHostTcpConnector::Std(_) => {
                panic!("TLS intermediate should build a TLS connector")
            }
        }
    }

    #[test]
    fn host_netd_threads_configured_tcp_timeouts_into_std_connector() {
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .max_open_flows(9)
            .tcp_connect_timeout(Duration::from_millis(75))
            .tcp_read_timeout(Duration::from_millis(9))
            .build()
            .unwrap();

        match ConfiguredHostTcpConnector::from_config(&config).unwrap() {
            ConfiguredHostTcpConnector::Std(connector) => {
                assert_eq!(
                    connector.config().connect_timeout(),
                    Some(Duration::from_millis(75))
                );
                assert_eq!(connector.config().read_timeout(), Duration::from_millis(9));
                assert_eq!(connector.config().max_open_flows(), 9);
            }
            ConfiguredHostTcpConnector::Tls(_) => panic!("expected standard TCP connector"),
        }
    }

    #[test]
    fn host_netd_threads_configured_tcp_timeouts_into_tls_connector() {
        let tls_intermediate = test_tls_intermediate();
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .tls_intermediate(tls_intermediate)
            .upstream_roots(HostTlsUpstreamRoots::Native)
            .max_open_flows(10)
            .tcp_connect_timeout(Duration::from_millis(80))
            .tcp_read_timeout(Duration::from_millis(11))
            .build()
            .unwrap();

        match ConfiguredHostTcpConnector::from_config(&config).unwrap() {
            ConfiguredHostTcpConnector::Tls(connector) => {
                assert_eq!(
                    connector.config().tcp().connect_timeout(),
                    Some(Duration::from_millis(80))
                );
                assert_eq!(
                    connector.config().tcp().read_timeout(),
                    Duration::from_millis(11)
                );
                assert_eq!(connector.config().tcp().max_open_flows(), 10);
                assert_eq!(connector.config().max_open_flows(), 10);
            }
            ConfiguredHostTcpConnector::Std(_) => panic!("expected TLS connector"),
        }
    }

    #[test]
    fn host_netd_threads_configured_tls_flow_detail_budget_into_tls_connector() {
        let config = HostNetdConfig::builder()
            .network_policy(mvm_core::policy::network_policy::NetworkPolicy::unrestricted())
            .now(NOW)
            .tls_intermediate(test_tls_intermediate())
            .upstream_roots(HostTlsUpstreamRoots::Native)
            .max_tls_flow_detail_bytes(17)
            .max_retained_tls_flow_details(19)
            .build()
            .unwrap();

        match ConfiguredHostTcpConnector::from_config(&config).unwrap() {
            ConfiguredHostTcpConnector::Tls(connector) => {
                assert_eq!(connector.config().max_tls_flow_detail_bytes(), 17);
                assert_eq!(connector.config().max_retained_tls_flow_details(), 19);
            }
            ConfiguredHostTcpConnector::Std(_) => panic!("expected TLS connector"),
        }
    }

    #[test]
    fn host_netd_service_loop_keeps_draining_upstream_after_guest_would_block() {
        let flow_id = FlowId::new(7).unwrap();
        let open = crate::proto::OpenTcp::new(
            flow_id,
            crate::proto::Target::new("203.0.113.10", 443).unwrap(),
        );
        let mut wire = MemoryWire::with_reads([
            crate::host_runner::HostAuthorityRead::Message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![Capability::Tcp],
            ))),
            crate::host_runner::HostAuthorityRead::Message(NetMessage::OpenTcp(open)),
            crate::host_runner::HostAuthorityRead::WouldBlock,
            crate::host_runner::HostAuthorityRead::Closed,
        ]);

        let stats = serve_host_netd_with_wire(
            &unrestricted_config(),
            NoopHostAuditSink,
            DelayedDrainConnector::with_drains([
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![crate::host::HostTcpEvent::Data(StreamChunk::new(
                    flow_id,
                    FlowDirection::HostToGuest,
                    0,
                    b"server-flight".to_vec(),
                ))],
                Vec::new(),
            ]),
            &mut wire,
        )
        .unwrap();

        assert_eq!(
            stats,
            HostRunnerStats {
                messages_read: 2,
                messages_written: 3,
                outcome: HostRunnerOutcome::Closed,
            }
        );
        assert!(matches!(wire.writes[0], NetMessage::HelloAck(_)));
        assert!(matches!(
            wire.writes[1],
            NetMessage::TcpOpenResult(crate::proto::TcpOpenResult {
                flow_id: returned_flow_id,
                status: crate::proto::FlowOpenStatus::Opened,
            }) if returned_flow_id == flow_id
        ));
        assert!(matches!(
            wire.writes[2],
            NetMessage::TcpData(StreamChunk {
                flow_id: returned_flow_id,
                direction: FlowDirection::HostToGuest,
                ..
            }) if returned_flow_id == flow_id
        ));
    }

    #[derive(Debug, Default)]
    struct TlsAdvertisingConnector;

    impl HostTcpConnector for TlsAdvertisingConnector {
        fn open(&mut self, _spec: &crate::host::TcpConnectSpec) -> Result<(), TransportError> {
            Ok(())
        }

        fn send(&mut self, _chunk: &StreamChunk) -> Result<(), TransportError> {
            Ok(())
        }

        fn close(&mut self, _flow_id: FlowId, _reason: CloseReason) -> Result<(), TransportError> {
            Ok(())
        }

        fn drain_events(
            &mut self,
            _max_events: usize,
        ) -> Result<Vec<crate::host::HostTcpEvent>, TransportError> {
            Ok(Vec::new())
        }

        fn supports_tls_transform(&self) -> bool {
            true
        }

        fn supports_stream_transforms(&self) -> bool {
            true
        }
    }

    #[test]
    fn host_netd_advertises_tls_transform_when_connector_supports_it() {
        let mut encoded = LengthPrefixedJsonAuthority::new(Cursor::new(Vec::new()));
        encoded
            .write_message(NetMessage::Hello(Hello::new(
                EndpointRole::Guest,
                vec![
                    Capability::Dns,
                    Capability::Tcp,
                    Capability::TlsTransform,
                    Capability::StreamTransforms,
                ],
            )))
            .unwrap();
        let input = Cursor::new(encoded.into_inner().into_inner());
        let output = Cursor::new(Vec::new());
        let mut wire = SplitJsonHostWire::new(input, output);

        let stats = run_host_netd_with_wire(
            &deny_all_config(),
            NoopHostAuditSink,
            TlsAdvertisingConnector,
            &mut wire,
        )
        .unwrap();

        assert_eq!(stats.messages_read, 1);
        assert_eq!(stats.messages_written, 1);
        let (_, writer) = wire.into_parts();
        let output = writer.into_inner().into_inner();
        let mut decoded = LengthPrefixedJsonAuthority::new(Cursor::new(output));
        assert!(matches!(
            decoded.read_message().unwrap(),
            JsonWireRead::Message(NetMessage::HelloAck(HelloAck {
                accepted_capabilities,
                ..
            })) if accepted_capabilities == vec![
                Capability::Dns,
                Capability::Tcp,
                Capability::TlsTransform,
                Capability::StreamTransforms,
            ]
        ));
    }
}
