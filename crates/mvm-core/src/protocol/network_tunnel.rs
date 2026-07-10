//! Shared guest-TUN ↔ host-UDS network tunnel contract.
//!
//! This module defines the first stable wire/config seam for a production
//! vsock-only data path:
//!
//! guest TUN -> framed packets -> AF_VSOCK -> host UDS -> host worker
//!
//! The implementation deliberately stops at the contract:
//! - session-bound identity and feature negotiation,
//! - guest network configuration,
//! - frame typing and bounded decoding.
//!
//! The host/guest packet pumps land in later slices; pinning the contract here
//! first lets both ends converge on one fail-closed shape.

use serde::{Deserialize, Serialize};

/// Fixed header magic for every tunnel frame (`MVNT`).
pub const NETWORK_TUNNEL_MAGIC: u32 = u32::from_be_bytes(*b"MVNT");
/// Protocol version implemented by this module.
pub const NETWORK_TUNNEL_VERSION: u8 = 1;
/// Fixed encoded length of [`PacketFrameHeader`].
pub const PACKET_FRAME_HEADER_LEN: usize = 24;
/// Default guest AF_VSOCK port for the packet-tunnel worker.
pub const NETWORK_TUNNEL_GUEST_PORT: u32 = 5302;
/// Maximum accepted payload size for one frame.
pub const MAX_FRAME_PAYLOAD_LEN: u32 = 64 * 1024;
/// Largest accepted identifier or version string in control messages.
pub const MAX_CONTROL_STRING_LEN: usize = 128;
/// Maximum number of DNS resolvers the host may hand the guest.
pub const MAX_DNS_SERVERS: usize = 4;
/// Maximum MTU admitted by the tunnel config.
pub const MAX_TUNNEL_MTU: u16 = 65_535;
/// Minimum sensible TUN MTU.
pub const MIN_TUNNEL_MTU: u16 = 576;
/// Maximum number of host→IP entries the host may inject into the guest's
/// `/etc/hosts`. Bounds the config so a hostile or buggy producer can't hand the
/// guest an unbounded allow-list.
pub const MAX_HOST_ENTRIES: usize = 64;
/// Upper bound on a host-entry name, matching the DNS name length limit.
pub const MAX_HOST_ENTRY_NAME_LEN: usize = 253;

/// Fixed frame type tags for the control/data tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    HelloAck = 2,
    Config = 3,
    Packet = 4,
    Credit = 5,
    Heartbeat = 6,
    Error = 7,
    Shutdown = 8,
}

impl FrameType {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FrameType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::Config),
            4 => Ok(Self::Packet),
            5 => Ok(Self::Credit),
            6 => Ok(Self::Heartbeat),
            7 => Ok(Self::Error),
            8 => Ok(Self::Shutdown),
            other => Err(DecodeError::UnknownFrameType(other)),
        }
    }
}

/// Immutable header prefix on every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFrameHeader {
    pub magic: u32,
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: u16,
    pub flow_id: u32,
    pub payload_len: u32,
    pub sequence: u64,
}

impl PacketFrameHeader {
    pub fn new(
        frame_type: FrameType,
        flags: u16,
        flow_id: u32,
        payload_len: u32,
        sequence: u64,
    ) -> Self {
        Self {
            magic: NETWORK_TUNNEL_MAGIC,
            version: NETWORK_TUNNEL_VERSION,
            frame_type,
            flags,
            flow_id,
            payload_len,
            sequence,
        }
    }

    pub fn encode(self) -> [u8; PACKET_FRAME_HEADER_LEN] {
        let mut out = [0_u8; PACKET_FRAME_HEADER_LEN];
        out[0..4].copy_from_slice(&self.magic.to_be_bytes());
        out[4] = self.version;
        out[5] = self.frame_type.as_u8();
        out[6..8].copy_from_slice(&self.flags.to_be_bytes());
        out[8..12].copy_from_slice(&self.flow_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.payload_len.to_be_bytes());
        out[16..24].copy_from_slice(&self.sequence.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != PACKET_FRAME_HEADER_LEN {
            return Err(DecodeError::WrongHeaderLength {
                got: bytes.len(),
                expected: PACKET_FRAME_HEADER_LEN,
            });
        }

        let magic = u32::from_be_bytes(bytes[0..4].try_into().expect("slice len checked"));
        if magic != NETWORK_TUNNEL_MAGIC {
            return Err(DecodeError::BadMagic(magic));
        }

        let version = bytes[4];
        if version != NETWORK_TUNNEL_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }

        let frame_type = FrameType::try_from(bytes[5])?;
        let flags = u16::from_be_bytes(bytes[6..8].try_into().expect("slice len checked"));
        let flow_id = u32::from_be_bytes(bytes[8..12].try_into().expect("slice len checked"));
        let payload_len = u32::from_be_bytes(bytes[12..16].try_into().expect("slice len checked"));
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(DecodeError::PayloadTooLarge(payload_len));
        }
        let sequence = u64::from_be_bytes(bytes[16..24].try_into().expect("slice len checked"));

        Ok(Self {
            magic,
            version,
            frame_type,
            flags,
            flow_id,
            payload_len,
            sequence,
        })
    }
}

/// One decoded frame borrowing its payload from the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BorrowedTunnelFrame<'a> {
    pub header: PacketFrameHeader,
    pub payload: &'a [u8],
}

impl<'a> BorrowedTunnelFrame<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < PACKET_FRAME_HEADER_LEN {
            return Err(DecodeError::TruncatedFrame {
                got: bytes.len(),
                expected_at_least: PACKET_FRAME_HEADER_LEN,
            });
        }
        let header = PacketFrameHeader::decode(&bytes[..PACKET_FRAME_HEADER_LEN])?;
        let expected_len = PACKET_FRAME_HEADER_LEN + header.payload_len as usize;
        if bytes.len() != expected_len {
            return Err(DecodeError::FrameLengthMismatch {
                payload_len: header.payload_len,
                actual_total_len: bytes.len(),
            });
        }
        Ok(Self {
            header,
            payload: &bytes[PACKET_FRAME_HEADER_LEN..],
        })
    }
}

/// Owned frame buffer ready to send over the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTunnelFrame {
    pub header: PacketFrameHeader,
    pub payload: Vec<u8>,
}

impl OwnedTunnelFrame {
    pub fn new(
        frame_type: FrameType,
        flags: u16,
        flow_id: u32,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| EncodeError::PayloadTooLarge(payload.len()))?;
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(EncodeError::PayloadTooLarge(payload.len()));
        }
        Ok(Self {
            header: PacketFrameHeader::new(frame_type, flags, flow_id, payload_len, sequence),
            payload,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PACKET_FRAME_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Negotiated feature bits. Closed shape: new features add explicit fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelFeatures {
    #[serde(default)]
    pub ipv4: bool,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub split_control_stream: bool,
    #[serde(default)]
    pub audit_stream: bool,
    #[serde(default)]
    pub dns_intercept: bool,
    #[serde(default)]
    pub typed_connectors: bool,
}

/// Guest-authored identity + feature request for one boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelHello {
    pub protocol_version: u8,
    pub tenant_id: String,
    pub vm_id: String,
    pub boot_id: String,
    pub session_nonce: String,
    pub guest_agent_version: String,
    #[serde(default)]
    pub requested_features: TunnelFeatures,
    pub maximum_frame_size: u32,
}

impl TunnelHello {
    pub fn validate(&self) -> Result<(), ControlMessageError> {
        validate_string("tenant_id", &self.tenant_id)?;
        validate_string("vm_id", &self.vm_id)?;
        validate_string("boot_id", &self.boot_id)?;
        validate_string("session_nonce", &self.session_nonce)?;
        validate_string("guest_agent_version", &self.guest_agent_version)?;

        if self.protocol_version != NETWORK_TUNNEL_VERSION {
            return Err(ControlMessageError::UnsupportedVersion(
                self.protocol_version,
            ));
        }
        if self.maximum_frame_size == 0 || self.maximum_frame_size > MAX_FRAME_PAYLOAD_LEN {
            return Err(ControlMessageError::FrameSizeOutOfRange(
                self.maximum_frame_size,
            ));
        }
        Ok(())
    }
}

/// Launch-time session identity and feature request for one packet-tunnel boot.
///
/// This is the shared runtime carrier both sides can thread through backend
/// wiring before the actual guest TUN + host worker data plane lands. The guest
/// turns it into a `HELLO`; the host validates against the same fields rather
/// than re-deriving them per backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelSessionConfig {
    pub tenant_id: String,
    pub vm_id: String,
    pub boot_id: String,
    pub session_nonce: String,
    #[serde(default)]
    pub requested_features: TunnelFeatures,
    pub maximum_frame_size: u32,
}

impl TunnelSessionConfig {
    pub fn validate(&self) -> Result<(), ControlMessageError> {
        validate_string("tenant_id", &self.tenant_id)?;
        validate_string("vm_id", &self.vm_id)?;
        validate_string("boot_id", &self.boot_id)?;
        validate_string("session_nonce", &self.session_nonce)?;
        if self.maximum_frame_size == 0 || self.maximum_frame_size > MAX_FRAME_PAYLOAD_LEN {
            return Err(ControlMessageError::FrameSizeOutOfRange(
                self.maximum_frame_size,
            ));
        }
        Ok(())
    }

    pub fn hello(
        &self,
        guest_agent_version: impl Into<String>,
    ) -> Result<TunnelHello, ControlMessageError> {
        let hello = TunnelHello {
            protocol_version: NETWORK_TUNNEL_VERSION,
            tenant_id: self.tenant_id.clone(),
            vm_id: self.vm_id.clone(),
            boot_id: self.boot_id.clone(),
            session_nonce: self.session_nonce.clone(),
            guest_agent_version: guest_agent_version.into(),
            requested_features: self.requested_features.clone(),
            maximum_frame_size: self.maximum_frame_size,
        };
        hello.validate()?;
        Ok(hello)
    }
}

/// Runtime launch carrier for the packet-tunnel channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelRuntimeConfig {
    #[serde(default = "default_network_tunnel_guest_port")]
    pub guest_port: u32,
    pub session: TunnelSessionConfig,
}

impl TunnelRuntimeConfig {
    pub fn validate(&self) -> Result<(), ControlMessageError> {
        if self.guest_port == 0 {
            return Err(ControlMessageError::InvalidTunnelGuestPort(self.guest_port));
        }
        self.session.validate()
    }
}

fn default_network_tunnel_guest_port() -> u32 {
    NETWORK_TUNNEL_GUEST_PORT
}

/// Host-authored acceptance of a tunnel session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelHelloAck {
    pub protocol_version: u8,
    pub vm_id: String,
    pub boot_id: String,
    pub session_nonce: String,
    #[serde(default)]
    pub accepted_features: TunnelFeatures,
    pub maximum_frame_size: u32,
}

impl TunnelHelloAck {
    pub fn validate_against(&self, hello: &TunnelHello) -> Result<(), ControlMessageError> {
        validate_string("vm_id", &self.vm_id)?;
        validate_string("boot_id", &self.boot_id)?;
        validate_string("session_nonce", &self.session_nonce)?;

        if self.protocol_version != NETWORK_TUNNEL_VERSION {
            return Err(ControlMessageError::UnsupportedVersion(
                self.protocol_version,
            ));
        }
        if self.vm_id != hello.vm_id || self.boot_id != hello.boot_id {
            return Err(ControlMessageError::IdentityMismatch);
        }
        if self.session_nonce != hello.session_nonce {
            return Err(ControlMessageError::SessionNonceMismatch);
        }
        if self.maximum_frame_size == 0
            || self.maximum_frame_size > hello.maximum_frame_size
            || self.maximum_frame_size > MAX_FRAME_PAYLOAD_LEN
        {
            return Err(ControlMessageError::FrameSizeOutOfRange(
                self.maximum_frame_size,
            ));
        }
        Ok(())
    }
}

/// One admission-time host→IPv4 pin the guest writes into `/etc/hosts`.
///
/// The host resolved every allowlisted name once at admission and gates guest
/// packets by dst IP against that pin set. Handing the guest the same
/// `name → ip` pairs makes in-guest resolution pin-consistent by construction:
/// an admitted name resolves to exactly the IP the gate admits, and a
/// non-allowlisted name has no entry and simply fails to resolve — default-deny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelHostEntry {
    pub name: String,
    pub ip: std::net::Ipv4Addr,
}

/// Host-provided guest network configuration for the tunnel endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelNetworkConfig {
    pub interface_name: String,
    pub guest_ipv4: std::net::Ipv4Addr,
    pub prefix_len: u8,
    pub gateway_ipv4: std::net::Ipv4Addr,
    #[serde(default)]
    pub dns_servers: Vec<std::net::IpAddr>,
    pub mtu: u16,
    /// Admission pins the guest injects into `/etc/hosts` for name resolution.
    #[serde(default)]
    pub host_entries: Vec<TunnelHostEntry>,
}

impl TunnelNetworkConfig {
    pub fn validate(&self) -> Result<(), ControlMessageError> {
        validate_string("interface_name", &self.interface_name)?;
        if self.prefix_len > 32 {
            return Err(ControlMessageError::InvalidPrefixLen(self.prefix_len));
        }
        if self.dns_servers.len() > MAX_DNS_SERVERS {
            return Err(ControlMessageError::TooManyDnsServers(
                self.dns_servers.len(),
            ));
        }
        if !(MIN_TUNNEL_MTU..=MAX_TUNNEL_MTU).contains(&self.mtu) {
            return Err(ControlMessageError::MtuOutOfRange(self.mtu));
        }
        if self.host_entries.len() > MAX_HOST_ENTRIES {
            return Err(ControlMessageError::TooManyHostEntries(
                self.host_entries.len(),
            ));
        }
        for entry in &self.host_entries {
            validate_host_entry_name(&entry.name)?;
        }
        Ok(())
    }
}

/// Credit-based backpressure update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelCreditUpdate {
    pub flow_id: u32,
    pub bytes: u32,
    pub packets: u32,
}

impl TunnelCreditUpdate {
    pub fn validate(&self) -> Result<(), ControlMessageError> {
        if self.bytes == 0 && self.packets == 0 {
            return Err(ControlMessageError::EmptyCreditUpdate);
        }
        Ok(())
    }
}

/// A structured control-plane error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelErrorFrame {
    pub code: TunnelErrorCode,
    pub detail: String,
}

impl TunnelErrorFrame {
    pub fn validate(&self) -> Result<(), ControlMessageError> {
        validate_string("detail", &self.detail)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelErrorCode {
    UnsupportedVersion,
    AuthenticationFailed,
    MalformedFrame,
    PolicyDenied,
    QuotaExceeded,
    Internal,
}

/// Explicit shutdown cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelShutdownReason {
    HostStopping,
    HostError,
    GuestStopping,
    PolicyDenied,
    ProtocolError,
}

/// All JSON-encoded control-plane payloads admitted on the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelControlMessage {
    Hello(TunnelHello),
    HelloAck(TunnelHelloAck),
    Config(TunnelNetworkConfig),
    Credit(TunnelCreditUpdate),
    Heartbeat,
    Error(TunnelErrorFrame),
    Shutdown(TunnelShutdownReason),
}

impl TunnelControlMessage {
    pub fn frame_type(&self) -> FrameType {
        match self {
            Self::Hello(_) => FrameType::Hello,
            Self::HelloAck(_) => FrameType::HelloAck,
            Self::Config(_) => FrameType::Config,
            Self::Credit(_) => FrameType::Credit,
            Self::Heartbeat => FrameType::Heartbeat,
            Self::Error(_) => FrameType::Error,
            Self::Shutdown(_) => FrameType::Shutdown,
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, ControlCodecError> {
        let payload = match self {
            Self::Hello(hello) => {
                hello
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                serde_json::to_vec(hello)?
            }
            Self::HelloAck(ack) => serde_json::to_vec(ack)?,
            Self::Config(config) => {
                config
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                serde_json::to_vec(config)?
            }
            Self::Credit(credit) => {
                credit
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                serde_json::to_vec(credit)?
            }
            Self::Heartbeat => Vec::new(),
            Self::Error(error) => {
                error
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                serde_json::to_vec(error)?
            }
            Self::Shutdown(reason) => serde_json::to_vec(reason)?,
        };
        if payload.len() > MAX_FRAME_PAYLOAD_LEN as usize {
            return Err(ControlCodecError::PayloadTooLarge(payload.len()));
        }
        Ok(payload)
    }

    pub fn decode(frame_type: FrameType, payload: &[u8]) -> Result<Self, ControlCodecError> {
        match frame_type {
            FrameType::Hello => {
                let hello: TunnelHello = serde_json::from_slice(payload)?;
                hello
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                Ok(Self::Hello(hello))
            }
            FrameType::HelloAck => Ok(Self::HelloAck(serde_json::from_slice(payload)?)),
            FrameType::Config => {
                let config: TunnelNetworkConfig = serde_json::from_slice(payload)?;
                config
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                Ok(Self::Config(config))
            }
            FrameType::Credit => {
                let credit: TunnelCreditUpdate = serde_json::from_slice(payload)?;
                credit
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                Ok(Self::Credit(credit))
            }
            FrameType::Heartbeat => {
                if payload.is_empty() {
                    Ok(Self::Heartbeat)
                } else {
                    Err(ControlCodecError::HeartbeatPayloadNotEmpty(payload.len()))
                }
            }
            FrameType::Error => {
                let error: TunnelErrorFrame = serde_json::from_slice(payload)?;
                error
                    .validate()
                    .map_err(ControlCodecError::InvalidMessage)?;
                Ok(Self::Error(error))
            }
            FrameType::Shutdown => Ok(Self::Shutdown(serde_json::from_slice(payload)?)),
            FrameType::Packet => Err(ControlCodecError::UnexpectedPacketFrame),
        }
    }

    pub fn encode_frame(
        &self,
        flags: u16,
        flow_id: u32,
        sequence: u64,
    ) -> Result<OwnedTunnelFrame, ControlCodecError> {
        let payload = self.encode_payload()?;
        OwnedTunnelFrame::new(self.frame_type(), flags, flow_id, sequence, payload)
            .map_err(ControlCodecError::FrameEncode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("wrong header length: expected {expected} bytes, got {got}")]
    WrongHeaderLength { got: usize, expected: usize },
    #[error("unexpected frame magic 0x{0:08x}")]
    BadMagic(u32),
    #[error("unsupported tunnel protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown frame type {0}")]
    UnknownFrameType(u8),
    #[error("payload length {0} exceeds the configured maximum")]
    PayloadTooLarge(u32),
    #[error("truncated frame: expected at least {expected_at_least} bytes, got {got}")]
    TruncatedFrame {
        got: usize,
        expected_at_least: usize,
    },
    #[error(
        "frame length mismatch: header payload_len={payload_len}, total bytes={actual_total_len}"
    )]
    FrameLengthMismatch {
        payload_len: u32,
        actual_total_len: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlMessageError {
    #[error("{0} must be non-empty and at most {MAX_CONTROL_STRING_LEN} bytes")]
    InvalidString(&'static str),
    #[error("unsupported tunnel protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("frame size {0} is outside the admitted range")]
    FrameSizeOutOfRange(u32),
    #[error("guest/host identity mismatch in hello acknowledgement")]
    IdentityMismatch,
    #[error("session nonce mismatch in hello acknowledgement")]
    SessionNonceMismatch,
    #[error("IPv4 prefix length {0} is invalid")]
    InvalidPrefixLen(u8),
    #[error("received {0} DNS servers, maximum is {MAX_DNS_SERVERS}")]
    TooManyDnsServers(usize),
    #[error("MTU {0} is outside the admitted range")]
    MtuOutOfRange(u16),
    #[error("tunnel guest port {0} is invalid")]
    InvalidTunnelGuestPort(u32),
    #[error("credit update must grant at least one packet or one byte")]
    EmptyCreditUpdate,
    #[error("received {0} host entries, maximum is {MAX_HOST_ENTRIES}")]
    TooManyHostEntries(usize),
    #[error("host entry name {0:?} is not a valid DNS-ish label")]
    InvalidHostEntryName(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("payload of {0} bytes exceeds the tunnel frame limit")]
    PayloadTooLarge(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum ControlCodecError {
    #[error("invalid control message: {0}")]
    InvalidMessage(ControlMessageError),
    #[error("failed to serialize or parse control payload: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("control payload of {0} bytes exceeds the tunnel frame limit")]
    PayloadTooLarge(usize),
    #[error("heartbeat frame must carry an empty payload, got {0} bytes")]
    HeartbeatPayloadNotEmpty(usize),
    #[error("packet frames must not be decoded as control messages")]
    UnexpectedPacketFrame,
    #[error("failed to build tunnel frame: {0}")]
    FrameEncode(EncodeError),
}

fn validate_string(field: &'static str, value: &str) -> Result<(), ControlMessageError> {
    if value.is_empty() || value.len() > MAX_CONTROL_STRING_LEN {
        return Err(ControlMessageError::InvalidString(field));
    }
    Ok(())
}

/// A host-entry name must be a non-empty, bounded DNS-ish label: only ASCII
/// alphanumerics plus `.` and `-`, so it can never inject a second `/etc/hosts`
/// token or a newline into the guest hosts file.
fn validate_host_entry_name(name: &str) -> Result<(), ControlMessageError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_HOST_ENTRY_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(ControlMessageError::InvalidHostEntryName(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_frame_header_roundtrips() {
        let header = PacketFrameHeader::new(FrameType::Packet, 3, 7, 4096, 99);
        let decoded = PacketFrameHeader::decode(&header.encode()).expect("decode");
        assert_eq!(decoded, header);
    }

    #[test]
    fn packet_frame_header_rejects_oversized_payloads() {
        let mut encoded =
            PacketFrameHeader::new(FrameType::Packet, 0, 1, MAX_FRAME_PAYLOAD_LEN + 1, 5).encode();
        encoded[12..16].copy_from_slice(&(MAX_FRAME_PAYLOAD_LEN + 1).to_be_bytes());
        let err = PacketFrameHeader::decode(&encoded).expect_err("oversize rejected");
        assert_eq!(err, DecodeError::PayloadTooLarge(MAX_FRAME_PAYLOAD_LEN + 1));
    }

    #[test]
    fn packet_frame_header_rejects_unknown_frame_type() {
        let mut encoded = PacketFrameHeader::new(FrameType::Packet, 0, 1, 1, 5).encode();
        encoded[5] = 99;
        let err = PacketFrameHeader::decode(&encoded).expect_err("unknown frame type rejected");
        assert_eq!(err, DecodeError::UnknownFrameType(99));
    }

    #[test]
    fn hello_roundtrips_and_validates() {
        let hello = TunnelHello {
            protocol_version: NETWORK_TUNNEL_VERSION,
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            guest_agent_version: "guest-netd/1".to_string(),
            requested_features: TunnelFeatures {
                ipv4: true,
                dns_intercept: true,
                ..TunnelFeatures::default()
            },
            maximum_frame_size: 4096,
        };
        hello.validate().expect("valid hello");
        let roundtrip: TunnelHello =
            serde_json::from_str(&serde_json::to_string(&hello).expect("serialize"))
                .expect("deserialize");
        assert_eq!(roundtrip, hello);
    }

    #[test]
    fn tunnel_session_config_builds_a_valid_hello() {
        let session = TunnelSessionConfig {
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            requested_features: TunnelFeatures {
                ipv4: true,
                ..TunnelFeatures::default()
            },
            maximum_frame_size: 4096,
        };

        let hello = session.hello("guest-netd/1").expect("hello");
        assert_eq!(hello.protocol_version, NETWORK_TUNNEL_VERSION);
        assert_eq!(hello.tenant_id, "tenant-a");
        assert_eq!(hello.vm_id, "vm-1");
        assert_eq!(hello.boot_id, "boot-1");
        assert_eq!(hello.session_nonce, "nonce-1");
        assert_eq!(hello.guest_agent_version, "guest-netd/1");
        assert!(hello.requested_features.ipv4);
    }

    #[test]
    fn tunnel_runtime_config_rejects_zero_guest_port() {
        let err = TunnelRuntimeConfig {
            guest_port: 0,
            session: TunnelSessionConfig {
                tenant_id: "tenant-a".to_string(),
                vm_id: "vm-1".to_string(),
                boot_id: "boot-1".to_string(),
                session_nonce: "nonce-1".to_string(),
                requested_features: TunnelFeatures::default(),
                maximum_frame_size: 4096,
            },
        }
        .validate()
        .expect_err("guest port rejected");

        assert_eq!(err, ControlMessageError::InvalidTunnelGuestPort(0));
    }

    #[test]
    fn hello_ack_must_match_hello_identity() {
        let hello = TunnelHello {
            protocol_version: NETWORK_TUNNEL_VERSION,
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            guest_agent_version: "guest-netd/1".to_string(),
            requested_features: TunnelFeatures::default(),
            maximum_frame_size: 4096,
        };
        let ack = TunnelHelloAck {
            protocol_version: NETWORK_TUNNEL_VERSION,
            vm_id: "vm-2".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            accepted_features: TunnelFeatures::default(),
            maximum_frame_size: 4096,
        };
        let err = ack
            .validate_against(&hello)
            .expect_err("mismatched identity rejected");
        assert_eq!(err, ControlMessageError::IdentityMismatch);
    }

    #[test]
    fn network_config_rejects_too_many_dns_servers() {
        let cfg = TunnelNetworkConfig {
            interface_name: "mvm-net0".to_string(),
            guest_ipv4: "10.240.0.2".parse().expect("ip"),
            prefix_len: 24,
            gateway_ipv4: "10.240.0.1".parse().expect("ip"),
            dns_servers: vec![
                "1.1.1.1".parse().expect("ip"),
                "8.8.8.8".parse().expect("ip"),
                "9.9.9.9".parse().expect("ip"),
                "2606:4700:4700::1111".parse().expect("ip"),
                "2606:4700:4700::1001".parse().expect("ip"),
            ],
            mtu: 1500,
            host_entries: Vec::new(),
        };
        let err = cfg.validate().expect_err("dns cap enforced");
        assert_eq!(err, ControlMessageError::TooManyDnsServers(5));
    }

    fn network_config_with_host_entries(host_entries: Vec<TunnelHostEntry>) -> TunnelNetworkConfig {
        TunnelNetworkConfig {
            interface_name: "mvm-net0".to_string(),
            guest_ipv4: "10.240.0.2".parse().expect("ip"),
            prefix_len: 30,
            gateway_ipv4: "10.240.0.1".parse().expect("ip"),
            dns_servers: Vec::new(),
            mtu: 1500,
            host_entries,
        }
    }

    #[test]
    fn tunnel_config_host_entries_serde_roundtrip_and_bounds() {
        let cfg = network_config_with_host_entries(vec![
            TunnelHostEntry {
                name: "api.openai.com".to_string(),
                ip: "104.18.7.42".parse().expect("ip"),
            },
            TunnelHostEntry {
                name: "example-cdn.net".to_string(),
                ip: "93.184.216.34".parse().expect("ip"),
            },
        ]);
        cfg.validate().expect("valid host entries");

        let roundtrip: TunnelNetworkConfig =
            serde_json::from_str(&serde_json::to_string(&cfg).expect("serialize"))
                .expect("deserialize");
        assert_eq!(roundtrip, cfg);

        // Over-cap vec is rejected.
        let over_cap: Vec<TunnelHostEntry> = (0..(MAX_HOST_ENTRIES + 1))
            .map(|i| TunnelHostEntry {
                name: format!("h{i}.example.com"),
                ip: "10.0.0.1".parse().expect("ip"),
            })
            .collect();
        let err = network_config_with_host_entries(over_cap)
            .validate()
            .expect_err("over-cap rejected");
        assert_eq!(
            err,
            ControlMessageError::TooManyHostEntries(MAX_HOST_ENTRIES + 1)
        );

        // A name with a disallowed character is rejected.
        let err = network_config_with_host_entries(vec![TunnelHostEntry {
            name: "bad name!".to_string(),
            ip: "10.0.0.1".parse().expect("ip"),
        }])
        .validate()
        .expect_err("bad name rejected");
        assert_eq!(
            err,
            ControlMessageError::InvalidHostEntryName("bad name!".to_string())
        );

        // An empty name is rejected.
        let err = network_config_with_host_entries(vec![TunnelHostEntry {
            name: String::new(),
            ip: "10.0.0.1".parse().expect("ip"),
        }])
        .validate()
        .expect_err("empty name rejected");
        assert_eq!(
            err,
            ControlMessageError::InvalidHostEntryName(String::new())
        );
    }

    #[test]
    fn tunnel_config_defaults_host_entries_to_empty_when_absent() {
        // Old configs without the field still parse (default = empty).
        let json = r#"{
            "interface_name": "mvm-net0",
            "guest_ipv4": "10.240.0.2",
            "prefix_len": 30,
            "gateway_ipv4": "10.240.0.1",
            "mtu": 1500
        }"#;
        let cfg: TunnelNetworkConfig = serde_json::from_str(json).expect("parse");
        assert!(cfg.host_entries.is_empty());
        cfg.validate().expect("valid");
    }

    #[test]
    fn owned_frame_roundtrips_through_borrowed_decode() {
        let frame =
            OwnedTunnelFrame::new(FrameType::Packet, 1, 77, 12, vec![1, 2, 3, 4]).expect("frame");
        let encoded = frame.encode();
        let decoded = BorrowedTunnelFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded.header, frame.header);
        assert_eq!(decoded.payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn borrowed_frame_rejects_length_mismatch() {
        let frame =
            OwnedTunnelFrame::new(FrameType::Packet, 1, 77, 12, vec![1, 2, 3, 4]).expect("frame");
        let mut encoded = frame.encode();
        encoded.pop();
        let err = BorrowedTunnelFrame::decode(&encoded).expect_err("length mismatch");
        assert_eq!(
            err,
            DecodeError::FrameLengthMismatch {
                payload_len: 4,
                actual_total_len: PACKET_FRAME_HEADER_LEN + 3,
            }
        );
    }

    #[test]
    fn control_message_roundtrips_through_frame_codec() {
        let msg = TunnelControlMessage::Hello(TunnelHello {
            protocol_version: NETWORK_TUNNEL_VERSION,
            tenant_id: "tenant-a".to_string(),
            vm_id: "vm-1".to_string(),
            boot_id: "boot-1".to_string(),
            session_nonce: "nonce-1".to_string(),
            guest_agent_version: "guest-netd/1".to_string(),
            requested_features: TunnelFeatures {
                ipv4: true,
                split_control_stream: true,
                ..TunnelFeatures::default()
            },
            maximum_frame_size: 4096,
        });
        let encoded = msg.encode_frame(0, 0, 1).expect("encode").encode();
        let frame = BorrowedTunnelFrame::decode(&encoded).expect("frame decode");
        let decoded = TunnelControlMessage::decode(frame.header.frame_type, frame.payload)
            .expect("control decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn credit_update_rejects_empty_grant() {
        let err = TunnelCreditUpdate {
            flow_id: 0,
            bytes: 0,
            packets: 0,
        }
        .validate()
        .expect_err("empty credit rejected");
        assert_eq!(err, ControlMessageError::EmptyCreditUpdate);
    }

    #[test]
    fn heartbeat_payload_must_be_empty() {
        let err = TunnelControlMessage::decode(FrameType::Heartbeat, b"{\"unexpected\":true}")
            .expect_err("heartbeat payload rejected");
        assert!(matches!(
            err,
            ControlCodecError::HeartbeatPayloadNotEmpty(_)
        ));
    }

    #[test]
    fn packet_frame_cannot_decode_as_control_message() {
        let err = TunnelControlMessage::decode(FrameType::Packet, b"{}")
            .expect_err("packet frame rejected");
        assert!(matches!(err, ControlCodecError::UnexpectedPacketFrame));
    }
}
