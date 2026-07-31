//! Fixed-layout payloads for the L3-over-vsock control messages.
//!
//! Every message has an exact byte layout with explicit big-endian
//! encoding. There is deliberately no serde, no self-describing container,
//! and no variable-length field that is not preceded by a bounded count —
//! a generic object decoder on a path a hostile guest drives is precisely
//! what this protocol exists to avoid.

use alloc::string::String;
use alloc::vec::Vec;

use super::frame::{FrameError, MessageType};
use super::limits::{MAX_ERROR_DETAIL, MAX_QUEUES, MTU_V1, PROTOCOL_VERSION};

/// Optional capabilities a peer may propose in `HELLO` and the host may
/// grant in `CONFIG`. A bit set in `CONFIG` that was not offered in
/// `HELLO` is a protocol error; a bit offered but not granted is simply
/// off. Version 1 grants none of them.
pub mod features {
    /// Peer can handle more than one data queue.
    pub const MULTI_QUEUE: u32 = 1 << 0;
    /// Peer can handle an assigned IPv6 configuration.
    pub const IPV6: u32 = 1 << 1;
    /// Every bit this build understands. Anything outside the mask is
    /// rejected rather than ignored, so a later version cannot be
    /// smuggled past an older peer.
    pub const KNOWN: u32 = MULTI_QUEUE | IPV6;
    /// What version 1 actually grants: nothing.
    pub const GRANTED_V1: u32 = 0;
}

/// Why a session is being torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ShutdownReason {
    /// Normal machine stop.
    MachineStopping = 1,
    /// The host revoked the session (restart, restore, policy change).
    SessionInvalidated = 2,
    /// The peer violated the protocol.
    ProtocolViolation = 3,
    /// The guest is shutting its side down.
    GuestExiting = 4,
}

impl ShutdownReason {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::MachineStopping),
            2 => Some(Self::SessionInvalidated),
            3 => Some(Self::ProtocolViolation),
            4 => Some(Self::GuestExiting),
            _ => None,
        }
    }
}

/// Bounded, enumerated error codes. The free-text detail is advisory and
/// capped; consumers branch on the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// Frame or message failed validation.
    MalformedMessage = 1,
    /// The plan does not admit L3 networking for this machine.
    NotAdmitted = 2,
    /// Session id did not match the live session.
    StaleSession = 3,
    /// Host could not allocate an address or a datapath.
    ResourceUnavailable = 4,
    /// Guest could not create or configure the interface.
    GuestSetupFailed = 5,
    /// Requested features could not be granted.
    FeatureUnsupported = 6,
}

impl ErrorCode {
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::MalformedMessage),
            2 => Some(Self::NotAdmitted),
            3 => Some(Self::StaleSession),
            4 => Some(Self::ResourceUnavailable),
            5 => Some(Self::GuestSetupFailed),
            6 => Some(Self::FeatureUnsupported),
            _ => None,
        }
    }
}

/// guest→host handshake. Carries no machine identity: the host derives
/// that from which per-VM listener the connection arrived on, never from
/// anything the guest says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub features: u32,
    pub max_queues: u16,
}

/// Wire size of [`Hello`].
pub const HELLO_LEN: usize = 1 + 4 + 2;

impl Hello {
    /// What a version-1 guest proposes.
    pub fn v1() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            features: 0,
            max_queues: 1,
        }
    }

    pub fn encode(&self) -> [u8; HELLO_LEN] {
        let mut out = [0u8; HELLO_LEN];
        out[0] = self.version;
        out[1..5].copy_from_slice(&self.features.to_be_bytes());
        out[5..7].copy_from_slice(&self.max_queues.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        let buf = exact(buf, HELLO_LEN, MessageType::Hello)?;
        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(MessageError::Frame(FrameError::UnsupportedVersion {
                got: version,
                want: PROTOCOL_VERSION,
            }));
        }
        let features = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if features & !features::KNOWN != 0 {
            return Err(MessageError::UnknownFeatureBits(
                features & !features::KNOWN,
            ));
        }
        let max_queues = u16::from_be_bytes([buf[5], buf[6]]);
        if max_queues == 0 || max_queues > MAX_QUEUES {
            return Err(MessageError::QueueCountOutOfRange(max_queues));
        }
        Ok(Self {
            version,
            features,
            max_queues,
        })
    }
}

/// An assigned IPv4 configuration. All addresses are host-chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Config {
    pub address: [u8; 4],
    pub prefix_len: u8,
    /// Point-to-point peer, which is also the synthetic gateway.
    pub peer: [u8; 4],
    /// Synthetic resolver the guest must use.
    pub dns: [u8; 4],
}

/// An assigned IPv6 configuration. Reserved: version 1 never assigns one,
/// because the workload kernel ships without IPv6. The layout exists so
/// enabling it later needs no wire change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Config {
    pub address: [u8; 16],
    pub prefix_len: u8,
    pub peer: [u8; 16],
    pub dns: [u8; 16],
}

/// host→guest assignment. The guest applies this verbatim; it never picks
/// its own address, gateway, resolver, or routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub v4: Option<Ipv4Config>,
    pub v6: Option<Ipv6Config>,
    pub mtu: u16,
    pub queue_count: u16,
    pub features: u32,
    pub policy_epoch: u64,
}

/// Wire size of [`Config`]: fixed, so decoding cannot be steered into a
/// large allocation. Unused address families are zeroed, not omitted.
pub const CONFIG_LEN: usize = 1 + 4 + 1 + 4 + 4 + 1 + 16 + 1 + 16 + 16 + 2 + 2 + 4 + 8;

impl Config {
    pub fn encode(&self) -> [u8; CONFIG_LEN] {
        let mut out = [0u8; CONFIG_LEN];
        let mut i = 0;
        match &self.v4 {
            Some(v4) => {
                out[i] = 1;
                out[i + 1..i + 5].copy_from_slice(&v4.address);
                out[i + 5] = v4.prefix_len;
                out[i + 6..i + 10].copy_from_slice(&v4.peer);
                out[i + 10..i + 14].copy_from_slice(&v4.dns);
            }
            None => out[i] = 0,
        }
        i += 14;
        match &self.v6 {
            Some(v6) => {
                out[i] = 1;
                out[i + 1..i + 17].copy_from_slice(&v6.address);
                out[i + 17] = v6.prefix_len;
                out[i + 18..i + 34].copy_from_slice(&v6.peer);
                out[i + 34..i + 50].copy_from_slice(&v6.dns);
            }
            None => out[i] = 0,
        }
        i += 50;
        out[i..i + 2].copy_from_slice(&self.mtu.to_be_bytes());
        out[i + 2..i + 4].copy_from_slice(&self.queue_count.to_be_bytes());
        out[i + 4..i + 8].copy_from_slice(&self.features.to_be_bytes());
        out[i + 8..i + 16].copy_from_slice(&self.policy_epoch.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        let buf = exact(buf, CONFIG_LEN, MessageType::Config)?;
        let mut i = 0;
        let v4 = match buf[i] {
            0 => None,
            1 => Some(Ipv4Config {
                address: [buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]],
                prefix_len: buf[i + 5],
                peer: [buf[i + 6], buf[i + 7], buf[i + 8], buf[i + 9]],
                dns: [buf[i + 10], buf[i + 11], buf[i + 12], buf[i + 13]],
            }),
            other => return Err(MessageError::InvalidPresenceFlag(other)),
        };
        i += 14;
        let v6 = match buf[i] {
            0 => None,
            1 => {
                let mut address = [0u8; 16];
                address.copy_from_slice(&buf[i + 1..i + 17]);
                let prefix_len = buf[i + 17];
                let mut peer = [0u8; 16];
                peer.copy_from_slice(&buf[i + 18..i + 34]);
                let mut dns = [0u8; 16];
                dns.copy_from_slice(&buf[i + 34..i + 50]);
                Some(Ipv6Config {
                    address,
                    prefix_len,
                    peer,
                    dns,
                })
            }
            other => return Err(MessageError::InvalidPresenceFlag(other)),
        };
        i += 50;
        let mtu = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let queue_count = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);
        let features = u32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        let policy_epoch = u64::from_be_bytes([
            buf[i + 8],
            buf[i + 9],
            buf[i + 10],
            buf[i + 11],
            buf[i + 12],
            buf[i + 13],
            buf[i + 14],
            buf[i + 15],
        ]);

        if v4.is_none() && v6.is_none() {
            return Err(MessageError::ConfigAssignsNoAddress);
        }
        if mtu != MTU_V1 {
            return Err(MessageError::UnsupportedMtu(mtu));
        }
        if queue_count == 0 || queue_count > MAX_QUEUES {
            return Err(MessageError::QueueCountOutOfRange(queue_count));
        }
        if features & !features::KNOWN != 0 {
            return Err(MessageError::UnknownFeatureBits(
                features & !features::KNOWN,
            ));
        }
        if let Some(v4) = &v4
            && (v4.prefix_len > 32)
        {
            return Err(MessageError::InvalidPrefixLen(v4.prefix_len));
        }
        if let Some(v6) = &v6
            && (v6.prefix_len > 128)
        {
            return Err(MessageError::InvalidPrefixLen(v6.prefix_len));
        }
        Ok(Self {
            v4,
            v6,
            mtu,
            queue_count,
            features,
            policy_epoch,
        })
    }
}

/// guest→host: the interface is configured and packets may flow. Echoes
/// the epoch and MTU so a mismatch surfaces as a refusal instead of a
/// silently divergent view of the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ready {
    pub policy_epoch: u64,
    pub mtu: u16,
    /// Set when the guest managed to point the system resolver at the
    /// assigned address. A read-only `/etc/resolv.conf` leaves it clear;
    /// the tunnel still works, applications that read the file do not.
    pub resolver_configured: bool,
}

/// Wire size of [`Ready`].
pub const READY_LEN: usize = 8 + 2 + 1;

impl Ready {
    pub fn encode(&self) -> [u8; READY_LEN] {
        let mut out = [0u8; READY_LEN];
        out[0..8].copy_from_slice(&self.policy_epoch.to_be_bytes());
        out[8..10].copy_from_slice(&self.mtu.to_be_bytes());
        out[10] = u8::from(self.resolver_configured);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        let buf = exact(buf, READY_LEN, MessageType::Ready)?;
        let policy_epoch = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let mtu = u16::from_be_bytes([buf[8], buf[9]]);
        let resolver_configured = match buf[10] {
            0 => false,
            1 => true,
            other => return Err(MessageError::InvalidPresenceFlag(other)),
        };
        Ok(Self {
            policy_epoch,
            mtu,
            resolver_configured,
        })
    }
}

/// Liveness. The counter is monotonic per direction so a peer can tell a
/// stalled sender from a quiet one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    pub counter: u64,
}

/// Wire size of [`Heartbeat`].
pub const HEARTBEAT_LEN: usize = 8;

impl Heartbeat {
    pub fn encode(&self) -> [u8; HEARTBEAT_LEN] {
        self.counter.to_be_bytes()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        let buf = exact(buf, HEARTBEAT_LEN, MessageType::Heartbeat)?;
        Ok(Self {
            counter: u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
        })
    }
}

/// Orderly teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shutdown {
    pub reason: ShutdownReason,
}

/// Wire size of [`Shutdown`].
pub const SHUTDOWN_LEN: usize = 2;

impl Shutdown {
    pub fn encode(&self) -> [u8; SHUTDOWN_LEN] {
        self.reason.as_u16().to_be_bytes()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        let buf = exact(buf, SHUTDOWN_LEN, MessageType::Shutdown)?;
        let raw = u16::from_be_bytes([buf[0], buf[1]]);
        let reason =
            ShutdownReason::from_u16(raw).ok_or(MessageError::UnknownShutdownReason(raw))?;
        Ok(Self { reason })
    }
}

/// Bounded error report. `detail` is advisory ASCII, capped at
/// [`MAX_ERROR_DETAIL`] bytes; consumers must branch on `code`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    pub code: ErrorCode,
    pub detail: String,
}

impl ErrorMessage {
    /// Build an error, truncating the detail on a character boundary so
    /// the cap holds regardless of what the caller passes.
    pub fn new(code: ErrorCode, detail: &str) -> Self {
        let mut end = detail.len().min(MAX_ERROR_DETAIL);
        while end > 0 && !detail.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            code,
            detail: String::from(&detail[..end]),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let detail = self.detail.as_bytes();
        let len = detail.len().min(MAX_ERROR_DETAIL);
        let mut out = Vec::with_capacity(3 + len);
        out.extend_from_slice(&self.code.as_u16().to_be_bytes());
        out.push(len as u8);
        out.extend_from_slice(&detail[..len]);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MessageError> {
        if buf.len() < 3 {
            return Err(MessageError::WrongLength {
                msg_type: MessageType::Error,
                expected: 3,
                got: buf.len(),
            });
        }
        let raw = u16::from_be_bytes([buf[0], buf[1]]);
        let code = ErrorCode::from_u16(raw).ok_or(MessageError::UnknownErrorCode(raw))?;
        let len = buf[2] as usize;
        if len > MAX_ERROR_DETAIL {
            return Err(MessageError::DetailTooLong(len));
        }
        if buf.len() != 3 + len {
            return Err(MessageError::WrongLength {
                msg_type: MessageType::Error,
                expected: 3 + len,
                got: buf.len(),
            });
        }
        let detail = core::str::from_utf8(&buf[3..3 + len])
            .map_err(|_| MessageError::DetailNotUtf8)?
            .into();
        Ok(Self { code, detail })
    }
}

/// Why a message payload was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// Outer framing rejected it first.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// A fixed-layout message had the wrong payload size.
    #[error("{msg_type:?} payload must be {expected} bytes, got {got}")]
    WrongLength {
        msg_type: MessageType,
        expected: usize,
        got: usize,
    },
    /// A presence/boolean byte was neither 0 nor 1.
    #[error("presence flag must be 0 or 1, got {0}")]
    InvalidPresenceFlag(u8),
    /// `CONFIG` assigned neither an IPv4 nor an IPv6 address.
    #[error("config assigns no address")]
    ConfigAssignsNoAddress,
    /// `CONFIG` named an MTU version 1 does not offer.
    #[error("unsupported mtu {0}")]
    UnsupportedMtu(u16),
    /// Queue count was zero or above the protocol ceiling.
    #[error("queue count {0} out of range")]
    QueueCountOutOfRange(u16),
    /// Feature bits outside [`features::KNOWN`].
    #[error("unknown feature bits {0:#010x}")]
    UnknownFeatureBits(u32),
    /// Prefix length exceeded the address family's width.
    #[error("invalid prefix length {0}")]
    InvalidPrefixLen(u8),
    /// `SHUTDOWN` carried an unrecognized reason.
    #[error("unknown shutdown reason {0}")]
    UnknownShutdownReason(u16),
    /// `ERROR` carried an unrecognized code.
    #[error("unknown error code {0}")]
    UnknownErrorCode(u16),
    /// `ERROR` detail exceeded [`MAX_ERROR_DETAIL`].
    #[error("error detail of {0} bytes exceeds the cap")]
    DetailTooLong(usize),
    /// `ERROR` detail was not valid UTF-8.
    #[error("error detail is not valid utf-8")]
    DetailNotUtf8,
}

/// Assert an exact payload length before any field is read.
fn exact(buf: &[u8], expected: usize, msg_type: MessageType) -> Result<&[u8], MessageError> {
    if buf.len() != expected {
        return Err(MessageError::WrongLength {
            msg_type,
            expected,
            got: buf.len(),
        });
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn v4_config() -> Config {
        Config {
            v4: Some(Ipv4Config {
                address: [10, 201, 0, 2],
                prefix_len: 30,
                peer: [10, 201, 0, 1],
                dns: [10, 201, 0, 1],
            }),
            v6: None,
            mtu: MTU_V1,
            queue_count: 1,
            features: features::GRANTED_V1,
            policy_epoch: 42,
        }
    }

    #[test]
    fn hello_roundtrips() {
        let hello = Hello::v1();
        assert_eq!(Hello::decode(&hello.encode()).unwrap(), hello);
    }

    #[test]
    fn hello_rejects_a_wrong_length_payload() {
        assert!(matches!(
            Hello::decode(&[0u8; HELLO_LEN - 1]),
            Err(MessageError::WrongLength { .. })
        ));
        assert!(matches!(
            Hello::decode(&[0u8; HELLO_LEN + 1]),
            Err(MessageError::WrongLength { .. })
        ));
    }

    #[test]
    fn hello_rejects_a_foreign_major_version() {
        let mut hello = Hello::v1();
        hello.version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            Hello::decode(&hello.encode()),
            Err(MessageError::Frame(FrameError::UnsupportedVersion { .. }))
        ));
    }

    #[test]
    fn hello_rejects_unknown_feature_bits() {
        let hello = Hello {
            version: PROTOCOL_VERSION,
            features: 1 << 30,
            max_queues: 1,
        };
        assert!(matches!(
            Hello::decode(&hello.encode()),
            Err(MessageError::UnknownFeatureBits(_))
        ));
    }

    #[test]
    fn hello_rejects_a_zero_or_oversized_queue_request() {
        for queues in [0, MAX_QUEUES + 1] {
            let hello = Hello {
                version: PROTOCOL_VERSION,
                features: 0,
                max_queues: queues,
            };
            assert!(matches!(
                Hello::decode(&hello.encode()),
                Err(MessageError::QueueCountOutOfRange(_))
            ));
        }
    }

    #[test]
    fn config_roundtrips_v4_only() {
        let cfg = v4_config();
        assert_eq!(Config::decode(&cfg.encode()).unwrap(), cfg);
    }

    #[test]
    fn config_roundtrips_a_dual_stack_assignment() {
        let mut cfg = v4_config();
        cfg.v6 = Some(Ipv6Config {
            address: [0x20; 16],
            prefix_len: 127,
            peer: [0x21; 16],
            dns: [0x22; 16],
        });
        cfg.features = features::IPV6;
        assert_eq!(Config::decode(&cfg.encode()).unwrap(), cfg);
    }

    #[test]
    fn config_has_a_fixed_wire_size() {
        assert_eq!(v4_config().encode().len(), CONFIG_LEN);
        let mut cfg = v4_config();
        cfg.v6 = Some(Ipv6Config {
            address: [1; 16],
            prefix_len: 64,
            peer: [2; 16],
            dns: [3; 16],
        });
        cfg.features = features::IPV6;
        assert_eq!(cfg.encode().len(), CONFIG_LEN);
    }

    #[test]
    fn config_must_assign_at_least_one_address() {
        let mut cfg = v4_config();
        cfg.v4 = None;
        assert!(matches!(
            Config::decode(&cfg.encode()),
            Err(MessageError::ConfigAssignsNoAddress)
        ));
    }

    #[test]
    fn config_rejects_a_foreign_mtu() {
        let mut cfg = v4_config();
        cfg.mtu = 9000;
        assert!(matches!(
            Config::decode(&cfg.encode()),
            Err(MessageError::UnsupportedMtu(9000))
        ));
    }

    #[test]
    fn config_rejects_an_out_of_range_prefix() {
        let mut cfg = v4_config();
        cfg.v4.as_mut().unwrap().prefix_len = 33;
        assert!(matches!(
            Config::decode(&cfg.encode()),
            Err(MessageError::InvalidPrefixLen(33))
        ));
    }

    #[test]
    fn config_rejects_a_non_boolean_presence_flag() {
        let mut bytes = v4_config().encode();
        bytes[0] = 2;
        assert!(matches!(
            Config::decode(&bytes),
            Err(MessageError::InvalidPresenceFlag(2))
        ));
    }

    #[test]
    fn ready_roundtrips() {
        for resolver_configured in [false, true] {
            let ready = Ready {
                policy_epoch: 7,
                mtu: MTU_V1,
                resolver_configured,
            };
            assert_eq!(Ready::decode(&ready.encode()).unwrap(), ready);
        }
    }

    #[test]
    fn heartbeat_roundtrips() {
        let hb = Heartbeat { counter: u64::MAX };
        assert_eq!(Heartbeat::decode(&hb.encode()).unwrap(), hb);
    }

    #[test]
    fn shutdown_roundtrips_every_reason() {
        for reason in [
            ShutdownReason::MachineStopping,
            ShutdownReason::SessionInvalidated,
            ShutdownReason::ProtocolViolation,
            ShutdownReason::GuestExiting,
        ] {
            let msg = Shutdown { reason };
            assert_eq!(Shutdown::decode(&msg.encode()).unwrap(), msg);
        }
    }

    #[test]
    fn shutdown_rejects_an_unknown_reason() {
        assert!(matches!(
            Shutdown::decode(&99u16.to_be_bytes()),
            Err(MessageError::UnknownShutdownReason(99))
        ));
    }

    #[test]
    fn error_roundtrips_and_truncates_a_long_detail() {
        let long = "x".repeat(MAX_ERROR_DETAIL * 3);
        let msg = ErrorMessage::new(ErrorCode::StaleSession, &long);
        assert_eq!(msg.detail.len(), MAX_ERROR_DETAIL);
        assert_eq!(ErrorMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn error_truncation_respects_char_boundaries() {
        // Multi-byte characters straddling the cap must not produce
        // invalid UTF-8 on the wire.
        let long = "é".repeat(MAX_ERROR_DETAIL);
        let msg = ErrorMessage::new(ErrorCode::MalformedMessage, &long);
        assert!(msg.detail.len() <= MAX_ERROR_DETAIL);
        assert_eq!(ErrorMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn error_rejects_a_declared_length_that_overruns_the_payload() {
        let mut bytes = ErrorMessage::new(ErrorCode::NotAdmitted, "short").encode();
        bytes[2] = 200;
        assert!(matches!(
            ErrorMessage::decode(&bytes),
            Err(MessageError::DetailTooLong(200))
        ));
    }

    #[test]
    fn error_rejects_a_length_that_disagrees_with_the_payload() {
        let mut bytes = ErrorMessage::new(ErrorCode::NotAdmitted, "short").encode();
        bytes[2] = 4;
        assert!(matches!(
            ErrorMessage::decode(&bytes),
            Err(MessageError::WrongLength { .. })
        ));
    }

    #[test]
    fn error_rejects_an_unknown_code() {
        let mut bytes = vec![0u8; 3];
        bytes[0..2].copy_from_slice(&4242u16.to_be_bytes());
        assert!(matches!(
            ErrorMessage::decode(&bytes),
            Err(MessageError::UnknownErrorCode(4242))
        ));
    }

    #[test]
    fn version_one_grants_no_features() {
        assert_eq!(features::GRANTED_V1, 0);
    }

    #[test]
    fn arbitrary_payloads_never_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 0..200usize {
            let mut buf = vec![0u8; len];
            for byte in buf.iter_mut() {
                *byte = (next() & 0xff) as u8;
            }
            let _ = Hello::decode(&buf);
            let _ = Config::decode(&buf);
            let _ = Ready::decode(&buf);
            let _ = Heartbeat::decode(&buf);
            let _ = Shutdown::decode(&buf);
            let _ = ErrorMessage::decode(&buf);
        }
    }
}
