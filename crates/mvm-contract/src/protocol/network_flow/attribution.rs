//! Attributing a guest flow to an admitted tool invocation.
//!
//! When the host admits a declared tool invocation whose tool owns routes or
//! secrets, it mints an opaque binding for that invocation. The guest agent
//! starts the command in a session of its own and answers, for each loopback
//! connection the egress client accepts, whether every process holding the
//! client socket is in that session. Only then does the egress client name the
//! binding in the flow's `OpenTcp`. The endpoint maps the binding back to the
//! tool and decides the tool's routes and secrets against it; a flow without a
//! binding it recognises is attributed to no tool.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Hex digits in a binding: 128 random bits.
pub const BINDING_HEX_LEN: usize = 32;
/// The longest `host:port` an `OpenTcp` may name.
pub const MAX_OPEN_TCP_TARGET_LEN: usize = 256;
/// Separates the target from the binding in an attributed `OpenTcp`. A target
/// never contains it, so an unattributed payload stays exactly the target.
const BINDING_SEPARATOR: u8 = 0;
/// The longest `OpenTcp` payload: a target, the separator, and a binding.
pub const MAX_OPEN_TCP_PAYLOAD_LEN: usize = MAX_OPEN_TCP_TARGET_LEN + 1 + BINDING_HEX_LEN;

/// The host-minted identity of one admitted tool invocation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ToolInvocationBinding(String);

impl ToolInvocationBinding {
    /// Encode 128 random bits as a binding.
    #[must_use]
    pub fn from_random(bytes: [u8; 16]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(BINDING_HEX_LEN);
        for byte in bytes {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self(text)
    }

    /// Parse a binding: exactly 32 lowercase hex digits.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        (text.len() == BINDING_HEX_LEN
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then(|| Self(String::from(text)))
    }

    /// The binding's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// What the audit log records for this binding: the first 64 bits of its
    /// SHA-256, in hex. The binding itself is a capability for as long as it
    /// is live, so the log carries an identifier that correlates entries
    /// without being usable as one.
    #[must_use]
    pub fn audit_id(&self) -> String {
        use sha2::{Digest, Sha256};
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let digest = Sha256::digest(self.0.as_bytes());
        let mut id = String::with_capacity(16);
        for byte in &digest[..8] {
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        id
    }
}

impl fmt::Debug for ToolInvocationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ToolInvocationBinding")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ToolInvocationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for ToolInvocationBinding {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).ok_or("a tool invocation binding is 32 lowercase hex digits")
    }
}

impl From<ToolInvocationBinding> for String {
    fn from(binding: ToolInvocationBinding) -> Self {
        binding.0
    }
}

/// Why an `OpenTcp` payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenTcpPayloadError {
    /// No target, or longer than [`MAX_OPEN_TCP_PAYLOAD_LEN`].
    Length,
    /// The target is not UTF-8.
    TargetEncoding,
    /// Bytes followed the separator that are not a binding.
    Binding,
}

impl fmt::Display for OpenTcpPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Length => "OpenTcp target missing or too long",
            Self::TargetEncoding => "OpenTcp target is not UTF-8",
            Self::Binding => "OpenTcp carries a malformed invocation binding",
        })
    }
}

/// Encode an `OpenTcp` payload: the target, then the binding when the flow is
/// attributed to an invocation.
#[must_use]
pub fn encode_open_tcp(target: &str, binding: Option<&ToolInvocationBinding>) -> Vec<u8> {
    let mut payload = Vec::from(target.as_bytes());
    if let Some(binding) = binding {
        payload.push(BINDING_SEPARATOR);
        payload.extend_from_slice(binding.as_str().as_bytes());
    }
    payload
}

/// Decode an `OpenTcp` payload into its target and optional binding.
pub fn decode_open_tcp(
    payload: &[u8],
) -> Result<(&str, Option<ToolInvocationBinding>), OpenTcpPayloadError> {
    if payload.is_empty() || payload.len() > MAX_OPEN_TCP_PAYLOAD_LEN {
        return Err(OpenTcpPayloadError::Length);
    }
    let (target, binding) = match payload.iter().position(|byte| *byte == BINDING_SEPARATOR) {
        Some(at) => (&payload[..at], Some(&payload[at + 1..])),
        None => (payload, None),
    };
    if target.is_empty() || target.len() > MAX_OPEN_TCP_TARGET_LEN {
        return Err(OpenTcpPayloadError::Length);
    }
    let target = core::str::from_utf8(target).map_err(|_| OpenTcpPayloadError::TargetEncoding)?;
    let binding = match binding {
        None => None,
        Some(bytes) => Some(
            core::str::from_utf8(bytes)
                .ok()
                .and_then(ToolInvocationBinding::parse)
                .ok_or(OpenTcpPayloadError::Binding)?,
        ),
    };
    Ok((target, binding))
}

/// Host-local request that ends an invocation's binding once its command has
/// finished, so a late flow cannot claim it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInvocationRelease {
    /// The binding to retire.
    pub release: ToolInvocationBinding,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ToolInvocationBinding {
        ToolInvocationBinding::from_random([0xab; 16])
    }

    #[test]
    fn bindings_are_32_lowercase_hex_digits() {
        let binding = binding();
        assert_eq!(binding.as_str(), "ab".repeat(16));
        assert_eq!(
            ToolInvocationBinding::parse(binding.as_str()),
            Some(binding)
        );
        assert!(ToolInvocationBinding::parse(&"AB".repeat(16)).is_none());
        assert!(ToolInvocationBinding::parse(&"ab".repeat(15)).is_none());
        assert!(ToolInvocationBinding::parse(&"zz".repeat(16)).is_none());
        assert!(serde_json::from_str::<ToolInvocationBinding>("\"nope\"").is_err());
    }

    #[test]
    fn the_audit_id_is_a_short_one_way_digest() {
        let binding = binding();
        let id = binding.audit_id();
        assert_eq!(id.len(), 16);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!binding.as_str().contains(&id));
        assert_eq!(id, binding.audit_id());
        assert_ne!(id, ToolInvocationBinding::from_random([1; 16]).audit_id());
    }

    #[test]
    fn an_unattributed_payload_is_exactly_the_target() {
        let payload = encode_open_tcp("example.com:443", None);
        assert_eq!(payload, b"example.com:443");
        assert_eq!(decode_open_tcp(&payload), Ok(("example.com:443", None)));
    }

    #[test]
    fn an_attributed_payload_round_trips() {
        let payload = encode_open_tcp("example.com:443", Some(&binding()));
        assert_eq!(
            decode_open_tcp(&payload),
            Ok(("example.com:443", Some(binding())))
        );
    }

    #[test]
    fn malformed_payloads_are_refused() {
        assert_eq!(decode_open_tcp(b""), Err(OpenTcpPayloadError::Length));
        assert_eq!(
            decode_open_tcp(&[b'a'; MAX_OPEN_TCP_PAYLOAD_LEN + 1]),
            Err(OpenTcpPayloadError::Length)
        );
        assert_eq!(
            decode_open_tcp(&[b'a'; MAX_OPEN_TCP_TARGET_LEN + 1]),
            Err(OpenTcpPayloadError::Length)
        );
        assert_eq!(decode_open_tcp(b"\0abc"), Err(OpenTcpPayloadError::Length));
        assert_eq!(
            decode_open_tcp(b"\xff:1"),
            Err(OpenTcpPayloadError::TargetEncoding)
        );
        assert_eq!(
            decode_open_tcp(b"example.com:443\0not-a-binding"),
            Err(OpenTcpPayloadError::Binding)
        );
    }

    #[test]
    fn a_release_names_one_binding_and_nothing_else() {
        let release = ToolInvocationRelease { release: binding() };
        let json = serde_json::to_string(&release).expect("serialize");
        assert_eq!(
            serde_json::from_str::<ToolInvocationRelease>(&json).expect("parse"),
            release
        );
        assert!(
            serde_json::from_str::<ToolInvocationRelease>(&alloc::format!(
                r#"{{"release":"{}","extra":1}}"#,
                binding()
            ))
            .is_err()
        );
    }
}
