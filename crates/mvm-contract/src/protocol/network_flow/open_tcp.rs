//! Validate the destination of a guest TCP flow before egress admission.

use core::fmt;

/// The longest `host:port` an `OpenTcp` may name.
pub const MAX_OPEN_TCP_TARGET_LEN: usize = 256;

/// Why an `OpenTcp` destination was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenTcpPayloadError {
    Length,
    TargetEncoding,
    LegacyBinding,
}

impl fmt::Display for OpenTcpPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Length => "OpenTcp target missing or too long",
            Self::TargetEncoding => "OpenTcp target is not UTF-8",
            Self::LegacyBinding => "tool invocation bindings are not supported",
        })
    }
}

/// Decode only a plain `host:port`; the retired binding suffix cannot grant access.
pub fn decode_open_tcp(payload: &[u8]) -> Result<&str, OpenTcpPayloadError> {
    if payload.contains(&0) {
        return Err(OpenTcpPayloadError::LegacyBinding);
    }
    if payload.is_empty() || payload.len() > MAX_OPEN_TCP_TARGET_LEN {
        return Err(OpenTcpPayloadError::Length);
    }
    core::str::from_utf8(payload).map_err(|_| OpenTcpPayloadError::TargetEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_target_round_trips_and_legacy_binding_refuses() {
        assert_eq!(decode_open_tcp(b"example.com:443"), Ok("example.com:443"));
        assert_eq!(
            decode_open_tcp(b"example.com:443\0abababababababababababababababab"),
            Err(OpenTcpPayloadError::LegacyBinding)
        );
    }

    #[test]
    fn invalid_targets_refuse_before_any_network_decision() {
        assert_eq!(decode_open_tcp(b""), Err(OpenTcpPayloadError::Length));
        assert_eq!(
            decode_open_tcp(&[b'a'; MAX_OPEN_TCP_TARGET_LEN + 1]),
            Err(OpenTcpPayloadError::Length)
        );
        assert_eq!(
            decode_open_tcp(b"\xff:1"),
            Err(OpenTcpPayloadError::TargetEncoding)
        );
    }
}
