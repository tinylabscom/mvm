//! The guest↔host ICMP-echo wire contract.
//!
//! A NIC-less guest has no raw socket and no route, so it cannot originate an
//! ICMP echo — `ping` fails at `socket()`, before a packet exists. The guest
//! instead asks the host to echo on its behalf over the shared vsock egress
//! stream, behind the [`ICMP_FRAME_LINE`] marker, and the host answers with one
//! reply per sequence number.
//!
//! The contract lives in `mvm-core` so the in-guest client and the host handler
//! serialize the same bytes; a drifted copy on either side would break echo in a
//! way that looks like packet loss.
//!
//! Framing is one JSON value per line in each direction — the request line, then
//! a reply line per sequence. Every bound here is a cap on *untrusted guest
//! input*: the guest names how many echoes to send and how large they are, so
//! each is clamped rather than trusted, and a request outside the caps is
//! refused instead of adjusted.
//!
//! `deny_unknown_fields` fails closed on an unexpected field.

use serde::{Deserialize, Serialize};

/// Largest number of echoes one request may ask for.
pub const MAX_ECHO_COUNT: u16 = 64;
/// Largest ICMP payload one echo may carry, in bytes. `ping`'s default is 56.
pub const MAX_PAYLOAD_LEN: u16 = 1024;
/// Longest a single echo may wait for its reply, in milliseconds.
pub const MAX_TIMEOUT_MS: u32 = 10_000;
/// Cap on one wire line, so a guest cannot make the host buffer without bound.
pub const MAX_LINE_LEN: usize = 8 * 1024;

/// The guest's request to echo a host.
///
/// There is no port: ICMP has none. Admission is by host name, decided against
/// the same allow-list pins every other egress verb uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IcmpEchoRequest {
    /// Destination host name, resolved host-side against the admission pins.
    /// The guest never resolves it.
    pub host: String,
    /// How many echoes to send, `1..=MAX_ECHO_COUNT`.
    pub count: u16,
    /// ICMP payload size in bytes, `0..=MAX_PAYLOAD_LEN`.
    pub payload_len: u16,
    /// Per-echo reply timeout in milliseconds, `1..=MAX_TIMEOUT_MS`.
    pub timeout_ms: u32,
}

/// Why a request was rejected before any echo was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestBoundsError {
    /// `count` was zero or above [`MAX_ECHO_COUNT`].
    Count(u16),
    /// `payload_len` was above [`MAX_PAYLOAD_LEN`].
    PayloadLen(u16),
    /// `timeout_ms` was zero or above [`MAX_TIMEOUT_MS`].
    TimeoutMs(u32),
    /// `host` was empty or implausibly long.
    Host,
}

impl std::fmt::Display for RequestBoundsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Count(n) => write!(f, "count {n} outside 1..={MAX_ECHO_COUNT}"),
            Self::PayloadLen(n) => write!(f, "payload_len {n} above {MAX_PAYLOAD_LEN}"),
            Self::TimeoutMs(n) => write!(f, "timeout_ms {n} outside 1..={MAX_TIMEOUT_MS}"),
            Self::Host => write!(f, "host must be a non-empty name under 253 bytes"),
        }
    }
}

impl IcmpEchoRequest {
    /// Check every bound, refusing rather than clamping.
    ///
    /// Clamping would answer a request the guest did not make — a `count` of
    /// 10_000 silently becoming 64 reads as packet loss rather than as the
    /// refusal it is.
    pub fn validate(&self) -> Result<(), RequestBoundsError> {
        if self.host.is_empty() || self.host.len() > 253 {
            return Err(RequestBoundsError::Host);
        }
        if self.count == 0 || self.count > MAX_ECHO_COUNT {
            return Err(RequestBoundsError::Count(self.count));
        }
        if self.payload_len > MAX_PAYLOAD_LEN {
            return Err(RequestBoundsError::PayloadLen(self.payload_len));
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(RequestBoundsError::TimeoutMs(self.timeout_ms));
        }
        Ok(())
    }
}

/// One line of the host's answer.
///
/// `Refused` is terminal and carries the policy reason; `Reply` and `Timeout`
/// repeat once per sequence number until `count` is exhausted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum IcmpEchoReply {
    /// An echo reply came back.
    Reply {
        /// Sequence number, from zero.
        seq: u16,
        /// The pinned address the host echoed, as a string.
        ip: String,
        /// How long the host's own leg took, in microseconds: the time from the
        /// host writing the echo to reading its reply. The guest measures its
        /// own end-to-end time separately; reporting both keeps the vsock and
        /// mediation overhead visible rather than folded into one number.
        host_leg_us: u64,
        /// Payload bytes echoed back.
        payload_len: u16,
    },
    /// No reply within `timeout_ms`.
    Timeout {
        /// Sequence number, from zero.
        seq: u16,
    },
    /// The request was refused; no echo was sent. Terminal.
    Refused {
        /// Policy or bounds reason, safe to show the guest.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> IcmpEchoRequest {
        IcmpEchoRequest {
            host: "example.com".into(),
            count: 3,
            payload_len: 56,
            timeout_ms: 1000,
        }
    }

    #[test]
    fn request_roundtrips() {
        let json = serde_json::to_string(&valid()).unwrap();
        assert_eq!(
            serde_json::from_str::<IcmpEchoRequest>(&json).unwrap(),
            valid()
        );
    }

    #[test]
    fn reply_variants_roundtrip() {
        for reply in [
            IcmpEchoReply::Reply {
                seq: 0,
                ip: "93.184.216.34".into(),
                host_leg_us: 9_800,
                payload_len: 56,
            },
            IcmpEchoReply::Timeout { seq: 2 },
            IcmpEchoReply::Refused {
                message: "example.com is not admitted".into(),
            },
        ] {
            let json = serde_json::to_string(&reply).unwrap();
            assert_eq!(serde_json::from_str::<IcmpEchoReply>(&json).unwrap(), reply);
        }
    }

    #[test]
    fn unknown_field_is_refused() {
        let json = r#"{"host":"a.test","count":1,"payload_len":0,"timeout_ms":1,"extra":true}"#;
        assert!(serde_json::from_str::<IcmpEchoRequest>(json).is_err());
    }

    /// Each bound refuses rather than clamps, so a guest asking for more than
    /// the cap gets an answer that says so.
    #[test]
    fn bounds_refuse_out_of_range_requests() {
        assert_eq!(valid().validate(), Ok(()));

        let mut zero_count = valid();
        zero_count.count = 0;
        assert_eq!(zero_count.validate(), Err(RequestBoundsError::Count(0)));

        let mut too_many = valid();
        too_many.count = MAX_ECHO_COUNT + 1;
        assert_eq!(
            too_many.validate(),
            Err(RequestBoundsError::Count(MAX_ECHO_COUNT + 1))
        );

        let mut huge_payload = valid();
        huge_payload.payload_len = MAX_PAYLOAD_LEN + 1;
        assert_eq!(
            huge_payload.validate(),
            Err(RequestBoundsError::PayloadLen(MAX_PAYLOAD_LEN + 1))
        );

        let mut forever = valid();
        forever.timeout_ms = MAX_TIMEOUT_MS + 1;
        assert_eq!(
            forever.validate(),
            Err(RequestBoundsError::TimeoutMs(MAX_TIMEOUT_MS + 1))
        );

        let mut no_host = valid();
        no_host.host = String::new();
        assert_eq!(no_host.validate(), Err(RequestBoundsError::Host));

        let mut long_host = valid();
        long_host.host = "a".repeat(254);
        assert_eq!(long_host.validate(), Err(RequestBoundsError::Host));
    }

    /// The boundary values themselves are admitted — an off-by-one here would
    /// refuse a legitimate `ping -c 64`.
    #[test]
    fn bounds_admit_their_endpoints() {
        let mut at_cap = valid();
        at_cap.count = MAX_ECHO_COUNT;
        at_cap.payload_len = MAX_PAYLOAD_LEN;
        at_cap.timeout_ms = MAX_TIMEOUT_MS;
        assert_eq!(at_cap.validate(), Ok(()));

        let mut empty_payload = valid();
        empty_payload.payload_len = 0;
        assert_eq!(empty_payload.validate(), Ok(()));
    }
}
