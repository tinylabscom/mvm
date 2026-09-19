//! Authenticated request used when a paused first-party VMM becomes a claimed child.

use serde::{Deserialize, Serialize};

/// Host request that authorizes a paused parent to become a claimed child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfHandoffRequest {
    /// Registry-safe child VM name; all channel paths are derived from it.
    pub child_vm_name: String,
    /// PID of the paused parent supervisor, bound into the authorization.
    pub parent_pid: u32,
    /// Presence bits for authorized child channels; paths remain supervisor-derived.
    pub channel_mask: u8,
    /// Ed25519 signature over the protocol domain, parent PID, and child name.
    pub signature: String,
}

/// Domain separator for the host-authorized live handoff signature.
pub const HVF_HANDOFF_PROTOCOL_DOMAIN: &[u8] = b"mvm-hvf-live-handoff-v1";

/// The parent's reply to a handoff that took: exactly this line.
pub const HANDOFF_ACCEPTED: &[u8] = b"OK\n";

/// Dedicated telemetry authorization bit in a signed handoff channel mask.
pub const HANDOFF_TELEMETRY: u8 = 1 << 4;
/// Channel-mask bit for the guest-to-host view-only display relay.
pub const HANDOFF_DISPLAY: u8 = 1 << 5;

/// Longest reply line either side of the handoff socket will handle, newline
/// included. The parent writes within it and the host reads no further, so an
/// unterminated reply cannot hold a claim open.
pub const HANDOFF_RESPONSE_MAX_BYTES: usize = 512;

/// The parent's reply to a handoff it refused: `ERR <reason>`, on one line.
///
/// The reason is the whole point. The parent is a paused process nobody can
/// attach to, and this line is the only account of what it refused — a bare
/// `ERR` left a failed claim reading `rejected live handoff: ERR` and nothing
/// more. Control characters are flattened so the reason cannot end the line
/// early, and it is cut on a character boundary to fit the bound.
pub fn refusal_line(reason: &str) -> Vec<u8> {
    const PREFIX: &str = "ERR ";
    let budget = HANDOFF_RESPONSE_MAX_BYTES - PREFIX.len() - 1;
    let mut line = String::with_capacity(HANDOFF_RESPONSE_MAX_BYTES);
    line.push_str(PREFIX);
    for ch in reason.chars().map(|c| if c.is_control() { ' ' } else { c }) {
        if line.len() - PREFIX.len() + ch.len_utf8() > budget {
            break;
        }
        line.push(ch);
    }
    line.push('\n');
    line.into_bytes()
}

impl HvfHandoffRequest {
    /// Build the canonical bytes signed by the host identity for one claim.
    pub fn signing_message(parent_pid: u32, child_vm_name: &str, channel_mask: u8) -> Vec<u8> {
        let name = child_vm_name.as_bytes();
        let name_len = u32::try_from(name.len()).expect("VM name fits protocol length");
        let mut message =
            Vec::with_capacity(HVF_HANDOFF_PROTOCOL_DOMAIN.len() + 4 + 4 + 1 + name.len());
        message.extend_from_slice(HVF_HANDOFF_PROTOCOL_DOMAIN);
        message.extend_from_slice(&parent_pid.to_be_bytes());
        message.push(channel_mask);
        message.extend_from_slice(&name_len.to_be_bytes());
        message.extend_from_slice(name);
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_carries_its_reason_on_one_line() {
        assert_eq!(
            refusal_line("handoff signature rejected"),
            b"ERR handoff signature rejected\n"
        );
    }

    #[test]
    fn a_reason_containing_a_newline_cannot_end_the_line_early() {
        let line = refusal_line("first\nsecond\r");
        assert_eq!(line, b"ERR first second \n");
        assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn a_long_reason_is_cut_to_the_bound_on_a_character_boundary() {
        let line = refusal_line(&"é".repeat(HANDOFF_RESPONSE_MAX_BYTES));
        assert!(line.len() <= HANDOFF_RESPONSE_MAX_BYTES);
        assert_eq!(line.last(), Some(&b'\n'));
        assert!(std::str::from_utf8(&line).is_ok(), "cut mid-character");
    }

    #[test]
    fn a_refusal_is_never_mistaken_for_acceptance() {
        assert_ne!(refusal_line(""), HANDOFF_ACCEPTED);
        assert_ne!(refusal_line("OK"), HANDOFF_ACCEPTED);
    }
}
