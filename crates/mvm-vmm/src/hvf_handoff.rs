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
