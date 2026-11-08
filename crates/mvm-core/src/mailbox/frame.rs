//! The one-frame mailbox exchange both ends of the mailbox port share.
//!
//! The guest writes a length-prefixed frame (a capability and a sealed
//! envelope) and reads one typed verdict; the host service parses the frame
//! with [`decode_frame`] and answers with a serialized `Result<(), Refusal>`.
//! Keeping both directions here means the guest and the host cannot drift.
//!
//! Frame: `u32 BE length`, then `u32 BE capability length`, the capability as
//! JSON, and the envelope in its canonical `encode_envelope` form.

use std::io::{Read, Write};

use mvm_contract::protocol::mailbox::{MailboxEnvelope, SignedMailboxCapability};
use serde::{Deserialize, Serialize};

use super::{decode_envelope, encode_envelope};

/// Why a frame was not queued. Sent back to the peer verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum Refusal {
    #[error("frame exceeds the {0}-byte limit")]
    Oversized(usize),
    #[error("mailbox queue is full ({0} messages)")]
    QueueFull(usize),
    #[error("frame is malformed")]
    Malformed,
    /// The mailbox gate refused it; carries the gate's own reason text.
    #[error("{0}")]
    Mailbox(String),
}

/// The frame body (without its outer length prefix).
pub fn encode_frame(
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<Vec<u8>, Refusal> {
    let cap = serde_json::to_vec(capability).map_err(|_| Refusal::Malformed)?;
    let env = encode_envelope(envelope).map_err(|e| Refusal::Mailbox(e.to_string()))?;
    let mut body = (cap.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(&cap);
    body.extend_from_slice(&env);
    Ok(body)
}

/// Split a frame body back into its capability and envelope.
pub fn decode_frame(body: &[u8]) -> Result<(SignedMailboxCapability, MailboxEnvelope), Refusal> {
    let (len, rest) = body.split_at_checked(4).ok_or(Refusal::Malformed)?;
    let cap_len = u32::from_be_bytes(len.try_into().map_err(|_| Refusal::Malformed)?) as usize;
    let (cap, env) = rest.split_at_checked(cap_len).ok_or(Refusal::Malformed)?;
    Ok((
        serde_json::from_slice(cap).map_err(|_| Refusal::Malformed)?,
        decode_envelope(env).map_err(|_| Refusal::Malformed)?,
    ))
}

/// Guest side: write one frame on `stream` and read the service's verdict.
/// The caller sets any timeouts on the stream.
pub fn send_frame<S: Read + Write>(
    stream: &mut S,
    capability: &SignedMailboxCapability,
    envelope: &MailboxEnvelope,
) -> Result<(), Refusal> {
    let body = encode_frame(capability, envelope)?;
    // A service that refuses on length alone closes early; the verdict is
    // still readable, so a failed write is not itself the answer.
    let _ = stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(&body));
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .map_err(|_| Refusal::Malformed)?;
    serde_json::from_slice::<Result<(), Refusal>>(&reply).map_err(|_| Refusal::Malformed)?
}
