//! Workload calls through the existing mailbox reader handoff, never the broker.

use std::path::Path;
use std::time::{Duration, Instant};

use mvm_core::mailbox::conversation_wire::{
    ConversationInvocation, ConversationRequest, ConversationResponse, MAX_FRAME_BYTES,
    read_local_response, write_local_request,
};
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::reader_wire::GUEST_READER_SOCKET_PATH;

/// Parse one FFI request without logging or returning payload-derived parse errors.
pub fn parse_request(method: &str, bytes: &[u8]) -> Result<ConversationRequest, Refusal> {
    let operation = match method {
        "host.mailbox.call" => "call",
        "host.mailbox.receive" => "receive",
        "host.mailbox.reply" => "reply",
        "host.mailbox.receive_result" => "receive_result",
        "host.mailbox.ack_result" => "ack_result",
        "host.mailbox.ack_request" => "ack_request",
        _ => return Err(Refusal::Malformed),
    };
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(Refusal::Oversized(MAX_FRAME_BYTES));
    }
    let serde_json::Value::Object(mut value) =
        serde_json::from_slice(bytes).map_err(|_| Refusal::Malformed)?
    else {
        return Err(Refusal::Malformed);
    };
    if value.insert("operation".into(), operation.into()).is_some() {
        return Err(Refusal::Malformed);
    }
    serde_json::from_value(value.into()).map_err(|_| Refusal::Malformed)
}

/// Execute once. A lost response is unknown; caller retains the original IDs.
pub fn call(
    request: &ConversationRequest,
    timeout: Duration,
) -> Result<ConversationResponse, Refusal> {
    if timeout.is_zero() || timeout > mvm_core::mailbox::conversation_wire::MAX_WAIT_BUDGET {
        return Err(Refusal::Malformed);
    }
    let deadline = Instant::now() + timeout;
    let mut stream =
        crate::vsock::connect_unix_before(Path::new(GUEST_READER_SOCKET_PATH), deadline).map_err(
            |_| {
                if Instant::now() >= deadline {
                    Refusal::Expired
                } else {
                    Refusal::Unavailable
                }
            },
        )?;
    crate::vsock::run_with_stream_deadline(&mut stream, deadline, |stream| {
        let invocation = ConversationInvocation::new(
            request.clone(),
            deadline.saturating_duration_since(Instant::now()),
        );
        Ok(invocation.and_then(|invocation| {
            write_local_request(stream, &invocation).and_then(|()| read_local_response(stream))
        }))
    })
    .map_err(|_| {
        if Instant::now() >= deadline {
            Refusal::Expired
        } else {
            Refusal::Unavailable
        }
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_is_closed_and_never_selects_a_broker_operation() {
        assert_eq!(
            parse_request("host.mailbox.receive", b"{}"),
            Ok(ConversationRequest::Receive {})
        );
        assert!(parse_request("host.mailbox.receive", br#"{"operation":"call"}"#).is_err());
        assert!(parse_request("host.actor.call", b"{}").is_err());
        assert!(parse_request("host.mailbox.receive", br#"{"payload_b64":"private"}"#).is_err());
    }
}
