//! Native guest witness: receive one call, reply, acknowledge, await destruction.

use std::time::Duration;

use anyhow::{Result, bail, ensure};
use mvm_contract::protocol::mailbox::{ContentType, MessageId};
use mvm_core::mailbox::conversation_wire::{ConversationRequest, ConversationResponse};

const TIMEOUT: Duration = Duration::from_secs(120);

fn mailbox(request: &ConversationRequest) -> Result<ConversationResponse> {
    use mvm_core::mailbox::frame::Refusal;
    let result = mvm_agentd::host_mailbox::call(request, TIMEOUT);
    let refusal = match &result {
        Ok(ConversationResponse::Refused { reason }) | Err(reason) => Some(reason),
        _ => None,
    };
    match refusal {
        Some(Refusal::NotAuthorized) => eprintln!("ACTOR_CHILD_REFUSAL_NOT_AUTHORIZED"),
        Some(Refusal::Unavailable) => eprintln!("ACTOR_CHILD_REFUSAL_UNAVAILABLE"),
        Some(Refusal::Expired) => eprintln!("ACTOR_CHILD_REFUSAL_EXPIRED"),
        Some(Refusal::Malformed) => eprintln!("ACTOR_CHILD_REFUSAL_MALFORMED"),
        Some(Refusal::StorageFull) => eprintln!("ACTOR_CHILD_REFUSAL_STORAGE_FULL"),
        Some(Refusal::QueueFull(_)) => eprintln!("ACTOR_CHILD_REFUSAL_QUEUE_FULL"),
        Some(Refusal::RetriesExhausted) => eprintln!("ACTOR_CHILD_REFUSAL_RETRIES_EXHAUSTED"),
        Some(_) => eprintln!("ACTOR_CHILD_REFUSAL_OTHER"),
        None => {}
    }
    Ok(result?)
}

fn main() -> Result<()> {
    eprintln!("ACTOR_CHILD_STAGE_RECEIVE");
    let request = mailbox(&ConversationRequest::Receive {})?;
    let ConversationResponse::Delivery {
        header,
        lease,
        payload,
    } = request
    else {
        bail!("worker did not receive one bounded call");
    };
    ensure!(
        payload == b"actor-live-private-request-v1",
        "unexpected request payload"
    );
    eprintln!("ACTOR_CHILD_STAGE_REPLY");
    let reply = mailbox(&ConversationRequest::Reply {
        request_message_id: header.message_id,
        message_id: MessageId::from_bytes([31; 32]),
        content_type: ContentType::parse("application/octet-stream", 1)?,
        payload: b"actor-live-private-response-v1".to_vec(),
    })?;
    ensure!(
        matches!(
            reply,
            ConversationResponse::Queued { .. } | ConversationResponse::Acknowledged
        ),
        "reply was not durably accepted"
    );
    eprintln!("ACTOR_CHILD_STAGE_ACK_REQUEST");
    let ack = mailbox(&ConversationRequest::AckRequest {
        request_message_id: header.message_id,
        lease,
        signed: None,
    })?;
    ensure!(
        matches!(ack, ConversationResponse::Acknowledged),
        "request lease acknowledgement was not committed"
    );
    eprintln!("ACTOR_CHILD_STAGE_ACKNOWLEDGED");
    println!("ACTOR_WORKER_REPLIED");
    // The parent must destroy this used actor. A bounded timer makes a missing
    // release fail rather than accidentally turning process exit into that proof.
    std::thread::park_timeout(Duration::from_secs(180));
    bail!("parent did not release the worker before its deadline")
}
