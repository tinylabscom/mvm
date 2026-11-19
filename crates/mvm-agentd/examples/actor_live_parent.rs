//! Native guest witness: exact child launch, bounded durable call/reply, release.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail, ensure};
use mvm_contract::protocol::mailbox::{ContentType, CorrelationId, MessageId};
use mvm_contract::protocol::workload_actor::{
    ActorBindingId, ActorOperation, ActorOutcome, ActorProtocolVersion, ActorRefusalCode,
    ActorRequest,
};
use mvm_core::mailbox::conversation_wire::{ConversationRequest, ConversationResponse};

const TIMEOUT: Duration = Duration::from_secs(120);
const MESSAGE: &[u8] = b"actor-live-private-request-v1";
const REPLY: &[u8] = b"actor-live-private-response-v1";

fn actor(operation: ActorOperation) -> Result<ActorOutcome> {
    Ok(mvm_agentd::host_actor::call(
        &ActorRequest {
            version: ActorProtocolVersion::V1,
            operation,
        },
        TIMEOUT,
    )?
    .outcome)
}

fn id(name: &str) -> Result<ActorBindingId> {
    Ok(ActorBindingId::new(name)?)
}

fn mailbox(request: &ConversationRequest, timeout: Duration) -> Result<ConversationResponse> {
    use mvm_core::mailbox::frame::Refusal;
    let result = mvm_agentd::host_mailbox::call(request, timeout);
    let refusal = match &result {
        Ok(ConversationResponse::Refused { reason }) | Err(reason) => Some(reason),
        _ => None,
    };
    match refusal {
        Some(Refusal::NotAuthorized) => eprintln!("ACTOR_LIVE_REFUSAL_NOT_AUTHORIZED"),
        Some(Refusal::Unavailable) => eprintln!("ACTOR_LIVE_REFUSAL_UNAVAILABLE"),
        Some(Refusal::Oversized(_)) => eprintln!("ACTOR_LIVE_REFUSAL_OVERSIZED"),
        Some(_) => eprintln!("ACTOR_LIVE_REFUSAL_OTHER"),
        None => {}
    }
    Ok(result?)
}

fn main() -> Result<()> {
    let denied = actor(ActorOperation::Launch {
        grant_id: id("actor-live")?,
        template_id: id("not-authorized")?,
        idempotency_key: id("negative-launch")?,
    })?;
    ensure!(
        matches!(
            denied,
            ActorOutcome::Refused {
                code: ActorRefusalCode::UnknownTemplate
            }
        ),
        "unbound child template was not refused"
    );
    let launched = actor(ActorOperation::Launch {
        grant_id: id("actor-live")?,
        template_id: id("worker")?,
        idempotency_key: id("launch-worker")?,
    })?;
    let ActorOutcome::Running { handle } = launched else {
        bail!("child did not reach running under the exact template");
    };
    eprintln!("ACTOR_LIVE_STAGE_NEGATIVE_CALL");
    let deadline_unix_ms =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?
            .checked_add(90_000)
            .ok_or_else(|| anyhow::anyhow!("deadline overflow"))?;
    let content_type = ContentType::parse("application/octet-stream", 1)?;
    let too_large = ConversationRequest::Call {
        destination: handle.mailbox,
        message_id: MessageId::from_bytes([11; 32]),
        correlation_id: CorrelationId::from_bytes([12; 32]),
        deadline_unix_ms,
        content_type: content_type.clone(),
        payload: vec![b'x'; 1025],
    };
    ensure!(
        matches!(
            mailbox(&too_large, TIMEOUT)?,
            ConversationResponse::Refused { .. }
        ),
        "payload above the signed 1024-byte bound was accepted"
    );
    let call_message_id = MessageId::from_bytes([21; 32]);
    eprintln!("ACTOR_LIVE_STAGE_CALL");
    let queued = mailbox(
        &ConversationRequest::Call {
            destination: handle.mailbox,
            message_id: call_message_id,
            correlation_id: CorrelationId::from_bytes([22; 32]),
            deadline_unix_ms,
            content_type,
            payload: MESSAGE.to_vec(),
        },
        TIMEOUT,
    )?;
    ensure!(
        matches!(queued, ConversationResponse::Queued { call_message_id: actual } if actual == call_message_id),
        "call did not become durable source intent"
    );
    // One bounded blocking receive, not a retry/poll loop that hides a lost wake.
    eprintln!("ACTOR_LIVE_STAGE_RECEIVE_RESULT");
    let result = mailbox(
        &ConversationRequest::ReceiveResult { call_message_id },
        TIMEOUT,
    )?;
    let ConversationResponse::Delivery {
        header,
        lease,
        payload,
    } = result
    else {
        bail!("bounded receive did not deliver the correlated reply");
    };
    ensure!(
        payload == REPLY && header.correlation_id == CorrelationId::from_bytes([22; 32]),
        "reply payload or correlation mismatch"
    );
    eprintln!("ACTOR_LIVE_STAGE_ACK_RESULT");
    let ack = mailbox(
        &ConversationRequest::AckResult {
            call_message_id,
            result_message_id: header.message_id,
            lease,
            signed: None,
        },
        TIMEOUT,
    )?;
    ensure!(
        matches!(
            ack,
            ConversationResponse::Acknowledged | ConversationResponse::Settled
        ),
        "reply lease acknowledgement was not committed"
    );
    eprintln!("ACTOR_LIVE_STAGE_RELEASE_CHILD");
    let released = actor(ActorOperation::ReleaseChild {
        handle,
        idempotency_key: id("release-worker")?,
    })?;
    ensure!(
        matches!(released, ActorOutcome::Released { .. }),
        "child release lacks teardown proof"
    );
    println!("ACTOR_LIVE_PASS");
    Ok(())
}
