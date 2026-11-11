//! Stage one guest-to-own-mailbox message. Local staging is not a signed
//! destination acceptance receipt; inspect the host journal for durability.

use std::path::Path;

use mvm_agentd::mailbox_outbox::{OUTBOX_PATH, write_outbox};
use mvm_contract::protocol::mailbox::PrincipalId;
use mvm_core::mailbox::frame::{OWN_MAILBOX_RECIPIENT, OutboxMessage};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let body = std::env::args()
        .nth(1)
        .filter(|body| !body.is_empty())
        .ok_or("usage: mailbox_writer_client <message>")?;
    let message = OutboxMessage::new(
        PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT),
        body.into_bytes(),
    );
    write_outbox(Path::new(OUTBOX_PATH), &message)?;
    eprintln!("staged locally: message {:?}", message.message_id);
    Ok(())
}
