//! Stage one guest-to-own-mailbox message. Local staging is not a signed
//! destination acceptance receipt; inspect the host journal for durability.

use std::path::Path;

use mvm_agentd::mailbox_outbox::{LOCAL_OUTBOX_PATH, OUTBOX_PATH, write_outbox};
use mvm_contract::protocol::mailbox::PrincipalId;
use mvm_core::mailbox::frame::{OWN_MAILBOX_RECIPIENT, OutboxMessage};

fn destination(args: &[String]) -> Option<(&'static str, &str)> {
    match args {
        [body] if !body.is_empty() && body != "--local" => Some((OUTBOX_PATH, body)),
        [flag, body] if flag == "--local" && !body.is_empty() => Some((LOCAL_OUTBOX_PATH, body)),
        _ => None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (outbox, body) =
        destination(&args).ok_or("usage: mailbox_writer_client [--local] <message>")?;
    let message = OutboxMessage::new(
        PrincipalId::from_bytes(OWN_MAILBOX_RECIPIENT),
        body.as_bytes().to_vec(),
    );
    write_outbox(Path::new(outbox), &message)?;
    eprintln!("staged locally: message {:?}", message.message_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_local_option_chooses_the_receipt_bearing_outbox_only_when_explicit() {
        assert_eq!(destination(&["hello".into()]), Some((OUTBOX_PATH, "hello")));
        assert_eq!(
            destination(&["--local".into(), "hello".into()]),
            Some((LOCAL_OUTBOX_PATH, "hello"))
        );
        assert_eq!(destination(&["--local".into()]), None);
        assert_eq!(destination(&["".into()]), None);
        assert_eq!(destination(&["one".into(), "two".into()]), None);
    }
}
