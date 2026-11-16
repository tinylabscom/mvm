//! `mvm-mailbox-client`: a workload's way to use the mailbox its launch granted.
//!
//! `send [--local] [--to <64 hex>] <message>` stages one message, for this
//! workload's own mailbox unless `--to` names another recipient (the spool by
//! default, the immutable production request with `--local`). Addressing
//! someone else is how a workload tries to exceed its grant: the host refuses
//! it, and the refusal is the point of doing it.
//! `recv [--ack]` reads one message from the workload's own inbox; pass `--ack`
//! only after the application has processed and flushed its output. Both report
//! local staging or local receipt only, not a destination-signed receipt: verify
//! the host-side receipt or journal before claiming destination acceptance.
//!
//! It ships in the signed runtime overlay, the single source of the guest
//! binaries, so a workload image needs no copy of its own.

use std::io::{self, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use mvm_agentd::mailbox_outbox::{LOCAL_OUTBOX_PATH, OUTBOX_PATH, write_outbox};
use mvm_contract::protocol::mailbox::PrincipalId;
use mvm_core::mailbox::frame::{OWN_MAILBOX_RECIPIENT, OutboxMessage};
use mvm_core::mailbox::reader_wire::{
    ApplicationReaderRequest, GUEST_READER_SOCKET_PATH, ReaderResponse, read_response,
    write_application_request,
};

const USAGE: &str =
    "usage: mvm-mailbox-client send [--local] [--to <64 hex>] <message> | recv [--ack]";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Send {
        outbox: &'static str,
        to: Option<[u8; 32]>,
        body: &'a str,
    },
    Recv {
        ack: bool,
    },
}

fn parse_recipient(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn parse(args: &[String]) -> Option<Command<'_>> {
    match args {
        [verb] if verb == "recv" => Some(Command::Recv { ack: false }),
        [verb, flag] if verb == "recv" && flag == "--ack" => Some(Command::Recv { ack: true }),
        [verb, rest @ ..] if verb == "send" => {
            let (mut outbox, mut to, mut rest) = (OUTBOX_PATH, None, rest);
            loop {
                match rest {
                    [flag, tail @ ..] if flag == "--local" => {
                        (outbox, rest) = (LOCAL_OUTBOX_PATH, tail)
                    }
                    [flag, hex, tail @ ..] if flag == "--to" => {
                        (to, rest) = (Some(parse_recipient(hex)?), tail)
                    }
                    [body] if !body.is_empty() && !body.starts_with("--") => {
                        return Some(Command::Send { outbox, to, body });
                    }
                    _ => return None,
                }
            }
        }
        _ => None,
    }
}

fn send(outbox: &str, to: Option<[u8; 32]>, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    let recipient = to.unwrap_or(OWN_MAILBOX_RECIPIENT);
    let message = OutboxMessage::new(PrincipalId::from_bytes(recipient), body.as_bytes().to_vec());
    write_outbox(Path::new(outbox), &message)?;
    eprintln!("staged locally: message {:?}", message.message_id);
    Ok(())
}

fn connect() -> io::Result<UnixStream> {
    let stream = UnixStream::connect(GUEST_READER_SOCKET_PATH)?;
    stream.set_read_timeout(Some(Duration::from_secs(12)))?;
    stream.set_write_timeout(Some(Duration::from_secs(12)))?;
    Ok(stream)
}

fn recv(ack: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = connect()?;
    write_application_request(&mut stream, &ApplicationReaderRequest::Receive)?;
    let response = read_response(&mut stream)?;
    let ReaderResponse::Delivery {
        lease,
        content_type,
        payload,
    } = response
    else {
        match response {
            ReaderResponse::Empty => eprintln!("inbox empty"),
            ReaderResponse::Refused { reason } => return Err(reason.into()),
            _ => return Err("unexpected reader response".into()),
        }
        return Ok(());
    };
    // Processing here is writing and flushing stdout. A real application ACKs
    // only after its own durable processing completes.
    io::stdout().write_all(&payload)?;
    io::stdout().flush()?;
    eprintln!(
        "received {} bytes as {} (message {:?}, delivery {:?})",
        payload.len(),
        content_type.name(),
        lease.lease.message_id,
        lease.lease.delivery_id
    );
    if ack {
        let mut stream = connect()?;
        write_application_request(
            &mut stream,
            &ApplicationReaderRequest::Ack {
                lease: lease.clone(),
            },
        )?;
        match read_response(&mut stream)? {
            ReaderResponse::Acknowledged { ack: signed } if signed.ack.lease == *lease => {
                eprintln!("locally acknowledged by MVM");
            }
            ReaderResponse::Refused { reason } => return Err(reason.into()),
            _ => return Err("ACK response did not identify this lease".into()),
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args).ok_or(USAGE)? {
        Command::Send { outbox, to, body } => send(outbox, to, body),
        Command::Recv { ack } => recv(ack),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_string()).collect()
    }

    const OTHER: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn send_chooses_the_receipt_bearing_outbox_only_when_local_is_explicit() {
        assert_eq!(
            parse(&args(&["send", "hello"])),
            Some(Command::Send {
                outbox: OUTBOX_PATH,
                to: None,
                body: "hello"
            })
        );
        assert_eq!(
            parse(&args(&["send", "--local", "hello"])),
            Some(Command::Send {
                outbox: LOCAL_OUTBOX_PATH,
                to: None,
                body: "hello"
            })
        );
    }

    #[test]
    fn send_addresses_another_recipient_only_when_asked_with_a_full_id() {
        let expected = Some(Command::Send {
            outbox: LOCAL_OUTBOX_PATH,
            to: Some([0xff; 32]),
            body: "x",
        });
        assert_eq!(
            parse(&args(&["send", "--local", "--to", OTHER, "x"])),
            expected
        );
        assert_eq!(
            parse(&args(&["send", "--to", OTHER, "--local", "x"])),
            expected
        );
        for bad in [
            "ff",
            &OTHER[..63],
            &format!("{OTHER}00"),
            &OTHER.replace('f', "g"),
        ] {
            assert_eq!(parse(&args(&["send", "--to", bad, "x"])), None, "{bad}");
        }
    }

    #[test]
    fn recv_acknowledges_only_when_asked() {
        assert_eq!(parse(&args(&["recv"])), Some(Command::Recv { ack: false }));
        assert_eq!(
            parse(&args(&["recv", "--ack"])),
            Some(Command::Recv { ack: true })
        );
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        for bad in [
            vec![],
            vec!["send"],
            vec!["send", "--local"],
            vec!["send", ""],
            vec!["send", "one", "two"],
            vec!["send", "--to"],
            vec!["send", "--local", "--local"],
            vec!["send", "--bogus"],
            vec!["recv", "--nope"],
            vec!["frobnicate"],
        ] {
            assert_eq!(parse(&args(&bad)), None, "{bad:?}");
        }
    }
}
