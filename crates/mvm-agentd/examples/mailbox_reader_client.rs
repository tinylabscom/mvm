//! Guest application example: read one message from this workload's own inbox.
//! Pass `--ack` only after the application has processed and flushed its output.

use std::io::{self, Write as _};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use mvm_core::mailbox::reader_wire::{
    ApplicationReaderRequest, GUEST_READER_SOCKET_PATH, ReaderResponse, read_response,
    write_application_request,
};

fn connect() -> io::Result<UnixStream> {
    let stream = UnixStream::connect(GUEST_READER_SOCKET_PATH)?;
    stream.set_read_timeout(Some(Duration::from_secs(12)))?;
    stream.set_write_timeout(Some(Duration::from_secs(12)))?;
    Ok(stream)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ack = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--ack" => true,
        _ => return Err("usage: mailbox_reader_client [--ack]".into()),
    };
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
    // This example's application processing is writing and flushing stdout.
    // A real application ACKs only after its own durable processing completes.
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
