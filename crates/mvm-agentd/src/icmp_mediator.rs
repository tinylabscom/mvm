//! Guest-local ICMP mediator, served by the process that holds the FlowMux
//! identity.
//!
//! The guest's signing key is root-only by construction (`/run/mvm`, mode
//! 0400): the workload runs as uid 901 and must not be able to authenticate as
//! its own guest. `mvm-ping` runs *as* the workload, so it cannot open a
//! FlowMux session of its own — the same reason an ordinary workload reaches
//! the network through the loopback SOCKS proxy and the loopback DNS stub
//! rather than dialling the host itself.
//!
//! So ICMP gets the third loopback mediator, beside those two and in the same
//! root process: the workload speaks to [`ICMP_MEDIATOR_LISTEN`], and the
//! mediator performs the echo over the one authenticated session. Nothing new
//! crosses the guest→host boundary — this is the guest's own loopback, and the
//! request and reply on it are the same [`IcmpEchoRequest`] / [`IcmpEchoReply`]
//! the FlowMux flow carries.
//!
//! The connection opens with a [`MediatorHello`] because the round trip
//! `mvm-ping` reports has to be the echo and not the handshake. The mediator
//! establishes its session first and says so; the client starts timing after
//! that, exactly as it did when it owned the session itself.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use anyhow::{Context, Result};
use mvm_contract::protocol::network_flow::Opcode;
use mvm_core::guest_netd::ICMP_MEDIATOR_LISTEN;
use mvm_core::icmp_wire::{IcmpEchoReply, IcmpEchoRequest};

use crate::flowmux_sync::SyncFlowMux;

/// The mediator's first line: whether it has a session to echo over.
///
/// A failure to reach the host is reported here rather than as a closed
/// socket, so the workload sees the host's own words instead of `EOF`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum MediatorHello {
    /// The session is up; send echo requests.
    Ready,
    /// No session could be opened. Terminal for this connection.
    Unavailable {
        /// Why, in terms the workload can act on.
        message: String,
    },
}

/// Bind the mediator's loopback port.
///
/// Separate from [`serve`] so the caller can bind before it spawns: the guest
/// init only waits for the proxy port, so a workload can be running by the time
/// a thread that binds lazily gets scheduled, and `ping` would fail with
/// connection-refused for the first moments of a boot.
pub fn bind_icmp_mediator() -> Result<TcpListener> {
    TcpListener::bind(ICMP_MEDIATOR_LISTEN)
        .with_context(|| format!("binding the ICMP mediator on {ICMP_MEDIATOR_LISTEN}"))
}

/// Serve echoes on `listener` until it fails. Blocking; the egress client runs
/// it on its own thread.
pub fn serve_icmp_mediator(listener: &TcpListener) -> Result<()> {
    serve(listener, SyncFlowMux::connect)
}

/// How long a connected client may go without sending before it is dropped.
///
/// A client owns a FlowMux session for as long as it stays connected, so one
/// that connects and then stops talking — a workload killed mid-`ping`, say —
/// would otherwise hold a session for the life of the guest.
const CLIENT_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Ceiling on one request line. An `IcmpEchoRequest` is a couple of hundred
/// bytes; without a ceiling a client that never sends a newline grows this
/// process's heap without bound, and the process holding the guest identity is
/// the wrong one to let a workload exhaust.
const MAX_REQUEST_LINE: u64 = 8 * 1024;

/// Slack over the caller's own per-echo wait before the mediator gives up on
/// the host. Outlasts it, so a reply the host is still legitimately waiting on
/// is not cut off here — but it is bounded, or a host that never answers pins
/// this thread and its session for the life of the guest.
const HOST_REPLY_SLACK: std::time::Duration = std::time::Duration::from_secs(10);

/// Accept loop, with the session opener injected so a test can drive a real
/// exchange without a host.
///
/// A thread per client, because a client holds its connection across all of its
/// echoes: served inline, one `ping -c 4 -W 4000` would make every other caller
/// in the guest wait up to sixteen seconds on a listener that looked live. One
/// client's error never ends the loop either.
pub fn serve<F>(listener: &TcpListener, open_session: F) -> Result<()>
where
    F: Fn() -> Result<SyncFlowMux> + Clone + Send + 'static,
{
    for conn in listener.incoming() {
        let stream = conn.context("accept on the ICMP mediator listener")?;
        let open_session = open_session.clone();
        std::thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &open_session) {
                eprintln!("mvm-icmp-mediator: {error:#}");
            }
        });
    }
    Ok(())
}

/// One client: announce a session, then echo for as long as it keeps asking.
fn handle_connection<F>(stream: TcpStream, open_session: &F) -> Result<()>
where
    F: Fn() -> Result<SyncFlowMux>,
{
    stream
        .set_read_timeout(Some(CLIENT_IDLE_TIMEOUT))
        .context("set the mediator idle timeout")?;
    let mut writer = stream
        .try_clone()
        .context("clone the mediator connection")?;
    let mut reader = BufReader::new(stream);

    let mut flowmux = match open_session() {
        Ok(flowmux) => {
            write_line(&mut writer, &MediatorHello::Ready)?;
            flowmux
        }
        Err(error) => {
            // The client is owed the reason: it cannot see the host endpoint,
            // the identity drive, or this process's stderr.
            write_line(
                &mut writer,
                &MediatorHello::Unavailable {
                    message: format!("{error:#}"),
                },
            )?;
            return Ok(());
        }
    };

    let mut line = String::new();
    loop {
        line.clear();
        let read = (&mut reader)
            .take(MAX_REQUEST_LINE)
            .read_line(&mut line)
            .context("read an echo request from the workload")?;
        if read == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') {
            anyhow::bail!("an echo request exceeded {MAX_REQUEST_LINE} bytes");
        }
        if line.trim().is_empty() {
            continue;
        }
        let request: IcmpEchoRequest =
            serde_json::from_str(line.trim()).context("decode the workload's echo request")?;
        let reply = echo_over_flowmux(&mut flowmux, &request)?;
        write_line(&mut writer, &reply)?;
    }
}

/// Perform one echo on an open session.
///
/// The bounds check is the wire contract's own, applied here because the
/// mediator forwards on the workload's behalf and an out-of-range request must
/// be refused locally rather than spent on the session.
pub fn echo_over_flowmux(
    flowmux: &mut SyncFlowMux,
    request: &IcmpEchoRequest,
) -> Result<IcmpEchoReply> {
    if let Err(bounds) = request.validate() {
        return Ok(IcmpEchoReply::Refused {
            message: bounds.to_string(),
        });
    }
    flowmux.set_read_timeout(
        std::time::Duration::from_millis(u64::from(request.timeout_ms))
            .saturating_add(HOST_REPLY_SLACK),
    )?;
    let encoded = serde_json::to_vec(request).context("encode the echo request")?;
    let stream_id = flowmux.next_stream_id();
    flowmux.send(Opcode::IcmpEcho, stream_id, &encoded)?;
    let (opcode, _stream_id, payload) = flowmux.recv()?;
    match opcode {
        Opcode::IcmpReply | Opcode::IcmpRefused => {
            serde_json::from_slice(&payload).context("decode the echo reply")
        }
        other => anyhow::bail!("expected an echo reply, got {other:?}"),
    }
}

/// Write one JSON line and flush it: the peer is reading line by line and a
/// buffered reply is indistinguishable from a hung host.
fn write_line<T: serde::Serialize>(writer: &mut impl Write, value: &T) -> Result<()> {
    let mut encoded = serde_json::to_vec(value).context("encode a mediator line")?;
    encoded.push(b'\n');
    writer
        .write_all(&encoded)
        .context("write a mediator line")?;
    writer.flush().context("flush a mediator line")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hello_round_trips_both_arms() {
        for hello in [
            MediatorHello::Ready,
            MediatorHello::Unavailable {
                message: "no identity".into(),
            },
        ] {
            let encoded = serde_json::to_string(&hello).unwrap();
            assert_eq!(
                serde_json::from_str::<MediatorHello>(&encoded).unwrap(),
                hello
            );
        }
    }

    /// An unknown field is a different protocol, not a newer one: the guest and
    /// the workload ship in the same binary, so there is no version skew to
    /// tolerate and a typo should be loud.
    #[test]
    fn an_unknown_hello_field_is_refused() {
        assert!(serde_json::from_str::<MediatorHello>(r#"{"ready":{"extra":1}}"#).is_err());
    }

    /// One echo end to end: an unprivileged client on the loopback, the
    /// mediator holding the only identity, and a host speaking the real sealed
    /// protocol on the other side.
    ///
    /// The client here does nothing but read and write lines — no key, no
    /// anchor, no vsock — which is exactly the position `mvm-ping` is in.
    #[test]
    fn an_echo_crosses_the_loopback_and_comes_back_off_the_session() {
        use ed25519_dalek::SigningKey;
        use mvm_contract::protocol::network_flow::hello::Handshake;
        use mvm_contract::protocol::network_flow::{MAX_FRAME_LEN, decode, encode_into};
        use mvm_core::net::session::{Session, read_sealed_frame, write_sealed_frame};
        use std::os::unix::net::UnixStream;

        let (guest_side, host_side) = UnixStream::pair().unwrap();
        let guest_key = SigningKey::from_bytes(&[5u8; 32]);
        let host_key = SigningKey::from_bytes(&[11u8; 32]);
        let host_anchor = host_key.verifying_key();

        let host = std::thread::spawn(move || {
            let mut stream = host_side;
            let (mut session, _peer) = Session::host(&mut stream, "icmp-test", host_key).unwrap();
            let recv = |session: &mut Session, stream: &mut UnixStream| {
                let sealed = read_sealed_frame(stream, MAX_FRAME_LEN + 512).unwrap();
                let plain = session.open(&sealed).unwrap();
                let parsed = decode(&plain).unwrap();
                (parsed.header.opcode, parsed.payload.to_vec())
            };
            let send = |session: &mut Session,
                        stream: &mut UnixStream,
                        opcode: Opcode,
                        stream_id: u32,
                        payload: &[u8]| {
                let mut wire = Vec::new();
                encode_into(&mut wire, opcode, stream_id, payload).unwrap();
                let sealed = session.seal(&wire).unwrap();
                write_sealed_frame(stream, &sealed).unwrap();
            };

            let (opcode, _) = recv(&mut session, &mut stream);
            assert_eq!(opcode, Opcode::Hello);
            send(
                &mut session,
                &mut stream,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            );

            let (opcode, payload) = recv(&mut session, &mut stream);
            assert_eq!(opcode, Opcode::IcmpEcho);
            let asked: IcmpEchoRequest = serde_json::from_slice(&payload).unwrap();
            assert_eq!(asked.host, "example.com");
            let reply = IcmpEchoReply::Reply {
                seq: 0,
                ip: "93.184.216.34".into(),
                host_leg_us: 4_200,
                payload_len: asked.payload_len,
            };
            send(
                &mut session,
                &mut stream,
                Opcode::IcmpReply,
                1,
                &serde_json::to_vec(&reply).unwrap(),
            );
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let opened = std::sync::Mutex::new(Some(guest_side));
        let mediator = std::thread::spawn(move || {
            let conn = listener.incoming().next().unwrap().unwrap();
            handle_connection(conn, &|| {
                let stream = opened.lock().unwrap().take().expect("one session");
                SyncFlowMux::handshake(stream, guest_key.clone(), &host_anchor)
            })
            .unwrap();
        });

        let client = TcpStream::connect(addr).unwrap();
        let mut writer = client.try_clone().unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<MediatorHello>(line.trim()).unwrap(),
            MediatorHello::Ready
        );

        let request = IcmpEchoRequest {
            host: "example.com".into(),
            count: 1,
            payload_len: 56,
            timeout_ms: 1000,
        };
        writeln!(writer, "{}", serde_json::to_string(&request).unwrap()).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        match serde_json::from_str::<IcmpEchoReply>(line.trim()).unwrap() {
            IcmpEchoReply::Reply {
                ip,
                host_leg_us,
                payload_len,
                ..
            } => {
                assert_eq!(ip, "93.184.216.34");
                assert_eq!(host_leg_us, 4_200);
                assert_eq!(payload_len, 56);
            }
            other => panic!("expected a reply, got {other:?}"),
        }

        drop(writer);
        drop(reader);
        mediator.join().unwrap();
        host.join().unwrap();
    }

    /// An out-of-range request is answered locally rather than spent on the
    /// session: the bounds are the wire contract's and the mediator forwards on
    /// the workload's behalf, so it owes the refusal itself. The host asserts
    /// the negative — no frame reached it — because "refused" and "refused by
    /// the host" print the same to the workload.
    #[test]
    fn an_out_of_bounds_request_is_refused_without_reaching_the_host() {
        use ed25519_dalek::SigningKey;
        use mvm_contract::protocol::network_flow::hello::Handshake;
        use mvm_contract::protocol::network_flow::{MAX_FRAME_LEN, decode, encode_into};
        use mvm_core::net::session::{Session, read_sealed_frame, write_sealed_frame};
        use std::os::unix::net::UnixStream;

        let (guest_side, host_side) = UnixStream::pair().unwrap();
        let guest_key = SigningKey::from_bytes(&[5u8; 32]);
        let host_key = SigningKey::from_bytes(&[11u8; 32]);
        let host_anchor = host_key.verifying_key();

        let host = std::thread::spawn(move || {
            let mut stream = host_side;
            let (mut session, _peer) = Session::host(&mut stream, "bounds-test", host_key).unwrap();
            let sealed = read_sealed_frame(&mut stream, MAX_FRAME_LEN + 512).unwrap();
            let plain = session.open(&sealed).unwrap();
            assert_eq!(decode(&plain).unwrap().header.opcode, Opcode::Hello);
            let mut wire = Vec::new();
            encode_into(
                &mut wire,
                Opcode::HelloAck,
                0,
                &Handshake::local("h").encode(),
            )
            .unwrap();
            let sealed = session.seal(&wire).unwrap();
            write_sealed_frame(&mut stream, &sealed).unwrap();
            // Anything after the handshake is an echo the mediator should have
            // refused itself.
            read_sealed_frame(&mut stream, MAX_FRAME_LEN + 512).is_ok()
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let opened = std::sync::Mutex::new(Some(guest_side));
        let mediator = std::thread::spawn(move || {
            let conn = listener.incoming().next().unwrap().unwrap();
            handle_connection(conn, &|| {
                let stream = opened.lock().unwrap().take().expect("one session");
                SyncFlowMux::handshake(stream, guest_key.clone(), &host_anchor)
            })
            .unwrap();
        });

        let client = TcpStream::connect(addr).unwrap();
        let mut writer = client.try_clone().unwrap();
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        let bad = IcmpEchoRequest {
            host: String::new(),
            count: 1,
            payload_len: 0,
            timeout_ms: 1,
        };
        writeln!(writer, "{}", serde_json::to_string(&bad).unwrap()).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        match serde_json::from_str::<IcmpEchoReply>(line.trim()).unwrap() {
            IcmpEchoReply::Refused { message } => assert!(!message.is_empty()),
            other => panic!("expected a refusal, got {other:?}"),
        }

        drop(writer);
        drop(reader);
        mediator.join().unwrap();
        assert!(
            !host.join().unwrap(),
            "an out-of-bounds request must not be spent on the session"
        );
    }

    /// A slow client does not hold the mediator: served in the accept loop, the
    /// second caller waits out the first, and `ping` in a guest running two
    /// things at once looks hung.
    #[test]
    fn a_second_client_is_served_while_the_first_is_still_holding_its_session() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // The first client's session never finishes opening; the second's fails
        // at once. Serial accept would leave the second with no hello at all.
        let held = Arc::new(Barrier::new(2));
        let opener_held = Arc::clone(&held);
        let seen = Arc::new(AtomicUsize::new(0));
        std::thread::spawn(move || {
            serve(&listener, move || {
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    opener_held.wait();
                }
                anyhow::bail!("no session")
            })
        });

        let first = TcpStream::connect(addr).unwrap();
        // Give the first client's thread time to reach the blocked opener, so a
        // pass cannot come from the second simply winning the race.
        first
            .set_read_timeout(Some(std::time::Duration::from_millis(250)))
            .unwrap();
        let mut discard = String::new();
        assert!(
            BufReader::new(&first).read_line(&mut discard).is_err(),
            "the first client must still be waiting on its session"
        );

        let second = TcpStream::connect(addr).unwrap();
        second
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut line = String::new();
        BufReader::new(second)
            .read_line(&mut line)
            .expect("the second client is served while the first is blocked");
        assert!(matches!(
            serde_json::from_str::<MediatorHello>(line.trim()).unwrap(),
            MediatorHello::Unavailable { .. }
        ));

        held.wait();
    }

    /// The whole point of the mediator: a client that cannot read the signing
    /// key still gets an answer, because the session is opened over here.
    #[test]
    fn a_client_that_cannot_open_a_session_is_told_why_rather_than_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let conn = listener.incoming().next().unwrap().unwrap();
            handle_connection(conn, &|| {
                anyhow::bail!("reading the guest signing key: EACCES")
            })
            .unwrap();
        });

        let client = TcpStream::connect(addr).unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        let hello: MediatorHello = serde_json::from_str(line.trim()).unwrap();
        match hello {
            MediatorHello::Unavailable { message } => {
                assert!(message.contains("EACCES"), "{message}")
            }
            MediatorHello::Ready => panic!("a failed session must not announce Ready"),
        }
    }
}
