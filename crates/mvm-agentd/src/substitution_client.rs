//! Framed `WireRequest`/`WireResponse` relay over an open stream.
//!
//! **Not a guest→host transport.** The in-guest forward proxy moved to the
//! authenticated FlowMux session (`crate::flowmux_sync`), and the vsock dial
//! that used to live here went with it — a guest reaches its host endpoint one
//! way now, and `xtask check-one-guest-protocol` enforces that.
//!
//! What survives is the relay over an already-open stream, whose one caller is
//! the wasm tier: `mvm-runtime`'s `mvm:egress` host import, running on the
//! *host*, connecting to the endpoint's Unix socket. That is host-internal IPC
//! between two host processes, not a guest speaking to its host, so it is not
//! on the channel the one-transport rule governs.

use std::os::unix::net::UnixStream;

use anyhow::Result;
use mvm_core::substitution_wire::{WireRequest, WireResponse};

use crate::vsock::{read_frame, write_frame};

/// Relay one request to the host substitution endpoint over an already-open
/// stream, returning its reply. One framed `WireRequest` out, one framed
/// `WireResponse` back.
pub fn relay(stream: &mut UnixStream, req: &WireRequest) -> Result<WireResponse> {
    write_frame(stream, req)?;
    read_frame(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn sample_request(placeholder: &str) -> WireRequest {
        WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
            body_b64: String::new(),
        }
    }

    #[test]
    fn relay_round_trips_a_request_and_response_over_a_socket_pair() {
        let (mut client, mut server) = UnixStream::pair().unwrap();

        // The "host" side: read the request, reply with a canned response.
        let handle = thread::spawn(move || {
            let got: WireRequest = read_frame(&mut server).unwrap();
            // The relayed request carries the opaque placeholder, untouched.
            assert_eq!(
                got.headers[0],
                ("authorization".into(), "Bearer mvm-secret-abc".into())
            );
            write_frame(
                &mut server,
                &WireResponse::Ok {
                    status: 200,
                    headers: vec![],
                    body_b64: "cG9uZw==".into(), // "pong"
                },
            )
            .unwrap();
        });

        let resp = relay(&mut client, &sample_request("mvm-secret-abc")).unwrap();
        match resp {
            WireResponse::Ok {
                status, body_b64, ..
            } => {
                assert_eq!(status, 200);
                assert_eq!(body_b64, "cG9uZw==");
            }
            WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn relay_surfaces_a_refusal() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let handle = thread::spawn(move || {
            let _: WireRequest = read_frame(&mut server).unwrap();
            write_frame(
                &mut server,
                &WireResponse::Refused {
                    message: "destination not bound".into(),
                },
            )
            .unwrap();
        });
        let resp = relay(&mut client, &sample_request("mvm-secret-xyz")).unwrap();
        assert!(matches!(resp, WireResponse::Refused { .. }));
        handle.join().unwrap();
    }
}
