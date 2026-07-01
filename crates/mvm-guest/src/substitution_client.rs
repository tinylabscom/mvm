//! In-guest substitution client (the relay half).
//!
//! The guest-local forward proxy relays a workload's secret-bearing request to
//! the host substitution endpoint over vsock, carrying an opaque placeholder.
//! The host resolves the placeholder, binding-checks the destination, injects
//! the real credential, and makes the real TLS — the guest only ever held the
//! placeholder. This module is the relay: send a `WireRequest`, get a
//! `WireResponse`. The HTTP-proxy front (parsing the workload's proxied
//! request, the `HTTP_PROXY` wiring) sits on top.

use std::os::unix::net::UnixStream;

use anyhow::Result;
use mvm_core::substitution_wire::{WireRequest, WireResponse};

use crate::vsock::{EGRESS_PORT, connect_host_vsock, read_frame, write_frame};

/// Relay one request to the host substitution endpoint over an already-open
/// stream, returning its reply. One framed `WireRequest` out, one framed
/// `WireResponse` back.
pub fn relay(stream: &mut UnixStream, req: &WireRequest) -> Result<WireResponse> {
    write_frame(stream, req)?;
    read_frame(stream)
}

/// Open a **guest→host** vsock stream to the host substitution endpoint
/// ([`EGRESS_PORT`]) and relay one request. Uses an AF_VSOCK connect to
/// the host (CID 2) — backend-agnostic on the guest side — not the host→guest
/// UDS-multiplexer path.
pub fn substitute(req: &WireRequest, timeout_secs: u64) -> Result<WireResponse> {
    let mut stream = connect_host_vsock(EGRESS_PORT, timeout_secs)?;
    relay(&mut stream, req)
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
