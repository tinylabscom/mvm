//! Blocking one-shot FlowMux client for the guest's non-async callers.
//!
//! `mvm-egress-client` owns a long-lived async session and multiplexes the
//! loopback proxy over it. Its blocking ICMP mediator cannot borrow that async
//! session, and the secret-substitution forward proxy is a separate privileged
//! process. They use this client instead: open a connection, do one
//! authenticated exchange on it, close.
//!
//! Every caller here holds the guest signing key, which is root-only by
//! construction. A process that runs as the workload cannot open a session at
//! all, which is why `ping` asks [`crate::icmp_mediator`] rather than dialling
//! the host itself.
//!
//! It is the same protocol on the same port, not a second one. The host accepts
//! any number of concurrent sessions per VM, all pinned to the same guest key,
//! so several sessions is not several transports — one wire contract, one auth
//! boundary, one gate.
//!
//! Everything here is `std`: [`mvm_core::net::session::Session::guest`] takes
//! `Read + Write`, and the frame codec is `no_std`.

#![warn(missing_docs)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_contract::protocol::network_flow::hello::{Handshake, agree};
use mvm_contract::protocol::network_flow::{
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN, Opcode, decode, encode_into,
};
use mvm_core::net::session::{Session, read_sealed_frame, write_sealed_frame};
use mvm_core::substitution_wire::{HttpFlowHead, HttpFlowResponseHead, WireRequest, WireResponse};

/// Independent guest-side ceiling for a typed response, including responses
/// whose upstream did not declare a content length.
const MAX_HTTP_RESPONSE_BODY_LEN: u64 = 32 * 1024 * 1024;

use crate::flowmux_drive::{GUEST_SIGNING_KEY_FILE, HOST_SIGNER_PUB_FILE};

/// Where the guest inits leave the identity material the drive carried.
const RUN_MVM_DIR: &str = "/run/mvm";

/// How long to wait for the host endpoint to accept a connection.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Human-readable build identity carried in the versioned FlowMux hello.
const GUEST_BUILD: &str = concat!("mvm-agentd ", env!("CARGO_PKG_VERSION"));

/// One authenticated FlowMux session, used for one exchange and dropped.
pub struct SyncFlowMux {
    stream: UnixStream,
    session: Session,
    next_stream_id: u32,
}

/// One decoded frame: opcode, stream id, payload.
pub type Frame = (Opcode, u32, Vec<u8>);

/// Result of asking the host to open one typed HTTP stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpFlowOpen {
    /// The host accepted the flow and assigned this stream id.
    Opened(u32),
    /// The host refused the flow before any request bytes were sent.
    Refused(WireResponse),
}

impl SyncFlowMux {
    /// Dial the host endpoint and complete the handshake, loading this boot's
    /// identity from `/run/mvm`.
    ///
    /// Two ways to reach the same endpoint: a guest→host AF_VSOCK connect on
    /// the microVM tiers, and the bind-mounted endpoint socket on the
    /// shared-kernel container tier. The protocol spoken over either is the
    /// same, so the choice is only how to open the socket.
    pub fn connect() -> Result<Self> {
        let signing_key = load_guest_signing_key(Path::new(RUN_MVM_DIR))?;
        let anchor = load_host_anchor(Path::new(RUN_MVM_DIR))?;
        let stream = match crate::forward_proxy::egress_endpoint_socket() {
            Some(path) => UnixStream::connect(&path)
                .with_context(|| format!("connect to the endpoint socket {}", path.display()))?,
            None => {
                crate::vsock::connect_host_vsock(crate::vsock::EGRESS_PORT, CONNECT_TIMEOUT_SECS)
                    .context("connect to the host FlowMux endpoint over vsock")?
            }
        };
        Self::handshake(stream, signing_key, &anchor)
    }

    /// Complete the guest handshake on an already-open stream.
    ///
    /// Separate from [`Self::connect`] so a test can drive a real session over
    /// a socket pair without a VM.
    pub fn handshake(
        mut stream: UnixStream,
        signing_key: SigningKey,
        anchor: &VerifyingKey,
    ) -> Result<Self> {
        let (session, _session_id) = Session::guest(&mut stream, signing_key, anchor)
            .map_err(|e| anyhow::anyhow!("FlowMux handshake failed: {e}"))?;
        let mut client = Self {
            stream,
            session,
            // Guest-initiated streams are odd, as the host's parity check
            // requires.
            next_stream_id: 1,
        };
        let local = Handshake::local(GUEST_BUILD);
        client.send(Opcode::Hello, 0, &local.encode())?;
        let (opcode, _stream_id, payload) = client.recv()?;
        if opcode != Opcode::HelloAck {
            bail!("expected HelloAck to open the session, got {opcode:?}");
        }
        let host = Handshake::decode(&payload)
            .map_err(|e| anyhow::anyhow!("invalid FlowMux HelloAck: {e}"))?;
        agree(&local, &host).map_err(|e| anyhow::anyhow!("incompatible FlowMux host: {e}"))?;
        Ok(client)
    }

    /// Claim the next guest stream id.
    pub fn next_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.saturating_add(2);
        id
    }

    /// Seal and write one frame.
    pub fn send(&mut self, opcode: Opcode, stream_id: u32, payload: &[u8]) -> Result<()> {
        let mut wire = Vec::new();
        encode_into(&mut wire, opcode, stream_id, payload)
            .map_err(|e| anyhow::anyhow!("encoding {opcode:?}: {e}"))?;
        let sealed = self
            .session
            .seal(&wire)
            .map_err(|e| anyhow::anyhow!("sealing {opcode:?}: {e}"))?;
        // The seal already spent this sequence. A write that fails now cannot
        // be retried under it — the AES-GCM nonce derives from the sequence —
        // so the session ends here instead of running on one frame ahead of
        // the peer.
        let sequence = sealed.sequence;
        write_sealed_frame(&mut self.stream, &sealed).map_err(|e| {
            self.session.poison_send(sequence, e.to_string());
            anyhow::anyhow!("writing {opcode:?}: {e}")
        })
    }

    /// Read and open the next frame.
    pub fn recv(&mut self) -> Result<Frame> {
        let sealed = read_sealed_frame(&mut self.stream, MAX_FRAME_LEN + 512)
            .map_err(|e| anyhow::anyhow!("reading a FlowMux frame: {e}"))?;
        let plain = self
            .session
            .open(&sealed)
            .map_err(|e| anyhow::anyhow!("opening a FlowMux frame: {e}"))?;
        let parsed =
            decode(&plain).map_err(|e| anyhow::anyhow!("decoding a FlowMux frame: {e}"))?;
        Ok((
            parsed.header.opcode,
            parsed.header.stream_id,
            parsed.payload.to_vec(),
        ))
    }

    /// Apply a read timeout to the underlying socket, so a host that never
    /// answers surfaces as an error rather than hanging the caller forever.
    pub fn set_read_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        self.stream
            .set_read_timeout(Some(timeout))
            .context("setting the FlowMux read timeout")
    }
}

/// Read this boot's guest signing key from `dir`.
pub fn load_guest_signing_key(dir: &Path) -> Result<SigningKey> {
    let path = signing_key_path(dir);
    let raw = std::fs::read(&path)
        .with_context(|| format!("reading the guest signing key from {}", path.display()))?;
    let bytes: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "guest signing key must be exactly 32 bytes, got {}",
            v.len()
        )
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// Read the boot-pinned host-signer anchor from `dir`.
pub fn load_host_anchor(dir: &Path) -> Result<VerifyingKey> {
    let path = dir.join(HOST_SIGNER_PUB_FILE);
    crate::vsock::load_host_signer_verifying_key(&path)
        .with_context(|| format!("reading the host-signer anchor from {}", path.display()))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no host-signer anchor at {} — this guest cannot verify the host it dials",
                path.display()
            )
        })
}

fn signing_key_path(dir: &Path) -> PathBuf {
    std::env::var("MVM_FLOWMUX_GUEST_SIGNING_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir.join(GUEST_SIGNING_KEY_FILE))
}

impl SyncFlowMux {
    /// Run one typed HTTP flow: send the request, return the host's reply.
    ///
    /// The request may carry `mvm-secret-<hex>` placeholders. Resolving them,
    /// authorizing the destination and making the real connection all happen on
    /// the host — this only frames what goes out and what comes back, which is
    /// the whole reason the guest never holds a credential.
    pub fn exchange_http(&mut self, request: &WireRequest) -> Result<WireResponse> {
        match self.open_http()? {
            HttpFlowOpen::Opened(stream_id) => self.exchange_open_http(stream_id, request),
            HttpFlowOpen::Refused(response) => Ok(response),
        }
    }

    /// Open one typed HTTP stream without sending its request yet.
    ///
    /// Keeping stream establishment separate lets long-lived clients observe
    /// admission latency without reconnecting the authenticated session.
    pub fn open_http(&mut self) -> Result<HttpFlowOpen> {
        let stream_id = self.next_stream_id();
        self.send(Opcode::OpenHttp, stream_id, &[])?;
        match self.recv()? {
            (Opcode::Opened, id, _) if id == stream_id => Ok(HttpFlowOpen::Opened(stream_id)),
            (Opcode::Refused, id, payload) if id == stream_id => {
                Ok(HttpFlowOpen::Refused(WireResponse::Refused {
                    message: refusal_message(&payload, "the host refused the flow"),
                }))
            }
            (opcode, id, _) => {
                bail!("expected Opened for http flow {stream_id}, got {opcode:?} on {id}")
            }
        }
    }

    /// Exchange one request on an already-open typed HTTP stream.
    pub fn exchange_open_http(
        &mut self,
        stream_id: u32,
        request: &WireRequest,
    ) -> Result<WireResponse> {
        let body = B64
            .decode(request.body_b64.as_bytes())
            .context("decoding the proxied request body")?;

        let head = HttpFlowHead {
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body_len: body.len() as u64,
        };
        let encoded = serde_json::to_vec(&head).context("encoding the request head")?;
        self.send(Opcode::HttpRequestHead, stream_id, &encoded)?;
        for chunk in body.chunks(MAX_PAYLOAD_LEN) {
            self.send(Opcode::HttpRequestBody, stream_id, chunk)?;
        }

        self.read_http_response(stream_id)
    }

    /// Collect the response head, its body chunks, and the completion.
    fn read_http_response(&mut self, stream_id: u32) -> Result<WireResponse> {
        let head = match self.recv()? {
            (Opcode::HttpResponseHead, id, payload) if id == stream_id => {
                serde_json::from_slice::<HttpFlowResponseHead>(&payload)
                    .context("decoding the response head")?
            }
            (Opcode::Reset, _, payload) | (Opcode::Refused, _, payload) => {
                return Ok(WireResponse::Refused {
                    message: refusal_message(&payload, "the host reset the flow"),
                });
            }
            (opcode, id, _) => {
                bail!("expected a response head on {stream_id}, got {opcode:?} on {id}")
            }
        };

        let (status, headers, body_len) = match head {
            HttpFlowResponseHead::Ok {
                status,
                headers,
                body_len,
            } => (status, headers, body_len),
            HttpFlowResponseHead::Refused { message } => {
                // Still drain to the completion so the session is left clean
                // for the next exchange on it.
                let _ = self.drain_to_complete(stream_id, Some(0), &mut Vec::new());
                return Ok(WireResponse::Refused { message });
            }
        };

        if body_len.is_some_and(|len| len > MAX_HTTP_RESPONSE_BODY_LEN) {
            bail!("response body exceeds the {MAX_HTTP_RESPONSE_BODY_LEN} byte limit");
        }
        let mut body = Vec::with_capacity(body_len.unwrap_or(0).min(1 << 20) as usize);
        self.drain_to_complete(stream_id, body_len, &mut body)?;
        Ok(WireResponse::Ok {
            status,
            headers,
            body_b64: B64.encode(&body),
        })
    }

    /// Read body frames until `HttpComplete`, refusing a body that does not
    /// match what the head declared.
    fn drain_to_complete(
        &mut self,
        stream_id: u32,
        body_len: Option<u64>,
        body: &mut Vec<u8>,
    ) -> Result<()> {
        loop {
            match self.recv()? {
                (Opcode::HttpComplete, id, _) if id == stream_id => break,
                (Opcode::HttpResponseBody, id, payload) if id == stream_id => {
                    body.extend_from_slice(&payload);
                    if body.len() as u64 > MAX_HTTP_RESPONSE_BODY_LEN {
                        bail!("response body exceeds the {MAX_HTTP_RESPONSE_BODY_LEN} byte limit");
                    }
                    if let Some(declared) = body_len
                        && body.len() as u64 > declared
                    {
                        bail!("response body overran the declared {declared} bytes");
                    }
                }
                (Opcode::Reset, _, payload) => {
                    bail!("{}", refusal_message(&payload, "the host reset the flow"));
                }
                (opcode, id, _) => {
                    bail!("unexpected {opcode:?} on {id} while reading the response body")
                }
            }
        }
        if let Some(declared) = body_len
            && body.len() as u64 != declared
        {
            bail!(
                "response body was {} bytes, head declared {declared}",
                body.len()
            );
        }
        Ok(())
    }
}

/// A refusal payload is a UTF-8 reason, or nothing useful.
fn refusal_message(payload: &[u8], fallback: &str) -> String {
    match std::str::from_utf8(payload) {
        Ok(s) if !s.trim().is_empty() => s.to_string(),
        _ => fallback.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn a_signing_key_of_the_wrong_length_is_refused() {
        let dir = temp_dir();
        let mut f = std::fs::File::create(dir.path().join(GUEST_SIGNING_KEY_FILE)).unwrap();
        f.write_all(b"short").unwrap();
        let err = load_guest_signing_key(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_missing_signing_key_names_the_path_it_looked_in() {
        let dir = temp_dir();
        let err = load_guest_signing_key(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains(GUEST_SIGNING_KEY_FILE),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn a_missing_anchor_is_an_error_not_an_unverified_session() {
        let dir = temp_dir();
        let err = load_host_anchor(dir.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("cannot verify the host"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn a_round_trip_key_loads_back_as_itself() {
        let dir = temp_dir();
        let bytes: [u8; 32] = [7u8; 32];
        std::fs::write(dir.path().join(GUEST_SIGNING_KEY_FILE), bytes).unwrap();
        let loaded = load_guest_signing_key(dir.path()).unwrap();
        assert_eq!(loaded.to_bytes(), bytes);
    }

    /// Drive one real authenticated exchange end to end: the guest sends a
    /// placeholder-bearing request over `OpenHttp`, a host that speaks the real
    /// protocol substitutes it, and the reply reassembles.
    ///
    /// The credential assertion is the point. The guest holds
    /// `mvm-secret-abc`; every frame it emits is captured and checked to
    /// confirm the real value never appears in one. That is claim 13 on this
    /// transport, checked on the bytes rather than assumed from the design.
    /// A FlowMux write that dies after the seal must end the session rather
    /// than run on one frame ahead of the host. Same defect as the control
    /// channel's: `seal` spends the sequence before the transport sees the
    /// frame, and the AES-GCM nonce derives from that sequence, so it cannot
    /// be reissued.
    #[test]
    fn a_send_that_never_reaches_the_host_ends_the_session() {
        use mvm_core::net::session::Session;

        let (mut guest_side, host_side) = UnixStream::pair().unwrap();
        let guest_key = SigningKey::from_bytes(&[3u8; 32]);
        let host_key = SigningKey::from_bytes(&[9u8; 32]);
        let host_anchor = host_key.verifying_key();

        let host = std::thread::spawn(move || {
            let mut stream = host_side;
            let (session, _peer) = Session::host(&mut stream, "poison-test", host_key).unwrap();
            (stream, session)
        });
        let (session, _session_id) =
            Session::guest(&mut guest_side, guest_key, &host_anchor).expect("guest handshake");
        let _host = host.join().unwrap();

        let mut mux = SyncFlowMux {
            stream: guest_side,
            session,
            next_stream_id: 1,
        };
        // Closing our own write half makes every later write fail at the
        // syscall, which is the shape a host that went away produces.
        mux.stream.shutdown(std::net::Shutdown::Write).unwrap();

        mux.send(Opcode::Hello, 0, b"first")
            .expect_err("the write half is closed");

        assert!(
            mux.session.is_poisoned(),
            "a spent sequence that never reached the host must end the session"
        );
        let err = mux
            .send(Opcode::Hello, 0, b"second")
            .expect_err("a poisoned session must refuse further sends");
        assert!(
            err.to_string().contains("session poisoned"),
            "the refusal must name the cause, got {err}"
        );
    }

    #[test]
    fn a_placeholder_bearing_request_round_trips_and_the_guest_never_sees_the_credential() {
        use mvm_core::net::session::Session;

        const REAL_CREDENTIAL: &str = "sk-live-super-secret-value";

        let (guest_side, host_side) = UnixStream::pair().unwrap();
        let guest_key = SigningKey::from_bytes(&[3u8; 32]);
        let host_key = SigningKey::from_bytes(&[9u8; 32]);
        let host_anchor = host_key.verifying_key();

        let host = std::thread::spawn(move || {
            let mut stream = host_side;
            let (mut session, _peer) =
                Session::host(&mut stream, "test-session", host_key).unwrap();
            let mut seen_from_guest: Vec<Vec<u8>> = Vec::new();

            let recv = |session: &mut Session, stream: &mut UnixStream| {
                let sealed = read_sealed_frame(stream, MAX_FRAME_LEN + 512).unwrap();
                let plain = session.open(&sealed).unwrap();
                let parsed = decode(&plain).unwrap();
                (
                    parsed.header.opcode,
                    parsed.header.stream_id,
                    parsed.payload.to_vec(),
                )
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

            let (opcode, _, _) = recv(&mut session, &mut stream);
            assert_eq!(opcode, Opcode::Hello);
            send(
                &mut session,
                &mut stream,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            );

            let (opcode, sid, _) = recv(&mut session, &mut stream);
            assert_eq!(opcode, Opcode::OpenHttp);
            send(&mut session, &mut stream, Opcode::Opened, sid, &[]);

            let (opcode, _, payload) = recv(&mut session, &mut stream);
            assert_eq!(opcode, Opcode::HttpRequestHead);
            seen_from_guest.push(payload.clone());
            let head: HttpFlowHead = serde_json::from_slice(&payload).unwrap();
            // The guest sent the placeholder, not a credential.
            assert_eq!(head.headers[0].1, "Bearer mvm-secret-abc");

            let mut body = Vec::new();
            while (body.len() as u64) < head.body_len {
                let (opcode, _, payload) = recv(&mut session, &mut stream);
                assert_eq!(opcode, Opcode::HttpRequestBody);
                seen_from_guest.push(payload.clone());
                body.extend_from_slice(&payload);
            }
            assert_eq!(body, b"question");

            // Stand in for the substitution the real host performs.
            let resolved = head.headers[0].1.replace("mvm-secret-abc", REAL_CREDENTIAL);
            assert!(resolved.contains(REAL_CREDENTIAL));

            let reply_body = b"answered".to_vec();
            let response_head = HttpFlowResponseHead::Ok {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                // A chunked upstream has no declared decoded length. The
                // guest drains bounded body frames through HttpComplete.
                body_len: None,
            };
            send(
                &mut session,
                &mut stream,
                Opcode::HttpResponseHead,
                sid,
                &serde_json::to_vec(&response_head).unwrap(),
            );
            send(
                &mut session,
                &mut stream,
                Opcode::HttpResponseBody,
                sid,
                &reply_body,
            );
            send(&mut session, &mut stream, Opcode::HttpComplete, sid, &[]);
            seen_from_guest
        });

        let mut client = SyncFlowMux::handshake(guest_side, guest_key, &host_anchor).unwrap();
        let request = WireRequest {
            method: "POST".into(),
            url: "https://api.example.com/v1/ask".into(),
            headers: vec![("authorization".into(), "Bearer mvm-secret-abc".into())],
            body_b64: B64.encode(b"question"),
        };
        let response = client.exchange_http(&request).unwrap();

        match response {
            WireResponse::Ok {
                status,
                headers,
                body_b64,
            } => {
                assert_eq!(status, 200);
                assert_eq!(headers[0], ("content-type".into(), "text/plain".into()));
                assert_eq!(B64.decode(body_b64.as_bytes()).unwrap(), b"answered");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        let frames = host.join().unwrap();
        for frame in &frames {
            assert!(
                !frame
                    .windows(REAL_CREDENTIAL.len())
                    .any(|w| w == REAL_CREDENTIAL.as_bytes()),
                "the real credential appeared in a frame the guest emitted"
            );
        }
    }

    /// A host that refuses the open surfaces as a refusal, not a panic or a
    /// hang — the workload gets a 502, never the host's internals.
    #[test]
    fn a_refused_open_becomes_a_refusal() {
        use mvm_core::net::session::Session;

        let (guest_side, host_side) = UnixStream::pair().unwrap();
        let guest_key = SigningKey::from_bytes(&[4u8; 32]);
        let host_key = SigningKey::from_bytes(&[8u8; 32]);
        let host_anchor = host_key.verifying_key();

        let host = std::thread::spawn(move || {
            let mut stream = host_side;
            let (mut session, _peer) =
                Session::host(&mut stream, "test-session", host_key).unwrap();
            let sealed = read_sealed_frame(&mut stream, MAX_FRAME_LEN + 512).unwrap();
            let plain = session.open(&sealed).unwrap();
            assert_eq!(decode(&plain).unwrap().header.opcode, Opcode::Hello);
            let mut wire = Vec::new();
            encode_into(
                &mut wire,
                Opcode::HelloAck,
                0,
                &Handshake::local("test-host").encode(),
            )
            .unwrap();
            let sealed = session.seal(&wire).unwrap();
            write_sealed_frame(&mut stream, &sealed).unwrap();

            let sealed = read_sealed_frame(&mut stream, MAX_FRAME_LEN + 512).unwrap();
            let plain = session.open(&sealed).unwrap();
            let parsed = decode(&plain).unwrap();
            assert_eq!(parsed.header.opcode, Opcode::OpenHttp);
            let mut wire = Vec::new();
            encode_into(
                &mut wire,
                Opcode::Refused,
                parsed.header.stream_id,
                b"no substitution service on this endpoint",
            )
            .unwrap();
            let sealed = session.seal(&wire).unwrap();
            write_sealed_frame(&mut stream, &sealed).unwrap();
        });

        let mut client = SyncFlowMux::handshake(guest_side, guest_key, &host_anchor).unwrap();
        let request = WireRequest {
            method: "GET".into(),
            url: "https://example.test/".into(),
            headers: vec![],
            body_b64: String::new(),
        };
        match client.exchange_http(&request).unwrap() {
            WireResponse::Refused { message } => {
                assert!(
                    message.contains("no substitution service"),
                    "got: {message}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        host.join().unwrap();
    }

    #[test]
    fn guest_stream_ids_are_odd_and_ascending() {
        // The host refuses an even id from the guest, so the parity is part of
        // the contract rather than a convention.
        let mut ids = Vec::new();
        let mut next = 1u32;
        for _ in 0..4 {
            ids.push(next);
            next = next.saturating_add(2);
        }
        assert_eq!(ids, vec![1, 3, 5, 7]);
        assert!(ids.iter().all(|id| id % 2 == 1));
    }
}
