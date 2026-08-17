//! Typed HTTP flows on the FlowMux `Http` class.
//!
//! One `OpenHttp` flow carries one request that the host may transform before
//! forwarding: the guest sends a head that may name `mvm-secret-<hex>`
//! placeholders, the host resolves them against the credentials only it holds,
//! makes the real connection itself, and sends the response back.
//!
//! The substitution itself is **not** implemented here. This module is framing
//! only: it assembles frames into the request the existing
//! [`SubstitutionService`] already takes, calls it, and frames what comes back.
//! Everything that makes the secret path what it is — placeholder resolution,
//! destination binding, the claim-10 gate, payload-free audit — stays where it
//! already is and is called, not reimplemented.

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_contract::protocol::network_flow::{MAX_PAYLOAD_LEN, Opcode};
use mvm_core::net::session::Session;
use mvm_core::substitution_wire::{HttpFlowHead, HttpFlowResponseHead, WireRequest, WireResponse};
use tracing::warn;

use super::super::network_endpoint_proxy::SubstitutionService;
use super::write_frame_to;

/// A typed HTTP flow the host is still assembling.
///
/// The head arrives whole in one frame; the body follows in bounded chunks and
/// is complete when exactly `body_len` bytes have arrived. Counting rather
/// than waiting for a half-close is what lets a truncated request be refused
/// instead of forwarded.
pub(super) struct HttpFlow {
    head: Option<HttpFlowHead>,
    body: Vec<u8>,
}

/// Why a frame on an HTTP flow could not be accepted.
#[derive(Debug, thiserror::Error)]
pub(super) enum HttpFlowError {
    #[error("HttpRequestHead is not valid JSON: {0}")]
    BadHead(String),
    #[error("a second HttpRequestHead on the same flow")]
    DuplicateHead,
    #[error("HttpRequestBody before HttpRequestHead")]
    BodyBeforeHead,
    #[error("body of {got} bytes exceeds the declared {declared}")]
    BodyOverrun { got: u64, declared: u64 },
    #[error("declared body of {declared} bytes exceeds the {max} allowed")]
    BodyTooLarge { declared: u64, max: u64 },
}

/// The largest request body a single typed HTTP flow may declare.
///
/// The body is buffered before it is forwarded, so this is a memory bound on
/// one flow, not a policy about what may be sent — a workload with a genuinely
/// large upload wants a plain TCP flow, which streams.
pub(super) const MAX_HTTP_BODY_LEN: u64 = 32 * 1024 * 1024;

impl HttpFlow {
    pub(super) fn new() -> Self {
        Self {
            head: None,
            body: Vec::new(),
        }
    }

    /// Take the request head. Returns an error rather than replacing a head
    /// that already arrived: two heads on one flow is a protocol violation,
    /// not a retry.
    pub(super) fn accept_head(&mut self, payload: &[u8]) -> Result<(), HttpFlowError> {
        if self.head.is_some() {
            return Err(HttpFlowError::DuplicateHead);
        }
        let head: HttpFlowHead =
            serde_json::from_slice(payload).map_err(|e| HttpFlowError::BadHead(e.to_string()))?;
        if head.body_len > MAX_HTTP_BODY_LEN {
            return Err(HttpFlowError::BodyTooLarge {
                declared: head.body_len,
                max: MAX_HTTP_BODY_LEN,
            });
        }
        self.body
            .reserve(head.body_len.min(MAX_PAYLOAD_LEN as u64) as usize);
        self.head = Some(head);
        Ok(())
    }

    /// Append a body chunk. Overrunning the declared length is refused rather
    /// than truncated, so a guest cannot describe one request and send another.
    pub(super) fn accept_body(&mut self, payload: &[u8]) -> Result<(), HttpFlowError> {
        let Some(head) = self.head.as_ref() else {
            return Err(HttpFlowError::BodyBeforeHead);
        };
        let got = self.body.len() as u64 + payload.len() as u64;
        if got > head.body_len {
            return Err(HttpFlowError::BodyOverrun {
                got,
                declared: head.body_len,
            });
        }
        self.body.extend_from_slice(payload);
        Ok(())
    }

    /// The assembled request, once every declared body byte has arrived.
    pub(super) fn take_when_complete(&mut self) -> Option<WireRequest> {
        let head = self.head.as_ref()?;
        if (self.body.len() as u64) != head.body_len {
            return None;
        }
        let head = self.head.take()?;
        Some(WireRequest {
            method: head.method,
            url: head.url,
            headers: head.headers,
            body_b64: B64.encode(std::mem::take(&mut self.body)),
        })
    }
}

/// Every HTTP flow this session is assembling, by stream id.
pub(super) type HttpFlows = BTreeMap<u32, HttpFlow>;

/// Forward one assembled request and frame the reply back to the guest.
///
/// Runs on the tokio runtime rather than the session's blocking read loop, for
/// two reasons. `SubstitutionService::process` is async and the read loop is
/// inside `spawn_blocking`, where tokio's `block_on` panics. And a request
/// forwarded inline would stall every other flow on the session behind one
/// slow upstream.
pub(super) fn spawn_forward(
    handle: &tokio::runtime::Handle,
    service: Arc<SubstitutionService>,
    session: Arc<Mutex<Session>>,
    writer: Arc<Mutex<UnixStream>>,
    stream_id: u32,
    request: WireRequest,
) {
    handle.spawn(async move {
        let response = service.process(request).await;
        if let Err(e) = write_response(&session, &writer, stream_id, response) {
            warn!(stream_id, error = %e, "FlowMux failed to send HTTP response");
        }
    });
}

/// Frame a `WireResponse` as head, body chunks, and a completion.
fn write_response(
    session: &Mutex<Session>,
    writer: &Mutex<UnixStream>,
    stream_id: u32,
    response: WireResponse,
) -> Result<(), super::FlowMuxError> {
    let (head, body) = match response {
        WireResponse::Ok {
            status,
            headers,
            body_b64,
        } => {
            // A body the host cannot decode is the host's own bug, and sending
            // a truncated one would look like a short read from upstream.
            let body = B64.decode(body_b64.as_bytes()).unwrap_or_default();
            (
                HttpFlowResponseHead::Ok {
                    status,
                    headers,
                    body_len: body.len() as u64,
                },
                body,
            )
        }
        WireResponse::Refused { message } => {
            (HttpFlowResponseHead::Refused { message }, Vec::new())
        }
    };

    let encoded =
        serde_json::to_vec(&head).map_err(|e| super::FlowMuxError::FrameRefused(e.to_string()))?;
    write_frame_to(
        session,
        writer,
        Opcode::HttpResponseHead,
        stream_id,
        &encoded,
    )?;
    for chunk in body.chunks(MAX_PAYLOAD_LEN) {
        write_frame_to(session, writer, Opcode::HttpResponseBody, stream_id, chunk)?;
    }
    write_frame_to(session, writer, Opcode::HttpComplete, stream_id, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_json(body_len: u64) -> Vec<u8> {
        serde_json::to_vec(&HttpFlowHead {
            method: "POST".into(),
            url: "https://api.example.com/v1".into(),
            headers: vec![("authorization".into(), "Bearer mvm-secret-abc".into())],
            body_len,
        })
        .unwrap()
    }

    #[test]
    fn a_flow_assembles_a_head_and_its_body_into_one_request() {
        let mut flow = HttpFlow::new();
        flow.accept_head(&head_json(5)).unwrap();
        assert!(flow.take_when_complete().is_none(), "body is not in yet");
        flow.accept_body(b"he").unwrap();
        assert!(flow.take_when_complete().is_none(), "still short");
        flow.accept_body(b"llo").unwrap();

        let req = flow.take_when_complete().expect("complete");
        assert_eq!(req.method, "POST");
        assert_eq!(B64.decode(req.body_b64.as_bytes()).unwrap(), b"hello");
        // The placeholder crosses untouched — resolving it is the host
        // substitution service's job, not the framing's.
        assert_eq!(req.headers[0].1, "Bearer mvm-secret-abc");
    }

    #[test]
    fn a_bodyless_request_is_complete_as_soon_as_its_head_lands() {
        let mut flow = HttpFlow::new();
        flow.accept_head(&head_json(0)).unwrap();
        let req = flow.take_when_complete().expect("complete");
        assert!(req.body_b64.is_empty());
    }

    #[test]
    fn a_body_longer_than_declared_is_refused_not_truncated() {
        let mut flow = HttpFlow::new();
        flow.accept_head(&head_json(2)).unwrap();
        assert!(matches!(
            flow.accept_body(b"toolong"),
            Err(HttpFlowError::BodyOverrun { .. })
        ));
    }

    #[test]
    fn a_body_before_a_head_is_refused() {
        let mut flow = HttpFlow::new();
        assert!(matches!(
            flow.accept_body(b"x"),
            Err(HttpFlowError::BodyBeforeHead)
        ));
    }

    #[test]
    fn a_second_head_on_one_flow_is_refused() {
        let mut flow = HttpFlow::new();
        flow.accept_head(&head_json(0)).unwrap();
        assert!(matches!(
            flow.accept_head(&head_json(0)),
            Err(HttpFlowError::DuplicateHead)
        ));
    }

    #[test]
    fn a_malformed_head_is_refused() {
        let mut flow = HttpFlow::new();
        assert!(matches!(
            flow.accept_head(b"{not json"),
            Err(HttpFlowError::BadHead(_))
        ));
    }

    #[test]
    fn a_head_declaring_an_oversized_body_is_refused_before_any_of_it_arrives() {
        let mut flow = HttpFlow::new();
        assert!(matches!(
            flow.accept_head(&head_json(MAX_HTTP_BODY_LEN + 1)),
            Err(HttpFlowError::BodyTooLarge { .. })
        ));
    }

    #[test]
    fn an_unknown_field_in_a_head_is_refused() {
        let mut flow = HttpFlow::new();
        let mut value: serde_json::Value = serde_json::from_slice(&head_json(0)).unwrap();
        value["surprise"] = serde_json::json!(1);
        let payload = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            flow.accept_head(&payload),
            Err(HttpFlowError::BadHead(_))
        ));
    }
}
