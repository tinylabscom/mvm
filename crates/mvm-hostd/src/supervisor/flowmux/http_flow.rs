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
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_contract::protocol::network_flow::{MAX_PAYLOAD_LEN, Opcode};
use mvm_core::net::session::Session;
use mvm_core::substitution_wire::{HttpFlowHead, HttpFlowResponseHead, WireResponse};
use tracing::warn;
use zeroize::Zeroizing;

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
    received: u64,
    sender: Option<tokio::sync::mpsc::Sender<Zeroizing<Vec<u8>>>>,
}

pub(super) struct HttpRequestStream {
    pub(super) head: HttpFlowHead,
    pub(super) body: tokio::sync::mpsc::Receiver<Zeroizing<Vec<u8>>>,
}

/// Why a frame on an HTTP flow could not be accepted.
#[derive(Debug, thiserror::Error)]
pub(super) enum HttpFlowError {
    #[error("HttpRequestHead is not valid JSON: {0}")]
    BadHead(String),
    #[error("request head of {got} bytes exceeds the {max} allowed")]
    HeadTooLarge { got: usize, max: usize },
    #[error("a second HttpRequestHead on the same flow")]
    DuplicateHead,
    #[error("HttpRequestBody before HttpRequestHead")]
    BodyBeforeHead,
    #[error("body of {got} bytes exceeds the declared {declared}")]
    BodyOverrun { got: u64, declared: u64 },
    #[error("declared body of {declared} bytes exceeds the {max} allowed")]
    BodyTooLarge { declared: u64, max: u64 },
    #[error("request body consumer closed before completion")]
    BodyConsumerClosed,
}

/// The largest request body a single typed HTTP flow may declare.
///
/// The body is buffered before it is forwarded, so this is a memory bound on
/// one flow, not a policy about what may be sent — a workload with a genuinely
/// large upload wants a plain TCP flow, which streams.
pub(super) const MAX_HTTP_BODY_LEN: u64 = 32 * 1024 * 1024;

/// Maximum serialized request-head size accepted on a typed flow.
pub(super) const MAX_HTTP_HEAD_LEN: usize = 64 * 1024;

/// Maximum silence between decoded upstream response chunks.
const HTTP_RESPONSE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

impl HttpFlow {
    pub(super) fn new() -> Self {
        Self {
            head: None,
            received: 0,
            sender: None,
        }
    }

    /// Take the request head. Returns an error rather than replacing a head
    /// that already arrived: two heads on one flow is a protocol violation,
    /// not a retry.
    pub(super) fn accept_head(
        &mut self,
        payload: &[u8],
    ) -> Result<HttpRequestStream, HttpFlowError> {
        if self.head.is_some() {
            return Err(HttpFlowError::DuplicateHead);
        }
        if payload.len() > MAX_HTTP_HEAD_LEN {
            return Err(HttpFlowError::HeadTooLarge {
                got: payload.len(),
                max: MAX_HTTP_HEAD_LEN,
            });
        }
        let head: HttpFlowHead =
            serde_json::from_slice(payload).map_err(|e| HttpFlowError::BadHead(e.to_string()))?;
        if head.body_len > MAX_HTTP_BODY_LEN {
            return Err(HttpFlowError::BodyTooLarge {
                declared: head.body_len,
                max: MAX_HTTP_BODY_LEN,
            });
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        self.sender = (head.body_len > 0).then_some(sender);
        self.head = Some(head.clone());
        Ok(HttpRequestStream {
            head,
            body: receiver,
        })
    }

    /// Append a body chunk. Overrunning the declared length is refused rather
    /// than truncated, so a guest cannot describe one request and send another.
    pub(super) fn accept_body(&mut self, payload: &[u8]) -> Result<(), HttpFlowError> {
        let Some(head) = self.head.as_ref() else {
            return Err(HttpFlowError::BodyBeforeHead);
        };
        let got = self.received.saturating_add(payload.len() as u64);
        if got > head.body_len {
            return Err(HttpFlowError::BodyOverrun {
                got,
                declared: head.body_len,
            });
        }
        let sender = self
            .sender
            .as_ref()
            .ok_or(HttpFlowError::BodyConsumerClosed)?;
        sender
            .blocking_send(Zeroizing::new(payload.to_vec()))
            .map_err(|_| HttpFlowError::BodyConsumerClosed)?;
        self.received = got;
        if got == head.body_len {
            self.sender.take();
        }
        Ok(())
    }

    pub(super) fn is_complete(&self) -> bool {
        self.head
            .as_ref()
            .is_some_and(|head| self.received == head.body_len)
    }
}

/// Every HTTP flow this session is assembling, by stream id.
pub(super) type HttpFlows = BTreeMap<u32, HttpFlow>;

/// Cancellation owners for forwarding tasks that outlive request assembly.
/// The entry is installed before the task is spawned, so completion cannot
/// race ahead of registration and leave a stale handle behind.
pub(super) type HttpCancellations = Arc<Mutex<BTreeMap<u32, tokio::sync::watch::Sender<bool>>>>;

pub(super) struct ForwardTask {
    runtime: tokio::runtime::Handle,
    service: Arc<SubstitutionService>,
    session: Arc<Mutex<Session>>,
    writer: Arc<Mutex<UnixStream>>,
    stream_id: u32,
    request: HttpRequestStream,
    cancellation: tokio::sync::watch::Receiver<bool>,
    cancellations: HttpCancellations,
    registry: Arc<Mutex<super::registry::StreamRegistry>>,
}

#[derive(Default)]
pub(super) struct ForwardTaskBuilder {
    runtime: Option<tokio::runtime::Handle>,
    service: Option<Arc<SubstitutionService>>,
    session: Option<Arc<Mutex<Session>>>,
    writer: Option<Arc<Mutex<UnixStream>>>,
    stream_id: Option<u32>,
    request: Option<HttpRequestStream>,
    cancellation: Option<tokio::sync::watch::Receiver<bool>>,
    cancellations: Option<HttpCancellations>,
    registry: Option<Arc<Mutex<super::registry::StreamRegistry>>>,
}

impl ForwardTask {
    pub(super) fn builder() -> ForwardTaskBuilder {
        ForwardTaskBuilder::default()
    }
}

impl ForwardTaskBuilder {
    pub(super) fn runtime(mut self, value: tokio::runtime::Handle) -> Self {
        self.runtime = Some(value);
        self
    }

    pub(super) fn service(mut self, value: Arc<SubstitutionService>) -> Self {
        self.service = Some(value);
        self
    }

    pub(super) fn session(mut self, value: Arc<Mutex<Session>>) -> Self {
        self.session = Some(value);
        self
    }

    pub(super) fn writer(mut self, value: Arc<Mutex<UnixStream>>) -> Self {
        self.writer = Some(value);
        self
    }

    pub(super) fn stream_id(mut self, value: u32) -> Self {
        self.stream_id = Some(value);
        self
    }

    pub(super) fn request(mut self, value: HttpRequestStream) -> Self {
        self.request = Some(value);
        self
    }

    pub(super) fn cancellation(mut self, value: tokio::sync::watch::Receiver<bool>) -> Self {
        self.cancellation = Some(value);
        self
    }

    pub(super) fn cancellations(mut self, value: HttpCancellations) -> Self {
        self.cancellations = Some(value);
        self
    }

    pub(super) fn registry(mut self, value: Arc<Mutex<super::registry::StreamRegistry>>) -> Self {
        self.registry = Some(value);
        self
    }

    pub(super) fn build(self) -> Result<ForwardTask, &'static str> {
        Ok(ForwardTask {
            runtime: self.runtime.ok_or("forward task runtime missing")?,
            service: self.service.ok_or("forward task service missing")?,
            session: self.session.ok_or("forward task session missing")?,
            writer: self.writer.ok_or("forward task writer missing")?,
            stream_id: self.stream_id.ok_or("forward task stream id missing")?,
            request: self.request.ok_or("forward task request missing")?,
            cancellation: self
                .cancellation
                .ok_or("forward task cancellation missing")?,
            cancellations: self
                .cancellations
                .ok_or("forward task cancellation owners missing")?,
            registry: self.registry.ok_or("forward task registry missing")?,
        })
    }
}

pub(super) fn cancel_forwarding(cancellations: &HttpCancellations, stream_id: u32) -> bool {
    let sender = cancellations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&stream_id);
    sender.is_some_and(|sender| sender.send(true).is_ok())
}

/// Cancel an assembling flow, dropping its zeroizing body immediately.
pub(super) fn cancel(flows: &mut HttpFlows, stream_id: u32) -> bool {
    flows.remove(&stream_id).is_some()
}

/// Forward one assembled request and frame the reply back to the guest.
///
/// Runs on the tokio runtime rather than the session's blocking read loop, for
/// two reasons. `SubstitutionService::process` is async and the read loop is
/// inside `spawn_blocking`, where tokio's `block_on` panics. And a request
/// forwarded inline would stall every other flow on the session behind one
/// slow upstream.
pub(super) fn spawn_forward(task: ForwardTask) {
    let ForwardTask {
        runtime,
        service,
        session,
        writer,
        stream_id,
        request,
        mut cancellation,
        cancellations,
        registry,
    } = task;
    let HttpRequestStream { head, body } = request;
    runtime.spawn(async move {
        let request_url = head.url.clone();
        let result = tokio::select! {
            biased;
            canceled = cancellation.changed() => {
                let reason = if canceled.is_ok() {
                    "guest_reset"
                } else {
                    "session_closed"
                };
                service.audit_http_stream_failure(&request_url, reason).await;
                Ok(())
            }
            response = service.process_body_stream(head, body) => {
                match response {
                    Ok(response) => write_stream_response(&session, &writer, stream_id, response).await,
                    Err(refusal) => write_response(&session, &writer, stream_id, refusal),
                }
            }
        };
        cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&stream_id);
        let _ = super::lock_registry(&registry).retire(stream_id);
        if let Err(e) = result {
            warn!(stream_id, error = %e, "FlowMux failed to send HTTP response");
            let _ = write_frame_to(
                &session,
                &writer,
                Opcode::Reset,
                stream_id,
                b"http response failed",
            );
        }
    });
}

/// Frame a bounded upstream stream without collecting its body in host
/// memory. Each receive waits on the channel event with an idle deadline.
async fn write_stream_response(
    session: &Mutex<Session>,
    writer: &Mutex<UnixStream>,
    stream_id: u32,
    mut response: super::super::network_endpoint_proxy::ForwardStreamResponse,
) -> Result<(), super::FlowMuxError> {
    let head = HttpFlowResponseHead::Ok {
        status: response.status,
        headers: response.headers,
        body_len: response.body_len,
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
    loop {
        let next = tokio::time::timeout(HTTP_RESPONSE_IDLE_TIMEOUT, response.body.recv())
            .await
            .map_err(|_| super::FlowMuxError::FrameRefused("http response idle timeout".into()))?;
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|error| super::FlowMuxError::FrameRefused(error.to_string()))?;
        for frame in chunk.chunks(MAX_PAYLOAD_LEN) {
            write_frame_to(session, writer, Opcode::HttpResponseBody, stream_id, frame)?;
        }
    }
    write_frame_to(session, writer, Opcode::HttpComplete, stream_id, &[])
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
                    body_len: Some(body.len() as u64),
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
    fn a_flow_streams_a_head_and_body_through_a_bounded_channel() {
        let mut flow = HttpFlow::new();
        let request = flow.accept_head(&head_json(5)).unwrap();
        assert_eq!(request.head.headers[0].1, "Bearer mvm-secret-abc");
        let mut receiver = request.body;
        assert!(!flow.is_complete(), "body is not in yet");
        flow.accept_body(b"he").unwrap();
        assert!(!flow.is_complete(), "still short");
        flow.accept_body(b"llo").unwrap();
        assert!(flow.is_complete());
        let first = receiver.blocking_recv().unwrap();
        let second = receiver.blocking_recv().unwrap();
        assert_eq!([first.as_slice(), second.as_slice()].concat(), b"hello");
        assert!(receiver.blocking_recv().is_none());
    }

    #[test]
    fn a_bodyless_request_is_complete_as_soon_as_its_head_lands() {
        let mut flow = HttpFlow::new();
        let mut receiver = flow.accept_head(&head_json(0)).unwrap().body;
        assert!(flow.is_complete());
        assert!(receiver.blocking_recv().is_none());
    }

    #[test]
    fn a_body_longer_than_declared_is_refused_not_truncated() {
        let mut flow = HttpFlow::new();
        let _receiver = flow.accept_head(&head_json(2)).unwrap().body;
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
        let _ = flow.accept_head(&head_json(0)).unwrap();
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
    fn an_oversized_serialized_head_is_refused_before_json_parsing() {
        let mut flow = HttpFlow::new();
        let payload = vec![b' '; MAX_HTTP_HEAD_LEN + 1];
        assert!(matches!(
            flow.accept_head(&payload),
            Err(HttpFlowError::HeadTooLarge { .. })
        ));
    }

    #[test]
    fn an_incomplete_body_uses_zeroizing_channel_storage() {
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}

        let mut flow = HttpFlow::new();
        let mut receiver = flow.accept_head(&head_json(8)).unwrap().body;
        flow.accept_body(b"secret").unwrap();
        let chunk = receiver.blocking_recv().unwrap();
        assert_zeroizing(&chunk);
    }

    #[test]
    fn cancellation_removes_an_incomplete_flow_immediately() {
        let mut flows = HttpFlows::new();
        let mut flow = HttpFlow::new();
        let _receiver = flow.accept_head(&head_json(8)).unwrap().body;
        flow.accept_body(b"secret").unwrap();
        flows.insert(7, flow);

        assert!(cancel(&mut flows, 7));
        assert!(flows.is_empty());
        assert!(!cancel(&mut flows, 7), "a second cancel is idempotent");
    }

    #[tokio::test]
    async fn forwarding_cancellation_is_event_driven_and_releases_its_owner() {
        let cancellations = HttpCancellations::default();
        let (sender, mut receiver) = tokio::sync::watch::channel(false);
        cancellations
            .lock()
            .expect("cancellation map lock")
            .insert(9, sender);

        assert!(cancel_forwarding(&cancellations, 9));
        receiver.changed().await.expect("cancellation event");
        assert!(*receiver.borrow());
        assert!(
            cancellations
                .lock()
                .expect("cancellation map lock")
                .is_empty()
        );
        assert!(!cancel_forwarding(&cancellations, 9));
    }

    #[test]
    fn a_forward_task_builder_refuses_missing_runtime_state() {
        assert!(matches!(
            ForwardTask::builder().build(),
            Err("forward task runtime missing")
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
