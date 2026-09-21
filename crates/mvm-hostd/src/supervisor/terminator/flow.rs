//! Drive one terminated egress flow.
//!
//! The guest opened an opaque TCP flow to a host that carries a bound secret.
//! Instead of refusing it, the endpoint keeps its half of a local socket pair
//! as the flow's upstream and hands the other half here. From this side the
//! flow is an ordinary blocking byte stream: terminate the guest's TLS on it
//! when the flow is encrypted, read one HTTP/1.1 request at a time, and put
//! each request through the same substitution pipeline the typed HTTP flows
//! use, so the egress gate, the destination bind check, redaction, replacement
//! and AI metering apply once and in one place.
//!
//! The pipeline itself is not implemented here. This module is termination and
//! framing: it builds the request the substitution service already takes,
//! calls it, and writes what comes back — chunked, so a streamed model
//! response reaches the guest as it arrives rather than all at once at the end.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mvm_core::crypto::egress_ca::VmEgressCa;
use mvm_core::substitution_wire::{HttpFlowHead, WireResponse};
use tracing::warn;
use zeroize::Zeroizing;

use super::read::{ReadError, read_http_request};
use super::request::{method_of, proxy_request_from_connect_authority};
use super::tls::{is_framing_header, reason_phrase, server_config_for_sni, smuggles_crlf};
use crate::supervisor::network_endpoint_proxy::{
    ForwardStreamResponse, SubstitutionService, TerminationMode,
};

/// Status written back when the request's `Host` disagrees with the authority
/// the flow was opened and admitted against.
const MISDIRECTED_REQUEST: u16 = 421;
/// Status written back when the substitution pipeline refused the request.
const BAD_GATEWAY: u16 = 502;
/// Status written back for a request this reader cannot frame.
const NOT_IMPLEMENTED: u16 = 501;

/// Fixed audit-label reasons. Each is a host-chosen word, so a refusal record
/// can never carry a byte the workload sent.
const REASON_AUTHORITY_MISMATCH: &str = "authority_mismatch";
const REASON_UNFRAMEABLE_REQUEST: &str = "unframeable_request";
const REASON_PIPELINED: &str = "pipelined_request";

/// How long a terminated flow waits on a silent guest before giving up.
///
/// The read is blocking and owns a thread, so without a deadline a guest can
/// open flows that never speak and hold a thread each. It bounds the wait
/// between requests too, which is what ends an idle keep-alive.
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How many terminated flows **one VM** may hold open at once, across every
/// FlowMux session on its endpoint.
///
/// Per VM rather than per session, because a per-session budget is multiplied
/// by `MAX_CONCURRENT_FLOWMUX_SESSIONS` and a guest reaches the product just
/// by reconnecting — the counter therefore lives on `FlowMuxVmResources`.
///
/// Deliberately far below `RegistryLimits::max_tcp`: an opaque flow costs one
/// thread and a socket, while a terminated one costs two threads, a rustls
/// session and a bounded request buffer. Sharing `max_tcp` would let a guest
/// spend the opaque budget on the expensive shape.
pub(crate) const MAX_TERMINATED_FLOWS: usize = 64;

/// Why a terminated flow ended other than by the guest closing it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FlowError {
    #[error("terminated flow transport failed: {0}")]
    Transport(#[from] std::io::Error),
    #[error("terminated flow could not start its tls leg: {0}")]
    Tls(String),
    #[error("terminated request could not be read: {0}")]
    Read(#[source] ReadError),
    #[error("terminated request refused: {0}")]
    Request(String),
    #[error("terminated flow lost its upstream mid-response: {0}")]
    Upstream(String),
}

/// One live terminated flow's claim on [`MAX_TERMINATED_FLOWS`].
///
/// An RAII guard rather than a matched pair of counter updates: the flow can
/// end at a dozen points, and a slot released on only some of them leaks the
/// ceiling downward until no flow can be terminated at all.
pub(crate) struct FlowSlot(Arc<AtomicUsize>);

impl FlowSlot {
    /// Claim a slot, or `None` when the ceiling is already reached.
    pub(crate) fn claim(live: &Arc<AtomicUsize>) -> Option<Self> {
        let mut current = live.load(Ordering::Acquire);
        loop {
            if current >= MAX_TERMINATED_FLOWS {
                return None;
            }
            match live.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(Arc::clone(live))),
                Err(seen) => current = seen,
            }
        }
    }
}

impl Drop for FlowSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How many minted configurations one VM keeps.
///
/// The cache is bounded because the authority is guest-chosen. A binding may
/// name a wildcard, and `host_is_bound` matches every label under it, so a
/// guest can walk `a.example.com`, `b.example.com`, … and mint a distinct
/// authority every time. Each entry retains a certificate chain and a private
/// key, so an unbounded map grows for as long as the guest keeps inventing
/// names — and it never helps, because none of those names recurs.
const MAX_CACHED_LEAVES: usize = 64;

/// Minted TLS server configurations, keyed by issuing intermediate and
/// authority.
///
/// Minting a leaf is a key generation plus a signature, so a client that
/// reconnects per request would otherwise pay for a certificate it has already
/// been shown. The intermediate is part of the key because it is what the leaf
/// chains to: were one ever rotated, an authority-only key would keep serving
/// a leaf chained to the retired issuer, which the guest no longer trusts.
#[derive(Default)]
pub(crate) struct LeafCache {
    entries: Mutex<CacheEntries>,
}

/// The cache's contents: the configurations, and the order they were minted in
/// so the oldest can be dropped when the bound is reached.
#[derive(Default)]
struct CacheEntries {
    by_key: BTreeMap<String, Arc<rustls::ServerConfig>>,
    minted: std::collections::VecDeque<String>,
}

impl LeafCache {
    /// The configuration presenting a leaf for `authority` under
    /// `intermediate`, minting it at most once per bounded cache lifetime.
    fn config_for(
        &self,
        intermediate: &VmEgressCa,
        authority: &str,
    ) -> Result<Arc<rustls::ServerConfig>, FlowError> {
        let key = cache_key(intermediate, authority);
        if let Some(config) = self.lock().by_key.get(&key) {
            return Ok(Arc::clone(config));
        }
        let config = Arc::new(
            server_config_for_sni(intermediate, authority)
                .map_err(|error| FlowError::Tls(error.to_string()))?,
        );

        let mut entries = self.lock();
        // A concurrent minter may have inserted first; either config is equally
        // valid, so take whichever is in the map and let the other drop.
        if let Some(existing) = entries.by_key.get(&key) {
            return Ok(Arc::clone(existing));
        }
        while entries.minted.len() >= MAX_CACHED_LEAVES {
            // Oldest first. A live flow holds its own `Arc`, so eviction never
            // pulls a configuration out from under a connection in progress —
            // it only costs the next flow to that authority a fresh mint.
            let Some(evicted) = entries.minted.pop_front() else {
                break;
            };
            entries.by_key.remove(&evicted);
        }
        entries.by_key.insert(key.clone(), Arc::clone(&config));
        entries.minted.push_back(key);
        Ok(config)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheEntries> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The cache key: which issuer would sign the leaf, and for which name.
///
/// The issuer is identified by a digest of its certificate rather than the
/// certificate itself, so the key stays short and carries no key material.
fn cache_key(intermediate: &VmEgressCa, authority: &str) -> String {
    use sha2::{Digest, Sha256};
    let issuer = hex::encode(Sha256::digest(intermediate.cert_pem().as_bytes()));
    format!("{issuer}/{authority}")
}

/// One terminated flow: who it is talking to, how, and what decides its fate.
///
/// Built through [`TerminatedFlow::builder`] rather than a positional
/// constructor: the string-ish authority and the three handles are exactly the
/// ones a caller would transpose.
pub(crate) struct TerminatedFlow {
    service: Arc<SubstitutionService>,
    runtime: tokio::runtime::Handle,
    leaves: Arc<LeafCache>,
    authority: Authority,
    mode: TerminationMode,
}

/// The `host:port` a flow was opened and admitted against.
#[derive(Clone)]
struct Authority {
    host: String,
    port: u16,
}

impl std::fmt::Display for Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl TerminatedFlow {
    #[must_use]
    pub(crate) fn builder() -> TerminatedFlowBuilder {
        TerminatedFlowBuilder::default()
    }

    /// The URL scheme a request on this flow is re-originated under.
    fn scheme(&self) -> &'static str {
        match self.mode {
            TerminationMode::Tls => "https",
            TerminationMode::Cleartext => "http",
        }
    }

    /// Serve `transport` until the guest closes it or the flow fails.
    ///
    /// The transport gets a read deadline first: everything below this point
    /// blocks, and a guest that opens a flow and says nothing would otherwise
    /// hold a thread for the life of the VM.
    pub(crate) fn serve(&self, transport: UnixStream) -> Result<(), FlowError> {
        transport.set_read_timeout(Some(FLOW_IDLE_TIMEOUT))?;
        transport.set_write_timeout(Some(FLOW_IDLE_TIMEOUT))?;
        match self.mode {
            TerminationMode::Tls => self.serve_tls(transport),
            TerminationMode::Cleartext => {
                let mut transport = transport;
                self.serve_requests(&mut transport)
            }
        }
    }

    /// Terminate the guest's TLS under a leaf minted for the flow's authority,
    /// then serve requests on the decrypted stream.
    ///
    /// The leaf is minted for the authority rather than for the name in the
    /// ClientHello, because the authority is what the flow was admitted
    /// against. A guest that sends a different SNI gets a certificate it will
    /// reject, which is the right answer: the flow it opened is not the flow
    /// it is now trying to use.
    fn serve_tls(&self, transport: UnixStream) -> Result<(), FlowError> {
        let intermediate = self
            .service
            .tls_intermediate()
            .ok_or_else(|| FlowError::Tls("endpoint holds no egress intermediate".to_string()))?;
        let config = self.leaves.config_for(intermediate, &self.authority.host)?;
        let connection = rustls::ServerConnection::new(config)
            .map_err(|error| FlowError::Tls(error.to_string()))?;
        let mut tls = rustls::StreamOwned::new(connection, transport);
        self.serve_requests(&mut tls)
    }

    /// Read requests off `io` until it ends, forwarding each one.
    fn serve_requests<T: Read + Write>(&self, io: &mut T) -> Result<(), FlowError> {
        loop {
            let read = match read_http_request(io) {
                Ok(read) => read,
                // The guest finished with the connection. Not an error.
                Err(ReadError::Closed) => return Ok(()),
                // Nothing was parsed, so the method is unknown and the
                // refusal has to be empty.
                Err(error) => return self.refuse_unreadable(io, error, None),
            };
            if !read.residue.is_empty() {
                // Pipelining is refused rather than served: the bytes behind
                // this request have not been through header substitution, and
                // serving them would mean deciding what a second request on a
                // credentialed flow is allowed to be without having read it.
                // The first request parsed, so its method is known and the
                // refusal can carry its explanation for every method but
                // `HEAD`.
                return self.refuse_unreadable(io, ReadError::Pipelined, method_of(&read.request));
            }
            let request = match proxy_request_from_connect_authority(
                &read.request,
                self.scheme(),
                &self.authority.host,
            ) {
                Ok(request) => request,
                Err(error) => {
                    // The request named a destination the flow was not
                    // admitted against. Record it — this is the one event on
                    // this path worth a chain entry — answer, and stop, so a
                    // client cannot keep probing on the same connection for a
                    // name the check lets through.
                    self.audit(REASON_AUTHORITY_MISMATCH);
                    let message = error.to_string();
                    // The parse is what failed, so the method is not known
                    // here; a refusal with no body is correct for every method
                    // including `HEAD`.
                    write_refusal(io, MISDIRECTED_REQUEST, &message, None)?;
                    return Err(FlowError::Request(message));
                }
            };
            let method = request.method.clone();
            let head = HttpFlowHead {
                method: request.method,
                url: request.url,
                headers: request.headers,
                body_len: request.body.len() as u64,
            };
            match self.forward(head, request.body) {
                Ok(response) => self.write_stream_response(io, &method, response)?,
                Err(message) => {
                    write_refusal(io, BAD_GATEWAY, &message, Some(&method))?;
                    return Ok(());
                }
            }
        }
    }

    /// Answer a request this reader cannot frame, and stop.
    ///
    /// Answering rather than closing because the causes are all things a
    /// client can correct — a transfer-coded body, a pipelined follow-up, a
    /// request over the size bound — and a bare close reads to the client as a
    /// network fault. A truncated request gets no answer, because by
    /// definition the peer is already gone.
    fn refuse_unreadable<T: Write>(
        &self,
        io: &mut T,
        error: ReadError,
        method: Option<&str>,
    ) -> Result<(), FlowError> {
        self.audit(refusal_reason(&error));
        if !matches!(error, ReadError::Truncated | ReadError::Io(_)) {
            write_refusal(io, NOT_IMPLEMENTED, &error.to_string(), method)?;
        }
        Err(FlowError::Read(error))
    }

    /// Record a chain-signed refusal against this flow's authority.
    ///
    /// `reason` is one of this module's fixed labels, and the authority is
    /// what the connect-time flow entry already names, so the record carries
    /// nothing from inside the flow.
    fn audit(&self, reason: &'static str) {
        self.runtime.block_on(
            self.service
                .audit_flow_refused(&self.authority.host, reason),
        );
    }

    /// Hand one request to the substitution pipeline.
    ///
    /// The body goes over the same bounded channel the typed HTTP flows use,
    /// in one chunk, because the terminator already has the whole request in
    /// hand — the request reader is bounded by `Content-Length` before this is
    /// reached. The response body stays a stream.
    fn forward(&self, head: HttpFlowHead, body: Vec<u8>) -> Result<ForwardStreamResponse, String> {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        if !body.is_empty() {
            sender
                .try_send(Zeroizing::new(body))
                .map_err(|error| format!("request body could not be queued: {error}"))?;
        }
        drop(sender);
        self.runtime
            .block_on(self.service.process_body_stream(head, receiver))
            .map_err(|refusal| match refusal {
                WireResponse::Refused { message } => message,
                // A refusal is the only variant this path returns; an `Ok`
                // here would mean the pipeline answered without forwarding.
                WireResponse::Ok { status, .. } => {
                    format!("substitution answered {status} without forwarding")
                }
            })
    }

    /// Write the response head and then each body chunk as it arrives.
    ///
    /// Chunked, not `Content-Length`: the upstream length is often unknown and
    /// buffering to discover it would hold a streamed response until it ended,
    /// which is the whole difference between watching an agent work and
    /// waiting for it. The exception is a response that may not carry a body
    /// at all — see [`carries_a_body`]. Framing one anyway leaves the
    /// terminating chunk in the stream, and the client reads it as the start
    /// of its next response.
    fn write_stream_response<T: Write>(
        &self,
        io: &mut T,
        method: &str,
        mut response: ForwardStreamResponse,
    ) -> Result<(), FlowError> {
        let framed = carries_a_body(method, response.status);
        let mut head = format!(
            "HTTP/1.1 {} {}\r\n",
            response.status,
            reason_phrase(response.status)
        );
        for (name, value) in &response.headers {
            if is_framing_header(name) || smuggles_crlf(name, value) {
                continue;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if framed {
            head.push_str("transfer-encoding: chunked\r\n");
        }
        head.push_str("\r\n");
        io.write_all(head.as_bytes())?;
        io.flush()?;

        while let Some(next) = self.runtime.block_on(response.body.recv()) {
            let chunk = next.map_err(|error| FlowError::Upstream(error.to_string()))?;
            // A bodyless response is still drained, so the forward leg's task
            // finishes rather than being cancelled by a dropped receiver.
            if chunk.is_empty() || !framed {
                continue;
            }
            io.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())?;
            io.write_all(&chunk)?;
            io.write_all(b"\r\n")?;
            io.flush()?;
        }
        if framed {
            // The terminating chunk is the only thing that tells the guest the
            // response ended rather than was cut off, so it is written last
            // and only on a body that completed.
            io.write_all(b"0\r\n\r\n")?;
            io.flush()?;
        }
        Ok(())
    }
}

/// Whether a response to `method` with `status` may carry a body.
///
/// A `HEAD` response and the 1xx/204/304 statuses carry none by definition, so
/// framing one desynchronises the connection: the client reads the terminating
/// chunk as the first bytes of whatever it asked for next.
fn carries_a_body(method: &str, status: u16) -> bool {
    !method.eq_ignore_ascii_case("HEAD") && !matches!(status, 100..=199 | 204 | 304)
}

/// The fixed audit label for a request that could not be read.
///
/// Pipelining gets its own word: it is a different thing from a transfer-coded
/// body, and recording both as one would make a chain reader unable to tell an
/// attempt to smuggle an uninspected second request from a client that simply
/// used chunked encoding.
fn refusal_reason(error: &ReadError) -> &'static str {
    match error {
        ReadError::Pipelined => REASON_PIPELINED,
        _ => REASON_UNFRAMEABLE_REQUEST,
    }
}

/// Write a refusal the guest's HTTP client can read, then stop.
///
/// `message` is host-generated refusal text: it names the destination and the
/// reason, never a byte of the request. `method` is the request's, where the
/// request got far enough to have one; `None` writes no body, which is correct
/// for every method and is the only safe answer when the method is unknown —
/// see [`carries_a_body`]. The `content-length` is written either way, because
/// that is what a `HEAD` response is supposed to carry.
fn write_refusal<T: Write>(
    io: &mut T,
    status: u16,
    message: &str,
    method: Option<&str>,
) -> Result<(), FlowError> {
    let body = message.as_bytes();
    let framed = method.is_some_and(|method| carries_a_body(method, status));
    // A `HEAD` response declares the length a `GET` would have returned and
    // writes no body. With the method unknown neither is safe to claim, so the
    // refusal declares nothing and writes nothing.
    let declared = if method.is_some() { body.len() } else { 0 };
    let head = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: text/plain\r\ncontent-length: {declared}\r\nconnection: close\r\n\r\n",
        reason_phrase(status),
    );
    io.write_all(head.as_bytes())?;
    if framed {
        io.write_all(body)?;
    }
    io.flush()?;
    Ok(())
}

/// Builder for [`TerminatedFlow`]. Every field is required.
#[derive(Default)]
pub(crate) struct TerminatedFlowBuilder {
    service: Option<Arc<SubstitutionService>>,
    runtime: Option<tokio::runtime::Handle>,
    leaves: Option<Arc<LeafCache>>,
    authority: Option<Authority>,
    mode: Option<TerminationMode>,
}

impl TerminatedFlowBuilder {
    #[must_use]
    pub(crate) fn service(mut self, value: Arc<SubstitutionService>) -> Self {
        self.service = Some(value);
        self
    }

    #[must_use]
    pub(crate) fn runtime(mut self, value: tokio::runtime::Handle) -> Self {
        self.runtime = Some(value);
        self
    }

    #[must_use]
    pub(crate) fn leaves(mut self, value: Arc<LeafCache>) -> Self {
        self.leaves = Some(value);
        self
    }

    #[must_use]
    pub(crate) fn authority(mut self, host: &str, port: u16) -> Self {
        self.authority = Some(Authority {
            host: host.to_string(),
            port,
        });
        self
    }

    #[must_use]
    pub(crate) fn mode(mut self, value: TerminationMode) -> Self {
        self.mode = Some(value);
        self
    }

    pub(crate) fn build(self) -> Result<TerminatedFlow, &'static str> {
        Ok(TerminatedFlow {
            service: self.service.ok_or("terminated flow service missing")?,
            runtime: self.runtime.ok_or("terminated flow runtime missing")?,
            leaves: self.leaves.ok_or("terminated flow leaf cache missing")?,
            authority: self.authority.ok_or("terminated flow authority missing")?,
            mode: self.mode.ok_or("terminated flow mode missing")?,
        })
    }
}

/// Run `flow` over `transport` on its own thread, holding `slot` for its life.
///
/// A thread rather than a task: the transport is a blocking socket and the
/// rustls stream over it is blocking too, and the flow drives the async
/// substitution pipeline by blocking on the runtime handle from outside it.
pub(crate) fn spawn(
    flow: TerminatedFlow,
    transport: UnixStream,
    slot: FlowSlot,
) -> std::io::Result<()> {
    let name = format!("mvm-terminated-{}", flow.authority);
    std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            if let Err(error) = flow.serve(transport) {
                warn!(
                    authority = %flow.authority,
                    %error,
                    "terminated egress flow ended early"
                );
            }
            drop(slot);
        })
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_core::plan::TenantId;
    use rustls::pki_types::pem::PemObject;
    use secrecy::SecretBox;

    use crate::keyholder::substitution::SubstitutionRegistry;
    use crate::keyholder::{LocalResolver, SecretResolver};
    use crate::supervisor::audit_file::FileAuditSigner;
    use crate::supervisor::audit_recorder::Recorder;
    use crate::supervisor::network_endpoint_proxy::test_support::gate_admitting;
    use crate::supervisor::network_endpoint_proxy::{
        ForwardError, ForwardResponse, Forwarder, PreparedRequest,
    };

    const TENANT: &str = "terminated-flow-tenant";
    const REAL_SECRET: &str = "sk-live-real-value";
    /// The destination every request names and the secret is bound to.
    const BOUND_HOST: &str = "api.bound.test";
    /// A second admitted name, so the deny test can point the policy somewhere
    /// real rather than at an empty allow-list.
    const OTHER_HOST: &str = "api.other.test";
    /// A subdomain wildcard binding, and a name two labels below it that the
    /// binding admits.
    const WILDCARD_PATTERN: &str = "*.wild.test";
    const WILDCARD_SUBDOMAIN: &str = "api.eu.wild.test";

    /// Records the request the forward leg was handed, so a test can prove the
    /// destination received the real credential without a network call.
    ///
    /// With `fail_after_send` set it records the request and then fails, which
    /// is an upstream that took the credential and never answered.
    struct RecordingForwarder {
        seen: Mutex<Option<PreparedRequest>>,
        body: Vec<u8>,
        fail_after_send: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Forwarder for RecordingForwarder {
        async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            *self.seen.lock().expect("forwarder record lock") = Some(req);
            if self
                .fail_after_send
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(ForwardError::Failed("upstream reset".into()));
            }
            Ok(ForwardResponse {
                status: 200,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    // Framing the terminator must re-derive rather than copy.
                    ("content-length".into(), self.body.len().to_string()),
                ],
                body: self.body.clone(),
            })
        }
    }

    struct Harness {
        service: Arc<SubstitutionService>,
        forwarder: Arc<RecordingForwarder>,
        placeholder: String,
        intermediate_pem: String,
        audit_path: std::path::PathBuf,
        audit_key: ed25519_dalek::VerifyingKey,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        /// The chain-signed audit log, verified before it is read, so a test
        /// asserting on an entry is also asserting the chain still holds.
        fn audit_chain(&self) -> String {
            crate::supervisor::audit_file::verify_audit_chain(&self.audit_path, &self.audit_key)
                .expect("audit chain verifies");
            std::fs::read_to_string(&self.audit_path).expect("read audit chain")
        }
    }

    /// Build a service over the real registry, resolver, claim-10 gate and
    /// chain-signed recorder, with a per-VM egress intermediate attached.
    ///
    /// `admitted` is the one host the network policy allows; the deny test
    /// points it away from the host the request names, so that test isolates
    /// the gate from the binding.
    fn harness(admitted: &str, response_body: &[u8]) -> Harness {
        harness_bound_to(BOUND_HOST, admitted, response_body)
    }

    /// As [`harness`], with the secret bound to — and the certificate minted
    /// from — `pattern` rather than [`BOUND_HOST`].
    fn harness_bound_to(pattern: &str, admitted: &str, response_body: &[u8]) -> Harness {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                TENANT,
                "model-api",
                &SecretBox::new(Box::new(REAL_SECRET.to_string())),
            )
            .expect("seed secret store");
        let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new(
            TENANT,
            Arc::new(store) as Arc<dyn SecretStore>,
        ));

        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(SecretRef {
                name: "model-api".into(),
                mount: SecretMount::Env {
                    var: "API_KEY".into(),
                },
                auth_type: AuthType::Bearer,
                allowed_hosts: vec![pattern.to_string()],
                sigv4: None,
            })
            .as_str()
            .to_string();

        let forwarder = Arc::new(RecordingForwarder {
            seen: Mutex::new(None),
            body: response_body.to_vec(),
            fail_after_send: std::sync::atomic::AtomicBool::new(false),
        });

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let audit_key = signing_key.verifying_key();
        let audit_path = dir.path().join("audit.jsonl");
        let signer =
            FileAuditSigner::open_file(signing_key, &audit_path).expect("open audit signer");
        let recorder = Recorder::new(Arc::new(signer), TenantId(TENANT.to_string()));

        // Through the production delivery, so the certificate a guest is handed
        // and the key the endpoint terminates under are the ones the launch path
        // actually ships rather than a look-alike minted here.
        let delivery = mvm_vmm::host::network_endpoint_spawn::build_egress_tls_delivery(&[pattern])
            .expect("mint the per-VM egress ca");
        let intermediate = mvm_core::crypto::egress_ca::VmEgressCa::from_pem(
            delivery.cert_pem(),
            delivery.key_pem(),
        )
        .expect("the endpoint rebuilds its ca from the delivered pems");
        let intermediate_pem = delivery.cert_pem().to_string();

        // Nothing is ever dialed: the forward leg is a double, and the gate pins
        // the admitted name without DNS.
        let service = SubstitutionService::new(
            Arc::new(registry),
            resolver,
            forwarder.clone(),
            gate_admitting(&[(admitted, 443)]),
        )
        .with_tenant(TENANT)
        .with_recorder(recorder)
        .with_tls_intermediate(intermediate);

        Harness {
            service: Arc::new(service),
            forwarder,
            placeholder,
            intermediate_pem,
            audit_path,
            audit_key,
            _dir: dir,
        }
    }

    /// A rustls client that trusts only the per-VM intermediate, which is what
    /// an unmodified guest HTTPS client does once the certificate is delivered
    /// to it.
    fn guest_client_config(intermediate_pem: &str) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(intermediate_pem.as_bytes()) {
            roots
                .add(cert.expect("intermediate pem parses"))
                .expect("intermediate is a usable trust anchor");
        }
        rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("client protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// Read exactly one HTTP/1.1 response off `io`, using the response's own
    /// framing to know when it ended.
    ///
    /// Reading to EOF would hang on the success path, where the terminator
    /// loops back and waits for the next keep-alive request rather than
    /// closing.
    fn read_response<T: Read>(io: &mut T) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = super::super::find_subslice(&buf, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                if head.contains("transfer-encoding: chunked") {
                    if buf.ends_with(b"0\r\n\r\n") {
                        return buf;
                    }
                } else {
                    let declared = head
                        .split("\r\n")
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.trim() == "content-length")
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + declared {
                        return buf;
                    }
                }
            }
            match io.read(&mut chunk) {
                Ok(0) | Err(_) => return buf,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Drive one request through a terminated TLS flow, exactly as an
    /// unmodified HTTPS client would: handshake against the minted leaf, send
    /// an origin-form request, read the response back.
    fn exchange(harness: &Harness, request: &[u8]) -> Vec<u8> {
        exchange_trusting(harness, &harness.intermediate_pem.clone(), request)
            .expect("the guest's tls client completes its handshake")
    }

    /// As [`exchange`], but with the guest trusting exactly `trusted_pem`.
    ///
    /// `None` when the handshake never completed — which is the answer a client
    /// that was delivered some other VM's certificate must get.
    fn exchange_trusting(harness: &Harness, trusted_pem: &str, request: &[u8]) -> Option<Vec<u8>> {
        exchange_with(harness, BOUND_HOST, trusted_pem, request).ok()
    }

    /// As [`exchange_trusting`], over a flow opened to `host:443`.
    ///
    /// A handshake that never completed is an `Err` carrying what each side
    /// reported: the guest client's error and the terminator's own result.
    fn exchange_with(
        harness: &Harness,
        host: &str,
        trusted_pem: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        let flow = TerminatedFlow::builder()
            .service(Arc::clone(&harness.service))
            .runtime(runtime.handle().clone())
            .leaves(Arc::new(LeafCache::default()))
            .authority(host, 443)
            .mode(TerminationMode::Tls)
            .build()
            .expect("build terminated flow");

        let (endpoint_side, guest_side) = UnixStream::pair().expect("socket pair");
        let served = std::thread::spawn(move || flow.serve(endpoint_side));

        let server_name = rustls::pki_types::ServerName::try_from(host)
            .expect("the flow's host is a server name")
            .to_owned();
        let connection =
            rustls::ClientConnection::new(Arc::new(guest_client_config(trusted_pem)), server_name)
                .expect("guest tls client");
        let mut tls = rustls::StreamOwned::new(connection, guest_side);

        let wrote = tls.write_all(request).and_then(|()| tls.flush());
        let response = wrote.as_ref().ok().map(|()| read_response(&mut tls));

        // Close the guest side so the terminator's keep-alive loop ends and
        // the thread can be joined.
        tls.conn.send_close_notify();
        let _ = tls.flush();
        let _ = tls.sock.shutdown(std::net::Shutdown::Both);
        // A refused request still wrote its refusal, which is what the caller
        // asserts on, so the flow's own result only matters when the handshake
        // failed and it is the terminator's half of the explanation.
        let served = served.join().expect("terminated flow thread");
        match (wrote, response) {
            (Ok(()), Some(response)) => Ok(response),
            (wrote, _) => Err(format!(
                "guest client: {:?}; terminator: {:?}",
                wrote.err(),
                served.err()
            )),
        }
    }

    /// The guest's loopback proxy, reduced to what a client configured from the
    /// proxy environment asks of it: accept one `CONNECT`, answer `200`, then
    /// relay bytes onto the flow the host opened.
    ///
    /// The production client does the same thing with the relay multiplexed
    /// over FlowMux and the flow opened by an `OpenTcp` the claim-10 gate
    /// admitted. The bytes either side of it are identical, which is why this
    /// stand-in can prove what the proxy environment makes a client do without
    /// booting a guest.
    ///
    /// Returns the request line it was given, so the test can assert the client
    /// tunnelled rather than handing over an absolute-URI request.
    fn connect_front(
        listener: std::net::TcpListener,
        flow_side: UnixStream,
    ) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let (mut client, _peer) = listener.accept().expect("the proxy accepts one client");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while super::super::find_subslice(&head, b"\r\n\r\n").is_none() {
                match client.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => head.push(byte[0]),
                }
            }
            let request_line = String::from_utf8_lossy(&head)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string();
            if !request_line.starts_with("CONNECT ") {
                // Anything else is not a tunnel, and this stand-in serves only
                // tunnels — the same refusal shape the real proxy gives an
                // `https` absolute-URI request.
                let _ = client.write_all(b"HTTP/1.1 501 Not Implemented\r\n\r\n");
                return request_line;
            }
            let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
            let _ = client.flush();

            let mut to_flow = client.try_clone().expect("clone the client socket");
            let mut from_flow = flow_side.try_clone().expect("clone the flow socket");
            let mut flow_in = flow_side;
            let up = std::thread::spawn(move || {
                let _ = std::io::copy(&mut to_flow, &mut flow_in);
                let _ = flow_in.shutdown(std::net::Shutdown::Write);
            });
            let _ = std::io::copy(&mut from_flow, &mut client);
            let _ = client.shutdown(std::net::Shutdown::Write);
            let _ = up.join();
            request_line
        })
    }

    /// Drive one request the way a workload's own HTTPS client does: read the
    /// proxy endpoint out of the environment mvm hands the guest, `CONNECT`
    /// through it, then speak ordinary TLS.
    ///
    /// Returns the request line the proxy saw alongside the response bytes.
    fn exchange_through_proxy_environment(
        harness: &Harness,
        request: &[u8],
    ) -> (String, Option<Vec<u8>>) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        let flow = TerminatedFlow::builder()
            .service(Arc::clone(&harness.service))
            .runtime(runtime.handle().clone())
            .leaves(Arc::new(LeafCache::default()))
            .authority(BOUND_HOST, 443)
            .mode(TerminationMode::Tls)
            .build()
            .expect("build terminated flow");

        let (endpoint_side, guest_side) = UnixStream::pair().expect("socket pair");
        let served = std::thread::spawn(move || flow.serve(endpoint_side));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind the guest proxy");
        let listen = listener.local_addr().expect("proxy address");
        let front = connect_front(listener, guest_side);

        // The workload reads this, not a constant: it is the environment the
        // launch path actually synthesizes for a guest.
        let env: std::collections::HashMap<String, String> =
            mvm_core::guest_netd::proxy_env_vars(&listen.to_string())
                .into_iter()
                .collect();
        let proxy = env
            .get("HTTPS_PROXY")
            .expect("the guest proxy environment names an https proxy")
            .strip_prefix("http://")
            .expect("an http proxy url")
            .to_string();

        let mut tcp = std::net::TcpStream::connect(&proxy).expect("dial the proxy from the env");
        tcp.write_all(
            format!("CONNECT {BOUND_HOST}:443 HTTP/1.1\r\nhost: {BOUND_HOST}:443\r\n\r\n")
                .as_bytes(),
        )
        .expect("write the tunnel request");
        tcp.flush().expect("flush the tunnel request");
        let mut reply = Vec::new();
        let mut byte = [0u8; 1];
        while super::super::find_subslice(&reply, b"\r\n\r\n").is_none() {
            match tcp.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => reply.push(byte[0]),
            }
        }
        let tunnelled = String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200");

        let response = tunnelled.then(|| {
            let server_name = rustls::pki_types::ServerName::try_from(BOUND_HOST)
                .expect("the bound host is a server name")
                .to_owned();
            let connection = rustls::ClientConnection::new(
                Arc::new(guest_client_config(&harness.intermediate_pem)),
                server_name,
            )
            .expect("guest tls client");
            let mut tls = rustls::StreamOwned::new(connection, tcp);
            tls.write_all(request).expect("write the request");
            tls.flush().expect("flush the request");
            let body = read_response(&mut tls);
            tls.conn.send_close_notify();
            let _ = tls.flush();
            let _ = tls.sock.shutdown(std::net::Shutdown::Both);
            body
        });

        let request_line = front.join().expect("proxy front thread");
        let _served = served.join().expect("terminated flow thread");
        (request_line, response)
    }

    /// The whole of what retiring the second guest proxy buys: a workload's own
    /// HTTPS client, told nothing but the standard proxy variables, reaches a
    /// credentialed destination and the host puts the real credential on the
    /// wire.
    ///
    /// The request line the proxy saw is asserted because it is the mechanism:
    /// pointed at an HTTP proxy for an `https://` URL, an unmodified client
    /// opens a `CONNECT` tunnel. The retired proxy answered that with `502`,
    /// and the one that could substitute never saw a tunnel — which is why
    /// whether a request was substituted used to depend on which variable the
    /// workload's toolchain happened to read.
    #[test]
    fn a_client_configured_from_the_proxy_environment_gets_the_substituted_credential() {
        let vm = harness(BOUND_HOST, b"{\"ok\":true}");
        let (request_line, response) = exchange_through_proxy_environment(
            &vm,
            &request_with_placeholder(&vm.placeholder, BOUND_HOST),
        );

        assert_eq!(
            request_line,
            format!("CONNECT {BOUND_HOST}:443 HTTP/1.1"),
            "the proxy environment must make an unmodified client tunnel"
        );
        let response = response.expect("the tunnel was established and the request answered");
        assert!(
            status_line(&response).starts_with("HTTP/1.1 200"),
            "unexpected status: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(dechunk(&response), b"{\"ok\":true}");

        let seen = vm
            .forwarder
            .seen
            .lock()
            .expect("forwarder record lock")
            .clone()
            .expect("the forward leg ran");
        assert_eq!(
            seen.headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.as_str()),
            Some(format!("Bearer {REAL_SECRET}").as_str()),
            "the destination receives the real credential"
        );
        assert!(
            !String::from_utf8_lossy(&response).contains(REAL_SECRET),
            "and the guest never sees it"
        );
    }

    fn request_with_placeholder(placeholder: &str, host: &str) -> Vec<u8> {
        method_request_with_placeholder("POST", placeholder, host)
    }

    fn method_request_with_placeholder(method: &str, placeholder: &str, host: &str) -> Vec<u8> {
        format!(
            "{method} /v1/messages HTTP/1.1\r\nhost: {host}\r\nauthorization: Bearer {placeholder}\r\ncontent-length: 9\r\n\r\n{{\"a\":\"b\"}}"
        )
        .into_bytes()
    }

    fn status_line(response: &[u8]) -> String {
        String::from_utf8_lossy(response)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn dechunk(response: &[u8]) -> Vec<u8> {
        let split = super::super::find_subslice(response, b"\r\n\r\n")
            .expect("response has a header terminator");
        let mut rest = &response[split + 4..];
        let mut out = Vec::new();
        loop {
            let line_end =
                super::super::find_subslice(rest, b"\r\n").expect("chunk size line is terminated");
            let size = usize::from_str_radix(
                std::str::from_utf8(&rest[..line_end]).expect("chunk size is ascii"),
                16,
            )
            .expect("chunk size parses");
            rest = &rest[line_end + 2..];
            if size == 0 {
                return out;
            }
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size + 2..];
        }
    }

    /// The end-to-end property the delivery exists for: an unmodified HTTPS
    /// client that trusts **only** the certificate the launch path put on this
    /// VM's identity drive completes a request whose credential the host
    /// substituted — and a client holding some other VM's certificate does not
    /// get that far, which is what makes the delivery per-VM rather than a
    /// blanket trust anchor.
    #[test]
    fn a_client_trusting_only_the_delivered_certificate_completes_a_substituted_request() {
        let vm = harness(BOUND_HOST, b"{\"ok\":true}");

        let response = exchange_trusting(
            &vm,
            &vm.intermediate_pem.clone(),
            &request_with_placeholder(&vm.placeholder, BOUND_HOST),
        )
        .expect("a client trusting the delivered certificate completes its handshake");
        assert!(
            status_line(&response).starts_with("HTTP/1.1 200"),
            "unexpected status: {}",
            String::from_utf8_lossy(&response)
        );
        let authorization = vm
            .forwarder
            .seen
            .lock()
            .expect("forwarder record lock")
            .clone()
            .expect("the forward leg ran")
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .expect("the re-originated request carries an authorization header");
        assert_eq!(authorization, format!("Bearer {REAL_SECRET}"));

        let other_vm =
            mvm_vmm::host::network_endpoint_spawn::build_egress_tls_delivery(&[BOUND_HOST])
                .expect("a second VM's delivery");
        assert_ne!(
            other_vm.cert_pem(),
            vm.intermediate_pem,
            "each VM's certificate is its own"
        );
        let stranger = harness(BOUND_HOST, b"{\"ok\":true}");
        assert!(
            exchange_trusting(
                &stranger,
                other_vm.cert_pem(),
                &request_with_placeholder(&stranger.placeholder, BOUND_HOST),
            )
            .is_none(),
            "a client holding another VM's certificate must not complete this flow"
        );
        assert!(
            stranger
                .forwarder
                .seen
                .lock()
                .expect("forwarder record lock")
                .is_none(),
            "and nothing may be forwarded on a flow that never handshook"
        );
    }

    /// The certificate minted for `*.wild.test` carries the `wild.test`
    /// subtree, which a verifier would accept for the apex too. The binding
    /// does not admit the apex, and this is the check that keeps a flow to it
    /// from being terminated.
    #[test]
    fn the_wildcard_apex_is_not_terminable() {
        let vm = harness_bound_to(WILDCARD_PATTERN, WILDCARD_SUBDOMAIN, b"never sent");
        let apex = WILDCARD_PATTERN
            .strip_prefix("*.")
            .expect("the wildcard pattern has a `*.` label");
        assert_eq!(
            vm.service.terminable(WILDCARD_SUBDOMAIN, 443),
            Some(TerminationMode::Tls),
            "a subdomain the wildcard admits terminates"
        );
        assert_eq!(vm.service.terminable(apex, 443), None);
        assert_eq!(vm.service.terminable(apex, 80), None);
    }

    /// A `*.` binding admits a subdomain at any depth, so an unmodified client
    /// trusting only the certificate minted from that binding has to complete
    /// a terminated flow to one: the certificate's name constraints must admit
    /// what the binding admits, in a form a real verifier accepts.
    #[test]
    fn a_wildcard_bound_subdomain_terminates() {
        let vm = harness_bound_to(WILDCARD_PATTERN, WILDCARD_SUBDOMAIN, b"{\"ok\":true}");

        let response = exchange_with(
            &vm,
            WILDCARD_SUBDOMAIN,
            &vm.intermediate_pem.clone(),
            &request_with_placeholder(&vm.placeholder, WILDCARD_SUBDOMAIN),
        )
        .unwrap_or_else(|error| {
            panic!(
                "a client trusting the delivered certificate must complete its handshake: {error}"
            )
        });

        assert!(
            status_line(&response).starts_with("HTTP/1.1 200"),
            "unexpected status: {}",
            String::from_utf8_lossy(&response)
        );
        let seen = vm
            .forwarder
            .seen
            .lock()
            .expect("forwarder record lock")
            .clone()
            .expect("the forward leg ran");
        assert_eq!(
            seen.url,
            format!("https://{WILDCARD_SUBDOMAIN}/v1/messages")
        );
        let authorization = seen
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .expect("the re-originated request carries an authorization header");
        assert_eq!(authorization, format!("Bearer {REAL_SECRET}"));
    }

    #[test]
    fn terminated_connect_substitutes_and_reoriginates() {
        let harness = harness(BOUND_HOST, b"{\"ok\":true}");
        let response = exchange(
            &harness,
            &request_with_placeholder(&harness.placeholder, BOUND_HOST),
        );

        assert!(
            status_line(&response).starts_with("HTTP/1.1 200"),
            "unexpected status: {}",
            String::from_utf8_lossy(&response)
        );
        assert_eq!(
            dechunk(&response),
            b"{\"ok\":true}",
            "the response body reaches the guest through the chunked re-framing"
        );

        let seen = harness
            .forwarder
            .seen
            .lock()
            .expect("forwarder record lock")
            .clone()
            .expect("the forward leg ran");
        assert_eq!(
            seen.url,
            format!("https://{BOUND_HOST}/v1/messages"),
            "the re-originated request keeps the authority and the path"
        );
        let authorization = seen
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .expect("the re-originated request carries an authorization header");
        assert_eq!(
            authorization,
            format!("Bearer {REAL_SECRET}"),
            "the destination receives the real credential"
        );
        let text = String::from_utf8_lossy(&response);
        assert!(
            !text.contains(REAL_SECRET),
            "the guest never sees the real credential"
        );
        assert!(
            !text.contains(&harness.placeholder),
            "the response carries neither the secret nor its placeholder"
        );
    }

    #[test]
    fn terminated_connect_is_refused_when_policy_denies_the_destination() {
        // The secret is still bound to the host the request names, so this
        // isolates the claim-10 gate: the policy admits somewhere else.
        let harness = harness(OTHER_HOST, b"never sent");
        let response = exchange(
            &harness,
            &request_with_placeholder(&harness.placeholder, BOUND_HOST),
        );

        assert!(
            status_line(&response).starts_with("HTTP/1.1 502"),
            "a denied destination must be refused: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            String::from_utf8_lossy(&response).contains("claim-10"),
            "the refusal must be the gate's, not another 502: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            harness
                .forwarder
                .seen
                .lock()
                .expect("forwarder record lock")
                .is_none(),
            "nothing reaches the forward leg once the gate refuses"
        );
        assert!(
            !String::from_utf8_lossy(&response).contains(REAL_SECRET),
            "a refusal carries no credential"
        );
    }

    /// The credential that went out is on the chain even when no response
    /// came back.
    ///
    /// `secret.substituted` used to be written only once the upstream response
    /// had finished, so a forward that failed after sending (a reset, a
    /// timeout, an oversized response) left the destination holding the real
    /// key and the chain saying nothing. It is now written when the request is
    /// handed to the forward leg, and how the forward ended is a separate entry
    /// after it.
    #[test]
    fn substitution_is_audited_when_upstream_fails_after_send() {
        let harness = harness(BOUND_HOST, b"never sent");
        harness
            .forwarder
            .fail_after_send
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let response = exchange(
            &harness,
            &request_with_placeholder(&harness.placeholder, BOUND_HOST),
        );
        assert!(
            status_line(&response).starts_with("HTTP/1.1 502"),
            "{}",
            String::from_utf8_lossy(&response)
        );

        let seen = harness
            .forwarder
            .seen
            .lock()
            .expect("forwarder record lock")
            .clone()
            .expect("the forward leg ran");
        assert!(
            seen.headers
                .iter()
                .any(|(_, value)| value.contains(REAL_SECRET)),
            "the forward leg was handed the real credential"
        );

        let chain = harness.audit_chain();
        let substituted = chain
            .find("secret.substituted")
            .unwrap_or_else(|| panic!("the send must be on the chain: {chain}"));
        let outcome = chain
            .find("secret.forward_outcome")
            .unwrap_or_else(|| panic!("the failure must be on the chain: {chain}"));
        assert!(
            substituted < outcome,
            "the hand-off is recorded before the outcome: {chain}"
        );
        assert!(chain.contains("upstream_failed"), "{chain}");
        assert!(chain.contains("model-api"), "{chain}");
        assert!(!chain.contains(REAL_SECRET), "no credential in the chain");
        assert!(
            !chain.contains("upstream reset"),
            "error text is not recorded: {chain}"
        );
    }

    /// A forward that completes records its substitution once, and then that
    /// it completed.
    #[test]
    fn a_completed_forward_records_the_substitution_once_then_completed() {
        let harness = harness(BOUND_HOST, b"{\"ok\":true}");
        let response = exchange(
            &harness,
            &request_with_placeholder(&harness.placeholder, BOUND_HOST),
        );
        assert!(status_line(&response).starts_with("HTTP/1.1 200"));

        let chain = harness.audit_chain();
        assert_eq!(
            chain.matches("secret.substituted").count(),
            1,
            "one substitution, one entry: {chain}"
        );
        let substituted = chain.find("secret.substituted").expect("substituted");
        let outcome = chain
            .find("secret.forward_outcome")
            .unwrap_or_else(|| panic!("no outcome entry: {chain}"));
        assert!(substituted < outcome, "{chain}");
        assert!(chain[outcome..].contains("completed"), "{chain}");
        assert!(!chain.contains("upstream_failed"), "{chain}");
    }

    /// The 502 a policy refusal produces on a terminated flow is recorded in
    /// the chain, naming the refused `host:port` and a fixed reason, and none
    /// of the request: not its path, its placeholder, or its body.
    #[test]
    fn a_policy_refusal_on_a_terminated_flow_is_recorded_in_the_chain_signed_log() {
        let harness = harness(OTHER_HOST, b"never sent");
        let response = exchange(
            &harness,
            &request_with_placeholder(&harness.placeholder, BOUND_HOST),
        );
        assert!(status_line(&response).starts_with("HTTP/1.1 502"));

        let chain = harness.audit_chain();
        assert!(chain.contains("secret.flow_refused"), "{chain}");
        assert!(chain.contains("policy_denied"), "{chain}");
        assert!(chain.contains(&format!("{BOUND_HOST}:443")), "{chain}");
        // The body is `{"a":"b"}`; a JSON chain would carry it escaped.
        for content in [
            "/v1/messages",
            harness.placeholder.as_str(),
            "\"a\":\"b\"",
            "\\\"a\\\":\\\"b\\\"",
        ] {
            assert!(
                !chain.contains(content),
                "request content `{content}` reached the chain: {chain}"
            );
        }
        assert!(!chain.contains(REAL_SECRET), "no credential in the chain");
    }

    #[test]
    fn decrypted_host_header_must_match_the_connect_authority() {
        let harness = harness(BOUND_HOST, b"never sent");
        let response = exchange(
            &harness,
            &request_with_placeholder(&harness.placeholder, OTHER_HOST),
        );

        assert!(
            status_line(&response).starts_with("HTTP/1.1 421"),
            "a request addressed away from the flow's authority must be refused: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            harness
                .forwarder
                .seen
                .lock()
                .expect("forwarder record lock")
                .is_none(),
            "the substitution pipeline never sees a misdirected request"
        );
    }

    #[test]
    fn a_request_without_a_host_header_is_refused_before_the_forward_leg() {
        let harness = harness(BOUND_HOST, b"never sent");
        let response = exchange(
            &harness,
            b"GET /v1/messages HTTP/1.1\r\naccept: */*\r\n\r\n",
        );
        assert!(
            status_line(&response).starts_with("HTTP/1.1 421"),
            "unexpected status: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            harness
                .forwarder
                .seen
                .lock()
                .expect("forwarder record lock")
                .is_none()
        );
    }

    /// The one event on this path worth a chain entry: a guest that opened a
    /// credentialed flow and then addressed the request somewhere else.
    ///
    /// Without a record the refusal leaves only a log line, and `trust audit
    /// verify` reads clean straight across an attempted bypass. The entry
    /// names the authority the flow was admitted against and a fixed reason
    /// word; the `Host` the guest actually sent never reaches it.
    #[test]
    fn an_authority_mismatch_is_recorded_in_the_chain_signed_log() {
        let harness = harness(BOUND_HOST, b"never sent");
        let response = exchange(
            &harness,
            &request_with_placeholder(&harness.placeholder, OTHER_HOST),
        );
        assert!(status_line(&response).starts_with("HTTP/1.1 421"));

        let chain = harness.audit_chain();
        assert!(
            chain.contains("secret.flow_refused"),
            "the refusal must reach the chain: {chain}"
        );
        assert!(
            chain.contains(REASON_AUTHORITY_MISMATCH),
            "the entry must say why: {chain}"
        );
        assert!(
            chain.contains(BOUND_HOST),
            "the entry names the authority the flow was admitted against: {chain}"
        );
        assert!(
            !chain.contains(OTHER_HOST),
            "the host the guest asked for is request content and must not be recorded: {chain}"
        );
        assert!(!chain.contains(REAL_SECRET), "no credential in the chain");
    }

    /// A transfer-coded request body is answered rather than read as if it had
    /// none. Reading it that way would hand the chunk framing to the pipeline
    /// as body content and spend a real credential on a corrupted request.
    #[test]
    fn a_transfer_coded_request_is_refused_before_the_forward_leg() {
        let harness = harness(BOUND_HOST, b"never sent");
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nhost: {BOUND_HOST}\r\nauthorization: Bearer {}\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            harness.placeholder
        );
        let response = exchange(&harness, request.as_bytes());

        assert!(
            status_line(&response).starts_with("HTTP/1.1 501"),
            "unexpected status: {}",
            String::from_utf8_lossy(&response)
        );
        assert!(
            harness
                .forwarder
                .seen
                .lock()
                .expect("forwarder record lock")
                .is_none(),
            "a request this reader cannot frame never reaches the forward leg"
        );
    }

    /// A pipelined follow-up is refused rather than served. Those bytes never
    /// passed header substitution, and a placeholder sitting in them would
    /// otherwise reach the wire unresolved.
    #[test]
    fn a_pipelined_second_request_is_refused_rather_than_forwarded() {
        let harness = harness(BOUND_HOST, b"never sent");
        let mut request = request_with_placeholder(&harness.placeholder, BOUND_HOST);
        request.extend_from_slice(
            format!("GET /second HTTP/1.1\r\nhost: {BOUND_HOST}\r\n\r\n").as_bytes(),
        );
        let response = exchange(&harness, &request);

        let text = String::from_utf8_lossy(&response);
        assert!(
            status_line(&response).starts_with("HTTP/1.1 501"),
            "unexpected status: {text}"
        );
        // The reason has to be true about the request. Reusing the
        // transfer-coded refusal told a pipelining client something false
        // about what it sent, and recorded the same word in the chain for two
        // different things.
        assert!(
            text.contains("pipelined requests are not supported"),
            "the refusal must say what was wrong: {text}"
        );
        assert!(
            !text.contains("transfer-coded"),
            "a pipelined request is not a transfer-coded one: {text}"
        );
        assert!(
            harness
                .forwarder
                .seen
                .lock()
                .expect("forwarder record lock")
                .is_none(),
            "neither request is forwarded once pipelining is seen"
        );

        let chain = harness.audit_chain();
        assert!(
            chain.contains(REASON_PIPELINED),
            "the chain must distinguish this from a transfer-coded body: {chain}"
        );
        assert!(
            !chain.contains(REASON_UNFRAMEABLE_REQUEST),
            "the two causes must not collapse to one label: {chain}"
        );
    }

    /// The transfer-coded refusal keeps its own word, so the two causes can be
    /// told apart in the chain rather than both reading `unframeable_request`.
    #[test]
    fn a_transfer_coded_refusal_is_labelled_apart_from_a_pipelined_one() {
        let harness = harness(BOUND_HOST, b"never sent");
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nhost: {BOUND_HOST}\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"
        );
        let _ = exchange(&harness, request.as_bytes());
        let chain = harness.audit_chain();
        assert!(chain.contains(REASON_UNFRAMEABLE_REQUEST), "{chain}");
        assert!(!chain.contains(REASON_PIPELINED), "{chain}");
    }

    /// A `HEAD` response carries no body by definition, so framing one leaves
    /// the terminating chunk in the stream and the client reads it as the
    /// first bytes of its next response.
    #[test]
    fn a_head_response_is_not_chunk_framed() {
        let harness = harness(BOUND_HOST, b"");
        let response = exchange(
            &harness,
            &method_request_with_placeholder("HEAD", &harness.placeholder, BOUND_HOST),
        );

        let text = String::from_utf8_lossy(&response).to_ascii_lowercase();
        assert!(
            status_line(&response).starts_with("HTTP/1.1 200"),
            "unexpected status: {text}"
        );
        assert!(
            !text.contains("transfer-encoding"),
            "a HEAD response must not be framed: {text}"
        );
        assert!(
            response.ends_with(b"\r\n\r\n") && !response.ends_with(b"0\r\n\r\n"),
            "no terminating chunk may follow a HEAD response: {text}"
        );
    }

    #[test]
    fn a_refusal_reason_names_the_cause_it_was_given() {
        assert_eq!(refusal_reason(&ReadError::Pipelined), REASON_PIPELINED);
        assert_eq!(
            refusal_reason(&ReadError::TransferCoded),
            REASON_UNFRAMEABLE_REQUEST
        );
        assert_eq!(
            refusal_reason(&ReadError::TooLarge),
            REASON_UNFRAMEABLE_REQUEST
        );
    }

    #[test]
    fn a_response_that_may_carry_no_body_is_never_framed() {
        assert!(carries_a_body("GET", 200));
        assert!(carries_a_body("POST", 500));
        assert!(!carries_a_body("HEAD", 200));
        assert!(!carries_a_body("head", 200));
        assert!(!carries_a_body("GET", 204));
        assert!(!carries_a_body("GET", 304));
        assert!(!carries_a_body("GET", 100));
        assert!(!carries_a_body("GET", 199));
    }

    /// The ceiling is its own, well under the opaque-flow budget, because a
    /// terminated flow costs two threads and a TLS session rather than one
    /// thread and a socket.
    #[test]
    fn the_terminated_flow_ceiling_holds_and_releases() {
        let live = Arc::new(AtomicUsize::new(0));
        let mut held: Vec<FlowSlot> = (0..MAX_TERMINATED_FLOWS)
            .map(|_| FlowSlot::claim(&live).expect("a slot below the ceiling"))
            .collect();
        assert_eq!(live.load(Ordering::Acquire), MAX_TERMINATED_FLOWS);
        assert!(
            FlowSlot::claim(&live).is_none(),
            "the ceiling refuses rather than growing"
        );

        held.pop();
        assert_eq!(live.load(Ordering::Acquire), MAX_TERMINATED_FLOWS - 1);
        let reclaimed = FlowSlot::claim(&live).expect("a released slot is reusable");
        drop(reclaimed);
        drop(held);
        assert_eq!(
            live.load(Ordering::Acquire),
            0,
            "every slot is released when its flow ends"
        );
    }

    /// Minting a leaf is a key generation plus a signature, so a client that
    /// reconnects per request must not pay for one each time.
    #[test]
    fn a_leaf_is_minted_once_per_authority() {
        let harness = harness(BOUND_HOST, b"");
        let intermediate = harness
            .service
            .tls_intermediate()
            .expect("the harness attaches an intermediate");
        let cache = LeafCache::default();
        let first = cache
            .config_for(intermediate, BOUND_HOST)
            .expect("mint a leaf");
        let second = cache
            .config_for(intermediate, BOUND_HOST)
            .expect("reuse the minted leaf");
        assert!(
            Arc::ptr_eq(&first, &second),
            "the second flow to one authority reuses the first flow's leaf"
        );
        let other = cache
            .config_for(intermediate, OTHER_HOST)
            .expect("mint a second authority's leaf");
        assert!(
            !Arc::ptr_eq(&first, &other),
            "a different authority gets its own leaf"
        );
    }

    /// The authority is guest-chosen — a wildcard binding matches every label
    /// under it — so the cache has to be bounded rather than merely believed
    /// to be small. Each entry holds a chain and a private key.
    #[test]
    fn the_leaf_cache_is_bounded_by_its_capacity() {
        let harness = harness(BOUND_HOST, b"");
        let intermediate = harness
            .service
            .tls_intermediate()
            .expect("the harness attaches an intermediate");
        let cache = LeafCache::default();
        let first_name = "n0.bound.test";
        let first = cache
            .config_for(intermediate, first_name)
            .expect("mint the first leaf");
        for index in 1..=MAX_CACHED_LEAVES {
            cache
                .config_for(intermediate, &format!("n{index}.bound.test"))
                .expect("mint a leaf for an invented authority");
        }
        assert_eq!(
            cache.lock().by_key.len(),
            MAX_CACHED_LEAVES,
            "the cache never grows past its capacity"
        );
        let refreshed = cache
            .config_for(intermediate, first_name)
            .expect("re-mint the evicted leaf");
        assert!(
            !Arc::ptr_eq(&first, &refreshed),
            "the oldest entry was evicted rather than retained forever"
        );
    }

    /// The key names the issuer as well as the authority. Rotating the
    /// intermediate is not reachable today, but an authority-only key would
    /// keep serving a leaf chained to the retired issuer, which the guest no
    /// longer trusts.
    #[test]
    fn a_cached_leaf_is_keyed_by_its_issuer_too() {
        let first = harness(BOUND_HOST, b"");
        let second = harness(BOUND_HOST, b"");
        let one = first
            .service
            .tls_intermediate()
            .expect("first intermediate");
        let two = second
            .service
            .tls_intermediate()
            .expect("second intermediate");
        assert_ne!(
            one.cert_pem(),
            two.cert_pem(),
            "the two harnesses mint independent intermediates"
        );
        assert_ne!(
            cache_key(one, BOUND_HOST),
            cache_key(two, BOUND_HOST),
            "one authority under two issuers is two cache entries"
        );

        let cache = LeafCache::default();
        let under_one = cache.config_for(one, BOUND_HOST).expect("mint under one");
        let under_two = cache.config_for(two, BOUND_HOST).expect("mint under two");
        assert!(
            !Arc::ptr_eq(&under_one, &under_two),
            "a rotated issuer must not be served the previous issuer's leaf"
        );
    }

    /// A refusal to a `HEAD` carries its length and no body, like every other
    /// response on this path.
    #[test]
    fn a_refusal_to_a_head_request_carries_no_body() {
        let mut framed = Vec::new();
        write_refusal(&mut framed, BAD_GATEWAY, "refused", Some("GET"))
            .expect("write a framed refusal");
        let framed = String::from_utf8(framed).expect("refusal is utf-8");
        assert!(framed.ends_with("\r\n\r\nrefused"), "{framed}");
        assert!(framed.contains("content-length: 7"), "{framed}");

        let mut bodyless = Vec::new();
        write_refusal(&mut bodyless, BAD_GATEWAY, "refused", Some("HEAD"))
            .expect("write a bodyless refusal");
        let bodyless = String::from_utf8(bodyless).expect("refusal is utf-8");
        assert!(bodyless.ends_with("\r\n\r\n"), "{bodyless}");
        assert!(
            !bodyless.contains("refused\n") && !bodyless.ends_with("refused"),
            "a HEAD response carries no body: {bodyless}"
        );
        assert!(
            bodyless.contains("content-length: 7"),
            "but it still declares the length a GET would have returned: {bodyless}"
        );

        // An unknown method is answered bodyless, which is correct for every
        // method rather than correct for most of them.
        let mut unknown = Vec::new();
        write_refusal(&mut unknown, MISDIRECTED_REQUEST, "refused", None)
            .expect("write an unattributed refusal");
        let unknown = String::from_utf8(unknown).expect("refusal is utf-8");
        assert!(unknown.ends_with("\r\n\r\n"), "{unknown}");
        assert!(
            unknown.contains("content-length: 0"),
            "an empty refusal must not claim a length it does not write: {unknown}"
        );
    }

    /// A response header that carries a bare CR or LF must be dropped even when
    /// it is not one of the framing headers: the `||` between the two
    /// conditions is what stops an upstream from ending the head early and
    /// injecting a header of its own. The framing header is dropped too — the
    /// terminator re-frames what it writes back.
    #[test]
    fn a_crlf_smuggling_response_header_is_stripped_even_when_not_framing() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build test runtime");
        let harness = harness(BOUND_HOST, b"");
        let flow = TerminatedFlow::builder()
            .service(Arc::clone(&harness.service))
            .runtime(runtime.handle().clone())
            .leaves(Arc::new(LeafCache::default()))
            .authority(BOUND_HOST, 443)
            .mode(TerminationMode::Tls)
            .build()
            .expect("build terminated flow");

        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let response = ForwardStreamResponse {
            status: 200,
            headers: vec![
                ("x-clean".to_string(), "keep".to_string()),
                (
                    "x-smuggled".to_string(),
                    "evil\r\ninjected: yes".to_string(),
                ),
                ("content-length".to_string(), "99".to_string()),
            ],
            body_len: None,
            body: rx,
        };
        tx.try_send(Ok(b"data".to_vec())).expect("one chunk");
        drop(tx);

        let mut out = Vec::new();
        flow.write_stream_response(&mut out, "GET", response)
            .expect("write the response");
        let text = String::from_utf8(out).expect("response is utf-8");

        assert!(text.contains("x-clean: keep\r\n"), "{text}");
        assert!(
            !text.contains("x-smuggled") && !text.contains("injected: yes"),
            "a header that smuggles CRLF must not reach the guest: {text}"
        );
        assert!(
            !text.contains("content-length"),
            "the upstream framing header must be re-framed, not carried: {text}"
        );
        assert!(text.contains("transfer-encoding: chunked\r\n"), "{text}");
    }

    /// A response that may not carry a body (HEAD here) still has its body
    /// channel drained, but no chunk may be written: framing one anyway would
    /// leave a terminating chunk in the stream that the guest reads as the
    /// start of its next response. The empty-chunk half of the same `||` is
    /// pinned by counting terminators on a framed body that carries one.
    #[test]
    fn a_bodyless_response_drains_its_channel_but_writes_no_chunks() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build test runtime");
        let harness = harness(BOUND_HOST, b"");
        let flow = TerminatedFlow::builder()
            .service(Arc::clone(&harness.service))
            .runtime(runtime.handle().clone())
            .leaves(Arc::new(LeafCache::default()))
            .authority(BOUND_HOST, 443)
            .mode(TerminationMode::Tls)
            .build()
            .expect("build terminated flow");

        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let bodyless = ForwardStreamResponse {
            status: 200,
            headers: Vec::new(),
            body_len: None,
            body: rx,
        };
        tx.try_send(Ok(b"must-not-appear".to_vec()))
            .expect("one chunk");
        drop(tx);

        let mut out = Vec::new();
        flow.write_stream_response(&mut out, "HEAD", bodyless)
            .expect("write the response");
        let text = String::from_utf8(out).expect("response is utf-8");
        assert!(
            !text.contains("must-not-appear"),
            "a bodyless response must not frame chunks: {text}"
        );
        assert!(
            !text.contains("transfer-encoding: chunked"),
            "a bodyless response is not chunked: {text}"
        );

        // Framed body with an empty chunk in the middle: the empty chunk is
        // skipped, so exactly one terminating chunk is written, at the end.
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let framed = ForwardStreamResponse {
            status: 200,
            headers: Vec::new(),
            body_len: None,
            body: rx,
        };
        tx.try_send(Ok(Vec::new())).expect("empty chunk");
        tx.try_send(Ok(b"data".to_vec())).expect("data chunk");
        drop(tx);

        let mut out = Vec::new();
        flow.write_stream_response(&mut out, "GET", framed)
            .expect("write the response");
        let text = String::from_utf8(out).expect("response is utf-8");
        assert!(
            !text.contains("must-not-appear"),
            "chunks from the bodyless half must not leak into this response: {text}"
        );
        let terminators = text.matches("0\r\n\r\n").count();
        assert_eq!(
            terminators, 1,
            "an empty chunk is skipped, not written as a mid-body terminator: {text}"
        );
        assert!(text.ends_with("0\r\n\r\n"), "{text}");
    }

    #[test]
    fn the_builder_names_the_field_it_is_missing() {
        assert!(matches!(
            TerminatedFlow::builder().build(),
            Err("terminated flow service missing")
        ));
    }

    #[test]
    fn a_tls_flow_re_originates_over_https_and_a_cleartext_one_over_http() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build test runtime");
        let harness = harness(BOUND_HOST, b"");
        let build = |mode| {
            TerminatedFlow::builder()
                .service(Arc::clone(&harness.service))
                .runtime(runtime.handle().clone())
                .leaves(Arc::new(LeafCache::default()))
                .authority(BOUND_HOST, 443)
                .mode(mode)
                .build()
                .expect("build terminated flow")
        };
        let tls = build(TerminationMode::Tls);
        assert_eq!(tls.scheme(), "https");
        assert_eq!(
            tls.authority.to_string(),
            format!("{BOUND_HOST}:443"),
            "the authority survives the builder"
        );
        assert_eq!(build(TerminationMode::Cleartext).scheme(), "http");
    }
}
