//! Plan 129 / ADR-067 §1 — host substitution endpoint: request preparation.
//!
//! The guest's SDK client routes a secret-bearing request to this host-local
//! endpoint carrying an opaque placeholder. [`prepare_request`] is the
//! security-critical core: it locates the placeholder in each header, resolves
//! it against the session registry, binding-checks the request's destination
//! (claim 12), and substitutes the real credential — yielding a request ready
//! for the host to make the real TLS to the destination (the forward leg,
//! a separate transport step).
//!
//! Substitution happens HERE, on the host, never in the guest: the guest only
//! ever held the opaque placeholder. The prepared request carries the real
//! credential because it must reach the wire — the confinement is that this
//! host component is the only place it exists in the clear.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::net::{UnixListener, UnixStream};
use url::Url;

use mvm_core::crypto::secret_store::SecretStore;
use mvm_core::plan::SecretBinding;
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use mvm_sdk::ir::AuthType;

use crate::framing::{FrameError, read_json_frame, write_json_frame};
use crate::keyholder::{
    AssembleError, BindingStore, HandedPlaceholders, LocalResolver, SecretResolver,
    SubstituteError, SubstitutionEndpoint, SubstitutionRegistry, assemble_registry,
    find_placeholder,
};
use crate::supervisor::audit_recorder::Recorder;
use crate::supervisor::network::stages::{RedactingSubstitution, RedactionHits};
use crate::supervisor::secret_audit::{emit_secret_redacted, emit_secret_substituted};
use crate::supervisor::tools::http_hardening::{
    hardened_client_builder_no_dns, resolve_ssrf_safe_ips,
};

/// 16 MiB cap on a single routed request/response frame.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// A request the guest routed to the substitution endpoint. Header values may
/// carry an opaque placeholder where a credential goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub method: String,
    /// The real destination URL (e.g. `https://api.openai.com/v1/...`).
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A request with every placeholder substituted to its real credential, ready
/// for the forward leg to send to the destination over real TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Errors from preparing a routed request for forwarding.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("request url `{0}` is not a valid absolute URL with a host")]
    BadUrl(String),
    #[error(transparent)]
    Substitute(#[from] SubstituteError),
}

/// Substitute every placeholder in `req`'s headers against `endpoint`,
/// binding-checked to the request's destination host. Returns a request whose
/// headers carry the real credentials, ready to forward.
///
/// Refuses — before the request is forwarded — if a placeholder's destination
/// is not bound for that secret (claim 12) or the placeholder is unknown. The
/// destination host is taken from the request URL, so a guest can't point a
/// secret at `api.openai.com` in the binding but send the bytes elsewhere: the
/// bind-check uses the URL we will actually dial.
pub fn prepare_request(
    endpoint: &SubstitutionEndpoint<'_>,
    req: ProxyRequest,
) -> Result<PreparedRequest, ProxyError> {
    let dest = destination_host(&req.url)?;
    let mut headers = Vec::with_capacity(req.headers.len());
    for (name, value) in req.headers {
        let new_value = match find_placeholder(&value) {
            Some(ph) => {
                let ph = ph.to_string();
                // `substitute` carries the claim-12 bind-check: an unbound
                // destination or unknown token errors here, before forwarding.
                endpoint.substitute(&ph, &dest, &value)?.to_string()
            }
            None => value,
        };
        headers.push((name, new_value));
    }
    Ok(PreparedRequest {
        method: req.method,
        url: req.url,
        headers,
        body: req.body,
    })
}

/// The destination host (no port) from an absolute URL.
pub(crate) fn destination_host(url: &str) -> Result<String, ProxyError> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .ok_or_else(|| ProxyError::BadUrl(url.to_string()))
}

/// Capture per-secret audit metadata (name + auth-type) for every header that
/// carries a known placeholder — BEFORE substitution consumes the request.
/// `resolve_meta` touches no secret value, so this is claim-13 safe. Shared by
/// the UDS/vsock `process` path and the terminator path so their two audit
/// emissions can't drift.
pub(crate) fn collect_substituted_meta(
    endpoint: &SubstitutionEndpoint<'_>,
    headers: &[(String, String)],
) -> Vec<(String, AuthType)> {
    headers
        .iter()
        .filter_map(|(_, v)| find_placeholder(v))
        .filter_map(|ph| endpoint.resolve_meta(ph))
        .collect()
}

// ============================================================================
// Transport — the host-local listener + the real-TLS forward leg (D-T2)
// ============================================================================

// The wire envelope (`WireRequest`/`WireResponse`) lives in
// `mvm_core::substitution_wire` so the in-guest client and this server share
// one contract (imported at the top of this file).

/// The response from the real destination.
pub struct ForwardResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Errors from the forward leg.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("forward failed: {0}")]
    Failed(String),
}

/// Errors from building a [`SubstitutionService`] from an admitted plan.
#[derive(Debug, thiserror::Error)]
pub enum FromPlanError {
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    #[error(transparent)]
    Forward(#[from] ForwardError),
}

/// Forwards a prepared (credential-substituted) request to the real
/// destination and returns its response — the real-TLS leg of the endpoint.
/// A trait so the listener can be tested with a mock that records the
/// credential it received without a network call.
#[async_trait]
pub trait Forwarder: Send + Sync {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError>;
}

/// Flatten an error and its `source()` chain into one message. reqwest wraps
/// the underlying connect/TLS/resolver cause as a source; the outer
/// `to_string()` alone is just "error sending request for url (...)", which
/// hides whether a forward failed on DNS, the SSRF filter, TLS, or timeout.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// Production forwarder: a hardened reqwest client (TLS 1.3 min, no redirects)
/// makes the real request. Unlike the HTTPS-only tool clients, the egress
/// forward target can be plain `http` (the guest's request scheme), so the
/// client is built **per request**: we resolve the host, SSRF-filter the IPs,
/// and pin them on the URL's *real* port via `resolve_to_addrs` — the shared
/// `SsrfFilteringResolver` hardcodes 443 and would send an `http` forward to the
/// HTTPS port. Plan 129 / ADR-067.
pub struct ReqwestForwarder {
    timeout_secs: u64,
}

impl ReqwestForwarder {
    pub fn new(timeout_secs: u64) -> Result<Self, ForwardError> {
        Ok(Self { timeout_secs })
    }
}

#[async_trait]
impl Forwarder for ReqwestForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        let method = reqwest::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| ForwardError::Failed(format!("bad method: {e}")))?;
        // Resolve + SSRF-filter the host ourselves, then pin reqwest to the safe
        // IPs on the URL's real port (default 80 for http, 443 for https, or an
        // explicit port). Keeps SSRF filtering without the resolver's 443 bug.
        let url = Url::parse(&req.url)
            .map_err(|e| ForwardError::Failed(format!("bad url {}: {e}", req.url)))?;
        let host = url
            .host_str()
            .ok_or_else(|| ForwardError::Failed(format!("url {} has no host", req.url)))?
            .to_string();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| ForwardError::Failed(format!("url {} has no port", req.url)))?;
        let addrs: Vec<std::net::SocketAddr> = resolve_ssrf_safe_ips(&host)
            .await
            .map_err(ForwardError::Failed)?
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip, port))
            .collect();
        let client = hardened_client_builder_no_dns(self.timeout_secs)
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|e| ForwardError::Failed(e.to_string()))?;
        let mut rb = client.request(method, &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        if !req.body.is_empty() {
            rb = rb.body(req.body);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| ForwardError::Failed(err_chain(&e)))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ForwardError::Failed(err_chain(&e)))?
            .to_vec();
        Ok(ForwardResponse {
            status,
            headers,
            body,
        })
    }
}

/// The running host substitution endpoint: the admission-minted placeholder
/// registry, the secret resolver, and the forward leg. Placeholders are minted
/// at admission (ADR-067 §4), so the registry is read-only while serving.
pub struct SubstitutionService {
    registry: Arc<SubstitutionRegistry>,
    resolver: Arc<dyn SecretResolver>,
    forwarder: Arc<dyn Forwarder>,
    /// Egress redactor (Plan 129 Phase E). Masks *undeclared* secret-shaped /
    /// PII content out of an outbound request before forwarding — the
    /// request-level twin of the gateway bridge's packet redactor, sharing one
    /// `RedactingSubstitution` definition so every backend that routes egress
    /// through this endpoint scrubs identically. Built once (rule compilation).
    redactor: RedactingSubstitution,
    /// Optional chain-signed audit recorder. When set, each substitution emits
    /// a `secret.substituted` entry (metadata only — claim 13).
    recorder: Option<Recorder>,
    /// Plan 129 Stage 2 — the per-VM name-constrained intermediate the `https`
    /// terminator mints per-SNI leaves under. `None` ⇒ no TLS leg (Stage 1b
    /// `http`-only). Set from `EndpointConfig.tls_intermediate` at assemble.
    tls_intermediate: Option<Arc<mvm_core::crypto::egress_ca::VmIntermediate>>,
}

impl SubstitutionService {
    pub fn new(
        registry: Arc<SubstitutionRegistry>,
        resolver: Arc<dyn SecretResolver>,
        forwarder: Arc<dyn Forwarder>,
    ) -> Self {
        Self {
            registry,
            resolver,
            forwarder,
            redactor: RedactingSubstitution::with_default_rules(),
            recorder: None,
            tls_intermediate: None,
        }
    }

    /// Attach a chain-signed audit recorder; each substitution then emits a
    /// `secret.substituted` entry (metadata only — claim 13).
    pub fn with_recorder(mut self, recorder: Recorder) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Plan 129 Stage 2 — attach the per-VM egress intermediate so the
    /// terminator can terminate bound-host `https`. Absent ⇒ `http`-only.
    pub fn with_tls_intermediate(
        mut self,
        intermediate: mvm_core::crypto::egress_ca::VmIntermediate,
    ) -> Self {
        self.tls_intermediate = Some(Arc::new(intermediate));
        self
    }

    /// Assemble a ready-to-serve service from an admitted plan's secret
    /// bindings: build the registry ([`assemble_registry`]), a [`LocalResolver`]
    /// over the tenant's secret store, and a hardened-reqwest forwarder.
    /// Returns the service plus the `(guest name, placeholder)` pairs the
    /// supervisor injects into the guest. The caller binds the listener and
    /// calls [`Self::serve`].
    pub fn from_plan(
        plan_secrets: &[SecretBinding],
        tenant: &str,
        bindings: &dyn BindingStore,
        secret_store: Arc<dyn SecretStore>,
        forward_timeout_secs: u64,
        tls_intermediate: Option<mvm_core::crypto::egress_ca::VmIntermediate>,
    ) -> Result<(Arc<Self>, HandedPlaceholders), FromPlanError> {
        let (registry, handed) = assemble_registry(plan_secrets, tenant, bindings)?;
        let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new(tenant, secret_store));
        let forwarder: Arc<dyn Forwarder> = Arc::new(ReqwestForwarder::new(forward_timeout_secs)?);
        let mut service = Self::new(Arc::new(registry), resolver, forwarder);
        if let Some(intermediate) = tls_intermediate {
            service = service.with_tls_intermediate(intermediate);
        }
        Ok((Arc::new(service), handed))
    }

    /// Accept loop: one routed request per connection, framed JSON, a task per
    /// connection. Runs until the listener errors.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_connection(stream).await {
                            tracing::warn!(error = %e, "substitution endpoint connection failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "substitution endpoint accept failed; stopping");
                    return;
                }
            }
        }
    }

    /// Accept loop over a host **AF_VSOCK** listener — the QEMU (`vhost-vsock`)
    /// guest→host path. Firecracker/libkrun route guest→host through a per-port
    /// UDS instead and use [`Self::serve`]. Both `accept(2)` and the per-
    /// connection framing run with **blocking** I/O on `spawn_blocking` threads
    /// (tokio's async reactor doesn't interplay reliably with an AF_VSOCK fd);
    /// the async forward leg is driven via `Handle::block_on`. No new dep.
    #[cfg(target_os = "linux")]
    pub async fn serve_vsock(self: Arc<Self>, listener: vsock::VsockListener) {
        loop {
            let listen_fd = listener.raw_fd();
            let accepted = tokio::task::spawn_blocking(move || vsock::accept(listen_fd)).await;
            let conn_fd = match accepted {
                Ok(Ok(fd)) => fd,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "vsock substitution accept failed; stopping");
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "vsock accept task panicked; stopping");
                    return;
                }
            };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = me.handle_vsock_connection(conn_fd).await {
                    tracing::warn!(error = %e, "vsock substitution connection failed");
                }
            });
        }
    }

    /// Accept loop for the transparent egress **terminator** (Plan 129 stage
    /// 1b): the host nft `nat` chain REDIRECTs a guest's outbound TCP here, we
    /// recover the original destination via `SO_ORIGINAL_DST`, substitute any
    /// secret placeholder in the request (claim-12 bind-checked), and splice
    /// the request to the real destination — returning its response verbatim.
    ///
    /// Linux-only: `SO_ORIGINAL_DST` is an `SOL_IP` getsockopt. The substitution
    /// core ([`terminator::handler::handle_request`]) and the splice
    /// ([`terminator::listener::forward_http_raw`]) are sync + blocking, so each
    /// connection's syscalls (orig-dst, request read, forward, write-back) run
    /// on `spawn_blocking` threads, off the reactor. A failure on one connection
    /// is logged and the socket dropped — never fatal to the loop.
    ///
    /// `timeout` is the configured per-connection I/O deadline (the endpoint's
    /// `forward_timeout_secs`), applied to BOTH the untrusted guest-facing socket
    /// (read+write) and the upstream forward leg. Without it a guest that sends a
    /// partial header or stops reading mid-write-back would park a blocking-pool
    /// thread forever — a bounded pool means a hostile guest could exhaust it.
    #[cfg(target_os = "linux")]
    pub async fn serve_terminator(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        timeout: std::time::Duration,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_terminator_connection(stream, timeout).await {
                            tracing::warn!(error = %e, "terminator connection failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "terminator accept failed; stopping");
                    return;
                }
            }
        }
    }

    /// Handle one redirected guest connection: recover orig-dst, read the
    /// request, substitute + forward, write the response back. claim-12
    /// fail-closed is enforced inside `handle_request` (it refuses an unbound
    /// destination / unknown placeholder before the forward runs); on refusal
    /// we log and close WITHOUT forwarding.
    #[cfg(target_os = "linux")]
    async fn handle_terminator_connection(
        &self,
        stream: tokio::net::TcpStream,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        use crate::keyholder::SubstitutionEndpoint;
        use crate::supervisor::terminator;
        use std::io::Write;

        // The orig-dst getsockopt + bounded request read are blocking syscalls.
        // The redirected socket is UNTRUSTED: set read+write deadlines so a guest
        // that never completes its header (`\r\n\r\n`) or stalls mid-write-back
        // can't park this blocking-pool thread forever (bounded pool ⇒ DoS).
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;
        std_stream.set_read_timeout(Some(timeout))?;
        std_stream.set_write_timeout(Some(timeout))?;

        // Recover the original destination first (cheap getsockopt) so we can
        // branch http(:80, Stage 1b) vs https(:443, Stage 2) before reading.
        let (std_stream, orig_dst) = tokio::task::spawn_blocking(move || {
            let orig_dst = terminator::orig_dst::original_dst(&std_stream)?;
            anyhow::Ok((std_stream, orig_dst))
        })
        .await??;

        if orig_dst.port() == 443 {
            return self
                .handle_https_terminator(std_stream, orig_dst, timeout)
                .await;
        }

        // ── Stage 1b: cleartext :80 ──
        let mut std_stream = std_stream;
        let (mut std_stream, raw) = tokio::task::spawn_blocking(move || {
            let raw = terminator::read::read_http_request(&mut std_stream)?;
            anyhow::Ok((std_stream, raw))
        })
        .await??;

        // Capture audit metadata before substitution consumes the request —
        // same as the UDS/vsock `process` path (shared helper so they can't
        // drift). resolve_meta touches no value, so this is claim-13 safe.
        let req = terminator::request::proxy_request_from_origin_form(&raw, orig_dst)?;
        let endpoint = SubstitutionEndpoint::new(&self.registry, self.resolver.as_ref());
        let destination = destination_host(&req.url).ok();
        let substituted = collect_substituted_meta(&endpoint, &req.headers);
        drop(req);

        // Substitution + the raw forward leg are sync; run them off the reactor.
        // Clone the Arcs the closure needs (it must be 'static — can't borrow
        // &self across spawn_blocking); the endpoint is rebuilt inside.
        let registry = Arc::clone(&self.registry);
        let resolver = Arc::clone(&self.resolver);
        let forwarded = tokio::task::spawn_blocking(move || {
            let endpoint = SubstitutionEndpoint::new(&registry, resolver.as_ref());
            terminator::handler::handle_request(&raw, orig_dst, &endpoint, |prepared, dst| {
                terminator::listener::forward_http_raw(prepared, dst, timeout)
            })
        })
        .await?;

        let resp = match forwarded {
            Ok(resp) => resp,
            Err(e) => {
                // claim-12 fail-closed: refusal closes the socket, no forward.
                tracing::warn!(error = %e, "terminator refused or forward failed; closing");
                return Ok(());
            }
        };

        self.audit_substitutions(&substituted, destination.as_deref())
            .await;

        tokio::task::spawn_blocking(move || {
            std_stream.write_all(&resp)?;
            std_stream.flush()
        })
        .await??;
        Ok(())
    }

    /// Stage 2 (`:443`): peek the ClientHello SNI, then **terminate** TLS for a
    /// bound host (mint a leaf under the per-VM intermediate, decrypt, substitute,
    /// re-originate over the hardened reqwest forwarder) or **splice** an unbound
    /// host straight through without decrypting. Fail-closed: a bound host whose
    /// substitution refuses closes the socket without forwarding (claim 12).
    #[cfg(target_os = "linux")]
    async fn handle_https_terminator(
        &self,
        std_stream: std::net::TcpStream,
        orig_dst: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        use crate::keyholder::SubstitutionEndpoint;
        use crate::supervisor::terminator::tls;

        // Peek the SNI without consuming the stream (blocking).
        let (std_stream, sni) = tokio::task::spawn_blocking(move || {
            let sni = tls::peek_sni(&std_stream)?;
            anyhow::Ok((std_stream, sni))
        })
        .await??;

        // Terminate ONLY a host bound by some workload secret, and only when we
        // hold the per-VM intermediate. Everything else is spliced end-to-end —
        // never decrypted (zero added host visibility over substitution's needs).
        let bound_sni = sni.filter(|s| self.registry.host_is_bound(s));
        let (intermediate, sni) = match (self.tls_intermediate.clone(), bound_sni) {
            (Some(intermediate), Some(sni)) => (intermediate, sni),
            _ => {
                return tokio::task::spawn_blocking(move || {
                    tls::splice_unbound(std_stream, orig_dst, timeout)
                })
                .await?;
            }
        };

        let config = Arc::new(tls::server_config_for_sni(&intermediate, &sni)?);
        let registry = Arc::clone(&self.registry);
        let resolver = Arc::clone(&self.resolver);
        let forwarder = Arc::clone(&self.forwarder);
        let handle = tokio::runtime::Handle::current();
        let outcome = tokio::task::spawn_blocking(move || {
            let endpoint = SubstitutionEndpoint::new(&registry, resolver.as_ref());
            tls::terminate_and_substitute(std_stream, config, orig_dst, &endpoint, |prepared| {
                // The upstream leg reuses the hardened reqwest forwarder (TLS +
                // system roots + SSRF filter); block_on is safe on a blocking
                // thread. reqwest decoded the body, so we re-frame the response.
                let resp = handle
                    .block_on(forwarder.forward(prepared.clone()))
                    .map_err(|e| anyhow::anyhow!("upstream forward: {e}"))?;
                Ok(tls::serialize_http_response(
                    resp.status,
                    &resp.headers,
                    &resp.body,
                ))
            })
        })
        .await?;

        match outcome {
            Ok(o) => {
                self.audit_substitutions(&o.substituted, o.destination.as_deref())
                    .await;
                Ok(())
            }
            Err(e) => {
                tracing::warn!(error = %e, "https terminator refused or failed; closing");
                Ok(())
            }
        }
    }

    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), FrameError> {
        let wire: WireRequest = read_json_frame(&mut stream, MAX_FRAME_BYTES).await?;
        let resp = self.process(wire).await;
        write_json_frame(&mut stream, &resp).await
    }

    /// Handle one vsock connection: the raw socket I/O is blocking, so the
    /// frame read/write run on `spawn_blocking` threads, while `process` (the
    /// substitution + forward leg — the prod forward needs the tokio reactor)
    /// runs on the runtime. We do NOT `block_on` the forward from a blocking
    /// thread: a `spawn_blocking` thread is still inside the runtime context,
    /// so tokio's `block_on` panics there.
    #[cfg(target_os = "linux")]
    async fn handle_vsock_connection(&self, conn_fd: std::os::fd::RawFd) -> std::io::Result<()> {
        use std::os::fd::FromRawFd;
        // SAFETY: `conn_fd` is an owned connected stream socket from `accept`.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(conn_fd) };
        let (mut stream, wire) = tokio::task::spawn_blocking(move || {
            let mut s = stream;
            let wire: WireRequest = vsock::read_frame_sync(&mut s)?;
            std::io::Result::Ok((s, wire))
        })
        .await
        .map_err(std::io::Error::other)??;
        let resp = self.process(wire).await;
        tokio::task::spawn_blocking(move || vsock::write_frame_sync(&mut stream, &resp))
            .await
            .map_err(std::io::Error::other)?
    }

    async fn process(&self, wire: WireRequest) -> WireResponse {
        let body = match B64.decode(wire.body_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                return WireResponse::Refused {
                    message: format!("bad body encoding: {e}"),
                };
            }
        };
        let req = ProxyRequest {
            method: wire.method,
            url: wire.url,
            headers: wire.headers,
            body,
        };
        // Per-request endpoint: two refs, cheap; the registry is read-only
        // after admission minted its placeholders.
        let registry: &SubstitutionRegistry = &self.registry;
        let endpoint = SubstitutionEndpoint::new(registry, self.resolver.as_ref());
        // Capture audit metadata (name + auth-type per substituted secret, and
        // the destination) before `prepare_request` consumes `req`.
        let destination = destination_host(&req.url).ok();
        let substituted = collect_substituted_meta(&endpoint, &req.headers);
        // Phase E: scrub undeclared secret-shaped / PII content before any
        // substitution. Runs first so a declared placeholder (not secret-shaped,
        // host-reserved) survives to be substituted, while an undeclared secret
        // the guest put in the body or a non-placeholder header is masked and
        // never reaches the wire.
        let (req, redaction_hits) = self.redact_outbound(req);
        let prepared = match prepare_request(&endpoint, req) {
            Ok(p) => p,
            Err(e) => {
                return WireResponse::Refused {
                    message: e.to_string(),
                };
            }
        };
        match self.forwarder.forward(prepared).await {
            Ok(r) => {
                self.audit_substitutions(&substituted, destination.as_deref())
                    .await;
                self.audit_redactions(&redaction_hits, destination.as_deref())
                    .await;
                WireResponse::Ok {
                    status: r.status,
                    headers: r.headers,
                    body_b64: B64.encode(r.body),
                }
            }
            Err(e) => WireResponse::Refused {
                message: e.to_string(),
            },
        }
    }

    /// Mask undeclared secret-shaped / PII content out of a guest-authored
    /// request before it leaves the host — the request-level twin of the
    /// gateway bridge's packet redactor (one shared `RedactingSubstitution`).
    /// A header value carrying a declared placeholder is left untouched (the
    /// real credential is substituted into it next, and the host-reserved
    /// placeholder is not secret-shaped); every other header value and the body
    /// are scrubbed. Returns the rewritten request plus the categories that
    /// fired, for the claim-13 audit. Plan 129 Phase E / ADR-067.
    fn redact_outbound(&self, mut req: ProxyRequest) -> (ProxyRequest, RedactionHits) {
        let mut hits = RedactionHits::default();
        for (_, value) in req.headers.iter_mut() {
            if find_placeholder(value).is_some() {
                continue; // declared placeholder — substituted next, never masked.
            }
            if let Some((masked, h)) = self.redactor.redact_bytes(value.as_bytes()) {
                *value = String::from_utf8_lossy(&masked).into_owned();
                hits.merge(h);
            }
        }
        if let Some((masked, h)) = self.redactor.redact_bytes(&req.body) {
            req.body = masked;
            hits.merge(h);
        }
        (req, hits)
    }

    /// Emit one `secret.redacted { destination, categories }` entry when the
    /// egress redactor masked anything (claim 13 — category names + destination,
    /// never the bytes). Best-effort; no-op without a recorder or a destination.
    async fn audit_redactions(&self, hits: &RedactionHits, destination: Option<&str>) {
        if hits.is_empty() {
            return;
        }
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        let mut categories: Vec<&str> = hits
            .secrets
            .iter()
            .chain(hits.pii.iter())
            .copied()
            .collect();
        categories.sort_unstable();
        categories.dedup();
        if let Err(e) = emit_secret_redacted(recorder, dest, &categories.join(",")).await {
            tracing::warn!(error = %e, "secret.redacted audit emit failed");
        }
    }

    /// Emit one `secret.substituted` audit entry per substituted secret (claim
    /// 13 — metadata only). Best-effort: an audit failure is logged, never
    /// fails the request. No-op when no recorder is wired.
    async fn audit_substitutions(
        &self,
        substituted: &[(String, AuthType)],
        destination: Option<&str>,
    ) {
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        for (name, auth_type) in substituted {
            if let Err(e) = emit_secret_substituted(recorder, name, dest, *auth_type).await {
                tracing::warn!(error = %e, secret = %name, "secret.substituted audit emit failed");
            }
        }
    }
}

/// Host-side AF_VSOCK listener for the QEMU (`vhost-vsock`) guest→host
/// substitution path. Firecracker/libkrun bridge guest→host through a per-port
/// UDS — those use the `UnixListener` `serve`. Raw libc (no async-vsock dep);
/// blocking `accept` is driven from the async loop via `spawn_blocking`.
#[cfg(target_os = "linux")]
pub mod vsock {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    const AF_VSOCK: libc::c_int = 40;
    /// Bind to any guest CID so any guest on this host can reach the endpoint.
    const VMADDR_CID_ANY: u32 = u32::MAX;

    // Kernel uapi `struct sockaddr_vm`: family u16 + reserved u16 + port u32 +
    // cid u32 + 4-byte pad = 16.
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }
    const _: () = assert!(std::mem::size_of::<SockaddrVm>() == 16);

    /// A bound, listening host AF_VSOCK socket on a vsock port.
    pub struct VsockListener {
        fd: OwnedFd,
    }

    impl VsockListener {
        /// Bind + listen on AF_VSOCK `(VMADDR_CID_ANY, port)`.
        pub fn bind(port: u32) -> io::Result<Self> {
            // SAFETY: standard socket/bind/listen on AF_VSOCK; `addr` is fully
            // initialized and sized exactly. The fd is adopted by `OwnedFd`
            // immediately, closing on drop / on the error paths.
            unsafe {
                let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let owned = OwnedFd::from_raw_fd(fd);
                let addr = SockaddrVm {
                    svm_family: AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: VMADDR_CID_ANY,
                    svm_zero: [0; 4],
                };
                if libc::bind(
                    fd,
                    std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::listen(fd, 128) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self { fd: owned })
            }
        }

        pub fn raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    /// Blocking `accept(2)` on a listening AF_VSOCK fd, returning the
    /// connection fd. Run via `spawn_blocking` from the async serve loop.
    pub fn accept(listen_fd: RawFd) -> io::Result<RawFd> {
        // SAFETY: accept(2) on a listening AF_VSOCK fd; peer addr not needed.
        let cfd = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cfd)
    }

    /// Read one length-prefixed JSON frame (4-byte BE length + body) with
    /// blocking I/O. The vsock connection is handled synchronously (tokio's
    /// async reactor doesn't interplay reliably with an AF_VSOCK fd).
    pub fn read_frame_sync<T: serde::de::DeserializeOwned, R: io::Read>(
        r: &mut R,
    ) -> io::Result<T> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > super::MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf)?;
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write one length-prefixed JSON frame with blocking I/O.
    pub fn write_frame_sync<T: serde::Serialize, W: io::Write>(
        w: &mut W,
        value: &T,
    ) -> io::Result<()> {
        let body =
            serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = u32::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
        w.write_all(&len.to_be_bytes())?;
        w.write_all(&body)?;
        w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SubstitutionRegistry};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn resolver_with(name: &str, value: &str) -> (tempfile::TempDir, LocalResolver) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put("local", name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        (dir, LocalResolver::new("local", store))
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    #[test]
    fn prepares_request_with_real_credential_for_a_bound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat".into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {}", ph.as_str())),
                ("content-type".into(), "application/json".into()),
            ],
            body: b"{}".to_vec(),
        };
        let prepared = prepare_request(&endpoint, req).unwrap();
        assert_eq!(
            prepared.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        // A header without a placeholder is untouched.
        assert_eq!(prepared.headers[1].1, "application/json");
    }

    #[test]
    fn refuses_a_request_to_an_unbound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {}", ph.as_str()))],
            body: vec![],
        };
        let err = prepare_request(&endpoint, req).unwrap_err();
        assert!(matches!(err, ProxyError::Substitute(_)));
    }

    #[test]
    fn passes_through_a_request_without_a_placeholder() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), "Bearer ya29.real-token".into())],
            body: vec![],
        };
        let prepared = prepare_request(&endpoint, req.clone()).unwrap();
        assert_eq!(prepared.headers, req.headers);
    }

    #[test]
    fn rejects_a_url_without_a_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "GET".into(),
            url: "not a url".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(matches!(
            prepare_request(&endpoint, req).unwrap_err(),
            ProxyError::BadUrl(_)
        ));
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::keyholder::LocalResolver;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Records the request it was handed so a test can prove the destination
    /// (not the guest) received the real credential — without a network call.
    struct MockForwarder {
        seen: Mutex<Option<PreparedRequest>>,
    }

    #[async_trait]
    impl Forwarder for MockForwarder {
        async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            *self.seen.lock().unwrap() = Some(req);
            Ok(ForwardResponse {
                status: 200,
                headers: vec![("x-mock".into(), "1".into())],
                body: b"pong".to_vec(),
            })
        }
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    /// Build a service over a file store seeded with `openai`=value, a registry
    /// holding one minted placeholder for `hosts`, and a `MockForwarder`.
    /// Returns the service, the minted placeholder string, and the forwarder.
    fn service_with(
        value: &str,
        hosts: &[&str],
    ) -> (
        Arc<SubstitutionService>,
        String,
        Arc<MockForwarder>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(value.to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", hosts)).as_str().to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let service = Arc::new(SubstitutionService::new(
            Arc::new(reg),
            resolver,
            forwarder.clone(),
        ));
        (service, ph, forwarder, dir)
    }

    /// End-to-end over a **real AF_VSOCK** connection (Linux vsock loopback,
    /// `VMADDR_CID_LOCAL`) — proving `serve_vsock` + the framed substitution
    /// path work over the actual transport, not just a UnixStream pair.
    /// Gracefully skips where vsock/loopback is unavailable (CI, macOS) so it
    /// only asserts where it can really run (a vsock-capable Linux box).
    #[cfg(target_os = "linux")]
    #[test]
    fn substitutes_over_real_af_vsock_loopback() {
        use super::vsock::VsockListener;
        use std::io::{Read, Write};
        use std::os::fd::FromRawFd;

        // serve_vsock's accept loop parks an un-cancellable spawn_blocking(accept);
        // a plain #[tokio::test] would hang on runtime drop waiting for it to
        // return. Build the runtime by hand and force teardown with
        // shutdown_timeout once the round-trip + assertions are done.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            const AF_VSOCK: libc::c_int = 40;
            const VMADDR_CID_LOCAL: u32 = 1;
            #[repr(C)]
            struct SockaddrVm {
                svm_family: libc::sa_family_t,
                svm_reserved1: u16,
                svm_port: u32,
                svm_cid: u32,
                svm_zero: [u8; 4],
            }

            let port = 54000 + (std::process::id() % 2000);
            let listener = match VsockListener::bind(port) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "SKIP substitutes_over_real_af_vsock_loopback: AF_VSOCK bind failed ({e})"
                    );
                    return;
                }
            };
            let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
            let server = tokio::spawn(Arc::clone(&service).serve_vsock(listener));

            // Client: connect over vsock loopback, send a framed WireRequest with the
            // placeholder, read the framed WireResponse. `None` = transport
            // unavailable → skip rather than assert.
            let client = tokio::task::spawn_blocking(move || -> Option<WireResponse> {
                let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
                if fd < 0 {
                    return None;
                }
                let addr = SockaddrVm {
                    svm_family: AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: VMADDR_CID_LOCAL,
                    svm_zero: [0; 4],
                };
                let rc = unsafe {
                    libc::connect(
                        fd,
                        std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                        std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
                    )
                };
                if rc < 0 {
                    unsafe { libc::close(fd) };
                    return None;
                }
                let mut s = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                // Bound the round-trip so a regression fails fast instead of hanging.
                s.set_read_timeout(Some(std::time::Duration::from_secs(15)))
                    .ok();
                s.set_write_timeout(Some(std::time::Duration::from_secs(15)))
                    .ok();
                let wire = WireRequest {
                    method: "POST".into(),
                    url: "https://api.openai.com/v1".into(),
                    headers: vec![("authorization".into(), format!("Bearer {ph}"))],
                    body_b64: String::new(),
                };
                let body = serde_json::to_vec(&wire).unwrap();
                s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
                s.write_all(&body).unwrap();
                s.flush().unwrap();
                let mut len = [0u8; 4];
                s.read_exact(&mut len).unwrap();
                let n = u32::from_be_bytes(len) as usize;
                let mut buf = vec![0u8; n];
                s.read_exact(&mut buf).unwrap();
                Some(serde_json::from_slice(&buf).unwrap())
            });
            // vsock does not reliably honor SO_RCVTIMEO, so the in-client read
            // timeout can't be trusted — bound the round-trip here so a server-side
            // regression fails fast instead of hanging until libtest's watchdog.
            let resp = match tokio::time::timeout(std::time::Duration::from_secs(20), client).await
            {
                Ok(joined) => joined.unwrap(),
                Err(_) => {
                    panic!("vsock loopback round-trip timed out (20s): serve_vsock did not reply")
                }
            };

            let Some(resp) = resp else {
                eprintln!(
                    "SKIP substitutes_over_real_af_vsock_loopback: vsock loopback unavailable"
                );
                server.abort();
                return;
            };

            // The destination (mock forwarder) saw the REAL credential over real vsock.
            let seen = forwarder.seen.lock().unwrap().clone().unwrap();
            assert_eq!(
                seen.headers[0],
                ("authorization".into(), "Bearer sk-live-zzz".into())
            );
            match resp {
                WireResponse::Ok { status, .. } => assert_eq!(status, 200),
                WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
            }
            server.abort();
        });
        rt.shutdown_timeout(std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn endpoint_substitutes_then_forwards_over_uds() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        // The forwarder (i.e. the destination) saw the REAL credential.
        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            seen.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        match resp {
            WireResponse::Ok {
                status, body_b64, ..
            } => {
                assert_eq!(status, 200);
                assert_eq!(B64.decode(body_b64).unwrap(), b"pong");
            }
            WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
        }
        server.abort();
    }

    /// Plan 129 Phase E / ADR-067: the endpoint scrubs an *undeclared*
    /// secret-shaped run from the outbound body before forwarding (the same
    /// redaction the gateway bridge applies, at the endpoint chokepoint so
    /// every backend routing egress through it is covered), while a *declared*
    /// placeholder is still substituted to its real credential. The destination
    /// sees the real declared credential and a masked undeclared one — the
    /// undeclared secret never leaves the host.
    #[tokio::test]
    async fn endpoint_redacts_undeclared_secret_in_body_then_forwards() {
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let leaked = "sk-".to_owned() + &"z".repeat(48);
        let body = format!("{{\"leak\":\"{leaked}\"}}");
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(body.as_bytes()),
        };

        let resp = service.process(wire).await;
        assert!(matches!(resp, WireResponse::Ok { .. }), "{resp:?}");

        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        // Declared secret: substituted to the real credential.
        assert_eq!(
            seen.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        // Undeclared secret in the body: masked before egress.
        let seen_body = String::from_utf8_lossy(&seen.body);
        assert!(
            !seen_body.contains(&leaked),
            "undeclared secret survived to the destination: {seen_body}"
        );
        assert!(
            seen_body.contains("XXX"),
            "body was not masked: {seen_body}"
        );
    }

    /// A clean request is forwarded byte-for-byte — redaction never rewrites
    /// content that doesn't match a secret/PII rule.
    #[tokio::test]
    async fn endpoint_forwards_clean_body_unchanged() {
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{\"prompt\":\"hello world\"}"),
        };

        let resp = service.process(wire).await;
        assert!(matches!(resp, WireResponse::Ok { .. }), "{resp:?}");
        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        assert_eq!(seen.body, b"{\"prompt\":\"hello world\"}");
    }

    #[test]
    fn from_plan_builds_a_service_and_handed_placeholders() {
        use crate::keyholder::{FileBindingStore, SecretBindingMeta};
        use mvm_core::plan::{SecretBinding, SecretSource};

        let dir = tempdir().unwrap();
        // Binding metadata (`secret set`) + the value store.
        let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
        bindings
            .put(
                "local",
                "openai",
                &SecretBindingMeta {
                    auth_type: AuthType::Bearer,
                    allowed_hosts: vec!["api.openai.com".into()],
                },
            )
            .unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk".to_string())),
            )
            .unwrap();
        let secret_store: Arc<dyn SecretStore> = Arc::new(store);

        let plan = [SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }];
        let (_service, handed) =
            SubstitutionService::from_plan(&plan, "local", &bindings, secret_store, 30, None)
                .unwrap();
        assert_eq!(handed.len(), 1);
        assert_eq!(handed[0].0, "OPENAI_API_KEY");
        assert!(handed[0].1.as_str().starts_with("mvm-secret-"));
    }

    #[tokio::test]
    async fn endpoint_refuses_unbound_destination_and_never_forwards() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        assert!(matches!(resp, WireResponse::Refused { .. }));
        // claim 12: an unbound destination never reaches the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn emits_secret_substituted_audit_on_success() {
        use crate::supervisor::audit_file::FileAuditSigner;
        use crate::supervisor::audit_recorder::Recorder;
        use ed25519_dalek::SigningKey;
        use mvm_core::plan::TenantId;

        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });

        let chain = dir.path().join("audit.jsonl");
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&[9u8; 32]), &chain).unwrap();
        let recorder = Recorder::new(Arc::new(signer), TenantId("local".into()));

        let service = Arc::new(
            SubstitutionService::new(Arc::new(reg), resolver, forwarder).with_recorder(recorder),
        );
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        // The audit emit completes before the Ok response is written, so the
        // chain entry is on disk by the time we read the reply.
        let _resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(logged.contains("secret.substituted"), "got: {logged}");
        assert!(logged.contains("openai"));
        assert!(logged.contains("api.openai.com"));
        // claim 13: the value never reaches the audit chain.
        assert!(
            !logged.contains("sk-live-zzz"),
            "audit chain must not carry the secret value: {logged}"
        );
        server.abort();
    }
}
