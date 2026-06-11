//! `L7EgressProxy` — the real `EgressProxy` impl that wires the
//! inspector chain into outbound HTTP traffic.
//!
//! ## Phase 1 scope (this module)
//!
//! - Pure inspection logic in [`L7EgressProxy::evaluate`]: takes
//!   (host, port, body) and a mockable `DnsResolver`, runs the
//!   chain twice (once with the host string, then again after
//!   DNS-pinning the resolved IP), returns an [`EgressDecision`]
//!   plus a structured [`AuditFields`] payload.
//! - HTTP CONNECT request parsing in [`parse_connect`].
//! - Per-connection lifecycle in [`L7EgressProxy::serve_connection`]:
//!   reads the CONNECT line, calls `evaluate`, writes a
//!   `200 Connection Established` or `403 Forbidden` response, and
//!   on Allow splices bytes via `tokio::io::copy_bidirectional` to
//!   the pinned upstream IP.
//! - TCP listener loop in [`L7EgressProxy::serve`].
//! - Audit emission via [`AuditSigner`] for every request.
//!
//! ## Out of scope (later)
//!
//! - TLS MITM (Phase 2).
//! - HTTP/2 / HTTP/3, connection pooling, bandwidth caps.
//! - Plain-HTTP request body inspection — Phase 1 ships HTTPS
//!   CONNECT only, plain HTTP is gated on `EgressPolicy::allow_plain_http`
//!   which the supervisor refuses to honour for `Variant::Prod`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::supervisor::audit::AuditError;
use crate::supervisor::egress::{EgressDecision, EgressError, EgressProxy};
use crate::supervisor::inspector::{InspectorChain, InspectorVerdict, RequestCtx};

/// Async DNS resolver, abstracted so tests can inject mock IPs and
/// the production wiring uses `tokio::net::lookup_host`. Returns
/// the **first** address — the proxy resolves once, pins that IP
/// into `RequestCtx`, and connects to it (not the hostname); this
/// is the DNS-rebinding defence.
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve_one(&self, host: &str, port: u16) -> Result<IpAddr, EgressError>;
}

/// Production resolver — wraps `tokio::net::lookup_host`. Returns
/// the first resolved address (IPv4 preferred when both are
/// returned by the OS resolver, but no explicit ordering is
/// guaranteed). Tests use a [`MockDnsResolver`] instead.
pub struct TokioDnsResolver;

#[async_trait]
impl DnsResolver for TokioDnsResolver {
    async fn resolve_one(&self, host: &str, port: u16) -> Result<IpAddr, EgressError> {
        let target = format!("{host}:{port}");
        let mut iter = tokio::net::lookup_host(target.as_str())
            .await
            .map_err(|e| EgressError::UpstreamUnreachable(format!("dns lookup {target}: {e}")))?;
        match iter.next() {
            Some(addr) => Ok(addr.ip()),
            None => Err(EgressError::UpstreamUnreachable(format!(
                "dns lookup {target}: no addresses returned"
            ))),
        }
    }
}

/// Verdict outcome surfaced to the audit signer. `Allow` means the
/// chain ran end-to-end; `Deny` means an inspector short-circuited;
/// `Transform` means at least one inspector returned `Transform`
/// (i.e., PII detected) but the chain still ended in Allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressOutcome {
    Allow,
    Deny,
    Transform,
}

/// Structured audit payload emitted per request, regardless of
/// outcome. The proxy hands this to [`crate::supervisor::audit::AuditSigner`]
/// after each [`evaluate`](L7EgressProxy::evaluate) call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFields {
    pub outcome: EgressOutcome,
    pub deciding_inspector: &'static str,
    pub host: String,
    pub port: u16,
    pub path: String,
    /// Every `Transform { note }` collected during the run, in
    /// chain order. Empty when no inspector returned Transform.
    pub transforms: Vec<String>,
    /// Populated for `outcome == Deny`. Reason text from the
    /// short-circuiting inspector.
    pub reason: Option<String>,
    /// Pinned destination IP after DNS resolution. `None` when the
    /// chain denied before resolution (e.g., DestinationPolicy
    /// blocked on the host string).
    pub resolved_ip: Option<IpAddr>,
    pub duration_ms: u32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub decision: EgressDecision,
    pub audit: AuditFields,
}

/// Sink the proxy hands [`AuditFields`] to. The supervisor's
/// production wiring wraps this around an [`AuditSigner`] +
/// plan/bundle binding, building proper `AuditEntry` records.
/// Tests use [`CapturingEgressAuditSink`] directly.
#[async_trait]
pub trait EgressAuditSink: Send + Sync {
    async fn record(&self, fields: &AuditFields) -> Result<(), AuditError>;
}

/// In-memory sink for tests + dev mode. A chain-signing production
/// sink will replace this in non-dev paths.
pub struct CapturingEgressAuditSink {
    entries: std::sync::Mutex<Vec<AuditFields>>,
}

impl CapturingEgressAuditSink {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn entries(&self) -> Vec<AuditFields> {
        self.entries
            .lock()
            .expect("CapturingEgressAuditSink mutex poisoned")
            .clone()
    }
}

impl Default for CapturingEgressAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EgressAuditSink for CapturingEgressAuditSink {
    async fn record(&self, fields: &AuditFields) -> Result<(), AuditError> {
        self.entries
            .lock()
            .expect("CapturingEgressAuditSink mutex poisoned")
            .push(fields.clone());
        Ok(())
    }
}

/// Sink that swallows audit records. Useful as a default for
/// callsites that don't yet have a plan/bundle binding (the
/// supervisor wires a real sink before exposing the proxy to
/// workload traffic). Errors silently — tests should use
/// [`CapturingEgressAuditSink`] when verifying audit emission.
pub struct NoopEgressAuditSink;

#[async_trait]
impl EgressAuditSink for NoopEgressAuditSink {
    async fn record(&self, _fields: &AuditFields) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Parsed `CONNECT host:port HTTP/1.x` request line. Phase 1 only
/// handles CONNECT; plain-HTTP request parsing lands later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConnectParseError {
    #[error("expected CONNECT method, got {0}")]
    NotConnect(String),
    #[error("authority missing port: {0}")]
    AuthorityMissingPort(String),
    #[error("authority port not a u16: {0}")]
    BadPort(String),
    #[error("malformed request line")]
    Malformed,
    #[error("non-utf8 bytes in request line")]
    NonUtf8,
}

/// Parse the first line of an HTTP CONNECT request.
///
/// Accepts `CONNECT host:port HTTP/1.x\r\n`. Tolerant about the
/// HTTP-version field (we only require it starts with `HTTP/1.`),
/// strict about the method and authority shape.
///
/// Phase 1 only consumes the request line — full header parsing
/// isn't needed because we're either (a) accepting the CONNECT
/// (in which case bytes after the empty line are the client's TLS
/// payload, opaque to us) or (b) refusing it (we reply with 403
/// and close).
pub fn parse_connect(line: &[u8]) -> Result<ConnectRequest, ConnectParseError> {
    let line = std::str::from_utf8(line).map_err(|_| ConnectParseError::NonUtf8)?;
    let line = line
        .strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line);
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().ok_or(ConnectParseError::Malformed)?;
    let authority = parts.next().ok_or(ConnectParseError::Malformed)?;
    let version = parts.next().ok_or(ConnectParseError::Malformed)?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(ConnectParseError::NotConnect(method.to_string()));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(ConnectParseError::Malformed);
    }
    let (host, port_str) = authority
        .rsplit_once(':')
        .ok_or_else(|| ConnectParseError::AuthorityMissingPort(authority.to_string()))?;
    if host.is_empty() {
        return Err(ConnectParseError::AuthorityMissingPort(
            authority.to_string(),
        ));
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| ConnectParseError::BadPort(port_str.to_string()))?;
    Ok(ConnectRequest {
        host: host.to_string(),
        port,
    })
}

pub struct L7EgressProxy {
    chain: Arc<InspectorChain>,
    resolver: Arc<dyn DnsResolver>,
    audit: Arc<dyn EgressAuditSink>,
    body_cap_bytes: usize,
    /// Whether plain-HTTP requests (where the proxy reads the body
    /// before invoking the chain) are allowed. The HTTPS CONNECT
    /// path doesn't read bodies and is unaffected by this flag.
    allow_plain_http: bool,
}

impl L7EgressProxy {
    pub fn new(
        chain: Arc<InspectorChain>,
        resolver: Arc<dyn DnsResolver>,
        audit: Arc<dyn EgressAuditSink>,
        body_cap_bytes: usize,
        allow_plain_http: bool,
    ) -> Self {
        Self {
            chain,
            resolver,
            audit,
            body_cap_bytes,
            allow_plain_http,
        }
    }

    pub fn body_cap_bytes(&self) -> usize {
        self.body_cap_bytes
    }

    pub fn allow_plain_http(&self) -> bool {
        self.allow_plain_http
    }

    /// Bind a TCP listener to `bind_addr` and accept connections.
    /// Each accepted connection is served on a fresh tokio task
    /// via [`L7EgressProxy::serve_connection`]. Returns when the
    /// listener errors or the future is dropped.
    ///
    /// The proxy is `Arc`-wrapped so per-connection tasks can
    /// hold a clone without taking exclusive ownership.
    pub async fn serve(self: Arc<Self>, bind_addr: SocketAddr) -> std::io::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        loop {
            let (stream, peer) = listener.accept().await?;
            let proxy = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = proxy.serve_connection(stream, peer).await {
                    // Audit sink already recorded the verdict; this
                    // log line is for operator-side noise on
                    // unrecoverable I/O.
                    tracing::warn!(peer = %peer, error = %e, "proxy connection ended with error");
                }
            });
        }
    }

    /// Serve one accepted client connection: read the CONNECT
    /// request line, run [`evaluate`], write the `200`/`403`
    /// response, and on Allow splice bytes to the pinned upstream.
    pub async fn serve_connection(
        self: Arc<Self>,
        mut client: TcpStream,
        _peer: SocketAddr,
    ) -> std::io::Result<()> {
        // Read the request line (up to the first \r\n). Cap at 8 KiB
        // — a CONNECT line never exceeds this and an unbounded read
        // is a DoS vector.
        let mut buf = [0u8; 8192];
        let mut filled = 0usize;
        let line_end = loop {
            if filled == buf.len() {
                let _ = write_status(&mut client, 400, "Request-line too long").await;
                return Ok(());
            }
            let n = client.read(&mut buf[filled..]).await?;
            if n == 0 {
                // Client hung up before sending a full line. Nothing
                // to audit (we don't even know the host) — drop.
                return Ok(());
            }
            filled += n;
            if let Some(idx) = find_subsequence(&buf[..filled], b"\r\n") {
                break idx;
            }
        };
        let request_line = &buf[..line_end];

        let req = match parse_connect(request_line) {
            Ok(req) => req,
            Err(e) => {
                let _ = write_status(&mut client, 400, &format!("bad CONNECT: {e}")).await;
                return Ok(());
            }
        };

        // Run the chain. Body is empty for CONNECT.
        let result = match self.evaluate(&req.host, req.port, Vec::new()).await {
            Ok(r) => r,
            Err(EgressError::UpstreamUnreachable(msg)) => {
                let _ = write_status(&mut client, 502, &format!("dns: {msg}")).await;
                return Ok(());
            }
            Err(e) => {
                let _ = write_status(&mut client, 500, &format!("internal: {e}")).await;
                return Ok(());
            }
        };

        // Emit audit BEFORE responding so the audit chain sees
        // every attempt even if the client hangs up after.
        let _ = self.audit.record(&result.audit).await;

        match result.decision {
            EgressDecision::Deny { reason } => {
                let _ = write_403(&mut client, &reason).await;
                Ok(())
            }
            EgressDecision::Allow => {
                // Connect to the pinned IP, NOT the hostname (DNS
                // rebinding defence — the IP we ran SsrfGuard
                // against is the only IP we'll connect to).
                let upstream_ip = match result.audit.resolved_ip {
                    Some(ip) => ip,
                    None => {
                        // Host was an IP literal; SsrfGuard already
                        // checked it. Use it directly.
                        match req.host.parse::<IpAddr>() {
                            Ok(ip) => ip,
                            Err(_) => {
                                // Should not happen — evaluate must
                                // populate resolved_ip for hostnames.
                                let _ =
                                    write_status(&mut client, 500, "internal: missing pinned IP")
                                        .await;
                                return Ok(());
                            }
                        }
                    }
                };
                let upstream_addr = SocketAddr::new(upstream_ip, req.port);
                match TcpStream::connect(upstream_addr).await {
                    Ok(mut upstream) => {
                        if write_200_established(&mut client).await.is_err() {
                            return Ok(());
                        }
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                        Ok(())
                    }
                    Err(e) => {
                        let _ =
                            write_status(&mut client, 502, &format!("upstream connect: {e}")).await;
                        Ok(())
                    }
                }
            }
        }
    }

    /// Core inspection routine. Runs the chain twice: once on the
    /// host string (catches `DestinationPolicy` denials before any
    /// network work), then again after DNS-pinning the resolved IP
    /// into `ctx.resolved_ip` (catches `SsrfGuard` denials post-
    /// resolution). Returns the decision plus a structured audit
    /// payload the caller hands to `AuditSigner`.
    ///
    /// Body-cap enforcement is the caller's responsibility *for the
    /// HTTPS CONNECT path* (no body read there); for the plain-HTTP
    /// path, the caller checks `body.len() > body_cap_bytes` before
    /// invoking this and returns `body_too_large` outside the chain.
    /// This separation keeps `evaluate` focused on the chain and
    /// keeps the cap visible at the read site.
    pub async fn evaluate(
        &self,
        host: &str,
        port: u16,
        body: Vec<u8>,
    ) -> Result<EvaluationResult, EgressError> {
        let started = Instant::now();
        let mut ctx = RequestCtx::new(host, port, "").with_body(body);
        let mut transforms: Vec<String> = Vec::new();

        // First pass: chain runs against the host string. If the
        // host is an IP literal, SsrfGuard's IP-parse branch fires
        // here and we may not even need DNS. If the host is a
        // hostname, body inspectors run against ctx.body and
        // DestinationPolicy filters by string.
        let (verdict_1, name_1) = self.chain.run(&mut ctx).await;
        if let InspectorVerdict::Transform { note } = &verdict_1 {
            transforms.push(note.clone());
        }
        if verdict_1.is_deny() {
            return Ok(self.deny(verdict_1, name_1, &ctx, transforms, started, None));
        }

        // If the host parsed as an IP literal in pass 1, SsrfGuard
        // already classified it; skip DNS resolution entirely.
        let needs_dns = host.parse::<IpAddr>().is_err();
        if !needs_dns {
            return Ok(self.allow_or_transform(name_1, &ctx, transforms, started, None));
        }

        // Second pass: resolve, pin, re-run. SsrfGuard now sees the
        // pinned IP and either denies or passes; DestinationPolicy
        // and body inspectors will produce identical verdicts to
        // pass 1 (idempotent), but re-running keeps the deny-source
        // attribution consistent — whichever inspector denied is
        // recorded, regardless of whether it needed the IP.
        let resolved = self.resolver.resolve_one(host, port).await?;
        ctx.resolved_ip = Some(resolved);

        let (verdict_2, name_2) = self.chain.run(&mut ctx).await;
        if let InspectorVerdict::Transform { note } = &verdict_2 {
            // Avoid duplicating the same Transform note from both
            // passes — they're behaviourally identical for body
            // inspectors.
            if !transforms.contains(note) {
                transforms.push(note.clone());
            }
        }
        if verdict_2.is_deny() {
            return Ok(self.deny(verdict_2, name_2, &ctx, transforms, started, Some(resolved)));
        }
        Ok(self.allow_or_transform(name_2, &ctx, transforms, started, Some(resolved)))
    }

    /// Build a Deny `EvaluationResult` from a chain verdict.
    fn deny(
        &self,
        verdict: InspectorVerdict,
        deciding: &'static str,
        ctx: &RequestCtx,
        transforms: Vec<String>,
        started: Instant,
        resolved_ip: Option<IpAddr>,
    ) -> EvaluationResult {
        let reason = match verdict {
            InspectorVerdict::Deny { reason } => reason,
            // Shouldn't happen — we only call deny() when is_deny()
            // is true — but keep the match exhaustive.
            other => format!("internal: unexpected verdict {other:?}"),
        };
        EvaluationResult {
            decision: EgressDecision::Deny {
                reason: reason.clone(),
            },
            audit: AuditFields {
                outcome: EgressOutcome::Deny,
                deciding_inspector: deciding,
                host: ctx.host.clone(),
                port: ctx.port,
                path: ctx.path.clone(),
                transforms,
                reason: Some(reason),
                resolved_ip,
                duration_ms: elapsed_ms(started),
                timestamp: Utc::now(),
            },
        }
    }

    /// Build an Allow / Transform `EvaluationResult` from chain
    /// completion. `outcome` is `Transform` iff at least one
    /// inspector returned `Transform { .. }` during the run.
    fn allow_or_transform(
        &self,
        deciding: &'static str,
        ctx: &RequestCtx,
        transforms: Vec<String>,
        started: Instant,
        resolved_ip: Option<IpAddr>,
    ) -> EvaluationResult {
        let outcome = if transforms.is_empty() {
            EgressOutcome::Allow
        } else {
            EgressOutcome::Transform
        };
        EvaluationResult {
            decision: EgressDecision::Allow,
            audit: AuditFields {
                outcome,
                deciding_inspector: deciding,
                host: ctx.host.clone(),
                port: ctx.port,
                path: ctx.path.clone(),
                transforms,
                reason: None,
                resolved_ip,
                duration_ms: elapsed_ms(started),
                timestamp: Utc::now(),
            },
        }
    }
}

fn elapsed_ms(started: Instant) -> u32 {
    let ms = started.elapsed().as_millis();
    // Cap at u32::MAX in the unlikely event a single request takes
    // longer than ~49 days (it won't, but the cast must be safe).
    u32::try_from(ms).unwrap_or(u32::MAX)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Write `HTTP/1.1 200 Connection Established\r\n\r\n` — the
/// canonical response to an accepted CONNECT.
async fn write_200_established(client: &mut TcpStream) -> std::io::Result<()> {
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    client.flush().await
}

/// Write a `403 Forbidden` with the chain's deny reason in the
/// `X-Mvm-Egress-Reason` header. The body is plain text so curl /
/// reqwest / etc. surface the reason to the workload.
///
/// The reason is whatever the inspector returned; it never echoes
/// matched body bytes (the inspectors already enforce that), but we
/// sanitise newlines defensively to avoid header injection.
async fn write_403(client: &mut TcpStream, reason: &str) -> std::io::Result<()> {
    let safe = reason.replace(['\r', '\n'], " ");
    let body = format!("egress denied: {safe}\n");
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         X-Mvm-Egress-Reason: {safe}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    );
    client.write_all(response.as_bytes()).await?;
    client.flush().await
}

/// Write a generic status response (used for `400 Bad Request`,
/// `500 Internal`, `502 Bad Gateway`). Not as load-bearing as the
/// 200/403 responses — used only for protocol/infrastructure
/// failures that aren't chain verdicts.
async fn write_status(client: &mut TcpStream, status: u16, msg: &str) -> std::io::Result<()> {
    let safe = msg.replace(['\r', '\n'], " ");
    let body = format!("{safe}\n");
    let reason_phrase = match status {
        400 => "Bad Request",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason_phrase}\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    );
    client.write_all(response.as_bytes()).await?;
    client.flush().await
}

#[async_trait]
impl EgressProxy for L7EgressProxy {
    async fn inspect(&self, host: &str, path: &str) -> Result<EgressDecision, EgressError> {
        // The original `EgressProxy` trait predates the (host, port,
        // body) shape. Until the trait widening, this method
        // delegates to `evaluate` with port=443 (the HTTPS default
        // — the host-only signature is never going to be the
        // primary callsite anyway) and an empty body. Real proxy
        // traffic uses `evaluate` directly via the `serve` loop.
        let result = self.evaluate(host, 443, Vec::new()).await?;
        // The path arg from the legacy trait is informational; we
        // record it on the side but it doesn't affect the chain
        // since no inspector reads it.
        let _ = path;
        Ok(result.decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::destination::DestinationPolicy;
    use crate::supervisor::inspector::InspectorChain;
    use crate::supervisor::secrets_scanner::SecretsScanner;
    use crate::supervisor::ssrf_guard::SsrfGuard;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    /// Mock resolver that returns a configured IP for any host.
    /// Tests instantiate one per scenario.
    struct MockResolver {
        next: Mutex<Option<Result<IpAddr, String>>>,
    }
    impl MockResolver {
        fn returns(ip: IpAddr) -> Arc<Self> {
            Arc::new(Self {
                next: Mutex::new(Some(Ok(ip))),
            })
        }
        fn errors_with(msg: &str) -> Arc<Self> {
            Arc::new(Self {
                next: Mutex::new(Some(Err(msg.to_string()))),
            })
        }
    }
    #[async_trait]
    impl DnsResolver for MockResolver {
        async fn resolve_one(&self, _host: &str, _port: u16) -> Result<IpAddr, EgressError> {
            let mut slot = self.next.lock().expect("MockResolver mutex poisoned");
            match slot.take() {
                Some(Ok(ip)) => Ok(ip),
                Some(Err(msg)) => Err(EgressError::UpstreamUnreachable(msg)),
                None => Err(EgressError::UpstreamUnreachable("mock exhausted".into())),
            }
        }
    }

    fn full_chain() -> Arc<InspectorChain> {
        Arc::new(
            InspectorChain::new()
                .with(Box::new(DestinationPolicy::new([(
                    "api.openai.com",
                    443u16,
                )])))
                .with(Box::new(SsrfGuard::new()))
                .with(Box::new(SecretsScanner::with_default_rules())),
        )
    }

    fn proxy_with(chain: Arc<InspectorChain>, resolver: Arc<dyn DnsResolver>) -> L7EgressProxy {
        L7EgressProxy::new(
            chain,
            resolver,
            Arc::new(NoopEgressAuditSink),
            16 * 1024 * 1024,
            false,
        )
    }

    fn proxy_with_audit(
        chain: Arc<InspectorChain>,
        resolver: Arc<dyn DnsResolver>,
        audit: Arc<dyn EgressAuditSink>,
    ) -> L7EgressProxy {
        L7EgressProxy::new(chain, resolver, audit, 16 * 1024 * 1024, false)
    }

    #[tokio::test]
    async fn allowed_destination_with_clean_body_allows() {
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 10)));
        let proxy = proxy_with(full_chain(), resolver);
        let r = proxy
            .evaluate("api.openai.com", 443, b"{\"hello\":\"world\"}".to_vec())
            .await
            .expect("evaluate ok");
        assert!(matches!(r.decision, EgressDecision::Allow));
        assert_eq!(r.audit.outcome, EgressOutcome::Allow);
        assert_eq!(r.audit.host, "api.openai.com");
        assert_eq!(r.audit.port, 443);
        assert_eq!(
            r.audit.resolved_ip,
            Some(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 10)))
        );
        assert!(r.audit.transforms.is_empty());
        assert!(r.audit.reason.is_none());
    }

    #[tokio::test]
    async fn unauthorised_destination_denies_before_dns() {
        let resolver = MockResolver::errors_with("should not be called");
        let proxy = proxy_with(full_chain(), resolver);
        let r = proxy
            .evaluate("evil.com", 443, Vec::new())
            .await
            .expect("evaluate ok");
        assert!(matches!(r.decision, EgressDecision::Deny { .. }));
        assert_eq!(r.audit.outcome, EgressOutcome::Deny);
        assert_eq!(r.audit.deciding_inspector, "destination_policy");
        // Resolver was never called → resolved_ip stays None.
        assert!(r.audit.resolved_ip.is_none());
    }

    #[tokio::test]
    async fn dns_rebinding_resolved_to_private_ip_denies() {
        // The host is allowlisted, so DestinationPolicy passes.
        // SsrfGuard's first pass sees only the hostname and is a
        // no-op. The mock resolver returns 127.0.0.1 — the second
        // pass must catch it.
        let chain = Arc::new(
            InspectorChain::new()
                .with(Box::new(DestinationPolicy::new([("evil.com", 443u16)])))
                .with(Box::new(SsrfGuard::new())),
        );
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let proxy = proxy_with(chain, resolver);
        let r = proxy
            .evaluate("evil.com", 443, Vec::new())
            .await
            .expect("evaluate ok");
        assert!(matches!(r.decision, EgressDecision::Deny { .. }));
        assert_eq!(r.audit.outcome, EgressOutcome::Deny);
        assert_eq!(r.audit.deciding_inspector, "ssrf_guard");
        assert_eq!(
            r.audit.resolved_ip,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }

    #[tokio::test]
    async fn ip_literal_host_skips_dns_resolution() {
        let chain = Arc::new(
            InspectorChain::new()
                .with(Box::new(DestinationPolicy::new([("8.8.8.8", 443u16)])))
                .with(Box::new(SsrfGuard::new())),
        );
        // Resolver MUST NOT be called when host is an IP literal.
        let resolver = MockResolver::errors_with("DNS should not be called for IP literal hosts");
        let proxy = proxy_with(chain, resolver);
        let r = proxy
            .evaluate("8.8.8.8", 443, Vec::new())
            .await
            .expect("evaluate ok");
        assert!(matches!(r.decision, EgressDecision::Allow));
        // resolved_ip stays None when DNS wasn't needed.
        assert!(r.audit.resolved_ip.is_none());
    }

    #[tokio::test]
    async fn body_with_secret_denies_with_secrets_scanner_attribution() {
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 10)));
        let proxy = proxy_with(full_chain(), resolver);
        let body = b"X-Api-Key: AKIAIOSFODNN7EXAMPLE".to_vec();
        let r = proxy
            .evaluate("api.openai.com", 443, body)
            .await
            .expect("evaluate ok");
        assert!(matches!(r.decision, EgressDecision::Deny { .. }));
        assert_eq!(r.audit.deciding_inspector, "secrets_scanner");
        // Audit must NOT echo the matched secret bytes.
        let reason = r.audit.reason.as_deref().unwrap_or("");
        assert!(!reason.contains("AKIAIOSFODNN7EXAMPLE"));
        // Rule name is fine.
        assert!(reason.contains("aws_access_key_id"));
    }

    #[tokio::test]
    async fn dns_failure_propagates_as_egress_error() {
        let resolver = MockResolver::errors_with("nxdomain");
        let proxy = proxy_with(full_chain(), resolver);
        let r = proxy.evaluate("api.openai.com", 443, Vec::new()).await;
        match r {
            Err(EgressError::UpstreamUnreachable(msg)) => assert!(msg.contains("nxdomain")),
            other => panic!("expected UpstreamUnreachable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_chain_allows_with_resolution() {
        let chain = Arc::new(InspectorChain::new());
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let proxy = proxy_with(chain, resolver);
        let r = proxy
            .evaluate("example.com", 80, Vec::new())
            .await
            .expect("evaluate ok");
        assert!(matches!(r.decision, EgressDecision::Allow));
        assert_eq!(r.audit.outcome, EgressOutcome::Allow);
        // <empty_chain> sentinel from InspectorChain::run.
        assert_eq!(r.audit.deciding_inspector, "<empty_chain>");
    }

    #[tokio::test]
    async fn legacy_inspect_trait_method_still_works() {
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 10)));
        let proxy = proxy_with(full_chain(), resolver);
        // The legacy 2-arg `inspect(host, path)` should delegate
        // through `evaluate` cleanly. Used by older callers until
        // the trait is widened.
        let r: &dyn EgressProxy = &proxy;
        let dec = r
            .inspect("api.openai.com", "/v1/chat")
            .await
            .expect("inspect ok");
        assert!(matches!(dec, EgressDecision::Allow));
    }

    #[test]
    fn proxy_exposes_configuration() {
        let chain = Arc::new(InspectorChain::new());
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let proxy = L7EgressProxy::new(
            chain,
            resolver,
            Arc::new(NoopEgressAuditSink),
            8 * 1024 * 1024,
            true,
        );
        assert_eq!(proxy.body_cap_bytes(), 8 * 1024 * 1024);
        assert!(proxy.allow_plain_http());
    }

    // ---- CONNECT parser ----

    #[test]
    fn parse_connect_basic() {
        let req = parse_connect(b"CONNECT api.openai.com:443 HTTP/1.1\r\n").unwrap();
        assert_eq!(req.host, "api.openai.com");
        assert_eq!(req.port, 443);
    }

    #[test]
    fn parse_connect_without_crlf() {
        let req = parse_connect(b"CONNECT example.com:8080 HTTP/1.1").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 8080);
    }

    #[test]
    fn parse_connect_lf_only() {
        let req = parse_connect(b"CONNECT example.com:443 HTTP/1.0\n").unwrap();
        assert_eq!(req.port, 443);
    }

    #[test]
    fn parse_connect_rejects_get() {
        let err = parse_connect(b"GET /foo HTTP/1.1\r\n").unwrap_err();
        assert!(matches!(err, ConnectParseError::NotConnect(_)));
    }

    #[test]
    fn parse_connect_rejects_missing_port() {
        let err = parse_connect(b"CONNECT example.com HTTP/1.1\r\n").unwrap_err();
        assert!(matches!(err, ConnectParseError::AuthorityMissingPort(_)));
    }

    #[test]
    fn parse_connect_rejects_bad_port() {
        let err = parse_connect(b"CONNECT example.com:abc HTTP/1.1\r\n").unwrap_err();
        assert!(matches!(err, ConnectParseError::BadPort(_)));
    }

    #[test]
    fn parse_connect_rejects_http_2() {
        let err = parse_connect(b"CONNECT example.com:443 HTTP/2.0\r\n").unwrap_err();
        assert_eq!(err, ConnectParseError::Malformed);
    }

    #[test]
    fn parse_connect_rejects_non_utf8() {
        let bytes = [0xFF, 0xFE, b'C', b'O', b'N'];
        assert_eq!(parse_connect(&bytes), Err(ConnectParseError::NonUtf8));
    }

    #[test]
    fn parse_connect_rejects_empty_host() {
        let err = parse_connect(b"CONNECT :443 HTTP/1.1\r\n").unwrap_err();
        assert!(matches!(err, ConnectParseError::AuthorityMissingPort(_)));
    }

    #[test]
    fn parse_connect_rejects_too_few_fields() {
        let err = parse_connect(b"CONNECT only-two-fields\r\n").unwrap_err();
        assert_eq!(err, ConnectParseError::Malformed);
    }

    #[test]
    fn parse_connect_handles_ipv6_literal_via_brackets_unsupported_for_now() {
        // IPv6 in CONNECT uses bracketed form: `[::1]:443`. Phase 1
        // accepts it via rsplit_once(':') which keeps the brackets
        // in the host slot — downstream IP parsing in `evaluate`
        // would then fail since `[::1]` isn't a valid IpAddr. Document
        // the limitation explicitly via this test until proper
        // bracket-stripping is added.
        let req = parse_connect(b"CONNECT [::1]:443 HTTP/1.1\r\n").unwrap();
        assert_eq!(req.host, "[::1]");
        assert_eq!(req.port, 443);
    }

    // ---- Audit sink ----

    #[tokio::test]
    async fn audit_sink_captures_allow_record() {
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(104, 18, 32, 10)));
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let proxy = proxy_with_audit(full_chain(), resolver, audit.clone());
        let r = proxy
            .evaluate("api.openai.com", 443, b"hi".to_vec())
            .await
            .expect("evaluate ok");
        // record() is called from serve_connection, not evaluate.
        // Verify the AuditFields shape directly here.
        audit.record(&r.audit).await.expect("record ok");
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, EgressOutcome::Allow);
        assert_eq!(entries[0].host, "api.openai.com");
    }

    // ---- In-process integration: real TcpStream through serve_connection ----
    //
    // These tests bind a proxy listener on an ephemeral 127.0.0.1
    // port and a "fake upstream" listener on another ephemeral port,
    // then drive CONNECT requests through the proxy. They assert
    // both the wire-protocol response shape AND the audit-sink
    // contents — the two observation surfaces real workloads have.
    // (`tokio::io::{AsyncReadExt, AsyncWriteExt}` come in via the
    // parent module's `use` — no need to re-import here.)

    /// Bind the proxy on an ephemeral port, return its address +
    /// the JoinHandle so the test can clean up.
    async fn spawn_proxy(
        proxy: Arc<L7EgressProxy>,
    ) -> (SocketAddr, tokio::task::JoinHandle<std::io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await?;
                let p = Arc::clone(&proxy);
                tokio::spawn(async move {
                    let _ = p.serve_connection(stream, peer).await;
                });
            }
        });
        (addr, handle)
    }

    /// Bind a fake upstream that accepts one connection, sends a
    /// fixed greeting, then closes. Returns the upstream's port.
    async fn spawn_fake_upstream(greeting: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(greeting).await;
                let _ = stream.flush().await;
                // Linger briefly so the test reads before close.
                let _ = stream.shutdown().await;
            }
        });
        port
    }

    /// Read from `stream` until either `\r\n\r\n` or EOF.
    async fn read_response_head(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        buf
    }

    #[tokio::test]
    async fn connect_to_disallowed_destination_returns_403_and_audits() {
        let resolver = MockResolver::errors_with("should not be called");
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let proxy = Arc::new(proxy_with_audit(full_chain(), resolver, audit.clone()));
        let (proxy_addr, _h) = spawn_proxy(proxy).await;

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let head = read_response_head(&mut client).await;
        let head = String::from_utf8(head).expect("utf8");
        assert!(head.starts_with("HTTP/1.1 403 "), "got: {head}");
        assert!(head.contains("X-Mvm-Egress-Reason:"), "got: {head}");
        assert!(head.contains("destination_policy") || head.contains("not in policy"));

        // Brief pause so the audit task records before we read.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, EgressOutcome::Deny);
        assert_eq!(entries[0].deciding_inspector, "destination_policy");
        assert_eq!(entries[0].host, "evil.com");
    }

    #[tokio::test]
    async fn connect_to_allowed_destination_splices_bytes() {
        // Spawn a fake upstream that replies "HELLO\n" on connect.
        let upstream_port = spawn_fake_upstream(b"HELLO\n").await;

        // Allow the upstream's host:port.
        let chain = Arc::new(
            InspectorChain::new().with(Box::new(DestinationPolicy::new([(
                "127.0.0.1",
                upstream_port,
            )]))),
        );

        // Resolver isn't used (host is an IP literal), but plumb a
        // mock anyway so any accidental resolution call errors loud.
        let resolver = MockResolver::errors_with("should not be called for IP literal");
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let proxy = Arc::new(proxy_with_audit(chain, resolver, audit.clone()));
        let (proxy_addr, _h) = spawn_proxy(proxy).await;

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        let connect_line = format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n");
        client
            .write_all(connect_line.as_bytes())
            .await
            .expect("write");

        // Read the proxy's 200 response, then the upstream's bytes.
        let head = read_response_head(&mut client).await;
        let head = String::from_utf8(head).expect("utf8");
        assert!(head.starts_with("HTTP/1.1 200 "), "got: {head}");

        // Now read what the upstream sent (spliced through).
        let mut payload = [0u8; 16];
        let n = client.read(&mut payload).await.expect("read");
        assert!(n >= 6);
        assert_eq!(&payload[..6], b"HELLO\n");

        // Audit recorded an Allow.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, EgressOutcome::Allow);
    }

    #[tokio::test]
    async fn malformed_request_line_returns_400() {
        let resolver = MockResolver::errors_with("should not be called");
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let proxy = Arc::new(proxy_with_audit(full_chain(), resolver, audit.clone()));
        let (proxy_addr, _h) = spawn_proxy(proxy).await;

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"GET /not-a-connect HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let head = read_response_head(&mut client).await;
        let head = String::from_utf8(head).expect("utf8");
        assert!(head.starts_with("HTTP/1.1 400 "), "got: {head}");
    }

    #[tokio::test]
    async fn dns_rebinding_via_real_connect_denies_with_403() {
        // Host parses public (DestinationPolicy passes), resolver
        // returns 127.0.0.1 (SsrfGuard fires post-resolution).
        let chain = Arc::new(
            InspectorChain::new()
                .with(Box::new(DestinationPolicy::new([("evil.com", 443u16)])))
                .with(Box::new(crate::supervisor::ssrf_guard::SsrfGuard::new())),
        );
        let resolver = MockResolver::returns(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let proxy = Arc::new(proxy_with_audit(chain, resolver, audit.clone()));
        let (proxy_addr, _h) = spawn_proxy(proxy).await;

        let mut client = TcpStream::connect(proxy_addr).await.expect("connect");
        client
            .write_all(b"CONNECT evil.com:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("write");
        let head = read_response_head(&mut client).await;
        let head = String::from_utf8(head).expect("utf8");
        assert!(head.starts_with("HTTP/1.1 403 "), "got: {head}");
        assert!(head.contains("ssrf_guard") || head.contains("loopback"));

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, EgressOutcome::Deny);
        assert_eq!(entries[0].deciding_inspector, "ssrf_guard");
        assert_eq!(
            entries[0].resolved_ip,
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
    }
}
