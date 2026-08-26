//! The client, its builder, and the request path.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use bytes::BytesMut;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use url::Url;

use crate::conn::Stream;
use crate::error::{Error, Result};
use crate::parse::parse_head;
use crate::resolve::{Resolve, SystemResolver};
use crate::response::Response;

/// Minimum TLS version to negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// What the TLS config will be built from, kept until first use.
#[derive(Debug)]
struct TlsSpec {
    min_tls: TlsVersion,
    roots: Option<rustls::RootCertStore>,
}

#[derive(Debug)]
struct Inner {
    /// Built on first send. Constructing it touches the platform trust store,
    /// which can fail for reasons that have nothing to do with the caller's
    /// configuration — so failing here rather than at `new()` keeps the common
    /// constructor infallible while still surfacing the error, instead of
    /// panicking the way reqwest's `Client::new` does.
    tls: std::sync::OnceLock<std::result::Result<Arc<rustls::ClientConfig>, String>>,
    tls_spec: TlsSpec,
    resolver: Arc<dyn Resolve>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    default_headers: HeaderMap,
    max_response_bytes: Option<u64>,
    user_agent: HeaderValue,
    proxy: Option<crate::proxy::ProxyConfig>,
}

/// An HTTP/1.1 client.
///
/// Redirects are never followed — there is no policy knob because every caller
/// in this workspace already set `Policy::none()`, and a redirect is the
/// cheapest way to walk a validated request to an unvalidated host.
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// A client with default settings.
    ///
    /// Infallible: the default user agent is a valid header value by
    /// construction, and the TLS config is built on first use.
    pub fn new() -> Self {
        ClientBuilder::default()
            .build()
            .expect("the default ClientBuilder cannot fail to validate")
    }

    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::GET, url)
    }
    pub fn post(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::POST, url)
    }
    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PUT, url)
    }
    pub fn delete(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }
    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        let url = url.as_ref();
        RequestBuilder {
            client: self.clone(),
            method,
            url: Url::parse(url).map_err(|e| Error::Url(format!("{url}: {e}"))),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            max_response_bytes: None,
            error: None,
        }
    }
}

#[derive(Debug)]
pub struct ClientBuilder {
    min_tls: TlsVersion,
    resolver: Option<Arc<dyn Resolve>>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    default_headers: HeaderMap,
    max_response_bytes: Option<u64>,
    user_agent: String,
    roots: Option<rustls::RootCertStore>,
    proxy: Option<crate::proxy::ProxyConfig>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            // TLS 1.2 matches reqwest's default floor. Migrating callers must
            // not silently change TLS policy; the hardened tool paths pin 1.3
            // explicitly via `min_tls_version` and keep doing so.
            min_tls: TlsVersion::Tls12,
            resolver: None,
            timeout: None,
            connect_timeout: None,
            default_headers: HeaderMap::new(),
            max_response_bytes: None,
            user_agent: concat!("mvm/", env!("CARGO_PKG_VERSION")).to_string(),
            roots: None,
            proxy: None,
        }
    }
}

impl ClientBuilder {
    #[must_use]
    pub fn min_tls_version(mut self, v: TlsVersion) -> Self {
        self.min_tls = v;
        self
    }

    /// Install the resolver the client dials through. The client connects
    /// **only** to addresses this returns, which is what makes it the SSRF
    /// chokepoint rather than an advisory check.
    #[must_use]
    pub fn resolver(mut self, r: Arc<dyn Resolve>) -> Self {
        self.resolver = Some(r);
        self
    }

    #[must_use]
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = Some(d);
        self
    }

    #[must_use]
    pub fn default_headers(mut self, h: HeaderMap) -> Self {
        self.default_headers = h;
        self
    }

    /// Cap every response body this client reads.
    #[must_use]
    pub fn max_response_bytes(mut self, n: u64) -> Self {
        self.max_response_bytes = Some(n);
        self
    }

    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Override the trust anchors. Without this the platform trust store is
    /// used, so enterprise CA policy and root revocation keep applying.
    #[must_use]
    pub fn root_store(mut self, roots: rustls::RootCertStore) -> Self {
        self.roots = Some(roots);
        self
    }

    /// Route requests through an upstream proxy.
    ///
    /// The proxy is a transport choice, not a policy one: it does not decide
    /// which destinations are reachable, and a destination this client would
    /// otherwise refuse is still refused. See [`crate::proxy`] for what
    /// proxying does to the resolver's SSRF guarantee.
    #[must_use]
    pub fn proxy(mut self, proxy: crate::proxy::ProxyConfig) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn build(self) -> Result<Client> {
        let user_agent = HeaderValue::from_str(&self.user_agent)
            .map_err(|_| Error::Header(format!("user agent {:?}", self.user_agent)))?;

        Ok(Client {
            inner: Arc::new(Inner {
                tls: std::sync::OnceLock::new(),
                tls_spec: TlsSpec {
                    min_tls: self.min_tls,
                    roots: self.roots,
                },
                resolver: self.resolver.unwrap_or_else(|| Arc::new(SystemResolver)),
                timeout: self.timeout,
                connect_timeout: self.connect_timeout,
                default_headers: self.default_headers,
                max_response_bytes: self.max_response_bytes,
                user_agent,
                proxy: self.proxy.filter(|p| !p.is_empty()),
            }),
        })
    }
}

impl Inner {
    /// The TLS config, built once on first use.
    fn tls(&self) -> Result<Arc<rustls::ClientConfig>> {
        self.tls
            .get_or_init(|| build_tls(&self.tls_spec).map_err(|e| e.to_string()))
            .clone()
            .map_err(|e| Error::Tls {
                host: "<tls config>".into(),
                source: std::io::Error::other(e),
            })
    }
}

fn build_tls(spec: &TlsSpec) -> Result<Arc<rustls::ClientConfig>> {
    use rustls_platform_verifier::BuilderVerifierExt as _;

    let versions: &[&rustls::SupportedProtocolVersion] = match spec.min_tls {
        TlsVersion::Tls13 => &[&rustls::version::TLS13],
        TlsVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| Error::Tls {
            host: "<config>".into(),
            source: std::io::Error::other(e.to_string()),
        })?;

    // The platform trust store by default, so enterprise CA policy and root
    // revocation keep applying — the same posture reqwest gave us. An explicit
    // root store is only for tests and pinned-CA callers.
    let tls = match &spec.roots {
        Some(roots) => builder
            .with_root_certificates(roots.clone())
            .with_no_client_auth(),
        None => builder
            .with_platform_verifier()
            .map_err(|e| Error::Tls {
                host: "<platform trust store>".into(),
                source: std::io::Error::other(e.to_string()),
            })?
            .with_no_client_auth(),
    };
    Ok(Arc::new(tls))
}

/// A request under construction.
#[derive(Debug)]
pub struct RequestBuilder {
    client: Client,
    method: Method,
    url: std::result::Result<Url, Error>,
    headers: HeaderMap,
    body: Option<RequestBody>,
    timeout: Option<Duration>,
    max_response_bytes: Option<u64>,
    /// A builder-stage failure, surfaced at `send` so the chain stays fluent.
    error: Option<Error>,
}

#[derive(Debug)]
enum RequestBody {
    Bytes(Vec<u8>),
    Stream {
        declared_len: Option<u64>,
        receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    },
    CheckedChunked {
        receiver: tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    },
}

impl RequestBody {
    fn framing(&self) -> RequestBodyFraming {
        match self {
            Self::Bytes(bytes) => RequestBodyFraming::Fixed(bytes.len() as u64),
            Self::Stream {
                declared_len: Some(declared_len),
                ..
            } => RequestBodyFraming::Fixed(*declared_len),
            Self::Stream {
                declared_len: None, ..
            }
            | Self::CheckedChunked { .. } => RequestBodyFraming::Chunked,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestBodyFraming {
    Fixed(u64),
    Chunked,
}

impl RequestBuilder {
    #[must_use]
    /// Set a header.
    ///
    /// Generic over both parts so a caller holding already-typed
    /// `HeaderName`/`HeaderValue` (a forwarding proxy, say) passes them
    /// straight through, while string callers still work. Conversion failure —
    /// which is what rejects the control characters behind response splitting —
    /// is recorded and surfaces at `send`.
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        match (name.try_into(), value.try_into()) {
            (Ok(n), Ok(v)) => {
                self.headers.insert(n, v);
            }
            _ => {
                self.error
                    .get_or_insert_with(|| Error::Header("invalid header name or value".into()));
            }
        }
        self
    }

    pub fn headers(mut self, h: HeaderMap) -> Self {
        self.headers.extend(h);
        self
    }

    #[must_use]
    pub fn bearer_auth(self, token: impl AsRef<str>) -> Self {
        self.header("authorization", format!("Bearer {}", token.as_ref()))
    }

    #[must_use]
    pub fn basic_auth(self, user: impl AsRef<str>, pass: Option<impl AsRef<str>>) -> Self {
        let user = user.as_ref();
        let raw = match pass {
            Some(p) => format!("{user}:{}", p.as_ref()),
            None => format!("{user}:"),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        self.header("authorization", format!("Basic {encoded}"))
    }

    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(RequestBody::Bytes(body.into()));
        self
    }

    /// Stream a request body with a length committed before any body bytes.
    ///
    /// The receiver provides backpressure selected by its creator. Sending
    /// fewer or more bytes than `declared_len` fails closed, so the emitted
    /// `Content-Length` can never disagree with what reaches the socket.
    #[must_use]
    pub fn body_stream(
        mut self,
        declared_len: u64,
        receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        self.body = Some(RequestBody::Stream {
            declared_len: Some(declared_len),
            receiver,
        });
        self
    }

    /// Stream a request body with HTTP/1.1 chunked transfer framing.
    ///
    /// Use this when a bounded transform can change the decoded byte count.
    /// The channel capacity remains the caller's backpressure bound; empty
    /// chunks are ignored and the terminating chunk is emitted only after the
    /// producer closes cleanly.
    #[must_use]
    pub fn body_chunked(mut self, receiver: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Self {
        self.body = Some(RequestBody::Stream {
            declared_len: None,
            receiver,
        });
        self
    }

    /// Stream a transformed body whose producer can fail closed.
    ///
    /// A producer error closes the connection without the final chunk, so the
    /// destination cannot accept a partial transformed request as complete.
    #[must_use]
    pub fn body_checked_chunked(
        mut self,
        receiver: tokio::sync::mpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    ) -> Self {
        self.body = Some(RequestBody::CheckedChunked { receiver });
        self
    }

    #[must_use]
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(v) => {
                self.body = Some(RequestBody::Bytes(v));
                self.headers.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
            }
            Err(e) => {
                self.error.get_or_insert(Error::Json(e));
            }
        }
        self
    }

    #[must_use]
    pub fn query(mut self, pairs: &[(&str, &str)]) -> Self {
        if let Ok(url) = self.url.as_mut() {
            let mut qs = url.query_pairs_mut();
            for (k, v) in pairs {
                qs.append_pair(k, v);
            }
        }
        self
    }

    #[must_use]
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    /// Cap this response's body, overriding the client default.
    #[must_use]
    pub fn max_response_bytes(mut self, n: u64) -> Self {
        self.max_response_bytes = Some(n);
        self
    }

    pub async fn send(self) -> Result<Response> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let url = self.url?;
        let inner = self.client.inner.clone();
        let deadline = self.timeout.or(inner.timeout);
        let fut = send_once(
            inner,
            self.method,
            url,
            self.headers,
            self.body,
            self.max_response_bytes,
        );
        match deadline {
            Some(d) => tokio::time::timeout(d, fut)
                .await
                .map_err(|_| Error::Timeout(d))?,
            None => fut.await,
        }
    }
}

async fn send_once(
    inner: Arc<Inner>,
    method: Method,
    url: Url,
    extra_headers: HeaderMap,
    body: Option<RequestBody>,
    max_response_bytes: Option<u64>,
) -> Result<Response> {
    let scheme = url.scheme().to_ascii_lowercase();
    let tls_wanted = match scheme.as_str() {
        "https" => true,
        "http" => false,
        other => return Err(Error::Scheme(other.to_string())),
    };
    let host = url
        .host_str()
        .ok_or_else(|| Error::Url(format!("{url} has no host")))?
        .to_string();
    let port = url
        .port_or_known_default()
        .unwrap_or(if tls_wanted { 443 } else { 80 });

    let via = inner
        .proxy
        .as_ref()
        .and_then(|c| c.select(&host, tls_wanted))
        .cloned();

    // An absolute-URI request line is required only for plaintext HTTP through
    // an HTTP proxy: that is the one case where the proxy reads the request
    // line to learn the destination. A CONNECT tunnel and SOCKS5 both carry the
    // destination out of band, so the request inside them is origin-form.
    let absolute_uri = matches!(
        via.as_ref().map(|p| p.kind),
        Some(crate::proxy::ProxyKind::Http)
    ) && !tls_wanted;

    let mut stream = match &via {
        Some(proxy) => connect_via_proxy(&inner, proxy, &host, port, tls_wanted).await?,
        None => {
            let addrs = inner
                .resolver
                .resolve(host.clone(), port)
                .await
                .map_err(|source| Error::Dns {
                    host: host.clone(),
                    source,
                })?;
            if addrs.is_empty() {
                return Err(Error::NoPermittedAddress(host));
            }
            connect(&inner, &addrs, &host, tls_wanted).await?
        }
    };

    let body_framing = body.as_ref().map(RequestBody::framing);
    let head = serialize_request(
        &inner,
        &method,
        &url,
        &extra_headers,
        body_framing,
        absolute_uri,
    )?;
    stream.write_all(&head).await?;
    write_request_body(&mut stream, body).await?;
    stream.flush().await?;

    read_response(
        stream,
        method == Method::HEAD,
        max_response_bytes.or(inner.max_response_bytes),
        url.to_string(),
    )
    .await
}

async fn write_request_body(stream: &mut Stream, body: Option<RequestBody>) -> Result<()> {
    match body {
        None => Ok(()),
        Some(RequestBody::Bytes(bytes)) => {
            stream.write_all(&bytes).await?;
            Ok(())
        }
        Some(RequestBody::Stream {
            declared_len: Some(declared_len),
            mut receiver,
        }) => {
            let mut written = 0_u64;
            while let Some(chunk) = receiver.recv().await {
                let chunk_len =
                    u64::try_from(chunk.len()).map_err(|_| Error::RequestBodyTooLarge {
                        declared: declared_len,
                    })?;
                written = written
                    .checked_add(chunk_len)
                    .ok_or(Error::RequestBodyTooLarge {
                        declared: declared_len,
                    })?;
                if written > declared_len {
                    return Err(Error::RequestBodyTooLarge {
                        declared: declared_len,
                    });
                }
                stream.write_all(&chunk).await?;
            }
            if written != declared_len {
                return Err(Error::IncompleteRequestBody {
                    remaining: declared_len.saturating_sub(written),
                });
            }
            Ok(())
        }
        Some(RequestBody::Stream {
            declared_len: None,
            mut receiver,
        }) => {
            while let Some(chunk) = receiver.recv().await {
                if chunk.is_empty() {
                    continue;
                }
                stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await?;
                stream.write_all(&chunk).await?;
                stream.write_all(b"\r\n").await?;
            }
            stream.write_all(b"0\r\n\r\n").await?;
            Ok(())
        }
        Some(RequestBody::CheckedChunked { mut receiver }) => {
            while let Some(next) = receiver.recv().await {
                let chunk = next.map_err(Error::RequestBodyProducer)?;
                if chunk.is_empty() {
                    continue;
                }
                stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await?;
                stream.write_all(&chunk).await?;
                stream.write_all(b"\r\n").await?;
            }
            stream.write_all(b"0\r\n\r\n").await?;
            Ok(())
        }
    }
}

/// How long one address may take to connect before the next is tried.
///
/// A default rather than an option, because "no timeout" is not a sensible
/// posture for a connect: a black-holed address does not refuse, it simply
/// never answers, so an untimed connect blocks forever and the fallback loop
/// below never runs. That is not hypothetical — a host with a configured but
/// non-functional IPv6 route hangs here indefinitely with no diagnostic, which
/// is how an image pull came to sit in `SYN-SENT` for half an hour.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Order candidate addresses IPv4-first.
///
/// The timeout above makes a dead address survivable; this makes it cheap.
/// Resolvers commonly return AAAA first, so a host whose IPv6 is broken would
/// otherwise pay the full timeout on every single connect before falling back.
/// Preferring IPv4 costs nothing where IPv6 works — both are tried, and the
/// order only decides which is attempted first.
fn ipv4_first(addrs: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    let (v4, v6): (Vec<_>, Vec<_>) = addrs.iter().partition(|a| a.is_ipv4());
    v4.into_iter().chain(v6).copied().collect()
}

/// The per-address connect budget. An unset timeout resolves to a finite
/// default; it must never resolve to "wait indefinitely", which is what let a
/// dead address consume a whole request.
fn connect_budget(configured: Option<Duration>) -> Duration {
    configured.unwrap_or(DEFAULT_CONNECT_TIMEOUT)
}

async fn connect(
    inner: &Inner,
    addrs: &[std::net::SocketAddr],
    host: &str,
    tls_wanted: bool,
) -> Result<Stream> {
    let mut last: Option<std::io::Error> = None;
    let budget = connect_budget(inner.connect_timeout);
    for addr in &ipv4_first(addrs) {
        let attempt = TcpStream::connect(addr);
        let tcp = match tokio::time::timeout(budget, attempt).await {
            Ok(r) => r,
            Err(_) => {
                last = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connect to {addr} timed out after {budget:?}"),
                ));
                continue;
            }
        };
        match tcp {
            Ok(tcp) => {
                tcp.set_nodelay(true).ok();
                if !tls_wanted {
                    return Ok(Stream::Plain(tcp));
                }
                let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| Error::Url(format!("invalid dns name {host}")))?;
                let connector = tokio_rustls::TlsConnector::from(inner.tls()?);
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|source| Error::Tls {
                        host: host.to_string(),
                        source,
                    })?;
                return Ok(Stream::Tls(Box::new(tls)));
            }
            Err(e) => last = Some(e),
        }
    }
    Err(Error::Connect {
        addr: addrs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        source: last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address")
        }),
    })
}

/// Dial the proxy itself.
///
/// Deliberately **not** through `inner.resolver`. That resolver is the SSRF
/// guard for guest-influenced destinations, and it rejects RFC1918 — which is
/// where a corporate proxy almost always lives. The proxy address comes from
/// operator configuration on this host, never from a guest, so it is resolved
/// the way any other operator-supplied endpoint would be.
async fn dial_proxy(inner: &Inner, proxy: &crate::proxy::Proxy) -> Result<TcpStream> {
    let addrs = crate::resolve::SystemResolver
        .resolve(proxy.host.clone(), proxy.port)
        .await
        .map_err(|source| Error::Dns {
            host: proxy.host.clone(),
            source,
        })?;
    let mut last: Option<std::io::Error> = None;
    for addr in &addrs {
        let attempt = TcpStream::connect(addr);
        let tcp = match inner.connect_timeout {
            Some(d) => match tokio::time::timeout(d, attempt).await {
                Ok(r) => r,
                Err(_) => {
                    last = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "proxy connect timed out",
                    ));
                    continue;
                }
            },
            None => attempt.await,
        };
        match tcp {
            Ok(tcp) => {
                tcp.set_nodelay(true).ok();
                return Ok(tcp);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(Error::Connect {
        addr: proxy.endpoint(),
        source: last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no address")
        }),
    })
}

/// Establish a stream to `host:port` through `proxy`, wrapping it in TLS when
/// the destination is `https`.
async fn connect_via_proxy(
    inner: &Inner,
    proxy: &crate::proxy::Proxy,
    host: &str,
    port: u16,
    tls_wanted: bool,
) -> Result<Stream> {
    let tcp = dial_proxy(inner, proxy).await?;
    let tcp = match proxy.kind {
        crate::proxy::ProxyKind::Http => {
            if tls_wanted {
                http_connect_tunnel(tcp, proxy, host, port).await?
            } else {
                // Plaintext through an HTTP proxy needs no tunnel; the
                // absolute-URI request line carries the destination.
                tcp
            }
        }
        crate::proxy::ProxyKind::Socks5 => socks5_connect(tcp, proxy, host, port).await?,
    };
    if !tls_wanted {
        return Ok(Stream::Plain(tcp));
    }
    // TLS terminates at the destination, not the proxy: the SNI and the
    // certificate checked are the destination's, so an HTTP proxy carrying this
    // tunnel cannot read or alter the body.
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| Error::Url(format!("invalid dns name {host}")))?;
    let connector = tokio_rustls::TlsConnector::from(inner.tls()?);
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|source| Error::Tls {
            host: host.to_string(),
            source,
        })?;
    Ok(Stream::Tls(Box::new(tls)))
}

fn proxy_auth_header(proxy: &crate::proxy::Proxy) -> Option<String> {
    use base64::Engine as _;
    let auth = proxy.auth.as_ref()?;
    let raw = format!("{}:{}", auth.username, auth.password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    Some(format!("Proxy-Authorization: Basic {encoded}\r\n"))
}

/// `CONNECT host:port` against an HTTP proxy, leaving the socket ready for a
/// TLS handshake with the destination.
async fn http_connect_tunnel(
    mut tcp: TcpStream,
    proxy: &crate::proxy::Proxy,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    use tokio::io::AsyncReadExt as _;
    let target = format!("{host}:{port}");
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(h) = proxy_auth_header(proxy) {
        req.push_str(&h);
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes()).await?;
    tcp.flush().await?;

    // Bounded by the same head limit the response parser uses, so a proxy that
    // never terminates its head cannot grow this without limit.
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = tcp.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::Proxy {
                proxy: proxy.endpoint(),
                target,
                reason: "proxy closed the connection before answering CONNECT".into(),
            });
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > crate::parse::MAX_HEAD_BYTES {
            return Err(Error::Proxy {
                proxy: proxy.endpoint(),
                target,
                reason: "CONNECT response head exceeded the size limit".into(),
            });
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| Error::Proxy {
            proxy: proxy.endpoint(),
            target: target.clone(),
            reason: "CONNECT response had no status code".into(),
        })?;
    if !(200..300).contains(&status) {
        return Err(Error::Proxy {
            proxy: proxy.endpoint(),
            target,
            reason: format!("CONNECT returned HTTP {status}"),
        });
    }
    Ok(tcp)
}

/// SOCKS5 CONNECT, sending the destination as a domain name so the proxy
/// resolves it. Resolving locally would defeat the purpose on a host that
/// cannot resolve external names itself.
async fn socks5_connect(
    mut tcp: TcpStream,
    proxy: &crate::proxy::Proxy,
    host: &str,
    port: u16,
) -> Result<TcpStream> {
    use tokio::io::AsyncReadExt as _;
    let target = format!("{host}:{port}");
    let fail = |reason: String| Error::Proxy {
        proxy: proxy.endpoint(),
        target: target.clone(),
        reason,
    };
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(fail("destination host is too long for SOCKS5".into()));
    }

    // Greeting: offer no-auth, plus username/password when credentials exist.
    let mut greet: Vec<u8> = vec![0x05];
    if proxy.auth.is_some() {
        greet.extend_from_slice(&[2, 0x00, 0x02]);
    } else {
        greet.extend_from_slice(&[1, 0x00]);
    }
    tcp.write_all(&greet).await?;
    tcp.flush().await?;
    let mut sel = [0u8; 2];
    tcp.read_exact(&mut sel).await?;
    if sel[0] != 0x05 {
        return Err(fail(format!("unexpected SOCKS version {}", sel[0])));
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            let auth = proxy
                .auth
                .as_ref()
                .ok_or_else(|| fail("proxy demanded credentials none were configured".into()))?;
            let (u, p) = (auth.username.as_bytes(), auth.password.as_bytes());
            if u.len() > 255 || p.len() > 255 {
                return Err(fail("SOCKS5 credentials exceed the field length".into()));
            }
            let mut msg: Vec<u8> = vec![0x01, u.len() as u8];
            msg.extend_from_slice(u);
            msg.push(p.len() as u8);
            msg.extend_from_slice(p);
            tcp.write_all(&msg).await?;
            tcp.flush().await?;
            let mut ok = [0u8; 2];
            tcp.read_exact(&mut ok).await?;
            if ok[1] != 0x00 {
                return Err(fail("proxy rejected the configured credentials".into()));
            }
        }
        0xFF => return Err(fail("proxy offered no acceptable auth method".into())),
        other => return Err(fail(format!("proxy chose unsupported auth method {other}"))),
    }

    // CONNECT by domain name.
    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&req).await?;
    tcp.flush().await?;

    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(fail(format!(
            "SOCKS5 CONNECT failed with reply {}",
            head[1]
        )));
    }
    // Drain the bound address so the socket is positioned at the payload.
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            tcp.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            tcp.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            tcp.read_exact(&mut skip).await?;
        }
        other => {
            return Err(fail(format!(
                "SOCKS5 reply had unknown address type {other}"
            )));
        }
    }
    Ok(tcp)
}

/// Build the request head. `Host` and `Connection: close` are always set here:
/// without a connection pool, asking the server to close is what keeps framing
/// unambiguous.
fn serialize_request(
    inner: &Inner,
    method: &Method,
    url: &Url,
    extra: &HeaderMap,
    body_framing: Option<RequestBodyFraming>,
    absolute_uri: bool,
) -> Result<Vec<u8>> {
    // Absolute-form is how a plaintext request tells an HTTP proxy where it is
    // going; origin-form would make the proxy treat the proxy itself as the
    // destination.
    let mut path = if absolute_uri {
        let mut u = url.clone();
        u.set_fragment(None);
        u.to_string()
    } else {
        url.path().to_string()
    };
    if path.is_empty() {
        path.push('/');
    }
    if !absolute_uri {
        if let Some(q) = url.query() {
            path.push('?');
            path.push_str(q);
        }
    }

    let mut headers = inner.default_headers.clone();
    for (k, v) in extra.iter() {
        headers.insert(k.clone(), v.clone());
    }
    if !headers.contains_key(http::header::USER_AGENT) {
        headers.insert(http::header::USER_AGENT, inner.user_agent.clone());
    }

    let host_header = match url.port() {
        Some(p) => format!("{}:{}", url.host_str().unwrap_or_default(), p),
        None => url.host_str().unwrap_or_default().to_string(),
    };

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"host: ");
    out.extend_from_slice(host_header.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(b"connection: close\r\n");
    out.extend_from_slice(b"accept: */*\r\n");
    match body_framing {
        Some(RequestBodyFraming::Fixed(body_len)) => {
            out.extend_from_slice(format!("content-length: {body_len}\r\n").as_bytes());
        }
        Some(RequestBodyFraming::Chunked) => {
            out.extend_from_slice(b"transfer-encoding: chunked\r\n");
        }
        None => {}
    }
    for (name, value) in headers.iter() {
        // Host/Connection/Content-Length are ours; a caller-supplied duplicate
        // would create exactly the two-values-one-field ambiguity the response
        // parser refuses, so drop them rather than emit both.
        if name == http::header::HOST
            || name == http::header::CONNECTION
            || name == http::header::CONTENT_LENGTH
            || name == http::header::TRANSFER_ENCODING
        {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        // `HeaderValue` already rejected CR/LF at construction, so this cannot
        // inject a header line.
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

async fn read_response(
    mut stream: Stream,
    request_was_head: bool,
    max_response_bytes: Option<u64>,
    url: String,
) -> Result<Response> {
    use tokio::io::AsyncReadExt as _;
    let mut buf = BytesMut::with_capacity(8 * 1024);
    loop {
        if let Some(head) = parse_head(&buf, request_was_head)? {
            let rest = buf.split_off(head.consumed);
            return Ok(Response::new(
                head.status,
                head.headers,
                stream,
                rest,
                head.body_length,
                max_response_bytes,
                url,
            ));
        }
        let start = buf.len();
        buf.resize(start + 8 * 1024, 0);
        let n = stream.read(&mut buf[start..]).await?;
        buf.truncate(start + n);
        if n == 0 {
            return Err(Error::Parse(crate::parse::ParseError::Malformed(
                "connection closed before response head completed".into(),
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inner() -> Inner {
        Inner {
            tls: std::sync::OnceLock::new(),
            tls_spec: TlsSpec {
                min_tls: TlsVersion::Tls12,
                roots: Some(rustls::RootCertStore::empty()),
            },
            resolver: Arc::new(SystemResolver),
            timeout: None,
            connect_timeout: None,
            default_headers: HeaderMap::new(),
            max_response_bytes: None,
            user_agent: HeaderValue::from_static("mvm-test"),
            proxy: None,
        }
    }

    fn serialize(url: &str, extra: HeaderMap, body_len: Option<u64>) -> String {
        let u = Url::parse(url).unwrap();
        let body_framing = body_len.map(RequestBodyFraming::Fixed);
        let out =
            serialize_request(&inner(), &Method::GET, &u, &extra, body_framing, false).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn request_line_carries_path_and_query() {
        let s = serialize("https://example.com/a/b?x=1&y=2", HeaderMap::new(), None);
        assert!(s.starts_with("GET /a/b?x=1&y=2 HTTP/1.1\r\n"), "{s}");
    }

    #[test]
    fn empty_path_becomes_root() {
        let s = serialize("https://example.com", HeaderMap::new(), None);
        assert!(s.starts_with("GET / HTTP/1.1\r\n"), "{s}");
    }

    #[test]
    fn host_header_includes_a_non_default_port_only() {
        assert!(
            serialize("https://example.com/", HeaderMap::new(), None)
                .contains("host: example.com\r\n")
        );
        assert!(
            serialize("https://example.com:8443/", HeaderMap::new(), None)
                .contains("host: example.com:8443\r\n")
        );
    }

    #[test]
    fn body_sets_content_length_exactly_once() {
        let s = serialize("https://example.com/", HeaderMap::new(), Some(5));
        assert_eq!(s.matches("content-length:").count(), 1, "{s}");
        assert!(s.contains("content-length: 5\r\n"), "{s}");
    }

    #[test]
    fn caller_cannot_smuggle_a_second_framing_header() {
        // A caller-supplied Content-Length or Transfer-Encoding would give the
        // request two framing values; ours must be the only one.
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("999"),
        );
        h.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        h.insert(http::header::HOST, HeaderValue::from_static("evil.example"));
        let s = serialize("https://example.com/", h, Some(2));
        assert_eq!(s.matches("content-length:").count(), 1, "{s}");
        assert!(!s.contains("transfer-encoding"), "{s}");
        assert!(!s.contains("evil.example"), "{s}");
        assert!(s.contains("host: example.com\r\n"), "{s}");
    }

    #[test]
    fn header_values_cannot_carry_crlf() {
        // Construction-time validation in `http` is what blocks response
        // splitting; assert the builder surfaces it rather than emitting it.
        let c = Client::builder()
            .root_store(rustls::RootCertStore::empty())
            .build()
            .unwrap();
        let rb = c.get("https://example.com/").header("x-a", "b\r\nevil: 1");
        assert!(rb.error.is_some(), "CRLF in a header value must be refused");
    }

    #[test]
    fn connection_close_is_always_requested() {
        assert!(
            serialize("https://example.com/", HeaderMap::new(), None)
                .contains("connection: close\r\n")
        );
    }

    #[test]
    fn default_user_agent_is_applied_and_overridable() {
        assert!(serialize("https://example.com/", HeaderMap::new(), None).contains("mvm-test"));
        let mut h = HeaderMap::new();
        h.insert(http::header::USER_AGENT, HeaderValue::from_static("custom"));
        let s = serialize("https://example.com/", h, None);
        assert!(s.contains("user-agent: custom"), "{s}");
        assert!(!s.contains("mvm-test"), "{s}");
    }

    #[tokio::test]
    async fn a_non_http_scheme_is_refused_by_name() {
        let c = Client::builder()
            .root_store(rustls::RootCertStore::empty())
            .build()
            .unwrap();
        let err = c.get("file:///etc/passwd").send().await.unwrap_err();
        assert!(matches!(&err, Error::Scheme(s) if s == "file"), "{err:?}");
    }

    #[tokio::test]
    async fn an_empty_resolver_answer_is_an_address_refusal() {
        #[derive(Debug)]
        struct Empty;
        impl Resolve for Empty {
            fn resolve(
                &self,
                _h: String,
                _p: u16,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>>
                        + Send,
                >,
            > {
                Box::pin(async { Ok(Vec::new()) })
            }
        }
        let c = Client::builder()
            .resolver(Arc::new(Empty))
            .root_store(rustls::RootCertStore::empty())
            .build()
            .unwrap();
        let err = c.get("https://blocked.example/").send().await.unwrap_err();
        assert!(err.is_address_refusal(), "{err:?}");
        assert!(matches!(&err, Error::NoPermittedAddress(h) if h == "blocked.example"));
    }
}

#[cfg(test)]
mod connect_resilience_tests {
    use super::*;

    fn v4(p: u16) -> std::net::SocketAddr {
        format!("127.0.0.1:{p}").parse().expect("v4")
    }
    fn v6(p: u16) -> std::net::SocketAddr {
        format!("[::1]:{p}").parse().expect("v6")
    }

    /// IPv4 is attempted first. A resolver that returns AAAA first would
    /// otherwise make a host with broken IPv6 pay the connect timeout on
    /// every request before it ever reaches a working address.
    #[test]
    fn addresses_are_ordered_ipv4_first() {
        let ordered = ipv4_first(&[v6(1), v4(2), v6(3), v4(4)]);
        assert_eq!(ordered, vec![v4(2), v4(4), v6(1), v6(3)]);
    }

    /// Ordering is stable within a family, so a resolver's own preference
    /// between two IPv4 addresses is preserved.
    #[test]
    fn ordering_is_stable_within_a_family() {
        assert_eq!(
            ipv4_first(&[v4(1), v4(2), v4(3)]),
            vec![v4(1), v4(2), v4(3)]
        );
    }

    #[test]
    fn an_empty_or_single_family_list_is_unchanged() {
        assert!(ipv4_first(&[]).is_empty());
        assert_eq!(ipv4_first(&[v6(1), v6(2)]), vec![v6(1), v6(2)]);
    }

    /// **The deterministic half of the regression.** An unset timeout must
    /// resolve to a finite budget. Before the fix it resolved to "no timeout",
    /// so one dead address consumed the request forever and the fallback loop
    /// below it never ran.
    ///
    /// Asserted on the selection itself rather than by dialing a black hole:
    /// whether a reserved address hangs or fails fast is a property of the
    /// host's network, so a dial-based test proves nothing portable.
    #[test]
    fn an_unset_connect_timeout_resolves_to_a_finite_budget() {
        assert_eq!(connect_budget(None), DEFAULT_CONNECT_TIMEOUT);
        assert!(connect_budget(None) <= Duration::from_secs(30));
        assert_eq!(
            connect_budget(Some(Duration::from_millis(250))),
            Duration::from_millis(250),
            "an explicit timeout still wins"
        );
    }

    /// Ordering, exercised through `connect` rather than by calling the
    /// helper. A dead IPv6 address listed first must not delay a working
    /// IPv4 sibling — which is the whole point of preferring v4, and is
    /// invisible to a test that only checks the sort function.
    ///
    /// `100::/64` is the RFC 6666 discard prefix: routed to nowhere by design.
    #[tokio::test]
    async fn a_dead_ipv6_first_does_not_delay_a_working_ipv4() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let good = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let inner = Client::builder().build().expect("builds").inner.clone();
        let dead_v6: std::net::SocketAddr = "[100::1]:443".parse().expect("discard prefix");

        let started = std::time::Instant::now();
        connect(&inner, &[dead_v6, good], "localhost", false)
            .await
            .expect("the reachable IPv4 address is used");

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "IPv4 should be tried first, not after the v6 budget expires; took {:?}",
            started.elapsed()
        );
    }

    /// A caller that sets nothing still gets a bound. `None` used to mean
    /// "wait forever", which is the shape that produced a half-hour hang with
    /// no output.
    #[test]
    fn the_default_connect_budget_is_bounded() {
        let inner = Client::builder()
            .build()
            .expect("client builds")
            .inner
            .clone();
        assert!(
            inner.connect_timeout.is_none(),
            "the builder still records 'unset' rather than inventing a value"
        );
        assert_eq!(
            inner.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            DEFAULT_CONNECT_TIMEOUT,
            "an unset timeout resolves to a finite default, never to no timeout"
        );
    }
}
