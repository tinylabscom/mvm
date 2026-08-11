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
    body: Option<Vec<u8>>,
    timeout: Option<Duration>,
    max_response_bytes: Option<u64>,
    /// A builder-stage failure, surfaced at `send` so the chain stays fluent.
    error: Option<Error>,
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
        self.body = Some(body.into());
        self
    }

    #[must_use]
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(v) => {
                self.body = Some(v);
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
    body: Option<Vec<u8>>,
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

    let stream = connect(&inner, &addrs, &host, tls_wanted).await?;
    let mut stream = stream;

    let head = serialize_request(&inner, &method, &url, &extra_headers, body.as_deref())?;
    stream.write_all(&head).await?;
    if let Some(b) = &body {
        stream.write_all(b).await?;
    }
    stream.flush().await?;

    read_response(
        stream,
        method == Method::HEAD,
        max_response_bytes.or(inner.max_response_bytes),
        url.to_string(),
    )
    .await
}

async fn connect(
    inner: &Inner,
    addrs: &[std::net::SocketAddr],
    host: &str,
    tls_wanted: bool,
) -> Result<Stream> {
    let mut last: Option<std::io::Error> = None;
    for addr in addrs {
        let attempt = TcpStream::connect(addr);
        let tcp = match inner.connect_timeout {
            Some(d) => match tokio::time::timeout(d, attempt).await {
                Ok(r) => r,
                Err(_) => {
                    last = Some(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "connect timed out",
                    ));
                    continue;
                }
            },
            None => attempt.await,
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

/// Build the request head. `Host` and `Connection: close` are always set here:
/// without a connection pool, asking the server to close is what keeps framing
/// unambiguous.
fn serialize_request(
    inner: &Inner,
    method: &Method,
    url: &Url,
    extra: &HeaderMap,
    body: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
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
    if let Some(b) = body {
        out.extend_from_slice(format!("content-length: {}\r\n", b.len()).as_bytes());
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
        }
    }

    fn serialize(url: &str, extra: HeaderMap, body: Option<&[u8]>) -> String {
        let u = Url::parse(url).unwrap();
        let out = serialize_request(&inner(), &Method::GET, &u, &extra, body).unwrap();
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
        let s = serialize("https://example.com/", HeaderMap::new(), Some(b"hello"));
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
        let s = serialize("https://example.com/", h, Some(b"hi"));
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
