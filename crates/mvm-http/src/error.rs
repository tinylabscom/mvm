//! Error type.

use crate::parse::ParseError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid url: {0}")]
    Url(String),
    /// The URL named a scheme this client does not speak. Kept distinct from
    /// `Url` so a caller can tell "not a URL" from "not http(s)".
    #[error("unsupported scheme: {0}")]
    Scheme(String),
    #[error("dns resolution failed for {host}: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
    /// Every address the resolver returned was rejected. This is the SSRF
    /// guard's refusal and is deliberately not folded into `Dns`.
    #[error("no permitted address for {0}")]
    NoPermittedAddress(String),
    #[error("connect to {addr} failed: {source}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("tls handshake with {host} failed: {source}")]
    Tls {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("timed out after {0:?}")]
    Timeout(std::time::Duration),
    /// The server closed the connection before the declared body arrived.
    #[error("connection closed with {remaining} body bytes outstanding")]
    IncompleteBody { remaining: u64 },
    /// A streaming request producer ended before its declared body length.
    #[error("request body stream ended with {remaining} bytes outstanding")]
    IncompleteRequestBody { remaining: u64 },
    /// A streaming request producer exceeded the length committed in the head.
    #[error("request body stream exceeded its declared {declared} bytes")]
    RequestBodyTooLarge { declared: u64 },
    /// A transform or other request-body producer failed after streaming had
    /// started. The connection is closed without a chunked terminator.
    #[error("request body producer failed: {0}")]
    RequestBodyProducer(String),
    #[error("response body exceeded the {limit} byte limit")]
    BodyTooLarge { limit: u64 },
    #[error("invalid header: {0}")]
    Header(String),
    /// The upstream proxy refused or mishandled the tunnel. Distinct from
    /// `Connect` (which is about reaching the proxy at all) so an operator can
    /// tell "cannot reach the proxy" from "the proxy said no".
    #[error("proxy {proxy} refused the tunnel to {target}: {reason}")]
    Proxy {
        proxy: String,
        target: String,
        reason: String,
    },
    /// The proxy configuration itself is unusable.
    #[error(transparent)]
    ProxyConfig(#[from] crate::proxy::ProxyError),
    #[error("response body was not valid utf-8")]
    NotUtf8,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// A non-2xx status, raised only by an explicit `error_for_status()`.
    /// Reaching a status is not itself a failure, so nothing raises this
    /// implicitly.
    #[error("HTTP {status} for {url}")]
    Status {
        status: http::StatusCode,
        url: String,
    },
    /// A blocking call was made from inside an async runtime, where blocking
    /// the thread would deadlock the executor.
    #[error("blocking HTTP call made from within an async runtime")]
    BlockingInAsyncContext,
}

impl Error {
    /// True when the failure is the SSRF guard or a DNS refusal rather than a
    /// transport fault. Callers surface these differently — an operator needs
    /// to know a policy refused the fetch, not that "the network failed".
    pub fn is_address_refusal(&self) -> bool {
        matches!(self, Error::NoPermittedAddress(_) | Error::Dns { .. })
    }

    /// The status, when this is a status error.
    pub fn status(&self) -> Option<http::StatusCode> {
        match self {
            Error::Status { status, .. } => Some(*status),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
