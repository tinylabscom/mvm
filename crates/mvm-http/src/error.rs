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
    #[error("response body exceeded the {limit} byte limit")]
    BodyTooLarge { limit: u64 },
    #[error("invalid header: {0}")]
    Header(String),
    #[error("response body was not valid utf-8")]
    NotUtf8,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Error {
    /// True when the failure is the SSRF guard or a DNS refusal rather than a
    /// transport fault. Callers surface these differently — an operator needs
    /// to know a policy refused the fetch, not that "the network failed".
    pub fn is_address_refusal(&self) -> bool {
        matches!(self, Error::NoPermittedAddress(_) | Error::Dns { .. })
    }
}

pub type Result<T> = std::result::Result<T, Error>;
