//! A minimal HTTP/1.1 client over rustls.
//!
//! This exists to keep the hyper/tower stack out of the shipped `mvmctl`
//! closure. It is deliberately smaller than a general-purpose client: no
//! HTTP/2, no redirect following, no connection pool, no proxy support, no
//! compression. Every caller in this workspace already disabled redirects and
//! set its own timeouts, so those are absences rather than regressions.
//!
//! What it does *not* hand-roll matters as much as what it implements. Header
//! types come from `http`, which rejects at construction the control characters
//! behind response splitting; the response head is parsed by `httparse`, the
//! same parser hyper uses; and URLs by `url`, because a bespoke URL parser that
//! disagreed with the SSRF guard about what the host is would *be* the SSRF
//! bug. What this crate owns is the framing decision — how long a body is —
//! which it resolves once, from the head, and fails closed on every ambiguity
//! that makes request smuggling possible.

pub mod blocking;
mod client;
mod conn;
mod error;
pub mod parse;
pub mod proxy;
pub mod resolve;
mod response;

pub use client::{Client, ClientBuilder, RequestBuilder, TlsVersion};
pub use error::{Error, Result};
pub use proxy::{NoProxy, Proxy, ProxyConfig, ProxyError, ProxyKind};
pub use resolve::{PinnedResolver, Resolve, SystemResolver};
pub use response::Response;

pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
pub use url::Url;
