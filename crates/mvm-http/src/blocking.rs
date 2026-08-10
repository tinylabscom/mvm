//! Blocking face over the async client.
//!
//! Several callers are plain synchronous code — CLI downloads, the Stage 0
//! asset fetch — and giving them a runtime of their own is simpler than making
//! their callers async. The body is fully buffered here rather than streamed,
//! because every blocking caller in this workspace wants the whole thing
//! (`text`, `json`, `bytes`); a blocking streaming reader would be API surface
//! nobody uses.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http as mvm_header;
use http::{HeaderMap, Method, StatusCode};

use crate::error::{Error, Result};
use crate::resolve::Resolve;
use crate::{ClientBuilder as AsyncBuilder, TlsVersion};

/// A blocking HTTP client.
///
/// Holds no runtime of its own. An earlier shape cached one per client, which
/// made the client un-droppable inside an async context — tokio panics on that,
/// and it would have fired far from the code that caused it. A current-thread
/// runtime costs microseconds to build next to a network round trip, so each
/// `send` makes and discards its own.
#[derive(Debug, Clone)]
pub struct Client {
    inner: crate::Client,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Infallible, for the same reason [`crate::Client::new`] is.
    pub fn new() -> Self {
        Builder::default()
            .build()
            .expect("the default Builder cannot fail to validate")
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
    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }

    pub fn request(&self, method: Method, url: impl AsRef<str>) -> RequestBuilder {
        RequestBuilder {
            inner: self.inner.request(method, url),
        }
    }
}

/// One-shot GET with default settings.
pub fn get(url: impl AsRef<str>) -> Result<Response> {
    Client::new().get(url).send()
}

#[derive(Debug, Default)]
pub struct Builder {
    inner: AsyncBuilder,
}

impl Builder {
    #[must_use]
    pub fn timeout(mut self, d: Duration) -> Self {
        self.inner = self.inner.timeout(d);
        self
    }
    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.inner = self.inner.connect_timeout(d);
        self
    }
    #[must_use]
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.inner = self.inner.user_agent(ua);
        self
    }
    #[must_use]
    pub fn min_tls_version(mut self, v: TlsVersion) -> Self {
        self.inner = self.inner.min_tls_version(v);
        self
    }
    #[must_use]
    pub fn max_response_bytes(mut self, n: u64) -> Self {
        self.inner = self.inner.max_response_bytes(n);
        self
    }
    #[must_use]
    pub fn resolver(mut self, r: Arc<dyn Resolve>) -> Self {
        self.inner = self.inner.resolver(r);
        self
    }
    #[must_use]
    pub fn default_headers(mut self, h: HeaderMap) -> Self {
        self.inner = self.inner.default_headers(h);
        self
    }
    #[must_use]
    pub fn root_store(mut self, roots: rustls::RootCertStore) -> Self {
        self.inner = self.inner.root_store(roots);
        self
    }

    pub fn build(self) -> Result<Client> {
        Ok(Client {
            inner: self.inner.build()?,
        })
    }
}

#[derive(Debug)]
pub struct RequestBuilder {
    inner: crate::RequestBuilder,
}

impl RequestBuilder {
    #[must_use]
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<mvm_header::HeaderName>,
        V: TryInto<mvm_header::HeaderValue>,
    {
        self.inner = self.inner.header(name, value);
        self
    }
    #[must_use]
    pub fn headers(mut self, h: HeaderMap) -> Self {
        self.inner = self.inner.headers(h);
        self
    }
    #[must_use]
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.inner = self.inner.bearer_auth(token);
        self
    }
    #[must_use]
    pub fn basic_auth(mut self, user: impl AsRef<str>, pass: Option<impl AsRef<str>>) -> Self {
        self.inner = self.inner.basic_auth(user, pass);
        self
    }
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.body(body);
        self
    }
    #[must_use]
    pub fn json<T: serde::Serialize>(mut self, v: &T) -> Self {
        self.inner = self.inner.json(v);
        self
    }
    #[must_use]
    pub fn query(mut self, pairs: &[(&str, &str)]) -> Self {
        self.inner = self.inner.query(pairs);
        self
    }
    #[must_use]
    pub fn timeout(mut self, d: Duration) -> Self {
        self.inner = self.inner.timeout(d);
        self
    }
    #[must_use]
    pub fn max_response_bytes(mut self, n: u64) -> Self {
        self.inner = self.inner.max_response_bytes(n);
        self
    }

    /// Send, and buffer the whole body.
    ///
    /// Refuses rather than deadlocks when called from inside an async runtime:
    /// `block_on` would park a thread the executor is depending on.
    pub fn send(self) -> Result<Response> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Error::BlockingInAsyncContext);
        }
        // Built after the refusal above, so this runtime is never created — or
        // dropped — inside an async context.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(Error::Io)?;
        let inner = self.inner;
        rt.block_on(async move {
            let resp = inner.send().await?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let url = resp.url().to_string();
            let declared = resp.content_length();
            let body = resp.bytes().await?;
            Ok(Response {
                status,
                headers,
                url,
                body,
                declared_length: declared,
            })
        })
    }
}

/// A blocking response, body already buffered.
#[derive(Debug, Clone)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    url: String,
    body: Bytes,
    declared_length: Option<u64>,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn content_length(&self) -> Option<u64> {
        self.declared_length
    }

    /// Refuse a non-2xx status.
    pub fn error_for_status(self) -> Result<Self> {
        if self.status.is_success() {
            return Ok(self);
        }
        Err(Error::Status {
            status: self.status,
            url: self.url,
        })
    }

    pub fn bytes(self) -> Bytes {
        self.body
    }

    pub fn text(self) -> Result<String> {
        String::from_utf8(self.body.to_vec()).map_err(|_| Error::NotUtf8)
    }

    pub fn json<T: serde::de::DeserializeOwned>(self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blocking_call_from_inside_a_runtime_is_refused_not_deadlocked() {
        // The client is built outside and only *used* inside, which is the
        // shape a caller would hit: blocking helper invoked from async code.
        let c = Client::builder()
            .root_store(rustls::RootCertStore::empty())
            .build()
            .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = c.get("http://127.0.0.1:1/").send().unwrap_err();
            assert!(
                matches!(err, Error::BlockingInAsyncContext),
                "expected a refusal, got {err:?}"
            );
        });
    }

    #[test]
    fn a_client_can_be_dropped_inside_an_async_context() {
        // Holding a runtime per client made this panic in tokio's shutdown
        // path, far from the code responsible.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = Client::builder()
                .root_store(rustls::RootCertStore::empty())
                .build()
                .unwrap();
            drop(c);
        });
    }

    #[test]
    fn error_for_status_passes_2xx_and_refuses_others() {
        let mk = |code: u16| Response {
            status: StatusCode::from_u16(code).unwrap(),
            headers: HeaderMap::new(),
            url: "http://example/".into(),
            body: Bytes::new(),
            declared_length: None,
        };
        assert!(mk(200).error_for_status().is_ok());
        assert!(mk(204).error_for_status().is_ok());
        let err = mk(404).error_for_status().unwrap_err();
        assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
        assert!(mk(500).error_for_status().is_err());
    }
}
