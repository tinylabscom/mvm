//! The name-resolution seam.
//!
//! This is the hook the SSRF guard installs. It matters that resolution is a
//! trait and that the client connects **only** to addresses the resolver
//! returned: a guard that validates a hostname and then lets the connect path
//! re-resolve it independently is a DNS-rebinding hole, because the second
//! lookup can answer differently from the first.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

/// Resolve a host and port to the addresses the client is permitted to dial,
/// in preference order.
///
/// Returning an empty vector means "resolved, but nothing is permitted" and
/// surfaces as [`crate::Error::NoPermittedAddress`] — distinct from an `Err`,
/// which means the lookup itself failed.
pub trait Resolve: Send + Sync + std::fmt::Debug {
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
}

/// The default resolver: the system resolver, unfiltered.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), port)).await?;
            Ok(addrs.collect())
        })
    }
}

/// A resolver that answers from a fixed table and never touches the network.
///
/// Used by callers that pre-resolve and validate addresses themselves, and by
/// tests. Because the client dials only what a resolver returns, pinning here
/// is what closes the rebinding window between check and connect.
#[derive(Debug, Clone, Default)]
pub struct PinnedResolver {
    entries: Vec<(String, Vec<SocketAddr>)>,
}

impl PinnedResolver {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, host: impl Into<String>, addrs: Vec<SocketAddr>) -> Self {
        self.entries.push((host.into(), addrs));
        self
    }
}

impl Resolve for PinnedResolver {
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>> {
        let found = self
            .entries
            .iter()
            .find(|(h, _)| h.eq_ignore_ascii_case(&host))
            .map(|(_, addrs)| {
                addrs
                    .iter()
                    .map(|a| SocketAddr::new(a.ip(), if a.port() == 0 { port } else { a.port() }))
                    .collect::<Vec<_>>()
            });
        Box::pin(async move {
            found.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "host not present in pinned resolver",
                )
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pinned_resolver_is_case_insensitive_and_fills_the_port() {
        let r = PinnedResolver::new().with("Example.COM", vec!["10.0.0.1:0".parse().unwrap()]);
        let got = r.resolve("example.com".into(), 8443).await.unwrap();
        assert_eq!(got, vec!["10.0.0.1:8443".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn pinned_resolver_keeps_an_explicit_port() {
        let r = PinnedResolver::new().with("h", vec!["10.0.0.1:99".parse().unwrap()]);
        let got = r.resolve("h".into(), 8443).await.unwrap();
        assert_eq!(got, vec!["10.0.0.1:99".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn unknown_host_is_an_error_not_an_empty_answer() {
        let r = PinnedResolver::new();
        assert!(r.resolve("nope".into(), 1).await.is_err());
    }
}
