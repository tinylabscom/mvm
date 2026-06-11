//! Pure-Rust DNS resolver backed by `hickory-resolver`.
//!
//! Alternative to [`crate::supervisor::l7_proxy::TokioDnsResolver`] (which calls
//! the host libc's `getaddrinfo`). Use this when operators want:
//!
//! - Custom upstream resolvers (e.g., a per-tenant resolver that
//!   filters to a curated list).
//! - DoT / DoH upstreams (configurable on the underlying
//!   `hickory_resolver::config::ResolverConfig`).
//! - A resolver that's independent of `/etc/resolv.conf`'s
//!   ambient state — useful when the supervisor runs in a
//!   different network namespace than the host.
//!
//! `TokioDnsResolver` stays the default; consumers explicitly
//! construct `HickoryDnsResolver` when they want this surface.
//!
//! The resolver is `Arc<HickoryDnsResolver>` so multiple proxy
//! tasks can share one cache. Construction is sync — the actual
//! `hickory_resolver::TokioAsyncResolver` is built lazily on first
//! `resolve` call so callers can construct in non-tokio contexts.
//!
//! ## What this module does NOT do
//!
//! - **No allow-listing of resolved IPs.** That's the L4 policy's
//!   job ([`crate::supervisor::proxy::l4`]) — DNS resolution returns the IPs;
//!   policy decides whether the flow to those IPs is allowed.
//! - **No DNS interception** of guest queries. The guest's `/etc/resolv.conf`
//!   gets pointed at the supervisor's DNS endpoint by the per-VM
//!   netns wiring; this module provides the resolver the endpoint uses.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use tokio::sync::OnceCell;

use crate::supervisor::egress::EgressError;
use crate::supervisor::l7_proxy::DnsResolver;

/// `DnsResolver` impl backed by `hickory-resolver`. Built around a
/// `OnceCell` so construction stays sync while resolution runs on
/// tokio.
pub struct HickoryDnsResolver {
    config: ResolverConfig,
    opts: ResolverOpts,
    inner: OnceCell<TokioAsyncResolver>,
}

impl HickoryDnsResolver {
    /// Build with the default Google / Cloudflare upstream config.
    /// Equivalent to `hickory_resolver::config::ResolverConfig::default()`
    /// — useful as a drop-in that works without
    /// `/etc/resolv.conf` introspection.
    pub fn with_defaults() -> Self {
        Self::new(ResolverConfig::default(), ResolverOpts::default())
    }

    /// Build with operator-supplied `ResolverConfig` + `ResolverOpts`.
    /// Use this for custom upstreams (DoT, DoH, per-tenant DNS
    /// servers).
    pub fn new(config: ResolverConfig, opts: ResolverOpts) -> Self {
        Self {
            config,
            opts,
            inner: OnceCell::new(),
        }
    }

    async fn ensure_resolver(&self) -> &TokioAsyncResolver {
        self.inner
            .get_or_init(|| async {
                TokioAsyncResolver::tokio(self.config.clone(), self.opts.clone())
            })
            .await
    }
}

impl Default for HickoryDnsResolver {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve_one(&self, host: &str, _port: u16) -> Result<IpAddr, EgressError> {
        let resolver = self.ensure_resolver().await;
        let lookup = resolver.lookup_ip(host).await.map_err(|e| {
            EgressError::UpstreamUnreachable(format!("hickory lookup_ip({host}): {e}"))
        })?;
        lookup.into_iter().next().ok_or_else(|| {
            EgressError::UpstreamUnreachable(format!("hickory resolved {host} to zero IPs"))
        })
    }
}

/// `Arc`-wrap the resolver. The `L7EgressProxy::new` constructor
/// takes `Arc<dyn DnsResolver>` so a shared resolver across
/// proxy tasks is the standard shape.
pub fn into_arc(r: HickoryDnsResolver) -> Arc<dyn DnsResolver> {
    Arc::new(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_with_defaults_without_panic() {
        // Construction is sync; the resolver is lazy. This test
        // proves the default config builds without needing a
        // tokio runtime context.
        let _r = HickoryDnsResolver::with_defaults();
    }

    #[test]
    fn default_impl_returns_with_defaults() {
        // The Default impl matches with_defaults — no surprise
        // upstream config diff.
        let _r: HickoryDnsResolver = Default::default();
    }

    #[test]
    fn into_arc_returns_dyn_resolver() {
        // Compile-time check that the helper produces the exact
        // shape the L7EgressProxy::new constructor expects.
        fn takes_resolver(_: Arc<dyn DnsResolver>) {}
        let r = HickoryDnsResolver::with_defaults();
        takes_resolver(into_arc(r));
    }

    // Live-DNS tests are deliberately out — sandboxed test envs
    // often have no DNS. The hickory crate has its own test
    // coverage; we test the wrapper shape.
}
