//! Shared HTTP-client hardening for the search/fetch tools.
//!
//! Before this module existed, each search provider built its own bare client
//! with a timeout but neither a redirect policy nor any SSRF guarding — so
//! poisoning DNS for `api.search.brave.com` to a private IP would have routed
//! credentials at a local attacker.
//!
//! Every HTTP-using tool surface goes through [`hardened_client_builder`],
//! which carries:
//!
//! - **No auto-redirect.** `mvm-http` never follows one, so this is an absence
//!   rather than a setting. An upstream 3xx surfaces its status and headers to
//!   the caller; nothing follows silently.
//! - **SSRF / DNS-rebinding defence.** [`SsrfFilteringResolver`] wraps the
//!   system resolver and discards every address [`SsrfGuard::classify`]
//!   rejects — RFC1918, loopback, link-local, cloud metadata
//!   (169.254.169.254), CGNAT, IPv6 unique-local. If every resolved address is
//!   blocked, resolution fails with the guard named so an operator sees the
//!   cause; if any survive, only the safe set is dialled. The client connects
//!   solely to what the resolver returned, which is what closes the gap between
//!   checking a host and connecting to it.
//! - **TLS 1.3 floor.** Only 1.3 mandates forward secrecy on every cipher
//!   suite, drops the static-RSA key exchange, and removes MAC-then-encrypt.
//!   Every targeted upstream supports it, so pinning the floor closes a
//!   downgrade vector without breaking an operator workflow.
//!
//! One resolver serves every caller. That was not previously possible: reqwest
//! connects on the resolver's port rather than the URL's, and its `Resolve`
//! trait is never handed the port, so the filtering resolver had to hardcode
//! 443 and any caller forwarding to another port needed a second builder with
//! no resolver plus a manual resolve-and-pin. `mvm_http::Resolve` receives
//! `(host, port)`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mvm_http::resolve::Resolve;

use crate::supervisor::ssrf_guard::SsrfGuard;

/// Minimum TLS version every client here accepts.
/// Pinned at TLS 1.3 to mandate forward secrecy +
/// AEAD-only ciphers + remove the static-RSA + MAC-then-encrypt
/// legacy paths. All operator-likely upstreams support 1.3.
pub const MIN_TLS_VERSION: mvm_http::TlsVersion = mvm_http::TlsVersion::Tls13;

/// Build a client pre-configured with the SSRF-filtering resolver and the
/// TLS-1.3 floor. Callers add their own per-tool config (headers, user-agent)
/// before `.build()`. Redirects are not a setting: `mvm-http` never follows
/// them.
///
/// There is one builder now. There used to be two, because reqwest connects on
/// the *resolver's* port rather than the URL's and its `Resolve` trait is never
/// handed the port — so an SSRF-filtering resolver had to hardcode 443, and
/// anything forwarding to another port needed a second, resolver-less builder
/// plus a manual resolve-and-pin dance. `mvm_http::Resolve` receives
/// `(host, port)`, so the filtering resolver is port-correct and the split is
/// gone.
pub fn hardened_client_builder(timeout_secs: u64) -> mvm_http::ClientBuilder {
    mvm_http::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .resolver(Arc::new(SsrfFilteringResolver))
        .min_tls_version(MIN_TLS_VERSION)
}

/// [`hardened_client_builder`] plus an upstream proxy, when one is configured.
///
/// The proxy is a transport choice and changes nothing about which
/// destinations are permitted — that decision is made by the egress gate before
/// a request ever reaches this client. What it does change is who performs the
/// destination's final address resolution: through a proxy that is the proxy,
/// not [`SsrfFilteringResolver`]. The guard still governs every direct dial,
/// and the proxy is operator configuration on this host rather than anything a
/// guest supplies.
pub fn hardened_client_builder_via(
    timeout_secs: u64,
    proxy: Option<&mvm_http::ProxyConfig>,
) -> mvm_http::ClientBuilder {
    let b = hardened_client_builder(timeout_secs);
    match proxy {
        Some(p) => b.proxy(p.clone()),
        None => b,
    }
}

/// Resolver that delegates to the system resolver and filters every returned
/// IP through [`SsrfGuard::classify`]. Stateless — one instance per program is
/// fine.
///
/// The client dials **only** what this returns, which is what makes it the
/// chokepoint rather than an advisory check, and closes the window between
/// checking a host and connecting to it.
#[derive(Debug, Default)]
pub struct SsrfFilteringResolver;

impl Resolve for SsrfFilteringResolver {
    fn resolve(
        &self,
        host: String,
        port: u16,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
    {
        Box::pin(async move {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
                .await?
                .collect();
            filter_ssrf_addrs(resolved).map_err(std::io::Error::other)
        })
    }
}

/// Default response-body cap for search-provider impls. 1 MiB is
/// the working budget for "search result JSON" — real-world Brave /
/// Tavily / Google responses run ~10-50 KB. Providers can override
/// when their upstream returns larger payloads (e.g. an embedded
/// thumbnail) but should always carry *some* cap; uncapped reads
/// expose the supervisor to "send-gigabytes-of-JSON" DoS.
pub const DEFAULT_RESPONSE_BODY_CAP: usize = 1 << 20;

/// Read a response body, refusing to accumulate more
/// than `max_bytes`. Implementation mirrors
/// the fetcher's chunk loop —
/// the cap is enforced *before* a chunk that would overflow lands
/// in the accumulator, so the returned `Vec<u8>` is exactly
/// `≤ max_bytes` on success.
///
/// Returns `Ok(bytes)` on success or an error string when the
/// upstream wanted to send more. Callers wrap the string into their
/// own provider-specific error type.
pub async fn read_capped(
    mut response: mvm_http::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut body = Vec::with_capacity(max_bytes.min(64 * 1024));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("reading response chunk: {e}"))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!(
                "response body exceeded max_bytes ({max_bytes}); upstream wanted to send more \
                 (refusing; plan 65 follow-on)"
            ));
        }
        body.extend_from_slice(&chunk);
        debug_assert!(body.len() <= max_bytes);
    }
    Ok(body)
}

/// Filter a list of resolved addresses through the SSRF guard.
///
/// Returns the safe subset on success. Returns an error if **every**
/// input address was rejected (so the caller can surface a clear
/// "all addresses are SSRF-blocked" message instead of a confusing
/// "no addresses to connect to"). If some IPs are safe + some are
/// blocked, the blocked ones are silently dropped — defense in
/// depth, not an audit signal, so a partial-block scenario doesn't
/// fail the whole call.
pub fn filter_ssrf_addrs(
    addrs: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, String> {
    let mut blocked: Vec<String> = Vec::new();
    let mut safe: Vec<SocketAddr> = Vec::new();
    for sa in addrs {
        match SsrfGuard::classify(sa.ip()) {
            Some(reason) => blocked.push(format!("{} ({reason})", sa.ip())),
            None => safe.push(sa),
        }
    }
    if safe.is_empty() && !blocked.is_empty() {
        return Err(format!(
            "SSRF guard rejected all resolved addresses: {} \
             (refusing to fetch; plan 65 W2)",
            blocked.join(", ")
        ));
    }
    Ok(safe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sa(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    #[test]
    fn filter_passes_public_ip() {
        let out = filter_ssrf_addrs([sa([8, 8, 8, 8], 443)]).unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn filter_rejects_when_only_loopback() {
        let err = filter_ssrf_addrs([sa([127, 0, 0, 1], 443)]).unwrap_err();
        assert!(err.contains("SSRF guard"), "{err}");
        assert!(err.contains("loopback"), "{err}");
        assert!(err.contains("127.0.0.1"), "{err}");
    }

    #[test]
    fn filter_rejects_when_only_imds() {
        let err = filter_ssrf_addrs([sa([169, 254, 169, 254], 80)]).unwrap_err();
        assert!(err.contains("metadata"), "{err}");
    }

    #[test]
    fn filter_rejects_when_only_rfc1918() {
        let err = filter_ssrf_addrs([sa([10, 0, 0, 1], 443)]).unwrap_err();
        assert!(err.contains("RFC1918"), "{err}");
    }

    #[test]
    fn filter_drops_blocked_keeps_safe_when_mixed() {
        // Two upstream addresses; one public + one private. The
        // public one survives; the private is silently dropped.
        // (Defense in depth — we don't fail the whole call just
        // because one of several IPs is bad. The audit signal lives
        // at the per-call layer in HardenedHttpFetcher, not here.)
        let out = filter_ssrf_addrs([sa([8, 8, 8, 8], 443), sa([10, 0, 0, 1], 443)]).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn filter_passes_empty_input() {
        // An empty resolution result isn't a security failure; let
        // the client surfaces "no addresses" through its own error path.
        let out = filter_ssrf_addrs(std::iter::empty()).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn hardened_client_builds_successfully() {
        // Smoke: the builder returns a real ClientBuilder we can
        // turn into a Client. Catches a future refactor that
        // accidentally breaks the chain.
        let client = hardened_client_builder(15).build();
        assert!(client.is_ok());
    }

    #[test]
    fn w7_min_tls_version_is_pinned_at_1_3() {
        // The MIN_TLS_VERSION constant must remain at TLS 1.3. A
        // future refactor that loosens it (e.g. for a one-off legacy
        // upstream) needs to flip this assertion explicitly. The pin
        // keeps the hardening posture visible from a one-line grep.
        assert_eq!(MIN_TLS_VERSION, mvm_http::TlsVersion::Tls13);
    }

    // ──────────────────────────────────────────────────────────────
    // read_capped — live HTTP via one-shot 127.0.0.1 server
    //
    // Lives in `crates/mvm-supervisor/tests/http_hardening_loopback.rs`
    // — the architecture.yml invariant scan forbids binding TCP
    // listeners in production source files even inside inline
    // `#[cfg(test)]` modules.
    // ──────────────────────────────────────────────────────────────
}
