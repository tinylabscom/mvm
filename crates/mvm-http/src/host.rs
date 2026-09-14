//! Host classification for transport decisions made before a request is sent.

use url::Url;

/// Whether `url` names a loopback host: `localhost`, `127.0.0.0/8`, or `::1`.
///
/// This is the one cleartext exception callers grant: a sidecar on the same
/// host. It judges the URL as written and does not resolve it, so a public
/// name that happens to resolve to a loopback address is not loopback here —
/// the safe direction for a rule that decides whether credentials may travel
/// unencrypted.
pub fn is_loopback_host(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback(url: &str) -> bool {
        is_loopback_host(&Url::parse(url).unwrap())
    }

    #[test]
    fn localhost_and_loopback_addresses_are_loopback() {
        assert!(loopback("http://localhost:4318/"));
        assert!(loopback("http://LOCALHOST/"));
        assert!(loopback("http://127.0.0.1:4318/"));
        assert!(loopback("http://127.8.9.10/"));
        assert!(loopback("http://[::1]:4318/"));
    }

    #[test]
    fn remote_and_lookalike_hosts_are_not_loopback() {
        assert!(!loopback("http://collector.example.com/"));
        assert!(!loopback("http://localhost.example.com/"));
        assert!(!loopback("http://128.0.0.1/"));
        assert!(!loopback("http://[::2]/"));
        assert!(!loopback("file:///tmp/x"));
    }
}
