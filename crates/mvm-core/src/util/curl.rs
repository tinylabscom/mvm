//! The transport limits every release download passes to `curl`.
//!
//! Each download is digest- or signature-checked afterwards, so these limits do
//! not guard integrity. They keep a hostile or broken server from downgrading
//! the transport, redirecting a fetch elsewhere, or holding the process on a
//! connection that never finishes.

/// Arguments that confine a `curl` fetch of `url` to HTTPS end to end: the
/// request and every redirect, at most five of them. A loopback `http://` URL
/// and a `file://` URL are the exceptions for the request itself, so a local
/// mirror or fixture can stand in for the release host; redirects must still be
/// HTTPS. A connection that cannot be opened in 30 seconds, or that stays under
/// 1 KiB/s for 60 seconds, is abandoned. There is deliberately no total-time or
/// size cap, because the artifacts are large and legitimately slow on a poor
/// link.
#[must_use]
pub fn curl_transport_args(url: &str) -> [&'static str; 12] {
    [
        "--proto",
        request_protocols(url),
        "--proto-redir",
        "=https",
        "--max-redirs",
        "5",
        "--connect-timeout",
        "30",
        "--speed-limit",
        "1024",
        "--speed-time",
        "60",
    ]
}

/// The protocols `url` itself may use. A `file://` URL reads the local disk and
/// has no transport to downgrade; a loopback `http://` URL stays on this
/// machine; anything else must be HTTPS.
fn request_protocols(url: &str) -> &'static str {
    if url.starts_with("file://") {
        "=file"
    } else if is_loopback_http(url) {
        "=http,https"
    } else {
        "=https"
    }
}

/// Whether `url` is plain HTTP to this machine: `127.0.0.1`, `localhost` or
/// `[::1]`, followed by a port, a path or nothing. `localhost.example.com` and
/// `127.0.0.1.example.com` are other hosts.
fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    ["127.0.0.1", "localhost", "[::1]"].iter().any(|host| {
        rest.strip_prefix(host)
            .is_some_and(|tail| tail.is_empty() || tail.starts_with([':', '/']))
    })
}

#[cfg(test)]
mod tests {
    use super::curl_transport_args;

    fn proto(url: &str) -> &'static str {
        let args = curl_transport_args(url);
        let at = args.iter().position(|a| *a == "--proto").unwrap();
        args[at + 1]
    }

    #[test]
    fn a_remote_fetch_is_https_only_and_so_are_its_redirects() {
        for url in [
            "https://github.com/x",
            "http://github.com/x",
            "http://localhost.example.com/x",
            "http://127.0.0.1.example.com/x",
            "http://127.0.0.1@example.com/x",
        ] {
            assert_eq!(proto(url), "=https", "{url}");
        }
        for url in [
            "http://127.0.0.1:8080/x",
            "http://localhost/x",
            "http://[::1]:1/x",
        ] {
            let args = curl_transport_args(url);
            let at = args.iter().position(|a| *a == "--proto-redir").unwrap();
            assert_eq!(args[at + 1], "=https", "{url}");
        }
    }

    #[test]
    fn a_loopback_server_may_be_plain_http() {
        for url in [
            "http://127.0.0.1:8080/x",
            "http://127.0.0.1/x",
            "http://localhost:9/x",
            "http://[::1]:9/x",
        ] {
            assert_eq!(proto(url), "=http,https", "{url}");
        }
    }

    #[test]
    fn a_file_url_reads_the_disk_and_nothing_else() {
        assert_eq!(proto("file:///tmp/mirror/x"), "=file");
        assert_eq!(proto("ftp://example.com/x"), "=https");
    }

    #[test]
    fn a_stalled_or_unreachable_server_is_abandoned() {
        let args = curl_transport_args("https://example/x");
        for flag in [
            "--max-redirs",
            "--connect-timeout",
            "--speed-limit",
            "--speed-time",
        ] {
            assert!(args.contains(&flag), "{flag}");
        }
    }
}
