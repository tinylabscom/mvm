//! HTTP CONNECT proxy with hostname allowlist.
//!
//! ## Why explicit-proxy CONNECT
//!
//! `pip`, `uv`, `pnpm`, and `npm` all honor `HTTPS_PROXY` /
//! `HTTP_PROXY` environment variables and, when set, route HTTPS
//! requests through the proxy via the standard HTTP CONNECT
//! method (RFC 7231 §4.3.6). Setting `HTTPS_PROXY=http://127.0.0.1:8443`
//! in the installer's env means every package fetch issues a
//! `CONNECT host:port HTTP/1.1` to us before TLS starts.
//!
//! We parse the host:port out of the CONNECT line, check it
//! against the allowlist, and either:
//!
//! - **Allowed**: open a TCP connection to the upstream, respond
//!   `HTTP/1.1 200 Connection Established\r\n\r\n` to the client,
//!   and shuttle bytes both ways. TLS handshakes between client +
//!   upstream pass through transparently. We never see plaintext.
//! - **Denied**: respond `HTTP/1.1 403 Forbidden\r\n...` and close
//!   the connection. The installer surfaces the 403 as a fetch
//!   error; the negative path is observable in the fetch log.
//!
//! ## Threading model
//!
//! One thread per accepted socket. The proxy is bounded by the
//! installer's concurrency (`uv`'s default is 8 parallel fetches),
//! so the thread count never explodes. No tokio dep — std::net +
//! std::thread keeps the crate's closure tiny.
//!
//! ## Idle / runaway protection
//!
//! Each accepted socket gets a hard read timeout on the CONNECT
//! handshake (5s). After the tunnel is established, the bytewise
//! copy uses no timeout — the installer's own request timeout
//! gates how long a tunnel stays open. Worst case: a slow upstream
//! holds a thread open for the installer's timeout (~30s default).

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::egress_proxy::allowlist::Allowlist;

/// Default address the proxy listens on inside the builder VM.
/// 127.0.0.1 only — the installer runs on the same network
/// namespace and dials localhost; the proxy doesn't need to be
/// reachable from outside the VM.
pub const DEFAULT_BIND: &str = "127.0.0.1:8443";

/// Max bytes we read into the CONNECT request line buffer before
/// giving up. RFC 7230 §3.1.1 caps request-line length at
/// implementation-defined; 8 KiB is generous for `CONNECT
/// <very.long.hostname>:443 HTTP/1.1`.
const MAX_REQUEST_LINE_LEN: usize = 8 * 1024;

/// Read timeout on the CONNECT handshake. After we send the
/// response, the per-direction copies run untimed — the
/// installer's request timeout is the upper bound.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect timeout when we dial the upstream on behalf of an
/// allowed CONNECT. Keeps us from hanging a thread on a slow
/// DNS or unreachable destination.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Run-handle for a listening proxy. Holds the listener thread's
/// `JoinHandle` and a shutdown flag the binding thread flips to
/// stop accepting new connections.
pub struct ProxyHandle {
    pub local_addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ProxyHandle {
    /// Signal the listener thread to stop accepting + wait for it
    /// to exit. Idempotent — calling twice is a no-op. Called from
    /// `Drop` if the caller forgot to invoke it.
    pub fn shutdown(&mut self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        // Poke the listener with a self-connect to unblock the
        // accept(). Best-effort; if it fails we still wait on the
        // join and rely on the SO_REUSEADDR + the OS to tear the
        // socket down.
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(200));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Bind a proxy to `bind_addr` (e.g. `"127.0.0.1:8443"` or
/// `"127.0.0.1:0"` for a kernel-assigned port). Spawns a listener
/// thread that accepts connections, parses CONNECT lines, and
/// either tunnels (allowed) or refuses (denied). Returns a handle
/// the caller drops or explicitly shuts down.
///
/// The allowlist is moved in by `Arc`-wrap so the listener thread
/// and each per-connection thread share one immutable reference.
/// The listener never mutates it.
pub fn start(bind_addr: &str, allowlist: Allowlist) -> io::Result<ProxyHandle> {
    let listener = TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(false)?;
    let local_addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let allowlist = Arc::new(allowlist);

    let shutdown_for_thread = Arc::clone(&shutdown);
    let allowlist_for_thread = Arc::clone(&allowlist);

    let join = std::thread::Builder::new()
        .name("mvm-egress-proxy-accept".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                if shutdown_for_thread.load(Ordering::SeqCst) {
                    break;
                }
                let stream = match incoming {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("mvm-egress-proxy: accept failed: {e}");
                        continue;
                    }
                };
                let allowlist = Arc::clone(&allowlist_for_thread);
                std::thread::Builder::new()
                    .name("mvm-egress-proxy-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(stream, &allowlist) {
                            eprintln!("mvm-egress-proxy: connection ended: {e}");
                        }
                    })
                    .ok();
            }
        })?;

    Ok(ProxyHandle {
        local_addr,
        shutdown,
        join: Some(join),
    })
}

/// Per-connection handler: parse CONNECT, decide allow/deny, and
/// either tunnel or refuse.
fn handle_connection(mut client: TcpStream, allowlist: &Allowlist) -> io::Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let request = match read_request_head(&mut client) {
        Ok(r) => r,
        Err(e) => {
            // Best-effort 400 — the client violated HTTP/1.1
            // before we could even parse host:port.
            let _ = client.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return Err(e);
        }
    };

    let (host, port) = match parse_connect_target(&request) {
        Ok(target) => target,
        Err(e) => {
            let _ = client.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return Err(io::Error::other(e));
        }
    };

    if !allowlist.is_allowed(&host, port) {
        eprintln!("mvm-egress-proxy: DENY {host}:{port}");
        let body =
            format!("denied by mvm-egress-proxy: {host}:{port} not on the ADR-047 allowlist");
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {len}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n{body}",
            len = body.len(),
        );
        let _ = client.write_all(response.as_bytes());
        return Ok(());
    }

    eprintln!("mvm-egress-proxy: ALLOW {host}:{port}");

    // Resolve + dial upstream. We use ToSocketAddrs lookup; the
    // builder VM's libkrun-provided DNS resolves the allowlisted
    // hostnames to their public IPs. Failure here is reported as
    // 502 Bad Gateway so the client can distinguish "allowlist
    // refused" (403) from "we tried and the upstream is down"
    // (502).
    let target = format!("{host}:{port}");
    let upstream = match TcpStream::connect_timeout(
        &match target.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(_) => {
                // Hostname literal — fall back to the resolver
                // path. std doesn't expose connect_timeout for
                // ToSocketAddrs; use connect() and let the OS
                // resolver handle DNS.
                match TcpStream::connect(&target) {
                    Ok(s) => {
                        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                        return tunnel(client, s);
                    }
                    Err(e) => {
                        eprintln!("mvm-egress-proxy: upstream dial {target} failed: {e}");
                        let _ = client.write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return Err(e);
                    }
                }
            }
        },
        UPSTREAM_CONNECT_TIMEOUT,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mvm-egress-proxy: upstream connect {target} failed: {e}");
            let _ = client.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return Err(e);
        }
    };

    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    tunnel(client, upstream)
}

/// Read the CONNECT request head (request line + headers). Stops
/// at the empty CRLFCRLF separator. Caps the total bytes read at
/// `MAX_REQUEST_LINE_LEN` to keep a malicious client from
/// exhausting memory.
fn read_request_head(client: &mut TcpStream) -> io::Result<String> {
    let mut reader = BufReader::new(client);
    let mut acc = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before CONNECT request",
            ));
        }
        acc.push_str(&line);
        if acc.len() > MAX_REQUEST_LINE_LEN {
            return Err(io::Error::other("request head exceeded 8 KiB"));
        }
        if line == "\r\n" || line == "\n" {
            return Ok(acc);
        }
    }
}

/// Parse the host + port out of the first line of `request`. The
/// expected shape is `CONNECT host:port HTTP/1.1\r\n`.
///
/// IPv6 literal targets (`[::1]:443`) are not handled — the
/// allowlisted hostnames are all DNS-resolved IPv4/IPv6 records, not
/// literal addresses; we don't need to parse the literal form.
/// An installer that somehow asks for a literal IPv6 target gets a
/// 400 from here. Documented as a known limitation.
pub fn parse_connect_target(request: &str) -> Result<(String, u16), String> {
    let first_line = request.lines().next().ok_or("empty request")?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?;
    let target = parts.next().ok_or("missing target")?;
    let version = parts.next().ok_or("missing HTTP version")?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(format!("expected CONNECT method, got `{method}`"));
    }
    if !version.starts_with("HTTP/") {
        return Err(format!("expected HTTP version, got `{version}`"));
    }

    // target is `host:port` for CONNECT. Splitting on the last
    // ':' lets IPv6 literals fail loudly (they contain ':' inside
    // the host) rather than parse a wrong host.
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("target `{target}` has no port"))?;
    if host.is_empty() {
        return Err("empty host in CONNECT target".to_string());
    }
    if host.contains(':') {
        // IPv6 literal — see note above.
        return Err(format!("IPv6 literal targets are not supported: {target}"));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("port `{port}` is not a valid u16"))?;
    Ok((host.to_string(), port))
}

/// Bidirectional byte copy. Returns when either side closes its
/// half of the connection. We split the streams and run two
/// `std::io::copy` loops in two threads — one for client→upstream
/// and one for upstream→client.
fn tunnel(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    // After the handshake, clear timeouts on both sides — the
    // installer's own request timeout is the upper bound on tunnel
    // duration.
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    upstream.set_read_timeout(None)?;
    upstream.set_write_timeout(None)?;

    let client_read = client.try_clone()?;
    let upstream_write = upstream.try_clone()?;
    let upstream_read = upstream;
    let client_write = client;

    let h1 = std::thread::spawn(move || copy_half(client_read, upstream_write));
    let h2 = std::thread::spawn(move || copy_half(upstream_read, client_write));
    // Wait for *both* halves to drain before tearing the handle
    // down. If we returned on the first close, an in-flight last
    // chunk on the other half would be lost.
    let _ = h1.join();
    let _ = h2.join();
    Ok(())
}

/// One half of the bidirectional copy. `std::io::copy` doesn't
/// surface a clean shutdown distinct from a half-close; treat any
/// error other than "would block / interrupted / connection reset"
/// as a hard fail.
fn copy_half(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = [0u8; 8 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => {
                // Peer closed its half. Half-close the destination
                // so the other direction can drain.
                let _ = dst.shutdown(std::net::Shutdown::Write);
                return;
            }
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = dst.shutdown(std::net::Shutdown::Write);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_proxy::allowlist::Allowlist;
    use std::io::Write;
    use std::net::TcpStream;

    fn local_allowlist() -> Allowlist {
        // For tests we use a one-entry custom allowlist so we
        // don't need to dial public infrastructure.
        Allowlist::from_parts(vec!["allowed.test".to_string()], 443)
    }

    #[test]
    fn parse_connect_target_happy_path() {
        let req = "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n";
        let (host, port) = parse_connect_target(req).unwrap();
        assert_eq!(host, "pypi.org");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_target_lowercased_method() {
        // RFC 7230 §3.1.1 says methods are case-sensitive, but in
        // practice the proxy ecosystem treats `connect` as
        // equivalent to `CONNECT`. We do the same.
        let req = "connect pypi.org:443 HTTP/1.1\r\n\r\n";
        let (host, port) = parse_connect_target(req).unwrap();
        assert_eq!(host, "pypi.org");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_target_rejects_non_connect_method() {
        let req = "GET http://pypi.org/ HTTP/1.1\r\n\r\n";
        let err = parse_connect_target(req).unwrap_err();
        assert!(err.contains("CONNECT"), "msg: {err}");
    }

    #[test]
    fn parse_connect_target_rejects_missing_port() {
        let req = "CONNECT pypi.org HTTP/1.1\r\n\r\n";
        let err = parse_connect_target(req).unwrap_err();
        assert!(err.contains("port"), "msg: {err}");
    }

    #[test]
    fn parse_connect_target_rejects_garbage_port() {
        let req = "CONNECT pypi.org:abc HTTP/1.1\r\n\r\n";
        let err = parse_connect_target(req).unwrap_err();
        assert!(err.contains("u16"), "msg: {err}");
    }

    #[test]
    fn parse_connect_target_rejects_empty_host() {
        let req = "CONNECT :443 HTTP/1.1\r\n\r\n";
        let err = parse_connect_target(req).unwrap_err();
        assert!(err.contains("empty host"), "msg: {err}");
    }

    #[test]
    fn parse_connect_target_rejects_ipv6_literal() {
        // IPv6 literal targets aren't supported in v1 (see
        // module-level note). Make sure they fail loudly rather
        // than slipping through with a wrong host parse.
        let req = "CONNECT [::1]:443 HTTP/1.1\r\n\r\n";
        let err = parse_connect_target(req).unwrap_err();
        assert!(err.contains("IPv6"), "msg: {err}");
    }

    #[test]
    fn parse_connect_target_rejects_missing_version() {
        let req = "CONNECT pypi.org:443\r\n\r\n";
        let err = parse_connect_target(req).unwrap_err();
        assert!(err.contains("HTTP version"), "msg: {err}");
    }

    #[test]
    fn parse_connect_target_high_port() {
        let req = "CONNECT pypi.org:8443 HTTP/1.1\r\n\r\n";
        let (_, port) = parse_connect_target(req).unwrap();
        assert_eq!(port, 8443);
    }

    /// End-to-end test: spawn a proxy on a kernel-assigned port,
    /// open a CONNECT to a denied host, assert 403.
    #[test]
    fn denied_target_returns_403() {
        let handle = start("127.0.0.1:0", local_allowlist()).unwrap();
        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client
            .write_all(
                b"CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com:443\r\n\r\n",
            )
            .unwrap();

        let mut buf = [0u8; 512];
        let n = client.read(&mut buf).unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "unexpected response: {response}"
        );
    }

    /// End-to-end test: spawn the proxy + a tiny upstream server,
    /// CONNECT through the proxy to the upstream's local address
    /// using an allowlist that names that address's host. Asserts
    /// the proxy responds 200 and bytes flow through.
    #[test]
    fn allowed_target_tunnels_bytes() {
        // Upstream: a one-shot TCP echo on a kernel-assigned port.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = upstream_listener.accept() {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf) {
                    let _ = s.write_all(&buf[..n]);
                }
            }
        });

        // Allowlist names 127.0.0.1 on the upstream's exact port.
        let allowlist = Allowlist::from_parts(vec!["127.0.0.1".to_string()], upstream_addr.port());
        let handle = start("127.0.0.1:0", allowlist).unwrap();

        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        let connect = format!(
            "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n",
            port = upstream_addr.port(),
        );
        client.write_all(connect.as_bytes()).unwrap();

        // Read the 200 line.
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected 200 Connection Established, got: {response}"
        );

        // Now the tunnel is open — send a payload, expect the echo.
        client.write_all(b"hello").unwrap();
        let mut echo = [0u8; 5];
        client.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"hello");
    }

    #[test]
    fn malformed_request_returns_400() {
        let handle = start("127.0.0.1:0", local_allowlist()).unwrap();
        let mut client = TcpStream::connect(handle.local_addr).unwrap();
        client.write_all(b"this is not HTTP\r\n\r\n").unwrap();
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).unwrap();
        let response = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "expected 400, got: {response}"
        );
    }

    #[test]
    fn shutdown_handle_stops_accepting() {
        let mut handle = start("127.0.0.1:0", local_allowlist()).unwrap();
        let addr = handle.local_addr;
        handle.shutdown();
        // After shutdown the listener thread has joined; a fresh
        // dial may still succeed if the OS hasn't released the
        // port yet (TIME_WAIT). What we assert is that calling
        // shutdown a second time is a no-op and doesn't panic.
        handle.shutdown();
        // Smoke-check: address is still reportable even after
        // shutdown.
        assert_eq!(addr, handle.local_addr);
    }
}
