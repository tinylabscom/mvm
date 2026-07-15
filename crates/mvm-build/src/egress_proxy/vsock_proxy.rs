//! Guest-local HTTP CONNECT proxy that relays upstream dials over host vsock.
//!
//! This is the NIC-less builder path: guest tools dial `127.0.0.1:8443`,
//! issue `CONNECT host:port`, and the proxy opens the real upstream through
//! the host-side `EGRESS_PORT` relay instead of a guest NIC.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::egress_proxy::{Allowlist, parse_connect_target};

/// Fixed guest-local bind the builder jobs use for `HTTP_PROXY` /
/// `HTTPS_PROXY`.
pub const DEFAULT_VSOCK_PROXY_BIND: &str = "127.0.0.1:8443";

/// Admission policy for guest-local CONNECT requests.
#[derive(Debug, Clone)]
pub enum ConnectPolicy {
    Allowlist(Allowlist),
    Unrestricted,
}

impl ConnectPolicy {
    fn permits(&self, host: &str, port: u16) -> bool {
        match self {
            Self::Allowlist(allowlist) => allowlist.is_allowed(host, port),
            Self::Unrestricted => {
                !host.is_empty()
                    && (1..=u16::MAX).contains(&port)
                    && !host.bytes().any(|b| b == b'\n' || b == b'\r')
            }
        }
    }
}

/// Owning handle for the listener thread.
pub struct VsockProxyHandle {
    pub local_addr: std::net::SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl VsockProxyHandle {
    pub fn shutdown(&mut self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(200));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for VsockProxyHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn start_vsock_proxy(bind_addr: &str, policy: ConnectPolicy) -> io::Result<VsockProxyHandle> {
    let listener = TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(false)?;
    let local_addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let policy = Arc::new(policy);

    let shutdown_for_thread = Arc::clone(&shutdown);
    let policy_for_thread = Arc::clone(&policy);

    let join = std::thread::Builder::new()
        .name("mvm-vsock-proxy-accept".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                if shutdown_for_thread.load(Ordering::SeqCst) {
                    break;
                }
                let stream = match incoming {
                    Ok(stream) => stream,
                    Err(e) => {
                        eprintln!("mvm-vsock-proxy: accept failed: {e}");
                        continue;
                    }
                };
                let policy = Arc::clone(&policy_for_thread);
                let _ = std::thread::Builder::new()
                    .name("mvm-vsock-proxy-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle_connection(stream, &policy) {
                            eprintln!("mvm-vsock-proxy: connection ended: {e}");
                        }
                    });
            }
        })?;

    Ok(VsockProxyHandle {
        local_addr,
        shutdown,
        join: Some(join),
    })
}

fn handle_connection(mut client: TcpStream, policy: &ConnectPolicy) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = read_request_head(&mut client)?;
    let (host, port) = parse_connect_target(&request).map_err(io::Error::other)?;
    if !policy.permits(&host, port) {
        let body = format!("denied by vsock proxy policy: {host}:{port}");
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: {len}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n{body}",
            len = body.len(),
        );
        client.write_all(response.as_bytes())?;
        return Ok(());
    }
    let upstream = dial_host_egress(&host, port)?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    // The 5s header-parse timeout is only for the CONNECT request. Once the
    // tunnel is established, long-running TLS/download reads must not trip a
    // stale socket timeout and silently tear down the splice on either side.
    client.set_read_timeout(None)?;
    client.set_write_timeout(None)?;
    upstream.set_read_timeout(None)?;
    upstream.set_write_timeout(None)?;
    splice_bidirectional(client, upstream)
}

fn read_request_head(client: &mut TcpStream) -> io::Result<String> {
    const MAX_REQUEST_LINE_LEN: usize = 8 * 1024;

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = client.read(&mut byte)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before CONNECT request",
            ));
        }
        buf.push(byte[0]);
        if buf.len() > MAX_REQUEST_LINE_LEN {
            return Err(io::Error::other(format!(
                "CONNECT request exceeded {MAX_REQUEST_LINE_LEN} bytes"
            )));
        }
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            return String::from_utf8(buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }
    }
}

fn dial_host_egress(host: &str, port: u16) -> io::Result<UnixStream> {
    let mut stream = mvm_agentd::vsock::connect_host_vsock(mvm_agentd::vsock::EGRESS_PORT, 10)
        .map_err(|e| io::Error::other(format!("connect host egress vsock: {e}")))?;
    writeln!(stream, "{host}:{port}")?;
    stream.flush()?;
    Ok(stream)
}

fn splice_bidirectional(client: TcpStream, upstream: UnixStream) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut client_write = client;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream;
    let pump = std::thread::spawn(move || {
        let result = std::io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        result
    });
    let upstream_to_client = std::io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let client_to_upstream = pump
        .join()
        .map_err(|_| io::Error::other("vsock splice thread panicked"))?;

    match (client_to_upstream, upstream_to_client) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(err), _) => Err(io::Error::new(
            err.kind(),
            format!("client->vsock splice failed: {err}"),
        )),
        (_, Err(err)) => Err(io::Error::new(
            err.kind(),
            format!("vsock->client splice failed: {err}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_policy_accepts_https_target_shape() {
        let policy = ConnectPolicy::Unrestricted;
        assert!(policy.permits("ftpmirror.gnu.org", 443));
    }

    #[test]
    fn unrestricted_policy_rejects_newline_injection() {
        let policy = ConnectPolicy::Unrestricted;
        assert!(!policy.permits("good.example\nbad", 443));
    }

    #[test]
    fn allowlist_policy_defers_to_allowlist() {
        let policy =
            ConnectPolicy::Allowlist(Allowlist::from_parts(vec!["example.com".to_string()], 443));
        assert!(policy.permits("example.com", 443));
        assert!(!policy.permits("example.com", 80));
        assert!(!policy.permits("other.example", 443));
    }
}
