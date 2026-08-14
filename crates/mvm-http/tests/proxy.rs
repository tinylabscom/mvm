//! Upstream-proxy transport tests against fake proxies on loopback.
//!
//! The unit tests in `src/proxy.rs` cover configuration and selection. These
//! cover the wire: what actually gets written to a proxy socket, and what a
//! refusal turns into.

use std::sync::Arc;

use mvm_http::{Client, NoProxy, PinnedResolver, Proxy, ProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Read bytes until `needle` is seen, returning everything read.
async fn read_until(sock: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while sock.read(&mut b).await.expect("read") == 1 {
        buf.push(b[0]);
        if buf.ends_with(needle) {
            break;
        }
    }
    buf
}

const OK_BODY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi";

/// An HTTP proxy that records the request line it was given and answers it
/// itself, standing in for the origin.
async fn http_proxy_recording_request_line() -> (u16, tokio::task::JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        let (mut sock, _) = l.accept().await.unwrap();
        let head = read_until(&mut sock, b"\r\n\r\n").await;
        sock.write_all(OK_BODY).await.unwrap();
        sock.flush().await.unwrap();
        String::from_utf8_lossy(&head).to_string()
    });
    (port, h)
}

#[tokio::test]
async fn plaintext_through_an_http_proxy_uses_an_absolute_uri_request_line() {
    let (port, server) = http_proxy_recording_request_line().await;
    let client = Client::builder()
        .proxy(ProxyConfig::all(
            Proxy::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
        ))
        .build()
        .unwrap();

    let resp = client
        .get("http://example.test/a/b?x=1")
        .send()
        .await
        .expect("request through proxy");
    assert_eq!(resp.status().as_u16(), 200);

    let head = server.await.unwrap();
    let line = head.lines().next().unwrap();
    assert_eq!(
        line, "GET http://example.test/a/b?x=1 HTTP/1.1",
        "a proxy learns the destination from the absolute-form request line"
    );
}

#[tokio::test]
async fn a_bypassed_host_ignores_the_proxy_and_dials_direct() {
    // The "proxy" would fail the test if used: it never answers.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();

    let (origin_port, origin) = http_proxy_recording_request_line().await;
    let client = Client::builder()
        .resolver(Arc::new(PinnedResolver::new().with(
            "direct.test",
            vec![format!("127.0.0.1:{origin_port}").parse().unwrap()],
        )))
        .proxy(
            ProxyConfig::all(Proxy::parse(&format!("http://127.0.0.1:{dead_port}")).unwrap())
                .with_no_proxy(NoProxy::parse("direct.test")),
        )
        .build()
        .unwrap();

    let resp = client
        .get("http://direct.test/hello")
        .send()
        .await
        .expect("direct request");
    assert_eq!(resp.status().as_u16(), 200);

    let head = origin.await.unwrap();
    assert!(
        head.starts_with("GET /hello HTTP/1.1"),
        "a direct dial uses origin-form, not absolute-form: {head:?}"
    );
}

#[tokio::test]
async fn a_refused_connect_surfaces_the_proxy_status_not_a_transport_error() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = l.accept().await.unwrap();
        let _ = read_until(&mut sock, b"\r\n\r\n").await;
        sock.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap();
        sock.flush().await.unwrap();
    });

    let client = Client::builder()
        .proxy(ProxyConfig::all(
            Proxy::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
        ))
        .build()
        .unwrap();

    let err = client
        .get("https://example.test/x")
        .send()
        .await
        .expect_err("407 must fail");
    let rendered = err.to_string();
    assert!(
        rendered.contains("407"),
        "the operator needs the proxy's own answer: {rendered}"
    );
    assert!(matches!(err, mvm_http::Error::Proxy { .. }), "{err:?}");
}

#[tokio::test]
async fn connect_carries_credentials_and_the_destination_authority() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = l.accept().await.unwrap();
        let head = read_until(&mut sock, b"\r\n\r\n").await;
        // Refuse after recording; the test only inspects what we were sent.
        sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            .await
            .unwrap();
        sock.flush().await.unwrap();
        String::from_utf8_lossy(&head).to_string()
    });

    let client = Client::builder()
        .proxy(ProxyConfig::all(
            Proxy::parse(&format!("http://user:hunter2@127.0.0.1:{port}")).unwrap(),
        ))
        .build()
        .unwrap();
    let _ = client.get("https://example.test:8443/x").send().await;

    let head = server.await.unwrap();
    assert!(
        head.starts_with("CONNECT example.test:8443 HTTP/1.1"),
        "CONNECT names the destination authority, not the proxy: {head:?}"
    );
    // base64("user:hunter2")
    assert!(
        head.contains("Proxy-Authorization: Basic dXNlcjpodW50ZXIy"),
        "{head:?}"
    );
}

/// A SOCKS5 proxy that completes the handshake, records the requested
/// destination, then answers HTTP itself.
#[tokio::test]
async fn socks5_sends_the_destination_as_a_domain_name() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = l.accept().await.unwrap();
        // Greeting.
        let mut hdr = [0u8; 2];
        sock.read_exact(&mut hdr).await.unwrap();
        let mut methods = vec![0u8; hdr[1] as usize];
        sock.read_exact(&mut methods).await.unwrap();
        sock.write_all(&[0x05, 0x00]).await.unwrap();
        // Request.
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await.unwrap();
        assert_eq!(req[3], 0x03, "must be sent as a domain name");
        let mut len = [0u8; 1];
        sock.read_exact(&mut len).await.unwrap();
        let mut host = vec![0u8; len[0] as usize];
        sock.read_exact(&mut host).await.unwrap();
        let mut p = [0u8; 2];
        sock.read_exact(&mut p).await.unwrap();
        // Success reply with a bound IPv4 address.
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let _ = read_until(&mut sock, b"\r\n\r\n").await;
        sock.write_all(OK_BODY).await.unwrap();
        sock.flush().await.unwrap();
        (
            String::from_utf8_lossy(&host).to_string(),
            u16::from_be_bytes(p),
        )
    });

    let client = Client::builder()
        .proxy(ProxyConfig::all(
            Proxy::parse(&format!("socks5://127.0.0.1:{port}")).unwrap(),
        ))
        .build()
        .unwrap();
    let resp = client
        .get("http://socks.test:8080/z")
        .send()
        .await
        .expect("request through socks5");
    assert_eq!(resp.status().as_u16(), 200);

    let (host, dst_port) = server.await.unwrap();
    assert_eq!(host, "socks.test");
    assert_eq!(dst_port, 8080);
}

#[tokio::test]
async fn a_socks5_connect_failure_is_reported_as_a_proxy_error() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = l.accept().await.unwrap();
        let mut hdr = [0u8; 2];
        sock.read_exact(&mut hdr).await.unwrap();
        let mut methods = vec![0u8; hdr[1] as usize];
        sock.read_exact(&mut methods).await.unwrap();
        sock.write_all(&[0x05, 0x00]).await.unwrap();
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await.unwrap();
        let mut len = [0u8; 1];
        sock.read_exact(&mut len).await.unwrap();
        let mut host = vec![0u8; len[0] as usize];
        sock.read_exact(&mut host).await.unwrap();
        let mut p = [0u8; 2];
        sock.read_exact(&mut p).await.unwrap();
        // 0x02 = connection not allowed by ruleset.
        sock.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        sock.flush().await.unwrap();
    });

    let client = Client::builder()
        .proxy(ProxyConfig::all(
            Proxy::parse(&format!("socks5://127.0.0.1:{port}")).unwrap(),
        ))
        .build()
        .unwrap();
    let err = client
        .get("http://socks.test/z")
        .send()
        .await
        .expect_err("a refused SOCKS5 connect must fail");
    assert!(matches!(err, mvm_http::Error::Proxy { .. }), "{err:?}");
}
