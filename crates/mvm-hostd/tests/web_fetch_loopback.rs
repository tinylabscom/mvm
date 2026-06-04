//! Live-listener tests for `mvm.web_fetch`'s plan-65 hardening.
//!
//! These exist as an integration test (not an inline `#[cfg(test)]`
//! module under `src/tools/web_fetch.rs`) so the architecture.yml
//! invariant scan — which forbids `TcpListener::bind` in production
//! source files — stays clean. The hardening contracts under test:
//!
//! - **W1 — no auto-redirect**: a 302 response surfaces as `status=302`
//!   with an empty body; the redirect target is not followed.
//! - **W3 — exact body cap**: an upstream that wants to send more bytes
//!   than `max_bytes` errors out with [`FetchError::BodyTooLarge`].
//! - **W3 boundary**: a response of exactly `max_bytes` succeeds.
//!
//! All three tests use [`ReqwestHttpFetcher::test_unsafe_no_ssrf`] to
//! bypass the W2 SSRF guard so the loopback fixture is reachable. The
//! seam is marked `#[doc(hidden)]` and named loudly because it MUST NOT
//! appear in production callers.

use mvm_hostd::supervisor::tools::web_fetch::{FetchError, HttpFetcher, ReqwestHttpFetcher};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

/// Bind a TCP listener on 127.0.0.1:0, accept one connection, drain
/// its request, write `response`, then close. Returns the port the
/// listener bound to.
async fn spawn_one_shot_server(response: String) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    port
}

#[tokio::test]
async fn reqwest_does_not_auto_follow_redirects() {
    let response = "HTTP/1.1 302 Found\r\n\
        Location: http://evil.example/exfil\r\n\
        Content-Length: 0\r\n\
        Connection: close\r\n\
        \r\n"
        .to_string();
    let port = spawn_one_shot_server(response).await;
    let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let fetcher = ReqwestHttpFetcher::test_unsafe_no_ssrf(30);
    let resp = HttpFetcher::fetch(&fetcher, &url, 1024)
        .await
        .expect("fetch");
    assert_eq!(
        resp.status, 302,
        "redirect was auto-followed; the W1 hardening regressed"
    );
    assert!(
        resp.body.is_empty(),
        "redirect target's body leaked into the response"
    );
}

#[tokio::test]
async fn body_cap_is_enforced_exactly() {
    let payload = "A".repeat(40);
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Length: 40\r\n\
        Connection: close\r\n\
        \r\n\
        {payload}"
    );
    let port = spawn_one_shot_server(response).await;
    let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let fetcher = ReqwestHttpFetcher::test_unsafe_no_ssrf(30);
    let err = HttpFetcher::fetch(&fetcher, &url, 8).await.unwrap_err();
    assert!(
        matches!(err, FetchError::BodyTooLarge { limit: 8 }),
        "expected BodyTooLarge {{ limit: 8 }}, got {err:?}"
    );
}

#[tokio::test]
async fn body_at_exactly_max_bytes_succeeds() {
    let payload = "B".repeat(16);
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Length: 16\r\n\
        Connection: close\r\n\
        \r\n\
        {payload}"
    );
    let port = spawn_one_shot_server(response).await;
    let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let fetcher = ReqwestHttpFetcher::test_unsafe_no_ssrf(30);
    let resp = HttpFetcher::fetch(&fetcher, &url, 16)
        .await
        .expect("at-cap fetch");
    assert_eq!(resp.body.len(), 16);
    assert_eq!(resp.body, payload.as_bytes());
}
