//! Live-listener tests for `http_hardening::read_capped`.
//!
//! These exist as an integration test (not an inline `#[cfg(test)]`
//! module under `src/tools/http_hardening.rs`) so the architecture.yml
//! invariant scan — which forbids `TcpListener::bind` in production
//! source files — stays clean. The unit-of-test is `read_capped`'s
//! chunk-loop accumulator: it must enforce the `max_bytes` cap
//! *before* a chunk that would overflow lands in the accumulator.
//!
//! The fixtures use a plain `reqwest::Client` (no hardening). The
//! resolver and TLS pin are not part of `read_capped`'s contract —
//! that responsibility lives in `hardened_client_builder`, exercised
//! by the inline unit tests in `http_hardening.rs`.

use std::time::Duration;

use mvm_hostd::supervisor::tools::http_hardening::read_capped;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

async fn fetch_from_test_server(
    response_body: String,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let port = spawn_one_shot_server(response_body).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let response = client
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    read_capped(response, max_bytes).await
}

#[tokio::test]
async fn read_capped_returns_full_body_when_under_cap() {
    let payload = "hello world";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    let body = fetch_from_test_server(response, 1024).await.unwrap();
    assert_eq!(body, payload.as_bytes());
}

#[tokio::test]
async fn read_capped_refuses_oversize_response() {
    let payload = "A".repeat(40);
    let response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: 40\r\nConnection: close\r\n\r\n{payload}");
    let err = fetch_from_test_server(response, 16).await.unwrap_err();
    assert!(err.contains("exceeded max_bytes"), "{err}");
    assert!(err.contains("16"), "{err}");
}

#[tokio::test]
async fn read_capped_succeeds_at_exact_boundary() {
    let payload = "B".repeat(16);
    let response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{payload}");
    let body = fetch_from_test_server(response, 16).await.unwrap();
    assert_eq!(body.len(), 16);
}
