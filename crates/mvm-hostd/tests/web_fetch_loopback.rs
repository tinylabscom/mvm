//! Typed-connector tests for `mvm.web_fetch`.
//!
//! The fetcher has no external socket implementation. These fixtures emulate
//! the endpoint's bounded UDS response and prove redirects remain visible and
//! the tool's own tighter body ceiling still applies.

use base64::Engine as _;
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use mvm_hostd::framing::{read_json_frame, write_json_frame};
use mvm_hostd::supervisor::tools::web_fetch::{FetchError, HardenedHttpFetcher, HttpFetcher};
use url::Url;

const MAX_FRAME: usize = 16 * 1024 * 1024;

async fn spawn_endpoint_response(
    response: WireResponse,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("endpoint.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _: WireRequest = read_json_frame(&mut stream, MAX_FRAME).await.unwrap();
        write_json_frame(&mut stream, &response).await.unwrap();
    });
    (dir, path)
}

fn ok(status: u16, body: &[u8]) -> WireResponse {
    WireResponse::Ok {
        status,
        headers: Vec::new(),
        body_b64: base64::engine::general_purpose::STANDARD.encode(body),
    }
}

#[tokio::test]
async fn the_fetcher_does_not_auto_follow_redirects() {
    let (_dir, path) = spawn_endpoint_response(WireResponse::Ok {
        status: 302,
        headers: vec![("location".into(), "https://evil.example/exfil".into())],
        body_b64: String::new(),
    })
    .await;
    let fetcher = HardenedHttpFetcher::new(path);
    let response = fetcher
        .fetch(&Url::parse("https://allowed.example/").unwrap(), 1024)
        .await
        .unwrap();
    assert_eq!(response.status, 302);
    assert!(response.body.is_empty());
}

#[tokio::test]
async fn body_cap_is_enforced_exactly() {
    let (_dir, path) = spawn_endpoint_response(ok(200, &[b'A'; 40])).await;
    let fetcher = HardenedHttpFetcher::new(path);
    let error = fetcher
        .fetch(&Url::parse("https://allowed.example/").unwrap(), 8)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::BodyTooLarge { limit: 8 }));
}

#[tokio::test]
async fn body_at_exactly_max_bytes_succeeds() {
    let payload = [b'B'; 16];
    let (_dir, path) = spawn_endpoint_response(ok(200, &payload)).await;
    let fetcher = HardenedHttpFetcher::new(path);
    let response = fetcher
        .fetch(&Url::parse("https://allowed.example/").unwrap(), 16)
        .await
        .unwrap();
    assert_eq!(response.body, payload);
}
