//! End-to-end client tests over real loopback sockets.
//!
//! The server here writes raw bytes rather than using an HTTP library, because
//! the point is to drive the framing decisions — including the malformed and
//! ambiguous cases a well-behaved server would never produce.

use std::net::SocketAddr;
use std::sync::Arc;

use mvm_http::{Client, Error, PinnedResolver, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a server that reads one request and replies with `reply` verbatim.
/// Returns its address and a handle yielding the raw request bytes it saw.
async fn serve_raw(reply: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    serve_raw_then(reply, false).await
}

/// As [`serve_raw`], but optionally drop the connection immediately after
/// writing, without a graceful shutdown.
async fn serve_raw_then(
    reply: &'static [u8],
    abrupt: bool,
) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = Vec::with_capacity(8192);
        loop {
            let mut chunk = [0u8; 1024];
            let n = sock.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            req.extend_from_slice(&chunk[..n]);
            if request_is_complete(&req) || req.len() >= 8192 {
                break;
            }
        }
        sock.write_all(reply).await.ok();
        if !abrupt {
            sock.shutdown().await.ok();
        }
        req
    });
    (addr, handle)
}

fn request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    content_length.is_none_or(|length| request.len() >= body_start + length)
}

fn client_for(addr: SocketAddr) -> Client {
    Client::builder()
        .resolver(Arc::new(
            PinnedResolver::new().with("test.local", vec![addr]),
        ))
        .root_store(rustls::RootCertStore::empty())
        .user_agent("mvm-http-test")
        .build()
        .unwrap()
}

fn url_for(addr: SocketAddr) -> String {
    format!("http://test.local:{}/path", addr.port())
}

#[tokio::test]
async fn fixed_length_body_round_trips() {
    let (addr, srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&resp.bytes().await.unwrap()[..], b"hello");

    let req = String::from_utf8(srv.await.unwrap()).unwrap();
    assert!(req.starts_with("GET /path HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("host: test.local:"), "{req}");
    assert!(req.contains("connection: close\r\n"), "{req}");
}

async fn serve_streamed_request(body_len: usize) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let head_end = loop {
            let mut chunk = [0_u8; 256];
            let n = sock.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed before the request head");
            received.extend_from_slice(&chunk[..n]);
            if let Some(pos) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        while received.len().saturating_sub(head_end) < body_len {
            let mut chunk = [0_u8; 256];
            let n = sock.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed before the declared request body");
            received.extend_from_slice(&chunk[..n]);
        }
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        received
    });
    (addr, handle)
}

#[tokio::test]
async fn request_body_stream_is_bounded_and_preserves_chunk_order() {
    let (addr, server) = serve_streamed_request(11).await;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let producer = tokio::spawn(async move {
        tx.send(b"hello ".to_vec()).await.unwrap();
        tx.send(b"world".to_vec()).await.unwrap();
    });
    let response = client_for(addr)
        .post(url_for(addr))
        .body_stream(11, rx)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    producer.await.unwrap();
    let received = server.await.unwrap();
    let head_end = received.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&received[head_end..], b"hello world");
    assert!(String::from_utf8_lossy(&received[..head_end]).contains("content-length: 11\r\n"));
}

#[tokio::test]
async fn a_short_request_body_stream_fails_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut sink = [0_u8; 1024];
        while socket.read(&mut sink).await.unwrap_or(0) > 0 {}
    });
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(b"short".to_vec()).await.unwrap();
    drop(tx);
    let error = client_for(addr)
        .post(url_for(addr))
        .body_stream(6, rx)
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::IncompleteRequestBody { remaining: 1 }),
        "{error:?}"
    );
}

#[tokio::test]
async fn transformed_request_body_uses_bounded_chunked_framing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        loop {
            let mut chunk = [0_u8; 256];
            let n = socket.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed before the terminating chunk");
            received.extend_from_slice(&chunk[..n]);
            if received.windows(5).any(|window| window == b"0\r\n\r\n") {
                break;
            }
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        received
    });

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let producer = tokio::spawn(async move {
        tx.send(b"hello ".to_vec()).await.unwrap();
        tx.send(b"world".to_vec()).await.unwrap();
    });
    let response = client_for(addr)
        .post(url_for(addr))
        .body_chunked(rx)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    producer.await.unwrap();
    let received = server.await.unwrap();
    let head_end = received.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8_lossy(&received[..head_end]);
    assert!(head.contains("transfer-encoding: chunked\r\n"), "{head}");
    assert_eq!(
        &received[head_end..],
        b"6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n"
    );
}

#[tokio::test]
async fn a_failed_transform_closes_without_completing_the_chunked_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        socket.read_to_end(&mut received).await.unwrap();
        received
    });
    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tx.send(Ok(b"partial".to_vec())).await.unwrap();
    tx.send(Err("transform failed closed".into()))
        .await
        .unwrap();
    drop(tx);
    let error = client_for(addr)
        .post(url_for(addr))
        .body_checked_chunked(rx)
        .send()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::RequestBodyProducer(_)), "{error:?}");
    let received = server.await.unwrap();
    assert!(!received.ends_with(b"0\r\n\r\n"));
}

#[tokio::test]
async fn chunked_body_is_decoded_across_chunks() {
    let (addr, _srv) = serve_raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          5\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\n\r\n",
    )
    .await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(&resp.bytes().await.unwrap()[..], b"hello world");
}

#[tokio::test]
async fn chunked_trailers_are_consumed() {
    let (addr, _srv) = serve_raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          3\r\nabc\r\n0\r\nX-Check: sum\r\n\r\n",
    )
    .await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(&resp.bytes().await.unwrap()[..], b"abc");
}

#[tokio::test]
async fn body_without_framing_headers_reads_until_close() {
    let (addr, _srv) = serve_raw(b"HTTP/1.1 200 OK\r\n\r\nstreamed-to-eof").await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(&resp.bytes().await.unwrap()[..], b"streamed-to-eof");
}

#[tokio::test]
async fn a_truncated_fixed_body_is_an_error_not_a_short_read() {
    // The server promises 100 bytes and delivers 5, then closes. Returning the
    // short body would hand the caller a silently truncated artifact.
    let (addr, _srv) =
        serve_raw_then(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello", true).await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    let err = resp.bytes().await.unwrap_err();
    assert!(
        matches!(err, Error::IncompleteBody { .. }),
        "expected IncompleteBody, got {err:?}"
    );
}

#[tokio::test]
async fn content_length_plus_transfer_encoding_is_refused() {
    let (addr, _srv) = serve_raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
    )
    .await;
    let c = client_for(addr);
    let err = c.get(url_for(addr)).send().await.unwrap_err();
    assert!(matches!(err, Error::Parse(_)), "{err:?}");
}

#[tokio::test]
async fn the_body_cap_is_enforced_by_the_reader() {
    let (addr, _srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world").await;
    let c = client_for(addr);
    let resp = c
        .get(url_for(addr))
        .max_response_bytes(4)
        .send()
        .await
        .unwrap();
    let err = resp.bytes().await.unwrap_err();
    assert!(
        matches!(err, Error::BodyTooLarge { limit: 4 }),
        "expected BodyTooLarge, got {err:?}"
    );
}

#[tokio::test]
async fn a_body_exactly_at_the_cap_is_returned() {
    let (addr, _srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
    let c = client_for(addr);
    let resp = c
        .get(url_for(addr))
        .max_response_bytes(5)
        .send()
        .await
        .unwrap();
    assert_eq!(&resp.bytes().await.unwrap()[..], b"hello");
}

#[tokio::test]
async fn the_cap_applies_to_a_chunked_body_too() {
    // A chunked body has no declared length, so the cap is the only bound.
    let (addr, _srv) = serve_raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
    )
    .await;
    let c = client_for(addr);
    let resp = c
        .get(url_for(addr))
        .max_response_bytes(6)
        .send()
        .await
        .unwrap();
    assert!(matches!(
        resp.bytes().await.unwrap_err(),
        Error::BodyTooLarge { limit: 6 }
    ));
}

#[tokio::test]
async fn a_redirect_is_returned_not_followed() {
    // The whole point of having no redirect policy: a 302 surfaces as a 302.
    let (addr, _srv) = serve_raw(
        b"HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "http://evil.example/"
    );
}

#[tokio::test]
async fn a_head_response_does_not_wait_for_a_body() {
    // Content-Length on a HEAD describes the body that *would* have been sent.
    // Reading it would block until the server closed.
    let (addr, _srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n").await;
    let c = client_for(addr);
    let resp = c.head(url_for(addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_204_carries_no_body() {
    let (addr, _srv) = serve_raw(b"HTTP/1.1 204 No Content\r\n\r\n").await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(resp.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn request_body_and_headers_reach_the_server() {
    let (addr, srv) = serve_streamed_request(9).await;
    let c = client_for(addr);
    let resp = c
        .post(url_for(addr))
        .bearer_auth("s3cret")
        .json(&serde_json::json!({"k": "v"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = String::from_utf8(srv.await.unwrap()).unwrap();
    assert!(req.starts_with("POST /path HTTP/1.1\r\n"), "{req}");
    assert!(req.contains("authorization: Bearer s3cret\r\n"), "{req}");
    assert!(req.contains("content-type: application/json\r\n"), "{req}");
    assert!(req.contains("content-length: 9\r\n"), "{req}");
    assert!(req.ends_with(r#"{"k":"v"}"#), "{req}");
}

#[tokio::test]
async fn basic_auth_is_base64_encoded() {
    let (addr, srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let c = client_for(addr);
    c.get(url_for(addr))
        .basic_auth("user", Some("pass"))
        .send()
        .await
        .unwrap();
    let req = String::from_utf8(srv.await.unwrap()).unwrap();
    // base64("user:pass")
    assert!(
        req.contains("authorization: Basic dXNlcjpwYXNz\r\n"),
        "{req}"
    );
}

#[tokio::test]
async fn query_pairs_are_appended_and_encoded() {
    let (addr, srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let c = client_for(addr);
    c.get(url_for(addr))
        .query(&[("q", "a b&c"), ("n", "1")])
        .send()
        .await
        .unwrap();
    let req = String::from_utf8(srv.await.unwrap()).unwrap();
    assert!(
        req.starts_with("GET /path?q=a+b%26c&n=1 HTTP/1.1\r\n"),
        "{req}"
    );
}

#[tokio::test]
async fn streaming_chunks_arrive_incrementally() {
    let (addr, _srv) = serve_raw(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
          3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n",
    )
    .await;
    let c = client_for(addr);
    let mut resp = c.get(url_for(addr)).send().await.unwrap();
    let mut seen = Vec::new();
    while let Some(chunk) = resp.chunk().await.unwrap() {
        seen.push(String::from_utf8(chunk.to_vec()).unwrap());
    }
    assert_eq!(seen, vec!["foo".to_string(), "bar".to_string()]);
}

#[tokio::test]
async fn a_garbage_response_head_is_refused() {
    let (addr, _srv) = serve_raw(b"NOT-HTTP AT ALL\r\n\r\n").await;
    let c = client_for(addr);
    let err = c.get(url_for(addr)).send().await.unwrap_err();
    assert!(matches!(err, Error::Parse(_)), "{err:?}");
}

#[tokio::test]
async fn a_connection_closed_before_the_head_is_refused() {
    let (addr, _srv) = serve_raw_then(b"HTTP/1.1 200 OK\r\nContent-Len", true).await;
    let c = client_for(addr);
    let err = c.get(url_for(addr)).send().await.unwrap_err();
    assert!(matches!(err, Error::Parse(_)), "{err:?}");
}

#[tokio::test]
async fn a_timeout_fires_when_the_server_never_answers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Hold the connection open and never reply.
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        drop(sock);
    });
    let c = client_for(addr);
    let err = c
        .get(url_for(addr))
        .timeout(std::time::Duration::from_millis(150))
        .send()
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout(_)), "{err:?}");
}

#[tokio::test]
async fn text_and_json_decode_the_body() {
    let (addr, _srv) =
        serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n{\"name\":\"mvm\"}").await;
    let c = client_for(addr);
    #[derive(serde::Deserialize)]
    struct Body {
        name: String,
    }
    let body: Body = c
        .get(url_for(addr))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body.name, "mvm");
}

// `content_length()` is what a caller checks to refuse an oversized body
// *before* reading it (mvm-fs's manifest fetch does exactly this), so these
// pin the declaration rather than a running total.

#[tokio::test]
async fn content_length_reports_the_declaration_and_does_not_move_as_the_body_is_read() {
    let (addr, _srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world").await;
    let c = client_for(addr);
    let mut resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(resp.content_length(), Some(11));
    let _ = resp.chunk().await.unwrap();
    assert_eq!(
        resp.content_length(),
        Some(11),
        "the declaration must not change as bytes are consumed"
    );
}

#[tokio::test]
async fn a_declared_zero_length_is_zero_not_absent() {
    // Inferring from body state reported `None` here, which a cap check reads
    // as "no declaration" rather than "declared empty".
    let (addr, _srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(resp.content_length(), Some(0));
}

#[tokio::test]
async fn a_head_response_still_reports_its_declared_length() {
    // The body is absent by design, but the length is the whole point of HEAD
    // and is what a size pre-check consumes.
    let (addr, _srv) = serve_raw(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n").await;
    let c = client_for(addr);
    let resp = c.head(url_for(addr)).send().await.unwrap();
    assert_eq!(resp.content_length(), Some(4096));
    assert!(resp.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_chunked_body_declares_no_length() {
    let (addr, _srv) =
        serve_raw(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
            .await;
    let c = client_for(addr);
    let resp = c.get(url_for(addr)).send().await.unwrap();
    assert_eq!(
        resp.content_length(),
        None,
        "a chunked body declares no length, so a pre-read cap check cannot rely on one"
    );
}

// ---- blocking face ----
//
// Driven over real sockets like the async tests. `serve_raw` needs a runtime to
// bind its listener, so each test hands the address to a blocking call made
// from a plain thread — which is the shape the CLI callers have.

fn blocking_client_for(addr: SocketAddr) -> mvm_http::blocking::Client {
    mvm_http::blocking::Client::builder()
        .resolver(Arc::new(
            PinnedResolver::new().with("test.local", vec![addr]),
        ))
        .root_store(rustls::RootCertStore::empty())
        .user_agent("mvm-http-blocking-test")
        .build()
        .unwrap()
}

/// Bind + serve on a dedicated runtime thread, returning the address.
fn serve_raw_blocking(reply: &'static [u8]) -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let (addr, srv) = serve_raw(reply).await;
            tx.send(addr).unwrap();
            let _ = srv.await;
        });
    });
    rx.recv().unwrap()
}

#[test]
fn blocking_get_returns_the_body() {
    let addr = serve_raw_blocking(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    let c = blocking_client_for(addr);
    let resp = c.get(url_for(addr)).send().unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().unwrap(), "hello");
}

#[test]
fn blocking_error_for_status_refuses_a_404() {
    let addr = serve_raw_blocking(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    let c = blocking_client_for(addr);
    let err = c
        .get(url_for(addr))
        .send()
        .unwrap()
        .error_for_status()
        .unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
}

#[test]
fn blocking_decodes_a_chunked_body() {
    let addr = serve_raw_blocking(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n",
    );
    let c = blocking_client_for(addr);
    assert_eq!(
        c.get(url_for(addr)).send().unwrap().text().unwrap(),
        "foobar"
    );
}

#[test]
fn blocking_honours_the_body_cap() {
    // The body streams, so the cap is enforced as it is read rather than at
    // `send` — the same shape as the async face. `send` returning Ok is the
    // head having arrived, not the body having been accepted.
    let addr = serve_raw_blocking(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world");
    let c = blocking_client_for(addr);
    let err = c
        .get(url_for(addr))
        .max_response_bytes(4)
        .send()
        .expect("head arrives")
        .bytes()
        .unwrap_err();
    assert!(matches!(err, Error::BodyTooLarge { limit: 4 }), "{err:?}");
}

#[test]
fn blocking_response_streams_through_io_read() {
    // `http_forward`'s Linux relay hands the guest an upstream response
    // incrementally via `io::Read`; buffering would delay an SSE or long-poll
    // body until completion.
    use std::io::Read as _;
    let addr = serve_raw_blocking(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n",
    );
    let c = blocking_client_for(addr);
    let mut resp = c.get(url_for(addr)).send().unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 2];
    loop {
        let n = resp.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    assert_eq!(out, b"foobar");
}

#[test]
fn blocking_io_copy_drains_the_whole_body() {
    // The other shape the relay uses, when it is not re-chunking.
    let addr = serve_raw_blocking(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world");
    let c = blocking_client_for(addr);
    let mut resp = c.get(url_for(addr)).send().unwrap();
    let mut out: Vec<u8> = Vec::new();
    std::io::copy(&mut resp, &mut out).unwrap();
    assert_eq!(out, b"hello world");
}

#[test]
fn blocking_parses_json() {
    let addr =
        serve_raw_blocking(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\n{\"name\":\"mvm\"}");
    let c = blocking_client_for(addr);
    let v: serde_json::Value = c.get(url_for(addr)).send().unwrap().json().unwrap();
    assert_eq!(v["name"], "mvm");
}
