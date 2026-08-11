//! Differential test: one corpus, both clients.
//!
//! This is the evidence for replacing `reqwest` on the OCI, egress
//! re-origination, and SSRF-guarded fetch paths. Each case is served as raw
//! bytes to *both* clients and their observable results compared.
//!
//! The contract is deliberately two-sided:
//!
//! - **Well-formed responses must agree exactly** — status, content type, and
//!   body bytes. A divergence here is a migration bug.
//! - **Ambiguous responses must be refused by `mvm-http`.** Resolving a framing
//!   ambiguity rather than refusing it is what lets two hops disagree, which is
//!   request smuggling.
//!
//! Measured against reqwest 0.13, the refusals split into two groups:
//!
//! | case | reqwest | mvm-http |
//! |---|---|---|
//! | `0x`-prefixed chunk size | refuses | refuses |
//! | `+`-prefixed Content-Length | refuses | refuses |
//! | disagreeing duplicate Content-Length | refuses | refuses |
//! | **Content-Length + Transfer-Encoding** | **accepts**, prefers TE | refuses |
//! | **`Transfer-Encoding: gzip, chunked`** | **accepts** | refuses |
//!
//! So there are exactly two behavioural divergences, and in both the migration
//! is strictly more conservative. The first is the textbook smuggling
//! primitive. The second is a body this client cannot frame single-valuedly,
//! and guessing at it on the egress path is not worth the compatibility.

use std::net::SocketAddr;
use std::sync::Arc;

use mvm_http::PinnedResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve `reply` verbatim to exactly `n` sequential connections.
async fn serve_n(reply: &'static [u8], n: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..n {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut scratch = vec![0u8; 8192];
            let _ = sock.read(&mut scratch).await;
            let _ = sock.write_all(reply).await;
            let _ = sock.shutdown().await;
        }
    });
    addr
}

/// What a client observed, reduced to the parts callers act on.
#[derive(Debug, PartialEq, Eq)]
enum Observed {
    Ok {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    },
    Refused,
}

async fn via_mvm_http(addr: SocketAddr, cap: Option<u64>) -> Observed {
    let client = mvm_http::Client::builder()
        .resolver(Arc::new(PinnedResolver::new().with("t.local", vec![addr])))
        .root_store(rustls::RootCertStore::empty())
        .build()
        .unwrap();
    let mut req = client.get(format!("http://t.local:{}/x", addr.port()));
    if let Some(c) = cap {
        req = req.max_response_bytes(c);
    }
    match req.send().await {
        Err(_) => Observed::Refused,
        Ok(resp) => {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            match resp.bytes().await {
                Ok(b) => Observed::Ok {
                    status,
                    content_type,
                    body: b.to_vec(),
                },
                Err(_) => Observed::Refused,
            }
        }
    }
}

/// reqwest is built with `rustls-no-provider`, so the process default has to
/// be installed before its first client. mvm-http passes its provider
/// explicitly and needs none of this.
fn install_provider_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn via_reqwest(addr: SocketAddr, cap: Option<u64>) -> Observed {
    install_provider_once();
    // Configured the way every caller in this workspace configured it: no
    // redirect following, and the address pinned so the comparison is of HTTP
    // behaviour rather than of DNS.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve("t.local", addr)
        .build()
        .unwrap();
    let resp = match client
        .get(format!("http://t.local:{}/x", addr.port()))
        .send()
        .await
    {
        Err(_) => return Observed::Refused,
        Ok(r) => r,
    };
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    // Mirror mvm-http's cap semantics: refuse once the accumulated body would
    // exceed it, before the chunk lands.
    let mut resp = resp;
    let mut body: Vec<u8> = Vec::new();
    loop {
        match resp.chunk().await {
            Err(_) => return Observed::Refused,
            Ok(None) => break,
            Ok(Some(chunk)) => {
                if let Some(c) = cap
                    && body.len() as u64 + chunk.len() as u64 > c
                {
                    return Observed::Refused;
                }
                body.extend_from_slice(&chunk);
            }
        }
    }
    Observed::Ok {
        status,
        content_type,
        body,
    }
}

/// Both clients see the same thing.
async fn assert_agrees(label: &str, reply: &'static [u8], cap: Option<u64>) {
    let addr = serve_n(reply, 2).await;
    let mine = via_mvm_http(addr, cap).await;
    let theirs = via_reqwest(addr, cap).await;
    assert_eq!(mine, theirs, "{label}: clients disagreed");
}

/// `mvm-http` refuses; what reqwest does is recorded but not asserted equal.
async fn assert_mvm_http_refuses(label: &str, reply: &'static [u8]) {
    let addr = serve_n(reply, 2).await;
    let mine = via_mvm_http(addr, None).await;
    assert_eq!(mine, Observed::Refused, "{label}: mvm-http must refuse");
    // Recorded for the reader: this is the behaviour being deliberately left.
    let theirs = via_reqwest(addr, None).await;
    eprintln!("{label}: mvm-http=Refused reqwest={theirs:?}");
}

// ---- well-formed: must agree exactly ----

#[tokio::test]
async fn agrees_on_a_fixed_length_body() {
    assert_agrees(
        "fixed",
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_a_chunked_body() {
    assert_agrees(
        "chunked",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n\
          5\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\n\r\n",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_chunked_with_trailers() {
    assert_agrees(
        "chunked+trailers",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\n\r\n",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_chunk_extensions() {
    assert_agrees(
        "chunk-extension",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;a=b\r\nhello\r\n0\r\n\r\n",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_204_and_304() {
    assert_agrees("204", b"HTTP/1.1 204 No Content\r\n\r\n", None).await;
    assert_agrees("304", b"HTTP/1.1 304 Not Modified\r\n\r\n", None).await;
}

#[tokio::test]
async fn agrees_on_a_redirect_being_returned_not_followed() {
    assert_agrees(
        "302",
        b"HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\nContent-Length: 0\r\n\r\n",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_error_statuses() {
    assert_agrees(
        "404",
        b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nnot found",
        None,
    )
    .await;
    assert_agrees(
        "500",
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nerr",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_an_empty_body() {
    assert_agrees(
        "empty",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_a_body_that_runs_to_connection_close() {
    assert_agrees("until-close", b"HTTP/1.1 200 OK\r\n\r\nstreamed", None).await;
}

#[tokio::test]
async fn agrees_on_the_body_cap_boundary() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
    assert_agrees("cap-under", reply, Some(11)).await;
    assert_agrees("cap-over", reply, Some(4)).await;
}

#[tokio::test]
async fn agrees_on_a_truncated_body_being_an_error() {
    assert_agrees(
        "truncated",
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello",
        None,
    )
    .await;
}

#[tokio::test]
async fn agrees_on_a_garbage_head_being_an_error() {
    assert_agrees("garbage", b"NOT HTTP AT ALL\r\n\r\n", None).await;
}

// ---- ambiguous framing: mvm-http refuses by design ----
//
// Each of these is a documented HTTP/1.1 request-smuggling primitive. reqwest
// resolves them by precedence rather than refusing; this client fails closed,
// because a resolution two hops can disagree about is the vulnerability.

#[tokio::test]
async fn refuses_content_length_together_with_transfer_encoding() {
    assert_mvm_http_refuses(
        "CL+TE",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n\
          5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn refuses_disagreeing_duplicate_content_lengths() {
    assert_mvm_http_refuses(
        "CL-CL",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 11\r\n\r\nhello world",
    )
    .await;
}

#[tokio::test]
async fn refuses_a_non_decimal_content_length() {
    assert_mvm_http_refuses(
        "CL-plus",
        b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello",
    )
    .await;
}

#[tokio::test]
async fn refuses_a_hex_prefixed_chunk_size() {
    assert_mvm_http_refuses(
        "chunk-0x",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
}

#[tokio::test]
async fn refuses_a_transfer_encoding_it_cannot_frame() {
    assert_mvm_http_refuses(
        "TE-gzip-chunked",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
}
