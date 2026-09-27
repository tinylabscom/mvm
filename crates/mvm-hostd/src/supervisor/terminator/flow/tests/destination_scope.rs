//! Where a placeholder is good for, and what a terminated flow does when the
//! destination cannot be verified.
//!
//! Each binding mints its own placeholder, valid only for the destinations
//! that binding names. A placeholder presented anywhere else — another bound
//! destination, the request URL, the request body — is refused before the
//! forward leg runs and the refusal is on the chain. The forward leg itself
//! re-originates TLS with ordinary certificate verification, and a destination
//! that fails it gets nothing: there is no fallback to relaying the guest's
//! own bytes.

use std::net::{SocketAddr, TcpListener};

use super::*;
use crate::supervisor::network_endpoint_proxy::{HardenedForwarder, TestTransport};

/// The second secret, bound to [`OTHER_HOST`].
const SECOND_SECRET: &str = "ci-token";

fn recording() -> Arc<RecordingForwarder> {
    Arc::new(RecordingForwarder {
        seen: Mutex::new(None),
        body: b"{\"ok\":true}".to_vec(),
        fail_after_send: std::sync::atomic::AtomicBool::new(false),
    })
}

/// Two secrets, each bound to its own destination, both destinations admitted.
fn two_bindings(forwarder: Arc<dyn Forwarder>) -> Assembled {
    assemble(
        &[
            Bound {
                secret: "model-api",
                pattern: BOUND_HOST,
            },
            Bound {
                secret: SECOND_SECRET,
                pattern: OTHER_HOST,
            },
        ],
        &[BOUND_HOST, OTHER_HOST],
        forwarder,
    )
}

fn forwarded(forwarder: &RecordingForwarder) -> Option<PreparedRequest> {
    forwarder
        .seen
        .lock()
        .expect("forwarder record lock")
        .clone()
}

fn authorization(request: &PreparedRequest) -> Option<&str> {
    request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str())
}

/// Exchange one request over a TLS flow opened to `host:443`.
fn over_flow_to(vm: &Assembled, host: &str, request: &[u8]) -> Vec<u8> {
    exchange_with(vm, host, &vm.intermediate_pem, request)
        .expect("the guest's tls client completes its handshake")
}

#[test]
fn each_destination_receives_only_its_own_credential() {
    let forwarder = recording();
    let vm = two_bindings(forwarder.clone());

    let response = over_flow_to(
        &vm,
        OTHER_HOST,
        &request_with_placeholder(&vm.placeholders[1], OTHER_HOST),
    );
    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let seen = forwarded(&forwarder).expect("the forward leg ran");
    assert_eq!(
        authorization(&seen),
        Some(format!("Bearer {REAL_SECRET}-{SECOND_SECRET}").as_str()),
        "the destination receives the credential bound to it, and no other"
    );
}

#[test]
fn a_placeholder_presented_to_another_bound_destination_is_refused_and_audited() {
    let forwarder = recording();
    let vm = two_bindings(forwarder.clone());

    // The first secret's placeholder, on a flow to the second secret's
    // destination. Both destinations are terminated and admitted by policy, so
    // only the placeholder's own scope can refuse this.
    let response = over_flow_to(
        &vm,
        OTHER_HOST,
        &request_with_placeholder(&vm.placeholders[0], OTHER_HOST),
    );
    assert!(
        status_line(&response).starts_with("HTTP/1.1 502"),
        "a placeholder is valid only where its binding says: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        forwarded(&forwarder).is_none(),
        "nothing reaches the forward leg"
    );
    let text = String::from_utf8_lossy(&response);
    assert!(
        !text.contains(REAL_SECRET),
        "a refusal carries no credential"
    );

    let chain = vm.audit_chain();
    assert!(chain.contains("secret.placeholder_dropped"), "{chain}");
    assert!(chain.contains(OTHER_HOST), "{chain}");
    assert!(
        !chain.contains("secret.substituted"),
        "no credential was handed off: {chain}"
    );
    assert!(!chain.contains(&vm.placeholders[0]), "{chain}");
    assert!(!chain.contains(REAL_SECRET), "{chain}");
}

#[test]
fn a_placeholder_in_the_url_of_a_terminated_request_is_refused_and_audited() {
    let harness = harness(BOUND_HOST, b"never sent");
    let request = format!(
        "GET /v1/models?key={} HTTP/1.1\r\nhost: {BOUND_HOST}\r\n\r\n",
        harness.placeholder
    );
    let response = exchange(&harness, request.as_bytes());

    assert!(
        status_line(&response).starts_with("HTTP/1.1 502"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(forwarded(&harness.forwarder).is_none());
    let chain = harness.audit_chain();
    assert!(chain.contains("secret.flow_refused"), "{chain}");
    assert!(chain.contains("placeholder_in_url"), "{chain}");
    assert!(!chain.contains(&harness.placeholder), "{chain}");
}

#[test]
fn a_placeholder_in_the_body_of_a_terminated_request_is_refused_before_forwarding() {
    let harness = harness(BOUND_HOST, b"never sent");
    // The header carries the placeholder too: the refusal has to land before
    // a forward leg that would already hold the substituted header exists.
    let body = format!("{{\"key\":\"{}\"}}", harness.placeholder);
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {BOUND_HOST}\r\nauthorization: Bearer {}\r\ncontent-length: {}\r\n\r\n{body}",
        harness.placeholder,
        body.len()
    );
    let response = exchange(&harness, request.as_bytes());

    assert!(
        status_line(&response).starts_with("HTTP/1.1 502"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        forwarded(&harness.forwarder).is_none(),
        "the forward leg never started"
    );
    let chain = harness.audit_chain();
    assert!(chain.contains("placeholder_in_body"), "{chain}");
    assert!(
        !chain.contains("secret.substituted"),
        "no credential was handed off: {chain}"
    );
    assert!(!chain.contains(&harness.placeholder), "{chain}");
}

/// A real TLS server behind [`BOUND_HOST`]: it presents a leaf chained to
/// `issuer`, records the plaintext of whatever request it is sent, and answers
/// one request.
struct Upstream {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    served: std::thread::JoinHandle<()>,
}

fn upstream(issuer: &VmEgressCa) -> Upstream {
    let config = Arc::new(
        crate::supervisor::terminator::tls::server_config_for_sni(issuer, BOUND_HOST)
            .expect("upstream server config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the upstream");
    let addr = listener.local_addr().expect("upstream address");
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&received);
    let served = std::thread::spawn(move || {
        let Some(socket) = accept_within(&listener, Duration::from_secs(15)) else {
            return;
        };
        let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
        let Ok(connection) = rustls::ServerConnection::new(config) else {
            return;
        };
        let mut tls = rustls::StreamOwned::new(connection, socket);
        let mut chunk = [0u8; 4096];
        loop {
            match tls.read(&mut chunk) {
                // A handshake the client rejected ends here with an error,
                // before a single byte of request was decrypted.
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let mut seen = sink.lock().expect("upstream record lock");
                    seen.extend_from_slice(&chunk[..n]);
                    if request_complete(&seen) {
                        break;
                    }
                }
            }
        }
        let _ = tls.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 11\r\n\r\n{\"ok\":true}",
        );
        let _ = tls.flush();
        tls.conn.send_close_notify();
        let _ = tls.flush();
    });
    Upstream {
        addr,
        received,
        served,
    }
}

/// Accept one connection, or give up after `limit` so a forward leg that
/// never dials cannot hang the test.
fn accept_within(listener: &TcpListener, limit: Duration) -> Option<std::net::TcpStream> {
    listener.set_nonblocking(true).ok()?;
    let deadline = std::time::Instant::now() + limit;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).ok()?;
                return Some(socket);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}

/// Whether `seen` holds one whole HTTP/1.1 request, by its own framing.
fn request_complete(seen: &[u8]) -> bool {
    let Some(end) = super::super::super::find_subslice(seen, b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    if head.contains("transfer-encoding: chunked") {
        return seen.ends_with(b"0\r\n\r\n");
    }
    let declared = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim() == "content-length")
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    seen.len() >= end + 4 + declared
}

/// A forward leg over the production client, resolving [`BOUND_HOST`] to
/// `upstream` and verifying it against `anchor` alone.
fn verifying_forwarder(upstream: &Upstream, anchor: &VmEgressCa) -> Arc<dyn Forwarder> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(anchor.cert_pem().as_bytes()) {
        roots
            .add(cert.expect("anchor pem parses"))
            .expect("anchor is a usable trust anchor");
    }
    let resolver = mvm_http::PinnedResolver::new().with(BOUND_HOST, vec![upstream.addr]);
    Arc::new(
        HardenedForwarder::new(10)
            .expect("forwarder")
            .with_test_transport(TestTransport {
                resolver: Arc::new(resolver),
                roots,
            }),
    )
}

fn single_binding(forwarder: Arc<dyn Forwarder>) -> Assembled {
    assemble(
        &[Bound {
            secret: "model-api",
            pattern: BOUND_HOST,
        }],
        &[BOUND_HOST],
        forwarder,
    )
}

#[test]
fn the_forward_leg_verifies_the_destination_and_carries_the_real_credential() {
    let issuer = VmEgressCa::mint(&[BOUND_HOST]).expect("upstream issuer");
    let server = upstream(&issuer);
    let vm = single_binding(verifying_forwarder(&server, &issuer));

    let response = over_flow_to(
        &vm,
        BOUND_HOST,
        &request_with_placeholder(&vm.placeholders[0], BOUND_HOST),
    );
    server.served.join().expect("upstream thread");

    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert_eq!(dechunk(&response), b"{\"ok\":true}");
    let received =
        String::from_utf8_lossy(&server.received.lock().expect("record lock")).to_string();
    assert!(
        received.contains(&format!("Bearer {REAL_SECRET}")),
        "the verified destination received the real credential: {received}"
    );
    assert!(!received.contains(&vm.placeholders[0]), "{received}");
    assert!(
        !String::from_utf8_lossy(&response).contains(REAL_SECRET),
        "and the guest never sees it"
    );
}

#[test]
fn a_destination_that_fails_certificate_verification_gets_nothing() {
    // The upstream presents a certificate from an issuer the forward leg does
    // not trust — what an interception or a misdirected name looks like.
    let impostor = VmEgressCa::mint(&[BOUND_HOST]).expect("impostor issuer");
    let trusted = VmEgressCa::mint(&[BOUND_HOST]).expect("trusted issuer");
    let server = upstream(&impostor);
    let vm = single_binding(verifying_forwarder(&server, &trusted));

    let response = over_flow_to(
        &vm,
        BOUND_HOST,
        &request_with_placeholder(&vm.placeholders[0], BOUND_HOST),
    );
    server.served.join().expect("upstream thread");

    assert!(
        status_line(&response).starts_with("HTTP/1.1 502"),
        "an unverifiable destination fails closed: {}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        server.received.lock().expect("record lock").is_empty(),
        "not one request byte reached a destination that failed verification"
    );
    let text = String::from_utf8_lossy(&response);
    assert!(!text.contains(REAL_SECRET), "{text}");
    let chain = vm.audit_chain();
    assert!(chain.contains("upstream_failed"), "{chain}");
    assert!(!chain.contains(REAL_SECRET), "{chain}");
}

/// The header an Anthropic client sends its key in is `x-api-key`, not
/// `authorization`. Substitution follows the placeholder, whatever header it
/// is in.
#[test]
fn an_x_api_key_header_carrying_the_placeholder_is_substituted() {
    let harness = harness(BOUND_HOST, b"{\"ok\":true}");
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nhost: {BOUND_HOST}\r\nx-api-key: {}\r\nanthropic-version: 2023-06-01\r\ncontent-length: 9\r\n\r\n{{\"a\":\"b\"}}",
        harness.placeholder
    );
    let response = exchange(&harness, request.as_bytes());
    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    let seen = forwarded(&harness.forwarder).expect("the forward leg ran");
    assert_eq!(
        seen.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-api-key"))
            .map(|(_, value)| value.as_str()),
        Some(REAL_SECRET)
    );
    assert!(
        !seen
            .headers
            .iter()
            .any(|(_, value)| value.contains(&harness.placeholder)),
        "no placeholder residue reaches the destination"
    );
}
