//! End-to-end test of the `mvm-network-endpoint` subprocess over UDS.
//!
//! Drives the real bin: writes an `EndpointConfig` on stdin, reads the
//! placeholder handshake line from stdout, then routes a request through the
//! served socket. Uses the UDS transport (works on every unix; the AF_VSOCK
//! path is covered by the serve_vsock loopback test) and an **unbound**
//! destination so the claim-12 bind-check refuses BEFORE any network forward —
//! the assertion is fully offline yet exercises parse → assemble (open stores,
//! mint placeholder) → serve → resolve → bind-check.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};

use mvm_contract::ir::AuthType;
use mvm_contract::protocol::network_flow::hello::Handshake;
use mvm_contract::protocol::network_flow::{Opcode, encode_into};
use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
use mvm_core::plan::{SecretBinding, SecretSource};
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};
use mvm_hostd::supervisor::network_endpoint::{
    EgressMode, EndpointConfig, EndpointTransport, ResolverBackend,
};
use secrecy::SecretBox;

const BIN: &str = env!("CARGO_BIN_EXE_mvm-network-endpoint");

fn write_frame<W: Write>(w: &mut W, value: &impl serde::Serialize) {
    let body = serde_json::to_vec(value).unwrap();
    w.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    w.write_all(&body).unwrap();
    w.flush().unwrap();
}

fn read_frame<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> T {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).unwrap();
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).unwrap();
    serde_json::from_slice(&buf).unwrap()
}

fn write_flowmux_frame(
    stream: &mut UnixStream,
    session: &mut mvm_core::net::session::Session,
    opcode: Opcode,
    stream_id: u32,
    payload: &[u8],
) {
    let mut plaintext = Vec::new();
    encode_into(&mut plaintext, opcode, stream_id, payload).unwrap();
    let sealed = session.seal(&plaintext).unwrap();
    let mut encoded = Vec::new();
    sealed.encode(&mut encoded).unwrap();
    stream
        .write_all(&u32::try_from(encoded.len()).unwrap().to_be_bytes())
        .unwrap();
    stream.write_all(&encoded).unwrap();
    stream.flush().unwrap();
}

fn read_flowmux_frame(
    stream: &mut UnixStream,
    session: &mut mvm_core::net::session::Session,
) -> (Opcode, u32, Vec<u8>) {
    let sealed = mvm_core::net::session::read_sealed_frame(stream, 1 << 20).unwrap();
    let plaintext = session.open(&sealed).unwrap();
    let frame = mvm_contract::protocol::network_flow::decode(&plaintext).unwrap();
    (
        frame.header.opcode,
        frame.header.stream_id,
        frame.payload.to_vec(),
    )
}

fn complete_flowmux_hello(stream: &mut UnixStream, session: &mut mvm_core::net::session::Session) {
    write_flowmux_frame(
        stream,
        session,
        Opcode::Hello,
        0,
        &Handshake::local("endpoint-bin-test").encode(),
    );
    let (opcode, stream_id, _) = read_flowmux_frame(stream, session);
    assert_eq!((opcode, stream_id), (Opcode::HelloAck, 0));
}

/// Kills the child on drop so a panicking assertion never leaks the process.
struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn endpoint_bin_serves_substitution_and_refuses_unbound_destination() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("substitution.sock");
    let connector = dir.path().join("connector.sock");

    // Host stores: a Bearer secret bound to api.openai.com only.
    FileBindingStore::with_dir(dir.path().join("bindings"))
        .put(
            "local",
            "openai",
            &SecretBindingMeta {
                auth_type: AuthType::Bearer,
                allowed_hosts: vec!["api.openai.com".into()],
                sigv4: None,
                provider: None,
            },
        )
        .unwrap();
    FileSecretStore::with_dir(dir.path().join("secrets"))
        .put(
            "local",
            "openai",
            &SecretBox::new(Box::new("sk-live-xyz".to_string())),
        )
        .unwrap();

    let cfg = EndpointConfig {
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: Some(dir.path().join("secrets")),
        binding_store_dir: Some(dir.path().join("bindings")),
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::Wire,
        resolver: ResolverBackend::default(),
        session_marker: None,
        session_ready_socket: None,
        connector_uds_path: Some(connector.clone()),
        flowmux_identity: None,
    };

    let mut child = Command::new(BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn endpoint bin");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&serde_json::to_vec(&cfg).unwrap()).unwrap();
    drop(stdin); // close stdin so the bin proceeds
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let guard = Kill(child);

    // Handshake: one JSON line of (guest var, placeholder) pairs.
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read handshake line");
    let handshake: mvm_runtime::EndpointHandshake =
        serde_json::from_str(line.trim()).expect("handshake json");
    let handed = handshake.env.clone();
    assert_eq!(handed.len(), 1);
    assert_eq!(handed[0].0, "OPENAI_API_KEY");
    let placeholder = handed[0].1.clone();
    assert!(placeholder.starts_with("mvm-secret-"), "got {placeholder}");

    // The endpoint bound the UDS before the handshake, so it's reachable now.
    let mut conn = UnixStream::connect(&connector).expect("connect to typed endpoint connector");
    let req = WireRequest {
        method: "POST".into(),
        // NOT in allowed_hosts — claim-12 bind-check refuses before forwarding,
        // so this asserts substitution wiring with zero network egress.
        url: "https://evil.example.com/v1".into(),
        headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
        body_b64: String::new(),
    };
    write_frame(&mut conn, &req);
    let resp: WireResponse = read_frame(&mut conn);
    match resp {
        WireResponse::Refused { message } => {
            assert!(
                message.contains("evil.example.com") || message.to_lowercase().contains("bound"),
                "expected a binding refusal, got: {message}"
            );
        }
        WireResponse::Ok { status, .. } => {
            panic!("unbound destination must be refused, got Ok status {status}")
        }
    }
    drop(guard);
}

/// The endpoint's claim-10 gate is the outer fence in the real relay-delivery
/// path: a WireRequest to a destination the secret binding WOULD allow is still
/// refused when the network policy doesn't admit it — the gate runs before the
/// claim-12 bind-check and before any forward. This is exactly the frame the run
/// loop relays to the endpoint in relay mode, driven against the real bin.
#[test]
fn endpoint_bin_claim10_gate_refuses_a_bound_but_unadmitted_destination() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("substitution.sock");

    // A Bearer secret bound to api.openai.com — the destination the request
    // targets, so a refusal here can only be the network-policy gate, not a
    // binding mismatch.
    FileBindingStore::with_dir(dir.path().join("bindings"))
        .put(
            "local",
            "openai",
            &SecretBindingMeta {
                auth_type: AuthType::Bearer,
                allowed_hosts: vec!["api.openai.com".into()],
                sigv4: None,
                provider: None,
            },
        )
        .unwrap();
    FileSecretStore::with_dir(dir.path().join("secrets"))
        .put(
            "local",
            "openai",
            &SecretBox::new(Box::new("sk-live-xyz".to_string())),
        )
        .unwrap();

    let cfg = EndpointConfig {
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: Some(dir.path().join("secrets")),
        binding_store_dir: Some(dir.path().join("bindings")),
        terminator_listen: None,
        tls_intermediate: None,
        // Deny-all: the endpoint gates every destination — even the bound one.
        network_policy: Some(mvm_core::policy::network_policy::NetworkPolicy::deny_all()),
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: mvm_hostd::supervisor::network_endpoint::EgressMode::Wire,
        resolver: ResolverBackend::default(),
        session_marker: None,
        session_ready_socket: None,
        connector_uds_path: None,
        flowmux_identity: None,
    };

    let mut child = Command::new(BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn endpoint bin");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&serde_json::to_vec(&cfg).unwrap()).unwrap();
    drop(stdin);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let guard = Kill(child);

    let mut line = String::new();
    stdout.read_line(&mut line).expect("read handshake line");
    let handshake: mvm_runtime::EndpointHandshake =
        serde_json::from_str(line.trim()).expect("handshake json");
    let handed = handshake.env.clone();
    let placeholder = handed[0].1.clone();

    let mut conn = UnixStream::connect(&sock).expect("connect to endpoint UDS");
    let req = WireRequest {
        method: "POST".into(),
        // A destination the binding allows — only the claim-10 gate can refuse it.
        url: "https://api.openai.com/v1".into(),
        headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
        body_b64: String::new(),
    };
    write_frame(&mut conn, &req);
    let resp: WireResponse = read_frame(&mut conn);
    match resp {
        WireResponse::Refused { message } => {
            let m = message.to_lowercase();
            assert!(
                m.contains("claim-10") || m.contains("network policy"),
                "expected a claim-10 network-policy refusal (not a binding refusal), got: {message}"
            );
        }
        WireResponse::Ok { status, .. } => {
            panic!("deny-all policy must refuse the destination, got Ok status {status}")
        }
    }
    drop(guard);
}

#[test]
fn a_flowmux_endpoint_keeps_serving_sessions_after_one_ends() {
    use base64::Engine as _;
    use mvm_core::net::session::Session;
    use mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("network.sock");
    let session_marker = dir.path().join("session.marker");
    let session_ready_socket = dir.path().join("session-ready.sock");

    let host_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let host_verify = host_key.verifying_key();
    let guest_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let b64 = base64::engine::general_purpose::STANDARD;

    let cfg = EndpointConfig {
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: Some(session_marker.clone()),
        session_ready_socket: Some(session_ready_socket.clone()),
        connector_uds_path: None,
        flowmux_identity: Some(FlowMuxIdentity {
            session_id: "keeps-serving".into(),
            host_signing_key_base64: b64.encode(host_key.to_bytes()),
            guest_verifying_key_base64: b64.encode(guest_key.verifying_key().to_bytes()),
        }),
    };

    let mut child = Command::new(BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn endpoint bin");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&serde_json::to_vec(&cfg).unwrap()).unwrap();
    drop(stdin);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let guard = Kill(child);

    let mut line = String::new();
    stdout.read_line(&mut line).expect("read handshake line");

    // Arm the readiness observer before authenticating. The endpoint bound it
    // before the process-ready line above, so this has no connect race.
    let mut readiness = UnixStream::connect(&session_ready_socket)
        .expect("connect to authenticated-session readiness socket");
    readiness
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();

    // A guest session: connect, complete the authenticated handshake, drop.
    // The read timeout turns "the host never answered" into a failure rather
    // than a hung test.
    let handshake_once = |what: &str| {
        let mut conn = UnixStream::connect(&sock).unwrap_or_else(|e| {
            panic!("{what}: endpoint stopped accepting: {e}");
        });
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        Session::guest(&mut conn, guest_key.clone(), &host_verify)
            .unwrap_or_else(|e| panic!("{what}: handshake did not complete: {e}"));
        conn
    };

    // First session, then let it end the way a real one does.
    drop(handshake_once("first session"));
    let mut signal = [0_u8; 1];
    readiness
        .read_exact(&mut signal)
        .expect("authenticated session wakes launch readiness");
    assert_eq!(signal, [1]);
    assert!(
        session_marker.exists(),
        "the durable marker must exist before the event is delivered"
    );

    // The assertion: a fresh session still authenticates after the first ended.
    let second = handshake_once("second session (after the first ended)");

    // And a third while the second is still open — two guest processes each
    // own a session, so the endpoint must hold more than one at a time.
    let third = handshake_once("third session (concurrent with the second)");

    drop(third);
    drop(second);
    drop(guard);
}

#[test]
fn a_flowmux_endpoint_enforces_one_admitted_ceiling_across_sessions() {
    use base64::Engine as _;
    use mvm_core::net::session::Session;
    use mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("network.sock");
    let host_key = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
    let host_verify = host_key.verifying_key();
    let guest_key = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
    let b64 = base64::engine::general_purpose::STANDARD;
    let cfg = EndpointConfig {
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::builder()
            .max_udp_associations(1)
            .build()
            .unwrap(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: None,
        connector_uds_path: None,
        session_ready_socket: None,
        flowmux_identity: Some(FlowMuxIdentity {
            session_id: "shared-limit".into(),
            host_signing_key_base64: b64.encode(host_key.to_bytes()),
            guest_verifying_key_base64: b64.encode(guest_key.verifying_key().to_bytes()),
        }),
    };

    let mut child = Command::new(BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn endpoint bin");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&cfg).unwrap())
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let guard = Kill(child);
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read handshake line");

    let connect_guest = || {
        let mut stream = UnixStream::connect(&sock).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let (mut session, _) =
            Session::guest(&mut stream, guest_key.clone(), &host_verify).unwrap();
        complete_flowmux_hello(&mut stream, &mut session);
        (stream, session)
    };

    let (mut first_stream, mut first_session) = connect_guest();
    write_flowmux_frame(
        &mut first_stream,
        &mut first_session,
        Opcode::OpenUdp,
        1,
        b"",
    );
    let (opcode, _, payload) = read_flowmux_frame(&mut first_stream, &mut first_session);
    assert_eq!(
        opcode,
        Opcode::UdpOpened,
        "first flow was refused: {}",
        String::from_utf8_lossy(&payload)
    );

    let (mut second_stream, mut second_session) = connect_guest();
    write_flowmux_frame(
        &mut second_stream,
        &mut second_session,
        Opcode::OpenUdp,
        1,
        b"",
    );
    let (opcode, _, payload) = read_flowmux_frame(&mut second_stream, &mut second_session);
    assert_eq!(opcode, Opcode::Refused);
    assert!(String::from_utf8_lossy(&payload).contains("ceiling reached (1)"));

    drop(second_stream);
    drop(first_stream);
    drop(guard);
}

#[test]
fn a_flowmux_endpoint_refuses_zero_limits_decoded_from_config() {
    use base64::Engine as _;
    use mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("network.sock");
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut cfg = serde_json::to_value(EndpointConfig {
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: None,
        session_ready_socket: None,
        connector_uds_path: None,
        flowmux_identity: Some(FlowMuxIdentity {
            session_id: "invalid-limit".into(),
            host_signing_key_base64: b64.encode([23u8; 32]),
            guest_verifying_key_base64: b64.encode(
                ed25519_dalek::SigningKey::from_bytes(&[29u8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        }),
    })
    .unwrap();
    cfg["network_limits"]["max_udp_associations"] = serde_json::json!(0);

    let mut child = Command::new(BIN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn endpoint bin");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&cfg).unwrap())
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read handshake line");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll endpoint exit") {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("kill endpoint after hang guard");
            panic!("endpoint did not refuse the invalid limit within five seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(!status.success());
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("validate admitted FlowMux network limits"),
        "unexpected endpoint error: {stderr}"
    );
}
