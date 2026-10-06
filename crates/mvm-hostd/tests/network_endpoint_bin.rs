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

/// A public address the network policy admits and no secret is bound to. It
/// must sit outside the mandatory-deny ranges, which refuse loopback under any
/// policy, or the gate rather than the binding would refuse it.
const UNBOUND_ADDR: &str = "93.184.216.34";

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
                inject: Default::default(),
                provider: None,
                approve: Default::default(),
                oauth: None,
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
        telemetry: None,
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
            destinations: Vec::new(),
            approval_required: false,
        }],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: Some(dir.path().join("secrets")),
        binding_store_dir: Some(dir.path().join("bindings")),
        tls_intermediate: None,
        // The policy admits the unbound destination, so the refusal below can
        // only be the binding check's. It is a literal address because the
        // endpoint resolves a policy's host names when it starts.
        network_policy: Some(mvm_core::policy::network_policy::NetworkPolicy::allow_list(
            vec![mvm_core::policy::network_policy::HostPort::new(
                UNBOUND_ADDR,
                443,
            )],
        )),
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::Wire,
        resolver: ResolverBackend::default(),
        session_marker: None,
        session_ready_socket: None,
        connector_uds_path: Some(connector.clone()),
        approval_socket: None,
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
        url: format!("https://{UNBOUND_ADDR}/v1"),
        headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
        body_b64: String::new(),
    };
    write_frame(&mut conn, &req);
    let resp: WireResponse = read_frame(&mut conn);
    match resp {
        WireResponse::Refused { message } => {
            assert!(
                message.contains(UNBOUND_ADDR) && message.contains("allowed_hosts"),
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
                inject: Default::default(),
                provider: None,
                approve: Default::default(),
                oauth: None,
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
        telemetry: None,
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
            destinations: Vec::new(),
            approval_required: false,
        }],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: Some(dir.path().join("secrets")),
        binding_store_dir: Some(dir.path().join("bindings")),
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
        approval_socket: None,
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
        telemetry: None,
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: Some(session_marker.clone()),
        session_ready_socket: Some(session_ready_socket.clone()),
        connector_uds_path: None,
        approval_socket: None,
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
        telemetry: None,
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        tls_intermediate: None,
        // The ceiling is under test, not the policy: admit UDP so the first
        // association opens and the second meets the ceiling.
        network_policy: Some(mvm_core::policy::network_policy::NetworkPolicy::unrestricted()),
        network_limits: mvm_core::plan::NetworkLimits::builder()
            .max_udp_associations(1)
            .build()
            .unwrap(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: None,
        connector_uds_path: None,
        approval_socket: None,
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
        telemetry: None,
        tenant_id: "local".into(),
        instance_id: "test".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: None,
        session_ready_socket: None,
        connector_uds_path: None,
        approval_socket: None,
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

/// A minimal endpoint config whose only listener is the host connector.
fn connector_only_config(connector: &std::path::Path, sock: &std::path::Path) -> EndpointConfig {
    EndpointConfig {
        tenant_id: "local".into(),
        instance_id: "lifetime".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds {
            path: sock.to_path_buf(),
        },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::Wire,
        resolver: ResolverBackend::default(),
        session_marker: None,
        session_ready_socket: None,
        connector_uds_path: Some(connector.to_path_buf()),
        approval_socket: None,
        flowmux_identity: None,
        telemetry: None,
    }
}

/// Start the endpoint from a short-lived shell, the way `machine start` starts
/// it from a short-lived `mvmctl`: the launcher hands over the config, waits
/// for the ready line, and exits while the endpoint is meant to keep serving.
/// Returns the pid the launcher recorded, which is what the stop path signals.
fn launch_from_a_launcher_that_exits(dir: &std::path::Path, args: &[&std::ffi::OsStr]) -> i32 {
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&connector_only_config(
            &dir.join("connector.sock"),
            &dir.join("network.sock"),
        ))
        .unwrap(),
    )
    .unwrap();
    let ready = dir.join("ready.line");
    let pid_file = dir.join("endpoint.pid");
    let status = Command::new("sh")
        .arg("-c")
        .arg(
            r#"bin="$1"; config="$2"; ready="$3"; pid="$4"; shift 4
"$bin" "$@" < "$config" > "$ready" 2>/dev/null &
echo $! > "$pid"
for _ in $(seq 1 200); do [ -s "$ready" ] && exit 0; sleep 0.05; done
exit 1"#,
        )
        .arg("launcher")
        .arg(BIN)
        .arg(&config)
        .arg(&ready)
        .arg(&pid_file)
        .args(args)
        .status()
        .expect("run the launcher");
    assert!(status.success(), "the endpoint never wrote its ready line");
    std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Whether anything is listening on the endpoint's host connector, polled
/// until it matches `expected` or five seconds pass.
fn connector_serving_settles_to(connector: &std::path::Path, expected: bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let serving = UnixStream::connect(connector).is_ok();
        if serving == expected || std::time::Instant::now() >= deadline {
            return serving;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Whether a process is alive, polled until it matches `expected` or five
/// seconds pass. Endpoint teardown can precede process exit on a busy runner.
fn process_liveness_settles_to(pid: i32, expected: bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let alive = mvm_vmm::host::process_liveness::pid_is_alive(pid);
        if alive == expected || std::time::Instant::now() >= deadline {
            return alive;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Signals a recorded pid on drop so a failing assertion leaks nothing.
struct KillPid(i32);
impl Drop for KillPid {
    fn drop(&mut self) {
        // SAFETY: signalling a pid this test started; a stale one is ESRCH.
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
        }
    }
}

#[test]
fn an_endpoint_bound_to_its_launcher_stops_serving_when_the_launcher_exits() {
    let dir = tempfile::tempdir().unwrap();
    let pid = launch_from_a_launcher_that_exits(dir.path(), &[]);
    let _guard = KillPid(pid);

    assert!(
        !connector_serving_settles_to(&dir.path().join("connector.sock"), false),
        "an endpoint with no keeper must not serve as an orphan"
    );
}

#[test]
fn a_kept_endpoint_serves_after_its_launcher_exits_until_its_vm_stops() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("vm");
    std::fs::create_dir_all(&state_dir).unwrap();
    // The VM: any live process recorded under one of the backend pid markers.
    let mut vm = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn VM stand-in");
    std::fs::write(state_dir.join("fc.pid"), vm.id().to_string()).unwrap();

    let keeper = launch_from_a_launcher_that_exits(
        dir.path(),
        &[
            std::ffi::OsStr::new(mvm_hostd::vm_lifetime::VM_LIFETIME_FLAG),
            state_dir.as_os_str(),
        ],
    );
    let _guard = KillPid(keeper);
    let connector = dir.path().join("connector.sock");

    // Past one keeper poll after the launcher has gone.
    std::thread::sleep(std::time::Duration::from_secs(1));
    assert!(
        connector_serving_settles_to(&connector, true),
        "a running VM's endpoint must keep serving after the launcher exits"
    );

    vm.kill().unwrap();
    vm.wait().unwrap();
    assert!(
        !connector_serving_settles_to(&connector, false),
        "a stopped VM's endpoint must stop serving"
    );
    assert!(
        !process_liveness_settles_to(keeper, false),
        "the keeper exits with its endpoint"
    );
}

#[test]
fn signalling_the_recorded_pid_stops_a_kept_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("vm");
    std::fs::create_dir_all(&state_dir).unwrap();
    let mut vm = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn VM stand-in");
    std::fs::write(state_dir.join("fc.pid"), vm.id().to_string()).unwrap();

    let keeper = launch_from_a_launcher_that_exits(
        dir.path(),
        &[
            std::ffi::OsStr::new(mvm_hostd::vm_lifetime::VM_LIFETIME_FLAG),
            state_dir.as_os_str(),
        ],
    );
    let _guard = KillPid(keeper);
    let connector = dir.path().join("connector.sock");
    assert!(connector_serving_settles_to(&connector, true));

    // What the stop path does with the pid it recorded.
    // SAFETY: signalling the keeper this test started.
    unsafe {
        libc::kill(keeper, libc::SIGTERM);
    }
    assert!(
        !connector_serving_settles_to(&connector, false),
        "stopping the keeper must take the endpoint with it"
    );
    vm.kill().unwrap();
    vm.wait().unwrap();
}

/// The embedded telemetry collector runs inside the confined endpoint, so its
/// I/O must fit the endpoint's confinement: on Linux a syscall the seccomp
/// allowlist lacks kills the whole endpoint with SIGSYS, taking the guest's
/// egress down with it and leaving nothing in the log. This drives the real
/// bin with a telemetry section, has a guest double announce coverage, and
/// requires the record to land, the status to reach `collecting`, the
/// periodic status rewrite to survive, and the endpoint to keep serving.
#[test]
fn an_endpoint_embedding_the_collector_collects_and_keeps_serving() {
    use base64::Engine as _;
    use mvm_core::net::session::Session;
    use mvm_core::net::telemetry::TelemetrySender;
    use mvm_core::protocol::telemetry::{
        CoverageState, ProducerEpoch, RecordBody, SourceKind, TelemetryRecord,
    };
    use mvm_hostd::audit_signer::helper::{SignerHelper, serve_on_listener};
    use mvm_hostd::audit_signer::helper_client::DEFAULT_HELPER_MAX_FRAME_BYTES;
    use mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity;
    use mvm_hostd::telemetry_collector::TelemetryEmbedConfig;
    use mvm_vmm::host::broker_services_spawn::{AUDIT_SIGNER_SOCK, HOST_SIGNER_PUB};
    use mvm_vmm::host::telemetry_provisioning::{
        TELEMETRY_COLLECTOR_STATUS_FILE, TELEMETRY_RECORDS_FILE,
    };
    use std::os::unix::process::ExitStatusExt as _;
    use std::time::{Duration, Instant};

    const VM: &str = "telemetry-vm";

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let sock = state_dir.join("network.sock");
    let b64 = base64::engine::general_purpose::STANDARD;

    // The endpoint reads the host anchor from the keys dir under its own
    // MVM_HOME, the one location its confinement makes readable for it.
    let mvm_home = dir.path().join("home");
    let keys_dir = mvm_core::config::mvm_keys_dir_at(&mvm_home);
    std::fs::create_dir_all(&keys_dir).unwrap();
    let host_key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
    let host_verify = host_key.verifying_key();
    let anchor_path = keys_dir.join(HOST_SIGNER_PUB);
    std::fs::write(&anchor_path, host_verify.to_bytes()).unwrap();

    // The delegated signer the collector authenticates through. It runs in
    // this test process, outside the endpoint's confinement, as the
    // resident signer does in production.
    let signer_key = dir.path().join("signer-key");
    std::fs::write(&signer_key, [23u8; 32]).unwrap();
    let signer_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let signer_sock = state_dir.join(AUDIT_SIGNER_SOCK);
    let signer_listener = {
        let _runtime = signer_runtime.enter();
        tokio::net::UnixListener::bind(&signer_sock).unwrap()
    };
    let signer = signer_runtime.spawn(serve_on_listener(
        signer_listener,
        std::sync::Arc::new(tokio::sync::Mutex::new(SignerHelper::new(
            "local",
            Some(signer_key),
        ))),
        DEFAULT_HELPER_MAX_FRAME_BYTES,
    ));

    // This boot's guest identity, registered as the spawner registers it.
    let guest_key = ed25519_dalek::SigningKey::from_bytes(&[29u8; 32]);
    mvm_vmm::host::telemetry_registration::register_telemetry_boot(
        &state_dir,
        VM,
        &b64.encode(guest_key.verifying_key().as_bytes()),
    )
    .unwrap();

    // Guest double on the bridged telemetry socket: announce coverage, then
    // hold the session open until released.
    let telemetry_sock = mvm_core::config::vm_hvf_vsock_port_socket_at(
        &state_dir,
        mvm_core::protocol::telemetry::TELEMETRY_PORT,
    );
    std::fs::create_dir_all(telemetry_sock.parent().unwrap()).unwrap();
    let guest_listener = std::os::unix::net::UnixListener::bind(&telemetry_sock).unwrap();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let guest_identity = guest_key.clone();
    let guest = std::thread::spawn(move || {
        let (mut stream, _) = guest_listener.accept().unwrap();
        let mut sender =
            TelemetrySender::connect(&mut stream, guest_identity, &host_verify).unwrap();
        let record = TelemetryRecord::builder()
            .epoch(ProducerEpoch::new([6; 16]).unwrap())
            .producer(1)
            .sequence(1)
            .source(SourceKind::GuestAgent)
            .body(RecordBody::Coverage {
                state: CoverageState::Started,
                code: "guest-agent".try_into().unwrap(),
            })
            .build()
            .unwrap();
        sender.send(&mut stream, &record).unwrap();
        let _ = release_rx.recv();
    });

    let cfg = EndpointConfig {
        telemetry: Some(TelemetryEmbedConfig {
            state_dir: state_dir.clone(),
            telemetry_sock,
            signer_sock,
            host_anchor_path: anchor_path,
            records_byte_cap: 64 * 1024,
        }),
        tenant_id: "local".into(),
        instance_id: VM.into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: Some(state_dir.join("session.marker")),
        session_ready_socket: None,
        connector_uds_path: None,
        approval_socket: None,
        flowmux_identity: Some(FlowMuxIdentity {
            session_id: VM.into(),
            host_signing_key_base64: b64.encode(host_key.to_bytes()),
            guest_verifying_key_base64: b64.encode(guest_key.verifying_key().to_bytes()),
        }),
    };

    let mut child = Command::new(BIN)
        .env("MVM_HOME", &mvm_home)
        .env("HOME", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn endpoint bin");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&serde_json::to_vec(&cfg).unwrap()).unwrap();
    drop(stdin);
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut guard = Kill(child);
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read handshake line");

    let mut assert_alive = |what: &str| {
        if let Some(status) = guard.0.try_wait().unwrap() {
            panic!(
                "the endpoint exited {what} (code {:?}, signal {:?}); a signal of 31 is \
                 SIGSYS from a syscall the confinement does not allow",
                status.code(),
                status.signal(),
            );
        }
    };
    let status_path = state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE);
    let records_path = state_dir.join(TELEMETRY_RECORDS_FILE);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert_alive("while the collector was starting");
        let recorded = std::fs::read_to_string(&records_path)
            .is_ok_and(|records| records.contains("guest-agent"));
        let collecting =
            std::fs::read_to_string(&status_path).is_ok_and(|status| status.contains("collecting"));
        if recorded && collecting {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the collector never persisted the record and reached collecting"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Outlast a status-writer cycle so its periodic replace runs confined.
    std::thread::sleep(Duration::from_millis(1_500));
    assert_alive("after the collector's periodic status rewrite");

    // And the endpoint still does its own job.
    let mut conn = UnixStream::connect(&sock).expect("endpoint still accepts guest sessions");
    conn.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    Session::guest(&mut conn, guest_key, &host_verify)
        .expect("endpoint still authenticates a guest session");

    drop(conn);
    drop(release_tx);
    let _ = guest.join();
    drop(guard);
    signer.abort();
}

/// Telemetry is observability; egress is the endpoint's job. A collector that
/// cannot start (here, no host anchor to authenticate under) must leave the
/// endpoint serving rather than take the guest's network down with it.
#[test]
fn an_endpoint_whose_collector_cannot_start_keeps_serving() {
    use base64::Engine as _;
    use mvm_core::net::session::Session;
    use mvm_hostd::supervisor::network_endpoint::FlowMuxIdentity;
    use mvm_hostd::telemetry_collector::TelemetryEmbedConfig;

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let sock = state_dir.join("network.sock");
    let b64 = base64::engine::general_purpose::STANDARD;
    let host_key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
    let host_verify = host_key.verifying_key();
    let guest_key = ed25519_dalek::SigningKey::from_bytes(&[37u8; 32]);

    let cfg = EndpointConfig {
        telemetry: Some(TelemetryEmbedConfig {
            state_dir: state_dir.clone(),
            telemetry_sock: state_dir.join("telemetry.sock"),
            signer_sock: state_dir.join("audit-signer.sock"),
            host_anchor_path: dir.path().join("no-such-anchor.pub"),
            records_byte_cap: 64 * 1024,
        }),
        tenant_id: "local".into(),
        instance_id: "collector-refused-vm".into(),
        secrets: vec![],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        tools: Default::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        forward_timeout_secs: 30,
        proxy_https: None,
        proxy_http: None,
        no_proxy: None,
        secret_store_dir: None,
        binding_store_dir: None,
        tls_intermediate: None,
        network_policy: None,
        network_limits: mvm_core::plan::NetworkLimits::default(),
        ingress: Vec::new(),
        egress_mode: EgressMode::FlowMux,
        resolver: ResolverBackend::default(),
        session_marker: Some(state_dir.join("session.marker")),
        session_ready_socket: None,
        connector_uds_path: None,
        approval_socket: None,
        flowmux_identity: Some(FlowMuxIdentity {
            session_id: "collector-refused-vm".into(),
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
    let mut guard = Kill(child);
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read handshake line");

    let mut conn = UnixStream::connect(&sock).expect("endpoint still accepts guest sessions");
    conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    Session::guest(&mut conn, guest_key, &host_verify)
        .expect("endpoint still authenticates a guest session");
    assert!(
        guard.0.try_wait().unwrap().is_none(),
        "a collector that cannot start must not end the endpoint"
    );
    drop(conn);
}
