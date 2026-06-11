//! End-to-end test of the `mvm-substitution-endpoint` subprocess over UDS.
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

use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
use mvm_core::plan::{SecretBinding, SecretSource};
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};
use mvm_hostd::supervisor::substitution_endpoint::{EndpointConfig, EndpointTransport};
use mvm_sdk::ir::AuthType;
use secrecy::SecretBox;

const BIN: &str = env!("CARGO_BIN_EXE_mvm-substitution-endpoint");

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

    // Host stores: a Bearer secret bound to api.openai.com only.
    FileBindingStore::with_dir(dir.path().join("bindings"))
        .put(
            "local",
            "openai",
            &SecretBindingMeta {
                auth_type: AuthType::Bearer,
                allowed_hosts: vec!["api.openai.com".into()],
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
        secrets: vec![SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }],
        transport: EndpointTransport::Uds { path: sock.clone() },
        redaction: mvm_core::policy::RedactionPolicy::default(),
        forward_timeout_secs: 30,
        secret_store_dir: Some(dir.path().join("secrets")),
        binding_store_dir: Some(dir.path().join("bindings")),
        terminator_listen: None,
        tls_intermediate: None,
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
    let handed: Vec<(String, String)> = serde_json::from_str(line.trim()).expect("handshake json");
    assert_eq!(handed.len(), 1);
    assert_eq!(handed[0].0, "OPENAI_API_KEY");
    let placeholder = handed[0].1.clone();
    assert!(placeholder.starts_with("mvm-secret-"), "got {placeholder}");

    // The endpoint bound the UDS before the handshake, so it's reachable now.
    let mut conn = UnixStream::connect(&sock).expect("connect to endpoint UDS");
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
