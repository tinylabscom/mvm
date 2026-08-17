//! Data-governance witness: a WASI module's egress is mediated by the same
//! host substitution/policy/audit seam every microVM backend uses.
//!
//! This proves, against a bound destination, that (a) the request is
//! admitted by policy and reaches the destination, (b) the destination
//! receives the real secret (never the placeholder), (c) the module itself
//! only ever held the opaque placeholder, and (d) a chain-signed
//! `secret.substituted` audit entry lands and the chain verifies.
//!
//! Deliberate deviation from a literal "spawn the OS subprocess" witness:
//! the production forward leg (`HardenedForwarder`) refuses loopback/private
//! destinations by construction (an SSRF hardening control with no test
//! escape hatch), so a hermetic test cannot drive a real destination through
//! it — confirmed by the existing subprocess-level tests, which only ever
//! exercise refusal paths for exactly this reason. This witness instead
//! builds the real `SubstitutionService` in-process (the same production
//! type the subprocess wraps: real registry, real resolver reading the real
//! encrypted secret store, real claim-10 gate, real chain-signed recorder)
//! and swaps only the one piece that cannot run hermetically — the outbound
//! TCP dial — for a test double implementing the same `Forwarder` trait
//! production code implements against. This is the identical seam the
//! crate's own test suite uses to prove the same properties. The wasm leg
//! (the module, wasmtime, the `mvm:egress` host-import, and the wire
//! protocol to the substitution socket) is exercised unmodified through the
//! real `WasmBackend`.

#![cfg(feature = "wasm-backend")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use mvm_contract::ir::AuthType;
use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
use mvm_core::plan::{SecretBinding, SecretSource, TenantId};
use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
use mvm_core::substitution_wire::WireResponse;
use mvm_core::vm_backend::{VmBackend, VmStartConfig};
use mvm_hostd::keyholder::resolver::LocalResolver as ProxyLocalResolver;
use mvm_hostd::keyholder::{
    BindingStore, FileBindingStore, HandedPlaceholders, SecretBindingMeta, assemble_registry,
};
use mvm_hostd::supervisor::audit_file::{FileAuditSigner, verify_audit_chain};
use mvm_hostd::supervisor::audit_recorder::Recorder;
use mvm_hostd::supervisor::network_endpoint::build_egress_gate;
use mvm_hostd::supervisor::network_endpoint_proxy::{
    ForwardError, ForwardResponse, Forwarder, PreparedRequest, SubstitutionService,
};
use mvm_runtime::wasm_backend::WasmBackend;
use secrecy::SecretBox;

const TENANT: &str = "witness-tenant";
const SECRET_ADDRESS: &str = "witness-secret";
const SECRET_ENV_VAR: &str = "API_KEY";
const REAL_SECRET_VALUE: &str = "s3cr3t-real";

/// The symbolic public destination the policy, binding, and URL all name. It
/// must be a routable public unicast address so the real claim-10 gate admits
/// it (the gate mandatory-denies loopback/private regardless of the allow-list).
/// The physical dial goes to a loopback mock via `LoopbackForwarder`, so nothing
/// ever actually connects here. `93.184.216.34` is a stable public IP well
/// outside the mandatory-deny set; `build_service` asserts that invariant.
fn policy_dest() -> SocketAddr {
    "93.184.216.34:443".parse().expect("policy dest parses")
}

/// Test-only `Forwarder`: dials the mock destination directly over a real
/// TCP socket. Production's `HardenedForwarder` refuses loopback/private
/// destinations by construction (`SsrfGuard`), so it cannot reach a locally
/// bound test double; this stands in for exactly that one wire hop while
/// every governance decision (registry, resolver, gate, audit) stays on the
/// real production types.
struct LoopbackForwarder {
    addr: SocketAddr,
}

#[async_trait]
impl Forwarder for LoopbackForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        let path = req
            .url
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .map(|(_, path)| format!("/{path}"))
            .unwrap_or_else(|| "/".to_string());
        let mut raw = format!("{} {path} HTTP/1.1\r\n", req.method);
        for (k, v) in &req.headers {
            raw.push_str(&format!("{k}: {v}\r\n"));
        }
        raw.push_str(&format!("content-length: {}\r\n", req.body.len()));
        raw.push_str("connection: close\r\n\r\n");
        let mut out = raw.into_bytes();
        out.extend_from_slice(&req.body);

        let mut stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .map_err(|e| ForwardError::Failed(format!("connect to mock destination: {e}")))?;
        tokio::io::AsyncWriteExt::write_all(&mut stream, &out)
            .await
            .map_err(|e| ForwardError::Failed(format!("write to mock destination: {e}")))?;
        let mut resp_bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut resp_bytes)
            .await
            .map_err(|e| ForwardError::Failed(format!("read from mock destination: {e}")))?;
        let text = String::from_utf8_lossy(&resp_bytes);
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| ForwardError::Failed("mock destination sent no status line".into()))?;
        Ok(ForwardResponse {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        })
    }
}

/// Bind a loopback TCP listener that accepts exactly one connection, records
/// the raw request text it received on `tx`, replies `200 pong`, then closes
/// its write half so the forwarder's `read_to_end` completes.
fn spawn_mock_destination() -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock destination");
    let addr = listener.local_addr().expect("mock destination local_addr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = vec![0u8; 8192];
        let mut total = 0usize;
        while total < buf.len() {
            match stream.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let request_text = String::from_utf8_lossy(&buf[..total]).to_string();
        let _ = tx.send(request_text);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\npong");
        let _ = stream.shutdown(std::net::Shutdown::Write);
    });
    (addr, rx)
}

/// Seed the encrypted secret store + binding store, mint the registry (the
/// same `assemble_registry` the real subprocess uses at admission), and
/// build a real `SubstitutionService` — production types end to end except
/// for the injected `LoopbackForwarder`. Returns the service, the minted
/// `(guest var, placeholder)` pairs, the audit chain's verifying key, and
/// the audit file path.
///
/// Two addresses, deliberately decoupled: `policy_dest` is the destination the
/// admitted `NetworkPolicy`, the binding's `allowed_hosts`, and the request URL
/// all name — it must be a genuinely routable public address so the real
/// claim-10 egress gate admits it (the gate mandatory-denies loopback/private by
/// construction, regardless of any allow-list). `mock_addr` is the loopback
/// listener the `LoopbackForwarder` physically dials, standing in for the one
/// wire hop that cannot run hermetically. Every governance decision between them
/// (gate, bind-check, substitution, audit) runs on the real production types.
fn build_service(
    dir: &std::path::Path,
    policy_dest: SocketAddr,
    bound_host: &str,
    mock_addr: SocketAddr,
) -> (
    Arc<SubstitutionService>,
    HandedPlaceholders,
    ed25519_dalek::VerifyingKey,
    std::path::PathBuf,
) {
    assert!(
        !mvm_core::policy::network_policy::is_mandatory_deny(policy_dest.ip()),
        "the policy destination must be outside the mandatory-deny set or the \
         claim-10 gate refuses it before substitution: {policy_dest}"
    );

    // The secret's binding allow-list (claim-12) is independent of the VM's
    // network policy (claim-10): a destination can be network-admitted yet not a
    // host this particular secret may be sent to. The allow path passes
    // `policy_dest`'s host here; the deny path passes a different host to drive a
    // bind-check drop against a network-admitted destination.
    let bindings = FileBindingStore::with_dir(dir.join("bindings"));
    bindings
        .put(
            TENANT,
            SECRET_ADDRESS,
            &SecretBindingMeta {
                auth_type: AuthType::Bearer,
                allowed_hosts: vec![bound_host.to_string()],
                sigv4: None,
                provider: None,
            },
        )
        .expect("seed secret binding");

    let secret_store = FileSecretStore::with_dir(dir.join("secrets"));
    secret_store
        .put(
            TENANT,
            SECRET_ADDRESS,
            &SecretBox::new(Box::new(REAL_SECRET_VALUE.to_string())),
        )
        .expect("seed secret value");

    let plan_secrets = vec![SecretBinding {
        name: SECRET_ENV_VAR.to_string(),
        source: SecretSource::Keystore {
            address: SECRET_ADDRESS.to_string(),
        },
    }];
    let (registry, handed) =
        assemble_registry(&plan_secrets, TENANT, &bindings).expect("assemble registry");
    let resolver: Arc<dyn mvm_hostd::keyholder::SecretResolver> = Arc::new(
        ProxyLocalResolver::new(TENANT, Arc::new(secret_store) as Arc<dyn SecretStore>),
    );
    let forwarder: Arc<dyn Forwarder> = Arc::new(LoopbackForwarder { addr: mock_addr });

    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let audit_path = dir.join(format!("{TENANT}.jsonl"));
    let signer = FileAuditSigner::open_file(signing_key, &audit_path).expect("open audit signer");
    let recorder = Recorder::new(Arc::new(signer), TenantId(TENANT.to_string()));

    let policy = NetworkPolicy::allow_list(vec![HostPort::new(
        policy_dest.ip().to_string(),
        policy_dest.port(),
    )]);
    let gate = build_egress_gate(&policy);

    let service = SubstitutionService::new(Arc::new(registry), resolver, forwarder)
        .with_tenant(TENANT)
        .with_recorder(recorder)
        .with_egress_gate(gate);

    (Arc::new(service), handed, verifying_key, audit_path)
}

/// Escape a string for embedding as a WAT string-literal data segment:
/// backslash and double-quote are the only two bytes WAT string syntax
/// requires escaped for otherwise-printable JSON/ASCII text.
fn wat_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build a WASI module that, on `_start`, writes `request_json` into linear
/// memory, calls the real `mvm:egress_json` host-import (the P3a ABI:
/// `(req_ptr,req_len,resp_ptr,resp_cap)->i32`), and exits `0` only if the
/// import returned a `WireResponse` whose bytes begin with `ok_prefix` —
/// i.e. only if the module itself observed `WireResponse::Ok{status:200,..}`.
/// Any negative import error, a too-short response, or a mismatched prefix
/// (e.g. `WireResponse::Refused`) exits nonzero. The module never has any
/// other channel back to the host, so this exit code is the module's own
/// account of what it saw — the test never peeks at wasm memory directly.
fn egress_probe_wat(request_json: &str, ok_prefix: &str) -> String {
    const RESP_PTR: i32 = 8192;
    const RESP_CAP: i32 = 8192;
    const PATTERN_PTR: i32 = 20000;
    format!(
        r#"(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (import "mvm" "egress_json" (func $mvm_egress (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 0) "{req}")
  (data (i32.const {pattern_ptr}) "{pattern}")
  (func $_start
    (local $len i32)
    (local $i i32)
    (local.set $len
      (call $mvm_egress
        (i32.const 0) (i32.const {req_len})
        (i32.const {resp_ptr}) (i32.const {resp_cap})))
    (if (i32.lt_s (local.get $len) (i32.const {pattern_len}))
      (then (call $proc_exit (i32.const 1))))
    (local.set $i (i32.const 0))
    (block $break
      (loop $loop
        (br_if $break (i32.ge_u (local.get $i) (i32.const {pattern_len})))
        (if (i32.ne
              (i32.load8_u (i32.add (i32.const {resp_ptr}) (local.get $i)))
              (i32.load8_u (i32.add (i32.const {pattern_ptr}) (local.get $i))))
          (then (call $proc_exit (i32.const 2))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)))
    (call $proc_exit (i32.const 0)))
  (export "_start" (func $_start)))
"#,
        req = wat_escape(request_json),
        pattern = wat_escape(ok_prefix),
        req_len = request_json.len(),
        pattern_ptr = PATTERN_PTR,
        pattern_len = ok_prefix.len(),
        resp_ptr = RESP_PTR,
        resp_cap = RESP_CAP,
    )
}

/// The `WireResponse::Ok` prefix through (but not including) the `headers`
/// field, computed from the real type rather than hand-typed — a
/// `#[serde(tag=...)]` field-order change breaks loudly here instead of
/// silently producing a fixture that can never match.
fn ok_status_200_prefix() -> String {
    let sample = serde_json::to_string(&WireResponse::Ok {
        status: 200,
        headers: Vec::new(),
        body_b64: String::new(),
    })
    .expect("WireResponse::Ok serializes");
    let cut = sample
        .find(",\"headers\"")
        .expect("WireResponse::Ok carries a headers field after status");
    sample[..cut].to_string()
}

/// Assert the chain-signed audit log verifies, carries an entry of `expect_kind`,
/// and never leaks the real secret value (claim 13). Shared by the allow path
/// (`secret.substituted`) and the deny path (`secret.placeholder_dropped`).
fn assert_audit_chain(
    audit_path: &std::path::Path,
    verifying_key: &ed25519_dalek::VerifyingKey,
    expect_kind: &str,
) {
    verify_audit_chain(audit_path, verifying_key).expect("audit chain verifies");
    let chain_text = std::fs::read_to_string(audit_path).expect("read audit chain");
    assert!(
        chain_text.contains(expect_kind),
        "audit chain must carry a {expect_kind} entry: {chain_text}"
    );
    assert!(
        !chain_text.contains(REAL_SECRET_VALUE),
        "audit chain must never carry the real secret value (claim 13)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn governed_egress_substitutes_secret_and_audits_on_bound_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mock_addr, dest_requests) = spawn_mock_destination();
    let policy_dest = policy_dest();

    let (service, handed, verifying_key, audit_path) = build_service(
        dir.path(),
        policy_dest,
        &policy_dest.ip().to_string(),
        mock_addr,
    );
    assert_eq!(handed.len(), 1, "exactly one secret binding was admitted");
    assert_eq!(handed[0].0, SECRET_ENV_VAR);
    let placeholder = handed[0].1.as_str().to_string();
    assert!(
        placeholder.starts_with("mvm-secret-"),
        "unexpected placeholder shape: {placeholder}"
    );

    let uds_path = dir.path().join("egress.sock");
    let listener = tokio::net::UnixListener::bind(&uds_path).expect("bind substitution UDS");
    tokio::spawn(Arc::clone(&service).serve(listener));

    // (c) the module never holds the real secret — only the placeholder is
    // ever written into the request bytes that become the module's memory.
    let request_json = serde_json::to_string(&mvm_core::substitution_wire::WireRequest {
        method: "GET".to_string(),
        url: format!("http://{policy_dest}/ping"),
        headers: vec![("authorization".to_string(), format!("Bearer {placeholder}"))],
        body_b64: String::new(),
    })
    .expect("WireRequest serializes");
    assert!(
        !request_json.contains(REAL_SECRET_VALUE),
        "the request handed to the module must never carry the real secret"
    );
    assert!(request_json.contains(&placeholder));

    let ok_prefix = ok_status_200_prefix();
    let wat = egress_probe_wat(&request_json, &ok_prefix);
    assert!(
        !wat.contains(REAL_SECRET_VALUE),
        "the compiled module's bytes must never carry the real secret"
    );

    let mut module_file = tempfile::Builder::new()
        .suffix(".wat")
        .tempfile()
        .expect("wat tempfile");
    module_file
        .write_all(wat.as_bytes())
        .expect("write wat fixture");
    module_file.flush().expect("flush wat fixture");

    let backend = WasmBackend::new().with_egress_endpoint(uds_path);
    let config = VmStartConfig {
        name: "witness-run".to_string(),
        rootfs_path: module_file.path().to_str().unwrap().to_string(),
        ..Default::default()
    };

    let status = tokio::task::spawn_blocking(move || {
        let id = backend.start(&config).expect("wasm module must run");
        backend.wait(&id).expect("wait returns the exit status")
    })
    .await
    .expect("spawn_blocking join");

    // (a) allow-by-policy: the module's own account (via its exit code) of
    // what the mvm:egress import returned is WireResponse::Ok{status:200,..}.
    assert!(
        status.success,
        "the module must have observed WireResponse::Ok{{status:200,..}}; exit code {:?}",
        status.code
    );

    // (b) substitution happened host-side: the destination received the
    // REAL secret, never the placeholder or a literal `${NAME}` token.
    let seen = dest_requests
        .recv_timeout(Duration::from_secs(5))
        .expect("mock destination must receive the forwarded request");
    let auth_line = seen
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .unwrap_or_else(|| panic!("no authorization header reached the destination: {seen}"));
    assert!(
        auth_line.contains(REAL_SECRET_VALUE),
        "destination must receive the substituted secret, got: {auth_line}"
    );
    assert!(
        !auth_line.contains(&placeholder) && !auth_line.contains("${"),
        "no placeholder may leak to the destination, got: {auth_line}"
    );

    // (d) a chain-signed `secret.substituted` audit entry exists, the chain
    // verifies, and the real secret never appears in it.
    assert_audit_chain(&audit_path, &verifying_key, "secret.substituted");
}

/// Deny path: a module carrying a valid secret placeholder targets a destination
/// the VM's network policy admits (claim-10 passes) but the secret's own binding
/// does not list (claim-12). The endpoint drops the placeholder before any
/// forward leg — the module observes a refusal, the destination is never
/// contacted, and a chain-signed `secret.placeholder_dropped` entry records the
/// drop. This is the fail-closed, audited half of the governance seam.
///
/// It deliberately exercises the bind-check drop rather than a bare claim-10
/// network-policy denial: the latter refuses too, but the gate denial is not
/// audited by design, so it cannot witness the "refused AND audited" property.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn governed_egress_denies_unbound_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mock_addr, dest_requests) = spawn_mock_destination();
    let policy_dest = policy_dest();
    // The secret is bound to a different host than the module targets, so sending
    // it to `policy_dest` is a claim-12 drop even though claim-10 admits the hop.
    let bound_host = "198.51.100.7";
    assert_ne!(bound_host, policy_dest.ip().to_string());

    let (service, handed, verifying_key, audit_path) =
        build_service(dir.path(), policy_dest, bound_host, mock_addr);
    let placeholder = handed[0].1.as_str().to_string();

    let uds_path = dir.path().join("egress.sock");
    let listener = tokio::net::UnixListener::bind(&uds_path).expect("bind substitution UDS");
    tokio::spawn(Arc::clone(&service).serve(listener));

    let request_json = serde_json::to_string(&mvm_core::substitution_wire::WireRequest {
        method: "GET".to_string(),
        url: format!("http://{policy_dest}/ping"),
        headers: vec![("authorization".to_string(), format!("Bearer {placeholder}"))],
        body_b64: String::new(),
    })
    .expect("WireRequest serializes");
    assert!(
        !request_json.contains(REAL_SECRET_VALUE),
        "the request handed to the module must never carry the real secret"
    );

    // Same ok-prefix probe: the module exits 0 only on WireResponse::Ok{200}; a
    // refusal fails the prefix match and exits nonzero.
    let ok_prefix = ok_status_200_prefix();
    let wat = egress_probe_wat(&request_json, &ok_prefix);
    let mut module_file = tempfile::Builder::new()
        .suffix(".wat")
        .tempfile()
        .expect("wat tempfile");
    module_file
        .write_all(wat.as_bytes())
        .expect("write wat fixture");
    module_file.flush().expect("flush wat fixture");

    let backend = WasmBackend::new().with_egress_endpoint(uds_path);
    let config = VmStartConfig {
        name: "witness-deny".to_string(),
        rootfs_path: module_file.path().to_str().unwrap().to_string(),
        ..Default::default()
    };
    let status = tokio::task::spawn_blocking(move || {
        let id = backend.start(&config).expect("wasm module must run");
        backend.wait(&id).expect("wait returns the exit status")
    })
    .await
    .expect("spawn_blocking join");

    // The module did not observe Ok{200} — the endpoint refused.
    assert!(
        !status.success,
        "an unbound destination must not yield WireResponse::Ok; exit code {:?}",
        status.code
    );

    // The drop precedes the forward leg, so the loopback mock never accepts.
    assert!(
        dest_requests
            .recv_timeout(Duration::from_millis(500))
            .is_err(),
        "a dropped request must never reach the destination"
    );

    // The drop is audited: a chain-signed secret.placeholder_dropped entry lands,
    // the chain verifies, and the real secret never appears.
    assert_audit_chain(&audit_path, &verifying_key, "secret.placeholder_dropped");
}
