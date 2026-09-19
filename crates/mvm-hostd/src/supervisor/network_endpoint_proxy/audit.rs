//! Payload-free audit emission for the substitution endpoint: which secret
//! was substituted where, and what was redacted or refused, never the bytes.

use mvm_contract::ir::AuthType;

use super::SubstitutionService;
use super::prepare::{PreparedFlow, destination_host};
use crate::supervisor::redactor::RedactionHits;
use crate::supervisor::secret_audit::{
    emit_rewrite_proof, emit_secret_flow_refused, emit_secret_placeholder_dropped,
    emit_secret_redacted, emit_secret_substituted,
};

/// The sorted, de-duplicated category list a `secret.redacted` entry carries.
///
/// Split out of `audit_redactions` so the counted channels can be asserted
/// without a recorder or a service: each is a `> 0` guard, and `> 0` against
/// `>= 0` is the difference between naming a channel that fired and naming
/// every channel on every entry — which would make the audit line useless
/// precisely when it matters.
pub(crate) fn redaction_categories(hits: &RedactionHits) -> Vec<String> {
    let mut categories: Vec<String> = hits
        .secrets
        .iter()
        .chain(hits.pii.iter())
        .map(|s| s.to_string())
        .collect();
    if hits.entropy > 0 {
        categories.push("entropy".into());
    }
    if hits.names > 0 {
        categories.push("name".into());
    }
    if hits.detector_failures > 0 {
        categories.push("detector_failure".into());
    }
    categories.sort_unstable();
    categories.dedup();
    categories
}

impl SubstitutionService {
    /// Record a chain-signed refusal of a flow to a credentialed destination,
    /// before anything was forwarded.
    ///
    /// `destination` is the authority the flow was admitted against and
    /// `reason` one of a fixed set of host-chosen labels, so neither field can
    /// carry a byte the workload sent.
    pub(crate) async fn audit_flow_refused(&self, destination: &str, reason: &str) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        if let Err(e) = emit_secret_flow_refused(recorder, destination, reason).await {
            tracing::warn!(error = %e, "flow refusal audit emit failed");
        }
    }

    /// Record cancellation/failure metadata for a typed HTTP stream without
    /// ever placing request bytes, headers, credentials, or the full URL in
    /// the audit record.
    pub(crate) async fn audit_http_stream_failure(&self, url: &str, reason: &str) {
        let destination = destination_host(url).ok();
        self.audit_fail_closed(destination.as_deref(), reason).await;
    }

    pub(super) async fn audit_completed_flow(
        &self,
        flow: &PreparedFlow,
        reinject_proofs: &[mvm_core::policy::RewriteProofRecord],
    ) {
        self.audit_substitutions(&flow.substituted, flow.destination.as_deref())
            .await;
        self.audit_rewrite_proofs(
            "replace",
            &flow.replacement_proofs,
            flow.destination.as_deref(),
        )
        .await;
        self.audit_rewrite_proofs("reinject", reinject_proofs, flow.destination.as_deref())
            .await;
        self.audit_redactions(&flow.redaction_hits, flow.destination.as_deref())
            .await;
    }

    /// Emit one `secret.redacted { destination, categories }` entry when the
    /// egress redactor masked anything (claim 13 — category names + destination,
    /// never the bytes). Best-effort; no-op without a recorder or a destination.
    async fn audit_redactions(&self, hits: &RedactionHits, destination: Option<&str>) {
        if hits.is_empty() {
            return;
        }
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        let categories = redaction_categories(hits);
        if let Err(e) = emit_secret_redacted(recorder, dest, &categories.join(",")).await {
            tracing::warn!(error = %e, "secret.redacted audit emit failed");
        }
    }

    /// Emit one `secret.substituted` audit entry per substituted secret (claim
    /// 13 — metadata only). Best-effort: an audit failure is logged, never
    /// fails the request. No-op when no recorder is wired.
    async fn audit_substitutions(
        &self,
        substituted: &[(String, AuthType)],
        destination: Option<&str>,
    ) {
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        for (name, auth_type) in substituted {
            if let Err(e) = emit_secret_substituted(recorder, name, dest, *auth_type).await {
                tracing::warn!(error = %e, secret = %name, "secret.substituted audit emit failed");
            }
        }
    }

    async fn audit_rewrite_proofs(
        &self,
        phase: &str,
        proofs: &[mvm_core::policy::RewriteProofRecord],
        destination: Option<&str>,
    ) {
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        for proof in proofs {
            if let Err(e) = emit_rewrite_proof(recorder, dest, phase, proof).await {
                tracing::warn!(error = %e, "secret.rewrite_proof audit emit failed");
            }
        }
    }

    /// Emit one `secret.placeholder_dropped { destination }` when the endpoint
    /// refuses a placeholder-bearing request bound for a destination the secret
    /// isn't allowed to reach (claim 12 — metadata only, never the value or the
    /// secret name). Best-effort; no-op without a recorder or a destination.
    pub(super) async fn audit_placeholder_dropped(&self, destination: Option<&str>) {
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        if let Err(e) = emit_secret_placeholder_dropped(recorder, dest).await {
            tracing::warn!(error = %e, "secret.placeholder_dropped audit emit failed");
        }
    }

    /// Emit one audit entry when a request to a redaction-opted-in destination
    /// is refused fail-closed (compressed or over-cap body we can't scan in
    /// cleartext). Metadata only — the reason + destination, never the body.
    pub(super) async fn audit_fail_closed(&self, destination: Option<&str>, reason: &str) {
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        if let Err(e) = emit_secret_redacted(recorder, dest, reason).await {
            tracing::warn!(error = %e, "fail-closed audit emit failed");
        }
    }
}

#[cfg(test)]
mod redaction_category_tests {
    use super::redaction_categories;
    use crate::supervisor::redactor::RedactionHits;

    /// A counted channel that did not fire must not be named.
    ///
    /// Each of `entropy`, `names` and `detector_failures` is a `> 0` guard.
    /// Against `>= 0` every entry would name every channel, and a
    /// `secret.redacted` line that always says the same thing carries no
    /// information about the request that produced it.
    #[test]
    fn a_zero_count_names_no_category() {
        let hits = RedactionHits {
            secrets: vec!["aws_key"],
            ..Default::default()
        };
        assert_eq!(redaction_categories(&hits), vec!["aws_key".to_string()]);
    }

    #[test]
    fn entropy_is_named_only_when_it_fired() {
        let mut hits = RedactionHits::default();
        assert!(!redaction_categories(&hits).contains(&"entropy".to_string()));
        hits.entropy = 1;
        assert!(redaction_categories(&hits).contains(&"entropy".to_string()));
    }

    #[test]
    fn names_is_named_only_when_it_fired() {
        let mut hits = RedactionHits::default();
        assert!(!redaction_categories(&hits).contains(&"name".to_string()));
        hits.names = 3;
        assert!(redaction_categories(&hits).contains(&"name".to_string()));
    }

    #[test]
    fn a_detector_failure_is_named_only_when_it_fired() {
        let mut hits = RedactionHits::default();
        assert!(!redaction_categories(&hits).contains(&"detector_failure".to_string()));
        hits.detector_failures = 1;
        assert!(redaction_categories(&hits).contains(&"detector_failure".to_string()));
    }

    /// Sorted and de-duplicated, so the joined label is stable for a reader
    /// diffing two entries rather than dependent on detector order.
    #[test]
    fn categories_are_sorted_and_deduplicated() {
        let hits = RedactionHits {
            secrets: vec!["zeta", "alpha", "alpha"],
            pii: vec!["email"],
            entropy: 2,
            names: 1,
            detector_failures: 0,
        };
        assert_eq!(
            redaction_categories(&hits),
            vec![
                "alpha".to_string(),
                "email".to_string(),
                "entropy".to_string(),
                "name".to_string(),
                "zeta".to_string(),
            ]
        );
    }
}

#[cfg(test)]
mod server_tests {
    use crate::framing::{read_json_frame, write_json_frame};
    use crate::keyholder::{LocalResolver, SecretResolver, SubstitutionRegistry};
    use crate::supervisor::network_endpoint_proxy::test_support::{
        MockForwarder, bearer_ref, gate_admitting,
    };
    use crate::supervisor::network_endpoint_proxy::{MAX_FRAME_BYTES, SubstitutionService};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use secrecy::SecretBox;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio::net::{UnixListener, UnixStream};

    /// A service with a chain-signed recorder, under `gate`, and the path of
    /// the chain it writes. Its one secret is bound to `api.openai.com`.
    fn recorded_service(
        dir: &std::path::Path,
        gate: Arc<mvm_runtime::vmm::egress_gate::EgressGate>,
    ) -> (Arc<SubstitutionService>, String, std::path::PathBuf) {
        use crate::supervisor::audit_file::FileAuditSigner;
        use crate::supervisor::audit_recorder::Recorder;
        use ed25519_dalek::SigningKey;
        use mvm_core::plan::TenantId;

        let store = FileSecretStore::with_dir(dir.join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let chain = dir.join("audit.jsonl");
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&[9u8; 32]), &chain).unwrap();
        let recorder = Recorder::new(Arc::new(signer), TenantId("local".into()));
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let service = Arc::new(
            SubstitutionService::new(Arc::new(reg), resolver, forwarder, gate)
                .with_recorder(recorder),
        );
        (service, ph, chain)
    }

    /// A claim-10 refusal lands one chain-signed entry naming the refused
    /// `host:port` and a fixed reason. Nothing else the request carried does:
    /// not its path, not a header value, not its body. Without the entry a
    /// workload probing destinations it was never admitted to leaves a clean
    /// chain.
    #[tokio::test]
    async fn a_claim10_refusal_is_recorded_in_the_chain_signed_log() {
        let dir = tempdir().unwrap();
        let (service, ph, chain) =
            recorded_service(dir.path(), gate_admitting(&[("api.openai.com", 443)]));

        let resp = service
            .process(WireRequest {
                method: "POST".into(),
                url: "http://93.184.216.34/probe-path-marker?q=query-marker".into(),
                headers: vec![
                    ("authorization".into(), format!("Bearer {ph}")),
                    ("x-note".into(), "header-marker".into()),
                ],
                body_b64: B64.encode(b"body-marker"),
            })
            .await;
        assert!(
            matches!(&resp, WireResponse::Refused { message } if message.contains("claim-10")),
            "{resp:?}"
        );

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(logged.contains("secret.flow_refused"), "{logged}");
        assert!(logged.contains("policy_denied"), "{logged}");
        assert!(logged.contains("93.184.216.34:80"), "{logged}");
        for marker in [
            "probe-path-marker",
            "query-marker",
            "header-marker",
            "body-marker",
            ph.as_str(),
            "sk-live-zzz",
        ] {
            assert!(
                !logged.contains(marker),
                "request content `{marker}` reached the chain: {logged}"
            );
        }
    }

    /// A URL naming no `host:port` is refused as malformed, and recorded as
    /// such rather than silently.
    #[tokio::test]
    async fn a_malformed_destination_refusal_is_recorded_in_the_chain_signed_log() {
        let dir = tempdir().unwrap();
        let (service, _ph, chain) =
            recorded_service(dir.path(), gate_admitting(&[("api.openai.com", 443)]));

        let resp = service
            .process(WireRequest {
                method: "GET".into(),
                url: "not a url".into(),
                headers: Vec::new(),
                body_b64: String::new(),
            })
            .await;
        assert!(matches!(resp, WireResponse::Refused { .. }), "{resp:?}");

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(logged.contains("secret.flow_refused"), "{logged}");
        assert!(logged.contains("malformed"), "{logged}");
        assert!(logged.contains("unparseable"), "{logged}");
    }

    /// The peer refusal is recorded too, under its own reason, so it cannot be
    /// read as a policy denial.
    #[tokio::test]
    async fn a_peer_refusal_is_recorded_in_the_chain_signed_log() {
        let dir = tempdir().unwrap();
        let (service, _ph, chain) =
            recorded_service(dir.path(), gate_admitting(&[("api.openai.com", 443)]));

        let resp = service
            .process(WireRequest {
                method: "GET".into(),
                url: "http://db.mvm.peer:5432/".into(),
                headers: Vec::new(),
                body_b64: String::new(),
            })
            .await;
        assert!(matches!(resp, WireResponse::Refused { .. }), "{resp:?}");

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(logged.contains("secret.flow_refused"), "{logged}");
        assert!(logged.contains("peer_destination"), "{logged}");
        assert!(logged.contains("db.mvm.peer"), "{logged}");
        assert!(!logged.contains("policy_denied"), "{logged}");
    }

    /// An admitted request writes no refusal.
    #[tokio::test]
    async fn an_admitted_request_records_no_refusal() {
        let dir = tempdir().unwrap();
        let (service, ph, chain) =
            recorded_service(dir.path(), gate_admitting(&[("api.openai.com", 443)]));

        let resp = service
            .process(WireRequest {
                method: "POST".into(),
                url: "https://api.openai.com/v1".into(),
                headers: vec![("authorization".into(), format!("Bearer {ph}"))],
                body_b64: String::new(),
            })
            .await;
        assert!(matches!(resp, WireResponse::Ok { .. }), "{resp:?}");

        let logged = std::fs::read_to_string(&chain).unwrap_or_default();
        assert!(!logged.contains("secret.flow_refused"), "{logged}");
    }

    /// A fail-closed refusal (compressed/over-cap body to a redaction-opted-in
    /// destination) is observable: it lands one metadata-only audit entry naming
    /// the destination, and never the body bytes.
    #[tokio::test]
    async fn fail_closed_refusal_is_audited() {
        use crate::supervisor::audit_file::FileAuditSigner;
        use crate::supervisor::audit_recorder::Recorder;
        use ed25519_dalek::SigningKey;
        use mvm_core::plan::TenantId;
        use mvm_core::policy::{EntropyMode, RedactionAction, RedactionPolicy, RedactionProfile};

        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });

        let policy = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile {
                host: "api.openai.com".into(),
                action: RedactionAction {
                    entropy: EntropyMode::Redact {
                        min_bits_per_char: 4.0,
                        min_run_len: 20,
                    },
                    ..Default::default()
                },
            }],
        };

        let chain = dir.path().join("audit.jsonl");
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&[9u8; 32]), &chain).unwrap();
        let recorder = Recorder::new(Arc::new(signer), TenantId("local".into()));

        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(reg),
                resolver,
                Arc::clone(&forwarder) as _,
                gate_admitting(&[("api.openai.com", 443)]),
            )
            .with_redaction_policy(policy)
            .with_recorder(recorder),
        );
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        // A magic body string we can grep for: it must never reach the chain.
        let secret_body = b"SUPERSECRETBODY compressed bytes";
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![
                ("content-encoding".into(), "gzip".into()),
                ("authorization".into(), format!("Bearer {ph}")),
            ],
            body_b64: B64.encode(secret_body),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();
        assert!(
            matches!(&resp, WireResponse::Refused { message } if message.contains("fail-closed")),
            "compressed body must fail closed: {resp:?}"
        );
        // The unscannable request never reached the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(
            logged.contains("api.openai.com"),
            "fail-closed refusal must be audited with the destination: {logged}"
        );
        assert!(
            logged.contains("fail_closed"),
            "fail-closed refusal must record a fail-closed marker: {logged}"
        );
        // The body bytes never reach the audit chain.
        assert!(
            !logged.contains("SUPERSECRETBODY"),
            "audit chain must not carry the body bytes: {logged}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn emits_secret_substituted_audit_on_success() {
        use crate::supervisor::audit_file::FileAuditSigner;
        use crate::supervisor::audit_recorder::Recorder;
        use ed25519_dalek::SigningKey;
        use mvm_core::plan::TenantId;

        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });

        let chain = dir.path().join("audit.jsonl");
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&[9u8; 32]), &chain).unwrap();
        let recorder = Recorder::new(Arc::new(signer), TenantId("local".into()));

        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(reg),
                resolver,
                forwarder,
                gate_admitting(&[("api.openai.com", 443)]),
            )
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
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        // The audit emit completes before the Ok response is written, so the
        // chain entry is on disk by the time we read the reply.
        let _resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(logged.contains("secret.substituted"), "got: {logged}");
        assert!(logged.contains("openai"));
        assert!(logged.contains("api.openai.com"));
        // claim 13: the value never reaches the audit chain.
        assert!(
            !logged.contains("sk-live-zzz"),
            "audit chain must not carry the secret value: {logged}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn emits_placeholder_dropped_audit_on_unbound_refusal() {
        use crate::supervisor::audit_file::FileAuditSigner;
        use crate::supervisor::audit_recorder::Recorder;
        use ed25519_dalek::SigningKey;
        use mvm_core::plan::TenantId;

        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path().join("secrets"));
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-zzz".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        // Placeholder bound to api.openai.com only.
        let ph = reg
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });

        let chain = dir.path().join("audit.jsonl");
        let signer =
            FileAuditSigner::open_file(SigningKey::from_bytes(&[9u8; 32]), &chain).unwrap();
        let recorder = Recorder::new(Arc::new(signer), TenantId("local".into()));

        // The gate admits the unbound host, so only the binding can refuse it.
        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(reg),
                resolver,
                Arc::clone(&forwarder) as _,
                gate_admitting(&[("api.openai.com", 443), ("evil.example.com", 443)]),
            )
            .with_recorder(recorder),
        );
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        // Bound placeholder, but pointed at an unbound destination (claim 12).
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();
        assert!(
            matches!(&resp, WireResponse::Refused { message }
                if message.contains("not in the secret's allowed_hosts")),
            "expected the binding refusal, got {resp:?}"
        );
        // claim 12: the unbound destination never reached the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());

        let logged = std::fs::read_to_string(&chain).unwrap();
        assert!(
            logged.contains("secret.placeholder_dropped"),
            "got: {logged}"
        );
        assert!(logged.contains("evil.example.com"), "got: {logged}");
        // claim 13: neither the value nor the secret name leaks into the chain.
        assert!(
            !logged.contains("sk-live-zzz"),
            "audit chain must not carry the secret value: {logged}"
        );
        server.abort();
    }
}
