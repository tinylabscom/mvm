//! Outbound redaction and reversible replacement: masking undeclared
//! secret-shaped and PII content, and refusing a body that cannot be scanned
//! in the clear.

use mvm_contract::substitution::ProxyRequest;

use super::SubstitutionService;
use crate::keyholder::find_placeholder;
use crate::supervisor::redactor::{RedactingSubstitution, RedactionHits, SensitiveDetectionError};
use crate::supervisor::reversible_replacement::ReplacementFlow;

/// Mask undeclared secret/PII content in `req` per the destination `action`,
/// leaving declared placeholders intact (they're substituted next). Returns the
/// categories that fired.
///
/// A header value carrying a declared placeholder is left untouched (the real
/// credential is substituted into it next, and the host-reserved placeholder is
/// not secret-shaped); every other header value and the body are scrubbed.
pub(crate) fn redact_request(
    req: &mut ProxyRequest,
    redactor: &RedactingSubstitution,
    action: &mvm_core::policy::RedactionAction,
) -> Result<RedactionHits, SensitiveDetectionError> {
    let mut hits = RedactionHits::default();
    for (_, value) in req.headers.iter_mut() {
        if find_placeholder(value).is_some() {
            continue; // declared placeholder — substituted next, never masked.
        }
        if let Some((masked, h)) = redactor.redact_bytes_for(value.as_bytes(), action) {
            *value = String::from_utf8_lossy(&masked).into_owned();
            hits.merge(h);
        }
    }
    if let Some((masked, h)) = redactor.redact_bytes_for(&req.body, action) {
        req.body = masked;
        hits.merge(h);
    }
    if hits.detector_failures > 0 {
        Err(SensitiveDetectionError)
    } else {
        Ok(hits)
    }
}

/// True when `action` requires body protection or observation. The default
/// action protects curated secrets and PII, so it arms the cleartext-scan gate
/// even when entropy and name scanning are off. Only an explicit audit-only
/// secrets action paired with disabled PII and no optional detectors is inactive.
pub(crate) fn redaction_active(action: &mvm_core::policy::RedactionAction) -> bool {
    !matches!(action.secrets, mvm_core::policy::SecretAction::Audit)
        || action.pii.mode.as_deref() != Some("disabled")
        || !matches!(action.entropy, mvm_core::policy::EntropyMode::Off)
        || !matches!(action.names, mvm_core::policy::NameMode::Off)
}

/// The fail-closed scan-gate run before substitute/forward:
/// when the destination opted into redaction, a `content-encoding` (compressed)
/// or over-cap body can't be scanned in the clear, so it's refused rather than
/// forwarded unscanned. Returns the reason marker when the request must be
/// refused, else `None`. `compressed` wins when both hold (the harder bypass).
pub(crate) fn fail_closed_reason(
    headers: &[(String, String)],
    body_len: usize,
    action: &mvm_core::policy::RedactionAction,
) -> Option<&'static str> {
    if !redaction_active(action) {
        return None;
    }
    let compressed = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"));
    let oversize = body_len as u64 > mvm_core::policy::DEFAULT_BODY_CAP_BYTES;
    if compressed {
        Some("fail_closed_compressed")
    } else if oversize {
        Some("fail_closed_oversize")
    } else {
        None
    }
}

impl SubstitutionService {
    /// Mask undeclared secret-shaped / PII content out of a guest-authored
    /// request before it leaves the host, through the shared
    /// `RedactingSubstitution`. A header value carrying a declared placeholder is left untouched (the
    /// real credential is substituted into it next, and the host-reserved
    /// placeholder is not secret-shaped); every other header value and the body
    /// are scrubbed. Returns the rewritten request plus the categories that
    /// fired, for the claim-13 audit.
    pub(super) fn redact_outbound(
        &self,
        req: ProxyRequest,
        action: &mvm_core::policy::RedactionAction,
    ) -> Result<(ProxyRequest, RedactionHits), SensitiveDetectionError> {
        let mut req = req;
        let hits = redact_request(&mut req, &self.redactor, action)?;
        Ok((req, hits))
    }

    pub(super) fn replace_outbound(
        &self,
        req: &mut ProxyRequest,
        replacement_flow: &mut ReplacementFlow,
    ) -> Vec<mvm_core::policy::RewriteProofRecord> {
        let mut proofs = Vec::new();
        for (name, value) in req.headers.iter_mut() {
            if find_placeholder(value).is_some() {
                continue;
            }
            let (rewritten, mut field_proofs) =
                replacement_flow.replace_header_value(name.clone(), value.as_bytes());
            if !field_proofs.is_empty() {
                *value = String::from_utf8_lossy(&rewritten).into_owned();
                proofs.append(&mut field_proofs);
            }
        }
        let (rewritten_body, mut body_proofs) = replacement_flow.replace_body(&req.body);
        if !body_proofs.is_empty() {
            req.body = rewritten_body;
            proofs.append(&mut body_proofs);
        }
        proofs
    }
}

#[cfg(test)]
mod redaction_gate_tests {
    use super::redaction_active;
    use mvm_core::policy::{PiiPolicy, RedactionAction, SecretAction};

    #[test]
    fn default_curated_protection_arms_the_fail_closed_gate() {
        assert!(redaction_active(&RedactionAction::default()));
    }

    #[test]
    fn audit_only_with_pii_disabled_does_not_claim_body_protection() {
        let action = RedactionAction {
            pii: PiiPolicy {
                mode: Some("disabled".into()),
                categories: Vec::new(),
            },
            secrets: SecretAction::Audit,
            ..Default::default()
        };
        assert!(!redaction_active(&action));
    }

    /// The all-off action the single-channel cases start from.
    fn all_channels_off() -> RedactionAction {
        RedactionAction {
            pii: PiiPolicy {
                mode: Some("disabled".into()),
                categories: Vec::new(),
            },
            secrets: SecretAction::Audit,
            ..Default::default()
        }
    }

    // `redaction_active` is a four-way OR, and the two cases above are
    // all-on and all-off — which an AND satisfies identically. So neither
    // test could tell the gate from its own inversion, and a mutation to
    // `&&` survived: a request protected by exactly one channel would have
    // been reported as carrying no protection at all, and the fail-closed
    // scan gate above skipped.
    //
    // Any single channel has to arm it, because that is the fail-safe
    // direction — the gate asks "is anything being redacted", not "is
    // everything".

    #[test]
    fn secrets_alone_arms_the_gate() {
        let mut action = all_channels_off();
        action.secrets = SecretAction::Redact;
        assert!(redaction_active(&action));
    }

    #[test]
    fn pii_alone_arms_the_gate() {
        let mut action = all_channels_off();
        action.pii.mode = Some("curated".into());
        assert!(redaction_active(&action));
    }

    #[test]
    fn entropy_alone_arms_the_gate() {
        let mut action = all_channels_off();
        action.entropy = mvm_core::policy::EntropyMode::Audit {
            min_bits_per_char: 3.5,
            min_run_len: 20,
        };
        assert!(redaction_active(&action));
    }

    #[test]
    fn names_alone_arms_the_gate() {
        let mut action = all_channels_off();
        action.names = mvm_core::policy::NameMode::Audit;
        assert!(redaction_active(&action));
    }

    #[test]
    fn an_absent_pii_mode_arms_the_gate() {
        // `None` is not `Some("disabled")`, so it counts as protection.
        let mut action = all_channels_off();
        action.pii.mode = None;
        assert!(redaction_active(&action));
    }
}

#[cfg(test)]
mod fail_closed_gate_tests {
    use super::fail_closed_reason;
    use mvm_core::policy::{DEFAULT_BODY_CAP_BYTES, PiiPolicy, RedactionAction, SecretAction};

    /// Redaction on, so the gate is reached at all.
    fn armed() -> RedactionAction {
        RedactionAction::default()
    }

    /// Redaction fully off — the gate returns early whatever the body is.
    fn disarmed() -> RedactionAction {
        RedactionAction {
            pii: PiiPolicy {
                mode: Some("disabled".into()),
                categories: Vec::new(),
            },
            secrets: SecretAction::Audit,
            ..Default::default()
        }
    }

    #[test]
    fn an_unredacted_destination_is_never_refused() {
        let huge = DEFAULT_BODY_CAP_BYTES as usize + 1;
        assert_eq!(fail_closed_reason(&[], huge, &disarmed()), None);
    }

    // The cap is a `>` comparison, so exactly-at-cap and one-over are the
    // only inputs that tell it from `>=`. Without both, a body of precisely
    // `DEFAULT_BODY_CAP_BYTES` could start being refused — or, in the other
    // direction, one byte over could start being forwarded unscanned —
    // without a single test noticing.

    #[test]
    fn a_body_exactly_at_the_cap_is_scannable() {
        let at_cap = DEFAULT_BODY_CAP_BYTES as usize;
        assert_eq!(fail_closed_reason(&[], at_cap, &armed()), None);
    }

    #[test]
    fn a_body_one_byte_over_the_cap_is_refused() {
        let over = DEFAULT_BODY_CAP_BYTES as usize + 1;
        assert_eq!(
            fail_closed_reason(&[], over, &armed()),
            Some("fail_closed_oversize")
        );
    }

    #[test]
    fn a_compressed_body_is_refused_whatever_its_size() {
        let headers = vec![("Content-Encoding".to_string(), "gzip".to_string())];
        assert_eq!(
            fail_closed_reason(&headers, 1, &armed()),
            Some("fail_closed_compressed")
        );
    }

    #[test]
    fn compression_outranks_size_because_it_is_the_harder_bypass() {
        let headers = vec![("content-encoding".to_string(), "br".to_string())];
        let over = DEFAULT_BODY_CAP_BYTES as usize + 1;
        assert_eq!(
            fail_closed_reason(&headers, over, &armed()),
            Some("fail_closed_compressed")
        );
    }
}

#[cfg(test)]
mod server_tests {
    use crate::framing::{read_json_frame, write_json_frame};
    use crate::keyholder::{LocalResolver, SecretResolver, SubstitutionRegistry};
    use crate::supervisor::network_endpoint_proxy::test_support::{bearer_ref, service_with};
    use crate::supervisor::network_endpoint_proxy::{
        ForwardError, ForwardResponse, Forwarder, MAX_FRAME_BYTES, PreparedRequest,
        SubstitutionService,
    };
    use async_trait::async_trait;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use secrecy::SecretBox;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio::net::{UnixListener, UnixStream};

    /// The endpoint scrubs an *undeclared* secret-shaped run from the
    /// outbound body before forwarding (at the endpoint chokepoint, so every
    /// backend routing egress through it is covered), while a *declared*
    /// placeholder is still substituted to its real credential. The destination
    /// sees the real declared credential and a masked undeclared one — the
    /// undeclared secret never leaves the host.
    #[tokio::test]
    async fn endpoint_redacts_undeclared_secret_in_body_then_forwards() {
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let leaked = "sk-".to_owned() + &"z".repeat(48);
        let body = format!("{{\"leak\":\"{leaked}\"}}");
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(body.as_bytes()),
        };

        let resp = service.process(wire).await;
        assert!(matches!(resp, WireResponse::Ok { .. }), "{resp:?}");

        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        // Declared secret: substituted to the real credential.
        assert_eq!(
            seen.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        // Undeclared secret in the body: masked before egress.
        let seen_body = String::from_utf8_lossy(&seen.body);
        assert!(
            !seen_body.contains(&leaked),
            "undeclared secret survived to the destination: {seen_body}"
        );
        assert!(
            seen_body.contains("XXX"),
            "body was not masked: {seen_body}"
        );
    }

    /// A clean request is forwarded byte-for-byte — redaction never rewrites
    /// content that doesn't match a secret/PII rule.
    #[tokio::test]
    async fn endpoint_forwards_clean_body_unchanged() {
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{\"prompt\":\"hello world\"}"),
        };

        let resp = service.process(wire).await;
        assert!(matches!(resp, WireResponse::Ok { .. }), "{resp:?}");
        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        assert_eq!(seen.body, b"{\"prompt\":\"hello world\"}");
    }

    #[tokio::test]
    async fn endpoint_replaces_and_reinjects_secret_and_pii_when_policy_enabled() {
        use mvm_core::policy::{
            ReversibleReplacementAction, ReversibleReplacementPolicy, ReversibleReplacementProfile,
        };

        struct EchoForwarder {
            seen: Mutex<Option<PreparedRequest>>,
        }

        #[async_trait]
        impl Forwarder for EchoForwarder {
            async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
                *self.seen.lock().unwrap() = Some(req.clone());
                let echoed_header = req
                    .headers
                    .iter()
                    .find(|(name, _)| name == "x-user")
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default();
                Ok(ForwardResponse {
                    status: 200,
                    headers: vec![("x-echo-user".into(), echoed_header)],
                    body: req.body,
                })
            }
        }

        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
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
        let forwarder = Arc::new(EchoForwarder {
            seen: Mutex::new(None),
        });
        let policy = ReversibleReplacementPolicy {
            default: Default::default(),
            profiles: vec![ReversibleReplacementProfile {
                host: "api.openai.com".into(),
                action: ReversibleReplacementAction {
                    enabled: true,
                    ..Default::default()
                },
            }],
        };
        let service = Arc::new(
            SubstitutionService::new(Arc::new(reg), resolver, forwarder.clone())
                .with_reversible_replacement_policy(policy),
        );

        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {ph}")),
                ("x-user".into(), "alice@example.com".into()),
            ],
            body_b64: B64.encode(
                b"Call +14155550123 with sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        };

        let resp = service.process(wire).await;
        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            seen.headers
                .iter()
                .find(|(name, _)| name == "authorization")
                .unwrap()
                .1,
            "Bearer sk-live-zzz"
        );
        assert!(
            !seen
                .headers
                .iter()
                .find(|(name, _)| name == "x-user")
                .unwrap()
                .1
                .contains("alice@example.com")
        );
        let seen_body = String::from_utf8_lossy(&seen.body);
        assert!(!seen_body.contains("+14155550123"));
        assert!(!seen_body.contains("sk-aaaaaaaa"));

        match resp {
            WireResponse::Ok {
                headers, body_b64, ..
            } => {
                assert_eq!(
                    headers
                        .iter()
                        .find(|(name, _)| name == "x-echo-user")
                        .unwrap()
                        .1,
                    "alice@example.com"
                );
                let body = String::from_utf8(B64.decode(body_b64).unwrap()).unwrap();
                assert!(body.contains("+14155550123"));
                assert!(body.contains("sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
            }
            WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
        }
    }

    #[tokio::test]
    async fn transformed_response_does_not_reinject_without_exact_token() {
        use mvm_core::policy::{
            ReversibleReplacementAction, ReversibleReplacementPolicy, ReversibleReplacementProfile,
        };

        struct RephrasingForwarder;

        #[async_trait]
        impl Forwarder for RephrasingForwarder {
            async fn forward(
                &self,
                _req: PreparedRequest,
            ) -> Result<ForwardResponse, ForwardError> {
                Ok(ForwardResponse {
                    status: 200,
                    headers: vec![],
                    body: b"please call the user later".to_vec(),
                })
            }
        }

        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
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
        let policy = ReversibleReplacementPolicy {
            default: Default::default(),
            profiles: vec![ReversibleReplacementProfile {
                host: "api.openai.com".into(),
                action: ReversibleReplacementAction {
                    enabled: true,
                    ..Default::default()
                },
            }],
        };
        let service = Arc::new(
            SubstitutionService::new(Arc::new(reg), resolver, Arc::new(RephrasingForwarder))
                .with_reversible_replacement_policy(policy),
        );
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"call +14155550123"),
        };
        let resp = service.process(wire).await;
        match resp {
            WireResponse::Ok { body_b64, .. } => {
                assert_eq!(B64.decode(body_b64).unwrap(), b"please call the user later");
            }
            WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
        }
    }

    /// Fail-closed: the default action protects curated secrets and PII, so a
    /// `content-encoding`-bearing request is refused before forwarding.
    #[tokio::test]
    async fn compressed_body_to_redaction_destination_is_refused() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));
        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![
                ("content-encoding".into(), "gzip".into()),
                ("authorization".into(), format!("Bearer {ph}")),
            ],
            body_b64: B64.encode(b"\x1f\x8b compressed bytes"),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();
        assert!(
            matches!(resp, WireResponse::Refused { .. }),
            "compressed body must fail closed: {resp:?}"
        );
        // The unscannable request never reached the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());
        server.abort();
    }
}
