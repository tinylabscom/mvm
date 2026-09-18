//! Request preparation: the binding check that decides whether a placeholder
//! may be substituted for the destination a request will actually dial, and
//! the pre-connect decisions every request path shares.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_contract::ir::AuthType;
use mvm_contract::substitution::{
    PrepareError, PreparedRequest, ProxyRequest, SubstitutionDriver,
    prepare_request as prepare_request_core,
};
use mvm_core::substitution_wire::{WireRequest, WireResponse};
use url::Url;

use super::SubstitutionService;
use super::redaction::fail_closed_reason;
use super::sign::{SignRequest, sign_into_headers};
use crate::keyholder::{
    NetworkEndpoint, SignDispatchError, SubstituteError, SubstitutionRegistry, find_placeholder,
};
use crate::supervisor::redactor::RedactionHits;
use crate::supervisor::reversible_replacement::ReplacementFlow;

/// Errors from preparing a routed request for forwarding.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("request url `{0}` is not a valid absolute URL with a host")]
    BadUrl(String),
    #[error(transparent)]
    Substitute(#[from] SubstituteError),
    /// The signing path (SigV4/HMAC) refused or failed. Carries the
    /// bind-check refusal (`DestinationNotBound`), an unknown placeholder, the
    /// signer error, or a malformed/over-restricted request — every variant is
    /// fail-closed: `prepare_request` returns `Err` and nothing is forwarded.
    #[error(transparent)]
    Sign(#[from] SignDispatchError),
    /// A signing secret reached the forward path without the data the
    /// signature needs (e.g. a SigV4 secret with no `access_key_id`/`region`/
    /// `service` binding, or a request the canonical form can't be built from).
    /// Fail-closed: refuse rather than forward an unsigned request.
    #[error("refusing to forward: {0}")]
    Refused(String),
}

/// Substitute every placeholder in `req`'s headers against `endpoint`,
/// binding-checked to the request's destination host. Returns a request whose
/// headers carry the real credentials, ready to forward.
///
/// Refuses — before the request is forwarded — if a placeholder's destination
/// is not bound for that secret (claim 12) or the placeholder is unknown. The
/// destination host is taken from the request URL, so a guest can't point a
/// secret at `api.openai.com` in the binding but send the bytes elsewhere: the
/// bind-check uses the URL we will actually dial.
pub fn prepare_request(
    endpoint: &NetworkEndpoint<'_>,
    req: ProxyRequest,
) -> Result<PreparedRequest, ProxyError> {
    let dest = destination_host(&req.url)?;
    match prepare_request_core(endpoint, &dest, req) {
        Ok(prepared) => Ok(prepared),
        Err(PrepareError::MultipleSigningPlaceholders) => Err(ProxyError::Refused(
            "more than one signing placeholder in one request".into(),
        )),
        Err(PrepareError::Driver(e)) => Err(e),
    }
}

impl<'a> SubstitutionDriver for NetworkEndpoint<'a> {
    type Error = ProxyError;

    fn auth_type(&self, placeholder: &str) -> Option<AuthType> {
        self.resolve_ref(placeholder).map(|r| r.auth_type)
    }

    fn substitute(
        &self,
        placeholder: &str,
        destination: &str,
        text: &str,
    ) -> Result<String, ProxyError> {
        Ok(self
            .substitute_bound_credential(placeholder, destination, text)
            .map(|z| z.to_string())?)
    }

    fn sign(
        &self,
        placeholder: &str,
        destination: &str,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<(String, String)>, ProxyError> {
        let auth_type = self
            .resolve_ref(placeholder)
            .map(|r| r.auth_type)
            .ok_or(ProxyError::Substitute(SubstituteError::UnknownPlaceholder))?;
        let sign_req = SignRequest::builder()
            .with_placeholder(placeholder)
            .with_auth_type(auth_type)
            .with_dest(destination)
            .with_method(method)
            .with_url(url)
            .with_body(body)
            .build();
        let mut headers = headers.to_vec();
        sign_into_headers(self, &sign_req, &mut headers)?;
        Ok(headers)
    }
}

/// The destination host (no port) from an absolute URL.
pub(crate) fn destination_host(url: &str) -> Result<String, ProxyError> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .ok_or_else(|| ProxyError::BadUrl(url.to_string()))
}

/// The `host:port` the egress gate decides on, using the scheme's default port
/// when the URL omits one. `None` when the URL has no parseable host or port —
/// which the caller treats as a claim-10 refusal (fail closed).
fn url_host_port(url: &str) -> Option<String> {
    let u = Url::parse(url).ok()?;
    match (u.host_str(), u.port_or_known_default()) {
        (Some(host), Some(port)) => Some(format!("{host}:{port}")),
        _ => None,
    }
}

/// Capture per-secret audit metadata (name + auth-type) for every header that
/// carries a known placeholder — BEFORE substitution consumes the request.
/// `resolve_meta` touches no secret value, so this is claim-13 safe.
pub(crate) fn collect_substituted_meta(
    endpoint: &NetworkEndpoint<'_>,
    headers: &[(String, String)],
) -> Vec<(String, AuthType)> {
    headers
        .iter()
        .filter_map(|(_, v)| find_placeholder(v))
        .filter_map(|ph| endpoint.resolve_meta(ph))
        .collect()
}

/// Security state retained from request preparation through response
/// completion. It contains metadata and rewrite state, never an extra copy of
/// the request or a credential value.
pub(super) struct PreparedFlow {
    pub(super) request: Option<PreparedRequest>,
    pub(super) destination: Option<String>,
    pub(super) substituted: Vec<(String, AuthType)>,
    pub(super) replacement_flow: ReplacementFlow,
    pub(super) replacement_proofs: Vec<mvm_core::policy::RewriteProofRecord>,
    pub(super) redaction_hits: RedactionHits,
    pub(super) redaction_action: mvm_core::policy::RedactionAction,
}

impl SubstitutionService {
    /// Apply every pre-connect security decision once, returning the prepared
    /// request plus the state needed to transform and audit its response.
    pub(super) async fn prepare_flow(
        &self,
        wire: WireRequest,
    ) -> Result<PreparedFlow, WireResponse> {
        let body = match B64.decode(wire.body_b64.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                return Err(WireResponse::Refused {
                    message: format!("bad body encoding: {e}"),
                });
            }
        };
        let req = ProxyRequest {
            method: wire.method,
            url: wire.url,
            headers: wire.headers,
            body,
        };
        // Per-request endpoint: two refs, cheap; the registry is read-only
        // after admission minted its placeholders.
        let registry: &SubstitutionRegistry = &self.registry;
        let endpoint = NetworkEndpoint::new(registry, self.resolver.as_ref());
        // Capture audit metadata (name + auth-type per substituted secret, and
        // the destination) before `prepare_request` consumes `req`.
        let destination = destination_host(&req.url).ok();
        // Claim-10: gate the full host:port against the VM's admitted network
        // policy before anything reaches the wire. Fail closed — a URL without a
        // parseable host:port, or a destination the policy doesn't admit, is
        // refused here. (Audit of the claim-10 denial is a later increment; the
        // refusal itself is the enforcement.)
        if let Some(gate) = &self.egress_gate {
            // A peer name is refused here even when the plan binds it. Peer
            // traffic goes over FlowMux as raw TCP; this leg substitutes
            // secrets into outbound HTTP, and whether a peer request should
            // receive a substituted credential is a question nobody has
            // answered. Refusing is the conservative answer and, unlike
            // falling through to `decide_request`, it says so.
            if let Some(host) = destination.as_deref()
                && mvm_contract::peer::PeerName::is_peer_target(host)
            {
                return Err(WireResponse::Refused {
                    message: "peer destinations are not reachable through the substitution proxy"
                        .into(),
                });
            }
            let admitted = url_host_port(&req.url).as_deref().is_some_and(|hp| {
                matches!(
                    gate.decide_request(hp),
                    mvm_runtime::vmm::egress_gate::EgressVerdict::Allow { .. }
                )
            });
            if !admitted {
                return Err(WireResponse::Refused {
                    message: "egress destination not admitted by network policy (claim-10)".into(),
                });
            }
        }
        let substituted = collect_substituted_meta(&endpoint, &req.headers);
        // Resolve the per-destination redaction action; clone so it outlives
        // `req` (which `redact_outbound` then `prepare_request` consume).
        let action = destination
            .as_deref()
            .map(|d| {
                crate::supervisor::redaction_resolve::resolve(&self.redaction_policy, d).clone()
            })
            .unwrap_or_default();
        let replacement_action = destination
            .as_deref()
            .map(|d| {
                crate::supervisor::reversible_replacement_resolve::resolve(
                    &self.reversible_replacement_policy,
                    d,
                )
                .clone()
            })
            .unwrap_or_default();
        // Fail closed: a body we can't scan in cleartext is a silent bypass. A
        // compressed body, or one over the scan cap, to a redaction-opted-in
        // destination is refused before any forward leg runs.
        if let Some(reason) = fail_closed_reason(&req.headers, req.body.len(), &action) {
            self.audit_fail_closed(destination.as_deref(), reason).await;
            return Err(WireResponse::Refused {
                message: "egress redaction enabled for destination but body is \
                          compressed or over the scan cap; refusing (fail-closed)"
                    .into(),
            });
        }
        // Whether the request smuggled a host placeholder at all — decides if a
        // refusal is a claim-12 placeholder drop (audited) or a plain bad request.
        let carried_placeholder = req
            .headers
            .iter()
            .any(|(_, v)| find_placeholder(v).is_some());
        // Scrub undeclared secret-shaped / PII content before any
        // substitution. Runs first so a declared placeholder (not secret-shaped,
        // host-reserved) survives to be substituted, while an undeclared secret
        // the guest put in the body or a non-placeholder header is masked and
        // never reaches the wire.
        let mut req = req;
        let mut replacement_flow = self
            .replacement_engine
            .start_flow(&self.tenant, &replacement_action);
        let replacement_proofs = self.replace_outbound(&mut req, &mut replacement_flow);
        let (req, redaction_hits) = match self.redact_outbound(req, &action) {
            Ok(redacted) => redacted,
            Err(_) => {
                self.audit_fail_closed(destination.as_deref(), "fail_closed_detector")
                    .await;
                return Err(WireResponse::Refused {
                    message: "sensitive-data detector failed closed; refusing request".into(),
                });
            }
        };
        let prepared = match prepare_request(&endpoint, req) {
            Ok(p) => p,
            Err(e) => {
                // A placeholder-bearing request refused before forwarding is a
                // claim-12 drop — audit it (metadata only). A refusal with no
                // placeholder is a plain bad request and not secret-relevant.
                if carried_placeholder {
                    self.audit_placeholder_dropped(destination.as_deref()).await;
                }
                return Err(WireResponse::Refused {
                    message: e.to_string(),
                });
            }
        };
        Ok(PreparedFlow {
            request: Some(prepared),
            destination,
            substituted,
            replacement_flow,
            replacement_proofs,
            redaction_hits,
            redaction_action: action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::SubstitutionRegistry;
    use crate::supervisor::network_endpoint_proxy::test_support::{bearer_ref, resolver_with};

    #[test]
    fn prepares_request_with_real_credential_for_a_bound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1/chat".into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {}", ph.as_str())),
                ("content-type".into(), "application/json".into()),
            ],
            body: b"{}".to_vec(),
        };
        let prepared = prepare_request(&endpoint, req).unwrap();
        assert_eq!(
            prepared.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        // A header without a placeholder is untouched.
        assert_eq!(prepared.headers[1].1, "application/json");
    }

    #[test]
    fn refuses_a_request_to_an_unbound_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", &["api.openai.com"]));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {}", ph.as_str()))],
            body: vec![],
        };
        let err = prepare_request(&endpoint, req).unwrap_err();
        assert!(matches!(err, ProxyError::Substitute(_)));
    }

    #[test]
    fn passes_through_a_request_without_a_placeholder() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = NetworkEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), "Bearer ya29.real-token".into())],
            body: vec![],
        };
        let prepared = prepare_request(&endpoint, req.clone()).unwrap();
        assert_eq!(prepared.headers, req.headers);
    }

    #[test]
    fn rejects_a_url_without_a_host() {
        let (_dir, resolver) = resolver_with("openai", "sk-live-zzz");
        let reg = SubstitutionRegistry::new();
        let endpoint = NetworkEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "GET".into(),
            url: "not a url".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(matches!(
            prepare_request(&endpoint, req).unwrap_err(),
            ProxyError::BadUrl(_)
        ));
    }
}

#[cfg(test)]
mod server_tests {
    use crate::framing::{read_json_frame, write_json_frame};
    use crate::supervisor::network_endpoint_proxy::MAX_FRAME_BYTES;
    use crate::supervisor::network_endpoint_proxy::test_support::service_with;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use std::sync::Arc;
    use tokio::net::{UnixListener, UnixStream};

    /// Build a claim-10 gate over an allow-list of literal `host:port` rules,
    /// each self-pinned so a literal-IP destination projects. `from_network_policy`
    /// fails closed on any projection error.
    fn gate_admitting(hosts: &[(&str, u16)]) -> mvm_runtime::vmm::egress_gate::EgressGate {
        use mvm_core::policy::dns_pin::{DnsPinRegistry, new_pin};
        use mvm_core::policy::network_policy::{HostPort, NetworkPolicy};
        let mut pins = DnsPinRegistry::new();
        let rules = hosts
            .iter()
            .map(|(h, p)| {
                if let Ok(ip) = h.parse::<std::net::IpAddr>() {
                    pins.add(new_pin(*h, vec![ip], chrono::Duration::hours(1)));
                }
                HostPort::new(*h, *p)
            })
            .collect();
        let policy = NetworkPolicy::allow_list(rules);
        mvm_runtime::vmm::egress_gate::EgressGate::from_network_policy(
            &policy,
            &pins,
            "2026-01-01T00:00:00Z",
        )
    }

    /// A destination the gate admits is forwarded — the gate lets an admitted
    /// `host:port` through to the substitution + forward path unchanged.
    #[tokio::test]
    async fn gate_admitted_destination_is_forwarded() {
        // A public literal IP (loopback / private ranges are mandatory-deny at
        // decision time, so they can never stand in for an admitted destination).
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["93.184.216.34"]);
        let service = Arc::new(
            Arc::try_unwrap(service)
                .ok()
                .expect("fresh service Arc")
                .with_egress_gate(gate_admitting(&[("93.184.216.34", 80)])),
        );
        let wire = WireRequest {
            method: "POST".into(),
            url: "http://93.184.216.34/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        let resp = service.process(wire).await;
        assert!(matches!(resp, WireResponse::Ok { .. }), "{resp:?}");
        assert!(
            forwarder.seen.lock().unwrap().is_some(),
            "admitted destination should have been forwarded"
        );
    }

    /// A destination the gate does NOT admit is refused before any forward — the
    /// mock forwarder never sees it, so no placeholder-substituted credential can
    /// cross to an unadmitted host.
    #[tokio::test]
    async fn gate_non_admitted_destination_is_refused_before_forward() {
        // The secret binding would allow the request host, proving the gate is the
        // outer fence: it refuses a destination the gate's allow-list omits even
        // though the credential is bound to it.
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["93.184.216.34"]);
        // Gate admits a *different* public host than the request targets.
        let service = Arc::new(
            Arc::try_unwrap(service)
                .ok()
                .expect("fresh service Arc")
                .with_egress_gate(gate_admitting(&[("1.1.1.1", 443)])),
        );
        let wire = WireRequest {
            method: "POST".into(),
            url: "http://93.184.216.34/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        let resp = service.process(wire).await;
        match resp {
            WireResponse::Refused { message } => assert!(
                message.contains("claim-10"),
                "expected claim-10 refusal, got: {message}"
            ),
            WireResponse::Ok { .. } => panic!("unadmitted destination was forwarded"),
        }
        // The credential-bearing request never reached the forward leg.
        assert!(
            forwarder.seen.lock().unwrap().is_none(),
            "forwarder must not see a request the gate refused (no secret crosses)"
        );
    }

    /// A deny-all gate refuses even a destination the secret binding would allow —
    /// the gate is the outer claim-10 fence, applied before substitution/forward.
    #[tokio::test]
    async fn gate_deny_all_refuses_before_forward() {
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["127.0.0.1"]);
        let deny = mvm_runtime::vmm::egress_gate::EgressGate::default_deny();
        let service = Arc::new(
            Arc::try_unwrap(service)
                .ok()
                .expect("fresh service Arc")
                .with_egress_gate(deny),
        );
        let wire = WireRequest {
            method: "POST".into(),
            url: "http://127.0.0.1/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        let resp = service.process(wire).await;
        assert!(matches!(resp, WireResponse::Refused { .. }), "{resp:?}");
        assert!(
            forwarder.seen.lock().unwrap().is_none(),
            "deny-all must refuse before the forward leg"
        );
    }

    /// Backward compat: with no gate installed, `process` forwards exactly as
    /// before — the additive field is inert when absent.
    #[tokio::test]
    async fn no_gate_installed_forwards_as_before() {
        let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        let resp = service.process(wire).await;
        assert!(matches!(resp, WireResponse::Ok { .. }), "{resp:?}");
        assert!(
            forwarder.seen.lock().unwrap().is_some(),
            "no gate ⇒ existing forward behavior unchanged"
        );
    }

    #[tokio::test]
    async fn endpoint_refuses_unbound_destination_and_never_forwards() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));

        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://evil.example.com/x".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: String::new(),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        assert!(matches!(resp, WireResponse::Refused { .. }));
        // claim 12: an unbound destination never reaches the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());
        server.abort();
    }
}
