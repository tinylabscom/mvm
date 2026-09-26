//! Request preparation: the binding check that decides whether a placeholder
//! may be substituted for the destination a request will actually dial, and
//! the pre-connect decisions every request path shares.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use mvm_contract::ir::AuthType;
use mvm_contract::substitution::{
    PrepareError, PreparedRequest, ProxyRequest, SubstitutionDriver, contains_minted_placeholder,
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
/// The host and port the forward leg will dial for `url`, keyed the way the
/// HTTP client asks its resolver.
fn url_host_and_port(url: &str) -> Option<(String, u16)> {
    let u = Url::parse(url).ok()?;
    Some((u.host_str()?.to_string(), u.port_or_known_default()?))
}

fn url_host_port(url: &str) -> Option<String> {
    let u = Url::parse(url).ok()?;
    match (u.host_str(), u.port_or_known_default()) {
        (Some(host), Some(port)) => Some(format!("{host}:{port}")),
        _ => None,
    }
}

/// The reason a peer destination is refused, as recorded in the chain.
const REASON_PEER_DESTINATION: &str = "peer_destination";
/// The reason a destination the network policy does not admit is refused.
/// The FlowMux connect path records the same word for the same decision.
const REASON_POLICY_DENIED: &str = "policy_denied";
/// The reason a request whose URL names no `host:port` is refused.
const REASON_MALFORMED: &str = "malformed";
/// What a refusal records as its destination when the URL names none.
pub(super) const UNPARSEABLE_DESTINATION: &str = "unparseable";
/// The reason a request carrying a placeholder in its URL is refused.
const REASON_PLACEHOLDER_IN_URL: &str = "placeholder_in_url";
/// The reason a request carrying a placeholder in its body is refused.
pub(crate) const REASON_PLACEHOLDER_IN_BODY: &str = "placeholder_in_body";
/// What the workload is told when it sends a placeholder outside a header.
pub(crate) const PLACEHOLDER_OUTSIDE_HEADERS: &str = "a secret placeholder is substituted only in a request header; refusing a request \
     that carries one elsewhere";

/// Finds a minted placeholder in a body that arrives in chunks, including one
/// split across two chunks.
///
/// A placeholder that is not substituted would go to the destination as the
/// token itself, authenticated to nobody, so the request is refused instead.
/// The check sees each chunk before the streaming redactor, which holds back
/// far more than a placeholder's length, releases any of it.
pub(super) struct BodyPlaceholderScan {
    /// The last `SECRET_PLACEHOLDER_LEN - 1` bytes seen, the most of a
    /// placeholder that can end one chunk.
    carry: zeroize::Zeroizing<Vec<u8>>,
}

impl BodyPlaceholderScan {
    pub(super) fn new() -> Self {
        Self {
            carry: zeroize::Zeroizing::new(Vec::new()),
        }
    }

    /// Whether the body, extended by `chunk`, now contains a placeholder.
    ///
    /// A placeholder lies wholly inside `chunk`, or starts in the carried tail
    /// and ends within `chunk`'s first `SECRET_PLACEHOLDER_LEN - 1` bytes, so
    /// those two places are all that need checking.
    pub(super) fn found_in(&mut self, chunk: &[u8]) -> bool {
        use mvm_contract::substitution::{SECRET_PLACEHOLDER_LEN, contains_minted_placeholder};
        let reach = SECRET_PLACEHOLDER_LEN - 1;
        let head = &chunk[..chunk.len().min(reach)];
        let mut seam = zeroize::Zeroizing::new(Vec::with_capacity(self.carry.len() + head.len()));
        seam.extend_from_slice(&self.carry);
        seam.extend_from_slice(head);
        let found = contains_minted_placeholder(&seam) || contains_minted_placeholder(chunk);
        let tail = if chunk.len() >= reach {
            &chunk[chunk.len() - reach..]
        } else {
            &seam[seam.len().saturating_sub(reach)..]
        };
        self.carry = zeroize::Zeroizing::new(tail.to_vec());
        found
    }
}

/// Why the claim-10 gate refuses `target`, or `None` when it admits it.
///
/// `target` is the request's `host:port`, and `None` when the URL has no
/// parseable one. The returned label is chosen here from a fixed set, so the
/// chain entry built from it carries nothing the workload sent.
#[cfg(test)]
fn claim10_refusal(
    gate: &mvm_runtime::vmm::egress_gate::EgressGate,
    target: Option<&str>,
) -> Option<&'static str> {
    claim10_decision(gate, target).err()
}

/// The gate's decision for `target`: the addresses it admitted, or the fixed
/// label of why not. A restricted address records its class
/// (`cloud_metadata`, `private_range`), every other policy refusal
/// `policy_denied`.
fn claim10_decision(
    gate: &mvm_runtime::vmm::egress_gate::EgressGate,
    target: Option<&str>,
) -> Result<Vec<std::net::IpAddr>, &'static str> {
    use mvm_runtime::vmm::egress_gate::EgressVerdict;
    let Some(target) = target else {
        return Err(REASON_MALFORMED);
    };
    match gate.decide_request(target) {
        EgressVerdict::Allow { ips, .. } => Ok(ips),
        EgressVerdict::Malformed => Err(REASON_MALFORMED),
        EgressVerdict::Deny(reason) => Err(match reason.audit_label() {
            "policy_denied" => REASON_POLICY_DENIED,
            label => label,
        }),
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
        // refused here, and the refusal is chain-signed so a workload probing
        // destinations it was not admitted to leaves a record.
        //
        // A peer name is refused here even when the plan binds it. Peer
        // traffic goes over FlowMux as raw TCP; this leg substitutes secrets
        // into outbound HTTP, and whether a peer request should receive a
        // substituted credential is a question nobody has answered. Refusing
        // is the conservative answer and, unlike falling through to
        // `decide_request`, it says so.
        if let Some(host) = destination.as_deref()
            && mvm_contract::peer::PeerName::is_peer_target(host)
        {
            self.audit_flow_refused(host, REASON_PEER_DESTINATION).await;
            return Err(WireResponse::Refused {
                message: "peer destinations are not reachable through the substitution proxy"
                    .into(),
            });
        }
        let target = url_host_port(&req.url);
        match claim10_decision(&self.egress_gate, target.as_deref()) {
            Ok(ips) => {
                // The forward leg connects to exactly these; see `pinned_dns`.
                if let Some((host, port)) = url_host_and_port(&req.url) {
                    self.admitted.record(&host, port, ips);
                    // Then what the request may do there. The path is the
                    // URL's own, the one the forward leg will send.
                    let path = Url::parse(&req.url)
                        .map(|u| u.path().to_string())
                        .unwrap_or_default();
                    if let Err(reason) = self.enforce_routes(&host, port, &req.method, &path).await
                    {
                        return Err(WireResponse::Refused {
                            message: format!(
                                "egress route refused {} {host}:{port} ({reason})",
                                super::routing::method_label(&req.method)
                            ),
                        });
                    }
                }
            }
            Err(reason) => {
                let recorded = target
                    .as_deref()
                    .or(destination.as_deref())
                    .unwrap_or(UNPARSEABLE_DESTINATION);
                self.audit_flow_refused(recorded, reason).await;
                return Err(WireResponse::Refused {
                    message: "egress destination not admitted by network policy (claim-10)".into(),
                });
            }
        }
        // A placeholder is substituted only in a header. Anywhere else it would
        // go to the destination as the token itself, so the request is refused
        // before anything is forwarded.
        let placeholder_elsewhere = if contains_minted_placeholder(req.url.as_bytes()) {
            Some(REASON_PLACEHOLDER_IN_URL)
        } else if contains_minted_placeholder(&req.body) {
            Some(REASON_PLACEHOLDER_IN_BODY)
        } else {
            None
        };
        if let Some(reason) = placeholder_elsewhere {
            self.audit_flow_refused(
                destination.as_deref().unwrap_or(UNPARSEABLE_DESTINATION),
                reason,
            )
            .await;
            return Err(WireResponse::Refused {
                message: PLACEHOLDER_OUTSIDE_HEADERS.into(),
            });
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

    fn minted_placeholder() -> String {
        let mut reg = SubstitutionRegistry::new();
        reg.mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string()
    }

    /// A placeholder is found wherever the body is cut, including cuts that
    /// split it between two chunks.
    #[test]
    fn a_placeholder_split_at_any_offset_is_found() {
        let body = format!("{{\"text\":\"{}\"}}", minted_placeholder());
        for cut in 0..=body.len() {
            let mut scan = BodyPlaceholderScan::new();
            let (first, second) = body.as_bytes().split_at(cut);
            let found = scan.found_in(first) || scan.found_in(second);
            assert!(found, "missed a placeholder split at byte {cut}");
        }
    }

    /// Byte-at-a-time delivery is the worst case for the carry.
    #[test]
    fn a_placeholder_delivered_one_byte_at_a_time_is_found() {
        let body = format!("prefix {} suffix", minted_placeholder());
        let mut scan = BodyPlaceholderScan::new();
        assert!(body.as_bytes().iter().any(|byte| scan.found_in(&[*byte])));
    }

    /// A body that only mentions the prefix, even split the same way, passes.
    #[test]
    fn a_body_mentioning_the_prefix_is_not_refused() {
        let body = b"see mvm-secret-deadbeef and the mvm-secret- prefix in the docs";
        for cut in 0..=body.len() {
            let mut scan = BodyPlaceholderScan::new();
            let (first, second) = body.split_at(cut);
            assert!(!scan.found_in(first) && !scan.found_in(second), "{cut}");
        }
    }

    /// Each refusal is named by a fixed label, and an admitted destination is
    /// not a refusal at all. The label is all the chain entry says about why.
    #[test]
    fn a_claim10_refusal_is_named_by_a_fixed_label() {
        use crate::supervisor::network_endpoint_proxy::test_support::gate_admitting;
        let gate = gate_admitting(&[("93.184.216.34", 443)]);

        assert_eq!(claim10_refusal(&gate, Some("93.184.216.34:443")), None);
        assert_eq!(
            claim10_refusal(&gate, Some("93.184.216.34:80")),
            Some(REASON_POLICY_DENIED)
        );
        assert_eq!(
            claim10_refusal(&gate, Some("elsewhere.example:443")),
            Some(REASON_POLICY_DENIED)
        );
        assert_eq!(
            claim10_refusal(&gate, Some("no-port")),
            Some(REASON_MALFORMED)
        );
        assert_eq!(claim10_refusal(&gate, None), Some(REASON_MALFORMED));
    }

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
    use crate::supervisor::network_endpoint_proxy::test_support::{
        gate_admitting, service_with, service_with_gate,
    };
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mvm_core::substitution_wire::{WireRequest, WireResponse};
    use std::sync::Arc;
    use tokio::net::{UnixListener, UnixStream};

    /// A destination the gate admits is forwarded — the gate lets an admitted
    /// `host:port` through to the substitution + forward path unchanged.
    #[tokio::test]
    async fn gate_admitted_destination_is_forwarded() {
        // A public literal IP (loopback / private ranges are mandatory-deny at
        // decision time, so they can never stand in for an admitted destination).
        let (service, ph, forwarder, _dir) = service_with_gate(
            "sk-live-zzz",
            &["93.184.216.34"],
            gate_admitting(&[("93.184.216.34", 80)]),
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
        // Gate admits a *different* public host than the request targets.
        let (service, ph, forwarder, _dir) = service_with_gate(
            "sk-live-zzz",
            &["93.184.216.34"],
            gate_admitting(&[("1.1.1.1", 443)]),
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
        // A public address, so the refusal is the deny-all policy's and not the
        // mandatory-deny ranges', which would refuse loopback under any gate.
        let (service, ph, forwarder, _dir) = service_with_gate(
            "sk-live-zzz",
            &["93.184.216.34"],
            Arc::new(mvm_runtime::vmm::egress_gate::EgressGate::default_deny()),
        );
        let wire = WireRequest {
            method: "POST".into(),
            url: "http://93.184.216.34/v1".into(),
            headers: vec![("authorization".into(), format!("Bearer {ph}"))],
            body_b64: B64.encode(b"{}"),
        };
        let resp = service.process(wire).await;
        assert!(
            matches!(&resp, WireResponse::Refused { message } if message.contains("claim-10")),
            "{resp:?}"
        );
        assert!(
            forwarder.seen.lock().unwrap().is_none(),
            "deny-all must refuse before the forward leg"
        );
    }

    /// The peer refusal holds on every service. It used to sit behind an
    /// optional gate, so a service built without one forwarded a peer name to
    /// the forward leg like any other host.
    #[tokio::test]
    async fn a_peer_destination_is_refused_by_every_service() {
        let (service, _ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        let wire = WireRequest {
            method: "GET".into(),
            url: "http://db.mvm.peer:5432/".into(),
            headers: Vec::new(),
            body_b64: String::new(),
        };
        let resp = service.process(wire).await;
        match resp {
            WireResponse::Refused { message } => assert_eq!(
                message,
                "peer destinations are not reachable through the substitution proxy"
            ),
            WireResponse::Ok { .. } => panic!("a peer destination was forwarded"),
        }
        assert!(forwarder.seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn endpoint_refuses_unbound_destination_and_never_forwards() {
        // The gate admits the unbound host too, so only the binding can refuse.
        let (service, ph, forwarder, dir) = service_with_gate(
            "sk-live-zzz",
            &["api.openai.com"],
            gate_admitting(&[("api.openai.com", 443), ("evil.example.com", 443)]),
        );
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

        assert!(
            matches!(&resp, WireResponse::Refused { message }
                if message.contains("not in the secret's allowed_hosts")),
            "expected the claim-12 binding refusal, got {resp:?}"
        );
        // claim 12: an unbound destination never reaches the forward leg.
        assert!(forwarder.seen.lock().unwrap().is_none());
        server.abort();
    }
}
