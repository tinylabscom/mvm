//! SigV4 and HMAC signing: the signature is computed under the bound
//! credential and written into the outgoing headers; the key never leaves
//! the signer.

use mvm_contract::ir::AuthType;

use super::prepare::ProxyError;
use crate::keyholder::{NetworkEndpoint, SigningInput, build_sigv4_input};

/// `yyyymmddThhmmssZ` UTC, the SigV4 `x-amz-date` format.
fn amz_date_now() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// The request to sign, under one signing credential. Borrowed — built once per
/// request just before [`sign_into_headers`]. `placeholder` names the SigV4/HMAC
/// secret (its header value was already dropped); `dest` is the bound destination
/// host; `method`/`url`/`body` are the request line and payload that get signed.
#[derive(Clone, Copy)]
pub(super) struct SignRequest<'a> {
    placeholder: &'a str,
    auth_type: AuthType,
    dest: &'a str,
    method: &'a str,
    url: &'a str,
    body: &'a [u8],
}

impl<'a> SignRequest<'a> {
    pub(super) fn builder() -> SignRequestBuilder<'a> {
        SignRequestBuilder::default()
    }
}

/// Builder for [`SignRequest`]: one setter per field, `build()` returns the
/// value. Every field is required; `build()` panics if a setter was skipped,
/// which is unreachable from the single internal call site that sets them all.
#[derive(Default)]
pub(super) struct SignRequestBuilder<'a> {
    placeholder: Option<&'a str>,
    auth_type: Option<AuthType>,
    dest: Option<&'a str>,
    method: Option<&'a str>,
    url: Option<&'a str>,
    body: Option<&'a [u8]>,
}

impl<'a> SignRequestBuilder<'a> {
    pub(super) fn with_placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = Some(placeholder);
        self
    }
    pub(super) fn with_auth_type(mut self, auth_type: AuthType) -> Self {
        self.auth_type = Some(auth_type);
        self
    }
    pub(super) fn with_dest(mut self, dest: &'a str) -> Self {
        self.dest = Some(dest);
        self
    }
    pub(super) fn with_method(mut self, method: &'a str) -> Self {
        self.method = Some(method);
        self
    }
    pub(super) fn with_url(mut self, url: &'a str) -> Self {
        self.url = Some(url);
        self
    }
    pub(super) fn with_body(mut self, body: &'a [u8]) -> Self {
        self.body = Some(body);
        self
    }
    pub(super) fn build(self) -> SignRequest<'a> {
        SignRequest {
            placeholder: self.placeholder.expect("sign request placeholder"),
            auth_type: self.auth_type.expect("sign request auth_type"),
            dest: self.dest.expect("sign request dest"),
            method: self.method.expect("sign request method"),
            url: self.url.expect("sign request url"),
            body: self.body.expect("sign request body"),
        }
    }
}

/// Sign the request for a SigV4/HMAC secret and append the signature header,
/// routing through the bind-checked `endpoint.sign` (claim 12, key-never-leaves).
/// Fail-closed: a missing SigV4 binding, a bad request, or a refused/failed sign
/// returns `Err` and the caller forwards nothing.
pub(super) fn sign_into_headers(
    endpoint: &NetworkEndpoint<'_>,
    req: &SignRequest<'_>,
    headers: &mut Vec<(String, String)>,
) -> Result<(), ProxyError> {
    let SignRequest {
        placeholder,
        auth_type,
        dest,
        method,
        url,
        body,
    } = *req;
    match auth_type {
        AuthType::Sigv4 => {
            // The non-secret scope (access_key_id/region/service) is operator-set
            // in the binding and reconstructed onto the ref at admission. Absent
            // ⇒ fail closed: we can't name a credential to sign under.
            let params = endpoint
                .resolve_ref(placeholder)
                .and_then(|r| r.sigv4.clone())
                .ok_or_else(|| {
                    ProxyError::Refused(
                        "sigv4 secret missing access_key_id/region/service binding".into(),
                    )
                })?;
            // SigV4 signs `x-amz-date`. Use the guest's if present, else
            // synthesize one now (UTC) — and make sure it is on the outgoing
            // request so the signature matches what the destination verifies.
            let amz_date = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| {
                    let d = amz_date_now();
                    headers.push(("x-amz-date".to_string(), d.clone()));
                    d
                });
            // Build the canonical request over the headers we will actually send
            // (the placeholder header is already dropped; x-amz-date is present).
            // `build_sigv4_input` reads x-amz-date from this set.
            let _ = &amz_date;
            let input =
                build_sigv4_input(method, url, headers, body, &params.region, &params.service)
                    .map_err(|e| {
                        ProxyError::Refused(format!("building sigv4 canonical request: {e}"))
                    })?;
            let sig = endpoint.sign(placeholder, dest, &SigningInput::SigV4(input.clone()))?;
            let scope = input.credential_scope();
            let authorization = format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                params.access_key_id, scope, input.signed_headers, sig.hex
            );
            // Replace any existing Authorization, else add it. The secret-access-
            // key never appears here — only the derived signature hex.
            if let Some(slot) = headers
                .iter_mut()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            {
                slot.1 = authorization;
            } else {
                headers.push(("Authorization".to_string(), authorization));
            }
            Ok(())
        }
        AuthType::Hmac => {
            // HMAC webhook: sign the body, emit the signature in a documented
            // default header. The key never leaves the signer.
            let sig = endpoint.sign(
                placeholder,
                dest,
                &SigningInput::Hmac {
                    payload: body.to_vec(),
                },
            )?;
            if let Some(slot) = headers
                .iter_mut()
                .find(|(k, _)| k.eq_ignore_ascii_case("x-mvm-signature"))
            {
                slot.1 = sig.hex;
            } else {
                headers.push(("x-mvm-signature".to_string(), sig.hex));
            }
            Ok(())
        }
        // Inject types never reach the sign pass.
        AuthType::Bearer | AuthType::Basic => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crate::keyholder::{NetworkEndpoint, SubstitutionRegistry};
    use crate::supervisor::network_endpoint_proxy::test_support::{
        hmac_ref, resolver_with, sigv4_ref, sigv4_ref_no_params,
    };
    use crate::supervisor::network_endpoint_proxy::{ProxyError, ProxyRequest, prepare_request};

    /// Parse the structured fields of an `AWS4-HMAC-SHA256` Authorization value.
    fn parse_sigv4_authorization(v: &str) -> (String, String, String) {
        let rest = v.strip_prefix("AWS4-HMAC-SHA256 ").expect("scheme prefix");
        let mut credential = String::new();
        let mut signed_headers = String::new();
        let mut signature = String::new();
        for part in rest.split(", ") {
            if let Some(c) = part.strip_prefix("Credential=") {
                credential = c.to_string();
            } else if let Some(s) = part.strip_prefix("SignedHeaders=") {
                signed_headers = s.to_string();
            } else if let Some(s) = part.strip_prefix("Signature=") {
                signature = s.to_string();
            }
        }
        (credential, signed_headers, signature)
    }

    // The canonical AWS example secret-access-key — used as our seeded signing
    // key so the no-leak assertions have a distinctive string to grep for.
    const AWS_SECRET_ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    #[test]
    fn sigv4_request_gets_a_valid_authorization_header() {
        let (_dir, resolver) = resolver_with("aws", AWS_SECRET_ACCESS_KEY);
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(sigv4_ref(
            "aws",
            &["s3.us-east-1.amazonaws.com"],
            "s3",
            "us-east-1",
        ));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);

        // The guest puts the opaque placeholder in the Authorization header,
        // exactly like Bearer; the endpoint branches on the resolved auth_type.
        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://s3.us-east-1.amazonaws.com/bucket/key".into(),
            headers: vec![
                ("authorization".into(), ph.as_str().to_string()),
                ("host".into(), "s3.us-east-1.amazonaws.com".into()),
                ("x-amz-date".into(), "20150830T123600Z".into()),
            ],
            body: vec![],
        };
        let prepared = prepare_request(&endpoint, req).unwrap();

        let auth = prepared
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone())
            .expect("Authorization header produced");
        let (credential, signed_headers, signature) = parse_sigv4_authorization(&auth);
        assert!(
            credential.starts_with("AKIAIOSFODNN7EXAMPLE/20150830/us-east-1/s3/aws4_request"),
            "credential scope: {credential}"
        );
        assert!(
            signed_headers.contains("host"),
            "signed headers: {signed_headers}"
        );
        assert!(
            signed_headers.contains("x-amz-date"),
            "signed headers: {signed_headers}"
        );
        // 64 hex chars of HMAC-SHA256.
        assert_eq!(signature.len(), 64, "signature: {signature}");
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));

        // No-leak: the secret-access-key (signing key) appears NOWHERE in the
        // prepared request — not the Authorization header, not any other header,
        // not the body, and the opaque placeholder is gone too.
        for (k, v) in &prepared.headers {
            assert!(
                !v.contains(AWS_SECRET_ACCESS_KEY),
                "key leaked in header {k}: {v}"
            );
            assert!(
                !v.contains(ph.as_str()),
                "placeholder leaked in header {k}: {v}"
            );
        }
        assert!(
            !prepared
                .body
                .windows(AWS_SECRET_ACCESS_KEY.len())
                .any(|w| w == AWS_SECRET_ACCESS_KEY.as_bytes())
        );
    }

    #[test]
    fn sigv4_forward_path_matches_the_aws_get_vanilla_signature() {
        // End-to-end oracle: drive the published aws-sig-v4-test-suite
        // get-vanilla request through prepare_request and assert the assembled
        // Authorization carries the published signature — proves the forward
        // path's canonicalization + signing is byte-correct, not just well-shaped.
        let (_dir, resolver) = resolver_with("aws", AWS_SECRET_ACCESS_KEY);
        let mut reg = SubstitutionRegistry::new();
        // get-vanilla scope: region=us-east-1, service="service".
        let ph = reg.mint(sigv4_ref(
            "aws",
            &["example.amazonaws.com"],
            "service",
            "us-east-1",
        ));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://example.amazonaws.com/".into(),
            headers: vec![
                ("authorization".into(), ph.as_str().to_string()),
                ("host".into(), "example.amazonaws.com".into()),
                ("x-amz-date".into(), "20150830T123600Z".into()),
            ],
            body: vec![],
        };
        let prepared = prepare_request(&endpoint, req).unwrap();
        let auth = prepared
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone())
            .unwrap();
        let (_, _, signature) = parse_sigv4_authorization(&auth);
        assert_eq!(
            signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn sigv4_unbound_destination_is_refused_before_signing() {
        // The key security test: a sigv4 placeholder bound to host A, sent to
        // host B (not in allowed_hosts), is refused by the bind-check inside
        // `endpoint.sign` BEFORE any signature is produced. No Authorization.
        let (_dir, resolver) = resolver_with("aws", AWS_SECRET_ACCESS_KEY);
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(sigv4_ref(
            "aws",
            &["s3.us-east-1.amazonaws.com"], // bound to host A only
            "s3",
            "us-east-1",
        ));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://evil.example.com/bucket/key".into(), // host B — unbound
            headers: vec![
                ("authorization".into(), ph.as_str().to_string()),
                ("host".into(), "evil.example.com".into()),
                ("x-amz-date".into(), "20150830T123600Z".into()),
            ],
            body: vec![],
        };
        let err = prepare_request(&endpoint, req).unwrap_err();
        assert!(
            matches!(
                err,
                ProxyError::Sign(crate::keyholder::SignDispatchError::DestinationNotBound(_))
            ),
            "expected a bind-check refusal, got {err:?}"
        );
    }

    #[test]
    fn sigv4_without_params_is_refused() {
        // A sigv4 secret with no access_key_id/region/service binding can't be
        // signed — fail closed rather than forward an unsigned request.
        let (_dir, resolver) = resolver_with("aws", AWS_SECRET_ACCESS_KEY);
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(sigv4_ref_no_params("aws", &["s3.us-east-1.amazonaws.com"]));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);

        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://s3.us-east-1.amazonaws.com/bucket/key".into(),
            headers: vec![
                ("authorization".into(), ph.as_str().to_string()),
                ("host".into(), "s3.us-east-1.amazonaws.com".into()),
                ("x-amz-date".into(), "20150830T123600Z".into()),
            ],
            body: vec![],
        };
        let err = prepare_request(&endpoint, req).unwrap_err();
        assert!(matches!(err, ProxyError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn sigv4_synthesizes_x_amz_date_when_absent() {
        // When the guest omits x-amz-date, the endpoint synthesizes one and adds
        // it to the outgoing request so the signature it computes matches.
        let (_dir, resolver) = resolver_with("aws", AWS_SECRET_ACCESS_KEY);
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(sigv4_ref(
            "aws",
            &["s3.us-east-1.amazonaws.com"],
            "s3",
            "us-east-1",
        ));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "GET".into(),
            url: "https://s3.us-east-1.amazonaws.com/x".into(),
            headers: vec![
                ("authorization".into(), ph.as_str().to_string()),
                ("host".into(), "s3.us-east-1.amazonaws.com".into()),
            ],
            body: vec![],
        };
        let prepared = prepare_request(&endpoint, req).unwrap();
        let amz = prepared
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
            .map(|(_, v)| v.clone())
            .expect("x-amz-date synthesized");
        // yyyymmddThhmmssZ — 16 chars.
        assert_eq!(amz.len(), 16, "amz date: {amz}");
        assert!(amz.contains('T') && amz.ends_with('Z'));
    }

    #[test]
    fn hmac_request_gets_a_signature_header() {
        // RFC 4231 case 2: key="Jefe", body="what do ya want for nothing?".
        let (_dir, resolver) = resolver_with("hook", "Jefe");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(hmac_ref("hook", &["hooks.example.com"]));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://hooks.example.com/event".into(),
            headers: vec![("x-sig".into(), ph.as_str().to_string())],
            body: b"what do ya want for nothing?".to_vec(),
        };
        let prepared = prepare_request(&endpoint, req).unwrap();
        let sig = prepared
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-mvm-signature"))
            .map(|(_, v)| v.clone())
            .expect("x-mvm-signature produced");
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // No-leak: the signing key ("Jefe") and the placeholder are both gone.
        for (k, v) in &prepared.headers {
            assert!(!v.contains("Jefe"), "key leaked in header {k}");
            assert!(!v.contains(ph.as_str()), "placeholder leaked in header {k}");
        }
    }

    #[test]
    fn hmac_unbound_destination_is_refused_before_signing() {
        let (_dir, resolver) = resolver_with("hook", "Jefe");
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(hmac_ref("hook", &["hooks.example.com"]));
        let endpoint = NetworkEndpoint::new(&reg, &resolver);
        let req = ProxyRequest {
            method: "POST".into(),
            url: "https://evil.example.com/event".into(), // unbound
            headers: vec![("x-sig".into(), ph.as_str().to_string())],
            body: b"x".to_vec(),
        };
        let err = prepare_request(&endpoint, req).unwrap_err();
        assert!(
            matches!(
                err,
                ProxyError::Sign(crate::keyholder::SignDispatchError::DestinationNotBound(_))
            ),
            "expected a bind-check refusal, got {err:?}"
        );
    }
}
