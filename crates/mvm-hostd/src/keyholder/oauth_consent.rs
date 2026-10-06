//! The protocol half of a host-browser OAuth consent.
//!
//! A human consents in a browser on the host, never inside a guest: the
//! session the consent creates, and the refresh token it yields, would
//! otherwise sit in guest memory where the workload can read it and every
//! snapshot or warm fork would copy it. Here the host runs the
//! authorization-code grant (RFC 6749 §4.1) as a native public client
//! (RFC 8252): the redirect comes back to a loopback listener on the host, the
//! code is bound to the authorization request by a PKCE S256 verifier
//! (RFC 7636) and the request is bound to the redirect by an unguessable
//! `state`, and the resulting token set is stored in the encrypted secret
//! store like any other OAuth binding.
//!
//! This module owns the parts that need no socket: the verifier and its
//! challenge, the authorization request URL, and the judgement of a redirect.
//! The listener and the orchestration live with the secret service, which is
//! where an operator's login command reaches them.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mvm_core::crypto::constant_time::constant_time_eq;
use mvm_core::crypto::secret_binding::OAuthBindingMeta;
use sha2::{Digest, Sha256};

use super::oauth::require_https_endpoint;
use super::resolver::OAuthSecretString;

/// The loopback redirect path. Fixed, so a request for anything else (a
/// browser's favicon fetch, a stray probe) is not mistaken for the callback.
pub const REDIRECT_PATH: &str = "/callback";

/// Random bytes behind each verifier and `state`. 32 bytes encode to the
/// 43-character minimum RFC 7636 §4.1 allows and carry 256 bits of entropy.
const RANDOM_BYTES: usize = 32;

/// Longest `error` code from a refused consent that is echoed back. The code
/// is attacker-influenced text from the redirect, so it is shortened and
/// restricted to the RFC 6749 §4.1.2.1 character set before anyone sees it.
const MAX_ERROR_CODE_LEN: usize = 64;

fn random_url_safe() -> String {
    let bytes: [u8; RANDOM_BYTES] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A PKCE code verifier (RFC 7636 §4.1): the secret half of the proof that the
/// party redeeming a code is the one that asked for it. Never printed.
pub struct PkceVerifier(OAuthSecretString);

impl PkceVerifier {
    /// A fresh verifier from the OS-seeded CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self(OAuthSecretString::from(random_url_safe()))
    }

    /// A verifier with a known value. Refuses anything outside RFC 7636 §4.1:
    /// 43 to 128 characters of `[A-Za-z0-9-._~]`.
    pub fn from_value(value: &str) -> anyhow::Result<Self> {
        let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~');
        if !(43..=128).contains(&value.len()) || !value.chars().all(valid_char) {
            anyhow::bail!("a PKCE verifier is 43 to 128 characters of [A-Za-z0-9-._~]");
        }
        Ok(Self(OAuthSecretString::from(value.to_owned())))
    }

    /// `BASE64URL(SHA256(verifier))`, the S256 challenge (RFC 7636 §4.2).
    #[must_use]
    pub fn s256_challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.0.expose_secret().as_bytes()))
    }

    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

/// Why a redirect was not accepted as this login's callback.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedirectRefusal {
    #[error("the request is not for the login callback path")]
    NotTheCallback,
    #[error("the callback carried no `state`; refusing it")]
    MissingState,
    #[error(
        "the callback's `state` does not match this login's; refusing it as forged or from another login"
    )]
    StateMismatch,
    #[error("the authorization server did not grant consent: `{0}`")]
    Denied(String),
    #[error("the callback carried no authorization code")]
    MissingCode,
}

/// One authorization request: its verifier, its `state`, and the loopback
/// redirect it names. Built per login and consumed by the code exchange.
pub struct ConsentRequest {
    verifier: PkceVerifier,
    state: String,
    redirect_uri: String,
    authorization_url: String,
}

impl ConsentRequest {
    /// An authorization request for `meta` whose redirect is the loopback
    /// listener on `port`. The redirect names the IPv4 loopback literal rather
    /// than `localhost` (RFC 8252 §7.3 and §8.3): a name could resolve
    /// somewhere else, and the listener is bound to that literal only.
    pub fn new(meta: &OAuthBindingMeta, port: u16) -> anyhow::Result<Self> {
        Self::with_verifier(meta, port, PkceVerifier::generate())
    }

    fn with_verifier(
        meta: &OAuthBindingMeta,
        port: u16,
        verifier: PkceVerifier,
    ) -> anyhow::Result<Self> {
        require_https_endpoint("authorization_url", &meta.authorization_url)?;
        let state = random_url_safe();
        let redirect_uri = format!("http://127.0.0.1:{port}{REDIRECT_PATH}");
        let mut url = url::Url::parse(&meta.authorization_url)?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &meta.client_id)
                .append_pair("redirect_uri", &redirect_uri);
            if !meta.scopes.is_empty() {
                query.append_pair("scope", &meta.scopes.join(" "));
            }
            query
                .append_pair("state", &state)
                .append_pair("code_challenge", &verifier.s256_challenge())
                .append_pair("code_challenge_method", "S256");
        }
        Ok(Self {
            verifier,
            state,
            redirect_uri,
            authorization_url: url.into(),
        })
    }

    /// The URL the human opens to consent.
    #[must_use]
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Judge one request that reached the loopback listener. `request_target`
    /// is the HTTP request target (`/callback?code=…&state=…`).
    ///
    /// The `state` is checked before anything else the redirect says, error
    /// responses included: a callback this login did not start is refused
    /// whatever it carries.
    pub fn accept_redirect(
        &self,
        request_target: &str,
    ) -> Result<OAuthSecretString, RedirectRefusal> {
        let base =
            url::Url::parse("http://127.0.0.1/").map_err(|_| RedirectRefusal::NotTheCallback)?;
        let url = base
            .join(request_target)
            .map_err(|_| RedirectRefusal::NotTheCallback)?;
        if url.path() != REDIRECT_PATH {
            return Err(RedirectRefusal::NotTheCallback);
        }
        let mut state = None;
        let mut code = None;
        let mut error = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "state" => state = Some(value.into_owned()),
                "code" => code = Some(OAuthSecretString::from(value.into_owned())),
                "error" => error = Some(value.into_owned()),
                _ => {}
            }
        }
        let state = state.ok_or(RedirectRefusal::MissingState)?;
        // Constant time: a local process can send the listener as many guesses
        // as it likes, so a comparison that stopped at the first wrong byte
        // would tell it how much of the state it had right.
        if !constant_time_eq(state.as_bytes(), self.state.as_bytes()) {
            return Err(RedirectRefusal::StateMismatch);
        }
        if let Some(error) = error {
            return Err(RedirectRefusal::Denied(sanitize_error_code(&error)));
        }
        code.filter(|code| !code.expose_secret().is_empty())
            .ok_or(RedirectRefusal::MissingCode)
    }

    /// The code exchange this request authorizes: the code the redirect
    /// returned, with this request's verifier and redirect.
    #[must_use]
    pub fn into_grant(self, code: OAuthSecretString) -> AuthorizationCodeGrant {
        AuthorizationCodeGrant {
            code,
            redirect_uri: self.redirect_uri,
            code_verifier: self.verifier,
        }
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> &str {
        &self.state
    }
}

/// Keep an `error` code to the RFC 6749 §4.1.2.1 character set and a bounded
/// length; anything else is replaced, so the text reaching a terminal or an
/// audit entry is never the redirect's raw bytes.
fn sanitize_error_code(error: &str) -> String {
    error
        .chars()
        .take(MAX_ERROR_CODE_LEN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// An authorization code ready to redeem, with the verifier and redirect the
/// token endpoint checks it against. Never printed.
pub struct AuthorizationCodeGrant {
    code: OAuthSecretString,
    redirect_uri: String,
    code_verifier: PkceVerifier,
}

impl AuthorizationCodeGrant {
    #[must_use]
    pub fn code(&self) -> &str {
        self.code.expose_secret()
    }

    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    #[must_use]
    pub fn code_verifier(&self) -> &str {
        self.code_verifier.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> OAuthBindingMeta {
        OAuthBindingMeta {
            authorization_url: "https://auth.example.com/authorize?audience=api".into(),
            token_url: "https://auth.example.com/token".into(),
            client_id: "public-client-id".into(),
            scopes: vec!["read".into(), "write all".into()],
            response_access_token_pointer: None,
        }
    }

    /// RFC 7636 Appendix B.
    #[test]
    fn s256_challenge_matches_the_rfc_7636_test_vector() {
        let verifier =
            PkceVerifier::from_value("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        assert_eq!(
            verifier.s256_challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_verifiers_are_valid_and_distinct() {
        let a = PkceVerifier::generate();
        let b = PkceVerifier::generate();
        assert_eq!(a.expose_secret().len(), 43);
        assert!(PkceVerifier::from_value(a.expose_secret()).is_ok());
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn from_value_refuses_a_verifier_outside_rfc_7636() {
        for bad in ["short", &"a".repeat(129), &format!("{}!", "a".repeat(43))] {
            assert!(PkceVerifier::from_value(bad).is_err(), "{bad}");
        }
    }

    fn query(url: &str) -> std::collections::BTreeMap<String, String> {
        url::Url::parse(url)
            .unwrap()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn the_authorization_request_carries_pkce_state_and_a_loopback_redirect() {
        let verifier =
            PkceVerifier::from_value("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        let request = ConsentRequest::with_verifier(&meta(), 49152, verifier).unwrap();
        let url = url::Url::parse(request.authorization_url()).unwrap();
        assert_eq!(url.host_str(), Some("auth.example.com"));
        assert_eq!(url.path(), "/authorize");
        let query = query(request.authorization_url());
        // The provider's own parameters are kept.
        assert_eq!(query["audience"], "api");
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], "public-client-id");
        assert_eq!(query["redirect_uri"], "http://127.0.0.1:49152/callback");
        assert_eq!(query["scope"], "read write all");
        assert_eq!(query["state"], request.state());
        assert_eq!(
            query["code_challenge"],
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(query["code_challenge_method"], "S256");
        // The verifier itself never goes to the authorization endpoint.
        assert!(
            !request
                .authorization_url()
                .contains("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        );
        assert_eq!(request.redirect_uri(), "http://127.0.0.1:49152/callback");
    }

    #[test]
    fn each_request_gets_its_own_state() {
        let a = ConsentRequest::new(&meta(), 1).unwrap();
        let b = ConsentRequest::new(&meta(), 1).unwrap();
        assert_ne!(a.state(), b.state());
        assert_eq!(a.state().len(), 43);
    }

    #[test]
    fn a_cleartext_authorization_endpoint_is_refused() {
        let mut meta = meta();
        meta.authorization_url = "http://auth.example.com/authorize".into();
        let err = ConsentRequest::new(&meta, 1).err().unwrap();
        assert!(format!("{err:#}").contains("https"), "{err:#}");
    }

    #[test]
    fn the_matching_callback_yields_its_code() {
        let request = ConsentRequest::new(&meta(), 1).unwrap();
        let target = format!("/callback?code=the-code&state={}", request.state());
        let code = request.accept_redirect(&target).unwrap();
        assert_eq!(code.expose_secret(), "the-code");
    }

    #[test]
    fn a_mismatched_state_is_refused_even_with_a_code() {
        let request = ConsentRequest::new(&meta(), 1).unwrap();
        assert_eq!(
            request
                .accept_redirect("/callback?code=the-code&state=forged")
                .err(),
            Some(RedirectRefusal::StateMismatch)
        );
        assert_eq!(
            request.accept_redirect("/callback?code=the-code").err(),
            Some(RedirectRefusal::MissingState)
        );
    }

    #[test]
    fn a_forged_error_callback_is_a_state_mismatch_not_a_denial() {
        let request = ConsentRequest::new(&meta(), 1).unwrap();
        assert_eq!(
            request
                .accept_redirect("/callback?error=access_denied&state=forged")
                .err(),
            Some(RedirectRefusal::StateMismatch)
        );
    }

    #[test]
    fn a_denied_consent_reports_a_sanitized_error_code() {
        let request = ConsentRequest::new(&meta(), 1).unwrap();
        let target = format!(
            "/callback?error=access_denied%1b%5b31m&state={}",
            request.state()
        );
        assert_eq!(
            request.accept_redirect(&target).err(),
            Some(RedirectRefusal::Denied("access_denied??31m".to_owned()))
        );
    }

    #[test]
    fn a_callback_without_a_code_is_refused() {
        let request = ConsentRequest::new(&meta(), 1).unwrap();
        for target in [
            format!("/callback?state={}", request.state()),
            format!("/callback?code=&state={}", request.state()),
        ] {
            assert_eq!(
                request.accept_redirect(&target).err(),
                Some(RedirectRefusal::MissingCode)
            );
        }
    }

    #[test]
    fn requests_for_other_paths_are_not_the_callback() {
        let request = ConsentRequest::new(&meta(), 1).unwrap();
        let state = request.state().to_owned();
        for target in [
            "/favicon.ico".to_owned(),
            format!("/callbackx?code=c&state={state}"),
            format!("/other/callback?code=c&state={state}"),
        ] {
            assert_eq!(
                request.accept_redirect(&target).err(),
                Some(RedirectRefusal::NotTheCallback),
                "{target}"
            );
        }
    }

    #[test]
    fn the_grant_carries_the_requests_verifier_and_redirect() {
        let verifier =
            PkceVerifier::from_value("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        let request = ConsentRequest::with_verifier(&meta(), 50000, verifier).unwrap();
        let grant = request.into_grant(OAuthSecretString::from("the-code".to_owned()));
        assert_eq!(grant.code(), "the-code");
        assert_eq!(grant.redirect_uri(), "http://127.0.0.1:50000/callback");
        assert_eq!(
            grant.code_verifier(),
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
    }
}
