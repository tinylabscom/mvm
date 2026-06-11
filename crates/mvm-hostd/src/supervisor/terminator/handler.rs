//! The host-testable substitution core for one redirected connection: parse the
//! raw request, run it through the existing substitution stack (claim-12
//! bind-checked), forward to the real destination, return the response bytes.
//! The TcpStream/SO_ORIGINAL_DST glue lives in the listener (a later task) so
//! this core stays unit-testable off-Linux.

use anyhow::Result;
use std::net::SocketAddr;

use super::error::TerminatorError;
use super::request::proxy_request_from_origin_form;
use crate::keyholder::substitution::SubstitutionEndpoint;
use crate::supervisor::network::stages::{RedactingSubstitution, RedactionHits};
use crate::supervisor::substitution_proxy::{
    PreparedRequest, fail_closed_reason, prepare_request, redact_request,
};
use mvm_core::policy::RedactionAction;

/// Parse `raw` (origin-form HTTP), mask undeclared secret/PII content against
/// the destination `action` (the same redaction the vsock `process` path runs),
/// substitute declared placeholders against `endpoint` (refuses an unbound
/// destination / unknown placeholder BEFORE forwarding — claim 12), then call
/// `forward` with the prepared request and `orig_dst`. Returns the raw response
/// bytes plus the redaction categories that fired (for the caller's audit).
///
/// The result is typed ([`TerminatorError`]) so the caller can tell a claim-12
/// refusal (`Refused`) from a fail-closed gate (`FailClosed`), a parse, or a
/// forward failure and audit accordingly. **Every error path closes the socket
/// without forwarding un-substituted / un-redacted bytes** — fail-closed.
pub fn handle_request<F>(
    raw: &[u8],
    orig_dst: SocketAddr,
    endpoint: &SubstitutionEndpoint<'_>,
    redactor: &RedactingSubstitution,
    action: &RedactionAction,
    forward: F,
) -> Result<(Vec<u8>, RedactionHits), TerminatorError>
where
    F: Fn(&PreparedRequest, SocketAddr) -> Result<Vec<u8>>,
{
    let mut req = proxy_request_from_origin_form(raw, orig_dst)
        .map_err(|e| TerminatorError::Parse(e.to_string()))?;
    // Fail closed BEFORE masking/substitution: a body we can't scan in cleartext
    // (compressed / over-cap) to a redaction-opted-in destination is a silent
    // bypass, so refuse it rather than forward it unscanned.
    if let Some(reason) = fail_closed_reason(&req.headers, req.body.len(), action) {
        return Err(TerminatorError::FailClosed(reason));
    }
    // Mask undeclared secret/PII first so a declared placeholder (host-reserved,
    // not secret-shaped) survives to be substituted, while undeclared secrets in
    // any other header or the body are masked and never reach the wire.
    let hits = redact_request(&mut req, redactor, action);
    let prepared =
        prepare_request(endpoint, req).map_err(|e| TerminatorError::Refused(e.to_string()))?;
    let resp = forward(&prepared, orig_dst).map_err(|e| TerminatorError::Forward(e.to_string()))?;
    Ok((resp, hits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SubstitutionRegistry};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_sdk::ir::{AuthType, SecretMount, SecretRef};
    use secrecy::SecretBox;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        }
    }

    /// The default redactor (curated rules) most tests pass — declared
    /// placeholders survive, undeclared secret/PII content is masked.
    fn default_redactor() -> RedactingSubstitution {
        RedactingSubstitution::with_default_rules()
    }

    /// Build a `(registry, resolver, _dir)` with one bearer secret `name`=`value`
    /// bound to `hosts`, and a minted placeholder ready to embed in requests.
    /// Returns `(registry, resolver, placeholder_string, _tempdir)`.
    fn setup(
        name: &str,
        value: &str,
        hosts: &[&str],
    ) -> (
        SubstitutionRegistry,
        LocalResolver,
        String,
        tempfile::TempDir,
    ) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put("local", name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        let resolver = LocalResolver::new("local", store);
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref(name, hosts)).as_str().to_string();
        (reg, resolver, ph, dir)
    }

    #[test]
    fn substitutes_placeholder_and_returns_forward_response() {
        let (reg, resolver, ph, _dir) = setup("openai", "REALTOKEN", &["api.openai.com"]);
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let raw = format!(
            "GET /v1/x HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer {ph}\r\n\r\n"
        );
        let canned = b"HTTP/1.1 200 OK\r\n\r\n";
        let captured: Arc<Mutex<Option<PreparedRequest>>> = Arc::new(Mutex::new(None));
        let cap = Arc::clone(&captured);

        let orig_dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 80));

        let redactor = default_redactor();
        let action = RedactionAction::default();
        let (resp, _hits) = handle_request(
            raw.as_bytes(),
            orig_dst,
            &endpoint,
            &redactor,
            &action,
            |prepared, _dst| {
                *cap.lock().unwrap() = Some(prepared.clone());
                Ok(canned.to_vec())
            },
        )
        .unwrap();

        // (1) placeholder was substituted to the real token.
        let seen = captured.lock().unwrap().clone().unwrap();
        let auth = seen
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        assert_eq!(auth, "Bearer REALTOKEN");

        // (2) handle_request returned the canned response bytes.
        assert_eq!(resp, canned);
    }

    #[test]
    fn unknown_placeholder_errors_before_forwarding() {
        // An empty registry — no placeholder is known.
        let reg = SubstitutionRegistry::new();
        let dir = tempdir().unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(FileSecretStore::with_dir(dir.path()));
        let resolver = LocalResolver::new("local", store);
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        // Embed a made-up placeholder token the registry never minted.
        let raw = b"GET /v1/x HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer mvm-secret-deadbeefdeadbeefdeadbeef\r\n\r\n";
        let orig_dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 80));

        let forward_called = Arc::new(Mutex::new(false));
        let fc = Arc::clone(&forward_called);

        let redactor = default_redactor();
        let action = RedactionAction::default();
        let result = handle_request(
            raw,
            orig_dst,
            &endpoint,
            &redactor,
            &action,
            |_prepared, _dst| {
                *fc.lock().unwrap() = true;
                Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
            },
        );

        assert!(
            matches!(result, Err(TerminatorError::Refused(_))),
            "expected Refused for unknown placeholder, got {result:?}"
        );
        assert!(
            !*forward_called.lock().unwrap(),
            "forward must not be called when substitution is refused"
        );
    }

    #[test]
    fn unbound_destination_errors_before_forwarding() {
        // A valid placeholder, but the request goes to a host NOT in allowed_hosts.
        let (reg, resolver, ph, _dir) = setup("openai", "REALTOKEN", &["api.openai.com"]);
        let endpoint = SubstitutionEndpoint::new(&reg, &resolver);

        let raw = format!(
            "GET /x HTTP/1.1\r\nhost: evil.example.com\r\nauthorization: Bearer {ph}\r\n\r\n"
        );
        let orig_dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 80));

        let forward_called = Arc::new(Mutex::new(false));
        let fc = Arc::clone(&forward_called);

        let redactor = default_redactor();
        let action = RedactionAction::default();
        let result = handle_request(
            raw.as_bytes(),
            orig_dst,
            &endpoint,
            &redactor,
            &action,
            |_prepared, _dst| {
                *fc.lock().unwrap() = true;
                Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
            },
        );

        assert!(
            matches!(result, Err(TerminatorError::Refused(_))),
            "expected Refused for unbound destination, got {result:?}"
        );
        assert!(
            !*forward_called.lock().unwrap(),
            "forward must not be called when substitution is refused"
        );
    }
}
