//! Host substitution endpoint: request preparation.
//!
//! The guest's SDK client routes a secret-bearing request to this host-local
//! endpoint carrying an opaque placeholder. `prepare_request` is the
//! security-critical core: it locates the placeholder in each header, resolves
//! it against the session registry, binding-checks the request's destination
//! (claim 12), and substitutes the real credential — yielding a request ready
//! for the host to make the real TLS to the destination (the forward leg,
//! a separate transport step).
//!
//! Substitution happens HERE, on the host, never in the guest: the guest only
//! ever held the opaque placeholder. The prepared request carries the real
//! credential because it must reach the wire — the confinement is that this
//! host component is the only place it exists in the clear.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::net::{UnixListener, UnixStream};
use url::Url;
use zeroize::Zeroizing;

use mvm_contract::ir::AuthType;
use mvm_core::observability::instance_metrics::{
    InstanceLabels, InstanceMetricsRegistry, global as instance_metrics_global,
};
use mvm_core::plan::SecretBinding;
use mvm_core::policy::audit::ai_usage::AiUsageRecord;
use mvm_core::substitution_wire::{WireRequest, WireResponse};

use crate::framing::{FrameError, read_json_frame, write_json_frame};
use crate::keyholder::{
    AssembleError, BindingStore, HandedPlaceholders, NetworkEndpoint, SecretResolver,
    SignDispatchError, SigningInput, SubstituteError, SubstitutionRegistry, assemble_registry,
    build_sigv4_input, find_placeholder,
};
use crate::supervisor::accept_loop::{
    AcceptAction, classify_accept_error, record_listener_stopped,
};
use crate::supervisor::ai_meter;
use crate::supervisor::audit_recorder::{EventCategory, Recorder};
use crate::supervisor::network::stages::{RedactingSubstitution, RedactionHits};
use crate::supervisor::reversible_replacement::{
    ReplacementEngine, ReplacementFlow, StreamingReinjector,
};
use crate::supervisor::secret_audit::{
    emit_rewrite_proof, emit_secret_placeholder_dropped, emit_secret_redacted,
    emit_secret_substituted,
};
use crate::supervisor::tools::http_hardening::hardened_client_builder_via;
pub use mvm_contract::substitution::{
    PrepareError, PreparedRequest, ProxyRequest, SubstitutionDriver,
    prepare_request as prepare_request_core,
};

/// 16 MiB cap on a single routed request/response frame.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// The response body must fit inside the bounded guest-facing response frame.
const MAX_FORWARD_RESPONSE_BYTES: usize = MAX_FRAME_BYTES;
/// Typed FlowMux request ceiling, independent of transport frame size.
const MAX_HTTP_STREAM_BODY_BYTES: usize = 32 * 1024 * 1024;
const HTTP_REQUEST_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(not(target_os = "linux"))]
const RVPROXY_ORIGINAL_DST_MAGIC: &[u8; 8] = b"RVPXOD01";

fn recover_terminator_original_destination(
    stream: &mut std::net::TcpStream,
) -> anyhow::Result<std::net::SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        Ok(crate::supervisor::terminator::orig_dst::original_dst(
            stream,
        )?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::io::Read;

        let mut header = [0_u8; 14];
        stream.read_exact(&mut header)?;
        anyhow::ensure!(
            &header[..8] == RVPROXY_ORIGINAL_DST_MAGIC,
            "invalid original-destination preamble"
        );
        let ip = std::net::Ipv4Addr::new(header[8], header[9], header[10], header[11]);
        let port = u16::from_be_bytes([header[12], header[13]]);
        Ok(std::net::SocketAddr::from((ip, port)))
    }
}

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
            .substitute(placeholder, destination, text)
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

/// `yyyymmddThhmmssZ` UTC, the SigV4 `x-amz-date` format.
fn amz_date_now() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// The request to sign, under one signing credential. Borrowed — built once per
/// request just before [`sign_into_headers`]. `placeholder` names the SigV4/HMAC
/// secret (its header value was already dropped); `dest` is the bound destination
/// host; `method`/`url`/`body` are the request line and payload that get signed.
#[derive(Clone, Copy)]
struct SignRequest<'a> {
    placeholder: &'a str,
    auth_type: AuthType,
    dest: &'a str,
    method: &'a str,
    url: &'a str,
    body: &'a [u8],
}

impl<'a> SignRequest<'a> {
    fn builder() -> SignRequestBuilder<'a> {
        SignRequestBuilder::default()
    }
}

/// Builder for [`SignRequest`]: one setter per field, `build()` returns the
/// value. Every field is required; `build()` panics if a setter was skipped,
/// which is unreachable from the single internal call site that sets them all.
#[derive(Default)]
struct SignRequestBuilder<'a> {
    placeholder: Option<&'a str>,
    auth_type: Option<AuthType>,
    dest: Option<&'a str>,
    method: Option<&'a str>,
    url: Option<&'a str>,
    body: Option<&'a [u8]>,
}

impl<'a> SignRequestBuilder<'a> {
    fn with_placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = Some(placeholder);
        self
    }
    fn with_auth_type(mut self, auth_type: AuthType) -> Self {
        self.auth_type = Some(auth_type);
        self
    }
    fn with_dest(mut self, dest: &'a str) -> Self {
        self.dest = Some(dest);
        self
    }
    fn with_method(mut self, method: &'a str) -> Self {
        self.method = Some(method);
        self
    }
    fn with_url(mut self, url: &'a str) -> Self {
        self.url = Some(url);
        self
    }
    fn with_body(mut self, body: &'a [u8]) -> Self {
        self.body = Some(body);
        self
    }
    fn build(self) -> SignRequest<'a> {
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
fn sign_into_headers(
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
/// `resolve_meta` touches no secret value, so this is claim-13 safe. Shared by
/// the UDS/vsock `process` path and the terminator path so their two audit
/// emissions can't drift.
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

/// Mask undeclared secret/PII content in `req` per the destination `action`,
/// leaving declared placeholders intact (they're substituted next). Returns the
/// categories that fired. Shared by the vsock/UDS `process` path and both
/// terminator cores so they scrub identically — one definition, no drift.
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

/// A detector violated the validated-span contract. No matched bytes or
/// dependency error text cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("sensitive-data detector failed closed")]
pub(crate) struct SensitiveDetectionError;

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

/// Whether the policy's catch-all action explicitly opts every destination
/// into inspection beyond the curated baseline. `RedactionAction::default()`
/// remains compatible with ordinary opaque relay; it is applied when a caller
/// deliberately chooses the typed HTTP class. Non-default detector modes are
/// an admitted requirement and therefore make opaque relay dishonest.
fn explicit_default_redaction(action: &mvm_core::policy::RedactionAction) -> bool {
    !matches!(action.entropy, mvm_core::policy::EntropyMode::Off)
        || !matches!(action.names, mvm_core::policy::NameMode::Off)
        || action.pii.mode.is_some()
        || !matches!(action.secrets, mvm_core::policy::SecretAction::Block)
}

#[cfg(test)]
mod redaction_category_tests {
    use super::redaction_categories;
    use crate::supervisor::network::stages::RedactionHits;

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

/// The fail-closed scan-gate the cleartext cores run before substitute/forward:
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

// ============================================================================
// Transport — the host-local listener + the real-TLS forward leg (D-T2)
// ============================================================================

// The wire envelope (`WireRequest`/`WireResponse`) lives in
// `mvm_core::substitution_wire` so the in-guest client and this server share
// one contract (imported at the top of this file).

/// The response from the real destination.
pub struct ForwardResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A real-destination response whose decoded body is delivered incrementally.
///
/// The bounded receiver makes backpressure part of the type: the upstream
/// reader cannot outrun the FlowMux writer by more than four HTTP chunks.
pub struct ForwardStreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body_len: Option<u64>,
    pub body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, ForwardError>>,
}

/// Errors from the forward leg.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("forward failed: {0}")]
    Failed(String),
}

fn check_forward_response_length(length: Option<u64>) -> Result<(), ForwardError> {
    if length.is_some_and(|length| length > MAX_FORWARD_RESPONSE_BYTES as u64) {
        return Err(ForwardError::Failed(format!(
            "response body exceeds the {MAX_FORWARD_RESPONSE_BYTES} byte limit"
        )));
    }
    Ok(())
}

/// Errors from building a [`SubstitutionService`] from an admitted plan.
#[derive(Debug, thiserror::Error)]
pub enum FromPlanError {
    #[error(transparent)]
    Assemble(#[from] AssembleError),
    #[error(transparent)]
    Forward(#[from] ForwardError),
}

/// Inputs to [`SubstitutionService::from_plan`] — the admitted plan's secret
/// bindings plus the host substrate (stores, redaction, optional TLS
/// intermediate, optional audit recorder) the per-VM endpoint assembles from.
pub struct FromPlanInputs<'a> {
    pub plan_secrets: &'a [SecretBinding],
    pub tenant: &'a str,
    /// VM instance identifier used to attribute AI egress metrics and audit
    /// records. An empty string means the endpoint has no instance context.
    pub instance_id: &'a str,
    pub bindings: &'a dyn BindingStore,
    /// The value resolver the service resolves each bound secret through. Built
    /// by the caller (`assemble`) from `EndpointConfig.resolver`: a
    /// [`LocalResolver`] over the host secret store (default), or a
    /// [`crate::keyholder::RemoteResolver`] dialing a fleet-secrets daemon UDS.
    pub resolver: Arc<dyn SecretResolver>,
    pub forward_timeout_secs: u64,
    /// Operator-configured upstream proxy for the forward leg, if the host
    /// force-tunnels its egress. `None` dials destinations directly.
    pub proxy: Option<mvm_http::ProxyConfig>,
    pub redaction: mvm_core::policy::RedactionPolicy,
    pub reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy,
    pub tls_intermediate: Option<mvm_core::crypto::egress_ca::VmIntermediate>,
    pub recorder: Option<Recorder>,
    /// Per-VM AI egress metering/budget policy. `None` means AI egress is not
    /// metered and no budget is enforced.
    pub ai_policy: Option<mvm_contract::policy::network_policy::AiPolicy>,
}

/// Forwards a prepared (credential-substituted) request to the real
/// destination and returns its response — the real-TLS leg of the endpoint.
/// A trait so the listener can be tested with a mock that records the
/// credential it received without a network call.
#[async_trait]
pub trait Forwarder: Send + Sync {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError>;

    /// Forward with a bounded incremental response body.
    ///
    /// Test doubles and compatibility forwarders get a safe buffered adapter;
    /// the production forwarder overrides this and reads the upstream socket
    /// only as the receiver makes room.
    async fn forward_stream(
        &self,
        req: PreparedRequest,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        let response = self.forward(req).await?;
        let body_len = Some(response.body.len() as u64);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(Ok(response.body))
            .await
            .map_err(|_| ForwardError::Failed("response consumer closed".into()))?;
        Ok(ForwardStreamResponse {
            status: response.status,
            headers: response.headers,
            body_len,
            body: receiver,
        })
    }

    /// Forward a request whose body arrives through a bounded channel.
    ///
    /// The default adapter is for test doubles: it preserves their existing
    /// whole-request assertions while enforcing the production body ceiling.
    /// The production forwarder overrides it and writes chunks directly to the
    /// upstream socket.
    async fn forward_body_stream(
        &self,
        mut req: PreparedRequest,
        mut body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        let mut collected = Vec::new();
        while let Some(next) = body.recv().await {
            let chunk = next.map_err(ForwardError::Failed)?;
            if collected.len().saturating_add(chunk.len()) > MAX_FORWARD_RESPONSE_BYTES {
                return Err(ForwardError::Failed(format!(
                    "request body exceeds the {MAX_FORWARD_RESPONSE_BYTES} byte limit"
                )));
            }
            collected.extend_from_slice(&chunk);
        }
        req.body = collected;
        self.forward_stream(req).await
    }
}

/// Flatten an error and its `source()` chain into one message. The client wraps
/// the underlying connect/TLS/resolver cause as a source; the outer
/// `to_string()` alone is just "error sending request for url (...)", which
/// hides whether a forward failed on DNS, the SSRF filter, TLS, or timeout.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// Production forwarder: a hardened client (TLS 1.3 floor, no redirects) makes
/// the real request through the shared SSRF-filtering resolver.
///
/// This used to resolve and SSRF-filter the host by hand and pin the safe
/// addresses on the URL's real port, because the shared resolver hardcoded 443
/// — reqwest's `Resolve` never saw the port, and an `http` forward would have
/// gone to the HTTPS port. `mvm_http::Resolve` receives `(host, port)`, so the
/// shared resolver handles it and the hand-rolled path is gone.
pub struct HardenedForwarder {
    timeout_secs: u64,
    proxy: Option<mvm_http::ProxyConfig>,
}

impl HardenedForwarder {
    pub fn new(timeout_secs: u64) -> Result<Self, ForwardError> {
        Ok(Self {
            timeout_secs,
            proxy: None,
        })
    }

    /// Route the forward leg through an operator-configured upstream proxy.
    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<mvm_http::ProxyConfig>) -> Self {
        self.proxy = proxy;
        self
    }

    async fn send_streaming(
        &self,
        req: PreparedRequest,
        stream_body: Option<tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>>,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        let method = mvm_http::Method::from_bytes(req.method.as_bytes())
            .map_err(|e| ForwardError::Failed(format!("bad method: {e}")))?;
        let client = hardened_client_builder_via(self.timeout_secs, self.proxy.as_ref())
            .max_response_bytes(MAX_FORWARD_RESPONSE_BYTES as u64)
            .build()
            .map_err(|e| ForwardError::Failed(e.to_string()))?;
        let mut rb = client.request(method, &req.url);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        rb = match stream_body {
            Some(receiver) => rb.body_checked_chunked(receiver),
            None if !req.body.is_empty() => rb.body(req.body),
            None => rb,
        };
        let mut resp = rb
            .send()
            .await
            .map_err(|e| ForwardError::Failed(err_chain(&e)))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        check_forward_response_length(resp.content_length())?;
        let body_len = resp.content_length();
        let (sender, body) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            loop {
                match resp.chunk().await {
                    Ok(Some(chunk)) => {
                        if sender.send(Ok(chunk.to_vec())).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = sender
                            .send(Err(ForwardError::Failed(err_chain(&error))))
                            .await;
                        return;
                    }
                }
            }
        });
        Ok(ForwardStreamResponse {
            status,
            headers,
            body_len,
            body,
        })
    }
}

#[async_trait]
impl Forwarder for HardenedForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        let mut response = self.forward_stream(req).await?;
        let mut body = Vec::new();
        while let Some(chunk) = response.body.recv().await {
            body.extend_from_slice(&chunk?);
        }
        Ok(ForwardResponse {
            status: response.status,
            headers: response.headers,
            body,
        })
    }

    async fn forward_stream(
        &self,
        req: PreparedRequest,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        self.send_streaming(req, None).await
    }

    async fn forward_body_stream(
        &self,
        req: PreparedRequest,
        body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        self.send_streaming(req, Some(body)).await
    }
}

/// The running host substitution endpoint: the admission-minted placeholder
/// registry, the secret resolver, and the forward leg. Placeholders are minted
/// at admission, so the registry is read-only while serving.
pub struct SubstitutionService {
    tenant: String,
    registry: Arc<SubstitutionRegistry>,
    resolver: Arc<dyn SecretResolver>,
    forwarder: Arc<dyn Forwarder>,
    /// Egress redactor. Masks *undeclared* secret-shaped / PII content out
    /// of an outbound request before forwarding — the
    /// request-level twin of the gateway bridge's packet redactor, sharing one
    /// `RedactingSubstitution` definition so every backend that routes egress
    /// through this endpoint scrubs identically. Built once (rule compilation).
    redactor: RedactingSubstitution,
    /// Optional chain-signed audit recorder. When set, each substitution emits
    /// a `secret.substituted` entry (metadata only — claim 13).
    recorder: Option<Arc<Recorder>>,
    /// The per-VM name-constrained intermediate the `https` terminator mints
    /// per-SNI leaves under. `None` ⇒ no TLS leg (`http`-only). Set from
    /// `EndpointConfig.tls_intermediate` at assemble.
    tls_intermediate: Option<Arc<mvm_core::crypto::egress_ca::VmIntermediate>>,
    /// Per-destination redaction policy. Default = curated baseline (entropy +
    /// names off); a profile opts a destination into entropy/name redaction.
    redaction_policy: mvm_core::policy::RedactionPolicy,
    /// Per-destination reversible replacement policy. Default = disabled.
    reversible_replacement_policy: mvm_core::policy::ReversibleReplacementPolicy,
    /// Request-scoped replacement / reinjection engine.
    replacement_engine: ReplacementEngine,
    /// Claim-10 egress gate. When present, every outbound destination is checked
    /// against the VM's resolved network policy before any forward — an
    /// unadmitted `host:port` is refused here. `None` ⇒ this endpoint does not
    /// gate (the run loop's gate is still active); a `Some` gate fails closed.
    egress_gate: Option<Arc<mvm_runtime::vmm::egress_gate::EgressGate>>,
    /// Per-VM AI egress metering/budget policy. `None` means AI egress is not
    /// metered and no budget is enforced.
    ai_policy: Option<mvm_contract::policy::network_policy::AiPolicy>,
    /// Per-VM AI token budget tracker, present only when metering is enabled.
    ai_tracker: Option<Arc<ai_meter::AiBudgetTracker>>,
    /// VM instance identifier used to attribute AI egress metrics.
    instance_id: Option<String>,
    /// Optional per-VM metrics registry for AI counters. When `None`, the
    /// process-global registry is used.
    instance_metrics:
        Option<Arc<mvm_core::observability::instance_metrics::InstanceMetricsRegistry>>,
}

/// Failure to resolve host-owned transformation material by its signed plan
/// reference. Errors name only the reference, never the secret bytes.
#[derive(Debug, thiserror::Error)]
pub enum HostMaterialError {
    #[error("host transformation material `{name}` is absent from the admitted plan")]
    NotAdmitted { name: String },
    #[error("host transformation material `{name}` could not be resolved")]
    Unavailable {
        name: String,
        #[source]
        source: crate::keyholder::ResolveError,
    },
}

/// Security state retained from request preparation through response
/// completion. It contains metadata and rewrite state, never an extra copy of
/// the request or a credential value.
struct PreparedFlow {
    request: Option<PreparedRequest>,
    destination: Option<String>,
    substituted: Vec<(String, AuthType)>,
    replacement_flow: ReplacementFlow,
    replacement_proofs: Vec<mvm_core::policy::RewriteProofRecord>,
    redaction_hits: RedactionHits,
    redaction_action: mvm_core::policy::RedactionAction,
}

/// Raw suffix retained between transform chunks. A 64 KiB window is larger
/// than every configured secret/PII fingerprint; an adversarial pattern that
/// still cannot reach a stable cut by twice that bound fails closed.
const STREAM_TRANSFORM_OVERLAP: usize = 64 * 1024;
const MAX_STREAM_TRANSFORM_PENDING: usize = STREAM_TRANSFORM_OVERLAP * 2;
/// Cap on how much of a streaming AI response body we retain for trailing
/// usage extraction. SSE usage blocks are small and appear at the end of the
/// stream; this buffer only keeps the tail so guest bandwidth is unaffected.
const MAX_AI_STREAM_BUFFER_BYTES: usize = 256 * 1024;

pub(crate) struct StreamingRedactor {
    pending: Zeroizing<Vec<u8>>,
}

impl StreamingRedactor {
    pub(crate) fn new() -> Self {
        Self {
            pending: Zeroizing::new(Vec::new()),
        }
    }

    pub(crate) fn push(
        &mut self,
        redactor: &RedactingSubstitution,
        action: &mvm_core::policy::RedactionAction,
        chunk: &[u8],
    ) -> Result<(Vec<u8>, RedactionHits), SensitiveDetectionError> {
        self.pending.extend_from_slice(chunk);
        if self.pending.len() <= STREAM_TRANSFORM_OVERLAP {
            return Ok((Vec::new(), RedactionHits::default()));
        }

        let safe_len = self.pending.len() - STREAM_TRANSFORM_OVERLAP;
        let (prefix, prefix_hits) = redact_or_copy(redactor, action, &self.pending[..safe_len])?;
        let (whole, _) = redact_or_copy(redactor, action, &self.pending)?;
        if whole.starts_with(&prefix) {
            let suffix = self.pending.split_off(safe_len);
            *self.pending = suffix;
            return Ok((prefix, prefix_hits));
        }
        if self.pending.len() > MAX_STREAM_TRANSFORM_PENDING {
            return Err(SensitiveDetectionError);
        }
        Ok((Vec::new(), RedactionHits::default()))
    }

    pub(crate) fn finish(
        &mut self,
        redactor: &RedactingSubstitution,
        action: &mvm_core::policy::RedactionAction,
    ) -> Result<(Vec<u8>, RedactionHits), SensitiveDetectionError> {
        let pending = std::mem::take(&mut *self.pending);
        redact_or_copy(redactor, action, &pending)
    }
}

fn redact_or_copy(
    redactor: &RedactingSubstitution,
    action: &mvm_core::policy::RedactionAction,
    bytes: &[u8],
) -> Result<(Vec<u8>, RedactionHits), SensitiveDetectionError> {
    match redactor.redact_bytes_for(bytes, action) {
        Some((_redacted, hits)) if hits.detector_failures > 0 => Err(SensitiveDetectionError),
        Some((redacted, hits)) => Ok((redacted, hits)),
        None => Ok((bytes.to_vec(), RedactionHits::default())),
    }
}

#[cfg(test)]
mod streaming_redactor_tests {
    use super::*;

    #[test]
    fn a_secret_split_across_chunks_is_withheld_and_redacted() {
        let secret = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let split = 17;
        let mut first = vec![b'x'; STREAM_TRANSFORM_OVERLAP - split];
        first.extend_from_slice(&secret[..split]);

        let redactor = RedactingSubstitution::with_default_rules();
        let action = mvm_core::policy::RedactionAction::default();
        let mut stream = StreamingRedactor::new();
        let (ready, _) = stream.push(&redactor, &action, &first).unwrap();
        assert!(ready.is_empty(), "the possible prefix must stay withheld");
        let (ready, _) = stream.push(&redactor, &action, &secret[split..]).unwrap();
        let (tail, hits) = stream.finish(&redactor, &action).unwrap();
        let output = [ready, tail].concat();
        assert!(!output.windows(secret.len()).any(|window| window == secret));
        assert!(!hits.secrets.is_empty(), "the split token must be detected");
    }

    #[test]
    fn clean_streams_release_every_byte_in_order_with_bounded_carry() {
        let redactor = RedactingSubstitution::with_default_rules();
        let action = mvm_core::policy::RedactionAction::default();
        let mut stream = StreamingRedactor::new();
        let input = vec![b'x'; STREAM_TRANSFORM_OVERLAP + 123];
        let (ready, _) = stream.push(&redactor, &action, &input).unwrap();
        assert_eq!(ready.len(), 123);
        assert!(stream.pending.len() <= STREAM_TRANSFORM_OVERLAP);
        let (tail, _) = stream.finish(&redactor, &action).unwrap();
        assert_eq!([ready, tail].concat(), input);
    }

    #[test]
    fn a_long_clean_stream_never_grows_the_overlap_buffer() {
        let redactor = RedactingSubstitution::with_default_rules();
        let action = mvm_core::policy::RedactionAction::default();
        let mut stream = StreamingRedactor::new();
        let chunk = vec![b'x'; 8 * 1024];
        let mut emitted = 0usize;

        for _ in 0..1024 {
            let (ready, hits) = stream.push(&redactor, &action, &chunk).unwrap();
            assert!(hits.is_empty());
            emitted = emitted.saturating_add(ready.len());
            assert!(stream.pending.len() <= STREAM_TRANSFORM_OVERLAP);
        }
        let (tail, hits) = stream.finish(&redactor, &action).unwrap();
        assert!(hits.is_empty());
        emitted = emitted.saturating_add(tail.len());
        assert_eq!(emitted, chunk.len() * 1024);
    }
}
/// Which audit an error path owes, given the cause and whether the request
/// carried a placeholder.
///
/// Every error on these paths is fail-closed — the socket closes WITHOUT
/// forwarding — but the causes are not equally interesting. A refusal that
/// dropped a placeholder and a fail-closed refusal are both claim-bearing
/// events an operator must be able to see; a parse or forward failure is not
/// secret-relevant and gets no entry.
///
/// Extracted from the two call sites that had this match inline and identical.
/// Two copies of a security classification is how they drift, and it is why
/// deleting either one's `FailClosed` arm changed no test: the classification
/// had no name and so nothing could assert on it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorAudit<'a> {
    /// claim-12: a placeholder was dropped rather than substituted.
    PlaceholderDropped,
    /// A fail-closed refusal, carrying the reason to record.
    FailClosed(&'a str),
    /// Not secret-relevant; nothing to record.
    Silent,
}

pub(crate) fn error_audit(
    error: &crate::supervisor::terminator::error::TerminatorError,
    carried_placeholder: bool,
) -> ErrorAudit<'_> {
    match error {
        crate::supervisor::terminator::error::TerminatorError::Refused(_)
            if carried_placeholder =>
        {
            ErrorAudit::PlaceholderDropped
        }
        crate::supervisor::terminator::error::TerminatorError::FailClosed(reason) => {
            ErrorAudit::FailClosed(reason)
        }
        _ => ErrorAudit::Silent,
    }
}

impl SubstitutionService {
    pub fn new(
        registry: Arc<SubstitutionRegistry>,
        resolver: Arc<dyn SecretResolver>,
        forwarder: Arc<dyn Forwarder>,
    ) -> Self {
        Self {
            tenant: "local".to_string(),
            registry,
            resolver,
            forwarder,
            redactor: RedactingSubstitution::with_default_rules(),
            recorder: None,
            tls_intermediate: None,
            redaction_policy: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement_policy: mvm_core::policy::ReversibleReplacementPolicy::default(),
            replacement_engine: ReplacementEngine::new(),
            egress_gate: None,
            ai_policy: None,
            ai_tracker: None,
            instance_id: None,
            instance_metrics: None,
        }
    }

    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = tenant.into();
        self
    }

    /// Attach a per-destination redaction policy. Default leaves entropy + names
    /// off everywhere (curated-only baseline); a policy opts specific
    /// destinations into entropy/name redaction.
    pub fn with_redaction_policy(mut self, policy: mvm_core::policy::RedactionPolicy) -> Self {
        self.redaction_policy = policy;
        self
    }

    pub fn with_reversible_replacement_policy(
        mut self,
        policy: mvm_core::policy::ReversibleReplacementPolicy,
    ) -> Self {
        self.reversible_replacement_policy = policy;
        self
    }

    /// Resolve a host-only transformation secret by its signed plan name.
    /// The returned `SecretBox` zeroizes on drop; callers must parse it in
    /// place and must never serialize or log the exposed bytes.
    pub fn resolve_host_material(
        &self,
        name: &str,
    ) -> Result<secrecy::SecretBox<Vec<u8>>, HostMaterialError> {
        let secret =
            self.registry
                .resolve_name(name)
                .ok_or_else(|| HostMaterialError::NotAdmitted {
                    name: name.to_string(),
                })?;
        self.resolver
            .resolve(secret)
            .map_err(|source| HostMaterialError::Unavailable {
                name: name.to_string(),
                source,
            })
    }

    /// Build per-connection ingress HTTP transformation state from the same
    /// admitted policies used by typed egress. `profile_key` is the signed host
    /// bind address; no peer-controlled Host header selects policy.
    pub fn ingress_transformer(
        &self,
        profile_key: &str,
    ) -> crate::supervisor::ingress_transform::IngressTransformer {
        let redaction =
            crate::supervisor::redaction_resolve::resolve(&self.redaction_policy, profile_key)
                .clone();
        let replacement = crate::supervisor::reversible_replacement_resolve::resolve(
            &self.reversible_replacement_policy,
            profile_key,
        )
        .clone();
        crate::supervisor::ingress_transform::IngressTransformer::new(
            &self.tenant,
            redaction,
            replacement,
        )
    }

    /// Append one payload-free signed audit event for a transformed ingress
    /// exchange. The runtime handle belongs to the endpoint; transform workers
    /// are bounded blocking threads and use it only for the short signer call.
    pub fn audit_ingress_transform(
        &self,
        runtime: &tokio::runtime::Handle,
        mapping_id: u16,
        result: &Result<
            crate::supervisor::ingress_transform::IngressTransformSummary,
            crate::supervisor::ingress_transform::IngressTransformError,
        >,
    ) {
        let Some(recorder) = self.recorder.clone() else {
            return;
        };
        let (event_name, labels) = ingress_transform_audit(mapping_id, result);
        let _ = runtime.block_on(recorder.record_unbound(EventCategory::Host, event_name, labels));
    }

    /// Explain why an opaque flow to `destination` cannot honestly satisfy the
    /// admitted transformation policy.
    ///
    /// Secret bindings and explicitly enabled replacement/redaction profiles
    /// are destination-bound. Letting the same destination use opaque TCP or
    /// UDP would silently bypass the only path that can inspect, substitute,
    /// or redact its bytes. The caller refuses before DNS resolution or socket
    /// creation. The curated default redaction action does not make every
    /// opaque destination transformed; only an explicit profile/default opt-in
    /// or a bound secret does.
    pub(crate) fn opaque_refusal_reason(&self, destination: &str) -> Option<&'static str> {
        if self.registry.host_is_bound(destination) {
            return Some("destination requires secret substitution over typed HTTP");
        }

        if crate::supervisor::reversible_replacement_resolve::resolve(
            &self.reversible_replacement_policy,
            destination,
        )
        .enabled
        {
            return Some("destination requires reversible replacement over typed HTTP");
        }

        let explicit_redaction = self
            .redaction_policy
            .profiles
            .iter()
            .find(|profile| mvm_contract::ir::host_matches(&profile.host, destination))
            .map(|profile| redaction_active(&profile.action))
            .unwrap_or_else(|| explicit_default_redaction(&self.redaction_policy.default));
        explicit_redaction.then_some("destination requires redaction over typed HTTP")
    }

    /// Record cancellation/failure metadata for a typed HTTP stream without
    /// ever placing request bytes, headers, credentials, or the full URL in
    /// the audit record.
    pub(crate) async fn audit_http_stream_failure(&self, url: &str, reason: &str) {
        let destination = destination_host(url).ok();
        self.audit_fail_closed(destination.as_deref(), reason).await;
    }

    /// The attached redaction policy. Test-only: lets the threading tests prove
    /// a policy carried through `from_plan` actually reached the service.
    #[cfg(test)]
    pub(crate) fn redaction_policy(&self) -> &mvm_core::policy::RedactionPolicy {
        &self.redaction_policy
    }

    /// The attached resolver. Test-only: lets `assemble`'s resolver-backend
    /// tests prove which `SecretResolver` (`LocalResolver` vs `RemoteResolver`)
    /// actually reached the service, via an observable `resolve()` call rather
    /// than reaching into a private field.
    #[cfg(test)]
    pub(crate) fn resolver(&self) -> &Arc<dyn SecretResolver> {
        &self.resolver
    }

    /// Run the service's redactor for a destination action. Test-only seam so the
    /// endpoint-config tests can prove the threaded policy fires end-to-end.
    #[cfg(test)]
    pub(crate) fn redactor_redact_bytes_for(
        &self,
        payload: &[u8],
        action: &mvm_core::policy::RedactionAction,
    ) -> Option<(Vec<u8>, crate::supervisor::network::stages::RedactionHits)> {
        self.redactor.redact_bytes_for(payload, action)
    }

    /// Attach a chain-signed audit recorder; each substitution then emits a
    /// `secret.substituted` entry (metadata only — claim 13).
    pub fn with_recorder(mut self, recorder: Recorder) -> Self {
        self.recorder = Some(Arc::new(recorder));
        self
    }

    /// Attach the endpoint's shared chain-signed audit sink.
    pub fn with_shared_recorder(mut self, recorder: Arc<Recorder>) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Attach the per-VM egress intermediate so the terminator can terminate
    /// bound-host `https`. Absent ⇒ `http`-only.
    pub fn with_tls_intermediate(
        mut self,
        intermediate: mvm_core::crypto::egress_ca::VmIntermediate,
    ) -> Self {
        self.tls_intermediate = Some(Arc::new(intermediate));
        self
    }

    /// Attach the claim-10 egress gate. Once attached, `process` refuses any
    /// destination the VM's network policy doesn't admit before forwarding.
    pub fn with_egress_gate(mut self, gate: mvm_runtime::vmm::egress_gate::EgressGate) -> Self {
        self.egress_gate = Some(Arc::new(gate));
        self
    }

    /// Attach the endpoint's shared claim-10 policy object.
    pub fn with_shared_egress_gate(
        mut self,
        gate: Arc<mvm_runtime::vmm::egress_gate::EgressGate>,
    ) -> Self {
        self.egress_gate = Some(gate);
        self
    }

    #[cfg(test)]
    pub(crate) fn shared_projection_ids(&self) -> (Option<usize>, Option<usize>) {
        (
            self.egress_gate
                .as_ref()
                .map(|gate| Arc::as_ptr(gate).cast::<()>() as usize),
            self.recorder
                .as_ref()
                .map(|recorder| Arc::as_ptr(recorder).cast::<()>() as usize),
        )
    }

    /// Attach the VM instance identifier used to attribute AI egress metrics
    /// and audit records. Empty strings are treated as absent.
    pub fn with_instance_id(mut self, instance_id: impl Into<String>) -> Self {
        let id = instance_id.into();
        self.instance_id = (!id.is_empty()).then_some(id);
        self
    }

    /// Attach a per-VM AI egress metering/budget policy. Metering is only
    /// active when `policy.metering` is `true`.
    pub fn with_ai_policy(
        mut self,
        policy: mvm_contract::policy::network_policy::AiPolicy,
    ) -> Self {
        if policy.metering {
            self.ai_tracker = Some(Arc::new(ai_meter::AiBudgetTracker::new(policy.budget)));
        }
        self.ai_policy = Some(policy);
        self
    }

    /// Override the per-VM metrics registry used for AI counters. When not
    /// set, the process-global registry is used.
    pub fn with_instance_metrics(
        mut self,
        registry: Arc<mvm_core::observability::instance_metrics::InstanceMetricsRegistry>,
    ) -> Self {
        self.instance_metrics = Some(registry);
        self
    }

    /// Assemble a ready-to-serve service from an admitted plan's secret
    /// bindings: build the registry ([`assemble_registry`]) and a
    /// hardened forwarder, and resolve values through the caller-supplied
    /// [`SecretResolver`] (a [`LocalResolver`] over the tenant's secret store by
    /// default, or a remote fleet-secrets resolver). Returns the service plus the
    /// `(guest name, placeholder)` pairs the supervisor injects into the guest.
    /// The caller binds the listener and calls [`Self::serve`].
    pub fn from_plan(
        inputs: FromPlanInputs<'_>,
    ) -> Result<(Arc<Self>, HandedPlaceholders), FromPlanError> {
        let FromPlanInputs {
            plan_secrets,
            tenant,
            instance_id,
            bindings,
            resolver,
            forward_timeout_secs,
            proxy,
            redaction,
            reversible_replacement,
            tls_intermediate,
            recorder,
            ai_policy,
        } = inputs;
        let (registry, handed) = assemble_registry(plan_secrets, tenant, bindings)?;
        let forwarder: Arc<dyn Forwarder> =
            Arc::new(HardenedForwarder::new(forward_timeout_secs)?.with_proxy(proxy));
        let mut service = Self::new(Arc::new(registry), resolver, forwarder)
            .with_tenant(tenant)
            .with_instance_id(instance_id);
        service = service.with_redaction_policy(redaction);
        service = service.with_reversible_replacement_policy(reversible_replacement);
        if let Some(intermediate) = tls_intermediate {
            service = service.with_tls_intermediate(intermediate);
        }
        if let Some(recorder) = recorder {
            service = service.with_recorder(recorder);
        }
        if let Some(policy) = ai_policy {
            service = service.with_ai_policy(policy);
        }
        Ok((Arc::new(service), handed))
    }

    /// Accept loop: one routed request per connection, framed JSON, a task per
    /// connection. Runs until the listener fails in a way it cannot recover from;
    /// transient accept errors are retried.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        let mut transient = 0u32;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    transient = 0;
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_connection(stream).await {
                            tracing::warn!(error = %e, "substitution endpoint connection failed");
                        }
                    });
                }
                Err(e) => match classify_accept_error(&e, transient) {
                    AcceptAction::Retry(delay) => {
                        tracing::warn!(error = %e, "substitution endpoint accept failed; retrying");
                        transient = transient.saturating_add(1);
                        tokio::time::sleep(delay).await;
                    }
                    AcceptAction::Fatal => {
                        tracing::error!(error = %e, "substitution endpoint accept failed; stopping");
                        record_listener_stopped(
                            self.recorder.as_deref(),
                            "substitution-uds",
                            &e.to_string(),
                        )
                        .await;
                        return;
                    }
                },
            }
        }
    }

    /// Accept loop over a host **AF_VSOCK** listener — the QEMU (`vhost-vsock`)
    /// guest→host path. Firecracker/libkrun route guest→host through a per-port
    /// UDS instead and use [`Self::serve`]. Both `accept(2)` and the per-
    /// connection framing run with **blocking** I/O on `spawn_blocking` threads
    /// (tokio's async reactor doesn't interplay reliably with an AF_VSOCK fd);
    /// the async forward leg is driven via `Handle::block_on`. No new dep.
    #[cfg(target_os = "linux")]
    pub async fn serve_vsock(self: Arc<Self>, listener: vsock::VsockListener) {
        let mut transient = 0u32;
        loop {
            let listen_fd = listener.raw_fd();
            let accepted = tokio::task::spawn_blocking(move || vsock::accept(listen_fd)).await;
            let conn_fd = match accepted {
                Ok(Ok(fd)) => {
                    transient = 0;
                    fd
                }
                Ok(Err(e)) => match classify_accept_error(&e, transient) {
                    AcceptAction::Retry(delay) => {
                        tracing::warn!(error = %e, "vsock substitution accept failed; retrying");
                        transient = transient.saturating_add(1);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    AcceptAction::Fatal => {
                        tracing::error!(error = %e, "vsock substitution accept failed; stopping");
                        record_listener_stopped(
                            self.recorder.as_deref(),
                            "substitution-vsock",
                            &e.to_string(),
                        )
                        .await;
                        return;
                    }
                },
                // A panic in the accept task is a bug in this process, not host
                // pressure that will clear. Retrying would hide it.
                Err(e) => {
                    tracing::error!(error = %e, "vsock accept task panicked; stopping");
                    record_listener_stopped(
                        self.recorder.as_deref(),
                        "substitution-vsock",
                        &e.to_string(),
                    )
                    .await;
                    return;
                }
            };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = me.handle_vsock_connection(conn_fd).await {
                    tracing::warn!(error = %e, "vsock substitution connection failed");
                }
            });
        }
    }

    /// Accept loop for the transparent egress **terminator**: guest outbound TCP
    /// is redirected here, we recover the original destination, substitute any
    /// secret placeholder in the request (claim-12 bind-checked), and splice the
    /// request to the real destination — returning its response verbatim.
    ///
    /// Linux recovers the destination via `SO_ORIGINAL_DST`; the native
    /// connections carry a compact preamble before the first guest byte. The
    /// substitution core (`terminator::handler::handle_request`) and splice
    /// (`terminator::listener::forward_http_raw`) are sync + blocking, so each
    /// connection's syscalls run on `spawn_blocking` threads, off the reactor.
    /// A failure on one connection is logged and the socket dropped — never
    /// fatal to the loop.
    ///
    /// `timeout` is the configured per-connection I/O deadline (the endpoint's
    /// `forward_timeout_secs`), applied to BOTH the untrusted guest-facing socket
    /// (read+write) and the upstream forward leg. Without it a guest that sends a
    /// partial header or stops reading mid-write-back would park a blocking-pool
    /// thread forever — a bounded pool means a hostile guest could exhaust it.
    pub async fn serve_terminator(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        timeout: std::time::Duration,
    ) {
        let mut transient = 0u32;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    transient = 0;
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = me.handle_terminator_connection(stream, timeout).await {
                            tracing::warn!(error = %e, "terminator connection failed");
                        }
                    });
                }
                Err(e) => match classify_accept_error(&e, transient) {
                    AcceptAction::Retry(delay) => {
                        tracing::warn!(error = %e, "terminator accept failed; retrying");
                        transient = transient.saturating_add(1);
                        tokio::time::sleep(delay).await;
                    }
                    AcceptAction::Fatal => {
                        tracing::error!(error = %e, "terminator accept failed; stopping");
                        record_listener_stopped(
                            self.recorder.as_deref(),
                            "terminator",
                            &e.to_string(),
                        )
                        .await;
                        return;
                    }
                },
            }
        }
    }

    /// Handle one redirected guest connection: recover orig-dst, read the
    /// request, substitute + forward, write the response back. claim-12
    /// fail-closed is enforced inside `handle_request` (it refuses an unbound
    /// destination / unknown placeholder before the forward runs); on refusal
    /// we log and close WITHOUT forwarding.
    async fn handle_terminator_connection(
        &self,
        stream: tokio::net::TcpStream,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        use crate::keyholder::NetworkEndpoint;
        use crate::supervisor::terminator;
        use std::io::Write;

        // The orig-dst getsockopt + bounded request read are blocking syscalls.
        // The redirected socket is UNTRUSTED: set read+write deadlines so a guest
        // that never completes its header (`\r\n\r\n`) or stalls mid-write-back
        // can't park this blocking-pool thread forever (bounded pool ⇒ DoS).
        let std_stream = stream.into_std()?;
        std_stream.set_nonblocking(false)?;
        std_stream.set_read_timeout(Some(timeout))?;
        std_stream.set_write_timeout(Some(timeout))?;

        let (std_stream, orig_dst) = tokio::task::spawn_blocking(move || {
            let mut std_stream = std_stream;
            let orig_dst = recover_terminator_original_destination(&mut std_stream)?;
            anyhow::Ok((std_stream, orig_dst))
        })
        .await??;

        if orig_dst.port() == 443 {
            return self
                .handle_https_terminator(std_stream, orig_dst, timeout)
                .await;
        }

        // ── cleartext :80 ──
        let mut std_stream = std_stream;
        let (mut std_stream, raw) = tokio::task::spawn_blocking(move || {
            let raw = terminator::read::read_http_request(&mut std_stream)?;
            anyhow::Ok((std_stream, raw))
        })
        .await??;

        // Capture audit metadata before substitution consumes the request —
        // same as the UDS/vsock `process` path (shared helper so they can't
        // drift). resolve_meta touches no value, so this is claim-13 safe.
        let req = terminator::request::proxy_request_from_origin_form(&raw, orig_dst)?;
        let endpoint = NetworkEndpoint::new(&self.registry, self.resolver.as_ref());
        let destination = destination_host(&req.url).ok();
        let substituted = collect_substituted_meta(&endpoint, &req.headers);
        // Whether the request smuggled a host placeholder at all — decides if a
        // refusal is a claim-12 placeholder drop (audited) or a plain bad request.
        let carried_placeholder = req
            .headers
            .iter()
            .any(|(_, v)| find_placeholder(v).is_some());
        drop(req);

        // Resolve the per-destination redaction action; clone so the closure owns
        // it across spawn_blocking.
        let action = destination
            .as_deref()
            .map(|d| {
                crate::supervisor::redaction_resolve::resolve(&self.redaction_policy, d).clone()
            })
            .unwrap_or_default();

        // Substitution + redaction + the raw forward leg are sync; run them off
        // the reactor. Clone the Arcs the closure needs (it must be 'static —
        // can't borrow &self across spawn_blocking); the endpoint + redactor are
        // rebuilt inside.
        let registry = Arc::clone(&self.registry);
        let resolver = Arc::clone(&self.resolver);
        let forwarded = tokio::task::spawn_blocking(move || {
            let endpoint = NetworkEndpoint::new(&registry, resolver.as_ref());
            // The redactor is the shared curated ruleset (same as the service's),
            // rebuilt here so the closure stays 'static without cloning rule state.
            let redactor = RedactingSubstitution::with_default_rules();
            terminator::handler::handle_request(
                &raw,
                orig_dst,
                &endpoint,
                &redactor,
                &action,
                |prepared, dst| terminator::listener::forward_http_raw(prepared, dst, timeout),
            )
        })
        .await?;

        let (resp, redaction_hits) = match forwarded {
            Ok(ok) => ok,
            Err(e) => {
                // Every error path is fail-closed: the socket closes WITHOUT
                // forwarding. Audit per cause so a claim-12 drop / fail-closed
                // refusal is observable; a parse / forward failure isn't
                // secret-relevant.
                match error_audit(&e, carried_placeholder) {
                    ErrorAudit::PlaceholderDropped => {
                        self.audit_placeholder_dropped(destination.as_deref()).await;
                    }
                    ErrorAudit::FailClosed(reason) => {
                        self.audit_fail_closed(destination.as_deref(), reason).await;
                    }
                    ErrorAudit::Silent => {}
                }
                tracing::warn!(error = %e, "terminator refused or forward failed; closing");
                return Ok(());
            }
        };

        self.audit_substitutions(&substituted, destination.as_deref())
            .await;
        self.audit_redactions(&redaction_hits, destination.as_deref())
            .await;

        tokio::task::spawn_blocking(move || {
            std_stream.write_all(&resp)?;
            std_stream.flush()
        })
        .await??;
        Ok(())
    }

    /// `:443`: peek the ClientHello SNI, then **terminate** TLS for a
    /// bound host (mint a leaf under the per-VM intermediate, decrypt, substitute,
    /// re-originate over the hardened forwarder) or **splice** an unbound
    /// host straight through without decrypting. Fail-closed: a bound host whose
    /// substitution refuses closes the socket without forwarding (claim 12).
    async fn handle_https_terminator(
        &self,
        std_stream: std::net::TcpStream,
        orig_dst: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()> {
        use crate::keyholder::NetworkEndpoint;
        use crate::supervisor::terminator::tls;

        // Peek the SNI without consuming the stream (blocking).
        let (std_stream, sni) = tokio::task::spawn_blocking(move || {
            let sni = tls::peek_sni(&std_stream)?;
            anyhow::Ok((std_stream, sni))
        })
        .await??;

        // Terminate ONLY a host bound by some workload secret, and only when we
        // hold the per-VM intermediate. Everything else is spliced end-to-end —
        // never decrypted (zero added host visibility over substitution's needs).
        let bound_sni = sni.filter(|s| self.registry.host_is_bound(s));
        let (intermediate, sni) = match (self.tls_intermediate.clone(), bound_sni) {
            (Some(intermediate), Some(sni)) => (intermediate, sni),
            _ => {
                return tokio::task::spawn_blocking(move || {
                    tls::splice_unbound(std_stream, orig_dst, timeout)
                })
                .await?;
            }
        };

        // The SNI is the bound destination; resolve its redaction action here so
        // the terminated (cleartext) request is scrubbed identically to the `:80`
        // and vsock paths. The spliced/unbound arm above never reaches this —
        // it's ciphertext, nothing to scan, redaction correctly does not apply.
        let dest = sni.clone();
        let action =
            crate::supervisor::redaction_resolve::resolve(&self.redaction_policy, &dest).clone();

        let config = Arc::new(tls::server_config_for_sni(&intermediate, &sni)?);
        let registry = Arc::clone(&self.registry);
        let resolver = Arc::clone(&self.resolver);
        let forwarder = Arc::clone(&self.forwarder);
        let handle = tokio::runtime::Handle::current();
        let (outcome, carried_placeholder) = tokio::task::spawn_blocking(move || {
            let endpoint = NetworkEndpoint::new(&registry, resolver.as_ref());
            let redactor = RedactingSubstitution::with_default_rules();
            let mut carried = false;
            let outcome = tls::terminate_and_substitute(
                std_stream,
                tls::TlsTermination::builder()
                    .with_config(config)
                    .with_orig_dst(orig_dst)
                    .with_endpoint(&endpoint)
                    .with_redactor(&redactor)
                    .with_action(&action)
                    .build(),
                &mut carried,
                |prepared| {
                    // The upstream leg reuses the hardened forwarder (TLS
                    // + system roots + SSRF filter); block_on is safe on a
                    // blocking thread. The client decoded the body, so we re-frame.
                    let resp = handle
                        .block_on(forwarder.forward(prepared.clone()))
                        .map_err(|e| anyhow::anyhow!("upstream forward: {e}"))?;
                    Ok(tls::serialize_http_response(
                        resp.status,
                        &resp.headers,
                        &resp.body,
                    ))
                },
            );
            (outcome, carried)
        })
        .await?;

        match outcome {
            Ok(o) => {
                self.audit_substitutions(&o.substituted, o.destination.as_deref())
                    .await;
                self.audit_redactions(&o.redaction_hits, o.destination.as_deref())
                    .await;
                Ok(())
            }
            Err(e) => {
                // Every error path is fail-closed (the socket closes WITHOUT
                // forwarding); audit per cause exactly like the `:80` path.
                match error_audit(&e, carried_placeholder) {
                    ErrorAudit::PlaceholderDropped => {
                        self.audit_placeholder_dropped(Some(&dest)).await;
                    }
                    ErrorAudit::FailClosed(reason) => {
                        self.audit_fail_closed(Some(&dest), reason).await;
                    }
                    ErrorAudit::Silent => {}
                }
                tracing::warn!(error = %e, "https terminator refused or failed; closing");
                Ok(())
            }
        }
    }

    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), FrameError> {
        let wire: WireRequest = read_json_frame(&mut stream, MAX_FRAME_BYTES).await?;
        let resp = self.process(wire).await;
        write_json_frame(&mut stream, &resp).await
    }

    /// Handle one vsock connection: the raw socket I/O is blocking, so the
    /// frame read/write run on `spawn_blocking` threads, while `process` (the
    /// substitution + forward leg — the prod forward needs the tokio reactor)
    /// runs on the runtime. We do NOT `block_on` the forward from a blocking
    /// thread: a `spawn_blocking` thread is still inside the runtime context,
    /// so tokio's `block_on` panics there.
    #[cfg(target_os = "linux")]
    async fn handle_vsock_connection(&self, conn_fd: std::os::fd::RawFd) -> std::io::Result<()> {
        use std::os::fd::FromRawFd;
        // SAFETY: `conn_fd` is an owned connected stream socket from `accept`.
        let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(conn_fd) };
        let (mut stream, wire) = tokio::task::spawn_blocking(move || {
            let mut s = stream;
            let wire: WireRequest = vsock::read_frame_sync(&mut s)?;
            std::io::Result::Ok((s, wire))
        })
        .await
        .map_err(std::io::Error::other)??;
        let resp = self.process(wire).await;
        tokio::task::spawn_blocking(move || vsock::write_frame_sync(&mut stream, &resp))
            .await
            .map_err(std::io::Error::other)?
    }

    /// Substitute, gate, forward, and audit one request.
    ///
    /// `pub(crate)` so the FlowMux `Http` arm can call it. That arm frames the
    /// request and the reply; everything this does — placeholder resolution,
    /// destination binding, the claim-10 gate, payload-free audit — happens
    /// here and only here, on every transport.
    pub(crate) async fn process(&self, wire: WireRequest) -> WireResponse {
        let mut flow = match self.prepare_flow(wire).await {
            Ok(flow) => flow,
            Err(refusal) => return refusal,
        };
        let request = flow
            .request
            .take()
            .expect("a prepared flow owns exactly one request");
        if self.ai_budget_exceeded() && ai_meter::is_known_ai_provider(&request.url) {
            self.audit_ai_budget_exceeded(&flow, &request.url).await;
            return WireResponse::Refused {
                message: "AI egress budget exceeded".into(),
            };
        }
        let ai_meta = self.ai_tracker().map(|_| AiRequestMeta {
            method: request.method.clone(),
            url: request.url.clone(),
        });
        match self.forwarder.forward(request).await {
            Ok(mut response) => {
                let reinject_proofs = flow.replacement_flow.reinject_response(&mut response);
                self.audit_completed_flow(&flow, &reinject_proofs).await;
                if let Some(meta) = ai_meta {
                    self.record_ai_usage(&meta, response.status, &response.body)
                        .await;
                }
                WireResponse::Ok {
                    status: response.status,
                    headers: response.headers,
                    body_b64: B64.encode(response.body),
                }
            }
            Err(error) => WireResponse::Refused {
                message: error.to_string(),
            },
        }
    }

    /// Substitute and forward one FlowMux request while keeping the upstream
    /// response body incremental and bounded.
    pub(crate) async fn process_stream(
        self: &Arc<Self>,
        wire: WireRequest,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        let mut flow = self.prepare_flow(wire).await?;
        let request = flow
            .request
            .take()
            .expect("a prepared flow owns exactly one request");
        if self.ai_budget_exceeded() && ai_meter::is_known_ai_provider(&request.url) {
            self.audit_ai_budget_exceeded(&flow, &request.url).await;
            return Err(WireResponse::Refused {
                message: "AI egress budget exceeded".into(),
            });
        }
        let ai_meta = self.ai_tracker().map(|_| AiRequestMeta {
            method: request.method.clone(),
            url: request.url.clone(),
        });
        let upstream = self
            .forwarder
            .forward_stream(request)
            .await
            .map_err(|error| WireResponse::Refused {
                message: error.to_string(),
            })?;

        self.transform_response_stream(flow, upstream, ai_meta)
            .await
    }

    /// Process a FlowMux request body as bounded chunks. Signing and
    /// reversible request-body replacement need replay after seeing the full
    /// payload, so those explicit classes retain a bounded zeroizing replay
    /// buffer; every other typed request streams through the inspector.
    pub(crate) async fn process_body_stream(
        self: &Arc<Self>,
        head: mvm_core::substitution_wire::HttpFlowHead,
        mut body: tokio::sync::mpsc::Receiver<Zeroizing<Vec<u8>>>,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        let destination = destination_host(&head.url).ok();
        let replacement_action = destination
            .as_deref()
            .map(|dest| {
                crate::supervisor::reversible_replacement_resolve::resolve(
                    &self.reversible_replacement_policy,
                    dest,
                )
            })
            .cloned()
            .unwrap_or_default();
        let endpoint = NetworkEndpoint::new(&self.registry, self.resolver.as_ref());
        let signs_body = head.headers.iter().any(|(_, value)| {
            find_placeholder(value).is_some_and(|placeholder| {
                matches!(
                    endpoint.auth_type(placeholder),
                    Some(AuthType::Sigv4 | AuthType::Hmac)
                )
            })
        });
        let replaces_body =
            replacement_action.replaces_on(mvm_core::policy::RewriteSurface::RequestBody);

        if signs_body || replaces_body {
            let mut replay = Zeroizing::new(Vec::new());
            loop {
                let next = match tokio::time::timeout(HTTP_REQUEST_IDLE_TIMEOUT, body.recv()).await
                {
                    Ok(next) => next,
                    Err(_) => {
                        self.audit_fail_closed(destination.as_deref(), "request_body_idle_timeout")
                            .await;
                        return Err(WireResponse::Refused {
                            message: "request body idle timeout".into(),
                        });
                    }
                };
                let Some(chunk) = next else {
                    break;
                };
                if replay.len().saturating_add(chunk.len()) > MAX_HTTP_STREAM_BODY_BYTES {
                    self.audit_fail_closed(destination.as_deref(), "request_body_limit_exceeded")
                        .await;
                    return Err(WireResponse::Refused {
                        message: format!(
                            "request body exceeds the {MAX_HTTP_STREAM_BODY_BYTES} byte limit"
                        ),
                    });
                }
                replay.extend_from_slice(&chunk);
            }
            if replay.len() as u64 != head.body_len {
                self.audit_fail_closed(destination.as_deref(), "request_body_truncated")
                    .await;
                return Err(WireResponse::Refused {
                    message: "request body ended before its declared length".into(),
                });
            }
            return self
                .process_stream(WireRequest {
                    method: head.method,
                    url: head.url,
                    headers: head.headers,
                    body_b64: B64.encode(&*replay),
                })
                .await;
        }

        let wire = WireRequest {
            method: head.method,
            url: head.url,
            headers: head.headers,
            body_b64: String::new(),
        };
        let mut flow = self.prepare_flow(wire).await?;
        let request = flow
            .request
            .take()
            .expect("a prepared flow owns exactly one request");
        if self.ai_budget_exceeded() && ai_meter::is_known_ai_provider(&request.url) {
            self.audit_ai_budget_exceeded(&flow, &request.url).await;
            return Err(WireResponse::Refused {
                message: "AI egress budget exceeded".into(),
            });
        }
        let ai_meta = self.ai_tracker().map(|_| AiRequestMeta {
            method: request.method.clone(),
            url: request.url.clone(),
        });
        let expected_len = head.body_len;
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let service = Arc::clone(self);
        let action = flow.redaction_action.clone();
        let producer_destination = destination.clone();
        let producer = tokio::spawn(async move {
            let mut redactor = StreamingRedactor::new();
            let mut hits = RedactionHits::default();
            let mut received = 0_u64;
            loop {
                let next = match tokio::time::timeout(HTTP_REQUEST_IDLE_TIMEOUT, body.recv()).await
                {
                    Ok(next) => next,
                    Err(_) => {
                        service
                            .audit_fail_closed(
                                producer_destination.as_deref(),
                                "request_body_idle_timeout",
                            )
                            .await;
                        let _ = sender.send(Err("request body idle timeout".into())).await;
                        return Err(SensitiveDetectionError);
                    }
                };
                let Some(chunk) = next else {
                    break;
                };
                received = received.saturating_add(chunk.len() as u64);
                if received > expected_len {
                    service
                        .audit_fail_closed(
                            producer_destination.as_deref(),
                            "request_body_length_exceeded",
                        )
                        .await;
                    let _ = sender
                        .send(Err("request body exceeded its declared length".into()))
                        .await;
                    return Err(SensitiveDetectionError);
                }
                let (ready, chunk_hits) = match redactor.push(&service.redactor, &action, &chunk) {
                    Ok(result) => result,
                    Err(error) => {
                        service
                            .audit_fail_closed(
                                producer_destination.as_deref(),
                                "request_body_detector_failed",
                            )
                            .await;
                        let _ = sender
                            .send(Err("sensitive-data detector failed closed".into()))
                            .await;
                        return Err(error);
                    }
                };
                hits.merge(chunk_hits);
                if !ready.is_empty() && sender.send(Ok(ready)).await.is_err() {
                    service
                        .audit_fail_closed(
                            producer_destination.as_deref(),
                            "request_body_stream_canceled",
                        )
                        .await;
                    return Err(SensitiveDetectionError);
                }
            }
            if received != expected_len {
                service
                    .audit_fail_closed(producer_destination.as_deref(), "request_body_truncated")
                    .await;
                let _ = sender
                    .send(Err("request body ended before its declared length".into()))
                    .await;
                return Err(SensitiveDetectionError);
            }
            let (tail, tail_hits) = match redactor.finish(&service.redactor, &action) {
                Ok(result) => result,
                Err(error) => {
                    service
                        .audit_fail_closed(
                            producer_destination.as_deref(),
                            "request_body_detector_failed",
                        )
                        .await;
                    return Err(error);
                }
            };
            hits.merge(tail_hits);
            if !tail.is_empty() && sender.send(Ok(tail)).await.is_err() {
                service
                    .audit_fail_closed(
                        producer_destination.as_deref(),
                        "request_body_stream_canceled",
                    )
                    .await;
                return Err(SensitiveDetectionError);
            }
            Ok(hits)
        });
        let upstream = self
            .forwarder
            .forward_body_stream(request, receiver)
            .await
            .map_err(|error| WireResponse::Refused {
                message: error.to_string(),
            })?;
        let request_hits = producer
            .await
            .map_err(|_| WireResponse::Refused {
                message: "request transform task failed closed".into(),
            })?
            .map_err(|_| WireResponse::Refused {
                message: "request transform failed closed".into(),
            })?;
        flow.redaction_hits.merge(request_hits);
        self.transform_response_stream(flow, upstream, ai_meta)
            .await
    }

    async fn transform_response_stream(
        self: &Arc<Self>,
        mut flow: PreparedFlow,
        mut upstream: ForwardStreamResponse,
        ai_meta: Option<AiRequestMeta>,
    ) -> Result<ForwardStreamResponse, WireResponse> {
        // Reinject and redact response headers before any body byte can cross
        // to the guest. HTTP transfer framing belongs to the upstream leg, not
        // FlowMux; remove it because transforms may change decoded length.
        let mut head = ForwardResponse {
            status: upstream.status,
            headers: upstream.headers,
            body: Vec::new(),
        };
        let mut reinject_proofs = flow.replacement_flow.reinject_response(&mut head);
        head.headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("transfer-encoding")
        });
        for (_, value) in &mut head.headers {
            if let Some((redacted, hits)) = self
                .redactor
                .redact_bytes_for(value.as_bytes(), &flow.redaction_action)
            {
                if hits.detector_failures > 0 {
                    self.audit_fail_closed(
                        flow.destination.as_deref(),
                        "response_header_detector_failed",
                    )
                    .await;
                    return Err(WireResponse::Refused {
                        message: "sensitive-data detector failed closed; refusing response".into(),
                    });
                }
                *value = String::from_utf8_lossy(&redacted).into_owned();
                flow.redaction_hits.merge(hits);
            }
        }

        let response_status = head.status;
        let response_headers = std::mem::take(&mut head.headers);
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let service = Arc::clone(self);
        let response_destination = flow.destination.clone();
        let meter_streaming = ai_meta.is_some();
        tokio::spawn(async move {
            let mut redactor = StreamingRedactor::new();
            let mut ai_body_buffer = if meter_streaming {
                Some(Vec::with_capacity(0))
            } else {
                None
            };
            let mut reinjector = StreamingReinjector::new();
            while let Some(next) = upstream.body.recv().await {
                let chunk = match next {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        return;
                    }
                };
                if let Some(buf) = ai_body_buffer.as_mut().filter(|buf| {
                    buf.len().saturating_add(chunk.len()) <= MAX_AI_STREAM_BUFFER_BYTES
                }) {
                    buf.extend_from_slice(&chunk);
                }
                let (reintroduced, proofs) = reinjector.push(&mut flow.replacement_flow, &chunk);
                reinject_proofs.extend(proofs);
                let (ready, hits) =
                    match redactor.push(&service.redactor, &flow.redaction_action, &reintroduced) {
                        Ok(result) => result,
                        Err(_) => {
                            service
                                .audit_fail_closed(
                                    response_destination.as_deref(),
                                    "response_body_detector_failed",
                                )
                                .await;
                            let _ = sender
                                .send(Err(ForwardError::Failed(
                                    "sensitive-data detector failed closed".into(),
                                )))
                                .await;
                            return;
                        }
                    };
                flow.redaction_hits.merge(hits);
                if !ready.is_empty() && sender.send(Ok(ready)).await.is_err() {
                    service
                        .audit_fail_closed(
                            response_destination.as_deref(),
                            "response_body_stream_canceled",
                        )
                        .await;
                    return;
                }
            }
            let (reintroduced_tail, proofs) = reinjector.finish(&mut flow.replacement_flow);
            reinject_proofs.extend(proofs);
            let (ready, hits) = match redactor.push(
                &service.redactor,
                &flow.redaction_action,
                &reintroduced_tail,
            ) {
                Ok(result) => result,
                Err(_) => {
                    service
                        .audit_fail_closed(
                            response_destination.as_deref(),
                            "response_body_detector_failed",
                        )
                        .await;
                    let _ = sender
                        .send(Err(ForwardError::Failed(
                            "sensitive-data detector failed closed".into(),
                        )))
                        .await;
                    return;
                }
            };
            flow.redaction_hits.merge(hits);
            if !ready.is_empty() && sender.send(Ok(ready)).await.is_err() {
                service
                    .audit_fail_closed(
                        response_destination.as_deref(),
                        "response_body_stream_canceled",
                    )
                    .await;
                return;
            }
            let (tail, hits) = match redactor.finish(&service.redactor, &flow.redaction_action) {
                Ok(result) => result,
                Err(_) => {
                    service
                        .audit_fail_closed(
                            response_destination.as_deref(),
                            "response_body_detector_failed",
                        )
                        .await;
                    let _ = sender
                        .send(Err(ForwardError::Failed(
                            "sensitive-data detector failed closed".into(),
                        )))
                        .await;
                    return;
                }
            };
            flow.redaction_hits.merge(hits);
            if !tail.is_empty() && sender.send(Ok(tail)).await.is_err() {
                service
                    .audit_fail_closed(
                        response_destination.as_deref(),
                        "response_body_stream_canceled",
                    )
                    .await;
                return;
            }
            service.audit_completed_flow(&flow, &reinject_proofs).await;
            if let (Some(meta), Some(body)) = (ai_meta, ai_body_buffer) {
                service
                    .record_streaming_ai_usage(&meta, response_status, &body)
                    .await;
            }
        });

        Ok(ForwardStreamResponse {
            status: response_status,
            headers: response_headers,
            // Header/body transforms can change decoded length. Completion is
            // explicit and the guest applies an independent hard cap.
            body_len: None,
            body: receiver,
        })
    }

    /// Apply every pre-connect security decision once, returning the prepared
    /// request plus the state needed to transform and audit its response.
    async fn prepare_flow(&self, wire: WireRequest) -> Result<PreparedFlow, WireResponse> {
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
        // destination is refused before any forward leg runs. Shared with the
        // cleartext terminator cores so the gate can't drift.
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

    async fn audit_completed_flow(
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

    /// Mask undeclared secret-shaped / PII content out of a guest-authored
    /// request before it leaves the host — the request-level twin of the
    /// gateway bridge's packet redactor (one shared `RedactingSubstitution`).
    /// A header value carrying a declared placeholder is left untouched (the
    /// real credential is substituted into it next, and the host-reserved
    /// placeholder is not secret-shaped); every other header value and the body
    /// are scrubbed. Returns the rewritten request plus the categories that
    /// fired, for the claim-13 audit.
    fn redact_outbound(
        &self,
        req: ProxyRequest,
        action: &mvm_core::policy::RedactionAction,
    ) -> Result<(ProxyRequest, RedactionHits), SensitiveDetectionError> {
        let mut req = req;
        let hits = redact_request(&mut req, &self.redactor, action)?;
        Ok((req, hits))
    }

    fn replace_outbound(
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
}

fn ingress_transform_audit(
    mapping_id: u16,
    result: &Result<
        crate::supervisor::ingress_transform::IngressTransformSummary,
        crate::supervisor::ingress_transform::IngressTransformError,
    >,
) -> (&'static str, std::collections::BTreeMap<String, String>) {
    match result {
        Ok(summary) => (
            "host.ingress.transformed",
            std::collections::BTreeMap::from([
                ("mapping_id".to_string(), mapping_id.to_string()),
                ("verdict".to_string(), "allowed".to_string()),
                (
                    "request_rewrites".to_string(),
                    summary.request_rewrites.to_string(),
                ),
                (
                    "response_reinjections".to_string(),
                    summary.response_reinjections.to_string(),
                ),
                (
                    "redaction_events".to_string(),
                    summary.redaction_events.to_string(),
                ),
            ]),
        ),
        Err(error) => (
            "host.ingress.transform_refused",
            std::collections::BTreeMap::from([
                ("mapping_id".to_string(), mapping_id.to_string()),
                ("verdict".to_string(), "denied".to_string()),
                ("reason".to_string(), error.audit_reason().to_string()),
            ]),
        ),
    }
}

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
    async fn audit_placeholder_dropped(&self, destination: Option<&str>) {
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
    async fn audit_fail_closed(&self, destination: Option<&str>, reason: &str) {
        let (Some(recorder), Some(dest)) = (&self.recorder, destination) else {
            return;
        };
        if let Err(e) = emit_secret_redacted(recorder, dest, reason).await {
            tracing::warn!(error = %e, "fail-closed audit emit failed");
        }
    }
}

/// Host-side AF_VSOCK listener for the QEMU (`vhost-vsock`) guest→host
/// substitution path. Firecracker/libkrun bridge guest→host through a per-port
/// UDS — those use the `UnixListener` `serve`. Raw libc (no async-vsock dep);
/// blocking `accept` is driven from the async loop via `spawn_blocking`.
#[cfg(target_os = "linux")]
pub mod vsock {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    const AF_VSOCK: libc::c_int = 40;
    /// Bind to any guest CID so any guest on this host can reach the endpoint.
    const VMADDR_CID_ANY: u32 = u32::MAX;

    // Kernel uapi `struct sockaddr_vm`.
    #[repr(C)]
    struct SockaddrVm {
        svm_family: libc::sa_family_t,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        /// `VMADDR_FLAG_TO_HOST` and friends. Zero for every address mvm
        /// builds; carried so the mirror matches the header field-for-field.
        svm_flags: u8,
        svm_zero: [u8; 3],
    }

    // Layout contract with linux/vm_sockets.h, derived on Linux 6.8 with cc
    // sizeof/offsetof/_Alignof rather than read off the Rust definition.
    // Bytes 12..16: the header gained `svm_flags` at offset 12 in Linux 6.0,
    // shrinking `svm_zero` to three bytes. The total is 16 either way, which
    // is why the pre-6.0 shape went unnoticed here.
    const _: () = {
        use std::mem::{align_of, offset_of, size_of};

        assert!(size_of::<SockaddrVm>() == 16);
        assert!(align_of::<SockaddrVm>() == 4);
        assert!(offset_of!(SockaddrVm, svm_family) == 0);
        assert!(offset_of!(SockaddrVm, svm_reserved1) == 2);
        assert!(offset_of!(SockaddrVm, svm_port) == 4);
        assert!(offset_of!(SockaddrVm, svm_cid) == 8);
        assert!(offset_of!(SockaddrVm, svm_flags) == 12);
        assert!(offset_of!(SockaddrVm, svm_zero) == 13);
    };

    /// A bound, listening host AF_VSOCK socket on a vsock port.
    pub struct VsockListener {
        fd: OwnedFd,
    }

    impl VsockListener {
        /// Bind + listen on AF_VSOCK `(VMADDR_CID_ANY, port)`.
        pub fn bind(port: u32) -> io::Result<Self> {
            // SAFETY: standard socket/bind/listen on AF_VSOCK; `addr` is fully
            // initialized and sized exactly. The fd is adopted by `OwnedFd`
            // immediately, closing on drop / on the error paths.
            unsafe {
                let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let owned = OwnedFd::from_raw_fd(fd);
                let addr = SockaddrVm {
                    svm_family: AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: VMADDR_CID_ANY,
                    svm_flags: 0,
                    svm_zero: [0; 3],
                };
                if libc::bind(
                    fd,
                    std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::listen(fd, 128) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self { fd: owned })
            }
        }

        pub fn raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    /// Blocking `accept(2)` on a listening AF_VSOCK fd, returning the
    /// connection fd. Run via `spawn_blocking` from the async serve loop.
    pub fn accept(listen_fd: RawFd) -> io::Result<RawFd> {
        // SAFETY: accept(2) on a listening AF_VSOCK fd; peer addr not needed.
        let cfd = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cfd)
    }

    /// Read one length-prefixed JSON frame (4-byte BE length + body) with
    /// blocking I/O. The vsock connection is handled synchronously (tokio's
    /// async reactor doesn't interplay reliably with an AF_VSOCK fd).
    pub fn read_frame_sync<T: serde::de::DeserializeOwned, R: io::Read>(
        r: &mut R,
    ) -> io::Result<T> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > super::MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf)?;
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write one length-prefixed JSON frame with blocking I/O.
    pub fn write_frame_sync<T: serde::Serialize, W: io::Write>(
        w: &mut W,
        value: &T,
    ) -> io::Result<()> {
        let body =
            serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = u32::try_from(body.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
        w.write_all(&len.to_be_bytes())?;
        w.write_all(&body)?;
        w.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyholder::{LocalResolver, SubstitutionRegistry};
    use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use secrecy::SecretBox;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn resolver_with(name: &str, value: &str) -> (tempfile::TempDir, LocalResolver) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put("local", name, &SecretBox::new(Box::new(value.to_string())))
            .unwrap();
        let store: Arc<dyn SecretStore> = Arc::new(store);
        (dir, LocalResolver::new("local", store))
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

    fn sigv4_ref(name: &str, hosts: &[&str], service: &str, region: &str) -> SecretRef {
        use mvm_contract::ir::Sigv4Params;
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Sigv4,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: Some(Sigv4Params {
                access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
                region: region.into(),
                service: service.into(),
            }),
        }
    }

    fn sigv4_ref_no_params(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Sigv4,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

    fn hmac_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Hmac,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

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
mod response_body_tests {
    use super::*;

    #[test]
    fn declared_response_length_is_checked_before_reading() {
        check_forward_response_length(Some(MAX_FORWARD_RESPONSE_BYTES as u64))
            .expect("a body exactly at the limit is accepted");
        let err = check_forward_response_length(Some((MAX_FORWARD_RESPONSE_BYTES as u64) + 1))
            .expect_err("an oversized declaration must be refused before allocation");
        assert!(err.to_string().contains("response body exceeds"));
        check_forward_response_length(None)
            .expect("chunked or close-delimited bodies are streamed");
    }
}

#[cfg(test)]
mod server_tests {
    use super::*;
    use crate::keyholder::LocalResolver;
    use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use secrecy::SecretBox;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Records the request it was handed so a test can prove the destination
    /// (not the guest) received the real credential — without a network call.
    struct MockForwarder {
        seen: Mutex<Option<PreparedRequest>>,
    }

    struct RedirectForwarder {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl Forwarder for MockForwarder {
        async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            *self.seen.lock().unwrap() = Some(req);
            Ok(ForwardResponse {
                status: 200,
                headers: vec![("x-mock".into(), "1".into())],
                body: b"pong".to_vec(),
            })
        }
    }

    #[async_trait]
    impl Forwarder for RedirectForwarder {
        async fn forward(&self, _req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ForwardResponse {
                status: 302,
                headers: vec![("location".into(), "https://unbound.example/steal".into())],
                body: Vec::new(),
            })
        }
    }

    fn bearer_ref(name: &str, hosts: &[&str]) -> SecretRef {
        SecretRef {
            name: name.into(),
            mount: SecretMount::Env { var: "K".into() },
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
            sigv4: None,
        }
    }

    /// Build a service over a file store seeded with `openai`=value, a registry
    /// holding one minted placeholder for `hosts`, and a `MockForwarder`.
    /// Returns the service, the minted placeholder string, and the forwarder.
    fn service_with(
        value: &str,
        hosts: &[&str],
    ) -> (
        Arc<SubstitutionService>,
        String,
        Arc<MockForwarder>,
        tempfile::TempDir,
    ) {
        service_with_policies(value, hosts, None, None)
    }

    fn service_with_policies(
        value: &str,
        hosts: &[&str],
        redaction_policy: Option<mvm_core::policy::RedactionPolicy>,
        reversible_policy: Option<mvm_core::policy::ReversibleReplacementPolicy>,
    ) -> (
        Arc<SubstitutionService>,
        String,
        Arc<MockForwarder>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new(value.to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut reg = SubstitutionRegistry::new();
        let ph = reg.mint(bearer_ref("openai", hosts)).as_str().to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let mut service = SubstitutionService::new(Arc::new(reg), resolver, forwarder.clone());
        if let Some(policy) = redaction_policy {
            service = service.with_redaction_policy(policy);
        }
        if let Some(policy) = reversible_policy {
            service = service.with_reversible_replacement_policy(policy);
        }
        (Arc::new(service), ph, forwarder, dir)
    }

    #[test]
    fn host_material_resolves_by_signed_name_without_serializing_its_value() {
        use secrecy::ExposeSecret as _;

        let marker = "-----BEGIN PRIVATE KEY-----\nhost-only";
        let (service, placeholder, _forwarder, _dir) =
            service_with(marker, &["ingress-material.local"]);
        let resolved = service.resolve_host_material("openai").unwrap();
        assert_eq!(resolved.expose_secret().as_slice(), marker.as_bytes());
        assert!(!placeholder.contains(marker));
        assert!(matches!(
            service.resolve_host_material("not-admitted"),
            Err(HostMaterialError::NotAdmitted { .. })
        ));
    }

    #[test]
    fn a_secret_bound_destination_requires_the_typed_transform_class() {
        let (service, _placeholder, _forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);

        assert_eq!(
            service.opaque_refusal_reason("api.openai.com"),
            Some("destination requires secret substitution over typed HTTP")
        );
        assert_eq!(service.opaque_refusal_reason("example.com"), None);
    }

    #[test]
    fn explicit_redaction_and_replacement_require_the_typed_transform_class() {
        use mvm_core::policy::{
            EntropyMode, RedactionAction, RedactionPolicy, RedactionProfile,
            ReversibleReplacementAction, ReversibleReplacementPolicy, ReversibleReplacementProfile,
        };

        let redaction = RedactionPolicy {
            profiles: vec![RedactionProfile {
                host: "redact.example".into(),
                action: RedactionAction {
                    entropy: EntropyMode::Redact {
                        min_bits_per_char: 4.0,
                        min_run_len: 20,
                    },
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        let replacement = ReversibleReplacementPolicy {
            profiles: vec![ReversibleReplacementProfile {
                host: "replace.example".into(),
                action: ReversibleReplacementAction {
                    enabled: true,
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        let (service, _placeholder, _forwarder, _dir) = service_with_policies(
            "sk-live-zzz",
            &["secret.example"],
            Some(redaction),
            Some(replacement),
        );

        assert_eq!(
            service.opaque_refusal_reason("redact.example"),
            Some("destination requires redaction over typed HTTP")
        );
        assert_eq!(
            service.opaque_refusal_reason("replace.example"),
            Some("destination requires reversible replacement over typed HTTP")
        );
        assert_eq!(service.opaque_refusal_reason("opaque.example"), None);
    }

    #[test]
    fn curated_default_redaction_does_not_claim_to_transform_opaque_flows() {
        let (service, _placeholder, _forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);

        assert_eq!(service.opaque_refusal_reason("opaque.example"), None);
    }

    #[tokio::test]
    async fn flowmux_request_body_streams_through_split_token_redaction() {
        let (service, placeholder, forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);
        let secret = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let split = 13;
        let mut first = vec![b'x'; STREAM_TRANSFORM_OVERLAP - split];
        first.extend_from_slice(&secret[..split]);
        let second = secret[split..].to_vec();
        let body_len = (first.len() + second.len()) as u64;
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        sender.send(Zeroizing::new(first)).await.unwrap();
        sender.send(Zeroizing::new(second)).await.unwrap();
        drop(sender);

        let mut response = service
            .process_body_stream(
                mvm_core::substitution_wire::HttpFlowHead {
                    method: "POST".into(),
                    url: "https://api.openai.com/v1".into(),
                    headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
                    body_len,
                },
                receiver,
            )
            .await
            .expect("streamed request");
        let mut response_body = Vec::new();
        while let Some(chunk) = response.body.recv().await {
            response_body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(response_body, b"pong");

        let seen = forwarder.seen.lock().unwrap();
        let request = seen.as_ref().expect("forwarded request");
        assert!(
            !request
                .body
                .windows(secret.len())
                .any(|window| window == secret),
            "split secret crossed the request inspector"
        );
        assert_eq!(request.headers[0].1, "Bearer sk-live-zzz");
    }

    #[tokio::test]
    async fn signing_flow_uses_the_bounded_replay_buffer_before_forwarding() {
        let dir = tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "hook",
                &SecretBox::new(Box::new("Jefe".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(SecretRef {
                name: "hook".into(),
                mount: SecretMount::Env { var: "K".into() },
                auth_type: AuthType::Hmac,
                allowed_hosts: vec!["hooks.example.com".into()],
                sigv4: None,
            })
            .as_str()
            .to_string();
        let forwarder = Arc::new(MockForwarder {
            seen: Mutex::new(None),
        });
        let service = Arc::new(SubstitutionService::new(
            Arc::new(registry),
            resolver,
            forwarder.clone(),
        ));
        let body = b"what do ya want for nothing?";
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(Zeroizing::new(body[..10].to_vec()))
            .await
            .unwrap();
        sender
            .send(Zeroizing::new(body[10..].to_vec()))
            .await
            .unwrap();
        drop(sender);
        let mut response = service
            .process_body_stream(
                mvm_core::substitution_wire::HttpFlowHead {
                    method: "POST".into(),
                    url: "https://hooks.example.com/event".into(),
                    headers: vec![("x-sig".into(), placeholder)],
                    body_len: body.len() as u64,
                },
                receiver,
            )
            .await
            .expect("signed request");
        while response.body.recv().await.is_some() {}

        let seen = forwarder.seen.lock().unwrap();
        let request = seen.as_ref().expect("forwarded request");
        assert_eq!(request.body, body);
        assert!(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("x-mvm-signature")
                && value == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        }));
    }

    /// End-to-end over a **real AF_VSOCK** connection (Linux vsock loopback,
    /// `VMADDR_CID_LOCAL`) — proving `serve_vsock` + the framed substitution
    /// path work over the actual transport, not just a UnixStream pair.
    /// Gracefully skips where vsock/loopback is unavailable (CI, macOS) so it
    /// only asserts where it can really run (a vsock-capable Linux box).
    #[cfg(target_os = "linux")]
    #[test]
    fn substitutes_over_real_af_vsock_loopback() {
        use super::vsock::VsockListener;
        use std::io::{Read, Write};
        use std::os::fd::FromRawFd;

        // serve_vsock's accept loop parks an un-cancellable spawn_blocking(accept);
        // a plain #[tokio::test] would hang on runtime drop waiting for it to
        // return. Build the runtime by hand and force teardown with
        // shutdown_timeout once the round-trip + assertions are done.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            const AF_VSOCK: libc::c_int = 40;
            const VMADDR_CID_LOCAL: u32 = 1;
            // A double of a kernel ABI type that is free to disagree with
            // the kernel cannot falsify anything the real type does, so it
            // carries the same contract as the production copy above.
            #[repr(C)]
            struct SockaddrVm {
                svm_family: libc::sa_family_t,
                svm_reserved1: u16,
                svm_port: u32,
                svm_cid: u32,
                svm_flags: u8,
                svm_zero: [u8; 3],
            }
            const _: () = {
                use std::mem::{align_of, offset_of, size_of};

                assert!(size_of::<SockaddrVm>() == 16);
                assert!(align_of::<SockaddrVm>() == 4);
                assert!(offset_of!(SockaddrVm, svm_family) == 0);
                assert!(offset_of!(SockaddrVm, svm_reserved1) == 2);
                assert!(offset_of!(SockaddrVm, svm_port) == 4);
                assert!(offset_of!(SockaddrVm, svm_cid) == 8);
                assert!(offset_of!(SockaddrVm, svm_flags) == 12);
                assert!(offset_of!(SockaddrVm, svm_zero) == 13);
            };

            let port = 54000 + (std::process::id() % 2000);
            let listener = match VsockListener::bind(port) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!(
                        "SKIP substitutes_over_real_af_vsock_loopback: AF_VSOCK bind failed ({e})"
                    );
                    return;
                }
            };
            let (service, ph, forwarder, _dir) = service_with("sk-live-zzz", &["api.openai.com"]);
            let server = tokio::spawn(Arc::clone(&service).serve_vsock(listener));

            // Client: connect over vsock loopback, send a framed WireRequest with the
            // placeholder, read the framed WireResponse. `None` = transport
            // unavailable → skip rather than assert.
            let client = tokio::task::spawn_blocking(move || -> Option<WireResponse> {
                let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
                if fd < 0 {
                    return None;
                }
                let addr = SockaddrVm {
                    svm_family: AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: port,
                    svm_cid: VMADDR_CID_LOCAL,
                    svm_flags: 0,
                    svm_zero: [0; 3],
                };
                let rc = unsafe {
                    libc::connect(
                        fd,
                        std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                        std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
                    )
                };
                if rc < 0 {
                    unsafe { libc::close(fd) };
                    return None;
                }
                let mut s = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                // Bound the round-trip so a regression fails fast instead of hanging.
                s.set_read_timeout(Some(std::time::Duration::from_secs(15)))
                    .ok();
                s.set_write_timeout(Some(std::time::Duration::from_secs(15)))
                    .ok();
                let wire = WireRequest {
                    method: "POST".into(),
                    url: "https://api.openai.com/v1".into(),
                    headers: vec![("authorization".into(), format!("Bearer {ph}"))],
                    body_b64: String::new(),
                };
                let body = serde_json::to_vec(&wire).unwrap();
                s.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
                s.write_all(&body).unwrap();
                s.flush().unwrap();
                let mut len = [0u8; 4];
                s.read_exact(&mut len).unwrap();
                let n = u32::from_be_bytes(len) as usize;
                let mut buf = vec![0u8; n];
                s.read_exact(&mut buf).unwrap();
                Some(serde_json::from_slice(&buf).unwrap())
            });
            // vsock does not reliably honor SO_RCVTIMEO, so the in-client read
            // timeout can't be trusted — bound the round-trip here so a server-side
            // regression fails fast instead of hanging until libtest's watchdog.
            let resp = match tokio::time::timeout(std::time::Duration::from_secs(20), client).await
            {
                Ok(joined) => joined.unwrap(),
                Err(_) => {
                    panic!("vsock loopback round-trip timed out (20s): serve_vsock did not reply")
                }
            };

            let Some(resp) = resp else {
                eprintln!(
                    "SKIP substitutes_over_real_af_vsock_loopback: vsock loopback unavailable"
                );
                server.abort();
                return;
            };

            // The destination (mock forwarder) saw the REAL credential over real vsock.
            let seen = forwarder.seen.lock().unwrap().clone().unwrap();
            assert_eq!(
                seen.headers[0],
                ("authorization".into(), "Bearer sk-live-zzz".into())
            );
            match resp {
                WireResponse::Ok { status, .. } => assert_eq!(status, 200),
                WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
            }
            server.abort();
        });
        rt.shutdown_timeout(std::time::Duration::from_millis(50));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_streaming_request_hits_the_idle_deadline_without_forwarding() {
        let (service, _placeholder, forwarder, _dir) =
            service_with("sk-live-zzz", &["api.openai.com"]);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let task_service = Arc::clone(&service);
        let request = tokio::spawn(async move {
            task_service
                .process_body_stream(
                    mvm_core::substitution_wire::HttpFlowHead {
                        method: "POST".into(),
                        url: "https://api.openai.com/v1".into(),
                        headers: Vec::new(),
                        body_len: 1,
                    },
                    receiver,
                )
                .await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(HTTP_REQUEST_IDLE_TIMEOUT + std::time::Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        drop(sender);
        let refusal = match request.await.expect("request task") {
            Ok(_) => panic!("idle request must refuse"),
            Err(refusal) => refusal,
        };
        assert!(
            matches!(
                refusal,
                WireResponse::Refused { ref message }
                    if message.contains("idle timeout") || message.contains("failed closed")
            ),
            "unexpected refusal: {refusal:?}"
        );
        assert!(
            forwarder.seen.lock().unwrap().is_none(),
            "an incomplete request must never reach the destination"
        );
    }

    #[tokio::test]
    async fn a_redirect_is_returned_without_following_or_rebinding_substitution() {
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
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(bearer_ref("openai", &["api.openai.com"]))
            .as_str()
            .to_string();
        let forwarder = Arc::new(RedirectForwarder {
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let service = Arc::new(SubstitutionService::new(
            Arc::new(registry),
            resolver,
            forwarder.clone(),
        ));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(sender);
        let mut response = service
            .process_body_stream(
                mvm_core::substitution_wire::HttpFlowHead {
                    method: "GET".into(),
                    url: "https://api.openai.com/v1".into(),
                    headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
                    body_len: 0,
                },
                receiver,
            )
            .await
            .expect("redirect response");
        while response.body.recv().await.is_some() {}

        assert_eq!(response.status, 302);
        assert!(response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("location") && value == "https://unbound.example/steal"
        }));
        assert_eq!(
            forwarder.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the endpoint must surface a redirect, never follow it with the bound credential"
        );
    }

    #[tokio::test]
    async fn endpoint_substitutes_then_forwards_over_uds() {
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
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
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();

        // The forwarder (i.e. the destination) saw the REAL credential.
        let seen = forwarder.seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            seen.headers[0],
            ("authorization".into(), "Bearer sk-live-zzz".into())
        );
        match resp {
            WireResponse::Ok {
                status, body_b64, ..
            } => {
                assert_eq!(status, 200);
                assert_eq!(B64.decode(body_b64).unwrap(), b"pong");
            }
            WireResponse::Refused { message } => panic!("unexpected refusal: {message}"),
        }
        server.abort();
    }

    /// The endpoint scrubs an *undeclared* secret-shaped run from the
    /// outbound body before forwarding (the same
    /// redaction the gateway bridge applies, at the endpoint chokepoint so
    /// every backend routing egress through it is covered), while a *declared*
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

    #[test]
    fn from_plan_builds_a_service_and_handed_placeholders() {
        use crate::keyholder::{FileBindingStore, SecretBindingMeta};
        use mvm_core::plan::{SecretBinding, SecretSource};

        let dir = tempdir().unwrap();
        // Binding metadata (`secret set`) + the value store.
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
                &SecretBox::new(Box::new("sk".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));

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
        assert_eq!(handed.len(), 1);
        assert_eq!(handed[0].0, "OPENAI_API_KEY");
        assert!(handed[0].1.as_str().starts_with("mvm-secret-"));
    }

    #[test]
    fn from_plan_threads_redaction_policy_onto_the_service() {
        use crate::keyholder::{FileBindingStore, SecretBindingMeta};
        use mvm_core::plan::{SecretBinding, SecretSource};
        use mvm_core::policy::{EntropyMode, RedactionAction, RedactionPolicy, RedactionProfile};

        let dir = tempdir().unwrap();
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
                &SecretBox::new(Box::new("sk".to_string())),
            )
            .unwrap();
        let resolver: Arc<dyn SecretResolver> =
            Arc::new(LocalResolver::new("local", Arc::new(store)));

        let plan = [SecretBinding {
            name: "OPENAI_API_KEY".into(),
            source: SecretSource::Keystore {
                address: "openai".into(),
            },
        }];

        // A policy that opts api.openai.com into entropy redaction. After
        // from_plan, resolving that host must yield the opted-in action — proving
        // the policy reached the live service (not just defaulted).
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
        let (service, _handed) = SubstitutionService::from_plan(FromPlanInputs {
            plan_secrets: &plan,
            tenant: "local",
            instance_id: "",
            ai_policy: None,
            bindings: &bindings,
            resolver,
            forward_timeout_secs: 30,
            proxy: None,
            redaction: policy,
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            tls_intermediate: None,
            recorder: None,
        })
        .unwrap();
        let resolved = crate::supervisor::redaction_resolve::resolve(
            service.redaction_policy(),
            "api.openai.com",
        );
        assert!(
            matches!(resolved.entropy, EntropyMode::Redact { .. }),
            "redaction policy did not reach the service: {:?}",
            resolved.entropy
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
            SubstitutionService::new(Arc::new(reg), resolver, Arc::clone(&forwarder) as _)
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
            matches!(resp, WireResponse::Refused { .. }),
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
            SubstitutionService::new(Arc::new(reg), resolver, forwarder).with_recorder(recorder),
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

        let service = Arc::new(
            SubstitutionService::new(Arc::new(reg), resolver, Arc::clone(&forwarder) as _)
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
        assert!(matches!(resp, WireResponse::Refused { .. }));
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

/// Minimal request metadata captured for AI metering so the streaming path
/// doesn't need to own the whole prepared request after it has been handed
/// to the forwarder.
#[derive(Debug, Clone)]
struct AiRequestMeta {
    method: String,
    url: String,
}

impl SubstitutionService {
    fn ai_tracker(&self) -> Option<&std::sync::Arc<ai_meter::AiBudgetTracker>> {
        self.ai_tracker.as_ref()
    }

    fn ai_budget_exceeded(&self) -> bool {
        self.ai_tracker().map(|t| t.is_exceeded()).unwrap_or(false)
    }

    async fn record_ai_usage(&self, meta: &AiRequestMeta, status: u16, body: &[u8]) {
        let Some(tracker) = self.ai_tracker() else {
            return;
        };
        let Some(usage) = ai_meter::extract_usage(&meta.url, body) else {
            return;
        };
        let totals = tracker.record(&usage);
        self.update_ai_metrics(totals);
        if let Some(recorder) = &self.recorder {
            let record = self.build_ai_usage_record(meta, status, &usage, totals.exceeded);
            if let Err(e) = recorder.record_ai_usage(&record).await {
                tracing::warn!(error = %e, "ai.usage audit emit failed");
            }
            if totals.exceeded {
                emit_ai_budget_exceeded(recorder, &record).await;
            }
        }
    }

    async fn record_streaming_ai_usage(&self, meta: &AiRequestMeta, status: u16, body: &[u8]) {
        let Some(tracker) = self.ai_tracker() else {
            return;
        };
        let Some(usage) = ai_meter::extract_streaming_usage(&meta.url, body) else {
            return;
        };
        let totals = tracker.record(&usage);
        self.update_ai_metrics(totals);
        if let Some(recorder) = &self.recorder {
            let record = self.build_ai_usage_record(meta, status, &usage, totals.exceeded);
            if let Err(e) = recorder.record_ai_usage(&record).await {
                tracing::warn!(error = %e, "ai.usage audit emit failed");
            }
            if totals.exceeded {
                emit_ai_budget_exceeded(recorder, &record).await;
            }
        }
    }

    async fn audit_ai_budget_exceeded(&self, flow: &PreparedFlow, url: &str) {
        let Some(recorder) = &self.recorder else {
            return;
        };
        let (host, port, path) = parse_url_parts(url);
        let destination = flow.destination.as_deref().unwrap_or(&host);
        let record = AiUsageRecord {
            trace_id: String::new(),
            span_id: String::new(),
            host: destination.to_string(),
            port,
            method: String::new(),
            path,
            provider: String::new(),
            model: None,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            status: 0,
            budget_exceeded: true,
        };
        if let Err(e) = recorder.record_ai_budget_exceeded(&record).await {
            tracing::warn!(error = %e, destination, "ai.budget_exceeded audit emit failed");
        }
    }

    fn update_ai_metrics(&self, totals: ai_meter::UsageTotals) {
        let Some(instance_id) = self.instance_id.as_deref() else {
            return;
        };
        let registry: &InstanceMetricsRegistry = match &self.instance_metrics {
            Some(r) => r.as_ref(),
            None => instance_metrics_global(),
        };
        if !registry.update_ai_counters(
            instance_id,
            totals.requests,
            totals.input_tokens,
            totals.output_tokens,
            totals.total_tokens,
        ) {
            let labels = InstanceLabels {
                instance_id: instance_id.to_string(),
                tenant: self.tenant.clone(),
                template: String::new(),
            };
            registry.register(labels);
            let _ = registry.update_ai_counters(
                instance_id,
                totals.requests,
                totals.input_tokens,
                totals.output_tokens,
                totals.total_tokens,
            );
        }
    }

    fn build_ai_usage_record(
        &self,
        meta: &AiRequestMeta,
        status: u16,
        usage: &ai_meter::ExtractedUsage,
        budget_exceeded: bool,
    ) -> AiUsageRecord {
        let (host, port, path) = parse_url_parts(&meta.url);
        AiUsageRecord {
            trace_id: String::new(),
            span_id: String::new(),
            host,
            port,
            method: meta.method.clone(),
            path,
            provider: usage.provider.to_string(),
            model: usage.model.clone(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            total_tokens: usage.total_tokens,
            status,
            budget_exceeded,
        }
    }
}

async fn emit_ai_budget_exceeded(recorder: &Recorder, record: &AiUsageRecord) {
    if let Err(e) = recorder.record_ai_budget_exceeded(record).await {
        tracing::warn!(error = %e, "ai.budget_exceeded audit emit failed");
    }
}

fn parse_url_parts(url: &str) -> (String, u16, String) {
    let Some(u) = Url::parse(url).ok() else {
        return (String::new(), 0, String::new());
    };
    let host = u.host_str().unwrap_or("").to_string();
    let port = u.port_or_known_default().unwrap_or(0);
    let path = u.path().to_string();
    (host, port, path)
}

#[cfg(test)]
#[test]
fn ingress_transform_audit_contains_only_bounded_metadata() {
    let result = Ok(
        crate::supervisor::ingress_transform::IngressTransformSummary {
            request_rewrites: 2,
            response_reinjections: 1,
            redaction_events: 3,
        },
    );
    let (event, labels) = ingress_transform_audit(17, &result);
    let encoded = serde_json::to_string(&labels).unwrap();

    assert_eq!(event, "host.ingress.transformed");
    assert_eq!(labels.get("mapping_id").map(String::as_str), Some("17"));
    assert_eq!(
        labels.get("request_rewrites").map(String::as_str),
        Some("2")
    );
    assert!(!encoded.contains("payload"));
    assert!(!encoded.contains("PRIVATE KEY"));
    assert!(!encoded.contains("sk-"));
}

#[cfg(test)]
#[test]
fn ingress_transform_refusal_audit_contains_only_a_stable_reason() {
    let result = Err(crate::supervisor::ingress_transform::IngressTransformError::BodyTooLarge);
    let (event, labels) = ingress_transform_audit(19, &result);
    let encoded = serde_json::to_string(&labels).unwrap();

    assert_eq!(event, "host.ingress.transform_refused");
    assert_eq!(
        labels,
        std::collections::BTreeMap::from([
            ("mapping_id".to_string(), "19".to_string()),
            ("reason".to_string(), "body_too_large".to_string()),
            ("verdict".to_string(), "denied".to_string()),
        ])
    );
    assert!(!encoded.contains("payload"));
    assert!(!encoded.contains("PRIVATE KEY"));
    assert!(!encoded.contains("sk-"));
}

#[cfg(test)]
mod error_audit_tests {
    use super::*;
    use crate::supervisor::terminator::error::TerminatorError;

    /// A fail-closed refusal must be audited. This is the one the mutation lane
    /// caught: deleting the `FailClosed` arm left every test passing, because a
    /// missing audit entry is invisible to anything that only checks the socket
    /// closed — and every one of these paths closes the socket either way.
    #[test]
    fn a_fail_closed_refusal_is_audited_with_its_reason() {
        let err = TerminatorError::FailClosed("body not scannable in cleartext");
        assert_eq!(
            error_audit(&err, false),
            ErrorAudit::FailClosed("body not scannable in cleartext")
        );
        // The reason travels regardless of whether a placeholder was carried:
        // fail-closed is about what could not be scanned, not about substitution.
        assert_eq!(
            error_audit(&err, true),
            ErrorAudit::FailClosed("body not scannable in cleartext")
        );
    }

    /// A refusal is claim-12 relevant only when a placeholder was actually
    /// dropped. Refusing a request that carried none is not a secret event.
    #[test]
    fn a_refusal_is_audited_only_when_it_dropped_a_placeholder() {
        let err = TerminatorError::Refused("unbound destination".into());
        assert_eq!(error_audit(&err, true), ErrorAudit::PlaceholderDropped);
        assert_eq!(error_audit(&err, false), ErrorAudit::Silent);
    }

    /// Parse and forward failures are fail-closed like everything else here,
    /// but they are not secret-relevant and must not manufacture audit entries
    /// — an audit log that records ordinary I/O failures as security events is
    /// as unreadable as one that records nothing.
    #[test]
    fn parse_and_forward_failures_record_nothing() {
        for err in [
            TerminatorError::Parse("bad request line".into()),
            TerminatorError::Forward("connection reset".into()),
        ] {
            assert_eq!(error_audit(&err, false), ErrorAudit::Silent, "{err}");
            assert_eq!(error_audit(&err, true), ErrorAudit::Silent, "{err}");
        }
    }
}

#[cfg(test)]
mod ai_metering_tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    use super::*;
    use crate::keyholder::SubstitutionRegistry;
    use mvm_contract::policy::network_policy::AiPolicy;
    use mvm_core::observability::instance_metrics::InstanceMetricsRegistry;
    use secrecy::SecretBox;

    struct NullResolver;

    impl crate::keyholder::SecretResolver for NullResolver {
        fn resolve(
            &self,
            _r: &crate::keyholder::SecretRef,
        ) -> Result<SecretBox<Vec<u8>>, crate::keyholder::ResolveError> {
            Err(crate::keyholder::ResolveError::Unbound {
                name: String::new(),
            })
        }
    }

    struct TestForwarder {
        status: u16,
        body: Vec<u8>,
    }

    impl TestForwarder {
        fn ok(body: impl Into<Vec<u8>>) -> Self {
            Self {
                status: 200,
                body: body.into(),
            }
        }
    }

    #[async_trait]
    impl Forwarder for TestForwarder {
        async fn forward(&self, _req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            Ok(ForwardResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone(),
            })
        }

        async fn forward_stream(
            &self,
            _req: PreparedRequest,
        ) -> Result<ForwardStreamResponse, ForwardError> {
            let (sender, receiver) = tokio::sync::mpsc::channel(2);
            for chunk in self.body.chunks(64) {
                sender
                    .send(Ok(chunk.to_vec()))
                    .await
                    .map_err(|_| ForwardError::Failed("consumer closed".into()))?;
            }
            Ok(ForwardStreamResponse {
                status: self.status,
                headers: Vec::new(),
                body_len: Some(self.body.len() as u64),
                body: receiver,
            })
        }
    }

    fn openai_response() -> Vec<u8> {
        br#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#
            .to_vec()
    }

    fn openai_stream() -> Vec<u8> {
        b"data: {\"choices\":[]}\n\ndata: {\"model\":\"gpt-4\",\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n".to_vec()
    }

    fn wire_to(url: &str) -> WireRequest {
        WireRequest {
            method: "POST".into(),
            url: url.into(),
            headers: Vec::new(),
            body_b64: B64.encode(b""),
        }
    }

    fn metered_service(
        forwarder: Arc<dyn Forwarder>,
        policy: AiPolicy,
    ) -> (Arc<SubstitutionService>, Arc<InstanceMetricsRegistry>) {
        let metrics = Arc::new(InstanceMetricsRegistry::new());
        let service = Arc::new(
            SubstitutionService::new(
                Arc::new(SubstitutionRegistry::default()),
                Arc::new(NullResolver),
                forwarder,
            )
            .with_instance_id("vm-1")
            .with_ai_policy(policy)
            .with_instance_metrics(Arc::clone(&metrics)),
        );
        (service, metrics)
    }

    #[tokio::test]
    async fn process_records_openai_usage_in_tracker_and_metrics() {
        let (service, metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered(),
        );
        let resp = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(resp, WireResponse::Ok { status: 200, .. }));

        let tracker = service.ai_tracker().expect("metering was enabled");
        assert_eq!(tracker.totals().requests, 1);
        assert_eq!(tracker.totals().input_tokens, 10);
        assert_eq!(tracker.totals().output_tokens, 5);
        assert_eq!(tracker.totals().total_tokens, 15);

        let (_, values) = metrics.get("vm-1").expect("instance registered");
        assert_eq!(values.ai_requests_total, 1);
        assert_eq!(values.ai_tokens_input_total, 10);
        assert_eq!(values.ai_tokens_output_total, 5);
        assert_eq!(values.ai_tokens_total_total, 15);
    }

    #[tokio::test]
    async fn process_allows_request_that_exceeds_budget_then_refuses_the_next() {
        let (service, _metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered_with_total_budget(5),
        );

        let first = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(first, WireResponse::Ok { status: 200, .. }));

        let second = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(
            matches!(second, WireResponse::Refused { ref message, .. } if message.contains("AI egress budget")),
            "expected budget refusal, got {second:?}"
        );
    }

    #[tokio::test]
    async fn process_stream_records_openai_streaming_usage() {
        let (service, metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_stream())),
            AiPolicy::metered(),
        );
        let stream = service
            .process_stream(wire_to("https://api.openai.com/v1/chat/completions"))
            .await
            .expect("stream request succeeded");
        assert_eq!(stream.status, 200);

        // Drain the body so the spawned transform task finishes and records usage.
        let mut receiver = stream.body;
        let mut received = 0;
        while let Some(chunk) = receiver.recv().await {
            let chunk = chunk.expect("chunk ok");
            received += chunk.len();
        }
        assert!(received > 0);

        // Give the spawned task a moment to record usage.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let tracker = service.ai_tracker().expect("metering was enabled");
        assert_eq!(tracker.totals().input_tokens, 3);
        assert_eq!(tracker.totals().output_tokens, 2);
        assert_eq!(tracker.totals().total_tokens, 5);

        let (_, values) = metrics.get("vm-1").expect("instance registered");
        assert_eq!(values.ai_tokens_total_total, 5);
    }

    #[tokio::test]
    async fn unknown_provider_is_not_metered() {
        let (service, metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered(),
        );
        let resp = service.process(wire_to("https://example.com/v1")).await;
        assert!(matches!(resp, WireResponse::Ok { status: 200, .. }));

        let tracker = service.ai_tracker().expect("metering was enabled");
        assert_eq!(tracker.totals().requests, 0);
        assert!(metrics.get("vm-1").is_none());
    }

    #[tokio::test]
    async fn budget_refusal_only_blocks_known_ai_providers() {
        let (service, _metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::metered_with_total_budget(5),
        );

        // First OpenAI call pushes the VM over budget.
        let first = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(first, WireResponse::Ok { status: 200, .. }));

        // A non-AI destination is still allowed after the budget is exhausted.
        let other = service.process(wire_to("https://example.com/v1")).await;
        assert!(matches!(other, WireResponse::Ok { status: 200, .. }));

        // Another OpenAI call is refused.
        let second = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(
            matches!(second, WireResponse::Refused { ref message, .. } if message.contains("AI egress budget")),
        );
    }

    #[tokio::test]
    async fn disabled_policy_skips_metering() {
        let (service, _metrics) = metered_service(
            Arc::new(TestForwarder::ok(openai_response())),
            AiPolicy::disabled(),
        );
        let resp = service
            .process(wire_to("https://api.openai.com/v1/chat/completions"))
            .await;
        assert!(matches!(resp, WireResponse::Ok { status: 200, .. }));
        assert!(service.ai_tracker().is_none());
    }
}
