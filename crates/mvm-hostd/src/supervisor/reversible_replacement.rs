//! Request-scoped detect → replace → reinject for owned cleartext paths.

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroizing;

use mvm_core::policy::{
    OpaqueRewriteToken, ReversibleReplacementAction, RewriteFlowId, RewriteProofRecord,
    RewriteSurface, SensitiveClass,
};

use crate::supervisor::network_endpoint_proxy::ForwardResponse;
use crate::supervisor::pii_redactor::{PiiMatch, PiiRedactor};
use crate::supervisor::secrets_scanner::{SecretMatch, SecretsScanner};
use crate::supervisor::sensitive_detector::{
    LeakGuardCredentialDetector, SensitiveDetector, SensitiveMatch,
};

type HmacSha256 = Hmac<Sha256>;

pub struct ReplacementEngine {
    proof_key: [u8; 32],
}

impl Default for ReplacementEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplacementEngine {
    pub fn new() -> Self {
        let mut proof_key = [0u8; 32];
        rand::rng().fill_bytes(&mut proof_key);
        Self { proof_key }
    }

    pub fn start_flow(
        &self,
        tenant: &str,
        action: &ReversibleReplacementAction,
    ) -> ReplacementFlow {
        let mut flow_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut flow_bytes);
        ReplacementFlow {
            tenant: tenant.to_string(),
            action: action.clone(),
            supplemental: LeakGuardCredentialDetector::new(),
            secrets: SecretsScanner::with_default_rules(),
            pii: PiiRedactor::with_default_rules(),
            proof_key: self.proof_key,
            flow_id: RewriteFlowId(hex::encode(flow_bytes)),
            tokens_by_value: HashMap::new(),
            values_by_token: HashMap::new(),
            next_token_index: 0,
            next_event_index: 0,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct DetectedSpan {
    class: SensitiveClass,
    category: &'static str,
    start: usize,
    end: usize,
}

#[derive(Clone, PartialEq, Eq)]
struct TokenEntry {
    token: OpaqueRewriteToken,
    class: SensitiveClass,
    value: Vec<u8>,
}

struct ProofRecordInput {
    class: SensitiveClass,
    surface: RewriteSurface,
    field_name: Option<String>,
    offset: usize,
    original: Vec<u8>,
    rewritten: Vec<u8>,
    token: OpaqueRewriteToken,
    policy_decision: String,
    authorization_decision: String,
}

pub struct ReplacementFlow {
    tenant: String,
    action: ReversibleReplacementAction,
    supplemental: LeakGuardCredentialDetector,
    secrets: SecretsScanner,
    pii: PiiRedactor,
    proof_key: [u8; 32],
    flow_id: RewriteFlowId,
    tokens_by_value: HashMap<Vec<u8>, TokenEntry>,
    values_by_token: HashMap<String, TokenEntry>,
    next_token_index: u64,
    next_event_index: u64,
}

/// Bounded exact-token reinjection across arbitrary response chunk boundaries.
pub(crate) struct StreamingReinjector {
    pending: Zeroizing<Vec<u8>>,
}

/// Bounded request-side replacement across arbitrary transport chunk
/// boundaries. The retained overlap exceeds every configured detector
/// fingerprint. A detected span that crosses the proposed cut moves the cut
/// back to the span's start, so each byte is replaced exactly once and tokens
/// remain eligible for response reinjection.
pub(crate) struct StreamingReplacer {
    pending: Zeroizing<Vec<u8>>,
}

const STREAM_REPLACEMENT_OVERLAP: usize = 64 * 1024;
const MAX_STREAM_REPLACEMENT_PENDING: usize = STREAM_REPLACEMENT_OVERLAP * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("streaming replacement could not establish a bounded safe cut")]
pub(crate) struct StreamingReplacementError;

impl StreamingReplacer {
    pub(crate) fn new() -> Self {
        Self {
            pending: Zeroizing::new(Vec::new()),
        }
    }

    pub(crate) fn push(
        &mut self,
        flow: &mut ReplacementFlow,
        chunk: &[u8],
    ) -> Result<(Vec<u8>, Vec<RewriteProofRecord>), StreamingReplacementError> {
        self.pending.extend_from_slice(chunk);
        if self.pending.len() <= STREAM_REPLACEMENT_OVERLAP {
            return Ok((Vec::new(), Vec::new()));
        }

        let proposed = self.pending.len() - STREAM_REPLACEMENT_OVERLAP;
        let stable = flow
            .detect_spans(&self.pending)
            .into_iter()
            .filter(|span| span.start < proposed && span.end > proposed)
            .map(|span| span.start)
            .min()
            .unwrap_or(proposed);
        if stable == 0 && self.pending.len() > MAX_STREAM_REPLACEMENT_PENDING {
            return Err(StreamingReplacementError);
        }
        if stable == 0 {
            return Ok((Vec::new(), Vec::new()));
        }
        let suffix = self.pending.split_off(stable);
        let ready = std::mem::replace(&mut *self.pending, suffix);
        Ok(flow.replace_body(&ready))
    }

    pub(crate) fn finish(
        &mut self,
        flow: &mut ReplacementFlow,
    ) -> (Vec<u8>, Vec<RewriteProofRecord>) {
        let pending = std::mem::take(&mut *self.pending);
        flow.replace_body(&pending)
    }
}

impl StreamingReinjector {
    pub(crate) fn new() -> Self {
        Self {
            pending: Zeroizing::new(Vec::new()),
        }
    }

    pub(crate) fn push(
        &mut self,
        flow: &mut ReplacementFlow,
        chunk: &[u8],
    ) -> (Vec<u8>, Vec<RewriteProofRecord>) {
        self.pending.extend_from_slice(chunk);
        let longest = flow
            .values_by_token
            .keys()
            .map(String::len)
            .max()
            .unwrap_or(0);
        if longest == 0 {
            return (std::mem::take(&mut *self.pending), Vec::new());
        }
        let candidate = self.pending.len().saturating_sub(longest.saturating_sub(1));
        let stable =
            flow.values_by_token
                .keys()
                .flat_map(|token| {
                    self.pending.windows(token.len()).enumerate().filter_map(
                        move |(start, window)| {
                            let end = start + token.len();
                            (window == token.as_bytes() && start < candidate && end > candidate)
                                .then_some(start)
                        },
                    )
                })
                .min()
                .unwrap_or(candidate);
        let suffix = self.pending.split_off(stable);
        let ready = std::mem::replace(&mut *self.pending, suffix);
        flow.reinject_bytes(&ready, RewriteSurface::ResponseBody, None)
    }

    pub(crate) fn finish(
        &mut self,
        flow: &mut ReplacementFlow,
    ) -> (Vec<u8>, Vec<RewriteProofRecord>) {
        let pending = std::mem::take(&mut *self.pending);
        flow.reinject_bytes(&pending, RewriteSurface::ResponseBody, None)
    }
}

impl ReplacementFlow {
    pub fn replace_request(
        &mut self,
        headers: &mut [(String, String)],
        body: &mut Vec<u8>,
    ) -> Vec<RewriteProofRecord> {
        let mut proofs = Vec::new();
        if self.action.replaces_on(RewriteSurface::RequestHeader) {
            for (name, value) in headers.iter_mut() {
                let (rewritten, mut field_proofs) =
                    self.replace_header_value(name.clone(), value.as_bytes());
                if !field_proofs.is_empty() {
                    *value = String::from_utf8_lossy(&rewritten).into_owned();
                    proofs.append(&mut field_proofs);
                }
            }
        }
        if self.action.replaces_on(RewriteSurface::RequestBody) {
            let (rewritten, mut body_proofs) = self.replace_body(body);
            if !body_proofs.is_empty() {
                *body = rewritten;
                proofs.append(&mut body_proofs);
            }
        }
        proofs
    }

    pub fn replace_header_value(
        &mut self,
        field_name: String,
        value: &[u8],
    ) -> (Vec<u8>, Vec<RewriteProofRecord>) {
        self.replace_bytes(value, RewriteSurface::RequestHeader, Some(field_name))
    }

    pub fn replace_body(&mut self, body: &[u8]) -> (Vec<u8>, Vec<RewriteProofRecord>) {
        self.replace_bytes(body, RewriteSurface::RequestBody, None)
    }

    pub fn reinject_response(&mut self, response: &mut ForwardResponse) -> Vec<RewriteProofRecord> {
        let mut proofs = Vec::new();
        if self.action.reinjects_on(RewriteSurface::ResponseHeader) {
            for (name, value) in response.headers.iter_mut() {
                let (rewritten, mut field_proofs) = self.reinject_bytes(
                    value.as_bytes(),
                    RewriteSurface::ResponseHeader,
                    Some(name.clone()),
                );
                if !field_proofs.is_empty() {
                    *value = String::from_utf8_lossy(&rewritten).into_owned();
                    proofs.append(&mut field_proofs);
                }
            }
        }
        if self.action.reinjects_on(RewriteSurface::ResponseBody) {
            let (rewritten, mut body_proofs) =
                self.reinject_bytes(&response.body, RewriteSurface::ResponseBody, None);
            if !body_proofs.is_empty() {
                response.body = rewritten;
                proofs.append(&mut body_proofs);
            }
        }
        proofs
    }

    fn replace_bytes(
        &mut self,
        payload: &[u8],
        surface: RewriteSurface,
        field_name: Option<String>,
    ) -> (Vec<u8>, Vec<RewriteProofRecord>) {
        let spans = self.detect_spans(payload);
        if spans.is_empty() {
            return (payload.to_vec(), Vec::new());
        }
        let mut out = Vec::with_capacity(payload.len());
        let mut proofs = Vec::new();
        let mut cursor = 0usize;
        for span in spans {
            out.extend_from_slice(&payload[cursor..span.start]);
            let matched = payload[span.start..span.end].to_vec();
            let token = self.token_for(&matched, span.class);
            let token_bytes = token.0.as_bytes();
            let offset = out.len();
            out.extend_from_slice(token_bytes);
            proofs.push(self.proof_record(ProofRecordInput {
                class: span.class,
                surface,
                field_name: field_name.clone(),
                offset,
                original: matched,
                rewritten: token_bytes.to_vec(),
                token: token.clone(),
                policy_decision: format!("replace:{}", span.category),
                authorization_decision: "runtime_owned".to_string(),
            }));
            cursor = span.end;
        }
        out.extend_from_slice(&payload[cursor..]);
        (out, proofs)
    }

    fn reinject_bytes(
        &mut self,
        payload: &[u8],
        surface: RewriteSurface,
        field_name: Option<String>,
    ) -> (Vec<u8>, Vec<RewriteProofRecord>) {
        if self.values_by_token.is_empty() {
            return (payload.to_vec(), Vec::new());
        }
        let mut out = Vec::with_capacity(payload.len());
        let mut cursor = 0usize;
        let mut proofs = Vec::new();
        while cursor < payload.len() {
            let next = self
                .values_by_token
                .values()
                .filter_map(|entry| {
                    find_bytes(&payload[cursor..], entry.token.0.as_bytes())
                        .map(|start| (cursor + start, entry.clone()))
                })
                .min_by_key(|(start, _)| *start);
            let Some((start, entry)) = next else {
                break;
            };
            let token_bytes = entry.token.0.as_bytes();
            out.extend_from_slice(&payload[cursor..start]);
            let offset = out.len();
            out.extend_from_slice(&entry.value);
            proofs.push(self.proof_record(ProofRecordInput {
                class: entry.class,
                surface,
                field_name: field_name.clone(),
                offset,
                original: token_bytes.to_vec(),
                rewritten: entry.value.clone(),
                token: entry.token.clone(),
                policy_decision: "reinject:exact_token".to_string(),
                authorization_decision: "runtime_owned".to_string(),
            }));
            cursor = start + token_bytes.len();
        }
        out.extend_from_slice(&payload[cursor..]);
        (out, proofs)
    }

    fn detect_spans(&self, payload: &[u8]) -> Vec<DetectedSpan> {
        let mut spans = Vec::new();
        if self.action.handles_class(SensitiveClass::Secret) {
            match self.supplemental.detect(payload) {
                Ok(supplemental) => {
                    spans.extend(supplemental.into_iter().map(
                        |SensitiveMatch {
                             class,
                             category,
                             start,
                             end,
                         }| DetectedSpan {
                            class,
                            category,
                            start,
                            end,
                        },
                    ));
                }
                Err(error) => {
                    tracing::error!(error = %error, "reversible detector failed closed");
                    if !payload.is_empty() {
                        return vec![DetectedSpan {
                            class: SensitiveClass::Secret,
                            category: "detector_failure",
                            start: 0,
                            end: payload.len(),
                        }];
                    }
                }
            }
            spans.extend(self.secrets.match_spans(payload).into_iter().map(
                |SecretMatch { name, start, end }| DetectedSpan {
                    class: SensitiveClass::Secret,
                    category: name,
                    start,
                    end,
                },
            ));
        }
        if self.action.handles_class(SensitiveClass::Pii) {
            spans.extend(
                self.pii
                    .match_spans_with_categories(payload)
                    .into_iter()
                    .map(|PiiMatch { name, start, end }| DetectedSpan {
                        class: SensitiveClass::Pii,
                        category: name,
                        start,
                        end,
                    }),
            );
        }
        spans.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then(right.end.cmp(&left.end))
                .then(class_rank(left.class).cmp(&class_rank(right.class)))
        });
        let mut accepted = Vec::new();
        let mut cursor = 0usize;
        for span in spans {
            if span.start < cursor {
                continue;
            }
            cursor = span.end;
            accepted.push(span);
        }
        accepted
    }

    fn token_for(&mut self, value: &[u8], class: SensitiveClass) -> OpaqueRewriteToken {
        if let Some(entry) = self.tokens_by_value.get(value) {
            return entry.token.clone();
        }
        self.next_token_index += 1;
        let mut random_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut random_bytes);
        let mut mac = HmacSha256::new_from_slice(&self.proof_key).expect("fixed proof key");
        mac.update(self.tenant.as_bytes());
        mac.update(self.flow_id.0.as_bytes());
        mac.update(&self.next_token_index.to_be_bytes());
        mac.update(value);
        let tag = hex::encode(mac.finalize().into_bytes());
        let token = OpaqueRewriteToken(format!(
            "mvmr1_{}_{}_{}_{}",
            self.tenant,
            self.flow_id.0,
            self.next_token_index,
            &tag[..16]
        ));
        let entry = TokenEntry {
            token: token.clone(),
            class,
            value: value.to_vec(),
        };
        self.tokens_by_value.insert(value.to_vec(), entry.clone());
        self.values_by_token.insert(token.0.clone(), entry);
        token
    }

    fn proof_record(&mut self, input: ProofRecordInput) -> RewriteProofRecord {
        self.next_event_index += 1;
        let ProofRecordInput {
            class,
            surface,
            field_name,
            offset,
            original,
            rewritten,
            token,
            policy_decision,
            authorization_decision,
        } = input;
        RewriteProofRecord {
            flow_id: self.flow_id.clone(),
            event_index: self.next_event_index,
            class,
            surface,
            field_name,
            offset,
            original_len: original.len(),
            rewritten_len: rewritten.len(),
            token_id: token,
            original_hmac_sha256: digest_hex(&self.proof_key, &original),
            rewritten_hmac_sha256: digest_hex(&self.proof_key, &rewritten),
            policy_decision,
            authorization_decision,
        }
    }
}

fn class_rank(class: SensitiveClass) -> u8 {
    match class {
        SensitiveClass::Secret => 0,
        SensitiveClass::Pii => 1,
    }
}

fn digest_hex(key: &[u8; 32], bytes: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("fixed proof key");
    mac.update(bytes);
    hex::encode(mac.finalize().into_bytes())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_action() -> ReversibleReplacementAction {
        ReversibleReplacementAction {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn replace_then_reinject_roundtrips_secret_and_pii() {
        let engine = ReplacementEngine::new();
        let mut flow = engine.start_flow("tenant-a", &enabled_action());
        let mut headers = vec![("x-user".into(), "alice@example.com".into())];
        let mut body =
            b"call +14155550123 with sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
        let replace = flow.replace_request(&mut headers, &mut body);
        assert_eq!(replace.len(), 3);
        assert!(!headers[0].1.contains("alice@example.com"));
        assert!(!String::from_utf8_lossy(&body).contains("+14155550123"));
        assert!(!String::from_utf8_lossy(&body).contains("sk-aaaaaaaa"));

        let mut response = ForwardResponse {
            status: 200,
            headers: vec![("x-echo".into(), headers[0].1.clone())],
            body: body.clone(),
        };
        let reinject = flow.reinject_response(&mut response);
        assert_eq!(reinject.len(), 3);
        assert_eq!(response.headers[0].1, "alice@example.com");
        let text = String::from_utf8(response.body).unwrap();
        assert!(text.contains("+14155550123"));
        assert!(text.contains("sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn response_token_split_across_chunks_is_reinjected_once() {
        let engine = ReplacementEngine::new();
        let mut flow = engine.start_flow("tenant-a", &enabled_action());
        let secret = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (token, replace_proofs) = flow.replace_body(secret);
        assert_eq!(replace_proofs.len(), 1);
        let split = token.len() / 2;
        let mut stream = StreamingReinjector::new();
        let (first, first_proofs) = stream.push(&mut flow, &token[..split]);
        assert!(first.is_empty());
        assert!(first_proofs.is_empty());
        let (second, mut proofs) = stream.push(&mut flow, &token[split..]);
        let (tail, tail_proofs) = stream.finish(&mut flow);
        proofs.extend(tail_proofs);
        assert_eq!([first, second, tail].concat(), secret);
        assert_eq!(proofs.len(), 1, "one token produces one reinjection proof");
    }

    #[test]
    fn request_secret_split_across_chunks_is_replaced_once() {
        let engine = ReplacementEngine::new();
        let mut flow = engine.start_flow("tenant-a", &enabled_action());
        let secret = b"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut first = vec![b'x'; STREAM_REPLACEMENT_OVERLAP - 10];
        first.extend_from_slice(&secret[..10]);
        let mut stream = StreamingReplacer::new();
        let (ready, proofs) = stream.push(&mut flow, &first).unwrap();
        assert!(ready.is_empty());
        assert!(proofs.is_empty());

        let (middle, mut proofs) = stream.push(&mut flow, &secret[10..]).unwrap();
        let (tail, tail_proofs) = stream.finish(&mut flow);
        proofs.extend(tail_proofs);
        let transformed = [middle, tail].concat();
        assert!(
            !transformed
                .windows(secret.len())
                .any(|bytes| bytes == secret)
        );
        assert_eq!(proofs.len(), 1);
    }

    #[test]
    fn supplemental_secret_is_replaced_and_exact_echo_reinjected() {
        let engine = ReplacementEngine::new();
        let mut flow = engine.start_flow("tenant", &enabled_action());
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "signature1234"
        );
        let (replaced, proofs) = flow.replace_body(format!("token={jwt}").as_bytes());
        let replaced = String::from_utf8(replaced).expect("replacement is UTF-8");
        assert!(!replaced.contains(&jwt));
        assert!(replaced.contains("mvmr1_"));
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].policy_decision, "replace:jwt");

        let mut response = ForwardResponse {
            status: 200,
            headers: Vec::new(),
            body: replaced.into_bytes(),
        };
        let reinjected = flow.reinject_response(&mut response);
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            format!("token={jwt}")
        );
        assert_eq!(reinjected.len(), 1);
    }

    #[test]
    fn same_value_reuses_same_token_within_one_flow() {
        let engine = ReplacementEngine::new();
        let mut flow = engine.start_flow("tenant-a", &enabled_action());
        let mut headers = Vec::new();
        let mut body = b"alice@example.com alice@example.com".to_vec();
        let proofs = flow.replace_request(&mut headers, &mut body);
        assert_eq!(proofs.len(), 2);
        assert_eq!(proofs[0].token_id, proofs[1].token_id);
    }
}
