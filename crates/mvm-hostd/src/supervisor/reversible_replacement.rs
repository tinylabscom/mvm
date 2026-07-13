//! Request-scoped detect → replace → reinject for owned cleartext paths.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use mvm_core::policy::{
    OpaqueRewriteToken, ReversibleReplacementAction, RewriteFlowId, RewriteProofRecord,
    RewriteSurface, SensitiveClass,
};

use crate::supervisor::pii_redactor::{PiiMatch, PiiRedactor};
use crate::supervisor::secrets_scanner::{SecretMatch, SecretsScanner};
use crate::supervisor::substitution_proxy::ForwardResponse;

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
        rand::thread_rng().fill_bytes(&mut proof_key);
        Self { proof_key }
    }

    pub fn start_flow(
        &self,
        tenant: &str,
        action: &ReversibleReplacementAction,
    ) -> ReplacementFlow {
        let mut flow_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut flow_bytes);
        ReplacementFlow {
            tenant: tenant.to_string(),
            action: action.clone(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetectedSpan {
    class: SensitiveClass,
    category: &'static str,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    secrets: SecretsScanner,
    pii: PiiRedactor,
    proof_key: [u8; 32],
    flow_id: RewriteFlowId,
    tokens_by_value: HashMap<Vec<u8>, TokenEntry>,
    values_by_token: HashMap<String, TokenEntry>,
    next_token_index: u64,
    next_event_index: u64,
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
        rand::thread_rng().fill_bytes(&mut random_bytes);
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
