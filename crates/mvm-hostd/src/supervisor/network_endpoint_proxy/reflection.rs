//! Keep a destination from handing a substituted credential back to the guest.
//!
//! Substitution puts the real value on the wire. A destination that echoes
//! request headers — a debugging endpoint, an error page quoting the request,
//! an API that lists the caller's own key — returns that value in its
//! response, and without this module the endpoint relays it to the guest
//! untouched. That is the one way a raw value reached the guest on the
//! substitution path, and it was observed live.
//!
//! The endpoint therefore remembers every value it has substituted in this VM
//! and replaces any occurrence of one in a response — header or body — with
//! that binding's placeholder before a byte crosses to the guest. The guest
//! sees the token it already holds, which tells it nothing new.
//!
//! The set is VM-wide rather than per request: a value sent to a destination
//! on one request can come back on a later one, so each response is scrubbed
//! of everything substituted so far. Values are learned as the injector puts
//! them on the wire, so a value rotated in the store while the VM runs — or a
//! refreshed token — is learned the first time it is sent, beside the one it
//! replaced. Only values that went on the wire are remembered; a signing key
//! leaves as a signature and cannot be reflected.
//!
//! The response has to be readable to be scrubbed. A VM holding any injected
//! credential asks upstreams for identity encoding and refuses a response that
//! arrives content-encoded anyway, rather than relaying bytes it cannot read.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

/// Values shorter than this are not scrubbed.
///
/// A value this short cannot be told apart from ordinary response content —
/// replacing every `abc` in a body corrupts the body and protects nothing an
/// eight-byte search could not already guess. Real API credentials are far
/// longer; the limit is stated where credentials are documented.
pub(crate) const MIN_SCRUBBED_VALUE_LEN: usize = 8;

/// One value the endpoint substituted, and what stands in for it.
struct Reflectable {
    name: String,
    placeholder: String,
    value: Zeroizing<Vec<u8>>,
}

/// Every value substituted so far in this VM. Immutable once built; a new
/// substitution builds a new set, so a response scrubs against a consistent
/// snapshot while later requests extend the next one.
#[derive(Default)]
pub(crate) struct ScrubSet {
    entries: Vec<Reflectable>,
    longest: usize,
}

/// How many times each binding's value was replaced, by binding name.
pub(crate) type ScrubCounts = BTreeMap<String, u64>;

impl ScrubSet {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn holds(&self, value: &[u8]) -> bool {
        self.entries.iter().any(|e| e.value.as_slice() == value)
    }

    /// The entry whose value starts at `buf[at..]`, longest value first so a
    /// value that is a prefix of another does not split the longer one.
    fn match_at(&self, buf: &[u8], at: usize) -> Option<&Reflectable> {
        self.entries
            .iter()
            .find(|e| buf[at..].starts_with(e.value.as_slice()))
    }

    /// Replace every value in `buf[..limit]` whose whole occurrence lies in
    /// `buf`, appending to `out`. Returns the index scanning stopped at, which
    /// is at or past `limit` only when a match straddled it.
    fn scrub_until(
        &self,
        buf: &[u8],
        limit: usize,
        out: &mut Vec<u8>,
        counts: &mut ScrubCounts,
    ) -> usize {
        let mut at = 0;
        while at < limit {
            if let Some(entry) = self.match_at(buf, at) {
                out.extend_from_slice(entry.placeholder.as_bytes());
                *counts.entry(entry.name.clone()).or_default() += 1;
                at += entry.value.len();
            } else {
                out.push(buf[at]);
                at += 1;
            }
        }
        at
    }

    /// Scrub a complete value — a header, or a buffered body.
    pub(crate) fn scrub(&self, bytes: &[u8], counts: &mut ScrubCounts) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        self.scrub_until(bytes, bytes.len(), &mut out, counts);
        out
    }

    /// Scrub a header value, keeping it a string. A header is text on the
    /// wire; a replacement can only swap one ASCII run for another, so the
    /// result is valid UTF-8 whenever the input was.
    pub(crate) fn scrub_str(&self, text: &str, counts: &mut ScrubCounts) -> String {
        String::from_utf8_lossy(&self.scrub(text.as_bytes(), counts)).into_owned()
    }
}

/// The VM-wide memory of substituted values.
#[derive(Default)]
pub(crate) struct ReflectionGuard {
    set: Mutex<Arc<ScrubSet>>,
}

impl ReflectionGuard {
    fn current(&self) -> Arc<ScrubSet> {
        Arc::clone(&self.set.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Remember `value` as substituted for `name`, standing in `placeholder`.
    /// A value already remembered is not added twice; a value too short to
    /// scrub is not remembered at all — see [`MIN_SCRUBBED_VALUE_LEN`].
    pub(crate) fn learn(&self, name: &str, placeholder: &str, value: &[u8]) {
        if value.len() < MIN_SCRUBBED_VALUE_LEN || self.current().holds(value) {
            return;
        }
        let mut guard = self.set.lock().unwrap_or_else(|p| p.into_inner());
        if guard.holds(value) {
            return;
        }
        let mut entries: Vec<Reflectable> = guard
            .entries
            .iter()
            .map(|e| Reflectable {
                name: e.name.clone(),
                placeholder: e.placeholder.clone(),
                value: Zeroizing::new(e.value.to_vec()),
            })
            .collect();
        entries.push(Reflectable {
            name: name.to_string(),
            placeholder: placeholder.to_string(),
            value: Zeroizing::new(value.to_vec()),
        });
        entries.sort_by_key(|e| std::cmp::Reverse(e.value.len()));
        let longest = entries.first().map_or(0, |e| e.value.len());
        *guard = Arc::new(ScrubSet { entries, longest });
    }

    /// The set a response is scrubbed against, or `None` when nothing has
    /// been substituted yet — the fast path, which touches no byte.
    pub(crate) fn snapshot(&self) -> Option<Arc<ScrubSet>> {
        let set = self.current();
        (!set.is_empty()).then_some(set)
    }
}

impl crate::keyholder::SubstitutionObserver for ReflectionGuard {
    fn substituted(&self, secret: &mvm_contract::ir::SecretRef, placeholder: &str, value: &str) {
        self.learn(&secret.name, placeholder, value.as_bytes());
    }
}

/// Scrubs a response body that arrives in chunks.
///
/// A value can be split across two chunks, so the last `longest - 1` bytes of
/// each chunk are held back until the next one decides them. Nothing held back
/// is ever released unscrubbed: [`Self::finish`] scrubs the remainder.
pub(crate) struct StreamingScrubber {
    set: Arc<ScrubSet>,
    carry: Zeroizing<Vec<u8>>,
    counts: ScrubCounts,
}

impl StreamingScrubber {
    pub(crate) fn new(set: Arc<ScrubSet>) -> Self {
        Self {
            set,
            carry: Zeroizing::new(Vec::new()),
            counts: ScrubCounts::new(),
        }
    }

    /// Scrub `chunk`, returning the bytes that are now safe to release.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut buf = Zeroizing::new(Vec::with_capacity(self.carry.len() + chunk.len()));
        buf.extend_from_slice(&self.carry);
        buf.extend_from_slice(chunk);
        // A value starting before `limit` ends inside `buf`, so every such
        // start can be decided now; later starts wait for more bytes.
        let limit = buf.len().saturating_sub(self.set.longest.saturating_sub(1));
        let mut out = Vec::with_capacity(buf.len());
        let stopped = self
            .set
            .scrub_until(&buf, limit, &mut out, &mut self.counts);
        self.carry = Zeroizing::new(buf[stopped.min(buf.len())..].to_vec());
        out
    }

    /// Scrub and release what is still held back. Called once the body has
    /// ended, when no further byte can complete a value.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        let carry = std::mem::take(&mut self.carry);
        self.set.scrub(&carry, &mut self.counts)
    }

    /// How many times each binding's value has been replaced so far.
    pub(crate) fn counts(&self) -> &ScrubCounts {
        &self.counts
    }
}

/// Merge `more` into `into`.
pub(crate) fn merge_counts(into: &mut ScrubCounts, more: ScrubCounts) {
    for (name, n) in more {
        *into.entry(name).or_default() += n;
    }
}

/// Whether a response's `Content-Encoding` leaves its body readable.
///
/// Anything but absent or `identity` is a transform the endpoint would have to
/// undo to scrub, and it does not decompress, so such a body is refused.
pub(crate) fn body_is_readable(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .all(|(_, value)| {
            value
                .split(',')
                .map(str::trim)
                .all(|coding| coding.is_empty() || coding.eq_ignore_ascii_case("identity"))
        })
}

/// Ask the upstream for an unencoded response: drop every `Accept-Encoding`
/// the guest sent and send `identity`. Without this an ordinary client that
/// accepts gzip gets a compressed body the endpoint must refuse.
pub(crate) fn request_identity_encoding(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("accept-encoding"));
    headers.push(("accept-encoding".to_string(), "identity".to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "sk-live-0123456789abcdef";
    const OTHER: &str = "ghp_abcdefghijklmnopqrst";
    const PH: &str = "mvm-secret-aaaa";
    const OTHER_PH: &str = "mvm-secret-bbbb";

    fn guard_with(values: &[(&str, &str, &str)]) -> ReflectionGuard {
        let guard = ReflectionGuard::default();
        for (name, placeholder, value) in values {
            guard.learn(name, placeholder, value.as_bytes());
        }
        guard
    }

    fn stream(set: Arc<ScrubSet>, chunks: &[&[u8]]) -> (Vec<u8>, ScrubCounts) {
        let mut scrubber = StreamingScrubber::new(set);
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(scrubber.push(chunk));
        }
        out.extend(scrubber.finish());
        (out, scrubber.counts().clone())
    }

    #[test]
    fn nothing_substituted_is_the_fast_path() {
        assert!(ReflectionGuard::default().snapshot().is_none());
    }

    #[test]
    fn a_value_split_at_every_offset_is_replaced() {
        let set = guard_with(&[("api", PH, KEY)]).snapshot().unwrap();
        let body = format!("{{\"headers\":{{\"authorization\":\"Bearer {KEY}\"}}}}");
        let expected = body.replace(KEY, PH);
        for cut in 0..=body.len() {
            let (a, b) = body.as_bytes().split_at(cut);
            let (out, counts) = stream(Arc::clone(&set), &[a, b]);
            assert_eq!(String::from_utf8(out).unwrap(), expected, "cut at {cut}");
            assert_eq!(counts.get("api"), Some(&1), "cut at {cut}");
        }
    }

    #[test]
    fn a_value_fed_one_byte_at_a_time_is_replaced() {
        let set = guard_with(&[("api", PH, KEY)]).snapshot().unwrap();
        let body = format!("x{KEY}y{KEY}");
        let chunks: Vec<&[u8]> = body.as_bytes().chunks(1).collect();
        let (out, counts) = stream(set, &chunks);
        assert_eq!(String::from_utf8(out).unwrap(), format!("x{PH}y{PH}"));
        assert_eq!(counts.get("api"), Some(&2));
    }

    #[test]
    fn several_values_are_each_replaced_by_their_own_placeholder() {
        let set = guard_with(&[("api", PH, KEY), ("gh", OTHER_PH, OTHER)])
            .snapshot()
            .unwrap();
        let body = format!("{OTHER} and {KEY} and {OTHER}");
        let (out, counts) = stream(set, &[body.as_bytes()]);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{OTHER_PH} and {PH} and {OTHER_PH}")
        );
        assert_eq!(counts.get("api"), Some(&1));
        assert_eq!(counts.get("gh"), Some(&2));
    }

    #[test]
    fn a_header_value_is_scrubbed() {
        let set = guard_with(&[("api", PH, KEY)]).snapshot().unwrap();
        let mut counts = ScrubCounts::new();
        let scrubbed = set.scrub_str(&format!("Bearer {KEY}"), &mut counts);
        assert_eq!(scrubbed, format!("Bearer {PH}"));
        assert_eq!(counts.get("api"), Some(&1));
    }

    #[test]
    fn a_body_without_the_value_passes_through_unchanged_and_uncounted() {
        let set = guard_with(&[("api", PH, KEY)]).snapshot().unwrap();
        let body = b"{\"ok\":true, \"almost\":\"sk-live-01234\"}";
        let (out, counts) = stream(set, &[&body[..10], &body[10..]]);
        assert_eq!(out, body);
        assert!(counts.is_empty());
    }

    #[test]
    fn a_value_that_prefixes_another_does_not_split_the_longer_one() {
        let longer = format!("{KEY}-extended");
        let set = guard_with(&[("short", PH, KEY), ("long", OTHER_PH, &longer)])
            .snapshot()
            .unwrap();
        let (out, counts) = stream(set, &[longer.as_bytes()]);
        assert_eq!(String::from_utf8(out).unwrap(), OTHER_PH);
        assert_eq!(counts.get("long"), Some(&1));
        assert!(!counts.contains_key("short"));
    }

    #[test]
    fn a_value_too_short_to_tell_from_content_is_not_remembered() {
        let guard = guard_with(&[("tiny", PH, "abc")]);
        assert!(guard.snapshot().is_none());
    }

    #[test]
    fn a_rotated_value_is_remembered_beside_the_one_it_replaced() {
        let guard = guard_with(&[("api", PH, KEY), ("api", PH, OTHER), ("api", PH, KEY)]);
        let set = guard.snapshot().unwrap();
        let (out, counts) = stream(set, &[format!("{KEY} {OTHER}").as_bytes()]);
        assert_eq!(String::from_utf8(out).unwrap(), format!("{PH} {PH}"));
        assert_eq!(counts.get("api"), Some(&2));
    }

    #[test]
    fn an_encoded_body_is_not_readable_and_identity_is() {
        let enc = |v: &str| vec![("Content-Encoding".to_string(), v.to_string())];
        assert!(body_is_readable(&[]));
        assert!(body_is_readable(&enc("identity")));
        assert!(!body_is_readable(&enc("gzip")));
        assert!(!body_is_readable(&enc("identity, br")));
    }

    #[test]
    fn the_guests_accept_encoding_is_replaced_by_identity() {
        let mut headers = vec![
            ("Accept-Encoding".to_string(), "gzip, br".to_string()),
            ("x-api-key".to_string(), PH.to_string()),
        ];
        request_identity_encoding(&mut headers);
        let values: Vec<_> = headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("accept-encoding"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(values, ["identity"]);
    }
}

/// The buffered typed path scrubs the same way the streamed one does.
#[cfg(test)]
mod buffered_tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use mvm_contract::substitution::PreparedRequest;
    use mvm_core::substitution_wire::{WireRequest, WireResponse};

    use super::super::test_support::{bearer_ref, gate_admitting, resolver_with};
    use super::super::{ForwardError, ForwardResponse, Forwarder, SubstitutionService};
    use crate::keyholder::SubstitutionRegistry;

    const VALUE: &str = "sk-buffered-reflection-value";
    const HOST: &str = "api.echo.test";

    struct Echo;

    #[async_trait]
    impl Forwarder for Echo {
        async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
            let auth = req
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let body = format!("you sent {auth}").into_bytes();
            Ok(ForwardResponse {
                status: 200,
                headers: vec![
                    ("x-echo".into(), auth),
                    ("content-length".into(), body.len().to_string()),
                ],
                body,
            })
        }
    }

    #[tokio::test]
    async fn a_buffered_response_echoing_the_value_carries_the_placeholder_and_a_true_length() {
        let (_dir, resolver) = resolver_with("openai", VALUE);
        let mut registry = SubstitutionRegistry::new();
        let placeholder = registry
            .mint(bearer_ref("openai", &[HOST]))
            .as_str()
            .to_string();
        let service = SubstitutionService::new(
            Arc::new(registry),
            Arc::new(resolver),
            Arc::new(Echo),
            gate_admitting(&[(HOST, 443)]),
        );
        let response = service
            .process(WireRequest {
                method: "GET".into(),
                url: format!("https://{HOST}/v1"),
                headers: vec![("authorization".into(), format!("Bearer {placeholder}"))],
                body_b64: String::new(),
            })
            .await;
        let WireResponse::Ok {
            headers, body_b64, ..
        } = response
        else {
            panic!("expected a response, got {response:?}");
        };
        let body = String::from_utf8(B64.decode(body_b64).unwrap()).unwrap();
        assert_eq!(body, format!("you sent Bearer {placeholder}"));
        let header = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(header("x-echo"), format!("Bearer {placeholder}"));
        assert_eq!(header("content-length"), body.len().to_string());
    }
}
