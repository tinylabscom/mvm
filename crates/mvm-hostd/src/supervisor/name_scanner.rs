//! `NameScanner` — redact personal names on egress, no ML.
//!
//! Names have no regex shape, so we catch the leaks that actually matter — the
//! ones with context. Three signals: a name-like field label, a census
//! gazetteer pair, or a capitalized pair adjacent to other PII. Freeform
//! unlabeled names with no nearby PII are out of scope (would need NER).

use crate::supervisor::names_gazetteer::{FIRST_NAMES, SURNAMES, in_list};
use crate::supervisor::pii_redactor::REDACTION_MASK;
use regex::bytes::Regex;
use std::sync::OnceLock;

/// JSON/form field keys whose value is a personal name.
const NAME_LABELS: &[&str] = &[
    "name",
    "first_name",
    "firstname",
    "last_name",
    "lastname",
    "full_name",
    "fullname",
    "customer",
    "patient",
    "cardholder",
    "given_name",
    "surname",
];

fn label_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // `"key":"value"` (JSON) or `key=value` (form) or `Key: value` (prose).
        // The key alternation is built from NAME_LABELS; the value capture (1)
        // is what we mask.
        let keys = NAME_LABELS.join("|");
        Regex::new(&format!(
            r#"(?i)(?:"(?:{keys})"\s*:\s*"|(?:{keys})\s*[:=]\s*"?)([A-Za-z][A-Za-z .'\-]{{1,60}})"#
        ))
        .expect("name-label regex compiles")
    })
}

/// A capitalized word run: `[A-Z][a-z]+`. Used for the gazetteer + co-occurrence
/// signals.
fn cap_words() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Z][a-z]{1,}").expect("cap-word regex compiles"))
}

pub struct NameScanner {
    /// Max byte gap between a capitalized pair and a PII span for the
    /// co-occurrence signal to fire.
    cooccur_window: usize,
}

impl NameScanner {
    pub fn new(cooccur_window: usize) -> Self {
        Self { cooccur_window }
    }
    pub fn with_defaults() -> Self {
        Self::new(40)
    }

    /// Mask names in `body`. `pii_spans` are byte ranges of structured-PII hits
    /// from a prior pass (empty if none). Returns the rewritten bytes + the
    /// number of name spans masked.
    pub fn redact(&self, body: &[u8], pii_spans: &[(usize, usize)]) -> (Vec<u8>, usize) {
        let mut spans: Vec<(usize, usize)> = Vec::new();

        // (a) labeled fields: mask capture group 1 (the value).
        for caps in label_regex().captures_iter(body) {
            if let Some(m) = caps.get(1) {
                spans.push((m.start(), m.end()));
            }
        }

        // Collect capitalized words once for (b) and (c).
        let words: Vec<(usize, usize)> = cap_words()
            .find_iter(body)
            .map(|m| (m.start(), m.end()))
            .collect();

        // (b) gazetteer pairs: adjacent capitalized words, first in FIRST_NAMES
        //     OR surname list, second in SURNAMES OR first list.
        for pair in words.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if !adjacent_words(body, a, b) {
                continue;
            }
            let wa = std::str::from_utf8(&body[a.0..a.1]).unwrap_or("");
            let wb = std::str::from_utf8(&body[b.0..b.1]).unwrap_or("");
            if (in_list(FIRST_NAMES, wa) || in_list(SURNAMES, wa))
                && (in_list(SURNAMES, wb) || in_list(FIRST_NAMES, wb))
            {
                spans.push((a.0, b.1));
            }
        }

        // (c) co-occurrence: a capitalized pair within `cooccur_window` bytes of
        //     any PII span (the "row" case — a name bound to other PII).
        if !pii_spans.is_empty() {
            for pair in words.windows(2) {
                let (a, b) = (pair[0], pair[1]);
                if !adjacent_words(body, a, b) {
                    continue;
                }
                if pii_spans
                    .iter()
                    .any(|&(ps, pe)| near(b.1, ps, pe, self.cooccur_window))
                {
                    spans.push((a.0, b.1));
                }
            }
        }

        if spans.is_empty() {
            return (body.to_vec(), 0);
        }
        // Dedup + sort, mask right-to-left so offsets stay valid.
        spans.sort_unstable();
        spans.dedup();
        let merged = merge_overlapping(spans);
        let count = merged.len();
        let mut out = body.to_vec();
        for (s, e) in merged.into_iter().rev() {
            out.splice(s..e, REDACTION_MASK.iter().copied());
        }
        (out, count)
    }
}

/// Two capitalized words are a "pair" iff separated by exactly one space.
fn adjacent_words(body: &[u8], a: (usize, usize), b: (usize, usize)) -> bool {
    b.0 == a.1 + 1 && body.get(a.1) == Some(&b' ')
}

/// True iff byte offset `at` is within `window` of the [ps, pe) span.
fn near(at: usize, ps: usize, pe: usize, window: usize) -> bool {
    let lo = ps.saturating_sub(window);
    at >= lo && at <= pe + window
}

/// Merge sorted, possibly-overlapping spans.
fn merge_overlapping(sorted: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(sorted.len());
    for (s, e) in sorted {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_a_labeled_name_field_json() {
        let s = NameScanner::with_defaults();
        let body = br#"{"first_name":"Jonathan","city":"Denver"}"#;
        let (out, n) = s.redact(body, &[]);
        let r = String::from_utf8_lossy(&out);
        assert!(n >= 1);
        assert!(!r.contains("Jonathan"), "labeled name not redacted: {r}");
        assert!(r.contains("Denver"), "non-name value wrongly touched: {r}");
    }

    #[test]
    fn redacts_a_gazetteer_name_pair() {
        let s = NameScanner::with_defaults();
        let body = b"contact John Smith about the order";
        let (out, n) = s.redact(body, &[]);
        let r = String::from_utf8_lossy(&out);
        assert!(n >= 1, "gazetteer pair not redacted: {r}");
        assert!(!r.contains("John Smith"), "name pair not masked: {r}");
    }

    #[test]
    fn redacts_capitalized_pair_adjacent_to_pii_span() {
        let s = NameScanner::with_defaults();
        // "Zephyr Quibblesworth" is not in the gazetteer, but it abuts a PII
        // span (passed in) → the co-occurrence signal fires.
        let body = b"Zephyr Quibblesworth ssn 123-45-6789";
        let pii_spans = [(21usize, 32usize)]; // the ssn span
        let (out, n) = s.redact(body, &pii_spans);
        let r = String::from_utf8_lossy(&out);
        assert!(n >= 1, "co-occurrence name not redacted: {r}");
        assert!(!r.contains("Zephyr Quibblesworth"), "name not masked: {r}");
    }

    #[test]
    fn leaves_unanchored_non_gazetteer_capitalized_words() {
        let s = NameScanner::with_defaults();
        // Capitalized but not a known name, not labeled, no nearby PII.
        let body = b"The Eiffel Tower is tall";
        let (out, n) = s.redact(body, &[]);
        assert_eq!(n, 0, "false positive on non-name capitalized words");
        assert_eq!(out, body);
    }
}
