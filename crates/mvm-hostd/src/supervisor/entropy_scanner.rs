//! `EntropyScanner` — mask undeclared high-entropy tokens on egress.
//!
//! Complements the curated `SecretsScanner`: that matches known vendor
//! prefixes; this catches unknown-shape high-entropy tokens (random API keys,
//! session blobs) the curated rules miss. Deliberately additive and
//! audit-first — high-entropy false positives (JWTs, UUIDs, base64 uploads,
//! hashes) must degrade, not break, and operators observe hits before masking.

use crate::supervisor::pii_redactor::REDACTION_MASK;

/// True for bytes that can be part of a secret-like token run: the
/// base64url/hex alphabet plus `+` and `/` from standard base64. `=` is
/// deliberately excluded — it appears in the wild as a `key=value` delimiter,
/// so treating it as a token byte would weld the `key=` prose onto the value
/// and mask the operator's context away. Base64 `=` padding is trailing and
/// low-information, so dropping it from the run costs no real detection.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')
}

/// One detected high-entropy run, as a half-open byte range. Carries NO bytes:
/// the matched value never leaves the host, not even into a struct that might
/// reach a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyHit {
    pub start: usize,
    pub end: usize,
}

/// Shannon-entropy scanner over token runs.
pub struct EntropyScanner {
    min_run_len: usize,
    min_bits_per_char: f64,
}

impl EntropyScanner {
    /// `min_run_len` keeps short prose words out; the `min_bits_per_char`
    /// threshold keeps natural-language runs out (English is ~3-4 bits/char;
    /// uniform base64 is 6, hex is 4).
    pub fn new(min_run_len: usize, min_bits_per_char: f64) -> Self {
        Self {
            min_run_len,
            min_bits_per_char,
        }
    }

    /// Defaults tuned for low false-positive on prose: 20-char minimum run,
    /// 4.0 bits/char. Audit-first means operators retune before enabling masking.
    pub fn with_defaults() -> Self {
        Self::new(20, 4.0)
    }

    /// Return every token run whose entropy clears the threshold.
    pub fn scan(&self, body: &[u8]) -> Vec<EntropyHit> {
        let mut hits = Vec::new();
        let mut i = 0usize;
        while i < body.len() {
            if !is_token_byte(body[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < body.len() && is_token_byte(body[i]) {
                i += 1;
            }
            let run = &body[start..i];
            if run.len() >= self.min_run_len && shannon_bits_per_char(run) >= self.min_bits_per_char
            {
                hits.push(EntropyHit { start, end: i });
            }
        }
        hits
    }

    /// Mask each high-entropy run with [`REDACTION_MASK`]; return the rewritten
    /// bytes and the number of runs masked. Right-to-left so earlier offsets
    /// stay valid as the buffer shrinks.
    pub fn redact(&self, body: &[u8]) -> (Vec<u8>, usize) {
        let hits = self.scan(body);
        if hits.is_empty() {
            return (body.to_vec(), 0);
        }
        let mut out = body.to_vec();
        for h in hits.iter().rev() {
            out.splice(h.start..h.end, REDACTION_MASK.iter().copied());
        }
        (out, hits.len())
    }
}

/// Shannon entropy of a byte run, in bits per character. Empty run -> 0.0.
fn shannon_bits_per_char(run: &[u8]) -> f64 {
    if run.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in run {
        counts[b as usize] += 1;
    }
    let len = run.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_a_high_entropy_token_run() {
        let s = EntropyScanner::with_defaults();
        let body = b"token=Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9 end";
        let hits = s.scan(body);
        assert_eq!(hits.len(), 1, "expected one high-entropy run, got {hits:?}");
    }

    #[test]
    fn ignores_low_entropy_prose() {
        let s = EntropyScanner::with_defaults();
        let body = b"the quick brown fox jumps over the lazy dog repeatedly today";
        assert!(s.scan(body).is_empty(), "prose wrongly flagged");
    }

    #[test]
    fn ignores_runs_below_min_length() {
        let s = EntropyScanner::with_defaults();
        let body = b"id=Xa9Kf2pQ end";
        assert!(s.scan(body).is_empty(), "short run wrongly flagged");
    }

    #[test]
    fn redact_masks_without_echoing_the_token() {
        let s = EntropyScanner::with_defaults();
        let token = "Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9";
        let body = format!("token={token} end").into_bytes();
        let (out, n) = s.redact(&body);
        let rendered = String::from_utf8_lossy(&out);
        assert_eq!(n, 1);
        assert!(
            !rendered.contains(token),
            "token leaked into output: {rendered}"
        );
        assert!(rendered.contains("XXX"), "no mask present: {rendered}");
        assert!(
            rendered.contains("token="),
            "context wrongly removed: {rendered}"
        );
    }

    #[test]
    fn clean_body_passes_through_unchanged() {
        let s = EntropyScanner::with_defaults();
        let (out, n) = s.redact(b"hello world");
        assert_eq!(out, b"hello world");
        assert_eq!(n, 0);
    }
}
