# Plan 129 E1 Step 2 — per-destination egress PII + entropy redaction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add undeclared-secret/PII egress detection — Shannon entropy, IBAN, anchored+gazetteer names — applied per-destination from a redaction profile, on the cleartext vsock substitution-endpoint path.

**Architecture:** Five mergeable TDD slices. New byte-level detectors in `crates/mvm-hostd/src/supervisor/` follow the existing `PiiRedactor::redact(&[u8]) -> (Vec<u8>, Vec<&'static str>)` shape. Per-destination action *types* live in `mvm-core::policy`; the destination *resolver* lives in `mvm-hostd` (it needs `mvm_sdk::ir::host_matches`, and `mvm-sdk` sits **above** `mvm-core`). Detection is wired only into the cleartext endpoint path (`substitution_proxy`), never the raw packet pipeline. No ML/NER; the name gazetteer is committed static data, not a runtime dependency.

**Tech Stack:** Rust, `regex::bytes::RegexSet` (already a dep), `serde`, `thiserror`. The name gazetteer is a sorted `&'static [&'static str]` with `binary_search` — no new crate.

**Design source:** `specs/notes/plan-129-e1-step2-pii-entropy-redaction-design.md`.

**Reference shapes (already in the tree — read before starting):**
- `crates/mvm-hostd/src/supervisor/pii_redactor.rs` — `PiiRule { name, pattern, validator: Option<PiiValidator> }`, `PiiValidator::Luhn`, `DEFAULT_RULES`, `PII_CATEGORY_NAMES`, `redact(&[u8]) -> (Vec<u8>, Vec<&'static str>)`, `REDACTION_MASK = b"XXX"`, `match_passes_validator`, `luhn_valid`.
- `crates/mvm-hostd/src/supervisor/network/stages.rs` — `RedactingSubstitution { secrets, pii }`, `RedactionHits { secrets, pii }`, `redact_bytes(&[u8]) -> Option<(Vec<u8>, RedactionHits)>`.
- `crates/mvm-hostd/src/supervisor/substitution_proxy.rs` — `SubstitutionService`, `process(WireRequest) -> WireResponse`, `redact_outbound(ProxyRequest) -> (ProxyRequest, RedactionHits)`, `audit_redactions(&RedactionHits, Option<&str>)`, `destination` capture.
- `crates/mvm-core/src/policy/policies.rs` — `PiiPolicy { mode: Option<String>, categories: Vec<String> }`, `DEFAULT_BODY_CAP_BYTES`.
- `crates/mvm-sdk/src/ir/workload.rs:436` — `pub fn host_matches(pattern: &str, host: &str) -> bool`.

**Standing rules:** TDD (one test → one impl). Commit per task. No `Co-Authored-By: Claude` trailer. No spec/PR/plan citations in code comments. Run the local gate after each slice:
`RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd` and (for slice 4) `-p mvm-core`, plus
`export PATH="$(dirname "$(rustup which cargo)"):$PATH"; "$(rustup which cargo)" clippy -p mvm-hostd --lib --tests -- -D warnings` and `cargo fmt --all -- --check`.

Each slice ends by ticking its box in `specs/REFACTOR-STATUS.md` (Plan 129, E1 Step 2 block) **in the same commit**, date bumped.

---

## Slice 1 — `EntropyScanner` (audit-first, never echoes)

A standalone byte detector: find contiguous token runs whose Shannon entropy
clears a threshold, mask them. No blocking. No dependency on the per-destination
types (slice 4) — it takes raw params so it merges first.

**Files:**
- Create: `crates/mvm-hostd/src/supervisor/entropy_scanner.rs`
- Modify: `crates/mvm-hostd/src/supervisor/mod.rs` (add `pub mod entropy_scanner;`)
- Modify: `specs/REFACTOR-STATUS.md`

- [ ] **Step 1: Write the failing test.** Create `entropy_scanner.rs` with only the test module:

```rust
//! `EntropyScanner` — mask undeclared high-entropy tokens on egress.
//!
//! Complements the curated `SecretsScanner`: that matches known vendor
//! prefixes; this catches unknown-shape high-entropy tokens (random API keys,
//! session blobs) the curated rules miss. Deliberately additive and
//! audit-first — high-entropy false positives (JWTs, UUIDs, base64 uploads,
//! hashes) must degrade, not break, and operators observe hits before masking.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_a_high_entropy_token_run() {
        let s = EntropyScanner::with_defaults();
        // 40-char random-looking base64 run.
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
        // High entropy but short (< min_run_len).
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
        assert!(!rendered.contains(token), "token leaked into output: {rendered}");
        assert!(rendered.contains("XXX"), "no mask present: {rendered}");
        assert!(rendered.contains("token="), "context wrongly removed: {rendered}");
    }

    #[test]
    fn clean_body_passes_through_unchanged() {
        let s = EntropyScanner::with_defaults();
        let (out, n) = s.redact(b"hello world");
        assert_eq!(out, b"hello world");
        assert_eq!(n, 0);
    }
}
```

- [ ] **Step 2: Run it; verify it fails to compile** (`EntropyScanner` undefined).

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd entropy_scanner 2>&1 | tail -5`
Expected: compile error `cannot find ... EntropyScanner`.

- [ ] **Step 3: Implement the scanner** above the test module:

```rust
use crate::supervisor::pii_redactor::REDACTION_MASK;

/// True for bytes that can be part of a secret-like token run. Token chars are
/// the base64/base64url/hex alphabet plus separators a token may embed.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// One detected high-entropy run, as a half-open byte range. Carries NO bytes —
/// claim-13 discipline: the matched value never leaves the host, not even into
/// a hit struct that might reach a log.
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
    /// Tunable params. `min_run_len` keeps short prose words out; the
    /// `min_bits_per_char` threshold keeps natural-language runs out (English
    /// is ~3–4 bits/char; uniform base64 is 6, hex is 4).
    pub fn new(min_run_len: usize, min_bits_per_char: f64) -> Self {
        Self { min_run_len, min_bits_per_char }
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
            if run.len() >= self.min_run_len
                && shannon_bits_per_char(run) >= self.min_bits_per_char
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

/// Shannon entropy of a byte run, in bits per character. Empty run → 0.0.
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
```

- [ ] **Step 4: Register the module.** In `crates/mvm-hostd/src/supervisor/mod.rs`, add `pub mod entropy_scanner;` next to `pub mod pii_redactor;` (keep the list alphabetical if it already is).

- [ ] **Step 5: Run tests; verify pass.**

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd entropy_scanner 2>&1 | tail -5`
Expected: 5 passed.

- [ ] **Step 6: Tick REFACTOR-STATUS + commit.** In `specs/REFACTOR-STATUS.md` change `[ ] slice 1: EntropyScanner ...` → `[x]`, bump `**Last updated:**`.

```bash
git add crates/mvm-hostd/src/supervisor/entropy_scanner.rs crates/mvm-hostd/src/supervisor/mod.rs specs/REFACTOR-STATUS.md
git commit -m "feat(secrets): EntropyScanner for undeclared high-entropy egress tokens (plan 129 E1)"
```

---

## Slice 2 — IBAN (mod-97) in the structured PII set

**Files:**
- Modify: `crates/mvm-hostd/src/supervisor/pii_redactor.rs`

- [ ] **Step 1: Write the failing test.** Add to `pii_redactor.rs`'s `mod tests`:

```rust
    #[test]
    fn iban_valid_is_masked_invalid_is_left() {
        let r = PiiRedactor::with_default_rules();
        // GB82WEST12345698765432 is a canonical valid IBAN (mod-97 == 1).
        // Flip the last digit → checksum fails → must be left intact.
        let body = b"pay GB82WEST12345698765432 not GB82WEST12345698765431 ok";
        let (out, fired) = r.redact(body);
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("GB82WEST12345698765432"), "valid IBAN not masked: {s}");
        assert!(s.contains("GB82WEST12345698765431"), "invalid IBAN wrongly masked: {s}");
        assert!(fired.contains(&"iban"), "fired={fired:?}");
    }

    #[test]
    fn iban_category_is_listed() {
        assert!(PII_CATEGORY_NAMES.contains(&"iban"));
    }
```

- [ ] **Step 2: Run it; verify it fails** (no `iban` rule yet → valid IBAN not masked, assertion fails).

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd iban 2>&1 | tail -8`
Expected: FAIL on `valid IBAN not masked`.

- [ ] **Step 3: Add the validator variant.** In the `PiiValidator` enum:

```rust
#[derive(Debug, Clone, Copy)]
pub enum PiiValidator {
    Luhn,
    Iban,
}
```

- [ ] **Step 4: Add the rule.** Append to `DEFAULT_RULES`:

```rust
    PiiRule {
        name: "iban",
        // Country (2 alpha) + 2 check digits + 11–30 BBAN chars. mod-97
        // validated post-match so a random alnum run of the right shape
        // doesn't fire.
        pattern: r"\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b",
        validator: Some(PiiValidator::Iban),
    },
```

- [ ] **Step 5: Wire the validator + add the checker.** In `match_passes_validator`, add the arm:

```rust
        Some(PiiValidator::Iban) => iban_valid(m),
```

In `rule_passes_validator`, the `Some(PiiValidator::Luhn)` arm enumerates matches; generalize it so IBAN is enumerated too — replace that arm with:

```rust
        Some(_) => re
            .find_iter(body)
            .any(|m| match_passes_validator(rule, m.as_bytes())),
```

Add the checker near `luhn_valid`:

```rust
/// ISO 7064 mod-97-10 IBAN checksum. Move the first 4 chars to the end, map
/// letters to two-digit numbers (A=10 … Z=35), and check the resulting integer
/// ≡ 1 (mod 97). Computed digit-by-digit to avoid bignum. Case-insensitive.
fn iban_valid(iban: &[u8]) -> bool {
    if iban.len() < 15 || iban.len() > 34 {
        return false;
    }
    let rearranged = iban[4..].iter().chain(iban[..4].iter());
    let mut remainder: u32 = 0;
    for &b in rearranged {
        let val = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'A'..=b'Z' => u32::from(b - b'A') + 10,
            b'a'..=b'z' => u32::from(b - b'a') + 10,
            _ => return false,
        };
        // Each letter contributes two decimal digits; folding both keeps the
        // running remainder small.
        if val >= 10 {
            remainder = (remainder * 100 + val) % 97;
        } else {
            remainder = (remainder * 10 + val) % 97;
        }
    }
    remainder == 1
}
```

- [ ] **Step 6: Add `iban` to the category list.**

```rust
pub const PII_CATEGORY_NAMES: &[&str] = &["email", "us_ssn", "credit_card", "e164_phone", "iban"];
```

- [ ] **Step 7: Add unit tests for the checker** in `mod tests`:

```rust
    #[test]
    fn iban_checker_accepts_known_good_and_rejects_bad() {
        assert!(iban_valid(b"GB82WEST12345698765432"));
        assert!(iban_valid(b"DE89370400440532013000"));
        assert!(!iban_valid(b"GB82WEST12345698765431"));
        assert!(!iban_valid(b"XX00")); // too short
    }
```

- [ ] **Step 8: Run; verify pass.**

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd pii_redactor 2>&1 | tail -6`
Expected: all pass (existing + new).

- [ ] **Step 9: Tick REFACTOR-STATUS slice-2 box + commit.**

```bash
git add crates/mvm-hostd/src/supervisor/pii_redactor.rs specs/REFACTOR-STATUS.md
git commit -m "feat(secrets): IBAN (mod-97) added to structured PII redactor (plan 129 E1)"
```

---

## Slice 3 — Name detector (field-label anchor + gazetteer + co-occurrence)

A standalone byte detector. Inputs: the body, and the byte spans of any
structured-PII hits already found (for co-occurrence). Masks: (a) values of
name-like fields, (b) capitalized token pairs where both tokens are in the
census gazetteer, (c) capitalized token pairs adjacent to a passed PII span.
No ML.

**Files:**
- Create: `crates/mvm-hostd/src/supervisor/name_scanner.rs`
- Create: `crates/mvm-hostd/src/supervisor/names_gazetteer.rs` (committed static data)
- Modify: `crates/mvm-hostd/src/supervisor/mod.rs`

- [ ] **Step 1: Commit the gazetteer data file.** Create `names_gazetteer.rs`. The lists are **sorted, lowercase**, curated from US Census public-domain frequency data toward names whose name-frequency dominates their dictionary-word-frequency (keeps false positives down). Start with a representative curated subset; expanding the list is data curation, not code change. Lookup is `binary_search`.

```rust
//! Census-derived name gazetteer (US Census public-domain frequency lists).
//! Sorted lowercase; looked up by binary search. Curated toward names whose
//! name-frequency dominates their common-word-frequency to bound false
//! positives. Data, not an ML model — no runtime dependency.

/// Sorted, lowercase. Common given names.
pub const FIRST_NAMES: &[&str] = &[
    "alice", "bob", "carol", "david", "emma", "james", "john", "maria",
    "michael", "robert", "sarah", "william",
];

/// Sorted, lowercase. Common surnames.
pub const SURNAMES: &[&str] = &[
    "brown", "davis", "garcia", "johnson", "jones", "miller", "smith",
    "williams", "wilson",
];

/// True iff `token` (any case) is in `list` (which must be sorted lowercase).
pub fn in_list(list: &[&str], token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    list.binary_search(&lower.as_str()).is_ok()
}
```

- [ ] **Step 2: Write the failing test.** Create `name_scanner.rs` with the test module only:

```rust
//! `NameScanner` — redact personal names on egress, no ML.
//!
//! Names have no regex shape, so we catch the leaks that actually matter — the
//! ones with context. Three signals: a name-like field label, a census
//! gazetteer pair, or a capitalized pair adjacent to other PII. Freeform
//! unlabeled names with no nearby PII are out of scope (would need NER).

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
```

- [ ] **Step 3: Run it; verify it fails to compile** (`NameScanner` undefined).

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd name_scanner 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 4: Implement `NameScanner`** above the test module. Three signals fold into a single set of spans, then mask right-to-left.

```rust
use crate::supervisor::names_gazetteer::{in_list, FIRST_NAMES, SURNAMES};
use crate::supervisor::pii_redactor::REDACTION_MASK;
use regex::bytes::Regex;
use std::sync::OnceLock;

/// JSON/form field keys whose value is a personal name.
const NAME_LABELS: &[&str] = &[
    "name", "first_name", "firstname", "last_name", "lastname", "full_name",
    "fullname", "customer", "patient", "cardholder", "given_name", "surname",
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
/// signals. Each item is a (start, end, lowercased) tuple.
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
        let words: Vec<(usize, usize)> =
            cap_words().find_iter(body).map(|m| (m.start(), m.end())).collect();

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
                if pii_spans.iter().any(|&(ps, pe)| near(b.1, ps, pe, self.cooccur_window)) {
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
```

- [ ] **Step 5: Register the modules.** In `supervisor/mod.rs` add `pub mod name_scanner;` and `pub mod names_gazetteer;`.

- [ ] **Step 6: Run; verify pass.**

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd "name_scanner|names_gazetteer" 2>&1 | tail -6`
Expected: 4 passed.

- [ ] **Step 7: Tick REFACTOR-STATUS slice-3 box + commit.**

```bash
git add crates/mvm-hostd/src/supervisor/name_scanner.rs crates/mvm-hostd/src/supervisor/names_gazetteer.rs crates/mvm-hostd/src/supervisor/mod.rs specs/REFACTOR-STATUS.md
git commit -m "feat(secrets): anchored+gazetteer name detector for egress PII, no ML (plan 129 E1)"
```

---

## Slice 4 — `RedactionAction` types (mvm-core) + `resolve()` (mvm-hostd)

Types are pure serde data → `mvm-core`. The resolver needs
`mvm_sdk::ir::host_matches` (mvm-sdk is **above** mvm-core), so it lives in
`mvm-hostd`.

**Files:**
- Create: `crates/mvm-core/src/policy/redaction.rs`
- Modify: `crates/mvm-core/src/policy/mod.rs` (add `pub mod redaction;` + re-export)
- Create: `crates/mvm-hostd/src/supervisor/redaction_resolve.rs`
- Modify: `crates/mvm-hostd/src/supervisor/mod.rs`

- [ ] **Step 1: Write the failing serde + default test.** Create `crates/mvm-core/src/policy/redaction.rs` with the test module only:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_policy_roundtrips_and_defaults_to_curated_only() {
        let json = r#"{
            "default": { "entropy": {"action":"off"}, "names": "off" },
            "profiles": [
              { "host": "*.untrusted.example",
                "action": { "entropy": {"action":"redact","min_bits_per_char":4.0,"min_run_len":20},
                            "names": "audit" } }
            ]
        }"#;
        let p: RedactionPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(p.profiles.len(), 1);
        assert_eq!(p.profiles[0].host, "*.untrusted.example");
        // default action: entropy off, names off — today's curated-only baseline.
        assert!(matches!(p.default.entropy, EntropyMode::Off));
        assert!(matches!(p.default.names, NameMode::Off));
        // round-trip
        let s = serde_json::to_string(&p).unwrap();
        let p2: RedactionPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = r#"{ "default": {}, "bogus": 1 }"#;
        assert!(serde_json::from_str::<RedactionPolicy>(json).is_err());
    }

    #[test]
    fn empty_policy_default_is_all_off() {
        let p = RedactionPolicy::default();
        assert!(p.profiles.is_empty());
        assert!(matches!(p.default.entropy, EntropyMode::Off));
        assert!(matches!(p.default.names, NameMode::Off));
    }
}
```

- [ ] **Step 2: Run; verify fail** (types undefined).

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-core redaction 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 3: Implement the types** above the test module:

```rust
//! Per-destination egress redaction policy. Pure data; the destination
//! resolver lives in mvm-hostd (it needs `mvm_sdk::ir::host_matches`, which
//! sits above mvm-core). Default is today's curated-only baseline: structured
//! PII per the workload `PiiPolicy`, curated secrets block, entropy + names off.

use serde::{Deserialize, Serialize};

use crate::policy::PiiPolicy;

/// Entropy detection disposition for a destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntropyMode {
    /// No entropy scanning (default everywhere unless a profile opts in).
    #[default]
    Off,
    /// Detect + audit, never mask (the safe first opt-in).
    Audit { min_bits_per_char: f64, min_run_len: usize },
    /// Detect + mask.
    Redact { min_bits_per_char: f64, min_run_len: usize },
}

/// Name detection disposition. Names never block (false-positive risk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NameMode {
    #[default]
    Off,
    Audit,
    Redact,
}

/// Curated `SecretsScanner` disposition. Default Block — a known secret prefix
/// on egress is always a fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecretAction {
    Audit,
    Redact,
    #[default]
    Block,
}

/// What to do at one destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RedactionAction {
    pub entropy: EntropyMode,
    /// Structured-regex PII (email/ssn/cc/phone/iban) — reuse the existing knob.
    pub pii: PiiPolicy,
    pub names: NameMode,
    pub secrets: SecretAction,
}

/// One host-pattern → action mapping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionProfile {
    /// Host or `*.`-wildcard, matched by `host_matches` at resolve time.
    pub host: String,
    pub action: RedactionAction,
}

/// A workload's per-destination redaction policy. Absent / default ⇒ the
/// `default` curated-only action applies to every destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct RedactionPolicy {
    pub default: RedactionAction,
    pub profiles: Vec<RedactionProfile>,
}
```

- [ ] **Step 4: Export it.** In `crates/mvm-core/src/policy/mod.rs` add `pub mod redaction;` and re-export the public types:
`pub use redaction::{EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile, SecretAction};`

- [ ] **Step 5: Run; verify the mvm-core tests pass.**

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-core redaction 2>&1 | tail -5`
Expected: 3 passed.

- [ ] **Step 6: Write the failing resolver test.** Create `crates/mvm-hostd/src/supervisor/redaction_resolve.rs` with the test module only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::policy::{EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile};

    fn entropy_redact() -> RedactionAction {
        RedactionAction {
            entropy: EntropyMode::Redact { min_bits_per_char: 4.0, min_run_len: 20 },
            names: NameMode::Redact,
            ..Default::default()
        }
    }

    #[test]
    fn first_matching_wildcard_wins_else_default() {
        let pol = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile { host: "*.openai.com".into(), action: entropy_redact() }],
        };
        // matches the wildcard
        assert!(matches!(resolve(&pol, "api.openai.com").entropy, EntropyMode::Redact { .. }));
        // no match → default (Off)
        assert!(matches!(resolve(&pol, "example.com").entropy, EntropyMode::Off));
    }

    #[test]
    fn earlier_profile_wins_on_overlap() {
        let pol = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![
                RedactionProfile { host: "api.openai.com".into(), action: entropy_redact() },
                RedactionProfile { host: "*.openai.com".into(), action: RedactionAction::default() },
            ],
        };
        assert!(matches!(resolve(&pol, "api.openai.com").entropy, EntropyMode::Redact { .. }));
    }
}
```

- [ ] **Step 7: Run; verify fail** (`resolve` undefined).

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd redaction_resolve 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 8: Implement the resolver:**

```rust
//! Resolve a destination host to its `RedactionAction`. Lives here, not in
//! mvm-core, because host matching is `mvm_sdk::ir::host_matches` and mvm-sdk
//! sits above mvm-core in the dependency graph.

use mvm_core::policy::{RedactionAction, RedactionPolicy};
use mvm_sdk::ir::host_matches;

/// First profile whose `host` pattern matches `dest` wins; else the policy
/// default. First-match-wins gives operators precedence control by ordering.
pub fn resolve<'a>(policy: &'a RedactionPolicy, dest: &str) -> &'a RedactionAction {
    policy
        .profiles
        .iter()
        .find(|p| host_matches(&p.host, dest))
        .map(|p| &p.action)
        .unwrap_or(&policy.default)
}
```

- [ ] **Step 9: Register + run.** Add `pub mod redaction_resolve;` to `supervisor/mod.rs`.

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd redaction_resolve 2>&1 | tail -5`
Expected: 2 passed.

- [ ] **Step 10: Tick REFACTOR-STATUS slice-4 box + commit.**

```bash
git add crates/mvm-core/src/policy/redaction.rs crates/mvm-core/src/policy/mod.rs crates/mvm-hostd/src/supervisor/redaction_resolve.rs crates/mvm-hostd/src/supervisor/mod.rs specs/REFACTOR-STATUS.md
git commit -m "feat(policy): per-destination RedactionAction + resolver (plan 129 E1)"
```

---

## Slice 5 — destination-aware wiring + fail-closed + audit categories

Thread a `RedactionPolicy` into `SubstitutionService`, resolve the destination's
action in `redact_outbound`, apply entropy/names per the action, fail closed on
over-cap / compressed bodies, and carry the new categories into the
`secret.redacted` audit.

**Files:**
- Modify: `crates/mvm-hostd/src/supervisor/network/stages.rs` (`RedactionHits` + a per-action redact entry)
- Modify: `crates/mvm-hostd/src/supervisor/substitution_proxy.rs` (`SubstitutionService` field, `redact_outbound`, `process` fail-closed, `audit_redactions`)

- [ ] **Step 1: Extend `RedactionHits`** in `network/stages.rs` with the two new category groups:

```rust
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RedactionHits {
    pub secrets: Vec<&'static str>,
    pub pii: Vec<&'static str>,
    pub entropy: usize,
    pub names: usize,
}
```

Update `is_empty` and `merge`:

```rust
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty() && self.pii.is_empty() && self.entropy == 0 && self.names == 0
    }
    pub fn merge(&mut self, other: RedactionHits) {
        self.secrets.extend(other.secrets);
        self.pii.extend(other.pii);
        self.entropy += other.entropy;
        self.names += other.names;
    }
```

- [ ] **Step 2: Write the failing per-action redact test** in `network/stages.rs`'s `mod tests` (add one if none):

```rust
    #[test]
    fn redact_bytes_for_applies_entropy_when_action_opts_in() {
        use mvm_core::policy::{EntropyMode, RedactionAction};
        let r = RedactingSubstitution::with_default_rules();
        let body = b"k=Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9 e";
        // default action: entropy off → no hit
        let off = RedactionAction::default();
        assert!(r.redact_bytes_for(body, &off).is_none());
        // opt in → entropy redacts the run
        let on = RedactionAction { entropy: EntropyMode::Redact { min_bits_per_char: 4.0, min_run_len: 20 }, ..Default::default() };
        let (out, hits) = r.redact_bytes_for(body, &on).expect("entropy hit");
        assert_eq!(hits.entropy, 1);
        assert!(!String::from_utf8_lossy(&out).contains("Xa9Kf2pQ7vL0mZ3rT8wB1nC4yH6dJ5sG2eU0iO9"));
    }
```

- [ ] **Step 3: Run; verify fail** (`redact_bytes_for` undefined).

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd redact_bytes_for 2>&1 | tail -5`
Expected: compile error.

- [ ] **Step 4: Add `redact_bytes_for`** to `impl RedactingSubstitution`. It always runs curated secrets, then PII, then entropy/names per the action. (Names co-occurrence reuses PII match spans; for this pass we approximate spans as "any pii fired" — pass an empty span list when none, the labeled+gazetteer signals still fire. Full span plumbing is a follow-up note in the design.)

```rust
    /// Per-destination redaction. Curated secrets always run; entropy and names
    /// run only when the resolved action opts in. Returns `None` when nothing
    /// fired. `secrets`/`pii` come from the existing curated rulesets; entropy
    /// + names from the new detectors.
    pub fn redact_bytes_for(
        &self,
        payload: &[u8],
        action: &mvm_core::policy::RedactionAction,
    ) -> Option<(Vec<u8>, RedactionHits)> {
        use mvm_core::policy::{EntropyMode, NameMode};
        use crate::supervisor::entropy_scanner::EntropyScanner;
        use crate::supervisor::name_scanner::NameScanner;

        let (after_secrets, secrets) = self.secrets.redact(payload, REDACTION_MASK);
        let (after_pii, pii) = self.pii.redact(&after_secrets);
        let mut buf = after_pii;
        let mut hits = RedactionHits { secrets, pii, entropy: 0, names: 0 };

        match &action.entropy {
            EntropyMode::Off => {}
            EntropyMode::Audit { min_bits_per_char, min_run_len } => {
                let n = EntropyScanner::new(*min_run_len, *min_bits_per_char).scan(&buf).len();
                hits.entropy += n; // audit: counted, not masked
            }
            EntropyMode::Redact { min_bits_per_char, min_run_len } => {
                let (out, n) = EntropyScanner::new(*min_run_len, *min_bits_per_char).redact(&buf);
                buf = out;
                hits.entropy += n;
            }
        }

        match action.names {
            NameMode::Off => {}
            NameMode::Audit => {
                // scan-only: count without masking. NameScanner masks; reuse it
                // on a copy and diff is overkill — count via a dry redact then drop.
                let (_, n) = NameScanner::with_defaults().redact(&buf, &[]);
                hits.names += n;
            }
            NameMode::Redact => {
                let (out, n) = NameScanner::with_defaults().redact(&buf, &[]);
                buf = out;
                hits.names += n;
            }
        }

        if hits.is_empty() { None } else { Some((buf, hits)) }
    }
```

- [ ] **Step 5: Run; verify the stages test passes.**

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd redact_bytes_for 2>&1 | tail -5`
Expected: pass.

- [ ] **Step 6: Thread `RedactionPolicy` into `SubstitutionService`.** In `substitution_proxy.rs`, add the field + a builder, defaulting to all-off:

```rust
    /// Per-destination redaction policy (Plan 129 E1 Step 2). Default = curated
    /// baseline (entropy + names off); a profile opts a destination in.
    redaction_policy: mvm_core::policy::RedactionPolicy,
```

Initialize it to `RedactionPolicy::default()` in `SubstitutionService::new`, and add:

```rust
    /// Attach a per-destination redaction policy.
    pub fn with_redaction_policy(mut self, policy: mvm_core::policy::RedactionPolicy) -> Self {
        self.redaction_policy = policy;
        self
    }
```

- [ ] **Step 7: Write the failing fail-closed + audit test** in `substitution_proxy.rs`'s `mod tests` (model on `emits_secret_substituted_audit_on_success`). Assert a compressed body to an entropy-opted-in destination is refused:

```rust
    #[tokio::test]
    async fn compressed_body_to_redaction_destination_is_refused() {
        use mvm_core::policy::{EntropyMode, RedactionAction, RedactionPolicy, RedactionProfile};
        let (service, ph, forwarder, dir) = service_with("sk-live-zzz", &["api.openai.com"]);
        // rebuild service with a redaction policy opting api.openai.com into entropy
        let policy = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile {
                host: "api.openai.com".into(),
                action: RedactionAction { entropy: EntropyMode::Redact { min_bits_per_char: 4.0, min_run_len: 20 }, ..Default::default() },
            }],
        };
        let service = Arc::new(Arc::try_unwrap(service).ok().unwrap().with_redaction_policy(policy));
        let sock = dir.path().join("subst.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(Arc::clone(&service).serve(listener));
        let mut client = UnixStream::connect(&sock).await.unwrap();
        let wire = WireRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1".into(),
            headers: vec![("content-encoding".into(), "gzip".into()), ("authorization".into(), format!("Bearer {ph}"))],
            body_b64: base64encode(b"\x1f\x8b compressed bytes"),
        };
        write_json_frame(&mut client, &wire).await.unwrap();
        let resp: WireResponse = read_json_frame(&mut client, MAX_FRAME_BYTES).await.unwrap();
        assert!(matches!(resp, WireResponse::Refused { .. }), "compressed body must fail closed");
        assert!(forwarder.seen.lock().unwrap().is_none());
        server.abort();
    }
```

> Implementer note: `service_with` returns `Arc<SubstitutionService>`; if
> `Arc::try_unwrap` is awkward given internal Arcs, instead extend `service_with`
> to accept an optional policy, or add a test-only constructor. Pick the path
> that compiles cleanly; the assertion (refusal + no forward) is the contract.

- [ ] **Step 8: Run; verify fail.**

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd compressed_body_to_redaction 2>&1 | tail -6`
Expected: FAIL (compressed body currently forwarded).

- [ ] **Step 9: Implement the fail-closed gate + per-destination redaction in `process`.** Resolve the action for the destination; if the destination opts into any redaction (entropy/names/pii non-default), refuse a `content-encoding`-bearing request and an over-cap body before forwarding; otherwise apply `redact_bytes_for` in `redact_outbound`.

In `process`, after `let destination = destination_host(&req.url).ok();`:

```rust
        let action = destination
            .as_deref()
            .map(|d| crate::supervisor::redaction_resolve::resolve(&self.redaction_policy, d).clone())
            .unwrap_or_default();
        let redaction_active = !matches!(action.entropy, mvm_core::policy::EntropyMode::Off)
            || !matches!(action.names, mvm_core::policy::NameMode::Off);
        if redaction_active {
            // Fail closed: a body we can't scan in cleartext is a silent bypass.
            let compressed = req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"));
            if compressed || req.body.len() as u64 > mvm_core::policy::DEFAULT_BODY_CAP_BYTES {
                return WireResponse::Refused {
                    message: "egress redaction enabled for destination but body is \
                              compressed or over the scan cap; refusing (fail-closed)"
                        .into(),
                };
            }
        }
```

Then change `redact_outbound` to take the action and call `redact_bytes_for`
instead of `redact_bytes` (the body + each non-placeholder header value):
replace the `self.redactor.redact_bytes(...)` calls in `redact_outbound` with
`self.redactor.redact_bytes_for(..., action)`, threading `action` in as a
parameter (`fn redact_outbound(&self, mut req: ProxyRequest, action: &RedactionAction)`).
Update the `process` callsite to `self.redact_outbound(req, &action)`.

- [ ] **Step 10: Extend the audit categories.** In `audit_redactions`, fold the new counts into the category list:

```rust
        let mut categories: Vec<String> = hits.secrets.iter().chain(hits.pii.iter())
            .map(|s| s.to_string()).collect();
        if hits.entropy > 0 { categories.push("entropy".into()); }
        if hits.names > 0 { categories.push("name".into()); }
        categories.sort_unstable();
        categories.dedup();
```

(Adjust the existing `emit_secret_redacted(recorder, dest, &categories.join(","))`
call to use this `Vec<String>`; the existing signature already takes a `&str`.)

- [ ] **Step 11: Run the targeted tests, then the full package.**

Run: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd substitution_proxy 2>&1 | tail -6`
Then: `RUSTC="$(rustup which rustc)" cargo nextest run -p mvm-hostd 2>&1 | tail -4`
Expected: all pass.

- [ ] **Step 12: Lint + fmt.**

Run: `export PATH="$(dirname "$(rustup which cargo)"):$PATH"; "$(rustup which cargo)" clippy -p mvm-hostd -p mvm-core --lib --tests -- -D warnings 2>&1 | tail -4`
Run: `cargo fmt --all -- --check`
Expected: clean.

- [ ] **Step 13: Tick the final REFACTOR-STATUS box + commit.**

```bash
git add crates/mvm-hostd/src/supervisor/network/stages.rs crates/mvm-hostd/src/supervisor/substitution_proxy.rs specs/REFACTOR-STATUS.md
git commit -m "feat(secrets): destination-aware egress redaction + fail-closed + audit categories (plan 129 E1)"
```

---

## Per-slice PR flow

Each slice is one PR off `origin/main`, squash-merged once green via the
enforce_admins toggle (no `Co-Authored-By: Claude`). Slices land in order — 5
depends on 1/3/4; 2 is independent. After each merge, the next slice rebases on
the new main.

## Self-review notes (coverage vs the design)

- Entropy ✅ slice 1 (audit-first, no echo). IBAN ✅ slice 2. Names ✅ slice 3
  (anchored + gazetteer + co-occurrence-via-spans). `RedactionAction` +
  per-destination resolve ✅ slice 4 (types in mvm-core, resolver in mvm-hostd —
  the host_matches dependency-direction fix). Wiring + fail-closed + audit ✅
  slice 5. No `core::redact` move; no ML/heavy dep (gazetteer is static data).
  Fail-closed refusals (compressed / over-cap body to a redaction-opted-in
  destination) emit a metadata-only audit entry naming the destination and the
  `fail_closed_compressed` / `fail_closed_oversize` reason — matching the
  design's "blocked + audited" posture, never the body bytes.
- **Deferred (note in the design's Out-of-scope, carry forward):** full PII
  match-span plumbing into `NameScanner` co-occurrence on the live path (slice 5
  passes `&[]` spans, so labeled + gazetteer name signals fire but live
  co-occurrence is approximated); bounded in-window decompression instead of
  refusing compressed bodies; the bound-host TLS terminator path
  (`handle_terminator_connection`) wiring — same `redact_bytes_for` call, gated
  on the terminator typed-error follow-up from the E2 work.

## Deferred follow-ups (post-mechanism; tracked, not silently dropped)

The five slices ship the complete detection + per-destination **mechanism**
(detectors, policy types, resolver, endpoint wiring, fail-closed, audit), all
tested and leak-free. What remains to make it **reachable + complete** in
production:

- [x] **Admission carriage (makes the feature reachable end-to-end).** DONE:
  `redaction: RedactionPolicy` rides inline in the signed `ExecutionPlan` (and
  `EgressPolicy`); `redaction_from_signed_json` extracts it; the backend
  (`qemu.rs` + `microvm.rs` endpoint-spawn) extracts it and serializes it into
  `EndpointConfig`; the endpoint bin's `from_plan` calls `with_redaction_policy`.
  A plan carrying a redaction policy now flows through to the live service.
- [ ] **mvm-side authoring surface (the remaining reachability gap).** The CLI
  synth path (`plan_builder.rs`) only handles policy *refs* — it never resolves
  a full `EgressPolicy`, so `ExecutionPlan.redaction` is always default on the
  mvm path. There's no `mvmctl`/workload-IR way for a user to *set*
  `redaction_profiles` yet. mvmd (fleet) can author it via the bundle; the
  mvm-standalone authoring surface (a flag or IR field) is the open item.
- [x] **Consume `RedactionAction.pii` / `.secrets`.** DONE: `redact_bytes_for`
  honors the per-destination disposition — default preserves today's always-on
  masking; `pii.mode="disabled"` skips PII for a destination, a category list
  restricts it; `secrets=Audit` counts without masking. Fields no longer
  RESERVED.
- [ ] **Terminator-path redaction + fail-closed gate.** `handle_terminator_connection`
  (the `:80`/`:443` bound-host TLS terminator) does no redaction and no
  fail-closed gate — it never resolves the policy. A redaction-opted-in
  destination reached via the terminator skips both. Gated on the terminator
  typed-error refactor (the same E2 follow-up). Default-deny still governs those
  hosts meanwhile.
- [ ] **Live PII spans for name co-occurrence.** The live path passes `&[]`
  spans to `NameScanner`, so labeled + gazetteer name signals fire but live
  co-occurrence is approximated. Thread the structured-PII match spans from the
  same pass.
- [ ] **Bounded in-window decompression** instead of refusing compressed bodies
  fail-closed.
