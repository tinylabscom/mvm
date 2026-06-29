//! Ingress secret redaction.
//!
//! The inbound counterpart to host-side egress substitution: before an inbound
//! buffer (an upstream response) is delivered to the guest, any occurrence of a
//! known secret VALUE the broker holds is masked. Secrets never enter the
//! microVM — so even if an upstream echoes a credential back, the guest receives
//! only the mask. Host-side and value-based (it masks the exact secret bytes the
//! broker knows), distinct from the egress pattern/entropy redactor.

/// The fixed mask substituted for a secret value.
pub const REDACTION_MASK: &[u8] = b"[mvm-redacted]";

/// The result of redacting an inbound buffer: the masked bytes and how many
/// secret occurrences were replaced (for the audit record — a non-zero count on
/// an inbound flow is worth flagging).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    pub redacted: Vec<u8>,
    pub hits: usize,
}

/// Mask every occurrence of any known secret value in `buffer` before it is
/// delivered to the guest. Binary-safe (operates on raw bytes). Empty secret
/// values are ignored — they would otherwise match everywhere.
pub fn redact_for_guest(buffer: &[u8], secret_values: &[&str]) -> RedactionResult {
    let mut redacted = buffer.to_vec();
    let mut hits = 0;
    for secret in secret_values {
        let needle = secret.as_bytes();
        if needle.is_empty() {
            continue;
        }
        let (next, n) = replace_all(&redacted, needle, REDACTION_MASK);
        redacted = next;
        hits += n;
    }
    RedactionResult { redacted, hits }
}

/// Replace every non-overlapping occurrence of `needle` in `haystack` with
/// `mask`, returning the new buffer and the number of replacements.
fn replace_all(haystack: &[u8], needle: &[u8], mask: &[u8]) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(haystack.len());
    let mut hits = 0;
    let mut i = 0;
    while i < haystack.len() {
        if needle.len() <= haystack.len() - i && &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(mask);
            i += needle.len();
            hits += 1;
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    (out, hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_a_known_secret_value() {
        let body = b"Authorization: Bearer sk-live-12345\r\n";
        let result = redact_for_guest(body, &["sk-live-12345"]);
        assert_eq!(result.hits, 1);
        assert!(
            !result
                .redacted
                .windows("sk-live-12345".len())
                .any(|w| w == b"sk-live-12345"),
            "secret value must not survive in the buffer delivered to the guest"
        );
    }

    #[test]
    fn redacts_multiple_occurrences_and_multiple_secrets() {
        let body = b"a=AAA b=BBB a2=AAA";
        let result = redact_for_guest(body, &["AAA", "BBB"]);
        assert_eq!(result.hits, 3); // AAA twice, BBB once
        assert!(
            !result
                .redacted
                .windows(3)
                .any(|w| w == b"AAA" || w == b"BBB")
        );
    }

    #[test]
    fn clean_buffer_is_unchanged_with_zero_hits() {
        let body = b"nothing secret here";
        let result = redact_for_guest(body, &["sk-live-12345"]);
        assert_eq!(result.hits, 0);
        assert_eq!(result.redacted, body);
    }

    #[test]
    fn empty_secret_value_is_ignored() {
        // An empty secret would otherwise "match" everywhere.
        let body = b"data";
        let result = redact_for_guest(body, &[""]);
        assert_eq!(result.hits, 0);
        assert_eq!(result.redacted, body);
    }

    #[test]
    fn redaction_is_binary_safe() {
        // Secret bytes embedded in non-UTF-8 surroundings still get masked.
        let mut body = vec![0xff, 0x00, 0xfe];
        body.extend_from_slice(b"TOKEN");
        body.push(0x00);
        let result = redact_for_guest(&body, &["TOKEN"]);
        assert_eq!(result.hits, 1);
        assert!(!result.redacted.windows(5).any(|w| w == b"TOKEN"));
        assert_eq!(result.redacted.first(), Some(&0xff));
    }
}
