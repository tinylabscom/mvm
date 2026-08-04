//! Recognising known secret material in a byte stream that arrives in
//! arbitrarily chopped frames — without holding any of it.
//!
//! The scanner is bound to a set of [`SecretFingerprint`]s, computed by the
//! process that legitimately holds the plaintext. It slides a rolling hash
//! over the concatenation of the tail it carried and the payload just offered,
//! at every offset and for every distinct secret length, so a secret split
//! down the middle of two writes is still a contiguous match here.
//!
//! ## Why it withholds, and why it withholds more than it used to
//!
//! Retaining context and withholding bytes are the same act. If the scanner
//! shipped the tail of a frame and kept a copy to scan against, a secret
//! straddling that boundary would be refused *after* its first half had
//! already reached the guest — the refusal would be theatre. So whatever it
//! must still be able to see, it must still be holding.
//!
//! Against plaintext, "what it must still see" is exactly the suffix that is
//! still a live prefix of some secret; everything else provably cannot become
//! one and ships at once. Against fingerprints that question is unanswerable —
//! deliberately, because the prefix hashes that would answer it are a
//! byte-at-a-time recovery oracle (see
//! [`mvm_protocol::stream::secret_fingerprint`]). So the scanner withholds a
//! fixed tail of `longest_secret - 1` bytes instead.
//!
//! The cost is bounded and worth naming: on a VM with bound secrets, the last
//! `longest - 1` bytes of each write wait for the next write or for
//! [`SecretScanner::flush`] at close. A VM with no bound secrets scans nothing
//! and withholds nothing, so the latency lands only where a secret could
//! actually be leaked. The withheld tail is never dropped — it rides out on
//! the next frame or on the close.
//!
//! ## What it cannot catch
//!
//! Not a gap more rules would close: any encoding of the secret (base64, hex,
//! URL-escaping), any derivation of it (a hash, a signature, a substring used
//! as a lookup key), and any secret the host never registered. It is a
//! backstop against a caller that pasted the wrong thing, not a defence
//! against a caller that wants the secret in there. The property that actually
//! holds is upstream — the host substitutes secrets on egress and so has no
//! reason to send one into a guest at all.

use std::sync::Arc;

use mvm_protocol::stream::secret_fingerprint::{
    SecretCategory, SecretFingerprint, leading_weight, roll, window_hash, window_sizes,
};
use zeroize::Zeroize;

/// Slides a window over a stream looking for bound fingerprints.
pub(crate) struct SecretScanner {
    fingerprints: Arc<Vec<SecretFingerprint>>,
    /// Distinct secret lengths, longest first: one rolling pass per entry.
    sizes: Vec<usize>,
    /// How many trailing bytes must stay resident to see a secret that
    /// straddles the next frame boundary — one byte short of the longest
    /// secret, because a full-length suffix would be a match, not a straddle.
    carry: usize,
    /// The withheld tail. Bytes the gate has scanned and is holding.
    pending: Vec<u8>,
}

impl SecretScanner {
    pub(crate) fn new(fingerprints: Arc<Vec<SecretFingerprint>>) -> Self {
        let sizes = window_sizes(&fingerprints);
        let carry = sizes.first().copied().unwrap_or(0).saturating_sub(1);
        Self {
            fingerprints,
            sizes,
            carry,
            pending: Vec::new(),
        }
    }

    /// Clear `payload` for delivery, or name the category it matched.
    ///
    /// On `Ok` the returned bytes may go to the guest in order; the tail this
    /// scanner is still holding comes out on a later call or on
    /// [`flush`](Self::flush).
    pub(crate) fn admit(&mut self, payload: &[u8]) -> Result<Vec<u8>, SecretCategory> {
        if self.sizes.is_empty() {
            return Ok(payload.to_vec());
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(payload);

        if let Some(category) = self.first_match(&buf) {
            // The buffer straddles a fingerprinted secret; it is not going
            // anywhere, and it does not linger in this process either.
            buf.zeroize();
            return Err(category);
        }

        let hold = self.carry.min(buf.len());
        self.pending = buf.split_off(buf.len() - hold);
        Ok(buf)
    }

    /// Release the withheld tail.
    ///
    /// Safe by construction: the scan already cleared every window inside it,
    /// so what is left is a stream that ended without completing any bound
    /// secret. Dropping it instead would silently swallow the writer's last
    /// bytes.
    pub(crate) fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    /// How much is being withheld. A length, not the bytes.
    pub(crate) fn withheld_len(&self) -> usize {
        self.pending.len()
    }

    /// The category of the first bound fingerprint `buf` contains, longest
    /// secret first.
    fn first_match(&self, buf: &[u8]) -> Option<SecretCategory> {
        self.sizes
            .iter()
            .filter(|&&len| len <= buf.len())
            .find_map(|&len| self.match_at_length(buf, len))
    }

    /// One rolling pass over every `len`-sized window of `buf`.
    ///
    /// The rolling hash proposes; [`SecretFingerprint::matches_window`]
    /// disposes. Re-deriving the candidate's hash directly costs one pass over
    /// `len` bytes on a hit and means a slip in the incremental arithmetic
    /// cannot on its own refuse a caller's frame — the two definitions have to
    /// agree before anything is refused.
    fn match_at_length(&self, buf: &[u8], len: usize) -> Option<SecretCategory> {
        let weight = leading_weight(len);
        let mut hash = window_hash(&buf[..len]);
        for start in 0..=buf.len() - len {
            if start > 0 {
                hash = roll(hash, buf[start - 1], buf[start + len - 1], weight);
            }
            let window = &buf[start..start + len];
            if let Some(hit) = self
                .fingerprints
                .iter()
                .filter(|fp| fp.len() == len && fp.hash() == hash)
                .find(|fp| fp.matches_window(window))
            {
                return Some(hit.category());
            }
        }
        None
    }
}

impl Drop for SecretScanner {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner(secrets: &[&str]) -> SecretScanner {
        SecretScanner::new(Arc::new(
            secrets
                .iter()
                .filter_map(|s| SecretFingerprint::of(s.as_bytes(), SecretCategory::HostSecret))
                .collect(),
        ))
    }

    #[test]
    fn a_secret_delivered_whole_is_refused() {
        let mut s = scanner(&["AKIAIOSFODNN7EXAMPLE"]);
        assert_eq!(
            s.admit(b"export KEY=AKIAIOSFODNN7EXAMPLE\n"),
            Err(SecretCategory::HostSecret)
        );
    }

    #[test]
    fn a_secret_split_across_two_admits_is_refused() {
        // The case the carried tail exists for: a per-frame check would clear
        // both halves and hand the guest the whole thing.
        let mut s = scanner(&["AKIAIOSFODNN7EXAMPLE"]);
        s.admit(b"AKIAIOSFODNN").expect("half is not a match");
        assert_eq!(
            s.admit(b"7EXAMPLE"),
            Err(SecretCategory::HostSecret),
            "the second half completes it"
        );
    }

    #[test]
    fn the_first_half_of_a_split_secret_is_never_cleared() {
        // Refusing the second frame is worthless if the first already handed
        // the guest twelve bytes of the key.
        let mut s = scanner(&["AKIAIOSFODNN7EXAMPLE"]);
        let cleared = s.admit(b"echo AKIAIOSFODNN").expect("half is not a match");
        assert!(
            !cleared.ends_with(b"AKIAIOSFODNN"),
            "cleared {:?}",
            String::from_utf8_lossy(&cleared)
        );
        assert_eq!(cleared, b"", "17 bytes, all inside the 19-byte carry");
        assert_eq!(s.withheld_len(), 17);
    }

    #[test]
    fn a_stream_that_ends_without_a_secret_gets_its_tail_back() {
        let mut s = scanner(&["AKIAIOSFODNN7EXAMPLE"]);
        let cleared = s.admit(b"ls -la\n").expect("nothing to match");
        assert_eq!(
            [cleared, s.flush()].concat(),
            b"ls -la\n",
            "every byte comes out, in order"
        );
        assert_eq!(s.withheld_len(), 0);
    }

    #[test]
    fn the_carry_is_one_byte_short_of_the_longest_secret() {
        let mut s = scanner(&["abcd", "abcdefghij"]);
        let cleared = s.admit(b"0123456789ABCDEF").expect("nothing to match");
        assert_eq!(cleared, b"0123456", "16 bytes in, 9 held back");
        assert_eq!(s.withheld_len(), 9);
    }

    #[test]
    fn a_scanner_with_no_fingerprints_delivers_verbatim_and_withholds_nothing() {
        // The latency of the carried tail must land only on VMs that bound a
        // secret; everything else pays nothing.
        let mut s = scanner(&[]);
        assert_eq!(
            s.admit(b"AKIAIOSFODNN7EXAMPLE").expect("nothing bound"),
            b"AKIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(s.withheld_len(), 0);
    }

    #[test]
    fn a_secret_arriving_one_byte_per_admit_is_still_refused() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let mut s = scanner(&[secret]);
        let mut refused = None;
        for byte in secret.bytes() {
            if let Err(category) = s.admit(&[byte]) {
                refused = Some(category);
                break;
            }
        }
        assert_eq!(refused, Some(SecretCategory::HostSecret));
    }

    #[test]
    fn a_fingerprint_no_secret_produced_still_refuses_the_bytes_that_satisfy_it() {
        // What a hash collision looks like from in here, and the reason the
        // gate's refusal may not claim the bytes *are* a secret: the scanner
        // holds no value to compare against, so anything satisfying a bound
        // (len, hash) pair is refused. Built from the wire form — which is how
        // a fingerprint actually arrives — so no plaintext enters this test's
        // scanner at all.
        let innocent = b"ls -la /tmp\n";
        let forged: SecretFingerprint = serde_json::from_str(&format!(
            r#"{{"len":{},"hash":{},"category":"host-secret"}}"#,
            innocent.len(),
            window_hash(innocent)
        ))
        .expect("a fingerprint arrives as JSON");
        let mut s = SecretScanner::new(Arc::new(vec![forged]));
        assert_eq!(
            s.admit(innocent),
            Err(SecretCategory::HostSecret),
            "matching is by fingerprint alone, whatever produced the bytes"
        );
    }
}
