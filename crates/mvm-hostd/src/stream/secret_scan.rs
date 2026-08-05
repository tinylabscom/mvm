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
//! deliberately, because the prefix hashes that would answer it disclose the
//! secret outright (see [`mvm_contract::stream::secret_fingerprint`]). So the
//! scanner withholds a fixed tail of `longest_secret - 1` bytes instead.
//!
//! ## Why the blanket carry is the safe one
//!
//! It looks like the lazy choice and it is the load-bearing one. Withholding
//! only the tails that could still *become* a secret — what plaintext buys —
//! makes the withhold-or-deliver decision depend on the content of the bytes,
//! and that decision is observable: whoever holds the input grant can feed one
//! byte, watch whether anything came out, and read the answer. That is a
//! prefix oracle, and it walks a 40-byte credential out in roughly 40x256
//! probes instead of 256^40. Because *everything* is withheld unconditionally,
//! the decision carries no information about the content at all. The
//! imprecision is what makes it silent.
//!
//! ## What the carry costs, and how the cost is paid
//!
//! On a VM with bound secrets the last `longest - 1` bytes of every write wait
//! for the *next* write — so a write shorter than the carry clears nothing.
//! Left there that is a deadlock rather than latency: with a 40-byte bound
//! secret an 11-byte request line delivers zero bytes, so a workload that
//! answers per line never gets a line, never answers, and the operator never
//! sends the write that would release the first one.
//!
//! [`SecretScanner::flush`] is what breaks that circle, and the caller decides
//! when to call it: this scanner is synchronous and has no clock, so the gate
//! releases the tail once its writer has been silent long enough (see
//! `stream::input_gate`'s `DEFAULT_IDLE_FLUSH_AFTER`). That release is on
//! elapsed time alone — never on what the bytes are, which is the same reason
//! the carry is blanket. What it costs is stated with the rest of what this
//! cannot catch, below: a secret split across the silence is no longer
//! contiguous here and is missed.
//!
//! A VM with no bound secrets scans nothing and withholds nothing, so all of
//! this lands only where a secret could actually be leaked, and the withheld
//! tail is never dropped — it rides out on the next frame, on the idle
//! release, or on the close.
//!
//! ## What it cannot catch
//!
//! Not a gap more rules would close: any encoding of the secret (base64, hex,
//! URL-escaping), any derivation of it (a hash, a signature, a substring used
//! as a lookup key), any secret the host never registered, and — once the tail
//! has been released — a secret whose halves the sender separated by a
//! deliberate pause. The last of those is the newest and the least of them:
//! it needs a caller patient enough to stop mid-credential, and a caller that
//! patient would simply base64 it. It is a backstop against a caller that
//! pasted the wrong thing, not a defence against a caller that wants the
//! secret in there. The property that actually holds is upstream — the host
//! substitutes secrets on egress and so has no reason to send one into a guest
//! at all.

use std::sync::Arc;

use mvm_contract::stream::secret_fingerprint::{
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
    fn a_line_shorter_than_the_carry_clears_nothing_until_someone_flushes() {
        // Why this scanner cannot be the whole answer. A 40-byte bound secret
        // makes the carry 39, so a whole request line is swallowed: the
        // workload gets no line, cannot answer, and the operator has no reason
        // to send the write that would release it. Nothing here can fix that,
        // because nothing here has a clock — `flush` is the seam, and the gate
        // above decides when the writer has been quiet long enough to use it.
        let mut s = scanner(&["AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI0K7MDE"]);
        let line = b"{\"q\":\"hi\"}\n";
        let cleared = s.admit(line).expect("a JSON line is not a secret");
        assert_eq!(
            cleared, b"",
            "an 11-byte line sits entirely inside the 39-byte carry"
        );
        assert_eq!(s.withheld_len(), line.len());
        assert_eq!(s.flush(), line, "and a flush is what hands it over");
    }

    #[test]
    fn what_is_withheld_is_a_length_and_never_a_verdict_about_the_bytes() {
        // The reason the carry is blanket rather than precise. If how much the
        // scanner held back depended on whether the tail could still become a
        // secret, the amount would be an oracle: feed a byte, see whether
        // anything came out, and walk the credential out a byte at a time. So
        // a live prefix of a bound secret and a payload that is nobody's must
        // be indistinguishable from outside.
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let live_prefix = &secret.as_bytes()[..12];
        let innocent = b"hello world!";
        assert_eq!(live_prefix.len(), innocent.len());

        let observe = |payload: &[u8]| {
            let mut s = scanner(&[secret]);
            let cleared = s.admit(payload).expect("neither completes the secret");
            (cleared, s.withheld_len(), s.flush())
        };
        assert_eq!(
            observe(live_prefix),
            (Vec::new(), 12, live_prefix.to_vec()),
            "the live prefix is treated as bytes of some length and nothing more"
        );
        assert_eq!(observe(innocent), (Vec::new(), 12, innocent.to_vec()));
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
