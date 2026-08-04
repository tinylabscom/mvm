//! A recognisable *shape* of a secret, computed where its plaintext already
//! lives — so the process that scans for it never has to hold it.
//!
//! The input gate refuses host→guest bytes that carry one of the host's own
//! secrets. Recognising a byte sequence normally means having it, and that is
//! the problem: the gate runs in the CLI process, while the substitution
//! endpoint that resolves raw credentials runs as a separate process on
//! purpose. Copying plaintext into the CLI to populate a scan would create a
//! new plaintext location in a process that has none, in order to close a gap
//! on a different property. It is the wrong trade.
//!
//! So the endpoint — which already holds the value — computes a
//! [`SecretFingerprint`] and only the fingerprint travels. A fingerprint is a
//! length plus a 64-bit polynomial hash, chosen because that hash *rolls*: a
//! scanner can slide a window over a stream and test every offset at one
//! multiply-add per byte, which is what makes finding a secret split across
//! two writes affordable without the bytes.
//!
//! ## What a fingerprint is not
//!
//! It is not proof. Two different byte sequences of the same length can hash
//! alike, so a match means "these bytes hash like a known secret", not "these
//! bytes are that secret". The gate refuses on a match anyway, because failing
//! closed on a collision is the right direction — but nothing downstream, the
//! refusal message least of all, may state the stronger fact.
//!
//! ## What it discloses
//!
//! Whoever holds a fingerprint learns the secret's **length**, and holds a
//! 64-bit hash of it. For a high-entropy credential that is not a recovery
//! path; for a short low-entropy one, a hash and a length are guessable
//! offline. That is a real if narrow disclosure and it is recorded in
//! `specs/adrs/035-workload-stream-plane.md` rather than only here, because a
//! reader deciding whether to bind a secret looks there.
//!
//! Deliberately absent: any fingerprint of a *prefix* of a secret. Prefix
//! hashes would let a scanner withhold only the tails that could still become
//! a secret — the behaviour that plaintext gives — but they also turn the
//! fingerprint set into a byte-at-a-time recovery oracle: guess byte 0 against
//! the length-1 prefix hash, then byte 1, and so on. The latency the scanner
//! pays for withholding a fixed-size tail is the price of not shipping that
//! oracle.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Category recorded for a secret value the host itself holds for a workload.
pub const CATEGORY_HOST_SECRET: &str = "host-secret";

/// Which kind of secret a fingerprint stands for.
///
/// An enum rather than a string because the category is the *only* thing a
/// match may put in the audit chain, and a closed vocabulary is what keeps a
/// runtime-derived label — anything shaped like the matched value — from
/// becoming representable there at all.
// allow(secret-debug): a category is a fixed vocabulary word, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretCategory {
    /// A credential the host holds on the workload's behalf.
    HostSecret,
}

impl SecretCategory {
    /// The wire-stable word this category is recorded under.
    ///
    /// `&'static str` so a matched value cannot be smuggled through the same
    /// channel: there is no way to produce one of these at runtime from bytes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostSecret => CATEGORY_HOST_SECRET,
        }
    }
}

/// Multiplier for the polynomial hash. The FNV-1a 64-bit prime: odd, so
/// multiplication stays invertible mod 2^64 and a low byte can never be
/// annihilated.
const BASE: u64 = 0x0000_0100_0000_01b3;

/// The hash of one whole window, computed directly.
///
/// The definition [`roll`] must agree with. Both exist because the scanner
/// uses the cheap incremental form on the hot path and this one to re-derive
/// a candidate before refusing, so an arithmetic slip in the incremental step
/// cannot on its own refuse a caller's frame.
#[must_use]
pub fn window_hash(window: &[u8]) -> u64 {
    window.iter().fold(0u64, |h, &b| {
        h.wrapping_mul(BASE).wrapping_add(u64::from(b))
    })
}

/// `BASE^(len - 1)`, the weight the oldest byte of a `len`-sized window
/// carries. Precomputed once per window size by a rolling scanner.
///
/// Zero-length windows have no oldest byte; the value is unused there and 0
/// is returned rather than wrapping the exponent around.
#[must_use]
pub fn leading_weight(len: usize) -> u64 {
    if len == 0 {
        return 0;
    }
    let mut weight = 1u64;
    for _ in 1..len {
        weight = weight.wrapping_mul(BASE);
    }
    weight
}

/// Advance a window hash by one byte: drop `leaving`, append `entering`.
///
/// `weight` is [`leading_weight`] for the window's size. Equivalent to
/// [`window_hash`] over the shifted window, which
/// [`SecretFingerprint::matches_window`] relies on.
#[must_use]
pub fn roll(hash: u64, leaving: u8, entering: u8, weight: u64) -> u64 {
    hash.wrapping_sub(u64::from(leaving).wrapping_mul(weight))
        .wrapping_mul(BASE)
        .wrapping_add(u64::from(entering))
}

/// One secret's recognisable shape: how long it is and how it hashes.
///
/// Carries no part of the value and has no accessor that could return one —
/// the fields are a length, a hash, and a vocabulary word. That is the whole
/// point of the type: it is what may cross into a process that must not hold
/// the secret.
// allow(secret-debug): holds a length and a hash, never a value; a redacted
// Debug would hide the only fields worth logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretFingerprint {
    /// Length of the secret in bytes.
    len: u32,
    /// [`window_hash`] over the whole secret.
    hash: u64,
    /// What kind of secret this is.
    category: SecretCategory,
}

impl SecretFingerprint {
    /// Fingerprint `value`, which the caller must legitimately hold.
    ///
    /// `None` for an empty value — a zero-length window matches at every
    /// offset, so it would refuse every frame while standing for nothing — and
    /// for one longer than `u32::MAX`, which no credential is and which the
    /// wire form cannot carry.
    #[must_use]
    pub fn of(value: &[u8], category: SecretCategory) -> Option<Self> {
        if value.is_empty() {
            return None;
        }
        Some(Self {
            len: u32::try_from(value.len()).ok()?,
            hash: window_hash(value),
            category,
        })
    }

    /// How long the fingerprinted secret is. The scanner needs it to size its
    /// window; it is also the disclosure this type makes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Never true: [`of`](Self::of) refuses an empty value. Present because
    /// clippy pairs it with [`len`](Self::len), and honest because the
    /// constructor is the reason rather than a check here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// What a match is recorded as.
    #[must_use]
    pub fn category(&self) -> SecretCategory {
        self.category
    }

    /// The hash a rolling scanner compares against.
    #[must_use]
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// Whether `window` hashes like this secret.
    ///
    /// **A hash match, not an identity.** Same length and same hash is the
    /// most this can ever say; a collision looks exactly like the real thing
    /// from here, and the caller must phrase its refusal accordingly.
    #[must_use]
    pub fn matches_window(&self, window: &[u8]) -> bool {
        window.len() == self.len() && window_hash(window) == self.hash
    }
}

/// The distinct window sizes a fingerprint set requires, longest first.
///
/// Longest first so a scanner that reports the first match reports the most
/// specific one; deduplicated so two secrets of equal length cost one pass.
#[must_use]
pub fn window_sizes(fingerprints: &[SecretFingerprint]) -> Vec<usize> {
    let mut sizes: Vec<usize> = fingerprints.iter().map(SecretFingerprint::len).collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    sizes.dedup();
    sizes
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn an_empty_value_has_no_fingerprint() {
        // A zero-length window matches at every offset, so admitting one
        // would refuse every frame on behalf of nothing.
        assert!(SecretFingerprint::of(b"", SecretCategory::HostSecret).is_none());
    }

    #[test]
    fn a_fingerprint_matches_only_its_own_length_and_hash() {
        let fp = SecretFingerprint::of(b"AKIAIOSFODNN7EXAMPLE", SecretCategory::HostSecret)
            .expect("a non-empty value fingerprints");
        assert!(fp.matches_window(b"AKIAIOSFODNN7EXAMPLE"));
        assert!(!fp.matches_window(b"AKIAIOSFODNN7EXAMPLF"));
        // The length is not decoration. A polynomial hash weights each byte by
        // its distance from the end, so a leading zero byte contributes
        // nothing: this longer window hashes *identically* and is caught only
        // because the lengths differ.
        let padded = [b"\0".as_slice(), b"AKIAIOSFODNN7EXAMPLE"].concat();
        assert_eq!(window_hash(&padded), fp.hash(), "the collision is real");
        assert!(
            !fp.matches_window(&padded),
            "a longer window is a different window, whatever it hashes to"
        );
        assert_eq!(fp.len(), 20);
        assert!(!fp.is_empty());
        assert_eq!(fp.category().as_str(), CATEGORY_HOST_SECRET);
    }

    #[test]
    fn rolling_agrees_with_hashing_the_window_directly() {
        // The scanner trusts these two to be the same function. If they drift,
        // it either misses secrets or refuses innocent frames, and neither
        // failure announces itself.
        let data = b"the quick brown fox jumps over the lazy dog";
        for len in 1..=8usize {
            let weight = leading_weight(len);
            let mut rolled = window_hash(&data[..len]);
            for start in 1..=data.len() - len {
                rolled = roll(rolled, data[start - 1], data[start + len - 1], weight);
                assert_eq!(
                    rolled,
                    window_hash(&data[start..start + len]),
                    "len {len} at offset {start}"
                );
            }
        }
    }

    #[test]
    fn window_sizes_are_deduplicated_longest_first() {
        let fps = vec![
            SecretFingerprint::of(b"abcd", SecretCategory::HostSecret).expect("fingerprints"),
            SecretFingerprint::of(b"wxyz", SecretCategory::HostSecret).expect("fingerprints"),
            SecretFingerprint::of(b"abcdefgh", SecretCategory::HostSecret).expect("fingerprints"),
        ];
        assert_eq!(window_sizes(&fps), vec![8, 4]);
    }

    #[test]
    fn the_wire_form_carries_no_value() {
        // The whole reason this type exists: what crosses a process boundary
        // is a length, a hash and a vocabulary word.
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let fp = SecretFingerprint::of(secret.as_bytes(), SecretCategory::HostSecret)
            .expect("fingerprints");
        let json = serde_json::to_string(&fp).expect("serializes");
        assert!(!json.contains(secret), "got {json}");
        assert!(!json.contains("AKIA"), "nor any part of it: {json}");
        assert_eq!(
            serde_json::from_str::<SecretFingerprint>(&json).expect("round-trips"),
            fp
        );
        assert!(json.contains("host-secret"));
    }

    #[test]
    fn the_wire_form_rejects_unknown_fields() {
        let err = serde_json::from_str::<SecretFingerprint>(
            r#"{"len":4,"hash":1,"category":"host-secret","value":"oops"}"#,
        )
        .expect_err("an unexpected field fails closed");
        assert!(err.to_string().contains("unknown field"), "got {err}");
    }

    #[test]
    fn debug_renders_shape_only() {
        let rendered = alloc::format!(
            "{:?}",
            SecretFingerprint::of(b"AKIAIOSFODNN7EXAMPLE", SecretCategory::HostSecret)
                .expect("fingerprints")
        );
        assert!(!rendered.contains("AKIA"), "got {rendered}");
        assert!(rendered.contains("len: 20"), "got {rendered}");
    }
}
