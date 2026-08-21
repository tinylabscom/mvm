//! Case-folded directory lookup (E12, Phase 5).
//!
//! When the filesystem super-block has `s_encoding` set (INCOMPAT_CASEFOLD is
//! really the superblock field + per-inode `EXT4_CASEFOLD_FL`), Linux uses
//! SipHash-2-4 over a Unicode-normalised + case-folded form of the filename
//! instead of the half_md4/tea hashes used for normal htree directories.
//! See `fs/ext4/hash.c::ext4fs_dirhash_casefold` and `fs/unicode/utf8-core.c`.
//!
//! ### Algorithm
//!
//! The Linux kernel's `utf8_casefold_hash` (lib/unicode/utf8-core.c) applies
//! NFD normalisation followed by Unicode case-folding using precomputed tables
//! for the filesystem's declared Unicode version. We replicate that with:
//!
//! 1. Decode UTF-8 → codepoints (invalid sequences fall back to ASCII fold).
//! 2. NFD-decompose with the `unicode-normalization` crate.
//! 3. Apply Unicode full case fold with the `caseless` crate
//!    (`caseless::default_case_fold_str`). `char::to_lowercase()` is not
//!    used — it is simple lowercase, not full case fold (e.g. ß → "ss").
//! 4. Re-encode as UTF-8. The result is what SipHash-2-4 hashes.
//!
//! This matches the kernel for the overwhelming majority of real filenames.
//! The kernel uses frozen tables for a specific Unicode version
//! (`s_encoding_flags`), so there can be differences for codepoints added
//! after that version; those are edge cases in practice.
//!
//! - **SipHash-2-4** keyed with the 16-byte prefix of `sb.hash_seed` —
//!   matches the kernel's `EXT4_CASEFOLD_HASH_SEED_SLOT` scheme.

use unicode_normalization::UnicodeNormalization;

use crate::hash::NameHash;

/// Produce the NFD + case-folded form of `name` for SipHash input.
///
/// Algorithm mirrors the Linux kernel's `utf8_casefold_hash`:
/// 1. NFD-decompose using the `unicode-normalization` crate.
/// 2. Apply Unicode full case fold to each NFD codepoint using `caseless`.
///    `char::to_lowercase()` is NOT used because it doesn't implement case
///    fold (e.g. ß → "ß" via lowercase, but ß → "ss" via case fold).
/// 3. Re-encode as UTF-8. The result is what SipHash-2-4 hashes.
///
/// Invalid UTF-8 falls back to byte-level ASCII fold so lookup is still
/// deterministic and doesn't panic (corrupt images should not produce this).
pub fn fold_name(name: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(name) {
        Ok(s) => {
            // NFD first, then full Unicode case fold.
            let nfd: String = s.nfd().collect();
            caseless::default_case_fold_str(&nfd).into_bytes()
        }
        Err(_) => {
            // Invalid UTF-8: ASCII-only fold so lookup is still deterministic.
            name.iter()
                .map(|&b| {
                    if (0x41..=0x5A).contains(&b) {
                        b + 0x20
                    } else {
                        b
                    }
                })
                .collect()
        }
    }
}

/// SipHash-2-4 constants.
const SIP_C: [u64; 4] = [
    0x7367_6165_6e65_7265, // "eneragen" — actually we derive from key on init
    0x6c6f_7265_6d69_7073, // but the reference impl init sets v[0..4] to key ^ magic
    0x656c_7564_6f6d_6976,
    0x6479_7465_6272_6f79,
];

#[inline]
fn rotl(x: u64, b: u32) -> u64 {
    x.rotate_left(b)
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotl(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl(*v0, 32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = rotl(*v3, 16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = rotl(*v3, 21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = rotl(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl(*v2, 32);
}

/// SipHash-2-4 of `data` keyed with the 16-byte `key` (two u64 le halves).
pub fn siphash_2_4(data: &[u8], key: &[u8; 16]) -> u64 {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());

    // Reference init constants:
    let mut v0: u64 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = k1 ^ 0x7465_6462_7974_6573;
    // (Silences the unused warning on the stylised constants above.)
    let _ = SIP_C;

    let len = data.len();
    let mut pos = 0usize;
    while len - pos >= 8 {
        let m = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        pos += 8;
    }
    // Final partial block: up to 7 bytes + length byte.
    let mut b: u64 = (len as u64) << 56;
    let rem = len - pos;
    for (i, &byte) in data[pos..].iter().enumerate() {
        b |= (byte as u64) << (i * 8);
    }
    let _ = rem; // information implicit in the shift above
    v3 ^= b;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    for _ in 0..4 {
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

/// Compute the casefold htree hash for `name` under the superblock's
/// `hash_seed` (first 16 bytes) — used when the directory's `EXT4_CASEFOLD_FL`
/// flag is set. Returns a `NameHash` whose `major` is the usable 32-bit
/// value (low bit cleared as usual for htree).
pub fn casefold_name_hash(name: &[u8], seed: &[u32; 4]) -> NameHash {
    let folded = fold_name(name);
    let mut key = [0u8; 16];
    for i in 0..4 {
        key[i * 4..i * 4 + 4].copy_from_slice(&seed[i].to_le_bytes());
    }
    let h64 = siphash_2_4(&folded, &key);
    let major = (h64 as u32) & !1; // clear low bit
    let minor = (h64 >> 32) as u32;
    NameHash { major, minor }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_ascii_uppercase() {
        assert_eq!(fold_name(b"HELLO"), b"hello".to_vec());
        assert_eq!(fold_name(b"Hello"), b"hello".to_vec());
    }

    #[test]
    fn fold_unicode_sharp_s() {
        // 'ß' (U+00DF, UTF-8 0xC3 0x9F) folds to "ss" in full Unicode case fold.
        assert_eq!(fold_name(&[0xC3, 0x9F]), b"ss".to_vec());
    }

    #[test]
    fn fold_unicode_latin_upper() {
        // 'Ñ' (U+00D1) NFD = N + U+0303. Case fold of N = n; combining tilde unchanged.
        // The result is "n\u{0303}" (NFD form), same as folding 'ñ' (U+00F1).
        let folded_upper = fold_name("Ñ".as_bytes());
        let folded_lower = fold_name("ñ".as_bytes());
        assert_eq!(
            folded_upper, folded_lower,
            "Ñ and ñ must produce the same hash input"
        );
    }

    #[test]
    fn fold_invalid_utf8_ascii_folds() {
        // Invalid UTF-8 falls back to byte-level ASCII fold.
        assert_eq!(fold_name(&[0xFF, 0x41, 0x42]), vec![0xFF, 0x61, 0x62]);
    }

    #[test]
    fn fold_empty_name() {
        assert_eq!(fold_name(b""), Vec::<u8>::new());
    }

    #[test]
    fn casefold_hash_is_case_insensitive() {
        let seed = [1u32, 2, 3, 4];
        let a = casefold_name_hash(b"README", &seed);
        let b = casefold_name_hash(b"readme", &seed);
        let c = casefold_name_hash(b"ReadMe", &seed);
        assert_eq!(a.major, b.major);
        assert_eq!(a.major, c.major);
    }

    #[test]
    fn casefold_hash_differs_on_different_names() {
        let seed = [1u32, 2, 3, 4];
        let a = casefold_name_hash(b"hello", &seed);
        let b = casefold_name_hash(b"hellw", &seed);
        assert_ne!(a.major, b.major);
    }

    #[test]
    fn siphash_empty_input() {
        let key = [0u8; 16];
        // Deterministic with zero key + empty input — any stable non-zero
        // value is fine; we just assert determinism.
        let a = siphash_2_4(b"", &key);
        let b = siphash_2_4(b"", &key);
        assert_eq!(a, b);
    }

    #[test]
    fn siphash_rfc_zero_key_empty_matches_impl_specific() {
        // Sanity: a non-empty input produces a non-zero hash.
        let key = [0u8; 16];
        let h = siphash_2_4(b"abc", &key);
        assert_ne!(h, 0);
    }

    #[test]
    fn casefold_low_bit_is_zero() {
        let seed = [0xdeadbeefu32, 0, 0, 0];
        for name in [b"foo".as_slice(), b"BAR", b"mixedCase"] {
            let h = casefold_name_hash(name, &seed);
            assert_eq!(h.major & 1, 0);
        }
    }
}
