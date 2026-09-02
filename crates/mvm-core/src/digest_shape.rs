//! The one `sha256:<64 lowercase hex>` shape check shared by every
//! prefixed content-address newtype in this crate (checkpoint digests,
//! workload addresses, OCI digests). The wrapper types stay distinct and
//! non-convertible — only this validation routine is shared, so a bug fixed
//! here is fixed for all three and none can silently drift.

/// The fixed prefix every `sha256:`-tagged content-address carries.
pub(crate) const SHA256_PREFIX: &str = "sha256:";

/// Outcome of validating a `sha256:<64 lowercase hex>` string. Neutral so each
/// newtype maps it onto its own distinct error type.
pub(crate) enum Sha256PrefixedShape {
    Ok,
    MissingPrefix,
    WrongLength { len: usize },
    NonHex { ch: char },
}

/// Validate `value` as `sha256:` followed by exactly 64 lowercase hex digits.
pub(crate) fn validate_sha256_prefixed(value: &str) -> Sha256PrefixedShape {
    let Some(hex) = value.strip_prefix(SHA256_PREFIX) else {
        return Sha256PrefixedShape::MissingPrefix;
    };
    if hex.len() != 64 {
        return Sha256PrefixedShape::WrongLength { len: hex.len() };
    }
    for ch in hex.chars() {
        if !matches!(ch, '0'..='9' | 'a'..='f') {
            return Sha256PrefixedShape::NonHex { ch };
        }
    }
    Sha256PrefixedShape::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_ok(value: &str) -> bool {
        matches!(validate_sha256_prefixed(value), Sha256PrefixedShape::Ok)
    }

    #[test]
    fn accepts_well_formed() {
        assert!(is_ok(&format!("sha256:{}", "a".repeat(64))));
    }

    #[test]
    fn rejects_missing_prefix_wrong_length_and_non_hex() {
        assert!(matches!(
            validate_sha256_prefixed(&format!("md5:{}", "a".repeat(64))),
            Sha256PrefixedShape::MissingPrefix
        ));
        assert!(matches!(
            validate_sha256_prefixed(&format!("sha256:{}", "a".repeat(63))),
            Sha256PrefixedShape::WrongLength { len: 63 }
        ));
        assert!(matches!(
            validate_sha256_prefixed(&format!("sha256:{}", "A".repeat(64))),
            Sha256PrefixedShape::NonHex { ch: 'A' }
        ));
        assert!(matches!(
            validate_sha256_prefixed(&format!("sha256:{}", "g".repeat(64))),
            Sha256PrefixedShape::NonHex { ch: 'g' }
        ));
    }
}
