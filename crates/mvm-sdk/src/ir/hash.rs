use crate::ir::canonicalize::canonicalize;
use sha2::{Digest, Sha256};

/// SHA-256 of the RFC 8785 canonical form of `value`, returned as a lowercase hex string.
///
/// Used to fingerprint a Workload IR document for inclusion in launch plans and
/// audit records. Two semantically equivalent IR documents produce the same hash.
pub fn ir_hash<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let canonical = canonicalize(value)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(hex(&digest))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stable_hash_for_identical_value() {
        let v = json!({ "a": 1, "b": [2, 3] });
        let h1 = ir_hash(&v).unwrap();
        let h2 = ir_hash(&v).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn key_order_does_not_change_hash() {
        let a = json!({ "x": 1, "y": 2 });
        let b = json!({ "y": 2, "x": 1 });
        assert_eq!(ir_hash(&a).unwrap(), ir_hash(&b).unwrap());
    }

    #[test]
    fn different_values_have_different_hashes() {
        assert_ne!(ir_hash(&json!(1)).unwrap(), ir_hash(&json!(2)).unwrap());
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let h = ir_hash(&json!({"a": 1})).unwrap();
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }
}
