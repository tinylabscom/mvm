//! Small hashing helpers shared by contract digests and their consumers.

/// sha256 of `bytes` as lowercase hex, the spelling the wire digests use.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble is hex"));
        encoded.push(char::from_digit(u32::from(byte & 0xf), 16).expect("nibble is hex"));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn sha256_hex_matches_the_standard_encoding() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
