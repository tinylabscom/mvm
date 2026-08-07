//! `did:key` derivation and parsing for Ed25519 public keys.
//!
//! This module implements the W3C `did:key` method for Ed25519 keys, used by
//! [`crate::receipt::ExecutionReceipt`] and [`crate::conformance_badge::ConformanceBadge`]
//! as the portable signer identity format.
//!
//! An Ed25519 `did:key` value is:
//!
//! ```text
//! did:key:z<base58btc(0xed01 || pubkey32)>
//! ```
//!
//! where `0xed01` is the multicodec prefix for Ed25519 public keys and `z` is
//! the multibase base58btc prefix.

use ed25519_dalek::VerifyingKey;

/// A parsed Ed25519 `did:key` identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKey {
    verifying_key: VerifyingKey,
}

impl DidKey {
    /// The multibase base58btc prefix character.
    pub const MULTIBASE_PREFIX: char = 'z';
    /// The multicodec prefix for an Ed25519 public key: `0xed01`.
    pub const MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    /// The string prefix every `did:key` carries.
    pub const DID_KEY_PREFIX: &'static str = "did:key:";

    /// Derive a `did:key` from an Ed25519 verifying key.
    pub fn from_verifying_key(key: VerifyingKey) -> Self {
        Self { verifying_key: key }
    }

    /// Parse a `did:key` string into a verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a well-formed Ed25519 `did:key`,
    /// including wrong prefix, unknown multicodec, bad base58 encoding, or
    /// wrong public-key length.
    pub fn parse(did: impl AsRef<str>) -> Result<Self, DidKeyError> {
        let did = did.as_ref();
        let rest = did
            .strip_prefix(Self::DID_KEY_PREFIX)
            .ok_or(DidKeyError::MissingPrefix)?;
        if rest.is_empty() {
            return Err(DidKeyError::EmptyKey);
        }
        let mut chars = rest.chars();
        let multibase = chars.next().ok_or(DidKeyError::EmptyKey)?;
        if multibase != Self::MULTIBASE_PREFIX {
            return Err(DidKeyError::UnsupportedMultibase(multibase));
        }
        let encoded = chars.as_str();
        let decoded = bs58::decode(encoded)
            .into_vec()
            .map_err(DidKeyError::Base58)?;
        if decoded.len() != Self::MULTICODEC_PREFIX.len() + 32 {
            return Err(DidKeyError::WrongLength(decoded.len()));
        }
        if decoded[..Self::MULTICODEC_PREFIX.len()] != Self::MULTICODEC_PREFIX {
            return Err(DidKeyError::UnsupportedMulticodec(
                decoded[..Self::MULTICODEC_PREFIX.len()].to_vec(),
            ));
        }
        let key_bytes: [u8; 32] = decoded[Self::MULTICODEC_PREFIX.len()..]
            .try_into()
            .map_err(|_| DidKeyError::WrongLength(decoded.len()))?;
        let verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(DidKeyError::InvalidPublicKey)?;
        Ok(Self { verifying_key })
    }

    /// The underlying Ed25519 verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Serialize this identifier as a `did:key` string.
    pub fn to_did_key(&self) -> String {
        let mut bytes = Vec::with_capacity(Self::MULTICODEC_PREFIX.len() + 32);
        bytes.extend_from_slice(&Self::MULTICODEC_PREFIX);
        bytes.extend_from_slice(self.verifying_key.as_bytes());
        format!(
            "{}{}{}",
            Self::DID_KEY_PREFIX,
            Self::MULTIBASE_PREFIX,
            bs58::encode(bytes).into_string()
        )
    }
}

impl core::fmt::Display for DidKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_did_key())
    }
}

/// [`DidKey::parse`] failure.
#[derive(Debug, thiserror::Error)]
pub enum DidKeyError {
    /// The value did not start with `did:key:`.
    #[error("did:key must start with \"did:key:\"")]
    MissingPrefix,
    /// The key material was empty.
    #[error("did:key has no key material")]
    EmptyKey,
    /// The multibase prefix was not `z` (base58btc).
    #[error("did:key uses unsupported multibase prefix {0:?}")]
    UnsupportedMultibase(char),
    /// The base58 decoding failed.
    #[error("did:key base58 decode failed: {0}")]
    Base58(bs58::decode::Error),
    /// The decoded byte length was wrong.
    #[error("did:key decoded length {0} is not 34 bytes (multicodec + 32-byte pubkey)")]
    WrongLength(usize),
    /// The multicodec prefix was not Ed25519 (`0xed01`).
    #[error("did:key uses unsupported multicodec prefix {0:?}")]
    UnsupportedMulticodec(Vec<u8>),
    /// The public key bytes were not a valid Ed25519 point.
    #[error("did:key public key is invalid: {0}")]
    InvalidPublicKey(ed25519_dalek::SignatureError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn roundtrip() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let did = DidKey::from_verifying_key(signing_key.verifying_key());
        let did_string = did.to_did_key();
        assert!(did_string.starts_with("did:key:z"));
        let parsed = DidKey::parse(&did_string).expect("roundtrip parse");
        assert_eq!(
            parsed.verifying_key().as_bytes(),
            signing_key.verifying_key().as_bytes()
        );
        assert_eq!(parsed, did);
    }

    #[test]
    fn parse_known_vector() {
        // A well-known Ed25519 test key:
        // secret: 0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
        // public: 0xd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
        let vk = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap()).unwrap();
        let did = DidKey::from_verifying_key(vk);
        assert_eq!(
            did.to_did_key(),
            "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
        );
        let parsed = DidKey::parse(did.to_did_key()).unwrap();
        assert_eq!(parsed.verifying_key().as_bytes(), vk.as_bytes());
    }

    #[test]
    fn parse_missing_prefix() {
        assert!(matches!(
            DidKey::parse("z6MkhaXgZAgMVMFG8oYF1ADbc94YHQ6D98F4BAtRzGWsqd71"),
            Err(DidKeyError::MissingPrefix)
        ));
    }

    #[test]
    fn parse_bad_multibase() {
        assert!(matches!(
            DidKey::parse("did:key:b6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"),
            Err(DidKeyError::UnsupportedMultibase('b'))
        ));
    }

    #[test]
    fn parse_wrong_length() {
        // Valid prefix + base58 of 33 bytes instead of 34.
        let bytes: Vec<u8> = [0xed, 0x01]
            .iter()
            .copied()
            .chain([0u8; 31].iter().copied())
            .collect();
        let short = bs58::encode(bytes).into_string();
        assert!(
            matches!(
                DidKey::parse(format!("did:key:z{short}")),
                Err(DidKeyError::WrongLength(33))
            ),
            "expected WrongLength(33)"
        );
    }

    #[test]
    fn parse_wrong_multicodec() {
        // Valid length but multicodec prefix changed to 0xed02.
        let bytes: Vec<u8> = [0xed, 0x02]
            .iter()
            .copied()
            .chain([0u8; 32].iter().copied())
            .collect();
        let encoded = bs58::encode(bytes).into_string();
        assert!(
            matches!(
                DidKey::parse(format!("did:key:z{encoded}")),
                Err(DidKeyError::UnsupportedMulticodec(_))
            ),
            "expected UnsupportedMulticodec"
        );
    }
}
