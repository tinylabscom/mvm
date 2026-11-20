//! Mailbox destination records the workload ledger orders against containment.
//!
//! A destination enrolls once with the key it will sign prepared heads under.
//! Each journal commit then asks the ledger's owner to move the destination's
//! tip, so a quarantine or replacement and a destination commit have one order.

use anyhow::{Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::ExecutionEpoch;

/// Most destinations the ledger records.
pub const MAX_DESTINATIONS: usize = 4_096;
const PREPARED_HEAD_DOMAIN: &[u8] = b"mvm.mailbox.prepared-head.v1\0";

/// Is `value` exactly 64 lowercase hex characters?
#[must_use]
pub fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The journal position a destination has committed: its cursor and chain head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationTip {
    pub cursor: u64,
    pub head: String,
}

impl DestinationTip {
    /// # Errors
    ///
    /// The head is not 64 lowercase hex characters.
    pub fn validate(&self) -> Result<()> {
        ensure!(is_hex64(&self.head), "destination tip head is malformed");
        Ok(())
    }
}

/// One enrolled destination in the canonical ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationEntry {
    pub workload: String,
    pub epoch: ExecutionEpoch,
    /// Hex Ed25519 verifying key that signs this destination's prepared heads.
    pub key: String,
    pub tip: DestinationTip,
    /// The ledger sequence at which this entry was inserted or its tip last moved.
    pub changed: u64,
}

/// A destination's request to be recorded under a workload epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationEnrollment {
    pub destination: String,
    pub workload: String,
    pub epoch: ExecutionEpoch,
    pub key: String,
    pub tip: DestinationTip,
}

/// What a destination asks the ledger's owner to commit: one step of its tip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedHead {
    pub destination: String,
    pub workload: String,
    pub epoch: ExecutionEpoch,
    pub expected: DestinationTip,
    pub next: DestinationTip,
}

/// A [`PreparedHead`] and the destination key's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPreparedHead {
    pub head: PreparedHead,
    /// Hex Ed25519 signature.
    pub signature: String,
}

/// A destination's answer: the tip it is at, and the ledger sequence at which
/// the destination last changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationCommit {
    /// The sequence at which the destination last changed, not the ledger's current one.
    pub sequence: u64,
    pub tip: DestinationTip,
}

impl PreparedHead {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = PREPARED_HEAD_DOMAIN.to_vec();
        bytes.extend(serde_jcs::to_vec(self)?);
        Ok(bytes)
    }

    /// # Errors
    ///
    /// The head cannot be encoded.
    pub fn sign(self, key: &SigningKey) -> Result<SignedPreparedHead> {
        let signature = hex::encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(SignedPreparedHead {
            head: self,
            signature,
        })
    }
}

impl SignedPreparedHead {
    /// # Errors
    ///
    /// The signature is malformed or does not verify under `key`.
    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        let bytes: [u8; 64] = hex::decode(&self.signature)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("prepared head signature has the wrong length"))?;
        key.verify(&self.head.signing_bytes()?, &Signature::from_bytes(&bytes))
            .map_err(|_| anyhow::anyhow!("prepared head signature does not verify"))
    }
}

/// Parse a hex Ed25519 verifying key.
///
/// # Errors
///
/// The text is not 64 lowercase hex characters or is not a valid key.
pub fn parse_key(key: &str) -> Result<VerifyingKey> {
    ensure!(is_hex64(key), "destination key is malformed");
    let bytes: [u8; 32] = hex::decode(key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("destination key has the wrong length"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| anyhow::anyhow!("destination key is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip(cursor: u64) -> DestinationTip {
        DestinationTip {
            cursor,
            head: format!("{cursor:064x}"),
        }
    }

    fn head() -> PreparedHead {
        PreparedHead {
            destination: "d".repeat(64),
            workload: "w".into(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            expected: tip(1),
            next: tip(2),
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn the_wire_types_round_trip_and_refuse_unknown_fields() {
        let signed = head().sign(&key(1)).unwrap();
        let bytes = serde_json::to_vec(&signed).unwrap();
        assert_eq!(
            serde_json::from_slice::<SignedPreparedHead>(&bytes).unwrap(),
            signed
        );
        let enrollment = DestinationEnrollment {
            destination: "d".repeat(64),
            workload: "w".into(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            key: "a".repeat(64),
            tip: tip(0),
        };
        let bytes = serde_json::to_vec(&enrollment).unwrap();
        assert_eq!(
            serde_json::from_slice::<DestinationEnrollment>(&bytes).unwrap(),
            enrollment
        );
        let commit = DestinationCommit {
            sequence: 3,
            tip: tip(2),
        };
        let bytes = serde_json::to_vec(&commit).unwrap();
        assert_eq!(
            serde_json::from_slice::<DestinationCommit>(&bytes).unwrap(),
            commit
        );
        let entry = DestinationEntry {
            workload: "w".into(),
            epoch: ExecutionEpoch::new(1).unwrap(),
            key: "a".repeat(64),
            tip: tip(0),
            changed: 4,
        };
        let bytes = serde_json::to_vec(&entry).unwrap();
        assert_eq!(
            serde_json::from_slice::<DestinationEntry>(&bytes).unwrap(),
            entry
        );
        assert!(
            serde_json::from_str::<DestinationTip>(r#"{"cursor":1,"head":"x","extra":1}"#).is_err()
        );
    }

    #[test]
    fn a_signed_head_verifies_only_under_its_key_and_unchanged() {
        let signing = key(1);
        let signed = head().sign(&signing).unwrap();
        signed.verify(&signing.verifying_key()).unwrap();
        assert!(signed.verify(&key(2).verifying_key()).is_err());
        let mut tampered = signed.clone();
        tampered.head.next = tip(3);
        assert!(tampered.verify(&signing.verifying_key()).is_err());
        let mut tampered = signed.clone();
        tampered.head.epoch = ExecutionEpoch::new(2).unwrap();
        assert!(tampered.verify(&signing.verifying_key()).is_err());
        let mut malformed = signed;
        malformed.signature = "00".into();
        assert!(malformed.verify(&signing.verifying_key()).is_err());
    }

    #[test]
    fn shapes_are_checked() {
        assert!(is_hex64(&"a".repeat(64)));
        assert!(!is_hex64(&"A".repeat(64)) && !is_hex64("ab"));
        assert!(
            DestinationTip {
                cursor: 0,
                head: "x".into()
            }
            .validate()
            .is_err()
        );
        assert!(parse_key(&hex::encode(key(1).verifying_key().to_bytes())).is_ok());
        assert!(parse_key("zz").is_err());
    }
}
