use serde::{Deserialize, Serialize};

/// A signed payload: the raw bytes of the canonical JSON, the Ed25519
/// signature, and an identifier for which key produced the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPayload {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_payload_serialization() {
        let sp = SignedPayload {
            payload: b"test data".to_vec(),
            signature: vec![0u8; 64],
            signer_id: "test-signer".to_string(),
        };
        let json = serde_json::to_string(&sp).unwrap();
        let parsed: SignedPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.payload, b"test data");
        assert_eq!(parsed.signature.len(), 64);
        assert_eq!(parsed.signer_id, "test-signer");
    }
}
