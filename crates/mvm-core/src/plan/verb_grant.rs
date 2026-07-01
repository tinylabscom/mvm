use crate::plan::{Nonce, VerbId};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Host-signer-signed, session- and time-bound capability granting a
/// workload a subset of agent control verbs. Signed by the admission
/// authority, verified by the guest — deliberately a different key from
/// the per-session frame-signing key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerbGrant {
    pub session_id: String,
    pub plan_nonce: Nonce,
    pub not_after: DateTime<Utc>,
    pub verbs: Vec<VerbId>,
    /// Raw Ed25519 signature bytes (64) over signing_bytes(); serialized as a JSON array.
    pub sig: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerbGrantError {
    #[error("verb grant session id mismatch")]
    SessionMismatch,
    #[error("verb grant nonce mismatch")]
    NonceMismatch,
    #[error("verb grant expired")]
    Expired,
    #[error("verb grant signature invalid")]
    BadSignature,
}

/// Fixed-field-order, map-free struct: `serde_json::to_vec` is
/// byte-deterministic, so it needs no external canonicalizer.
#[derive(Serialize)]
struct VerbGrantSigned<'a> {
    session_id: &'a str,
    plan_nonce: &'a str,
    not_after: String,
    verbs: Vec<&'a str>,
}

impl VerbGrant {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = VerbGrantSigned {
            session_id: &self.session_id,
            plan_nonce: self.plan_nonce.as_hex(),
            not_after: self.not_after.to_rfc3339(),
            verbs: self.verbs.iter().map(VerbId::as_str).collect(),
        };
        serde_json::to_vec(&body).expect("VerbGrantSigned serializes")
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        session_id: &str,
        plan_nonce: &Nonce,
        now: DateTime<Utc>,
    ) -> Result<(), VerbGrantError> {
        if self.session_id != session_id {
            return Err(VerbGrantError::SessionMismatch);
        }
        if self.plan_nonce != *plan_nonce {
            return Err(VerbGrantError::NonceMismatch);
        }
        if now > self.not_after {
            return Err(VerbGrantError::Expired);
        }
        let sig = Signature::from_slice(&self.sig).map_err(|_| VerbGrantError::BadSignature)?;
        key.verify(&self.signing_bytes(), &sig)
            .map_err(|_| VerbGrantError::BadSignature)
    }

    /// Baseline verbs are always answerable regardless of the grant set,
    /// mirroring the broker's implicit `host.audit.v1`. `protocol-hello`
    /// is the handshake itself and is pinned before any grant exists.
    pub fn permits(&self, verb: &str) -> bool {
        const BASELINE: &[&str] = &["protocol-hello", "ping", "readiness-status"];
        BASELINE.contains(&verb) || self.verbs.iter().any(|v| v.as_str() == verb)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn nonce() -> Nonce {
        Nonce::from_bytes([1u8; 16])
    }

    fn signed(now: DateTime<Utc>, verbs: Vec<&str>) -> (VerbGrant, SigningKey) {
        let k = key();
        let mut g = VerbGrant {
            session_id: "sess-A".into(),
            plan_nonce: nonce(),
            not_after: now + Duration::minutes(10),
            verbs: verbs.into_iter().map(|v| VerbId::new(v).unwrap()).collect(),
            sig: vec![],
        };
        g.sig = k.sign(&g.signing_bytes()).to_bytes().to_vec();
        (g, k)
    }

    #[test]
    fn valid_grant_verifies() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        assert!(
            g.verify(&k.verifying_key(), "sess-A", &nonce(), now)
                .is_ok()
        );
    }

    #[test]
    fn forged_key_rejected() {
        let now = Utc::now();
        let (g, _) = signed(now, vec!["run-entrypoint"]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(matches!(
            g.verify(&attacker, "sess-A", &nonce(), now),
            Err(VerbGrantError::BadSignature)
        ));
    }

    #[test]
    fn wrong_session_rejected() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        assert!(matches!(
            g.verify(&k.verifying_key(), "sess-B", &nonce(), now),
            Err(VerbGrantError::SessionMismatch)
        ));
    }

    #[test]
    fn wrong_nonce_rejected() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        let other = Nonce::from_bytes([2u8; 16]);
        assert!(matches!(
            g.verify(&k.verifying_key(), "sess-A", &other, now),
            Err(VerbGrantError::NonceMismatch)
        ));
    }

    #[test]
    fn expired_rejected() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        let later = g.not_after + Duration::seconds(1);
        assert!(matches!(
            g.verify(&k.verifying_key(), "sess-A", &nonce(), later),
            Err(VerbGrantError::Expired)
        ));
    }

    #[test]
    fn signing_bytes_are_stable_and_exclude_sig() {
        let now = Utc::now();
        let (mut g, _) = signed(now, vec!["ping"]);
        let a = g.signing_bytes();
        g.sig = vec![0xAA; 64]; // mutate sig only
        assert_eq!(a, g.signing_bytes(), "signing_bytes must not depend on sig");
    }

    #[test]
    fn permits_baseline_verbs_always() {
        let now = Utc::now();
        let (g, _) = signed(now, vec!["run-entrypoint"]);
        assert!(g.permits("protocol-hello"));
        assert!(g.permits("ping"));
        assert!(g.permits("readiness-status"));
        assert!(g.permits("run-entrypoint"));
        assert!(!g.permits("shutdown"));
    }
}
