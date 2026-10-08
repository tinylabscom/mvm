use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use crate::plan::types::Nonce;
use crate::plan::verb::VerbId;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assurance::Sha256Digest;

/// Verbs always permitted regardless of grant state or trust-policy configuration.
/// Referenced by both the verb-grant gate and the verb-trust gate so the two
/// allow-sets stay in sync from one definition.
pub const VERB_GRANT_BASELINE: [&str; 4] = [
    "protocol-hello",
    "ping",
    "readiness-status",
    "resource-usage",
];

/// Host-signer-signed, session- and time-bound capability granting a
/// workload a subset of agent control verbs. Signed by the admission
/// authority, verified by the guest — deliberately a different key from
/// the per-session frame-signing key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct VerbGrant {
    pub session_id: String,
    pub plan_nonce: Nonce,
    pub not_after: DateTime<Utc>,
    pub verbs: Vec<VerbId>,
    /// Drive authority copied from the admitted signed plan. It rides inside
    /// this host-signed envelope so the guest can enforce the same roots,
    /// program identity, byte bounds, and lifetime without trusting request
    /// fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<crate::grants::DriveGrant>,
    /// Presence requires arbitrary guest command RPCs to use the mediated
    /// path. The host signer derives this from the admitted plan's tool rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_mediation: Option<ToolMediationGrant>,
    /// Raw Ed25519 signature bytes (64) over signing_bytes(), serialized as
    /// base64. A `Vec<u8>` would otherwise render as a JSON array of 64 decimal
    /// numbers — roughly 230 characters against base64's 88 — and this grant
    /// rides the guest kernel cmdline, where the budget is finite and silently
    /// enforced. `sig` is excluded from `signing_bytes`, so how it is encoded
    /// cannot affect signature validity.
    #[serde(with = "sig_base64")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub sig: Vec<u8>,
}

/// How a tool-mediated guest preserves the prior verb-grant posture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ToolMediationGrant {
    /// A dev plan without an agent-verb list continues to use the profile
    /// class gate for non-command verbs. Command RPCs are still mediated.
    pub class_gate_only: bool,
    /// Digest of the exact tool-to-executable map sent at activation. The
    /// complete map cannot ride this grant's bounded kernel command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_map_digest: Option<Sha256Digest>,
}

impl ToolMediationGrant {
    /// Hash a deterministic map encoding after rejecting paths whose tool
    /// identity would be ambiguous at the guest command boundary.
    pub fn digest_commands(
        commands: &BTreeMap<String, String>,
    ) -> Result<Option<Sha256Digest>, &'static str> {
        let mut paths = BTreeSet::new();
        let valid = commands.iter().all(|(tool, path)| {
            !tool.is_empty()
                && tool.len() <= crate::protocol::network_flow::tool::MAX_TOOL_NAME_BYTES
                && !tool.contains('\0')
                && crate::policy::tool_rules::normalized_executable_path(path)
                && paths.insert(path)
        });
        if !valid {
            return Err("invalid or ambiguous tool executable map");
        }
        if commands.is_empty() {
            return Ok(None);
        }
        let encoded = serde_json::to_vec(commands).map_err(|_| "serialize tool executable map")?;
        let mut hasher = Sha256::new();
        hasher.update(b"mvm-tool-command-map-v1\0");
        hasher.update(encoded);
        Ok(Some(Sha256Digest::from_bytes(&hasher.finalize().into())))

    }
}

/// Serializes the raw signature bytes as a base64 string rather than a JSON
/// array of numbers.
mod sig_base64 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        B64.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        B64.decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    drive: Option<&'a crate::grants::DriveGrant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_mediation: Option<&'a ToolMediationGrant>,
}

impl VerbGrant {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = VerbGrantSigned {
            session_id: &self.session_id,
            plan_nonce: self.plan_nonce.as_hex(),
            not_after: self.not_after.to_rfc3339(),
            verbs: self.verbs.iter().map(VerbId::as_str).collect(),
            drive: self.drive.as_ref(),
            tool_mediation: self.tool_mediation.as_ref(),
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

    /// Baseline verbs (see `VERB_GRANT_BASELINE`) are always answerable regardless
    /// of the grant set. `protocol-hello` is the handshake itself and is pinned
    /// before any grant exists.
    pub fn permits(&self, verb: &str) -> bool {
        VERB_GRANT_BASELINE.contains(&verb)
            || (self.drive.is_some() && matches!(verb, "drive-open" | "drive-file"))
            || self.verbs.iter().any(|v| v.as_str() == verb)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
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
            drive: None,
            tool_mediation: None,
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
    fn tool_mediation_is_signed_and_round_trips() {
        let now = Utc::now();
        let (mut grant, signer) = signed(now, vec![]);
        grant.tool_mediation = Some(ToolMediationGrant {
            class_gate_only: true,
            command_map_digest: ToolMediationGrant::digest_commands(&BTreeMap::from([(
                "shell".into(),
                "/bin/sh".into(),
            )]))
            .expect("valid map"),

        });
        grant.sig = signer.sign(&grant.signing_bytes()).to_bytes().to_vec();
        let json = serde_json::to_string(&grant).expect("serialize mediated grant");
        let round: VerbGrant = serde_json::from_str(&json).expect("deserialize mediated grant");
        assert_eq!(round.tool_mediation, grant.tool_mediation);
        assert!(
            round
                .verify(&signer.verifying_key(), "sess-A", &nonce(), now)
                .is_ok()
        );

        let mut weakened = round.clone();
        weakened.tool_mediation = None;
        assert_eq!(
            weakened.verify(&signer.verifying_key(), "sess-A", &nonce(), now),
            Err(VerbGrantError::BadSignature)
        );
        let mut narrowed = round;
        narrowed
            .tool_mediation
            .as_mut()
            .expect("mediated grant")
            .class_gate_only = false;
        assert_eq!(
            narrowed.verify(&signer.verifying_key(), "sess-A", &nonce(), now),
            Err(VerbGrantError::BadSignature)
        );

        let mut redirected = grant;
        redirected
            .tool_mediation
            .as_mut()
            .expect("mediated grant")
            .command_map_digest = ToolMediationGrant::digest_commands(&BTreeMap::from([(
            "shell".into(),
            "/bin/bash".into(),
        )]))
        .expect("valid map");
        assert_eq!(
            redirected.verify(&signer.verifying_key(), "sess-A", &nonce(), now),
            Err(VerbGrantError::BadSignature)
        );
    }

    #[test]
    fn command_map_digest_is_deterministic_and_rejects_ambiguous_paths() {
        let commands = BTreeMap::from([("shell".into(), "/bin/sh".into())]);
        let digest = ToolMediationGrant::digest_commands(&commands).expect("valid map");
        assert!(digest.is_some());
        assert_eq!(
            digest,
            ToolMediationGrant::digest_commands(&commands).expect("same map")
        );
        assert_eq!(
            ToolMediationGrant::digest_commands(&BTreeMap::new()),
            Ok(None)
        );
        let duplicates = BTreeMap::from([
            ("shell".into(), "/bin/sh".into()),
            ("other".into(), "/bin/sh".into()),
        ]);
        assert!(ToolMediationGrant::digest_commands(&duplicates).is_err());
        let noncanonical = BTreeMap::from([("shell".into(), "/bin/../bin/sh".into())]);
        assert!(ToolMediationGrant::digest_commands(&noncanonical).is_err());
    }

    #[test]
    fn large_command_map_does_not_expand_kernel_cmdline_grant() {
        let commands: BTreeMap<_, _> = (0..100)
            .map(|index| {
                (
                    alloc::format!("tool-{index}"),
                    alloc::format!("/bin/tool-{index}"),
                )
            })
            .collect();
        let (mut grant, signer) = signed(Utc::now(), vec![]);
        grant.tool_mediation = Some(ToolMediationGrant {
            class_gate_only: true,
            command_map_digest: ToolMediationGrant::digest_commands(&commands).expect("valid map"),
        });
        grant.sig = signer.sign(&grant.signing_bytes()).to_bytes().to_vec();
        let encoded = serde_json::to_vec(&grant).expect("serialize grant");
        assert!(encoded.len() < 512, "grant grew to {} bytes", encoded.len());
    }

    #[test]
    fn legacy_grant_omits_tool_mediation() {
        let now = Utc::now();
        let (grant, signer) = signed(now, vec!["run-entrypoint"]);
        let json = serde_json::to_string(&grant).expect("serialize legacy grant");
        assert!(!json.contains("tool_mediation"));
        let round: VerbGrant = serde_json::from_str(&json).expect("deserialize legacy grant");
        assert!(round.tool_mediation.is_none());
        assert!(
            round
                .verify(&signer.verifying_key(), "sess-A", &nonce(), now)
                .is_ok()
        );
    }

    #[test]
    fn sig_serializes_as_base64_and_still_verifies_after_a_round_trip() {
        let now = Utc::now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);

        let json = serde_json::to_string(&g).expect("grant serializes");
        // A base64 string, not the JSON array of 64 numbers a bare Vec<u8> emits.
        let expected = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&g.sig)
        };
        assert!(
            json.contains(&alloc::format!("\"sig\":\"{expected}\"")),
            "sig is not base64-encoded: {json}"
        );

        let back: VerbGrant = serde_json::from_str(&json).expect("grant round-trips");
        assert_eq!(
            back.sig, g.sig,
            "signature bytes must survive the round trip"
        );
        assert!(
            back.verify(&k.verifying_key(), "sess-A", &nonce(), now)
                .is_ok(),
            "a round-tripped grant must still verify"
        );
    }

    #[test]
    fn sig_rejects_non_base64() {
        let now = Utc::now();
        let (g, _) = signed(now, vec!["ping"]);
        let json = serde_json::to_string(&g).expect("grant serializes");
        let broken = json.replace("\"sig\":\"", "\"sig\":\"!!!");
        assert!(
            serde_json::from_str::<VerbGrant>(&broken).is_err(),
            "malformed base64 must fail closed"
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
    fn verb_grant_baseline_contains_expected_verbs() {
        assert!(VERB_GRANT_BASELINE.contains(&"protocol-hello"));
        assert!(VERB_GRANT_BASELINE.contains(&"ping"));
        assert!(VERB_GRANT_BASELINE.contains(&"readiness-status"));
        assert!(VERB_GRANT_BASELINE.contains(&"resource-usage"));
        assert_eq!(VERB_GRANT_BASELINE.len(), 4);
    }

    #[test]
    fn permits_baseline_verbs_always() {
        let now = Utc::now();
        let (g, _) = signed(now, vec!["run-entrypoint"]);
        assert!(g.permits("protocol-hello"));
        assert!(g.permits("ping"));
        assert!(g.permits("readiness-status"));
        assert!(g.permits("resource-usage"));
        assert!(g.permits("run-entrypoint"));
        assert!(!g.permits("shutdown"));
    }
}
