use alloc::string::String;
use alloc::vec::Vec;

use crate::plan::types::Nonce;
use crate::plan::verb::VerbId;
use crate::timestamp::UtcTimestamp;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Verbs always permitted regardless of grant state or trust-policy configuration.
/// Referenced by both the verb-grant gate and the verb-trust gate so the two
/// allow-sets stay in sync from one definition.
pub const VERB_GRANT_BASELINE: [&str; 4] = [
    "protocol-hello",
    "ping",
    "readiness-status",
    "resource-usage",
];

/// The console verbs an application-terminal grant lets through. The guest
/// still answers them only in the development profile, and opens a terminal
/// only for the granted argv.
pub const APPLICATION_TERMINAL_VERBS: [&str; 6] = [
    "console-open",
    "console-attach",
    "console-detach",
    "console-list",
    "console-close",
    "console-resize",
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
    pub not_after: UtcTimestamp,
    pub verbs: Vec<VerbId>,
    /// Drive authority copied from the admitted signed plan. It rides inside
    /// this host-signed envelope so the guest can enforce the same roots,
    /// program identity, byte bounds, and lifetime without trusting request
    /// fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<crate::grants::DriveGrant>,
    /// The admitted application terminal's argv digest. Its presence lets the
    /// console verbs through this grant, and the guest then opens a terminal
    /// only for exactly that argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_terminal: Option<crate::grants::ApplicationTerminalBinding>,
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

/// Serializes raw bytes as a base64 string rather than a JSON array of
/// numbers. Also used by the `host.cell.v1` payloads.
pub(crate) mod sig_base64 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        B64.encode(bytes).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
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
    application_terminal: Option<&'a crate::grants::ApplicationTerminalBinding>,
}

impl VerbGrant {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = VerbGrantSigned {
            session_id: &self.session_id,
            plan_nonce: self.plan_nonce.as_hex(),
            // chrono's `+00:00` form: changing it would invalidate every minted grant.
            not_after: self.not_after.to_rfc3339_offset(),
            verbs: self.verbs.iter().map(VerbId::as_str).collect(),
            drive: self.drive.as_ref(),
            application_terminal: self.application_terminal.as_ref(),
        };
        serde_json::to_vec(&body).expect("VerbGrantSigned serializes")
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        session_id: &str,
        plan_nonce: &Nonce,
        now: UtcTimestamp,
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
            .map_err(|_| VerbGrantError::BadSignature)?;
        Ok(())
    }

    /// Baseline verbs (see `VERB_GRANT_BASELINE`) are always answerable regardless
    /// of the grant set. `protocol-hello` is the handshake itself and is pinned
    /// before any grant exists.
    pub fn permits(&self, verb: &str) -> bool {
        VERB_GRANT_BASELINE.contains(&verb)
            || (self.drive.is_some() && matches!(verb, "drive-open" | "drive-file"))
            || (self.application_terminal.is_some() && APPLICATION_TERMINAL_VERBS.contains(&verb))
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
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn now() -> UtcTimestamp {
        UtcTimestamp::from_unix(1_700_000_000, 0).unwrap()
    }
    fn nonce() -> Nonce {
        Nonce::from_bytes([1u8; 16])
    }

    fn signed(now: UtcTimestamp, verbs: Vec<&str>) -> (VerbGrant, SigningKey) {
        let k = key();
        let mut g = VerbGrant {
            session_id: "sess-A".into(),
            plan_nonce: nonce(),
            not_after: now.checked_add_secs(600).unwrap(),
            verbs: verbs.into_iter().map(|v| VerbId::new(v).unwrap()).collect(),
            drive: None,
            application_terminal: None,
            sig: vec![],
        };
        g.sig = k.sign(&g.signing_bytes()).to_bytes().to_vec();
        (g, k)
    }

    fn pinned(secs: i64, nanos: u32) -> VerbGrant {
        VerbGrant {
            session_id: "s".into(),
            plan_nonce: nonce(),
            not_after: UtcTimestamp::from_unix(secs, nanos).unwrap(),
            verbs: vec![VerbId::new("run-entrypoint").unwrap()],
            drive: None,
            application_terminal: None,
            sig: vec![],
        }
    }

    /// The signed expiry keeps chrono's `+00:00` form while the wire form is `Z`.
    #[test]
    fn expiry_bytes_are_pinned() {
        let cases = [
            (
                1_700_000_000,
                0,
                "2023-11-14T22:13:20+00:00",
                "2023-11-14T22:13:20Z",
            ),
            (
                1_700_000_000,
                500_000_000,
                "2023-11-14T22:13:20.500+00:00",
                "2023-11-14T22:13:20.500Z",
            ),
            (
                1_700_000_000,
                123_456_789,
                "2023-11-14T22:13:20.123456789+00:00",
                "2023-11-14T22:13:20.123456789Z",
            ),
        ];
        for (secs, nanos, signed, wire) in cases {
            let g = pinned(secs, nanos);
            let want = format!(
                r#"{{"session_id":"s","plan_nonce":"{}","not_after":"{signed}","verbs":["run-entrypoint"]}}"#,
                nonce().as_hex()
            );
            assert_eq!(String::from_utf8(g.signing_bytes()).unwrap(), want);
            let json = serde_json::to_string(&g).unwrap();
            assert!(json.contains(&format!(r#""not_after":"{wire}""#)), "{json}");
        }
    }

    #[test]
    fn valid_grant_verifies() {
        let now = now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        assert!(
            g.verify(&k.verifying_key(), "sess-A", &nonce(), now)
                .is_ok()
        );
    }

    #[test]
    fn an_application_terminal_binding_is_signed_and_admits_only_console_verbs() {
        use crate::grants::{ApplicationTerminalBinding, ApplicationTerminalGrant};
        let now = now();
        let (mut grant, signer) = signed(now, vec![]);
        assert!(!grant.permits("console-open"));
        let claude = ApplicationTerminalGrant::new(vec!["/usr/bin/claude".into()]).unwrap();
        grant.application_terminal = Some(ApplicationTerminalBinding::from(&claude));
        grant.sig = signer.sign(&grant.signing_bytes()).to_bytes().to_vec();
        let json = serde_json::to_string(&grant).expect("serialize");
        let round: VerbGrant = serde_json::from_str(&json).expect("deserialize");
        assert!(
            round
                .verify(&signer.verifying_key(), "sess-A", &nonce(), now)
                .is_ok()
        );
        for verb in APPLICATION_TERMINAL_VERBS {
            assert!(round.permits(verb), "{verb}");
        }
        assert!(!round.permits("exec"));
        assert!(!round.permits("proc-start"));

        let shell = ApplicationTerminalGrant::new(vec!["/opt/other/bin/app".into()]).unwrap();
        let mut redirected = round.clone();
        redirected.application_terminal = Some(ApplicationTerminalBinding::from(&shell));
        assert_eq!(
            redirected.verify(&signer.verifying_key(), "sess-A", &nonce(), now),
            Err(VerbGrantError::BadSignature)
        );
        let mut stripped = round;
        stripped.application_terminal = None;
        assert_eq!(
            stripped.verify(&signer.verifying_key(), "sess-A", &nonce(), now),
            Err(VerbGrantError::BadSignature)
        );
    }

    #[test]
    fn signed_legacy_tool_mediation_is_refused() {
        let now = now();
        let (grant, signer) = signed(now, vec!["run-entrypoint"]);
        let mut encoded = serde_json::to_value(&grant).expect("serialize grant");
        encoded["tool_mediation"] = serde_json::json!({"class_gate_only": true});
        assert!(serde_json::from_value::<VerbGrant>(encoded.clone()).is_err());
        encoded["tool_mediation"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<VerbGrant>(encoded).is_err());
        assert!(
            grant
                .verify(&signer.verifying_key(), "sess-A", &nonce(), now)
                .is_ok()
        );
    }

    #[test]
    fn legacy_grant_omits_tool_mediation() {
        let now = now();
        let (grant, signer) = signed(now, vec!["run-entrypoint"]);
        let json = serde_json::to_string(&grant).expect("serialize legacy grant");
        assert!(!json.contains("tool_mediation"));
        let round: VerbGrant = serde_json::from_str(&json).expect("deserialize legacy grant");
        assert!(
            round
                .verify(&signer.verifying_key(), "sess-A", &nonce(), now)
                .is_ok()
        );
    }

    #[test]
    fn sig_serializes_as_base64_and_still_verifies_after_a_round_trip() {
        let now = now();
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
        let now = now();
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
        let now = now();
        let (g, _) = signed(now, vec!["run-entrypoint"]);
        let attacker = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(matches!(
            g.verify(&attacker, "sess-A", &nonce(), now),
            Err(VerbGrantError::BadSignature)
        ));
    }

    #[test]
    fn wrong_session_rejected() {
        let now = now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        assert!(matches!(
            g.verify(&k.verifying_key(), "sess-B", &nonce(), now),
            Err(VerbGrantError::SessionMismatch)
        ));
    }

    #[test]
    fn wrong_nonce_rejected() {
        let now = now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        let other = Nonce::from_bytes([2u8; 16]);
        assert!(matches!(
            g.verify(&k.verifying_key(), "sess-A", &other, now),
            Err(VerbGrantError::NonceMismatch)
        ));
    }

    #[test]
    fn expired_rejected() {
        let now = now();
        let (g, k) = signed(now, vec!["run-entrypoint"]);
        let later = g.not_after.checked_add_secs(1).unwrap();
        assert!(matches!(
            g.verify(&k.verifying_key(), "sess-A", &nonce(), later),
            Err(VerbGrantError::Expired)
        ));
    }

    #[test]
    fn signing_bytes_are_stable_and_exclude_sig() {
        let now = now();
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
        let now = now();
        let (g, _) = signed(now, vec!["run-entrypoint"]);
        assert!(g.permits("protocol-hello"));
        assert!(g.permits("ping"));
        assert!(g.permits("readiness-status"));
        assert!(g.permits("resource-usage"));
        assert!(g.permits("run-entrypoint"));
        assert!(!g.permits("shutdown"));
    }
}
