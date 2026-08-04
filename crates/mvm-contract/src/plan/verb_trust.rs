//! The build-time-baked, dm-verity-measured policy that governs whether a guest
//! requires a pinned agent-verb grant, and which key source it trusts. Generic
//! per image (no per-host key), so it can live in the sealed rootfs.

use serde::{Deserialize, Serialize};

pub const VERB_TRUST_POLICY_VERSION: u32 = 1;

/// Where the guest expects the grant's verifying key to come from. Today only
/// `LaunchProvisioned` (the key rides the launcher-provisioned envelope). The
/// `Attested` arm is the forward hook for a future measured-boot / vTPM anchor
/// and is defined-but-unimplemented (treated as fail-closed by the guest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrantKeySource {
    #[default]
    LaunchProvisioned,
    Attested,
}

/// The measured verb-trust policy baked into a sealed image's rootfs at
/// `/etc/mvm/verb-trust.json`. Absent file ⇒ no requirement (dev/OCI default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerbTrustPolicy {
    pub version: u32,
    /// Guest fails closed if a grant is required but none is validly pinned.
    pub require_grant: bool,
    #[serde(default)]
    pub grant_key_source: GrantKeySource,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_key_source_default() {
        let p = VerbTrustPolicy {
            version: VERB_TRUST_POLICY_VERSION,
            require_grant: false,
            grant_key_source: GrantKeySource::LaunchProvisioned,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: VerbTrustPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        // grant_key_source defaults when omitted.
        let minimal: VerbTrustPolicy =
            serde_json::from_str(r#"{"version":1,"require_grant":true}"#).unwrap();
        assert_eq!(minimal.grant_key_source, GrantKeySource::LaunchProvisioned);
        assert!(minimal.require_grant);
    }

    #[test]
    fn unknown_field_rejected() {
        // deny_unknown_fields fails closed on drift.
        let r: Result<VerbTrustPolicy, _> =
            serde_json::from_str(r#"{"version":1,"require_grant":false,"evil":1}"#);
        assert!(r.is_err());
    }

    #[test]
    fn attested_source_parses() {
        let p: VerbTrustPolicy = serde_json::from_str(
            r#"{"version":1,"require_grant":true,"grant_key_source":"attested"}"#,
        )
        .unwrap();
        assert_eq!(p.grant_key_source, GrantKeySource::Attested);
    }
}
