//! Subprocess startup config (read from stdin at spawn).
//!
//! The supervisor passes this JSON on stdin once at startup, then closes
//! the pipe. The W1a parser is unsigned-passthrough; W1b will require an
//! enclosing signed envelope (Plan 104 §H-L3.6) before the broker accepts
//! the config.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Config the supervisor hands to a `mvm-broker` subprocess at spawn.
///
/// The envelope is currently unsigned (W1a). Plan 104 §H-L3.6 (G1) — to
/// close in W1b — wraps this struct in a release-key-signed envelope so a
/// compromised supervisor cannot induce the subprocess to point its
/// audit-back-channel at `/dev/null` or its proxy UDS at a sibling
/// workload's socket. The TODO comment at the parse site is the
/// commitment to that closure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubprocessConfig {
    /// Workload identifier (assigned by the supervisor at admission).
    pub workload_id: String,
    /// Tenant identifier the workload belongs to.
    pub tenant_id: String,
    /// Per-VM UDS path the broker listens on for supervisor-proxied calls
    /// (mode 0600, supervisor-owned).
    pub uds_path: PathBuf,
    /// Path to the host signer's *public* key (for response-payload
    /// signature verification on the secrets dispatcher — the broker
    /// reads it too so its in-process composition can verify
    /// secrets-dispatcher responses; see ADR-061 §"Decision" T0.5).
    pub host_signer_public_key_path: PathBuf,
    /// Path to the audit-signer's UDS (so the broker can forward audit
    /// subentries via the supervisor proxy). Unused in W1a — included
    /// in the config now so W1b doesn't change the envelope shape.
    #[serde(default)]
    pub audit_signer_uds_path: Option<PathBuf>,
    /// Maximum frame size in bytes. Plan 104 §"Capability gating" gate 1
    /// caps this at 64 KiB by default.
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
    /// Parse timeout in milliseconds. Plan 104 §"Capability gating" gate 1
    /// caps this at 50ms by default.
    #[serde(default = "default_parse_timeout_ms", with = "duration_ms")]
    pub parse_timeout: Duration,
}

fn default_max_frame_bytes() -> usize {
    65_536
}

fn default_parse_timeout_ms() -> Duration {
    Duration::from_millis(50)
}

mod duration_ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = u64::deserialize(d)?;
        Ok(Duration::from_millis(ms))
    }
}

/// Parse a [`SubprocessConfig`] from a JSON byte slice.
///
/// TODO(W1b / Plan 104 §H-L3.6): wrap in a signed envelope before parse;
/// reject the config + audit `broker.subprocess.config_signature_invalid`
/// on mismatch. v1 of the envelope ships the algorithm-identifier byte
/// (Plan 104 §H-L4.1) so the signing key can swap (Ed25519 → P-256 on the
/// macOS SE path → future PQC) without a hard fork.
pub fn parse(bytes: &[u8]) -> Result<SubprocessConfig, serde_json::Error> {
    serde_json::from_slice(bytes)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_canonical_form() {
        let cfg = SubprocessConfig {
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            uds_path: PathBuf::from("/tmp/test/broker.sock"),
            host_signer_public_key_path: PathBuf::from("/tmp/test/host-signer.pub"),
            audit_signer_uds_path: Some(PathBuf::from("/tmp/test/audit-signer.sock")),
            max_frame_bytes: 65_536,
            parse_timeout: Duration::from_millis(50),
        };
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let parsed: SubprocessConfig = parse(&bytes).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn defaults_for_optional_fields() {
        // Minimal config — defaults supply max_frame_bytes / parse_timeout /
        // audit_signer_uds_path.
        let json = serde_json::json!({
            "workload_id": "wl-min",
            "tenant_id": "t-min",
            "uds_path": "/tmp/test/broker.sock",
            "host_signer_public_key_path": "/tmp/test/host-signer.pub",
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.max_frame_bytes, 65_536);
        assert_eq!(parsed.parse_timeout, Duration::from_millis(50));
        assert!(parsed.audit_signer_uds_path.is_none());
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = serde_json::json!({
            "workload_id": "wl",
            "tenant_id": "t",
            "uds_path": "/tmp/test/broker.sock",
            "host_signer_public_key_path": "/tmp/test/host-signer.pub",
            "extra_field": "should not parse",
        });
        let bytes = serde_json::to_vec(&bad).unwrap();
        let err = parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
