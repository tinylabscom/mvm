//! Subprocess startup config (read from stdin at spawn).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Config the supervisor hands to a `mvm-host-signer` subprocess at
/// spawn.
///
/// W1b.1 parses the envelope unsigned. Plan 104 §H-L3.6 (G1) — to close
/// in W1b.2 — wraps this struct in a release-key-signed envelope so a
/// compromised supervisor cannot induce the subprocess to point its
/// audit-back-channel at `/dev/null` or its proxy UDS at a sibling
/// workload's socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubprocessConfig {
    pub workload_id: String,
    pub tenant_id: String,
    /// Per-VM UDS path this subprocess listens on for sign requests
    /// (mode 0600, supervisor-owned).
    pub uds_path: PathBuf,
    /// Audit-signer UDS path. Sign events (`host_signer.plan_signed`,
    /// `host_signer.credential_signed`) flow through it for chain-
    /// signing. Unused in W1b.1; wired in W1b.2.
    #[serde(default)]
    pub audit_signer_uds_path: Option<PathBuf>,
    /// Optional path to a pre-existing key file (W1b.1 software-fallback
    /// path — used by tests + persisted-key dev workflows). If absent,
    /// the subprocess generates a fresh in-memory key at boot.
    /// W8 replaces this with `enclave_keypair_handle: TpmHandle` (Linux)
    /// or `enclave_keychain_label: String` (macOS SE).
    #[serde(default)]
    pub software_key_path: Option<PathBuf>,
}

pub fn parse(bytes: &[u8]) -> Result<SubprocessConfig, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_canonical() {
        let cfg = SubprocessConfig {
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            uds_path: PathBuf::from("/tmp/test/host-signer.sock"),
            audit_signer_uds_path: Some(PathBuf::from("/tmp/test/audit-signer.sock")),
            software_key_path: None,
        };
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = serde_json::json!({
            "workload_id": "wl",
            "tenant_id": "t",
            "uds_path": "/tmp/test/host-signer.sock",
            "side_channel": "data",
        });
        assert!(
            parse(&serde_json::to_vec(&bad).unwrap())
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }
}
