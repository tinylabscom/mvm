//! Subprocess startup config (read from stdin at spawn).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Config the supervisor hands to a `mvm-audit-signer` subprocess at spawn.
///
/// Parsed unsigned today; a signed-envelope wrapper closes that gap later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubprocessConfig {
    pub workload_id: String,
    pub tenant_id: String,
    /// Per-VM UDS path this subprocess listens on for `AppendEntryRequest`
    /// (mode 0600, supervisor-owned).
    pub uds_path: PathBuf,
    /// Path to the per-tenant audit chain JSONL file. The supervisor
    /// creates the parent dir at mode 0700 with the dir-immutable flag
    /// (chattr +a / UF_APPEND) before spawning; this subprocess just
    /// trusts the path.
    pub audit_jsonl_path: PathBuf,
    /// Path to the secondary chain-head persistence file. The audit-signer
    /// writes the latest `chain_head` here after every successful append;
    /// supervisor's verify path can cross-check.
    pub chain_head_secondary_path: PathBuf,
    /// Path to a pre-existing chain-signing key file (software path; a
    /// hardware enclave handle replaces it later).
    /// If absent, the subprocess generates a fresh in-memory key at boot.
    #[serde(default)]
    pub software_chain_key_path: Option<PathBuf>,
}

pub fn parse(bytes: &[u8]) -> Result<SubprocessConfig, serde_json::Error> {
    serde_json::from_slice(bytes)
}

/// Config for the resident per-tenant signer helper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignerHelperConfig {
    /// The single tenant this helper serves.
    pub tenant_id: String,
    /// UDS the host-agent daemon uses for register/deregister/append requests.
    pub uds_path: PathBuf,
    /// Path to a pre-existing tenant signing key (software path; a hardware
    /// enclave handle replaces it later).
    #[serde(default)]
    pub software_chain_key_path: Option<PathBuf>,
    /// Max request frame size accepted by the helper.
    #[serde(default = "crate::audit_signer::server::default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

pub fn parse_signer_helper(bytes: &[u8]) -> Result<SignerHelperConfig, serde_json::Error> {
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
            uds_path: PathBuf::from("/tmp/test/audit-signer.sock"),
            audit_jsonl_path: PathBuf::from("/tmp/test/audit.jsonl"),
            chain_head_secondary_path: PathBuf::from("/tmp/test/HEAD"),
            software_chain_key_path: None,
        };
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse(&bytes).unwrap(), cfg);
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = serde_json::json!({
            "workload_id": "wl",
            "tenant_id": "t",
            "uds_path": "/tmp/test/audit-signer.sock",
            "audit_jsonl_path": "/tmp/test/audit.jsonl",
            "chain_head_secondary_path": "/tmp/test/HEAD",
            "extra": "field",
        });
        let err = parse(&serde_json::to_vec(&bad).unwrap()).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn signer_helper_config_roundtrips() {
        let cfg = SignerHelperConfig {
            tenant_id: "local".into(),
            uds_path: PathBuf::from("/tmp/test/signer-helper.sock"),
            software_chain_key_path: Some(PathBuf::from("/tmp/test/host-signer.ed25519")),
            max_frame_bytes: 4096,
        };
        let bytes = serde_json::to_vec(&cfg).unwrap();
        assert_eq!(parse_signer_helper(&bytes).unwrap(), cfg);
    }

    #[test]
    fn signer_helper_config_defaults_max_frame_bytes() {
        let raw = serde_json::json!({
            "tenant_id": "local",
            "uds_path": "/tmp/test/signer-helper.sock",
        });
        let cfg = parse_signer_helper(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(
            cfg.max_frame_bytes,
            crate::audit_signer::server::default_max_frame_bytes()
        );
    }
}
