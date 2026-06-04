//! Subprocess startup config (read from stdin at spawn).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Config the supervisor hands to a `mvm-audit-signer` subprocess at spawn.
///
/// W1b.1 parses unsigned; W1b.2's §H-L3.6 wrapper closes the
/// signed-envelope gap.
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
    /// (chattr +a / UF_APPEND) before spawning — that's the W1b.2
    /// boundary; W1b.1 just trusts the path.
    pub audit_jsonl_path: PathBuf,
    /// Path to the secondary chain-head persistence file (Plan 104
    /// §H-L5.2 / §H-L8). The audit-signer writes the latest `chain_head`
    /// here after every successful append; supervisor's verify path
    /// can cross-check.
    pub chain_head_secondary_path: PathBuf,
    /// Path to a pre-existing chain-signing key file (W1b.1 software
    /// path; W8 replaces with enclave handle).
    /// If absent, the subprocess generates a fresh in-memory key at boot.
    #[serde(default)]
    pub software_chain_key_path: Option<PathBuf>,
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
}
