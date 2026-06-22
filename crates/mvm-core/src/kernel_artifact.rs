use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Identifies a compiled kernel artifact by version, configuration fingerprint,
/// and a content-addressed SHA-256 hash of the vmlinux binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelArtifactId {
    pub kernel_version: String,
    pub config_hash: String,
    pub artifact_hash: String,
}

/// Returns the SHA-256 hex digest of the given vmlinux binary bytes.
///
/// The hash is stable: identical input always produces identical output.
pub fn compute_artifact_hash(vmlinux: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(vmlinux);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_hash_is_stable_sha256_hex() {
        let h = compute_artifact_hash(b"vmlinux-bytes");
        assert_eq!(h.len(), 64);
        assert_eq!(h, compute_artifact_hash(b"vmlinux-bytes"));
        assert_ne!(h, compute_artifact_hash(b"other"));
    }

    #[test]
    fn artifact_id_serde_roundtrip() {
        let id = KernelArtifactId {
            kernel_version: "6.12.91".into(),
            config_hash: "abc".into(),
            artifact_hash: "def".into(),
        };
        let j = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<KernelArtifactId>(&j).unwrap(), id);
    }
}
