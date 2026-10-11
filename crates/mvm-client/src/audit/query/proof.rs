//! Verified leaf selection and signed-root membership operations.

use anyhow::{Context, Result, bail};
use ed25519_dalek::VerifyingKey;
use mvm_contract::merkle::{InclusionProof, SignedAuditRoot};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MAX_PROOF_BYTES: usize = 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ProofRequest {
    pub tenant: String,
    pub selector: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofReport {
    pub proof: InclusionProof,
    pub signed_root: Option<SignedAuditRoot>,
}

pub fn prove(request: &ProofRequest) -> Result<ProofReport> {
    super::validate_tenant(&request.tenant)?;
    let tenant = &request.tenant;
    let keys = mvm_hostd::audit::host_keypair::default_keys_dir()?;
    let verifier = mvm_hostd::audit::host_keypair::load_verifier_at(&keys)
        .context("loading host signer to build inclusion proof")?;
    let dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    let leaves = mvm_hostd::audit::merkle::read_leaves(&dir, tenant, &verifier)
        .with_context(|| format!("reading the verified audit chain for tenant '{tenant}'"))?;
    let index = resolve_selector(&leaves, &request.selector)?;
    let proof = mvm_contract::merkle::build_inclusion_proof(&leaves, index)
        .map_err(|e| anyhow::anyhow!("building inclusion proof for leaf {index}: {e}"))?;
    let root_path = mvm_core::config::audit_root_path(tenant);
    let signed_root = if root_path.exists() {
        let raw = super::read_bounded(&root_path, MAX_PROOF_BYTES)
            .with_context(|| format!("reading signed root {}", root_path.display()))?;
        Some(
            serde_json::from_slice(&raw)
                .with_context(|| format!("decoding signed root {}", root_path.display()))?,
        )
    } else {
        None
    };
    let report = ProofReport { proof, signed_root };
    if serde_json::to_vec(&report)?.len() > MAX_PROOF_BYTES {
        bail!("inclusion proof exceeds the {MAX_PROOF_BYTES}-byte limit");
    }
    Ok(report)
}

/// Resolve an index, exact line digest, or unique plan ID. This selects a
/// position only; it does not grant authenticity to caller-supplied leaves.
pub fn resolve_selector(leaves: &[String], selector: &str) -> Result<usize> {
    use sha2::{Digest, Sha256};
    if let Ok(idx) = selector.parse::<usize>() {
        if idx >= leaves.len() {
            bail!(
                "line index {idx} out of range: the chain has {} entries",
                leaves.len()
            );
        }
        return Ok(idx);
    }
    let line_hash_want = selector
        .strip_prefix("sha256:")
        .map(str::to_ascii_lowercase);
    let mut matches = Vec::new();
    for (i, line) in leaves.iter().enumerate() {
        let mut matched = line_hash_want
            .as_ref()
            .is_some_and(|want| &hex::encode(Sha256::digest(line.as_bytes())) == want);
        if !matched
            && let Ok(env) = serde_json::from_str::<mvm_hostd::supervisor::SignedEnvelope>(line)
            && env.entry.plan_id.0 == selector
        {
            matched = true;
        }
        if matched {
            matches.push(i);
        }
    }
    match matches.as_slice() {
        [] => bail!("selector '{selector}' matched no audit line in the chain"),
        [only] => Ok(*only),
        many => bail!(
            "selector '{selector}' is ambiguous: it matches {} lines (indices {many:?}); \
             use a numeric line index or a `sha256:<hex>` line hash to disambiguate",
            many.len()
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct InclusionVerifyRequest {
    /// Raw public proof JSON, capped before decoding.
    pub proof: Vec<u8>,
    pub root: Option<PathBuf>,
    pub pubkey: Option<PathBuf>,
    pub tenant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct InclusionVerification {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root_hash: String,
}

impl InclusionVerification {
    pub fn message(&self) -> String {
        format!(
            "verified: entry at index {idx} of {n} is in the host-signed log (root {root})",
            idx = self.leaf_index,
            n = self.tree_size,
            root = self.root_hash,
        )
    }
}

pub fn verify_inclusion(request: &InclusionVerifyRequest) -> Result<InclusionVerification> {
    super::validate_tenant(&request.tenant)?;
    if request.proof.len() > MAX_PROOF_BYTES {
        bail!("inclusion proof exceeds the {MAX_PROOF_BYTES}-byte limit");
    }
    let proof = serde_json::from_slice(&request.proof).context("decoding inclusion-proof JSON")?;
    let root_path = request
        .root
        .clone()
        .unwrap_or_else(|| mvm_core::config::audit_root_path(&request.tenant));
    let raw = super::read_bounded(&root_path, MAX_PROOF_BYTES)
        .with_context(|| format!("reading signed root {}", root_path.display()))?;
    let root = serde_json::from_slice(&raw).context("decoding signed-root JSON")?;
    let key = match &request.pubkey {
        Some(path) => load_verifying_key(path)?,
        None => {
            let keys = mvm_hostd::audit::host_keypair::default_keys_dir()?;
            mvm_hostd::audit::host_keypair::load_verifier_at(&keys)
                .context("loading host signer public key")?
        }
    };
    verify_inclusion_membership(&proof, &root, &key, &request.tenant)
}

/// Check signature, intended tenant, proof arithmetic, root hash and tree size.
pub fn verify_inclusion_membership(
    proof: &InclusionProof,
    signed_root: &SignedAuditRoot,
    key: &VerifyingKey,
    expected_tenant: &str,
) -> Result<InclusionVerification> {
    mvm_contract::merkle::verify_membership(proof, signed_root, key, expected_tenant)?;
    Ok(InclusionVerification {
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        root_hash: signed_root.root_hash.clone(),
    })
}

/// Load an explicitly trusted public key, accepting raw, hex, or base64 bytes.
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = super::read_bounded(path, MAX_PUBLIC_KEY_BYTES)
        .with_context(|| format!("reading pubkey file {}", path.display()))?;
    if raw.len() == 32 {
        let arr: [u8; 32] = raw.as_slice().try_into().expect("length checked");
        return VerifyingKey::from_bytes(&arr)
            .with_context(|| format!("parsing raw pubkey {}", path.display()));
    }
    let text = String::from_utf8(raw).with_context(|| {
        format!(
            "pubkey file {} is neither 32 raw bytes nor UTF-8 text",
            path.display()
        )
    })?;
    let text = text.trim();
    let bytes = hex::decode(text)
        .ok()
        .filter(|b| b.len() == 32)
        .or_else(|| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .ok()
                .or_else(|| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(text)
                        .ok()
                })
                .filter(|b| b.len() == 32)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "pubkey file {} did not contain a 32-byte Ed25519 key (raw, hex, or base64)",
                path.display()
            )
        })?;
    let arr: [u8; 32] = bytes.as_slice().try_into().expect("length checked");
    VerifyingKey::from_bytes(&arr).with_context(|| format!("parsing pubkey {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_and_public_key_inputs_are_bounded_before_decoding() {
        let request = InclusionVerifyRequest {
            proof: vec![0; MAX_PROOF_BYTES + 1],
            root: None,
            pubkey: None,
            tenant: "local".into(),
        };
        assert!(
            verify_inclusion(&request)
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        std::fs::write(&key, vec![b' '; MAX_PUBLIC_KEY_BYTES + 1]).unwrap();
        assert!(load_verifying_key(&key).is_err());
        std::fs::write(&key, [0; 31]).unwrap();
        assert!(load_verifying_key(&key).is_err());
    }
}
