//! Verifying a signed run receipt against the host's trusted public key.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::super::host_signer::PUBLIC_FILENAME;
use super::{SignedRunReceipt, sha256_hex};

pub(super) fn verify_run_receipt(
    path: &Path,
    pubkey_path: Option<&Path>,
) -> Result<SignedRunReceipt> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading receipt {}", path.display()))?;
    let receipt: SignedRunReceipt = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing receipt {}", path.display()))?;
    if receipt.payload.schema_version != 1 {
        anyhow::bail!(
            "unsupported receipt schema_version {}; this build supports 1",
            receipt.payload.schema_version
        );
    }
    if !receipt.signature.algorithm.eq_ignore_ascii_case("ed25519") {
        anyhow::bail!(
            "unsupported receipt signature algorithm '{}'",
            receipt.signature.algorithm
        );
    }
    let verifying = load_receipt_pubkey(pubkey_path)?;
    let public_key = verifying.to_bytes();
    let actual_key_hash = sha256_hex(&public_key);
    if actual_key_hash != receipt.signature.public_key_sha256 {
        anyhow::bail!(
            "receipt was signed by public key {}; trusted key is {}",
            receipt.signature.public_key_sha256,
            actual_key_hash
        );
    }

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature.signature_base64)
        .context("decoding receipt signature")?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid receipt signature bytes: {e}"))?;
    let payload_bytes =
        serde_json::to_vec(&receipt.payload).context("serializing receipt payload")?;
    verifying
        .verify(&payload_bytes, &signature)
        .map_err(|e| anyhow::anyhow!("receipt signature verification failed: {e}"))?;
    Ok(receipt)
}

fn load_receipt_pubkey(path: Option<&Path>) -> Result<VerifyingKey> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => super::super::host_signer::default_keys_dir()?.join(PUBLIC_FILENAME),
    };
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading trusted receipt public key {}", path.display()))?;
    let key: [u8; super::super::host_signer::KEY_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must contain exactly 32 bytes", path.display()))?;
    VerifyingKey::from_bytes(&key).with_context(|| format!("parsing {}", path.display()))
}
