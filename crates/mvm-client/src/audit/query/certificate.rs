//! Signature verification and optional (unauthenticated) chain correlation.

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const MAX_CERTIFICATE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CertificateRequest {
    pub certificate: Vec<u8>,
    pub pubkey: Option<PathBuf>,
    pub chain: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DestructionReceipt {
    pub tenant: String,
    pub workload: String,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub destroyed_at: chrono::DateTime<chrono::Utc>,
    pub files_wiped: u64,
    pub bytes_wiped: u64,
}

/// Correlation with supplied log contents, not authentication of that log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ChainMatch {
    Matched,
    Missing,
    Mismatched,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CertificateReport {
    pub receipts: Vec<DestructionReceipt>,
    pub chain_matches: Vec<ChainMatch>,
}

impl CertificateReport {
    pub fn ensure_correlated(&self) -> Result<()> {
        if self
            .chain_matches
            .iter()
            .any(|m| matches!(m, ChainMatch::Missing | ChainMatch::Mismatched))
        {
            bail!(
                "chain cross-reference failed for one or more certificate(s); \
                 see the per-cert ✗ markers above. The cert's signature is \
                 valid but the audit chain does not corroborate it."
            );
        }
        Ok(())
    }
}

pub fn verify_certificate(request: &CertificateRequest) -> Result<CertificateReport> {
    use mvm_runtime::vm::overlay::{
        SignedDestructionReceipt, cert_fingerprint, verify_destruction_receipt,
    };
    if request.certificate.len() > MAX_CERTIFICATE_BYTES {
        bail!("certificate exceeds the {MAX_CERTIFICATE_BYTES}-byte limit");
    }
    let raw = std::str::from_utf8(&request.certificate).context("decoding certificate")?;
    let certs: Vec<SignedDestructionReceipt> = if raw.trim_start().starts_with('[') {
        serde_json::from_str(raw).context("decoding certificate array")?
    } else {
        vec![serde_json::from_str(raw).context("decoding certificate")?]
    };
    let expected_pubkey = request
        .pubkey
        .as_deref()
        .map(read_certificate_key)
        .transpose()?;
    let mut receipts = Vec::with_capacity(certs.len());
    for (i, signed) in certs.iter().enumerate() {
        let r =
            verify_destruction_receipt(signed, expected_pubkey.as_ref()).with_context(|| {
                format!(
                    "verifying certificate {} ({}/{})",
                    i + 1,
                    signed.receipt.tenant,
                    signed.receipt.workload
                )
            })?;
        receipts.push(DestructionReceipt {
            tenant: r.tenant.clone(),
            workload: r.workload.clone(),
            destroyed_at: r.destroyed_at,
            files_wiped: r.files_wiped,
            bytes_wiped: r.bytes_wiped,
        });
    }
    let chain_index = request
        .chain
        .as_deref()
        .map(load_chain_fingerprint_index)
        .transpose()?;
    let chain_matches = certs
        .iter()
        .zip(&receipts)
        .map(|(signed, receipt)| {
            let Some(index) = &chain_index else {
                return ChainMatch::Skipped;
            };
            match index.get(&(receipt.tenant.clone(), receipt.workload.clone())) {
                Some(fp) if *fp == cert_fingerprint(signed) => ChainMatch::Matched,
                Some(_) => ChainMatch::Mismatched,
                None => ChainMatch::Missing,
            }
        })
        .collect();
    Ok(CertificateReport {
        receipts,
        chain_matches,
    })
}

fn read_certificate_key(path: &Path) -> Result<ed25519_dalek::VerifyingKey> {
    let raw = super::read_bounded(path, 4096)
        .with_context(|| format!("reading pubkey file {}", path.display()))?;
    let raw = std::str::from_utf8(&raw)
        .with_context(|| format!("reading pubkey file {}", path.display()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw.trim().as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw.trim().as_bytes()))
        .with_context(|| format!("decoding base64 pubkey from {}", path.display()))?;
    if bytes.len() != 32 {
        bail!(
            "pubkey file {} contains {} bytes; expected 32",
            path.display(),
            bytes.len()
        );
    }
    let array: [u8; 32] = bytes.as_slice().try_into().expect("length checked");
    ed25519_dalek::VerifyingKey::from_bytes(&array).context("parsing pubkey")
}

/// Index correlation labels only. Malformed/non-destruction lines are ignored
/// for compatibility; this function does not verify a chain or confer trust.
pub fn load_chain_fingerprint_index(path: &Path) -> Result<HashMap<(String, String), String>> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening chain file {}", path.display()))?;
    let raw = super::read_bounded_from(file, super::MAX_RECEIPT_ARCHIVE_BYTES)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut index = HashMap::new();
    for line in raw.as_slice().lines() {
        let line = line.with_context(|| format!("reading {}", path.display()))?;
        let Ok(envelope) = serde_json::from_str::<mvm_hostd::supervisor::SignedEnvelope>(&line)
        else {
            continue;
        };
        if envelope.entry.event != "lifecycle.tenant.destroyed" {
            continue;
        }
        let labels = &envelope.entry.labels;
        if let (Some(tenant), Some(workload), Some(fingerprint)) = (
            labels.get("tenant"),
            labels.get("workload"),
            labels.get("cert_fingerprint"),
        ) {
            index.insert((tenant.clone(), workload.clone()), fingerprint.clone());
        }
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_runtime::vm::overlay::{cert_fingerprint, sign_destruction_receipt};

    #[test]
    fn matching_untrusted_correlation_cannot_override_a_pinned_key() {
        let dir = tempfile::tempdir().unwrap();
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
        let trusted = ed25519_dalek::SigningKey::from_bytes(&[34; 32]);
        let receipt = mvm_runtime::vm::overlay::DestructionReceipt {
            tenant: "local".into(),
            workload: "worker".into(),
            destroyed_at: chrono::Utc::now(),
            files_wiped: 1,
            bytes_wiped: 32,
        };
        let signed = sign_destruction_receipt(&receipt, &attacker);
        let chain = dir.path().join("untrusted.jsonl");
        std::fs::write(
            &chain,
            serde_json::to_vec(&serde_json::json!({
                "entry": {
                    "timestamp": chrono::Utc::now(),
                    "tenant": "local", "plan_id": "plan-1", "plan_version": 1,
                    "bundle_id": null, "bundle_version": null,
                    "image_name": "img", "image_sha256": "abc123",
                    "event": "lifecycle.tenant.destroyed",
                    "labels": {
                        "tenant": "local", "workload": "worker",
                        "cert_fingerprint": cert_fingerprint(&signed)
                    }
                },
                "prev_hash": "invalid",
                "signature": "invalid"
            }))
            .unwrap(),
        )
        .unwrap();
        let pubkey = dir.path().join("trusted.pub");
        std::fs::write(
            &pubkey,
            base64::engine::general_purpose::STANDARD.encode(trusted.verifying_key().to_bytes()),
        )
        .unwrap();
        let mut request = CertificateRequest {
            certificate: serde_json::to_vec(&signed).unwrap(),
            pubkey: None,
            chain: Some(chain),
        };
        // The certificate is internally valid and its untrusted correlation matches.
        assert_eq!(
            verify_certificate(&request).unwrap().chain_matches,
            vec![ChainMatch::Matched]
        );
        request.pubkey = Some(pubkey);
        assert!(verify_certificate(&request).is_err());
    }

    #[tokio::test]
    async fn unverified_correlation_cannot_rescue_an_invalid_certificate() {
        use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};
        let dir = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[33; 32]);
        let receipt = mvm_runtime::vm::overlay::DestructionReceipt {
            tenant: "local".into(),
            workload: "worker".into(),
            destroyed_at: chrono::Utc::now(),
            files_wiped: 1,
            bytes_wiped: 32,
        };
        let mut signed = sign_destruction_receipt(&receipt, &key);
        let mut request = CertificateRequest {
            certificate: serde_json::to_vec(&signed).unwrap(),
            pubkey: None,
            chain: None,
        };
        let report = verify_certificate(&request).unwrap();
        assert_eq!(report.chain_matches, vec![ChainMatch::Skipped]);
        assert_eq!(
            serde_json::to_value(&report.receipts[0]).unwrap(),
            serde_json::to_value(&receipt).unwrap()
        );
        signed.receipt.bytes_wiped += 1;
        let fingerprint = cert_fingerprint(&signed);
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        signer
            .sign_and_emit(&PlanAuditEntry {
                timestamp: chrono::Utc::now(),
                tenant: mvm_core::plan::TenantId("local".into()),
                plan_id: mvm_core::plan::PlanId("plan-1".into()),
                plan_version: 1,
                bundle_id: None,
                bundle_version: None,
                image_name: "img".into(),
                image_sha256: "abc123".into(),
                event: "lifecycle.tenant.destroyed".into(),
                caller_commitment: None,
                labels: std::collections::BTreeMap::from([
                    ("tenant".into(), "local".into()),
                    ("workload".into(), "worker".into()),
                    ("cert_fingerprint".into(), fingerprint.clone()),
                ]),
            })
            .await
            .unwrap();
        drop(signer);
        let chain = dir.path().join("local.jsonl");
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&chain).unwrap()).unwrap();
        envelope["signature"] = serde_json::json!("invalid");
        std::fs::write(&chain, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(
            load_chain_fingerprint_index(&chain)
                .unwrap()
                .get(&("local".into(), "worker".into())),
            Some(&fingerprint)
        );
        request.chain = Some(chain);
        request.certificate = serde_json::to_vec(&signed).unwrap();
        assert!(
            verify_certificate(&request)
                .unwrap_err()
                .to_string()
                .contains("verifying certificate 1")
        );
    }

    #[test]
    fn certificate_key_length_and_input_caps_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkey");
        std::fs::write(
            &path,
            base64::engine::general_purpose::STANDARD.encode([0; 31]),
        )
        .unwrap();
        assert!(
            read_certificate_key(&path)
                .unwrap_err()
                .to_string()
                .contains("expected 32")
        );
        let request = CertificateRequest {
            certificate: vec![0; MAX_CERTIFICATE_BYTES + 1],
            pubkey: None,
            chain: None,
        };
        assert!(
            verify_certificate(&request)
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
    }
}
