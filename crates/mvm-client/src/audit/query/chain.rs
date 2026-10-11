//! Explicit audit-chain mutations; preview is read-only and commit re-verifies.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChainVerification {
    Empty {
        directory: PathBuf,
    },
    Checked {
        directory: PathBuf,
        sources: Vec<crate::audit::VerifiedSourceSummary>,
        refusals: Vec<crate::audit::AuditSourceRefusal>,
        append_only: AppendOnlyReport,
        witness: WitnessReport,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AppendOnlyReport {
    Verified {
        roots: usize,
        transitions_checked: usize,
    },
    Failed {
        detail: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct WitnessDivergence {
    pub tree_size: u64,
    pub witnessed_root: String,
    pub host_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WitnessReport {
    NotConfigured,
    Compared {
        agreed: usize,
        unwitnessed: usize,
        diverged: Vec<WitnessDivergence>,
    },
    Failed {
        detail: String,
    },
}

/// Verify all discovered sources using the shared reader, then independently
/// report append-only evidence and witness agreement. Failures remain failures,
/// not absent evidence or an empty successful comparison.
pub fn verify_chain(tenant: &str) -> Result<ChainVerification> {
    super::validate_tenant(tenant)?;
    let dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    let discovered = crate::audit::discover_source_ids(&dir, Some(tenant))
        .context("enumerating audit sources")?;
    if discovered.is_empty() {
        return Ok(ChainVerification::Empty { directory: dir });
    }
    let keys = mvm_hostd::audit::host_keypair::default_keys_dir()?;
    let verifier = mvm_hostd::audit::host_keypair::load_verifier_at(&keys)
        .context("loading host signer to verify audit chain")?;
    let outcome = crate::audit::LocalAuditReader::new(&dir, verifier)
        .verify_sources(Some(tenant))
        .context("verifying audit sources")?;
    let append_only = match mvm_hostd::audit::merkle::verify_root_history(&dir, tenant, &verifier) {
        Ok(r) => AppendOnlyReport::Verified {
            roots: r.roots,
            transitions_checked: r.transitions_checked,
        },
        Err(e) => AppendOnlyReport::Failed {
            detail: format!("{e:#}"),
        },
    };
    let witness = match mvm_hostd::audit::witness::configured_source() {
        None => WitnessReport::NotConfigured,
        Some(source) => match mvm_hostd::audit::witness::detect_divergence(
            &dir,
            tenant,
            source.as_ref(),
            &verifier,
        ) {
            Ok(r) => WitnessReport::Compared {
                agreed: r.agreed,
                unwitnessed: r.unwitnessed,
                diverged: r
                    .diverged
                    .into_iter()
                    .map(|d| WitnessDivergence {
                        tree_size: d.tree_size,
                        witnessed_root: d.witnessed_root,
                        host_root: d.host_root,
                    })
                    .collect(),
            },
            Err(e) => WitnessReport::Failed {
                detail: format!("{e:#}"),
            },
        },
    };
    Ok(ChainVerification::Checked {
        directory: dir,
        sources: outcome.sources,
        refusals: outcome.refusals,
        append_only,
        witness,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PublishedRoot {
    pub tenant: String,
    pub root_hash: String,
    pub tree_size: u64,
    pub path: PathBuf,
}

/// Explicitly sign and publish the tenant's current Merkle root.
pub fn publish_root(tenant: &str) -> Result<PublishedRoot> {
    super::validate_tenant(tenant)?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading host signer to publish audit root")?;
    let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing)
        .context("opening host audit emitter")?;
    let signed = emitter
        .publish_root(tenant)
        .with_context(|| format!("publishing Merkle root for tenant '{tenant}'"))?;
    Ok(PublishedRoot {
        tenant: tenant.to_string(),
        root_hash: signed.root_hash,
        tree_size: signed.tree_size,
        path: mvm_core::config::audit_root_path(tenant),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PruneIntent {
    Preview,
    AcknowledgeEvidenceRemoval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct PruneRequest {
    pub tenant: String,
    pub through: u64,
    pub intent: PruneIntent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PruneReport {
    Nothing {
        floor: u64,
        through: u64,
    },
    Preview {
        floor: u64,
        through: u64,
        segments: usize,
        entries: usize,
    },
    Pruned {
        through: u64,
        entries: u64,
    },
}

pub fn prune_chain(request: &PruneRequest) -> Result<PruneReport> {
    super::validate_tenant(&request.tenant)?;
    let dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    let keys = mvm_hostd::audit::host_keypair::default_keys_dir()?;
    let verifier = mvm_hostd::audit::host_keypair::load_verifier_at(&keys)
        .context("loading host signer to prune audit chain")?;
    let preview = preview_prune(request, &dir, &verifier)?;
    if request.intent == PruneIntent::Preview || matches!(preview, PruneReport::Nothing { .. }) {
        return Ok(preview);
    }
    let signer = mvm_hostd::audit::host_keypair::load_or_init_at(&keys)
        .context("loading host signer to prune audit chain")?;
    let file_signer = mvm_hostd::supervisor::FileAuditSigner::open(signer.signing, &dir)
        .context("opening the audit signer to record the prune")?;
    // The authoritative operation locks and verifies the current segment set
    // again. A preview is never a capability to delete a later, different set.
    let pruned = file_signer
        .prune_through(
            &mvm_core::plan::TenantId(request.tenant.clone()),
            request.through,
        )
        .context("pruning audit segments")?;
    Ok(PruneReport::Pruned {
        through: pruned.through,
        entries: pruned.entries,
    })
}

fn preview_prune(
    request: &PruneRequest,
    dir: &std::path::Path,
    verifier: &ed25519_dalek::VerifyingKey,
) -> Result<PruneReport> {
    let tenant = &request.tenant;
    let through = request.through;
    let verified =
        mvm_hostd::supervisor::verify_segment_set(dir, tenant, verifier).with_context(|| {
            format!(
                "refusing to prune tenant '{tenant}': its chain does not verify. Pruning a \
                 broken chain would delete the evidence of whatever broke it"
            )
        })?;
    let floor = match verified.pruned {
        Some(p) => p
            .through
            .checked_add(1)
            .context("pruned segment sequence overflow")?,
        None => 1,
    };
    let doomed: Vec<_> = verified
        .segments
        .iter()
        .filter(|s| !s.active && s.seq >= floor && s.seq <= through)
        .collect();
    if doomed.is_empty() {
        return Ok(PruneReport::Nothing { floor, through });
    }
    let entries = doomed.iter().filter_map(|s| s.entries).sum();
    Ok(PruneReport::Preview {
        floor,
        through,
        segments: doomed.len(),
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn published_proof_and_witness_fail_closed_on_tamper_and_wrong_key() {
        use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        env.set("MVM_AUDIT_WITNESS", "");
        assert!(matches!(
            verify_chain("local").unwrap(),
            ChainVerification::Empty { .. }
        ));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let identity =
            mvm_hostd::audit::host_keypair::load_or_init_at(&dir.path().join("keys")).unwrap();
        let signer =
            FileAuditSigner::open(identity.signing.clone(), dir.path().join("audit")).unwrap();
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
                event: "plan.launched".into(),
                caller_commitment: None,
                labels: Default::default(),
            })
            .await
            .unwrap();
        drop(signer);
        let published = publish_root("local").unwrap();
        let proof = super::super::prove(&super::super::ProofRequest {
            tenant: "local".into(),
            selector: "0".into(),
        })
        .unwrap();
        let mut request = super::super::InclusionVerifyRequest {
            proof: serde_json::to_vec(&proof.proof).unwrap(),
            root: None,
            pubkey: None,
            tenant: "local".into(),
        };
        assert_eq!(
            super::super::verify_inclusion(&request).unwrap().leaf_index,
            0
        );
        request.tenant = "other".into();
        request.root = Some(published.path.clone());
        assert!(super::super::verify_inclusion(&request).is_err());
        request.tenant = "local".into();
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[89; 32]);
        let wrong_path = dir.path().join("wrong.pub");
        std::fs::write(&wrong_path, wrong.verifying_key().to_bytes()).unwrap();
        request.pubkey = Some(wrong_path);
        assert!(super::super::verify_inclusion(&request).is_err());
        request.pubkey = None;
        let original = std::fs::read(&published.path).unwrap();
        let witness = dir.path().join("witness.jsonl");
        let mut root: mvm_contract::merkle::SignedAuditRoot =
            serde_json::from_slice(&original).unwrap();
        // Published roots are pretty JSON; a witness is one compact root per line.
        std::fs::write(&witness, serde_json::to_vec(&root).unwrap()).unwrap();
        env.set("MVM_AUDIT_WITNESS", &witness);
        assert!(matches!(
            verify_chain("local").unwrap(),
            ChainVerification::Checked {
                witness: WitnessReport::Compared { agreed: 1, .. },
                ..
            }
        ));
        root.root_hash = "00".repeat(32);
        std::fs::write(&witness, serde_json::to_vec(&root).unwrap()).unwrap();
        assert!(matches!(
            verify_chain("local").unwrap(),
            ChainVerification::Checked {
                witness: WitnessReport::Failed { .. },
                ..
            }
        ));
        std::fs::write(&published.path, serde_json::to_vec(&root).unwrap()).unwrap();
        assert!(super::super::verify_inclusion(&request).is_err());
        use base64::Engine;
        use ed25519_dalek::Signer;
        let payload = mvm_contract::merkle::root_signing_bytes(
            &root.tenant,
            root.tree_size,
            &root.root_hash,
            &root.timestamp,
        )
        .unwrap();
        root.signature =
            base64::engine::general_purpose::STANDARD.encode(wrong.sign(&payload).to_bytes());
        root.signer_pubkey = hex::encode(wrong.verifying_key().to_bytes());
        std::fs::write(&witness, serde_json::to_vec(&root).unwrap()).unwrap();
        assert!(matches!(
            verify_chain("local").unwrap(),
            ChainVerification::Checked {
                witness: WitnessReport::Failed { .. },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn preview_preserves_evidence_and_commit_rechecks_current_chain() {
        use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry, RotationPolicy};
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let keys = dir.path().join("keys");
        let identity = mvm_hostd::audit::host_keypair::load_or_init_at(&keys).unwrap();
        let audit = dir.path().join("audit");
        let signer = FileAuditSigner::open(identity.signing, &audit)
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(1));
        let entry = PlanAuditEntry {
            timestamp: chrono::Utc::now(),
            tenant: mvm_core::plan::TenantId("local".into()),
            plan_id: mvm_core::plan::PlanId("plan-1".into()),
            plan_version: 1,
            bundle_id: None,
            bundle_version: None,
            image_name: "img".into(),
            image_sha256: "abc123".into(),
            event: "plan.launched".into(),
            caller_commitment: None,
            labels: Default::default(),
        };
        signer.sign_and_emit(&entry).await.unwrap();
        signer.sign_and_emit(&entry).await.unwrap();
        drop(signer);
        let before = snapshot(&audit);
        let keys_before = snapshot(&keys);
        let mut request = PruneRequest {
            tenant: "local".into(),
            through: 1,
            intent: PruneIntent::Preview,
        };
        assert!(matches!(
            prune_chain(&request).unwrap(),
            PruneReport::Preview { segments: 1, .. }
        ));
        assert_eq!(snapshot(&audit), before);
        assert_eq!(snapshot(&keys), keys_before);
        let active = audit.join("local.jsonl");
        let active_before = std::fs::read_to_string(&active).unwrap();
        std::fs::write(
            &active,
            active_before.replace("plan.launched", "plan.hijacked"),
        )
        .unwrap();
        let tampered = snapshot(&audit);
        request.intent = PruneIntent::AcknowledgeEvidenceRemoval;
        assert!(prune_chain(&request).is_err());
        assert_eq!(snapshot(&audit), tampered);
        std::fs::write(&active, active_before).unwrap();
        assert!(matches!(
            prune_chain(&request).unwrap(),
            PruneReport::Pruned { through: 1, .. }
        ));
        assert!(
            !audit
                .join(mvm_core::config::audit_segment_file_name("local", 1))
                .exists()
        );
    }

    fn snapshot(dir: &std::path::Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }

    #[test]
    fn preview_with_no_identity_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let request = PruneRequest {
            tenant: "local".into(),
            through: 1,
            intent: PruneIntent::Preview,
        };
        assert!(prune_chain(&request).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: PruneRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.intent, PruneIntent::Preview);
    }
}
