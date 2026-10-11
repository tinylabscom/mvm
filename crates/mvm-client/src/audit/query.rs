//! Audit operation boundary. Callers receive owned reports, never signing keys.

mod certificate;
pub use certificate::{
    CertificateReport, CertificateRequest, ChainMatch, DestructionReceipt, MAX_CERTIFICATE_BYTES,
    load_chain_fingerprint_index, verify_certificate,
};
mod chain;
pub use chain::{
    AppendOnlyReport, ChainVerification, PruneIntent, PruneReport, PruneRequest, PublishedRoot,
    WitnessDivergence, WitnessReport, prune_chain, publish_root, verify_chain,
};
mod decisions;
pub use decisions::{
    DecisionExport, DecisionExportFormat, DecisionRequest, export_decisions, get_decision,
    impact_decisions, list_decisions, similar_decisions, trace_decisions,
};
mod proof;
pub use proof::{
    InclusionVerification, InclusionVerifyRequest, MAX_PROOF_BYTES, ProofReport, ProofRequest,
    load_verifying_key, prove, resolve_selector, verify_inclusion, verify_inclusion_membership,
};

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Audit tenant labels may contain dots; unlike shell identifiers, they need
/// only be safe, non-special single path components on every supported host.
fn validate_tenant(tenant: &str) -> Result<()> {
    let mut components = Path::new(tenant).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
        || tenant.contains(['/', '\\', ':'])
        || tenant.chars().any(char::is_control)
    {
        bail!("invalid audit tenant: expected a non-special single path component");
    }
    Ok(())
}

/// Locate the raw local chain; the path itself makes no verification claim.
pub fn chain_file(tenant: &str) -> Result<PathBuf> {
    validate_tenant(tenant)?;
    let dir = mvm_hostd::audit::emitter::default_audit_dir()?;
    Ok(mvm_hostd::audit::emitter::audit_path_for_tenant(
        &dir, tenant,
    ))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSource {
    LocalLog,
    TenantChain,
}

/// Export the existing provenance interpretation, without implying that a
/// PROV-O conversion authenticates the input log.
pub fn export_provenance(tenant: &str, source: ProvenanceSource) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    match source {
        ProvenanceSource::LocalLog => {
            let path = mvm_core::policy::audit::default_audit_log();
            let file = std::fs::File::open(&path)
                .with_context(|| format!("opening local audit log: {path}"))?;
            mvm_core::provenance::export_local_audit_log(
                std::io::BufReader::new(file),
                &mut output,
            )
            .context("exporting local audit log to PROV-O")?;
        }
        ProvenanceSource::TenantChain => {
            let path = chain_file(tenant).context("resolving audit directory")?;
            let file = std::fs::File::open(&path)
                .with_context(|| format!("opening chain-signed audit log: {}", path.display()))?;
            mvm_core::provenance::export_tenant_audit_log(
                std::io::BufReader::new(file),
                &mut output,
            )
            .context("exporting tenant audit log to PROV-O")?;
        }
    }
    Ok(output)
}

/// Compressed and expanded archive limit enforced by the authoritative verifier.
pub const MAX_RECEIPT_ARCHIVE_BYTES: usize =
    mvm_hostd::audit::receipt_archive_verify::ARCHIVE_MAX_BYTES;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ReceiptExportRequest {
    pub tenant: String,
    pub plan_id: Option<String>,
    pub full_chain: bool,
}

impl ReceiptExportRequest {
    /// Whole-chain coverage wins over a contradictory plan filter.
    pub fn plan_scoped_archive(&self) -> bool {
        self.plan_id.is_some() && !self.full_chain
    }

    fn scope(&self) -> mvm_core::receipt_archive::ArchiveScope {
        match (&self.plan_id, self.full_chain) {
            (Some(plan_id), false) => mvm_core::receipt_archive::ArchiveScope::Plan {
                plan_id: plan_id.clone(),
            },
            _ => mvm_core::receipt_archive::ArchiveScope::Tenant,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ReceiptCitation {
    pub leaf_index: u64,
    pub digest: String,
    pub event: String,
    pub plan_id: String,
    pub timestamp: String,
}

/// Signed portable receipt contract plus explicitly cited unmapped entries.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiptEvidence {
    pub receipts: Vec<mvm_core::receipt::SignedExecutionReceipt>,
    pub cited: Vec<ReceiptCitation>,
}

pub fn export_receipts(request: &ReceiptExportRequest) -> Result<ReceiptEvidence> {
    validate_tenant(&request.tenant)?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading host signer to export receipts")?;
    let dir =
        mvm_hostd::audit::emitter::default_audit_dir().context("resolving audit directory")?;
    let evidence = mvm_hostd::audit::receipt_export::export_evidence(
        &dir,
        &request.tenant,
        request.plan_id.as_deref(),
        &signer.signing,
    )
    .with_context(|| format!("exporting receipts for tenant '{}'", request.tenant))?;
    Ok(ReceiptEvidence {
        receipts: evidence.receipts,
        cited: evidence
            .cited
            .into_iter()
            .map(|c| ReceiptCitation {
                leaf_index: c.leaf_index,
                digest: c.digest,
                event: c.event,
                plan_id: c.plan_id,
                timestamp: c.timestamp,
            })
            .collect(),
    })
}

/// Build bounded, public evidence bytes. Signing material never leaves this boundary.
pub fn export_receipt_archive(request: &ReceiptExportRequest) -> Result<Vec<u8>> {
    validate_tenant(&request.tenant)?;
    let signer = mvm_hostd::audit::host_keypair::load_or_init()
        .context("loading host signer to export receipts")?;
    let dir =
        mvm_hostd::audit::emitter::default_audit_dir().context("resolving audit directory")?;
    build_receipt_archive(request, &dir, &signer.signing)
}

fn build_receipt_archive(
    request: &ReceiptExportRequest,
    dir: &Path,
    signing: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>> {
    let req = mvm_hostd::audit::receipt_archive::ArchiveRequest::builder()
        .audit_dir(dir)
        .tenant(request.tenant.clone())
        .scope(request.scope())
        .build()?;
    let bytes = mvm_hostd::audit::receipt_archive::write_archive(&req, signing)
        .with_context(|| format!("building the evidence archive for '{}'", request.tenant))?;
    if bytes.len() > MAX_RECEIPT_ARCHIVE_BYTES {
        bail!(
            "archive is {} bytes, over the {MAX_RECEIPT_ARCHIVE_BYTES}-byte limit",
            bytes.len()
        );
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ReceiptVerifyRequest {
    pub archive: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum VerificationResult {
    #[serde(rename = "ok")]
    Passed,
    #[serde(rename = "FAILED")]
    Failed,
}

impl VerificationResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "ok",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct VerificationCheck {
    pub result: VerificationResult,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum CompletenessResult {
    #[serde(rename = "derived")]
    Derived,
    #[serde(rename = "attested")]
    Attested,
    #[serde(rename = "FAILED")]
    Failed,
}

impl CompletenessResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "derived",
            Self::Attested => "attested",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct CompletenessCheck {
    pub result: CompletenessResult,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ReceiptVerificationReport {
    pub integrity: VerificationCheck,
    pub inclusion: VerificationCheck,
    pub completeness: CompletenessCheck,
    pub exit_code: i32,
}

pub fn verify_receipts(request: &ReceiptVerifyRequest) -> Result<ReceiptVerificationReport> {
    let bytes = read_bounded(&request.archive, MAX_RECEIPT_ARCHIVE_BYTES)
        .with_context(|| format!("reading archive {}", request.archive.display()))?;
    verify_receipt_bytes(&bytes)
        .with_context(|| format!("verifying archive {}", request.archive.display()))
}

/// Run the authoritative signature, inclusion, tenant and coverage checks.
/// A report is not a blanket success: callers must inspect all three outcomes.
pub fn verify_receipt_bytes(bytes: &[u8]) -> Result<ReceiptVerificationReport> {
    use mvm_hostd::audit::receipt_archive_verify as authoritative;
    let report = authoritative::verify_archive(bytes)?;
    let exit_code = report.exit_code();
    let check = |result| match result {
        authoritative::CheckResult::Passed => VerificationCheck {
            result: VerificationResult::Passed,
            detail: None,
        },
        authoritative::CheckResult::Failed(reason) => VerificationCheck {
            result: VerificationResult::Failed,
            detail: Some(reason),
        },
    };
    let completeness = match report.completeness {
        authoritative::CompletenessResult::Derived => CompletenessCheck {
            result: CompletenessResult::Derived,
            detail: None,
        },
        authoritative::CompletenessResult::Attested => CompletenessCheck {
            result: CompletenessResult::Attested,
            detail: None,
        },
        authoritative::CompletenessResult::Failed(reason) => CompletenessCheck {
            result: CompletenessResult::Failed,
            detail: Some(reason),
        },
    };
    Ok(ReceiptVerificationReport {
        integrity: check(report.integrity),
        inclusion: check(report.inclusion),
        completeness,
        exit_code,
    })
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    read_bounded_from(std::fs::File::open(path)?, limit)
}

fn read_bounded_from(reader: impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("input exceeds the {limit}-byte limit");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_tenants_are_rejected_before_any_filesystem_side_effect() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(&home);
        let outside = dir.path().join("outside");
        let absolute = outside.to_str().unwrap();
        for tenant in [
            "",
            ".",
            "..",
            "../../outside",
            absolute,
            "a/b",
            "a\\b",
            "C:outside",
            "a\0b",
            "a\nb",
        ] {
            assert!(chain_file(tenant).is_err(), "{tenant:?}");
            assert!(export_provenance(tenant, ProvenanceSource::TenantChain).is_err());
            assert!(verify_chain(tenant).is_err());
            assert!(publish_root(tenant).is_err());
            assert!(list_decisions(tenant).is_err());
            assert!(export_decisions(tenant, DecisionExportFormat::Json).is_err());
            let decision = DecisionRequest {
                tenant: tenant.into(),
                decision_id: "0".repeat(64),
            };
            assert!(get_decision(&decision).is_err());
            assert!(trace_decisions(&decision).is_err());
            assert!(impact_decisions(&decision).is_err());
            assert!(similar_decisions(&decision).is_err());
            assert!(
                prove(&ProofRequest {
                    tenant: tenant.into(),
                    selector: "0".into()
                })
                .is_err()
            );
            assert!(
                verify_inclusion(&InclusionVerifyRequest {
                    tenant: tenant.into(),
                    proof: Vec::new(),
                    root: None,
                    pubkey: None,
                })
                .unwrap_err()
                .to_string()
                .contains("invalid audit tenant")
            );
            for intent in [
                PruneIntent::Preview,
                PruneIntent::AcknowledgeEvidenceRemoval,
            ] {
                assert!(
                    prune_chain(&PruneRequest {
                        tenant: tenant.into(),
                        through: 1,
                        intent
                    })
                    .is_err()
                );
            }
            let receipts = ReceiptExportRequest {
                tenant: tenant.into(),
                plan_id: None,
                full_chain: true,
            };
            assert!(export_receipts(&receipts).is_err());
            assert!(export_receipt_archive(&receipts).is_err());
            assert!(!outside.exists());
            assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0, "{tenant:?}");
        }
        for tenant in ["local", "acme.prod", "tenant-1", "tenant_2"] {
            assert_eq!(
                chain_file(tenant).unwrap(),
                home.join("audit").join(format!("{tenant}.jsonl"))
            );
            assert!(list_decisions(tenant).unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn archive_export_verifies_with_derived_or_attested_scope() {
        use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};
        let dir = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
        let signer = FileAuditSigner::open(key.clone(), dir.path()).unwrap();
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
        drop(signer);
        let mut request = ReceiptExportRequest {
            tenant: "local".into(),
            plan_id: Some("plan-1".into()),
            full_chain: true,
        };
        for (full_chain, expected) in [
            (true, CompletenessResult::Derived),
            (false, CompletenessResult::Attested),
        ] {
            request.full_chain = full_chain;
            let bytes = build_receipt_archive(&request, dir.path(), &key).unwrap();
            let report = verify_receipt_bytes(&bytes).unwrap();
            assert_eq!(report.integrity.result, VerificationResult::Passed);
            assert_eq!(report.inclusion.result, VerificationResult::Passed);
            assert_eq!(report.completeness.result, expected);
            assert_eq!(report.exit_code, 0);
            assert_eq!(request.plan_scoped_archive(), !full_chain);
        }
        request.tenant = "different".into();
        assert!(build_receipt_archive(&request, dir.path(), &key).is_err());
        request.tenant = "local".into();
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[18; 32]);
        assert!(build_receipt_archive(&request, dir.path(), &wrong_key).is_err());
        let path = dir.path().join("local.jsonl");
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, raw.replace("plan.launched", "plan.hijacked")).unwrap();
        assert!(build_receipt_archive(&request, dir.path(), &key).is_err());
    }

    #[test]
    fn oversized_archive_is_refused_before_parsing_or_expansion() {
        let bytes = vec![0; MAX_RECEIPT_ARCHIVE_BYTES + 1];
        let error = verify_receipt_bytes(&bytes).unwrap_err().to_string();
        assert!(error.contains("over the"));
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("oversized.mvmev");
        std::fs::File::create(&archive)
            .unwrap()
            .set_len((MAX_RECEIPT_ARCHIVE_BYTES + 1) as u64)
            .unwrap();
        assert!(verify_receipts(&ReceiptVerifyRequest { archive }).is_err());
    }

    #[test]
    fn bounded_inputs_accept_limit_and_refuse_the_next_byte() {
        assert_eq!(read_bounded_from(&b"abc"[..], 3).unwrap(), b"abc");
        assert!(read_bounded_from(&b"abcd"[..], 3).is_err());
        assert!(verify_receipt_bytes(b"not an archive").is_err());
    }

    #[test]
    fn receipt_report_preserves_cli_wire_shape() {
        let report = ReceiptVerificationReport {
            integrity: VerificationCheck {
                result: VerificationResult::Passed,
                detail: None,
            },
            inclusion: VerificationCheck {
                result: VerificationResult::Failed,
                detail: Some("mismatch".into()),
            },
            completeness: CompletenessCheck {
                result: CompletenessResult::Attested,
                detail: None,
            },
            exit_code: 1,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["integrity"],
            serde_json::json!({"result":"ok","detail":null})
        );
        assert_eq!(
            json["inclusion"],
            serde_json::json!({"result":"FAILED","detail":"mismatch"})
        );
        assert_eq!(
            json["completeness"],
            serde_json::json!({"result":"attested","detail":null})
        );
        assert_eq!(
            serde_json::from_value::<ReceiptVerificationReport>(json).unwrap(),
            report
        );
    }
}
