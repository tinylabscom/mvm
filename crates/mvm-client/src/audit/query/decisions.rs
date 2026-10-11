//! Cached decision queries; the portable decision contract is shared with provenance.

use anyhow::{Context, Result};
use mvm_contract::provenance::{DecisionId, DecisionRecord};
use mvm_hostd::audit::decisions::DecisionStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DecisionRequest {
    pub tenant: String,
    pub decision_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DecisionExportFormat {
    Json,
    Tibet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DecisionExport {
    pub records: usize,
    /// Public portable records, encoded in the requested format with a final newline.
    pub bytes: Vec<u8>,
}

fn open_store(tenant: &str) -> Result<DecisionStore> {
    super::validate_tenant(tenant)?;
    let dir = DecisionStore::default_dir().context("resolving decision store directory")?;
    DecisionStore::open(&dir, tenant)
        .with_context(|| format!("opening decision store for tenant '{tenant}'"))
}

// DecisionId's portable contract is a SHA-256 content address, not a path.
// Validate before opening the store, which can create/chmod its directory.
fn validate_decision_id(id: &str) -> Result<()> {
    anyhow::ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid decision id: expected 64 lowercase hexadecimal characters"
    );
    Ok(())
}

pub fn list_decisions(tenant: &str) -> Result<Vec<DecisionRecord>> {
    open_store(tenant)?
        .list()
        .with_context(|| format!("listing decisions for tenant '{tenant}'"))
}

pub fn get_decision(request: &DecisionRequest) -> Result<DecisionRecord> {
    validate_decision_id(&request.decision_id)?;
    let DecisionRequest {
        tenant,
        decision_id,
    } = request;
    let record = open_store(tenant)?
        .get(&DecisionId(decision_id.clone()))
        .with_context(|| format!("reading decision '{decision_id}' for tenant '{tenant}'"))?
        .with_context(|| format!("decision '{decision_id}' not found for tenant '{tenant}'"))?;
    anyhow::ensure!(
        record.decision_id.0 == *decision_id,
        "decision record does not match requested id"
    );
    Ok(record)
}

pub fn trace_decisions(request: &DecisionRequest) -> Result<Vec<DecisionRecord>> {
    validate_decision_id(&request.decision_id)?;
    let DecisionRequest {
        tenant,
        decision_id,
    } = request;
    open_store(tenant)?
        .trace_decision_chain(&DecisionId(decision_id.clone()))
        .with_context(|| format!("tracing decision chain for '{decision_id}' in tenant '{tenant}'"))
}

pub fn impact_decisions(request: &DecisionRequest) -> Result<Vec<DecisionRecord>> {
    validate_decision_id(&request.decision_id)?;
    let DecisionRequest {
        tenant,
        decision_id,
    } = request;
    open_store(tenant)?
        .analyze_decision_impact(&DecisionId(decision_id.clone()))
        .with_context(|| {
            format!("analyzing impact of decision '{decision_id}' in tenant '{tenant}'")
        })
}

pub fn similar_decisions(request: &DecisionRequest) -> Result<Vec<DecisionRecord>> {
    validate_decision_id(&request.decision_id)?;
    let DecisionRequest {
        tenant,
        decision_id,
    } = request;
    let store = open_store(tenant)?;
    let seed = store
        .get(&DecisionId(decision_id.clone()))
        .with_context(|| format!("reading seed decision '{decision_id}' in tenant '{tenant}'"))?
        .with_context(|| {
            format!("seed decision '{decision_id}' not found for tenant '{tenant}'")
        })?;
    anyhow::ensure!(
        seed.decision_id.0 == *decision_id,
        "seed decision record does not match requested id"
    );
    store.find_similar_decisions(&seed).with_context(|| {
        format!("finding similar decisions for '{decision_id}' in tenant '{tenant}'")
    })
}

pub fn export_decisions(tenant: &str, format: DecisionExportFormat) -> Result<DecisionExport> {
    let records = list_decisions(tenant)?;
    let mut bytes = match format {
        DecisionExportFormat::Json => {
            serde_json::to_vec_pretty(&records).context("serializing decision records")?
        }
        DecisionExportFormat::Tibet => {
            mvm_core::provenance::tibet::decision_records_to_tibet_json(&records).into_bytes()
        }
    };
    bytes.push(b'\n');
    Ok(DecisionExport {
        records: records.len(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_ids_cannot_read_another_tenants_valid_record() {
        use mvm_contract::provenance::{
            ActorRef, AttestationBinding, DecisionCategory, DecisionOutcome, DecisionRecordBuilder,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let record = DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Admission)
            .actor(ActorRef {
                principal: "host:builder".into(),
                key_id: "signer-1".into(),
                key_role: None,
            })
            .reasoning("grant ceiling satisfied")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-13T00:00:00Z")
            .attestation(AttestationBinding::default())
            .build()
            .unwrap();
        let other = open_store("other").unwrap();
        other.put(&record).unwrap();
        let id = &record.decision_id.0;
        let valid = DecisionRequest {
            tenant: "other".into(),
            decision_id: id.clone(),
        };
        assert_eq!(
            get_decision(&valid).unwrap().decision_id,
            record.decision_id
        );
        let absolute = dir
            .path()
            .join("decisions/other")
            .join(id)
            .to_str()
            .unwrap()
            .to_owned();
        for decision_id in [
            format!("../other/{id}"),
            absolute,
            "missing".into(),
            "A".repeat(64),
            "0".repeat(63),
            "0".repeat(65),
        ] {
            let request = DecisionRequest {
                tenant: "local".into(),
                decision_id,
            };
            assert!(
                get_decision(&request)
                    .unwrap_err()
                    .to_string()
                    .contains("invalid decision id")
            );
            assert!(similar_decisions(&request).is_err());
            assert!(trace_decisions(&request).is_err());
            assert!(impact_decisions(&request).is_err());
            assert!(!dir.path().join("decisions/local").exists());
        }
        // A valid but misplaced record must not satisfy a different requested ID.
        let local = dir.path().join("decisions/local");
        std::fs::create_dir(&local).unwrap();
        std::fs::write(
            local.join(format!("{}.json", "0".repeat(64))),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let request = DecisionRequest {
            tenant: "local".into(),
            decision_id: "0".repeat(64),
        };
        assert!(
            get_decision(&request)
                .unwrap_err()
                .to_string()
                .contains("does not match requested id")
        );
        assert!(
            similar_decisions(&request)
                .unwrap_err()
                .to_string()
                .contains("does not match requested id")
        );
    }

    #[test]
    fn missing_decision_and_empty_exports_keep_query_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        assert!(list_decisions("local").unwrap().is_empty());
        let request = DecisionRequest {
            tenant: "local".into(),
            decision_id: "0".repeat(64),
        };
        assert!(
            get_decision(&request)
                .unwrap_err()
                .to_string()
                .contains("not found")
        );
        assert!(
            similar_decisions(&request)
                .unwrap_err()
                .to_string()
                .contains("seed decision")
        );
        let exported = export_decisions("local", DecisionExportFormat::Json).unwrap();
        assert_eq!(exported.records, 0);
        assert_eq!(exported.bytes, b"[]\n");
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: DecisionRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.tenant, request.tenant);
        assert_eq!(decoded.decision_id, request.decision_id);
    }
}
