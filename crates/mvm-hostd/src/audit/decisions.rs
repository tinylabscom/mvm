//! Content-addressed decision store.
//!
//! Decision records are a derived, read-only view over the chain-signed audit
//! log. The log remains the source of truth; this store only caches records
//! that have already been authenticated so they can be queried without
//! replaying the whole chain.
//!
//! Layout under the decisions directory (defaults to `~/.mvm/decisions/`):
//!
//! ```text
//! <decisions_dir>/<tenant>/
//!   .lock
//!   <decision_id>.json   one canonical decision record per file
//! ```
//!
//! Files are named by the decision's content-address, so the store is
//! idempotent: writing the same record twice lands at the same path. The
//! store can be deleted and rebuilt by replaying verified `decision_record`
//! events from `tenant.jsonl`.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_contract::provenance::{DecisionId, DecisionRecord};

use crate::audit::emitter::write_atomic;
use crate::supervisor::audit_file::{flock_exclusive, verify_audit_chain_entries};

/// File-backed content-addressed store for one tenant's decision records.
#[derive(Debug, Clone)]
pub struct DecisionStore {
    tenant_dir: PathBuf,
    lock_path: PathBuf,
}

impl DecisionStore {
    /// Open (and create if missing) the decision store for `tenant` under
    /// `decisions_dir`.
    pub fn open(decisions_dir: &Path, tenant: &str) -> Result<Self> {
        let tenant_dir = decisions_dir.join(tenant);
        std::fs::create_dir_all(&tenant_dir)
            .with_context(|| format!("creating decision store dir {}", tenant_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&tenant_dir, perms).with_context(|| {
                format!(
                    "setting 0700 on decision store dir {}",
                    tenant_dir.display()
                )
            })?;
        }
        let lock_path = tenant_dir.join(".lock");
        Ok(Self {
            tenant_dir,
            lock_path,
        })
    }

    /// Default decision-store directory: `~/.mvm/decisions/` (respects
    /// `MVM_HOME`).
    pub fn default_dir() -> Result<PathBuf> {
        Ok(mvm_core::config::mvm_home_strict()?.join("decisions"))
    }

    /// Persist a decision record if it is not already stored.
    ///
    /// Verifies the content-address before writing so a corrupted or
    /// tampered record cannot enter the cache.
    pub fn put(&self, record: &DecisionRecord) -> Result<DecisionId> {
        let _guard = self.lock()?;
        if !record.verify_id() {
            anyhow::bail!("decision record id does not match its body");
        }
        let id = record.decision_id.clone();
        let path = self.path_for(&id);
        if !path.exists() {
            let bytes = serde_json::to_vec_pretty(record).context("serializing decision record")?;
            write_atomic(&path, &bytes).context("writing decision record")?;
        }
        Ok(id)
    }

    /// Read a decision record by id, verifying its content-address.
    pub fn get(&self, id: &DecisionId) -> Result<Option<DecisionRecord>> {
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading decision record {}", path.display()))?;
        let record: DecisionRecord = serde_json::from_str(&text)
            .with_context(|| format!("parsing decision record {}", path.display()))?;
        if !record.verify_id() {
            anyhow::bail!(
                "corrupted decision record: id mismatch at {}",
                path.display()
            );
        }
        Ok(Some(record))
    }

    /// List all cached decision records for this tenant, sorted by id.
    pub fn list(&self) -> Result<Vec<DecisionRecord>> {
        let _guard = self.lock()?;
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&self.tenant_dir)
            .with_context(|| format!("reading decision store {}", self.tenant_dir.display()))?
            .flatten()
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".json") || name.starts_with('.') {
                continue;
            }
            let text = std::fs::read_to_string(entry.path())
                .with_context(|| format!("reading decision record {}", entry.path().display()))?;
            let record: DecisionRecord = serde_json::from_str(&text)
                .with_context(|| format!("parsing decision record {}", entry.path().display()))?;
            if !record.verify_id() {
                tracing::warn!(
                    decision_id = %record.decision_id.0,
                    path = %entry.path().display(),
                    "skipping corrupted decision record with id mismatch"
                );
                continue;
            }
            records.push(record);
        }
        records.sort_by(|a, b| a.decision_id.0.cmp(&b.decision_id.0));
        Ok(records)
    }

    /// Rebuild the store by replaying verified `decision_record` events from
    /// the tenant's chain-signed audit log.
    pub fn rebuild_from_chain(
        &self,
        audit_path: &Path,
        verifying_key: &VerifyingKey,
    ) -> Result<()> {
        let entries = verify_audit_chain_entries(audit_path, verifying_key)
            .map_err(|e| anyhow::anyhow!("audit chain verification failed during rebuild: {e}"))?;
        for entry in entries {
            if entry.event != "decision_record" {
                continue;
            }
            let Some(record_json) = entry.labels.get("record") else {
                continue;
            };
            let record: DecisionRecord = serde_json::from_str(record_json).with_context(|| {
                format!(
                    "parsing decision record from audit entry for tenant {}",
                    entry.tenant.0
                )
            })?;
            if !record.verify_id() {
                tracing::warn!(
                    tenant = %entry.tenant.0,
                    decision_id = %record.decision_id.0,
                    "rebuilt decision record id mismatch; skipping"
                );
                continue;
            }
            self.put(&record)?;
        }
        Ok(())
    }

    fn path_for(&self, id: &DecisionId) -> PathBuf {
        self.tenant_dir.join(format!("{}.json", id.0))
    }

    fn lock(&self) -> Result<LockGuard> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("opening decision store lock {}", self.lock_path.display()))?;
        flock_exclusive(&file)
            .with_context(|| format!("locking decision store {}", self.lock_path.display()))?;
        Ok(LockGuard { _file: file })
    }
}

/// Holds the decision store's exclusive lock for as long as it is alive.
struct LockGuard {
    _file: std::fs::File,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::provenance::{
        ActorRef, AttestationBinding, DecisionCategory, DecisionOutcome, DecisionRecordBuilder,
    };

    fn sample_record(plan_id: &str) -> DecisionRecord {
        DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Admission)
            .actor(ActorRef {
                principal: "host:builder".to_string(),
                key_id: "signer-1".to_string(),
                key_role: None,
            })
            .reasoning("grant ceiling satisfied")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-13T00:00:00Z".to_string())
            .attestation(AttestationBinding {
                plan_id: Some(plan_id.to_string()),
                audit_entry_hash: "sha256:entryhash".to_string(),
                signer_pubkey: "ed25519:pubkey".to_string(),
                ..AttestationBinding::default()
            })
            .build()
            .expect("valid record")
    }

    #[test]
    fn put_and_get_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DecisionStore::open(tmp.path(), "local").unwrap();
        let record = sample_record("plan-a");
        let id = store.put(&record).unwrap();
        let got = store.get(&id).unwrap().expect("record exists");
        assert_eq!(record, got);
    }

    #[test]
    fn put_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DecisionStore::open(tmp.path(), "local").unwrap();
        let record = sample_record("plan-a");
        let id1 = store.put(&record).unwrap();
        let id2 = store.put(&record).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn get_unknown_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DecisionStore::open(tmp.path(), "local").unwrap();
        assert!(
            store
                .get(&DecisionId("nope".to_string()))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn list_returns_sorted_records() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DecisionStore::open(tmp.path(), "local").unwrap();
        let r1 = sample_record("plan-a");
        let mut r2 = sample_record("plan-b");
        r2.reasoning = "second decision".to_string();
        r2.decision_id = r2.compute_id();
        store.put(&r1).unwrap();
        store.put(&r2).unwrap();
        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].decision_id.0 < list[1].decision_id.0);
    }

    #[test]
    fn put_refuses_id_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let store = DecisionStore::open(tmp.path(), "local").unwrap();
        let mut record = sample_record("plan-a");
        record.decision_id = DecisionId("tampered".to_string());
        assert!(store.put(&record).is_err());
    }

    #[test]
    fn rebuild_from_chain_recovers_decision_records() {
        use crate::audit::emitter::AuditEmitter;
        use ed25519_dalek::SigningKey;
        use mvm_contract::provenance::{
            ActorRef, AttestationBinding, DecisionCategory, DecisionOutcome, DecisionRecordBuilder,
        };

        let audit_dir = tempfile::tempdir().unwrap();
        let key = {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            SigningKey::from_bytes(&seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, audit_dir.path())
            .unwrap()
            .with_decisions_dir(tempfile::tempdir().unwrap().path());
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();

        let record = DecisionRecordBuilder::new()
            .version(1)
            .category(DecisionCategory::Admission)
            .actor(ActorRef {
                principal: "host:builder".to_string(),
                key_id: "host-signer-1".to_string(),
                key_role: None,
            })
            .reasoning("grant ceiling satisfied")
            .outcome(DecisionOutcome::Approved)
            .timestamp("2026-08-13T00:00:00Z".to_string())
            .attestation(AttestationBinding {
                plan_id: Some("sha256:abc".to_string()),
                audit_entry_hash: String::new(),
                signer_pubkey: "ed25519:pubkey".to_string(),
                ..AttestationBinding::default()
            })
            .build()
            .expect("valid record");

        let id = emitter.emit_decision_record(&plan, record.clone()).unwrap();

        let rebuild_dir = tempfile::tempdir().unwrap();
        let store = DecisionStore::open(rebuild_dir.path(), "local").unwrap();
        let audit_path = audit_dir.path().join("local.jsonl");
        store.rebuild_from_chain(&audit_path, &vk).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].decision_id, id);
        assert_eq!(list[0].category, DecisionCategory::Admission);
    }
}
