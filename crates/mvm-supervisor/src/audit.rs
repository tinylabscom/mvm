//! Audit signer slot. Wave 3 — chain-signed audit stream.
//!
//! Plan 37 §22: the supervisor signs each audit entry into the
//! previous entry's hash, producing a tamper-evident chain. Per
//! `mvm-policy::AuditPolicy`, entries can also be replicated to
//! per-tenant streams. Wave 1.3 ships the trait surface; Wave 3
//! wires the real chain-signing impl.

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mvm_plan::{ExecutionPlan, PlanId, TenantId};
use mvm_policy::{PolicyBundle, PolicyId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One audit-stream entry. Plan 37 §22's "audit binding" — every
/// entry references the plan, the policy bundle, and the image
/// that were in force when the event happened. A runbook can
/// answer "what was the runtime contract at the moment of incident?"
/// in O(1) by reading any one entry, without re-deriving from logs.
///
/// `bundle_id` + `bundle_version` are `Option`-typed because audit
/// entries can be emitted before policy resolution lands (Wave 2)
/// or in degraded modes where no bundle is available (e.g. `--dev`
/// override). When present they carry the same `(id, version)`
/// shape the bundle itself does.
///
/// Wave 3's `AuditSigner` real impl wraps this struct in a
/// chain-signed envelope (each entry's signature includes the
/// previous entry's hash, producing a tamper-evident stream).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub tenant: TenantId,

    pub plan_id: PlanId,
    pub plan_version: u32,

    /// Bundle id at the moment the event happened. Optional because
    /// some events emit before the policy has been resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<PolicyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<u32>,

    /// Image SHA-256 the workload was running. Always recorded
    /// because the image is fixed at plan-verification time
    /// (the plan carries `SignedImageRef`).
    pub image_name: String,
    pub image_sha256: String,

    pub event: String,

    /// Free-form labels. Inherits `audit_labels` from the plan plus
    /// per-event extras the supervisor adds.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

impl AuditEntry {
    /// Construct an audit entry bound to a plan + (optional) bundle.
    /// Plan `audit_labels` are merged into the entry's labels;
    /// per-event extras override on collision.
    pub fn for_plan(
        plan: &ExecutionPlan,
        bundle: Option<&PolicyBundle>,
        event: impl Into<String>,
        extras: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        let mut labels = plan.audit_labels.clone();
        labels.extend(extras);
        Self {
            timestamp: Utc::now(),
            tenant: plan.tenant.clone(),
            plan_id: plan.plan_id.clone(),
            plan_version: plan.plan_version,
            bundle_id: bundle.map(|b| b.bundle_id.clone()),
            bundle_version: bundle.map(|b| b.bundle_version),
            image_name: plan.image.name.clone(),
            image_sha256: plan.image.sha256.to_ascii_lowercase(),
            event: event.into(),
            labels,
        }
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit signer not wired (Noop slot)")]
    NotWired,

    #[error("io error writing audit entry: {0}")]
    Io(String),
}

#[async_trait]
pub trait AuditSigner: Send + Sync {
    /// Sign and persist one entry. Wave 3's chain-signing impl
    /// computes `prev_hash` from the previous entry, derives the
    /// current entry's signature, and writes both to the audit
    /// stream destination(s).
    async fn sign_and_emit(&self, entry: &AuditEntry) -> Result<(), AuditError>;
}

pub struct NoopAuditSigner;

#[async_trait]
impl AuditSigner for NoopAuditSigner {
    async fn sign_and_emit(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
        Err(AuditError::NotWired)
    }
}

/// Test/dev signer that records every emitted entry into an
/// in-memory `Vec`. Use cases:
/// - unit tests assert the supervisor emitted the expected entries
/// - dev mode without persistent storage
///
/// Wave 3's chain-signing real impl will replace this for production,
/// but keep this around for `cargo test` and `mvmctl --dev`.
pub struct CapturingAuditSigner {
    entries: Mutex<Vec<AuditEntry>>,
}

impl CapturingAuditSigner {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries
            .lock()
            .expect("CapturingAuditSigner mutex poisoned")
            .clone()
    }
}

impl Default for CapturingAuditSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuditSigner for CapturingAuditSigner {
    async fn sign_and_emit(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        self.entries
            .lock()
            .expect("CapturingAuditSigner mutex poisoned")
            .push(entry.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_plan::{
        ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef, KeyRotationSpec,
        PolicyRef, PostRunLifecycle, Resources, RuntimeProfileRef, SignedImageRef, TimeoutSpec,
        WorkloadId,
    };
    use mvm_policy::{AuditPolicy, EgressPolicy, KeyPolicy, NetworkPolicy, PiiPolicy, ToolPolicy};
    use std::collections::BTreeMap;

    fn sample_plan() -> ExecutionPlan {
        ExecutionPlan {
            schema_version: 1,
            plan_id: PlanId("plan-x".to_string()),
            plan_version: 7,
            tenant: TenantId("tenant-a".to_string()),
            workload: WorkloadId("workload-1".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "tenant-worker-aarch64".to_string(),
                sha256: "ABC123".to_string(), // mixed case → entry should normalise
                cosign_bundle: None,
            },
            resources: Resources {
                cpus: 2,
                mem_mib: 1024,
                disk_mib: 4096,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 600,
                },
            },
            network_policy: PolicyRef("n".to_string()),
            fs_policy: FsPolicyRef("f".to_string()),
            secrets: vec![],
            egress_policy: PolicyRef("e".to_string()),
            tool_policy: PolicyRef("t".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec![],
                retention_days: 0,
            },
            audit_labels: BTreeMap::from([("workflow".to_string(), "etl-1".to_string())]),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
        }
    }

    fn sample_bundle() -> PolicyBundle {
        PolicyBundle {
            schema_version: 1,
            bundle_id: PolicyId("bundle-y".to_string()),
            bundle_version: 3,
            network: NetworkPolicy::default(),
            egress: EgressPolicy::default(),
            pii: PiiPolicy::default(),
            tool: ToolPolicy::default(),
            artifact: mvm_policy::policies::ArtifactPolicy::default(),
            keys: KeyPolicy::default(),
            audit: AuditPolicy::default(),
            tenant_overlays: BTreeMap::new(),
        }
    }

    #[test]
    fn noop_audit_signer_is_constructable() {
        let _: Box<dyn AuditSigner> = Box::new(NoopAuditSigner);
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            tenant: TenantId("t".to_string()),
            plan_id: PlanId("p".to_string()),
            plan_version: 1,
            bundle_id: Some(PolicyId("b".to_string())),
            bundle_version: Some(2),
            image_name: "img".to_string(),
            image_sha256: "deadbeef".to_string(),
            event: "plan.verified".to_string(),
            labels: BTreeMap::from([("actor".to_string(), "supervisor".to_string())]),
        };
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_for_plan_binds_plan_bundle_image() {
        let plan = sample_plan();
        let bundle = sample_bundle();
        let entry = AuditEntry::for_plan(&plan, Some(&bundle), "plan.verified", []);
        assert_eq!(entry.plan_id, plan.plan_id);
        assert_eq!(entry.plan_version, plan.plan_version);
        assert_eq!(entry.tenant, plan.tenant);
        assert_eq!(entry.bundle_id, Some(bundle.bundle_id.clone()));
        assert_eq!(entry.bundle_version, Some(bundle.bundle_version));
        assert_eq!(entry.image_name, plan.image.name);
        // SHA is normalised to lowercase regardless of plan input.
        assert_eq!(entry.image_sha256, "abc123");
        assert_eq!(entry.event, "plan.verified");
        // Plan's audit_labels merged in.
        assert_eq!(entry.labels.get("workflow"), Some(&"etl-1".to_string()));
    }

    #[test]
    fn entry_for_plan_handles_missing_bundle() {
        let plan = sample_plan();
        let entry = AuditEntry::for_plan(&plan, None, "plan.verified", []);
        assert_eq!(entry.bundle_id, None);
        assert_eq!(entry.bundle_version, None);
        // Image still bound from plan.
        assert_eq!(entry.image_name, plan.image.name);
    }

    #[test]
    fn entry_for_plan_extras_override_plan_labels() {
        let plan = sample_plan(); // has workflow=etl-1
        let entry = AuditEntry::for_plan(
            &plan,
            None,
            "evt",
            [("workflow".to_string(), "override".to_string())],
        );
        assert_eq!(entry.labels.get("workflow"), Some(&"override".to_string()));
    }

    #[test]
    fn capturing_audit_signer_records_entries() {
        let signer = CapturingAuditSigner::new();
        let plan = sample_plan();
        let entry = AuditEntry::for_plan(&plan, None, "plan.verified", []);

        // Sync block_on via a fresh tokio runtime — the trait method
        // is async; mvm-supervisor's tokio dev-dep covers this.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            signer.sign_and_emit(&entry).await.unwrap();
            signer.sign_and_emit(&entry).await.unwrap();
        });

        let captured = signer.entries();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0], entry);
    }
}
