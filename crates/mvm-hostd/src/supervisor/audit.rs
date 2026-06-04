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
use mvm_core::plan::{ExecutionPlan, PlanId, TenantId};
use mvm_core::policy::{PolicyBundle, PolicyId};
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

    /// Construct a chain entry for a `FlowOpened` event ([Plan 102
    /// W6.A](../../specs/plans/103-w6a-implementation-tracker.md) /
    /// [ADR-058](../../specs/adrs/058-claim-10-bytes-leaving-trust-boundary.md)
    /// claim 10 leg 2). The gateway bridge calls this on the first
    /// byte per direction of a new flow.
    pub fn flow_opened(
        plan: &ExecutionPlan,
        bundle: Option<&PolicyBundle>,
        flow_id: &str,
        direction: FlowDirection,
    ) -> Self {
        Self::for_plan(
            plan,
            bundle,
            FLOW_OPENED_EVENT,
            [
                ("flow_id".to_string(), flow_id.to_string()),
                ("direction".to_string(), direction.as_str().to_string()),
            ],
        )
    }

    /// Construct a chain entry for a `FlowClosed` event. Pairs with
    /// [`Self::flow_opened`] on the same `flow_id`. `reason` carries
    /// the close discriminator (EOF / bridge fault / policy drop /
    /// shutdown).
    pub fn flow_closed(
        plan: &ExecutionPlan,
        bundle: Option<&PolicyBundle>,
        flow_id: &str,
        direction: FlowDirection,
        reason: FlowCloseReason,
    ) -> Self {
        Self::for_plan(
            plan,
            bundle,
            FLOW_CLOSED_EVENT,
            [
                ("flow_id".to_string(), flow_id.to_string()),
                ("direction".to_string(), direction.as_str().to_string()),
                ("reason".to_string(), reason.as_str().to_string()),
            ],
        )
    }
}

/// Canonical `event` string for a `FlowOpened` chain entry. Pinned
/// so downstream parsers (mvmd tenant audit rollup, `mvmctl audit
/// traffic`) can filter on a stable literal.
pub const FLOW_OPENED_EVENT: &str = "gateway.flow_opened";

/// Canonical `event` string for a `FlowClosed` chain entry.
pub const FLOW_CLOSED_EVENT: &str = "gateway.flow_closed";

/// Per-direction flow label for [`AuditEntry::flow_opened`] /
/// [`AuditEntry::flow_closed`]. Egress = guest → internet,
/// Ingress = internet → guest. North-south only — east-west
/// microVM ↔ microVM lateral flows are out of W6 scope
/// ([ADR-058](../../specs/adrs/058-claim-10-bytes-leaving-trust-boundary.md)
/// out-of-scope list, deferred to W11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Egress,
    Ingress,
}

impl FlowDirection {
    /// Stable wire string for label values. Matches the
    /// `#[serde(rename_all = "snake_case")]` derive output;
    /// pinned so downstream parsers don't drift.
    pub fn as_str(self) -> &'static str {
        match self {
            FlowDirection::Egress => "egress",
            FlowDirection::Ingress => "ingress",
        }
    }
}

/// Close discriminator for [`AuditEntry::flow_closed`]. Plan 102
/// W6.A commit 3.
///
/// `Eof` is the steady-state happy path (TCP FIN, UDP timeout,
/// DGRAM peer closed). `BridgeError` covers bridge-task panic
/// catch / I/O error / drop guard. `PolicyDropped` is the
/// `FlowPolicy` hook returning `FlowAction::Drop` — substrate
/// for Plan 74 enforcement to plug in. `Shutdown` covers graceful
/// supervisor teardown (Vz Swift bridge cancellation, libkrun
/// `exit()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowCloseReason {
    Eof,
    BridgeError,
    PolicyDropped,
    Shutdown,
}

impl FlowCloseReason {
    /// Stable wire string for label values.
    pub fn as_str(self) -> &'static str {
        match self {
            FlowCloseReason::Eof => "eof",
            FlowCloseReason::BridgeError => "bridge_error",
            FlowCloseReason::PolicyDropped => "policy_dropped",
            FlowCloseReason::Shutdown => "shutdown",
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
    use chrono::TimeZone;
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
        KeyRotationSpec, Nonce, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
        RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef, TimeoutSpec, WorkloadId,
    };
    use mvm_core::policy::{
        AuditPolicy, EgressPolicy, KeyPolicy, NetworkPolicy, PiiPolicy, ToolPolicy,
    };
    use std::collections::BTreeMap;

    fn sample_plan() -> ExecutionPlan {
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
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
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
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
            // G4 (plan 37 Addendum G4) replay-protection fields.
            valid_from: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
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
            artifact: mvm_core::policy::policies::ArtifactPolicy::default(),
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

    // -----------------------------------------------------------------
    // Plan 102 W6.A commit 3 — gateway flow event types + helpers.
    // -----------------------------------------------------------------

    #[test]
    fn flow_direction_wire_strings_pinned() {
        // Downstream parsers (mvmd tenant audit rollup, mvmctl audit
        // traffic) filter on these literals; a rename here would
        // silently break them. Both serde and `as_str` must agree.
        assert_eq!(FlowDirection::Egress.as_str(), "egress");
        assert_eq!(FlowDirection::Ingress.as_str(), "ingress");
        assert_eq!(
            serde_json::to_string(&FlowDirection::Egress).unwrap(),
            "\"egress\""
        );
        assert_eq!(
            serde_json::to_string(&FlowDirection::Ingress).unwrap(),
            "\"ingress\""
        );
    }

    #[test]
    fn flow_close_reason_wire_strings_pinned() {
        // Same contract as flow_direction. Four reasons cover the
        // close discriminators the bridge can emit in W6.A:
        // Eof (steady-state), BridgeError (drop guard), PolicyDropped
        // (FlowPolicy hook returns Drop), Shutdown (graceful teardown).
        let cases = [
            (FlowCloseReason::Eof, "eof"),
            (FlowCloseReason::BridgeError, "bridge_error"),
            (FlowCloseReason::PolicyDropped, "policy_dropped"),
            (FlowCloseReason::Shutdown, "shutdown"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.as_str(), expected);
            assert_eq!(
                serde_json::to_string(&variant).unwrap(),
                format!("\"{expected}\"")
            );
        }
    }

    #[test]
    fn flow_direction_serde_roundtrip() {
        for variant in [FlowDirection::Egress, FlowDirection::Ingress] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: FlowDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn flow_close_reason_serde_roundtrip() {
        for variant in [
            FlowCloseReason::Eof,
            FlowCloseReason::BridgeError,
            FlowCloseReason::PolicyDropped,
            FlowCloseReason::Shutdown,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let parsed: FlowCloseReason = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn flow_opened_helper_carries_canonical_event_and_labels() {
        let plan = sample_plan();
        let entry = AuditEntry::flow_opened(&plan, None, "f00ba4", FlowDirection::Egress);

        assert_eq!(entry.event, FLOW_OPENED_EVENT);
        assert_eq!(entry.event, "gateway.flow_opened");
        assert_eq!(entry.labels.get("flow_id"), Some(&"f00ba4".to_string()));
        assert_eq!(entry.labels.get("direction"), Some(&"egress".to_string()));
        // Plan binding still in place — same shape as for_plan().
        assert_eq!(entry.plan_id, plan.plan_id);
        assert_eq!(entry.tenant, plan.tenant);
    }

    #[test]
    fn flow_closed_helper_carries_canonical_event_and_labels() {
        let plan = sample_plan();
        let entry = AuditEntry::flow_closed(
            &plan,
            None,
            "f00ba4",
            FlowDirection::Ingress,
            FlowCloseReason::Eof,
        );

        assert_eq!(entry.event, FLOW_CLOSED_EVENT);
        assert_eq!(entry.event, "gateway.flow_closed");
        assert_eq!(entry.labels.get("flow_id"), Some(&"f00ba4".to_string()));
        assert_eq!(entry.labels.get("direction"), Some(&"ingress".to_string()));
        assert_eq!(entry.labels.get("reason"), Some(&"eof".to_string()));
    }

    #[test]
    fn flow_helpers_inherit_plan_audit_labels() {
        // The bridge runs alongside the plan; the chain must carry
        // the plan's audit_labels so a forensics pass can answer
        // "what workload was this flow attributed to?" without
        // dereferencing plan_id separately.
        let plan = sample_plan(); // sample_plan adds workflow=etl-1.
        let entry = AuditEntry::flow_opened(&plan, None, "f1", FlowDirection::Egress);
        assert_eq!(entry.labels.get("workflow"), Some(&"etl-1".to_string()));
    }

    #[test]
    fn flow_closed_reason_variants_distinguishable_on_wire() {
        // The four reasons MUST serialize differently — collapsing
        // any two would prevent downstream tooling from distinguishing
        // a steady-state close from a policy drop or a bridge fault.
        let plan = sample_plan();
        let mut emitted = std::collections::BTreeSet::new();
        for reason in [
            FlowCloseReason::Eof,
            FlowCloseReason::BridgeError,
            FlowCloseReason::PolicyDropped,
            FlowCloseReason::Shutdown,
        ] {
            let entry = AuditEntry::flow_closed(&plan, None, "f1", FlowDirection::Egress, reason);
            emitted.insert(entry.labels.get("reason").cloned().unwrap());
        }
        assert_eq!(emitted.len(), 4, "all four reasons must be distinguishable");
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
