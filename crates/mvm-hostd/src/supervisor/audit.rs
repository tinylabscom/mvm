//! Audit signer slot — chain-signed audit stream.
//!
//! The supervisor signs each audit entry into the previous entry's
//! hash, producing a tamper-evident chain. Per
//! `mvm-core::policy::AuditPolicy`, entries can also be replicated to
//! per-tenant streams. This module ships the trait surface; the real
//! chain-signing impl is wired separately.

use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mvm_core::plan::{ExecutionPlan, PlanId, TenantId};
use mvm_core::policy::{PolicyBundle, PolicyId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One audit-stream entry — the "audit binding": every entry
/// Canonical chain-signed audit entry used by the host.
///
/// This is the typed instantiation of [`mvm_contract::verify::PlanAuditEntry`]:
/// `TenantId`, `PlanId`, and `PolicyId` upstream serialize as bare strings, so
/// the JSON shape matches the browser verifier while the host keeps strongly
/// typed identifiers internally.
pub type PlanAuditEntry =
    mvm_contract::verify::PlanAuditEntry<TenantId, PlanId, PolicyId, DateTime<Utc>>;

/// On-disk representation of one host audit line.
pub type SignedEnvelope = mvm_contract::verify::SignedEnvelope<PlanAuditEntry>;

/// Construct an audit entry bound to a plan + (optional) bundle.
/// The plan's `audit_labels` are merged into the entry's labels;
/// per-event extras override on collision.
pub fn for_plan(
    plan: &ExecutionPlan,
    bundle: Option<&PolicyBundle>,
    event: impl Into<String>,
    extras: impl IntoIterator<Item = (String, String)>,
) -> PlanAuditEntry {
    let mut labels = plan.audit_labels.clone();
    labels.extend(extras);
    PlanAuditEntry {
        timestamp: Utc::now(),
        tenant: plan.tenant.clone(),
        plan_id: plan.plan_id.clone(),
        plan_version: plan.plan_version,
        bundle_id: bundle.map(|b| b.bundle_id.clone()),
        bundle_version: bundle.map(|b| b.bundle_version),
        image_name: plan.image.name.clone(),
        image_sha256: plan.image.sha256.to_ascii_lowercase(),
        event: event.into(),
        caller_commitment: plan.caller_commitment.clone(),
        labels,
    }
}

/// Construct a chain entry for a `FlowOpened` event (claim 10
/// leg 2: bytes leaving the trust boundary). The gateway bridge
/// calls this on the first byte per direction of a new flow.
pub fn flow_opened(
    plan: &ExecutionPlan,
    bundle: Option<&PolicyBundle>,
    flow_id: &str,
    direction: FlowDirection,
) -> PlanAuditEntry {
    for_plan(
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
/// [`flow_opened`] on the same `flow_id`. `reason` carries
/// the close discriminator (EOF / bridge fault / policy drop /
/// shutdown).
pub fn flow_closed(
    plan: &ExecutionPlan,
    bundle: Option<&PolicyBundle>,
    flow_id: &str,
    direction: FlowDirection,
    reason: FlowCloseReason,
) -> PlanAuditEntry {
    for_plan(
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

/// Construct a chain entry recording that a host-allowlisted observer
/// forced a fail-closed flow kill. `reason` is one of `drop` /
/// `modify_over_mtu` / `modify_unserializable`. The
/// entry attributes the `observer` so an operator can answer "which
/// observer killed this flow and why?" from the signed chain alone.
pub fn flow_observer_fault(
    plan: &ExecutionPlan,
    bundle: Option<&PolicyBundle>,
    flow_id: &str,
    direction: FlowDirection,
    observer: &str,
    reason: &str,
) -> PlanAuditEntry {
    for_plan(
        plan,
        bundle,
        FLOW_OBSERVER_FAULT_EVENT,
        [
            ("flow_id".to_string(), flow_id.to_string()),
            ("direction".to_string(), direction.as_str().to_string()),
            ("observer".to_string(), observer.to_string()),
            ("reason".to_string(), reason.to_string()),
        ],
    )
}

/// Construct the chain entry that authenticates a sealed transcript's
/// ciphertext-manifest root without exposing payload bytes or plaintext
/// digests to the audit stream.
pub fn transcript_sealed(
    plan: &ExecutionPlan,
    bundle: Option<&PolicyBundle>,
    capture_id: &str,
    vm_name: &str,
    sealed_root_hex: &str,
    chunk_count: usize,
    adopted: bool,
) -> PlanAuditEntry {
    for_plan(
        plan,
        bundle,
        TRANSCRIPT_SEALED_EVENT,
        [
            (LABEL_CAPTURE_ID.to_string(), capture_id.to_string()),
            (LABEL_VM_NAME.to_string(), vm_name.to_string()),
            (
                LABEL_TRANSCRIPT_ROOT.to_string(),
                sealed_root_hex.to_string(),
            ),
            (LABEL_CHUNK_COUNT.to_string(), chunk_count.to_string()),
            // A rebuilt seal cannot account for records the departed writer
            // shed after its last durable append, so an entry that did not say
            // so would attest a floor as if it were the whole capture.
            (LABEL_ADOPTED.to_string(), adopted.to_string()),
        ],
    )
}

pub const FLOW_OPENED_EVENT: &str = "gateway.flow_opened";

/// Canonical `event` string for a `FlowClosed` chain entry.
pub const FLOW_CLOSED_EVENT: &str = "gateway.flow_closed";

/// Canonical `event` string for a `FlowObserverFault` chain entry —
/// emitted when a host-allowlisted observer's `Modify`/`Drop` forced a
/// fail-closed flow kill.
pub const FLOW_OBSERVER_FAULT_EVENT: &str = "gateway.flow_observer_fault";

/// Canonical chain event and labels for a sealed transcript content address.
pub const TRANSCRIPT_SEALED_EVENT: &str = "gateway.transcript_sealed";
/// Label containing the transcript capture identifier.
pub const LABEL_CAPTURE_ID: &str = "capture_id";
/// Label containing the VM identity bound into the transcript root.
pub const LABEL_VM_NAME: &str = "vm_name";
/// Label containing the authenticated ciphertext-manifest root.
pub const LABEL_TRANSCRIPT_ROOT: &str = "transcript_root";
/// Label containing the number of ordered ciphertext chunks.
pub const LABEL_CHUNK_COUNT: &str = "chunk_count";

/// Whether the seal was rebuilt from the journal rather than written by the
/// process that owned the capture. `true` marks an incomplete record.
pub const LABEL_ADOPTED: &str = "adopted";

/// Per-direction flow label for [`flow_opened`] /
/// [`flow_closed`]. Egress = guest → internet,
/// Ingress = internet → guest. North-south only — east-west
/// microVM ↔ microVM lateral flows are out of scope here, deferred.
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

/// Close discriminator for [`flow_closed`].
///
/// `Eof` is the steady-state happy path (TCP FIN, UDP timeout,
/// DGRAM peer closed). `BridgeError` covers bridge-task panic
/// catch / I/O error / drop guard. `PolicyDropped` is the
/// `FlowPolicy` hook returning `FlowAction::Drop` — the substrate
/// enforcement plugs into. `Shutdown` covers graceful
/// supervisor teardown (libkrun
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

    /// The tenant stream's last record has no terminating newline, so a
    /// previous append died mid-write. Chaining onto it would hash a partial
    /// record, and every later entry would then verify against a prefix no
    /// signer ever produced. Refuse rather than extend a chain from a record
    /// that was never completed.
    #[error("audit stream {path} ends mid-record; refusing to chain onto a partial write")]
    TruncatedTail { path: String },
}

#[async_trait]
pub trait AuditSigner: Send + Sync {
    /// Sign and persist one entry. The chain-signing impl computes
    /// `prev_hash` from the previous entry, derives the current
    /// entry's signature, and writes both to the audit stream
    /// destination(s).
    async fn sign_and_emit(&self, entry: &PlanAuditEntry) -> Result<(), AuditError>;
}

pub struct NoopAuditSigner;

#[async_trait]
impl AuditSigner for NoopAuditSigner {
    async fn sign_and_emit(&self, _entry: &PlanAuditEntry) -> Result<(), AuditError> {
        Err(AuditError::NotWired)
    }
}

/// Test/dev signer that records every emitted entry into an
/// in-memory `Vec`. Use cases:
/// - unit tests assert the supervisor emitted the expected entries
/// - dev mode without persistent storage
///
/// The chain-signing real impl will replace this for production,
/// but keep this around for `cargo test` and `mvmctl --dev`.
pub struct CapturingAuditSigner {
    entries: Mutex<Vec<PlanAuditEntry>>,
}

impl CapturingAuditSigner {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn entries(&self) -> Vec<PlanAuditEntry> {
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
    async fn sign_and_emit(&self, entry: &PlanAuditEntry) -> Result<(), AuditError> {
        self.entries
            .lock()
            .expect("CapturingAuditSigner mutex poisoned")
            .push(entry.clone());
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use chrono::TimeZone;
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
        KeyRotationSpec, Nonce, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
        RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef, TimeoutSpec, WorkloadId,
    };
    use mvm_core::policy::{
        AuditPolicy, BundleNetworkPolicy, EgressPolicy, KeyPolicy, PiiPolicy, ToolPolicy,
    };
    use std::collections::BTreeMap;

    pub(crate) fn sample_plan() -> ExecutionPlan {
        ExecutionPlan {
            grants: None,
            environment: None,
            build_provenance: Default::default(),
            snapshot_at: Default::default(),
            network_mode: Default::default(),
            stream_retention: Default::default(),
            ingress: Vec::new(),
            network_limits: Default::default(),
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
                entrypoint_present: true,
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
            redaction: Default::default(),
            reversible_replacement: Default::default(),
            tool_policy: PolicyRef("t".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec![],
                retention_days: 0,
            },
            caller_commitment: None,
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
            // G4 replay-protection fields.
            valid_from: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
            asset_identities: Vec::new(),
            agent_verbs: None,
            services: Vec::new(),
            extensions: Vec::new(),
            stream_edges: Vec::new(),
        }
    }

    fn sample_bundle() -> PolicyBundle {
        PolicyBundle {
            schema_version: 1,
            bundle_id: PolicyId("bundle-y".to_string()),
            bundle_version: 3,
            network: BundleNetworkPolicy::default(),
            egress: EgressPolicy::default(),
            pii: PiiPolicy::default(),
            tool: ToolPolicy::default(),
            artifact: mvm_core::policy::policies::ArtifactPolicy::default(),
            keys: KeyPolicy::default(),
            audit: AuditPolicy::default(),
            wasi: Default::default(),
            tenant_overlays: BTreeMap::new(),
        }
    }

    #[test]
    fn noop_audit_signer_is_constructable() {
        let _: Box<dyn AuditSigner> = Box::new(NoopAuditSigner);
    }

    #[test]
    fn audit_entry_serde_roundtrip() {
        let entry = PlanAuditEntry {
            timestamp: Utc::now(),
            tenant: TenantId("t".to_string()),
            plan_id: PlanId("p".to_string()),
            plan_version: 1,
            bundle_id: Some(PolicyId("b".to_string())),
            bundle_version: Some(2),
            image_name: "img".to_string(),
            image_sha256: "deadbeef".to_string(),
            event: "plan.verified".to_string(),
            caller_commitment: None,
            labels: BTreeMap::from([("actor".to_string(), "supervisor".to_string())]),
        };
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed: PlanAuditEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_for_plan_binds_plan_bundle_image() {
        let plan = sample_plan();
        let bundle = sample_bundle();
        let entry = for_plan(&plan, Some(&bundle), "plan.verified", []);
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
    fn entry_for_plan_copies_the_typed_caller_commitment() {
        let mut plan = sample_plan();
        let commitment = mvm_core::plan::CallerCommitment::from_bytes([0x5a; 32]);
        plan.caller_commitment = Some(commitment.clone());
        let entry = for_plan(&plan, None, "plan.admitted", []);
        assert_eq!(entry.caller_commitment, Some(commitment));
    }

    #[test]
    fn entry_for_plan_handles_missing_bundle() {
        let plan = sample_plan();
        let entry = for_plan(&plan, None, "plan.verified", []);
        assert_eq!(entry.bundle_id, None);
        assert_eq!(entry.bundle_version, None);
        // Image still bound from plan.
        assert_eq!(entry.image_name, plan.image.name);
    }

    #[test]
    fn entry_for_plan_extras_override_plan_labels() {
        let plan = sample_plan(); // has workflow=etl-1
        let entry = for_plan(
            &plan,
            None,
            "evt",
            [("workflow".to_string(), "override".to_string())],
        );
        assert_eq!(entry.labels.get("workflow"), Some(&"override".to_string()));
    }

    // -----------------------------------------------------------------
    // Gateway flow event types + helpers.
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
        // close discriminators the bridge can emit:
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
        let entry = flow_opened(&plan, None, "f00ba4", FlowDirection::Egress);

        assert_eq!(entry.event, FLOW_OPENED_EVENT);
        assert_eq!(entry.event, "gateway.flow_opened");
        assert_eq!(entry.labels.get("flow_id"), Some(&"f00ba4".to_string()));
        assert_eq!(entry.labels.get("direction"), Some(&"egress".to_string()));
        // Plan binding still in place — same shape as for_plan().
        assert_eq!(entry.plan_id, plan.plan_id);
        assert_eq!(entry.tenant, plan.tenant);
    }

    #[test]
    fn transcript_sealed_helper_carries_only_ciphertext_root_metadata() {
        let plan = sample_plan();
        let root = "ab".repeat(32);
        let entry = transcript_sealed(&plan, None, "capture-1", "vm-1", &root, 7, false);

        assert_eq!(entry.event, TRANSCRIPT_SEALED_EVENT);
        assert_eq!(
            entry.labels.get(LABEL_CAPTURE_ID),
            Some(&"capture-1".to_string())
        );
        assert_eq!(entry.labels.get(LABEL_VM_NAME), Some(&"vm-1".to_string()));
        assert_eq!(entry.labels.get(LABEL_TRANSCRIPT_ROOT), Some(&root));
        assert_eq!(entry.labels.get(LABEL_CHUNK_COUNT), Some(&"7".to_string()));
        assert_eq!(entry.labels.get(LABEL_ADOPTED), Some(&"false".to_string()));
        assert_eq!(entry.plan_id, plan.plan_id);
        assert_eq!(entry.tenant, plan.tenant);

        // The exhaustive key set is the assertion that matters. Checking only
        // the labels this test thought of would let a future label carrying
        // captured bytes or a plaintext digest through, which is the one thing
        // this entry exists to keep out of the chain.
        //
        // Operator-supplied `audit_labels` ride along on every plan entry via
        // `for_plan`, so they are subtracted rather than enumerated: what is
        // pinned here is exactly the set this helper itself contributes.
        let mut contributed: Vec<&str> = entry
            .labels
            .keys()
            .map(String::as_str)
            .filter(|k| !plan.audit_labels.contains_key(*k))
            .collect();
        contributed.sort_unstable();
        assert_eq!(
            contributed,
            [
                LABEL_ADOPTED,
                LABEL_CAPTURE_ID,
                LABEL_CHUNK_COUNT,
                LABEL_TRANSCRIPT_ROOT,
                LABEL_VM_NAME,
            ]
        );
    }

    #[test]
    fn an_adopted_seal_is_distinguishable_from_one_its_writer_produced() {
        // A rebuilt seal cannot account for records the departed writer shed
        // after its last durable append. An entry that did not carry the
        // distinction would attest a floor as though it were the whole
        // capture -- a wrong record rather than a missing one.
        let plan = sample_plan();
        let root = "cd".repeat(32);

        let owned = transcript_sealed(&plan, None, "capture-2", "vm-2", &root, 4, false);
        let adopted = transcript_sealed(&plan, None, "capture-2", "vm-2", &root, 4, true);

        assert_eq!(owned.labels.get(LABEL_ADOPTED), Some(&"false".to_string()));
        assert_eq!(adopted.labels.get(LABEL_ADOPTED), Some(&"true".to_string()));
        assert_ne!(owned.labels, adopted.labels);
    }

    #[test]
    fn flow_closed_helper_carries_canonical_event_and_labels() {
        let plan = sample_plan();
        let entry = flow_closed(
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
        let entry = flow_opened(&plan, None, "f1", FlowDirection::Egress);
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
            let entry = flow_closed(&plan, None, "f1", FlowDirection::Egress, reason);
            emitted.insert(entry.labels.get("reason").cloned().unwrap());
        }
        assert_eq!(emitted.len(), 4, "all four reasons must be distinguishable");
    }

    #[test]
    fn flow_observer_fault_helper_attributes_observer_and_reason() {
        let plan = sample_plan();
        let entry = flow_observer_fault(
            &plan,
            None,
            "vm-egress",
            FlowDirection::Egress,
            "egress-redactor",
            "modify_over_mtu",
        );
        assert_eq!(entry.event, FLOW_OBSERVER_FAULT_EVENT);
        assert_eq!(entry.event, "gateway.flow_observer_fault");
        assert_eq!(entry.labels.get("flow_id"), Some(&"vm-egress".to_string()));
        assert_eq!(
            entry.labels.get("observer"),
            Some(&"egress-redactor".to_string())
        );
        assert_eq!(
            entry.labels.get("reason"),
            Some(&"modify_over_mtu".to_string())
        );
        assert_eq!(entry.labels.get("direction"), Some(&"egress".to_string()));
    }

    #[test]
    fn capturing_audit_signer_records_entries() {
        let signer = CapturingAuditSigner::new();
        let plan = sample_plan();
        let entry = for_plan(&plan, None, "plan.verified", []);

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
