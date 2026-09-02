//! Shared test-only `ExecutionPlan` fixtures.
//!
//! The audit / admission tests across mvm-core and mvm-hostd each hand-rolled
//! the same ~40-line minimal plan. [`PlanFixture`] is the single source: a
//! valid local plan (one cpu, 128 MiB, `local-default` policies, a 10-minute
//! validity window, all-zero nonce) with builder overrides for only the fields
//! a given test actually pins. Gated behind
//! `cfg(any(test, feature = "test-support"))` so it never reaches a production
//! build.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

use crate::plan::execution_plan::{ExecutionPlan, SCHEMA_VERSION};
use crate::plan::types::{
    AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
    KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
    RuntimeProfileRef, SecretBinding, SignedImageRef, StreamRetention, TenantId, TimeoutSpec,
    WorkloadId,
};
use mvm_contract::protocol::broker::ServiceId;

/// Builder for a minimal, valid local [`ExecutionPlan`]. Defaults match the
/// shape the audit/admission tests need; override only what a test pins.
pub struct PlanFixture {
    tenant: String,
    plan_id: String,
    workload: String,
    runtime_profile: String,
    nonce: [u8; 16],
    secrets: Vec<SecretBinding>,
    valid_from: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    services: Vec<ServiceId>,
    extensions: Vec<mvm_contract::protocol::extension_pack::ExtensionPlanBinding>,
    stream_edges: Vec<mvm_contract::stream::StreamEdge>,
    stream_retention: StreamRetention,
    audit_labels: BTreeMap<String, String>,
    caller_commitment: Option<crate::plan::CallerCommitment>,
    grants: Option<mvm_contract::grants::Grants>,
}

impl Default for PlanFixture {
    fn default() -> Self {
        Self {
            tenant: "local".to_string(),
            plan_id: "fixture-plan".to_string(),
            workload: "vm-test".to_string(),
            runtime_profile: "firecracker".to_string(),
            nonce: [0u8; 16],
            secrets: Vec::new(),
            valid_from: None,
            valid_until: None,
            services: Vec::new(),
            extensions: Vec::new(),
            stream_edges: Vec::new(),
            stream_retention: StreamRetention::default(),
            audit_labels: BTreeMap::new(),
            caller_commitment: None,
            grants: None,
        }
    }
}

impl PlanFixture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = tenant.into();
        self
    }

    pub fn plan_id(mut self, plan_id: impl Into<String>) -> Self {
        self.plan_id = plan_id.into();
        self
    }

    pub fn workload(mut self, workload: impl Into<String>) -> Self {
        self.workload = workload.into();
        self
    }

    pub fn runtime_profile(mut self, runtime_profile: impl Into<String>) -> Self {
        self.runtime_profile = runtime_profile.into();
        self
    }

    pub fn nonce(mut self, nonce: [u8; 16]) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn secrets(mut self, secrets: Vec<SecretBinding>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Bind host services this workload is authorized to call. Drives the
    /// broker's dispatch gate and the SDK-sidecar attachment decision.
    pub fn services(mut self, services: Vec<ServiceId>) -> Self {
        self.services = services;
        self
    }

    pub fn extensions(
        mut self,
        extensions: Vec<mvm_contract::protocol::extension_pack::ExtensionPlanBinding>,
    ) -> Self {
        self.extensions = extensions;
        self
    }

    /// Whether this plan's captured output is kept after the run. The default
    /// is [`StreamRetention::Persist`]; a test pins `Ephemeral` to exercise the
    /// signed opt-out.
    pub fn stream_retention(mut self, retention: StreamRetention) -> Self {
        self.stream_retention = retention;
        self
    }

    /// Labels the plan carries onto every audit entry emitted under it.
    /// Default empty, which is *not* what a production plan looks like — a
    /// test asserting on an entry's exact key set needs one of these to prove
    /// the assertion covers the merge rather than the fixture's silence.
    pub fn audit_labels(mut self, labels: BTreeMap<String, String>) -> Self {
        self.audit_labels = labels;
        self
    }

    /// Opaque caller commitment copied into the signed plan and audit chain.
    pub fn caller_commitment(mut self, commitment: crate::plan::CallerCommitment) -> Self {
        self.caller_commitment = Some(commitment);
        self
    }

    /// The permission set this plan is admitted under. Default `None`, which a
    /// restore reads as unbounded CPU and wall clock but deny-all egress.
    pub fn grants(mut self, grants: Option<mvm_contract::grants::Grants>) -> Self {
        self.grants = grants;
        self
    }

    /// Pin an explicit validity window. Without this the plan is valid from
    /// `now` to `now + 10min`.
    pub fn validity(mut self, from: DateTime<Utc>, until: DateTime<Utc>) -> Self {
        self.valid_from = Some(from);
        self.valid_until = Some(until);
        self
    }

    pub fn build(self) -> ExecutionPlan {
        let now = Utc::now();
        ExecutionPlan {
            grants: self.grants,
            environment: None,
            build_provenance: Default::default(),
            snapshot_at: Default::default(),
            network_mode: Default::default(),
            ingress: Vec::new(),
            network_limits: Default::default(),
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId(self.plan_id),
            plan_version: 1,
            tenant: TenantId(self.tenant),
            workload: WorkloadId(self.workload),
            runtime_profile: RuntimeProfileRef(self.runtime_profile),
            image: SignedImageRef {
                name: "vm-test".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 0,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("local-default".to_string()),
            fs_policy: FsPolicyRef("local-default".to_string()),
            secrets: self.secrets,
            egress_policy: PolicyRef("local-default".to_string()),
            redaction: Default::default(),
            reversible_replacement: Default::default(),
            tool_policy: PolicyRef("local-default".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: Vec::new(),
                retention_days: 0,
            },
            caller_commitment: self.caller_commitment,
            audit_labels: self.audit_labels,
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
            valid_from: self.valid_from.unwrap_or(now),
            valid_until: self.valid_until.unwrap_or(now + Duration::minutes(10)),
            nonce: Nonce::from_bytes(self.nonce),
            agent_verbs: None,
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
            services: self.services,
            extensions: self.extensions,
            stream_edges: self.stream_edges.clone(),
            stream_retention: self.stream_retention,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_builds_a_valid_minimal_plan() {
        let plan = PlanFixture::new().build();
        assert_eq!(plan.tenant.0, "local");
        assert_eq!(plan.plan_id.0, "fixture-plan");
        assert_eq!(plan.runtime_profile.0, "firecracker");
        assert_eq!(plan.resources.cpus, 1);
        assert_eq!(plan.resources.mem_mib, 128);
        assert!(plan.secrets.is_empty());
        // Validity window defaults to a live 10-minute window.
        assert!(plan.valid_until > plan.valid_from);
    }

    #[test]
    fn overrides_are_applied() {
        let from = Utc::now();
        let until = from + Duration::minutes(5);
        let plan = PlanFixture::new()
            .tenant("acme")
            .plan_id("p-1")
            .workload("w-1")
            .runtime_profile("hvf")
            .nonce([7u8; 16])
            .validity(from, until)
            .audit_labels(BTreeMap::from([(
                "owner".to_string(),
                "team-a".to_string(),
            )]))
            .build();
        assert_eq!(
            plan.audit_labels.get("owner").map(String::as_str),
            Some("team-a")
        );
        assert_eq!(plan.tenant.0, "acme");
        assert_eq!(plan.plan_id.0, "p-1");
        assert_eq!(plan.workload.0, "w-1");
        assert_eq!(plan.runtime_profile.0, "hvf");
        assert_eq!(plan.nonce, Nonce::from_bytes([7u8; 16]));
        assert_eq!(plan.valid_from, from);
        assert_eq!(plan.valid_until, until);
    }

    #[test]
    fn stream_retention_defaults_to_persist() {
        assert_eq!(
            PlanFixture::new().build().stream_retention,
            StreamRetention::Persist
        );
        assert_eq!(
            PlanFixture::new()
                .stream_retention(StreamRetention::Ephemeral)
                .build()
                .stream_retention,
            StreamRetention::Ephemeral
        );
    }

    #[test]
    fn services_default_empty_and_are_overridable() {
        assert!(PlanFixture::new().build().services.is_empty());
        let bound = PlanFixture::new()
            .services(vec![ServiceId::parse("host.audit.v1").unwrap()])
            .build();
        assert_eq!(bound.services.len(), 1);
        assert_eq!(bound.services[0].as_str(), "host.audit.v1");
    }
}
