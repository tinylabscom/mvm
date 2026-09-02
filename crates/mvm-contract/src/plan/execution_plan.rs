//! `ExecutionPlan` — the cornerstone workload-launch type.
//!
//! Every workload mvm runs is launched from one of these. The plan
//! is signed by mvmd (or a developer key in dev mode) and the
//! supervisor refuses unsigned plans outside dev mode. Every audit
//! entry the supervisor emits references `(plan_id, plan_version)`
//! so a runbook can answer "what plan was this workload running at
//! the moment of incident?" in O(1) without re-deriving from logs.

use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lifecycle::SnapshotAt;
use crate::plan::bundle::PlanArtifact;
use crate::plan::types::{
    AdmissionProfile, ArtifactPolicy, AttestationRequirement, AuditLabels, BuildProvenance,
    CallerCommitment, DepsVolumeBinding, EnvironmentRef, FsPolicyRef, HostShareGrant,
    IngressMapping, IngressMappingsError, KeyRotationSpec, NetworkLimits, NetworkMode, Nonce,
    PlanId, PolicyRef, PostRunLifecycle, ReleasePin, Resources, RuntimeProfileRef, SecretBinding,
    SignedImageRef, StreamRetention, TenantId, WorkloadId, validate_ingress_mappings,
    validate_ingress_material,
};
use crate::plan::verb::VerbId;
use crate::protocol::broker::ServiceId;
use crate::protocol::extension_pack::ExtensionPlanBinding;

/// Wire-format version of the `ExecutionPlan`. New fields are additive with
/// `#[serde(default)]`; the verifier rejects any plan whose `schema_version`
/// exceeds this build's, before per-field deserialisation.
pub const SCHEMA_VERSION: u32 = 1;

/// Typed contract for one workload's execution.
///
/// The fields here are the rubric — `enforce_*` in `mvm/src/enforce.rs`
/// walks the plan field-by-field and rejects any plan that doesn't
/// satisfy the corresponding enforcement row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    /// Wire-format version. See [`SCHEMA_VERSION`].
    pub schema_version: u32,

    /// Stable plan identifier. Audit entries reference this verbatim.
    pub plan_id: PlanId,

    /// Monotonic revision counter under the stable workload identity
    /// `(tenant, workload)`. `plan_id` is a per-execution content-address
    /// that changes on every synthesis/revision, so it does not stay
    /// constant across revisions — `plan_version` is what increments as
    /// mvmd publishes revised plans for the same workload (eg. policy
    /// changes). The supervisor logs `plan_id` + `plan_version` +
    /// `(tenant, workload)` on every audit entry, so both "which exact
    /// run" (`plan_id`) and "which revision of the workload"
    /// (`plan_version`) are answerable from audit alone.
    pub plan_version: u32,

    pub tenant: TenantId,
    pub workload: WorkloadId,

    /// Which backend / runtime profile this workload runs on.
    /// Resolved by `BackendRegistry`.
    pub runtime_profile: RuntimeProfileRef,

    /// Signed image to boot. SHA-256 + cosign bundle reference;
    /// resolved by `mvm-core::crypto::image_verify`.
    pub image: SignedImageRef,

    /// The environment the image is admitted to boot in — currently the kernel
    /// digest. `None` (default) = this plan pins no environment, which is every
    /// plan written before the field existed.
    ///
    /// Skip-serialized when absent so those plans stay byte-identical: the field
    /// is inside the signed payload, so emitting it as `null` would invalidate
    /// every existing signature and frozen vector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvironmentRef>,

    pub resources: Resources,

    /// What this workload is permitted to consume, as admitted.
    ///
    /// Inside the signed payload because a grant read from anywhere else is a
    /// grant the launcher could widen after admission checked it: the host
    /// applies these at launch and reports which of them a mechanism actually
    /// bounded, and both of those answers are only meaningful about a value the
    /// signature covers. The host-side ceiling that limits what may be asked
    /// for is deliberately *not* here — it has a different trust root and is
    /// resolved from host configuration at admission.
    ///
    /// `None` (the default) means the workload declared none. Skip-serialized
    /// when absent so a plan that declares no grant stays byte-identical to one
    /// written before the field existed — the field is inside the content
    /// address, so emitting `null` would move every existing plan's identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<crate::grants::Grants>,

    /// Intent-bound profile resolved before admission. This binds the
    /// workload purpose to the concrete seccomp tier, policy refs,
    /// secret-release posture, and audit taxonomy the runtime must
    /// enforce for this boot.
    pub admission_profile: AdmissionProfile,

    /// Network policy reference. Wired to `mvm-core::policy::EgressPolicy`
    /// (L7 + PII rules) via the supervisor's `SupervisorEgressProxy`.
    pub network_policy: PolicyRef,

    /// Networking transport mode. Closed by default ([`NetworkMode::None`]): no
    /// guest NIC, nothing reachable. `HostVsockProxy` selects brokered egress/
    /// ingress over vsock; `network_policy` still gates which endpoints are
    /// reachable. `#[serde(default)]` so a plan without the field deserializes as the safe
    /// closed default.
    #[serde(default)]
    pub network_mode: NetworkMode,

    /// Transport-neutral endpoint resource ceilings. Defaults are omitted so
    /// adding this signed field does not change bytes produced for existing
    /// plans. New networking transports consume this value instead of
    /// transport-specific limits.
    #[serde(default, skip_serializing_if = "NetworkLimits::is_default")]
    pub network_limits: NetworkLimits,

    /// Exact host listeners and guest-loopback targets admitted for ingress.
    /// Empty means the endpoint owns no public listener for this workload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<IngressMapping>,

    /// Opt-in warm-snapshot timing. `None` (default) = this workload is not
    /// warm-snapshotted; `Some(at)` = the host may capture a warm snapshot when
    /// the guest reaches `at`'s trigger marker (`mvm-init` lifecycle). Part of
    /// the signed contract so the snapshot point is admitted, not host-chosen.
    /// `#[serde(default)]` so a plan without the field deserializes as `None`.
    #[serde(default)]
    pub snapshot_at: Option<SnapshotAt>,

    /// Build provenance: the input kind/ref, input pin, builder identity, and
    /// per-artifact digests behind this launch — so a run is traceable to exact
    /// deterministic inputs and outputs. `None` (default) = not recorded for this
    /// workload. The deterministic build pipeline populates it.
    /// `#[serde(default)]` so a plan without the field deserializes as `None`.
    #[serde(default)]
    pub build_provenance: Option<BuildProvenance>,

    /// Filesystem policy reference.
    pub fs_policy: FsPolicyRef,

    pub secrets: Vec<SecretBinding>,

    /// L7 egress + PII rules. The same kind of `PolicyRef` as
    /// `network_policy` so the resolver is shared, but kept separate
    /// here so an audit entry can show "egress allowed, pii redacted"
    /// as orthogonal facts.
    pub egress_policy: PolicyRef,

    /// Per-destination egress redaction policy. Rides inline in the signed plan
    /// — like `secrets` — so the per-VM substitution endpoint gets it at spawn
    /// without resolving the bundle. Default = the all-off curated baseline (no
    /// per-destination entropy/name redaction).
    #[serde(default)]
    pub redaction: crate::policy::redaction::RedactionPolicy,

    /// Per-destination reversible replacement policy. Disabled by default; when
    /// enabled for a destination, the runtime may replace detected secret / PII
    /// bytes with opaque request-scoped tokens on owned outbound cleartext
    /// paths, and exact-token reinject on the paired owned response path.
    #[serde(default)]
    pub reversible_replacement: crate::policy::reversible_replacement::ReversibleReplacementPolicy,

    /// Tool-call policy (which tools the model is allowed to invoke
    /// over the supervisor's vsock RPC).
    pub tool_policy: PolicyRef,

    pub artifact_policy: ArtifactPolicy,

    /// Optional opaque caller commitment fixed before execution. The bytes are
    /// part of the plan content address and host signature; MVM deliberately
    /// assigns them no semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_commitment: Option<CallerCommitment>,

    /// Free-form audit labels copied verbatim into every audit entry
    /// generated for this plan. Usually carries tenant-meaningful
    /// metadata (`workflow_id`, `request_id`).
    pub audit_labels: AuditLabels,

    pub key_rotation: KeyRotationSpec,
    pub attestation: AttestationRequirement,

    /// Optional release pin. mvmd sets this to enforce
    /// "this workload runs at exactly v0.X.Y of mvm/mvmd."
    pub release_pin: Option<ReleasePin>,

    pub post_run: PostRunLifecycle,

    /// Plan validity window — start. The supervisor refuses to admit
    /// a plan before `valid_from`.
    pub valid_from: DateTime<Utc>,

    /// Plan validity window — end. The supervisor refuses to admit
    /// a plan at or after `valid_until`. Without this bound, signed
    /// plans are forever-valid and replayable.
    pub valid_until: DateTime<Utc>,

    /// Per-plan nonce for replay protection. The supervisor maintains
    /// a seen-nonce ledger keyed by signer; an admission attempt with
    /// a previously-seen nonce for the same signer is refused. The
    /// ledger self-prunes once `valid_until` passes for a stored
    /// nonce.
    pub nonce: Nonce,

    /// Per-workload agent verb allow-list. `None` (or absent) → the
    /// guest applies the class/profile gate only (current behavior).
    /// `Some(set)` → the guest also requires each control verb to be a
    /// baseline verb or present in this set. Strictly subtractive: this
    /// can only narrow, never widen, the class gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_verbs: Option<Vec<VerbId>>,

    /// Optional pin to a content-addressed `.mvmpkg` bundle. When
    /// present, the supervisor's admit path re-runs
    /// [`crate::plan::bundle::read_and_verify_bundle`] against the
    /// resolved archive bytes, then compares the resulting
    /// `bundle_sha256` + `manifest_sig` + `key_id` against the
    /// pinned values here. Any mismatch refuses the admission —
    /// claim 9 is load-bearing at launch, not just at fetch.
    ///
    /// `None` (the default) means the plan is not pinned to a
    /// bundle; the admit path skips the bundle re-verify step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<PlanArtifact>,

    /// Optional pin to an application-dependencies volume sealed
    /// by `mvm_sdk::compile::deps_audit::seal_volume`. When present,
    /// the supervisor's admit path re-runs `verify_sealed_volume`
    /// against `~/.mvm/volumes/deps/<volume_hash>/`, then compares
    /// the derived volume hash + manifest sha against the pinned
    /// values here. Any mismatch refuses admission (claim 9).
    ///
    /// `None` (the default) means the plan has no deps volume; the
    /// admit path skips this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deps_volume: Option<DepsVolumeBinding>,

    /// User-supplied host-fs grants (`--volume` / `MVM_VOLUMES`):
    /// directory shares and disk images the workload is admitted to
    /// mount. Empty for the common no-volume case. The admit path
    /// asserts the launch config's volumes are a subset of this list
    /// (claim 1 / claim 8) and emits it to the chain-signed audit log;
    /// a future supervisor-side per-attach gate reads it to refuse
    /// any share the plan didn't name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<HostShareGrant>,

    /// Host services this workload is authorized to call over the broker
    /// channel. The broker's dispatch gate refuses any service that is not
    /// listed here, and the launch path reads the same list to decide whether
    /// the optional glibc SDK sidecar has to be attached — see
    /// [`crate::plan::sdk_sidecar`]. Empty (the default) means the workload
    /// calls no host service: the broker answers every call `NotBound` and no
    /// sidecar is attached.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceId>,

    /// Optional independently signed extension packs admitted for this exact
    /// workload. Empty keeps ordinary launches on the existing path: no pack
    /// discovery, installation, or extension dispatch occurs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionPlanBinding>,

    /// Inbound stream edges: other workloads whose output feeds this one's
    /// stdin. Each names a *binding* the host resolves, never a VM — see
    /// [`crate::stream::edge`] for why a guest never addresses another guest.
    ///
    /// Skip-serialized when empty so a plan that declares no edge stays
    /// byte-identical to one written before the field existed: the field is
    /// inside the signed payload and inside the content address, so emitting
    /// `[]` would move every existing plan's identity for nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stream_edges: Vec<crate::stream::StreamEdge>,

    /// Whether this workload's captured output is kept after the run.
    ///
    /// Always serialized, unlike the optional pins above: the point of
    /// admitting the mode is that the signed bytes state it outright, so an
    /// absent transcript is attributable to a decision rather than to a gap in
    /// the record. `#[serde(default)]` still makes a plan without the field
    /// deserialize as [`StreamRetention::Persist`], the recording default.
    #[serde(default)]
    pub stream_retention: StreamRetention,

    /// Whether the workload uses the SDK sidecar (glibc cdylib) to reach host
    /// services, or speaks the broker protocol directly. This controls whether
    /// the optional SDK sidecar must be attached: when `true`, the admission
    /// gate requires the sidecar; when `false`, the sidecar is forbidden and
    /// the workload must reach services via direct vsock calls.
    ///
    /// `true` (default) preserves existing behavior: workloads bound to SDK
    /// services receive the glibc sidecar. Set to `false` when the workload
    /// can speak the broker protocol natively (e.g., Python with AF_VSOCK,
    /// Go with golang.org/x/sys/unix).
    ///
    /// Always serialized so a plan that doesn't set it still states the
    /// default in the signed bytes.
    #[serde(default)]
    pub sdk_uses_sidecar: bool,
}

impl ExecutionPlan {
    /// Validate all ingress mappings as one signed listener set.
    pub fn validate_ingress(&self) -> Result<(), IngressMappingsError> {
        validate_ingress_mappings(&self.ingress, self.network_limits.max_ingress_listeners)?;
        validate_ingress_material(&self.ingress, &self.secrets)
    }

    /// Validate and return the admitted networking ceilings for this plan.
    pub fn effective_network_limits(
        &self,
    ) -> Result<NetworkLimits, crate::plan::types::NetworkLimitsError> {
        self.network_limits.validate()
    }
}

/// Minimal, valid local `ExecutionPlan`. Rebuilt inline rather than
/// reusing `mvm-core`'s `plan::signing::test_support::sample_plan` —
/// that fixture lives above `plan::signing` (which stays in
/// `mvm-core`), so it's unreachable from here. A fixed timestamp
/// stands in for `Utc::now()`, which needs chrono's `clock` feature
/// this crate doesn't enable.
///
/// `pub(crate)` (not module-private) so other in-crate test modules —
/// e.g. `crate::stream::input`'s plan-grant tests — can build a plan
/// without duplicating this fixture.
#[cfg(test)]
pub(crate) fn minimal_plan() -> ExecutionPlan {
    use alloc::collections::BTreeMap;
    use alloc::string::ToString;

    use chrono::{Duration, TimeZone};

    use crate::plan::types::{AttestationMode, PlanSeccompTier, TimeoutSpec};

    let valid_from = Utc.with_ymd_and_hms(2026, 7, 16, 12, 0, 0).unwrap();
    ExecutionPlan {
        environment: None,
        schema_version: SCHEMA_VERSION,
        plan_id: PlanId("fixture-plan".to_string()),
        plan_version: 1,
        tenant: TenantId("local".to_string()),
        workload: WorkloadId("vm-test".to_string()),
        runtime_profile: RuntimeProfileRef("firecracker".to_string()),
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
        grants: None,
        admission_profile: AdmissionProfile::local_default("vm:boot", PlanSeccompTier::Standard),
        network_policy: PolicyRef("local-default".to_string()),
        network_mode: Default::default(),
        ingress: Vec::new(),
        network_limits: Default::default(),
        snapshot_at: Default::default(),
        build_provenance: Default::default(),
        fs_policy: FsPolicyRef("local-default".to_string()),
        secrets: Vec::new(),
        egress_policy: PolicyRef("local-default".to_string()),
        redaction: Default::default(),
        reversible_replacement: Default::default(),
        tool_policy: PolicyRef("local-default".to_string()),
        artifact_policy: ArtifactPolicy {
            capture_paths: Vec::new(),
            retention_days: 0,
        },
        caller_commitment: None,
        audit_labels: BTreeMap::new(),
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
        valid_from,
        valid_until: valid_from + Duration::minutes(10),
        nonce: Nonce::from_bytes([0u8; 16]),
        agent_verbs: None,
        bundle: None,
        deps_volume: None,
        shares: Vec::new(),
        services: Vec::new(),
        extensions: Vec::new(),
        stream_edges: Vec::new(),
        stream_retention: StreamRetention::Persist,
        sdk_uses_sidecar: true,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn default_network_limits_preserve_existing_signed_bytes() {
        let plan = minimal_plan();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(!json.contains("network_limits"), "default leaked: {json}");

        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("network_limits");
        let back: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert_eq!(back.network_limits, NetworkLimits::default());
    }

    #[test]
    fn absent_caller_commitment_preserves_existing_plan_bytes() {
        let plan = minimal_plan();
        let json = serde_json::to_string(&plan).expect("plan serializes");
        assert!(
            !json.contains("caller_commitment"),
            "default leaked: {json}"
        );

        let mut committed = plan;
        committed.caller_commitment = Some(CallerCommitment::from_bytes([0x44; 32]));
        let json = serde_json::to_string(&committed).expect("committed plan serializes");
        assert!(json.contains(&format!("\"caller_commitment\":\"{}\"", "44".repeat(32))));
    }

    #[test]
    fn services_default_empty_and_roundtrip() {
        use crate::protocol::broker::ServiceId;

        let plan = minimal_plan();
        assert!(
            plan.services.is_empty(),
            "a plan that binds no host service must default to an empty set"
        );

        // Empty => key omitted entirely, so existing signatures over plans
        // without the field stay byte-identical.
        let json = serde_json::to_string(&plan).unwrap();
        assert!(
            !json.contains("services"),
            "an empty services set must be omitted, not serialized as []"
        );

        // Absent in JSON => empty (serde default), preserving old plans.
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("services");
        let back: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert!(back.services.is_empty());

        // Present => preserved, in order.
        let mut bound = plan.clone();
        bound.services = vec![
            ServiceId::parse("host.audit.v1").unwrap(),
            ServiceId::parse("host.time.v1").unwrap(),
        ];
        let round: ExecutionPlan =
            serde_json::from_str(&serde_json::to_string(&bound).unwrap()).unwrap();
        assert_eq!(round.services, bound.services);
        assert!(crate::plan::sdk_sidecar::sdk_sidecar_required(&round));
        assert!(!crate::plan::sdk_sidecar::sdk_sidecar_required(&plan));
    }

    #[test]
    fn undeclared_grants_leave_the_signed_bytes_untouched() {
        use crate::grants::{CpuGrant, Grants};

        let plan = minimal_plan();
        assert!(plan.grants.is_none(), "a plan declares no grant by default");

        // The field is inside the content address, so an absent grant set must
        // not appear at all — `null` would move the identity of every plan
        // written before the field existed.
        let json = serde_json::to_string(&plan).unwrap();
        assert!(
            !json.contains("grants"),
            "absent grants must be omitted, not serialized as null"
        );

        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("grants");
        let back: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert!(back.grants.is_none());

        let mut granted = plan.clone();
        granted.grants = Some(Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Grants::default()
        });
        let round: ExecutionPlan =
            serde_json::from_str(&serde_json::to_string(&granted).unwrap()).unwrap();
        assert_eq!(round.grants, granted.grants);
    }

    #[test]
    fn a_malformed_service_id_fails_the_plan_closed() {
        let plan = minimal_plan();
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().insert(
            "services".to_string(),
            serde_json::json!(["host.audit"]), // no version segment
        );
        assert!(
            serde_json::from_value::<ExecutionPlan>(value).is_err(),
            "an unversioned service id must refuse to deserialize"
        );
    }

    #[test]
    fn agent_verbs_defaults_none_and_roundtrips() {
        let plan = minimal_plan();
        assert!(plan.agent_verbs.is_none(), "field must default to None");

        // None => key is omitted entirely, not serialized as null.
        let s = serde_json::to_string(&plan).unwrap();
        assert!(
            !s.contains("agent_verbs"),
            "None agent_verbs must be omitted, not serialized as null"
        );

        // Absent in JSON => None (serde default), preserving old plans.
        let mut v = serde_json::to_value(&plan).unwrap();
        v.as_object_mut().unwrap().remove("agent_verbs");
        let back: ExecutionPlan = serde_json::from_value(v).unwrap();
        assert!(back.agent_verbs.is_none());

        // Present => preserved.
        let mut with = plan.clone();
        with.agent_verbs = Some(vec![
            VerbId::new("run-entrypoint").unwrap(),
            VerbId::new("ping").unwrap(),
        ]);
        let round: ExecutionPlan =
            serde_json::from_str(&serde_json::to_string(&with).unwrap()).unwrap();
        assert_eq!(round.agent_verbs, with.agent_verbs);
    }

    /// The recording default has to survive both directions: a plan that says
    /// nothing records, and a plan that opts out says so in the bytes that get
    /// signed. Omitting `persist` from the wire would be the cheaper encoding
    /// and the wrong one — the mode is only useful if the artifact states it.
    #[test]
    fn stream_retention_defaults_to_persist_and_states_itself_on_the_wire() {
        let plan = minimal_plan();
        assert_eq!(plan.stream_retention, StreamRetention::Persist);

        let json = serde_json::to_string(&plan).unwrap();
        assert!(
            json.contains("\"stream_retention\":\"persist\""),
            "the admitted mode must be in the signed bytes, not implied by absence: {json}"
        );

        // A plan predating the field still deserializes, and it records.
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("stream_retention");
        let back: ExecutionPlan = serde_json::from_value(value).unwrap();
        assert_eq!(back.stream_retention, StreamRetention::Persist);

        let mut opted_out = plan.clone();
        opted_out.stream_retention = StreamRetention::Ephemeral;
        let round: ExecutionPlan =
            serde_json::from_str(&serde_json::to_string(&opted_out).unwrap()).unwrap();
        assert_eq!(round.stream_retention, StreamRetention::Ephemeral);
    }
}
