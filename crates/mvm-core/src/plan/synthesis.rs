//! `ExecutionPlan` synthesis from a resolved [`SynthesisInput`].
//!
//! Turns an already-resolved launch shape (name, backend, image digest,
//! cpus, memory, volumes, secrets, policy refs, etc.) into a typed
//! [`crate::plan::ExecutionPlan`] the supervisor can verify, audit, and gate
//! on. This is the pure, side-effect-free core of signed-plan admission
//! (claim 8): the caller resolves CLI/API args into a `SynthesisInput`, this
//! builds the unsigned plan, and the caller signs + admits it. Living in
//! `mvm-core` (beside the plan types) lets every driver — the CLI, and the
//! `mvm-client` local backend once the boot seam lands — synthesize through
//! one contract.
//!
//! ## What lives here
//!
//! - [`synthesize_plan`] — the one entry point. Takes a borrowed
//!   `SynthesisInput` and produces an `ExecutionPlan` ready to sign.
//! - Internal helpers for resource budgets and validity windows.
//!
//! ## What does NOT live here
//!
//! - **Signing.** The `signer` module owns it — `synthesize_plan`
//!   builds the unsigned plan; the caller signs.
//! - **Backend dispatch.** The supervisor wires `BackendLauncher`;
//!   this module is plan-shape-only, no I/O.
//! - **Policy resolution.** The `policy_resolver` turns the plan's
//!   `PolicyRef` fields into concrete supervisor components.
//!
//! ## Field source map (plan field → CLI input)
//!
//! | Plan field | Where it comes from |
//! |---|---|
//! | `plan_id` | content-address of the finished plan (all load-bearing fields except the id itself) |
//! | `plan_version` | always 1 for synthesized plans; the revision counter under the stable `(tenant, workload)` identity (mvmd revisions get higher numbers) |
//! | `tenant` | `--tenant` flag or default `"local"` |
//! | `workload` | derived from `--name` or flake ref leaf |
//! | `runtime_profile` | hypervisor flag mapped to a profile name |
//! | `image` | computed lazily from rootfs SHA-256 (filled by caller after build) |
//! | `resources` | `--cpus`, `--memory`, `--ttl` |
//! | `*_policy` / `fs_policy` | `"local-default"` (resolver maps to Noops) |
//! | `valid_from`/`valid_until` | now + 10 min window |
//! | `nonce` | fresh 128 bits from `OsRng` per invocation |
//! | everything else | conservative defaults (no attestation, destroy-on-exit, etc.) |

use crate::plan::{
    AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, AuditLabels,
    AuditTaxonomy, DepsVolumeBinding, EnvironmentRef, ExecutionPlan, FsPolicyRef, KeyRotationSpec,
    L3NetworkSpec, NetworkMode, Nonce, PlanId, PlanSeccompTier, PolicyRef, PostRunLifecycle,
    Resources, RuntimeProfileRef, SCHEMA_VERSION, SecretBinding, SecretReleasePolicy,
    SignedImageRef, TenantId, TimeoutSpec, WorkloadId, WorkloadIntent,
};
use anyhow::Result;
use chrono::{Duration, Utc};
use rand::RngCore;
use std::collections::BTreeMap;

/// Default tenant for single-host runs. The "one guest = one
/// workload" model means the tenant boundary is the host itself unless
/// mvmd's multi-tenant control plane is wired in.
pub const DEFAULT_TENANT: &str = "local";

/// Default policy name resolved by the policy_resolver to a Noop
/// component-slot set. Production deployments override via the
/// supervisor's policy bundle.
pub const DEFAULT_POLICY_REF: &str = "local-default";

/// Default intent for direct `mvmctl up` boots. Higher-level callers
/// can pass a more specific purpose such as `code:execute` or
/// `agent:web-research` once their API has that context.
pub const DEFAULT_INTENT: &str = "vm:boot";

/// Default audit event prefix for direct VM boots.
pub const DEFAULT_AUDIT_EVENT_PREFIX: &str = "vm.boot";

/// Plan validity window from `now`. 10 minutes is long enough that
/// boot + signature verification + state machine walk finishes well
/// within the window; short enough that a captured plan can't be
/// replayed hours later.
pub const VALIDITY_WINDOW_MINUTES: i64 = 10;

/// Caller-supplied input. We take a struct rather than the 10
/// individual fields the workspace clippy `too_many_arguments` lint
/// would otherwise force into a refactor anyway.
#[derive(Debug, Clone)]
pub struct SynthesisInput<'a> {
    /// VM name (post-validation). Synthesized plans use this verbatim
    /// as the `WorkloadId`.
    pub vm_name: &'a str,
    /// Optional tenant override. `None` → `DEFAULT_TENANT`.
    pub tenant: Option<&'a str>,
    /// Resolved runtime profile (`firecracker` / `libkrun` / `hvf` / `qemu`).
    pub backend_name: &'a str,
    /// Image reference for `SignedImageRef`. `sha256` is the
    /// lowercase-hex digest of the rootfs (computed by `mvm-core::crypto::
    /// image_verify::sha256_file` or upstream Nix).
    pub image_name: &'a str,
    pub image_sha256: &'a str,
    /// Lowercase-hex SHA-256 of the kernel this workload boots, pinning the
    /// environment into the signed plan. `None` = the caller resolved no kernel
    /// (a backend that supplies its own bundled one), and the plan pins none.
    pub kernel_sha256: Option<&'a str>,
    pub image_cosign_bundle: Option<&'a str>,
    /// Purpose this run is admitted for. `None` means
    /// `DEFAULT_INTENT`.
    pub intent: Option<&'a str>,
    /// Seccomp tier resolved by the caller before admission. This is
    /// mirrored into `ExecutionPlan.admission_profile` so audit can
    /// prove which filter tier the boot was bound to.
    pub seccomp_tier: PlanSeccompTier,
    /// Policy refs selected by the caller. `None` falls back to
    /// `DEFAULT_POLICY_REF`. Keeping refs in the synthesis input
    /// lets intent profiles bind to live policy bundles without a
    /// later mutation step.
    pub network_policy_ref: Option<&'a str>,
    pub fs_policy_ref: Option<&'a str>,
    pub egress_policy_ref: Option<&'a str>,
    pub tool_policy_ref: Option<&'a str>,
    /// Whether any secret can be released under this profile.
    pub secret_release: SecretReleasePolicy,
    /// Secret refs lowered into plan-visible bindings.
    pub secrets: Vec<SecretBinding>,
    /// Optional audit event prefix override. `None` derives from the
    /// intent.
    pub audit_event_prefix: Option<&'a str>,
    /// How this workload reaches the network. Part of the signed contract:
    /// the transport is admitted, never a host-side default the guest
    /// discovers at boot. `Default` is the closed mode.
    pub network_mode: NetworkMode,
    /// The L3-tunnel contract, when `network_mode` selects it. Admission
    /// refuses the pair being inconsistent in either direction.
    pub l3_network: Option<L3NetworkSpec>,
    /// vCPU count.
    pub cpus: u32,
    /// Memory budget in MiB.
    pub mem_mib: u64,
    /// Disk budget in MiB. 0 = no explicit cap (supervisor falls back
    /// to whatever the image carries).
    pub disk_mib: u64,
    /// Boot-timeout seconds. Conservative default 60s on capable hosts.
    pub boot_timeout_secs: u32,
    /// Exec-timeout seconds. 0 = unbounded.
    pub exec_timeout_secs: u32,
    /// Whether the post-run lifecycle should destroy the VM on exit.
    /// True for one-shot CLI workloads; false for daemon-shape services.
    pub destroy_on_exit: bool,
    /// Optional pin to a content-addressed `.mvmpkg` bundle. When
    /// set, the synthesised plan carries the pin and the supervisor's
    /// admit path re-verifies the archive against this triple before
    /// backend dispatch. Populating it from `mvmctl up` flags is the
    /// next step.
    pub bundle_pin: Option<crate::plan::bundle::PlanArtifact>,
    /// Optional pin to an application-dependencies volume sealed by
    /// `mvm_sdk::compile::deps_audit::seal_volume`. Populated by
    /// `mvmctl up`'s deps-install path when the workload declares
    /// `App.dependencies = Dependencies::Python | Dependencies::Node`;
    /// absent when `Dependencies::None` / no `--from-workload-ir` flag
    /// is set. The supervisor's admit path re-runs
    /// `verify_sealed_volume` against the pinned `volume_hash` +
    /// `manifest_sha256` before backend dispatch (security claim 9).
    pub deps_volume: Option<DepsVolumeBinding>,
    /// User-supplied host-fs grants (`--volume` / `MVM_VOLUMES`) to bake
    /// into the signed plan + audit log (claim 1 / claim 8). Empty for
    /// the common no-volume case.
    pub shares: Vec<crate::plan::HostShareGrant>,
    /// Per-destination egress redaction authored by `--redact HOST[=audit]`.
    /// Default (all-off) preserves the curated-only baseline.
    pub redaction: crate::policy::RedactionPolicy,
    /// Per-destination reversible replacement. Default (disabled) preserves the
    /// current one-way-only behavior.
    pub reversible_replacement: crate::policy::ReversibleReplacementPolicy,
    /// Caller-supplied audit labels merged into the synthesized plan's
    /// `audit_labels`. They serialize inside the signed payload and are
    /// inherited by every chain-signed audit entry. The profile-derived keys
    /// (intent / admission_profile / seccomp_tier) take precedence — caller
    /// labels cannot override them. Key format is caller-defined
    /// (unconstrained); supervisor-injected per-event extras are applied
    /// separately at audit-emit time and do not modify the plan's stored labels.
    pub audit_labels: AuditLabels,
    /// Per-workload agent verb allow-list threaded verbatim into the plan.
    /// `None` preserves the current class/profile-gate-only behavior.
    pub agent_verbs: Option<Vec<crate::plan::VerbId>>,
    /// Host services this workload is authorized to call over the broker
    /// channel, threaded verbatim into the plan. Empty (the common case) means
    /// the workload calls none: the broker answers `NotBound` and the launch
    /// path attaches no SDK sidecar.
    pub services: Vec<mvm_protocol::protocol::broker::ServiceId>,
}

/// The L3 spec a plan carries, given its mode.
///
/// `Some` exactly when the mode is the tunnel, so the pair can never be
/// half-set: an `l3_vsock` plan without a spec and a spec on a non-L3 plan
/// are both refused at admission, and neither is constructible from here.
/// A caller that supplied a spec keeps it; one that did not gets the
/// version-1 defaults.
fn l3_spec_for(mode: NetworkMode, supplied: Option<&L3NetworkSpec>) -> Option<L3NetworkSpec> {
    if !mode.is_l3_vsock() {
        return None;
    }
    Some(supplied.cloned().unwrap_or_else(L3NetworkSpec::v1))
}

/// Build an unsigned `ExecutionPlan` from CLI-shaped input.
///
/// Generates a fresh `nonce` (128 random bits) per invocation and
/// derives `plan_id` as the content-address of the finished plan (see
/// [`crate::plan::compute_plan_id`]); the validity window starts at the
/// call site's `now()` and lasts `VALIDITY_WINDOW_MINUTES`. The caller
/// signs the returned plan via [`crate::plan::sign_plan`] before passing
/// it to the supervisor — the signature covers the derived id.
pub fn synthesize_plan(input: &SynthesisInput<'_>) -> Result<ExecutionPlan> {
    let nonce = fresh_nonce();
    let now = Utc::now();

    let tenant_str = input.tenant.unwrap_or(DEFAULT_TENANT);
    if tenant_str.is_empty() {
        anyhow::bail!("tenant must not be empty");
    }
    if input.vm_name.is_empty() {
        anyhow::bail!("vm_name must not be empty");
    }
    if input.image_sha256.len() != 64 {
        anyhow::bail!(
            "image_sha256 must be a 64-character lowercase hex digest, got {} chars",
            input.image_sha256.len()
        );
    }
    if let Some(kernel) = input.kernel_sha256
        && kernel.len() != 64
    {
        anyhow::bail!(
            "kernel_sha256 must be a 64-character lowercase hex digest, got {} chars",
            kernel.len()
        );
    }
    let intent = input.intent.unwrap_or(DEFAULT_INTENT);
    if intent.is_empty() {
        anyhow::bail!("intent must not be empty");
    }

    let network_policy = policy_ref(input.network_policy_ref);
    let fs_policy = fs_policy_ref(input.fs_policy_ref);
    let egress_policy = policy_ref(input.egress_policy_ref);
    let tool_policy = policy_ref(input.tool_policy_ref);
    let admission_profile = admission_profile(
        input,
        intent,
        &network_policy,
        &fs_policy,
        &egress_policy,
        &tool_policy,
    );
    let mut audit_labels = audit_labels_for_profile(&admission_profile);
    // Caller labels fill additional keys; profile-derived keys stay authoritative.
    for (k, v) in &input.audit_labels {
        audit_labels.entry(k.clone()).or_insert_with(|| v.clone());
    }

    let resources = Resources {
        cpus: input.cpus.max(1),
        mem_mib: input.mem_mib.max(64),
        disk_mib: input.disk_mib,
        timeouts: TimeoutSpec {
            boot_secs: input.boot_timeout_secs.max(1),
            exec_secs: input.exec_timeout_secs,
        },
    };

    let image = SignedImageRef {
        name: input.image_name.to_string(),
        sha256: input.image_sha256.to_string(),
        cosign_bundle: input.image_cosign_bundle.map(str::to_string),
        // The CLI only ever synthesizes plans for images that carry an
        // entrypoint (the SDK's compile gate refuses to produce one
        // without). The supervisor's admission gate rejects
        // entrypoint_present == false as defense in depth.
        entrypoint_present: true,
    };

    let environment = input.kernel_sha256.map(|kernel_sha256| EnvironmentRef {
        kernel_sha256: kernel_sha256.to_string(),
    });

    let mut plan = ExecutionPlan {
        environment,
        build_provenance: Default::default(),
        snapshot_at: Default::default(),
        network_mode: input.network_mode,
        // Derived from the mode, never taken alongside it. The two fields
        // disagreeing is an inadmissible plan (the compatibility gate
        // refuses both directions), so synthesis is the one place that can
        // guarantee they never do.
        l3_network: l3_spec_for(input.network_mode, input.l3_network.as_ref()),
        schema_version: SCHEMA_VERSION,
        // Placeholder — overwritten below with the content-address once every
        // load-bearing field is set. The derivation excludes `plan_id`, so this
        // seed value never influences the result.
        plan_id: PlanId(String::new()),
        plan_version: 1,
        tenant: TenantId(tenant_str.to_string()),
        workload: WorkloadId(input.vm_name.to_string()),
        runtime_profile: RuntimeProfileRef(input.backend_name.to_string()),
        image,
        resources,
        admission_profile,
        network_policy,
        fs_policy,
        secrets: input.secrets.clone(),
        egress_policy,
        redaction: input.redaction.clone(),
        reversible_replacement: input.reversible_replacement.clone(),
        tool_policy,
        artifact_policy: ArtifactPolicy {
            capture_paths: Vec::new(),
            retention_days: 0,
        },
        audit_labels,
        key_rotation: KeyRotationSpec { interval_days: 0 },
        attestation: AttestationRequirement {
            mode: AttestationMode::Noop,
        },
        release_pin: None,
        post_run: PostRunLifecycle {
            destroy_on_exit: input.destroy_on_exit,
            snapshot_on_idle: false,
            idle_secs: 0,
        },
        valid_from: now,
        valid_until: now + Duration::minutes(VALIDITY_WINDOW_MINUTES),
        nonce,
        agent_verbs: input.agent_verbs.clone(),
        bundle: input.bundle_pin.clone(),
        // Populated by the caller when an `mvmctl up --from-workload-ir
        // <path>` invocation drove `install_app_deps` to a sealed
        // volume. `None` preserves claim 8 (the supervisor's
        // deps-volume gate is skipped).
        deps_volume: input.deps_volume.clone(),
        shares: input.shares.clone(),
        services: input.services.clone(),
    };

    // Content-address the finished plan. The fresh nonce makes this unique per
    // synthesis; the signature the caller applies next covers the derived id.
    plan.plan_id = crate::plan::compute_plan_id(&plan);
    Ok(plan)
}

/// Generate a fresh 128-bit nonce from `OsRng`. `crate::plan::Nonce`
/// wraps a 32-character lowercase hex string (i.e., 16 bytes = 128
/// bits) — match that here so the wire format roundtrips.
fn fresh_nonce() -> Nonce {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    Nonce::from_bytes(bytes)
}

fn policy_ref(value: Option<&str>) -> PolicyRef {
    PolicyRef(value.unwrap_or(DEFAULT_POLICY_REF).to_string())
}

fn fs_policy_ref(value: Option<&str>) -> FsPolicyRef {
    FsPolicyRef(value.unwrap_or(DEFAULT_POLICY_REF).to_string())
}

fn admission_profile(
    input: &SynthesisInput<'_>,
    intent: &str,
    network_policy: &PolicyRef,
    fs_policy: &FsPolicyRef,
    egress_policy: &PolicyRef,
    tool_policy: &PolicyRef,
) -> AdmissionProfile {
    let profile_id = format!("{intent}:{}", input.seccomp_tier);
    let event_prefix = input
        .audit_event_prefix
        .map(str::to_string)
        .unwrap_or_else(|| event_prefix_for_intent(intent));
    AdmissionProfile {
        id: profile_id,
        intent: WorkloadIntent(intent.to_string()),
        seccomp_tier: input.seccomp_tier,
        network_policy: network_policy.clone(),
        fs_policy: fs_policy.clone(),
        egress_policy: egress_policy.clone(),
        tool_policy: tool_policy.clone(),
        secret_release: input.secret_release,
        audit: AuditTaxonomy {
            event_prefix,
            required_labels: vec![
                "intent".to_string(),
                "admission_profile".to_string(),
                "seccomp_tier".to_string(),
            ],
        },
    }
}

fn event_prefix_for_intent(intent: &str) -> String {
    match intent {
        DEFAULT_INTENT => DEFAULT_AUDIT_EVENT_PREFIX.to_string(),
        "code:execute" => "execution.code".to_string(),
        "agent:web-research" => "agent.web".to_string(),
        "deploy:publish" => "deploy.release".to_string(),
        other => other.replace(':', "."),
    }
}

fn audit_labels_for_profile(profile: &AdmissionProfile) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("intent".to_string(), profile.intent.0.clone()),
        ("admission_profile".to_string(), profile.id.clone()),
        ("seccomp_tier".to_string(), profile.seccomp_tier.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(vm_name: &str) -> SynthesisInput<'_> {
        SynthesisInput {
            kernel_sha256: None,
            network_mode: NetworkMode::default(),
            l3_network: None,
            vm_name,
            tenant: None,
            backend_name: "firecracker",
            image_name: "myimage",
            image_sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            image_cosign_bundle: None,
            intent: None,
            seccomp_tier: PlanSeccompTier::Standard,
            network_policy_ref: None,
            fs_policy_ref: None,
            egress_policy_ref: None,
            tool_policy_ref: None,
            secret_release: SecretReleasePolicy::None,
            secrets: Vec::new(),
            audit_event_prefix: None,
            cpus: 2,
            mem_mib: 512,
            disk_mib: 0,
            boot_timeout_secs: 60,
            exec_timeout_secs: 0,
            destroy_on_exit: false,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: crate::policy::RedactionPolicy::default(),
            reversible_replacement: crate::policy::ReversibleReplacementPolicy::default(),
            audit_labels: Default::default(),
            agent_verbs: None,
            services: Vec::new(),
        }
    }

    #[test]
    fn carries_cli_resource_overrides() {
        let mut inp = input("myvm");
        inp.cpus = 4;
        inp.mem_mib = 2048;
        inp.boot_timeout_secs = 120;
        inp.exec_timeout_secs = 600;
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.resources.cpus, 4);
        assert_eq!(plan.resources.mem_mib, 2048);
        assert_eq!(plan.resources.timeouts.boot_secs, 120);
        assert_eq!(plan.resources.timeouts.exec_secs, 600);
    }

    #[test]
    fn defaults_tenant_to_local() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.tenant.0, DEFAULT_TENANT);
    }

    #[test]
    fn honors_explicit_tenant_override() {
        let mut inp = input("myvm");
        inp.tenant = Some("acme");
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.tenant.0, "acme");
    }

    #[test]
    fn workload_is_vm_name_verbatim() {
        let plan = synthesize_plan(&input("my-special-vm")).unwrap();
        assert_eq!(plan.workload.0, "my-special-vm");
    }

    #[test]
    fn round_trips_through_serde() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let json = serde_json::to_string(&plan).expect("plan serializes");
        let parsed: ExecutionPlan = serde_json::from_str(&json).expect("plan parses");
        assert_eq!(parsed, plan);
    }

    #[test]
    fn generates_unique_plan_id_per_call() {
        // Fresh nonce per synthesis ⇒ distinct content ⇒ distinct
        // content-address, even for byte-identical CLI input.
        let p1 = synthesize_plan(&input("myvm")).unwrap();
        let p2 = synthesize_plan(&input("myvm")).unwrap();
        assert_ne!(p1.plan_id, p2.plan_id);
    }

    #[test]
    fn plan_id_is_the_content_address_of_the_plan() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert!(
            plan.plan_id.0.starts_with("sha256:"),
            "content-addressed, not a UUID: {}",
            plan.plan_id.0
        );
        // The stored id equals the address recomputed from the plan body.
        assert_eq!(crate::plan::verify_plan_id(&plan), Ok(()));
        assert_eq!(plan.plan_id, crate::plan::compute_plan_id(&plan));
    }

    #[test]
    fn signing_does_not_perturb_the_content_address() {
        // The signature lives in the envelope, not the plan body, so the id a
        // verified plan carries is exactly the address of its content.
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let signed = crate::plan::sign_plan(&plan, &key, "host:test");
        let recovered =
            crate::plan::verify_plan(&signed, &[("host:test", &key.verifying_key())]).unwrap();
        assert_eq!(recovered.plan_id, plan.plan_id);
        assert_eq!(crate::plan::verify_plan_id(&recovered), Ok(()));
    }

    #[test]
    fn generates_unique_nonce_per_call() {
        let p1 = synthesize_plan(&input("myvm")).unwrap();
        let p2 = synthesize_plan(&input("myvm")).unwrap();
        assert_ne!(p1.nonce, p2.nonce);
    }

    #[test]
    fn nonce_is_32_hex_chars() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let hex = plan.nonce.as_hex();
        assert_eq!(hex.len(), 32);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn validity_window_is_default_10_minutes() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        let elapsed = plan.valid_until - plan.valid_from;
        assert_eq!(elapsed.num_minutes(), VALIDITY_WINDOW_MINUTES);
    }

    #[test]
    fn enforces_minimum_cpus_of_one() {
        let mut inp = input("myvm");
        inp.cpus = 0;
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.resources.cpus, 1, "CPUs floor at 1");
    }

    #[test]
    fn enforces_minimum_memory_of_64mib() {
        let mut inp = input("myvm");
        inp.mem_mib = 0;
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.resources.mem_mib, 64, "memory floor at 64MiB");
    }

    #[test]
    fn rejects_empty_vm_name() {
        let err = synthesize_plan(&input("")).unwrap_err();
        assert!(err.to_string().contains("vm_name"));
    }

    #[test]
    fn rejects_empty_tenant() {
        let mut inp = input("myvm");
        inp.tenant = Some("");
        let err = synthesize_plan(&inp).unwrap_err();
        assert!(err.to_string().contains("tenant"));
    }

    #[test]
    fn rejects_wrong_length_sha256() {
        let mut inp = input("myvm");
        inp.image_sha256 = "deadbeef";
        let err = synthesize_plan(&inp).unwrap_err();
        assert!(err.to_string().contains("64-character"));
    }

    #[test]
    fn defaults_attestation_to_noop_and_no_release_pin() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.attestation.mode, AttestationMode::Noop);
        assert!(plan.release_pin.is_none());
    }

    #[test]
    fn all_policy_refs_default_to_local_default() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.network_policy.0, DEFAULT_POLICY_REF);
        assert_eq!(plan.fs_policy.0, DEFAULT_POLICY_REF);
        assert_eq!(plan.egress_policy.0, DEFAULT_POLICY_REF);
        assert_eq!(plan.tool_policy.0, DEFAULT_POLICY_REF);
    }

    #[test]
    fn admission_profile_binds_default_intent_to_controls() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.admission_profile.intent.0, DEFAULT_INTENT);
        assert_eq!(
            plan.admission_profile.seccomp_tier,
            PlanSeccompTier::Standard
        );
        assert_eq!(plan.admission_profile.network_policy, plan.network_policy);
        assert_eq!(plan.admission_profile.fs_policy, plan.fs_policy);
        assert_eq!(plan.admission_profile.egress_policy, plan.egress_policy);
        assert_eq!(plan.admission_profile.tool_policy, plan.tool_policy);
        assert_eq!(
            plan.admission_profile.secret_release,
            SecretReleasePolicy::None
        );
        assert_eq!(
            plan.admission_profile.audit.event_prefix,
            DEFAULT_AUDIT_EVENT_PREFIX
        );
        assert_eq!(plan.audit_labels["intent"], DEFAULT_INTENT);
        assert_eq!(
            plan.audit_labels["admission_profile"],
            plan.admission_profile.id
        );
        assert_eq!(plan.audit_labels["seccomp_tier"], "standard");
    }

    #[test]
    fn admission_profile_honors_intent_bound_overrides() {
        let mut inp = input("myvm");
        inp.intent = Some("agent:web-research");
        inp.seccomp_tier = PlanSeccompTier::Network;
        inp.network_policy_ref = Some("acme:web-agent");
        inp.fs_policy_ref = Some("acme:web-agent");
        inp.egress_policy_ref = Some("acme:web-agent");
        inp.tool_policy_ref = Some("acme:web-agent");
        inp.secret_release = SecretReleasePolicy::PlanBound;

        let plan = synthesize_plan(&inp).unwrap();

        assert_eq!(plan.admission_profile.intent.0, "agent:web-research");
        assert_eq!(plan.admission_profile.id, "agent:web-research:network");
        assert_eq!(
            plan.admission_profile.seccomp_tier,
            PlanSeccompTier::Network
        );
        assert_eq!(plan.network_policy.0, "acme:web-agent");
        assert_eq!(plan.admission_profile.network_policy.0, "acme:web-agent");
        assert_eq!(
            plan.admission_profile.secret_release,
            SecretReleasePolicy::PlanBound
        );
        assert_eq!(plan.admission_profile.audit.event_prefix, "agent.web");
        assert_eq!(plan.audit_labels["intent"], "agent:web-research");
        assert_eq!(plan.audit_labels["seccomp_tier"], "network");
    }

    #[test]
    fn synthesized_plan_carries_secret_bindings() {
        let mut inp = input("myvm");
        inp.secret_release = SecretReleasePolicy::PlanBound;
        inp.secrets = vec![SecretBinding {
            name: "API_KEY".into(),
            source: crate::plan::SecretSource::Keystore {
                address: "api-key".into(),
            },
        }];
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.secrets, inp.secrets);
    }

    #[test]
    fn synthesized_plan_carries_redaction_profiles() {
        use crate::policy::{
            EntropyMode, NameMode, RedactionAction, RedactionPolicy, RedactionProfile,
        };
        let mut inp = input("myvm");
        inp.redaction = RedactionPolicy {
            default: RedactionAction::default(),
            profiles: vec![RedactionProfile {
                host: "api.openai.com".into(),
                action: RedactionAction {
                    entropy: EntropyMode::Redact {
                        min_bits_per_char: 4.0,
                        min_run_len: 20,
                    },
                    names: NameMode::Redact,
                    ..Default::default()
                },
            }],
        };
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.redaction.profiles.len(), 1);
        assert_eq!(plan.redaction.profiles[0].host, "api.openai.com");
    }

    #[test]
    fn schema_version_is_pinned() {
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert_eq!(plan.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn without_deps_volume_plan_carries_none() {
        // Claim-8 preservation guard: when the caller doesn't pin a
        // deps volume, the plan carries `deps_volume = None` and the
        // supervisor's admission path skips the gate.
        let plan = synthesize_plan(&input("myvm")).unwrap();
        assert!(plan.deps_volume.is_none());
    }

    #[test]
    fn with_deps_volume_plan_carries_binding_verbatim() {
        // `mvmctl up`'s install pipeline yielded an `InstallResult`;
        // the caller turns it into a `DepsVolumeBinding` and threads it
        // through synthesis. The plan field must round-trip the volume
        // + manifest hashes verbatim so the supervisor's verifier
        // re-derives them against the on-disk volume.
        let volume_hash = "a".repeat(64);
        let manifest_sha256 = "b".repeat(64);
        let binding = DepsVolumeBinding::new(&volume_hash, &manifest_sha256).expect("binding");
        let mut inp = input("myvm");
        inp.deps_volume = Some(binding.clone());
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.deps_volume, Some(binding));
    }

    #[test]
    fn deps_volume_round_trips_through_serde() {
        let binding = DepsVolumeBinding::new("a".repeat(64), "b".repeat(64)).expect("binding");
        let mut inp = input("myvm");
        inp.deps_volume = Some(binding.clone());
        let plan = synthesize_plan(&inp).unwrap();
        let json = serde_json::to_string(&plan).expect("plan serializes");
        let parsed: ExecutionPlan = serde_json::from_str(&json).expect("plan parses");
        assert_eq!(parsed.deps_volume, Some(binding));
    }

    #[test]
    fn caller_audit_labels_merge_into_signed_plan() {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("origin.descriptor".to_string(), "blake3:abc".to_string());
        // A reserved profile key the caller must NOT be able to override.
        labels.insert("intent".to_string(), "spoofed".to_string());
        let mut inp = input("vm");
        inp.audit_labels = labels;
        let plan = synthesize_plan(&inp).unwrap();
        assert_eq!(plan.audit_labels["origin.descriptor"], "blake3:abc");
        // Profile-derived key wins over the caller's attempt.
        assert_ne!(plan.audit_labels["intent"], "spoofed");

        // The label survives the sign -> verify round-trip inside the signed bytes.
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let signed = crate::plan::sign_plan(&plan, &key, "host:test");
        let recovered =
            crate::plan::verify_plan(&signed, &[("host:test", &key.verifying_key())]).unwrap();
        assert_eq!(recovered.audit_labels["origin.descriptor"], "blake3:abc");
    }
}

#[cfg(test)]
mod l3_spec_tests {
    use super::*;

    /// The mode and the spec are two fields that must agree, and admission
    /// refuses both directions of disagreement. Synthesis is the only place
    /// that can guarantee they never do, so it derives one from the other.
    #[test]
    fn the_spec_is_present_exactly_when_the_mode_is_the_tunnel() {
        assert!(l3_spec_for(NetworkMode::L3Vsock, None).is_some());
        assert!(l3_spec_for(NetworkMode::None, None).is_none());
        assert!(l3_spec_for(NetworkMode::HostVsockProxy, None).is_none());
    }

    /// A spec offered alongside a non-L3 mode is dropped rather than
    /// carried: keeping it would make the plan inadmissible.
    #[test]
    fn a_spec_on_a_non_l3_mode_is_dropped() {
        let supplied = L3NetworkSpec::v1();
        assert!(l3_spec_for(NetworkMode::HostVsockProxy, Some(&supplied)).is_none());
    }

    /// A caller that configured limits or ingress keeps them; only the
    /// absent case gets defaults.
    #[test]
    fn a_supplied_spec_is_preserved() {
        let mut supplied = L3NetworkSpec::v1();
        supplied.max_flows = 17;
        let carried = l3_spec_for(NetworkMode::L3Vsock, Some(&supplied)).expect("present");
        assert_eq!(carried.max_flows, 17);
    }

    #[test]
    fn an_absent_spec_becomes_the_version_one_defaults() {
        let carried = l3_spec_for(NetworkMode::L3Vsock, None).expect("present");
        assert_eq!(carried, L3NetworkSpec::v1());
    }

    /// The end-to-end property: a synthesized plan is always admissible on
    /// this axis, whichever mode it carries.
    #[test]
    fn every_synthesized_plan_has_a_consistent_mode_and_spec() {
        for mode in [
            NetworkMode::None,
            NetworkMode::HostVsockProxy,
            NetworkMode::L3Vsock,
        ] {
            let spec = l3_spec_for(mode, None);
            assert_eq!(
                mode.is_l3_vsock(),
                spec.is_some(),
                "{mode:?} produced an inadmissible mode/spec pairing"
            );
        }
    }
}
