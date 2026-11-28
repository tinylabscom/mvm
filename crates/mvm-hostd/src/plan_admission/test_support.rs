#![cfg(test)]

//! Fixtures shared by the plan-admission test files.

pub(super) use super::extension_packs::{
    budgets_are_narrower, extension_artifact_exceeds_budget, extension_binding_matches_contract,
    validate_extension_bindings,
};
pub(super) use super::grant_validation::{
    enforce_mailbox_retention, enforceability_gate, host_cpu_mechanism_gap,
};
pub(super) use super::launch_substrate::{enforce_size_cap, write_secret_file};
pub(super) use super::registry_pack::verify_registry_pack_assets;
pub(super) use super::start::{attach_assurance_proxy, launch_decision_record};
pub(super) use super::verb_grant_sidecar::mint_verb_grant_sidecar;
use super::*;
pub(super) use crate::audit::host_keypair::host_signer_id;
pub(super) use ed25519_dalek::SigningKey;
pub(super) use mvm_build::guest_libc::GuestLibc;
pub(super) use mvm_contract::builder::BuilderError;
pub(super) use mvm_contract::protocol::mailbox::{
    ExecutionEpoch, MailboxGrant, MailboxId, MailboxRetentionPolicy,
};
pub(super) use mvm_contract::protocol::resource_controls::EnforcedGrants;
pub(super) use mvm_contract::provenance::DecisionCategory;
pub(super) use mvm_contract::timestamp::UtcTimestamp;
pub(super) use mvm_core::plan::test_support::PlanFixture;
pub(super) use mvm_core::plan::{
    ExecutionPlan, PlanSeccompTier, SecretReleasePolicy, SynthesisInput, check_window, sign_plan,
    synthesize_plan, verify_plan,
};
pub(super) use mvm_core::user_config::{MvmConfig, TrustedPlanSigner};
pub(super) use mvm_core::util::test_env::TestEnv;
pub(super) use mvm_core::vm_backend::VmId;
pub(super) use rand::Rng;
pub(super) use sha2::{Digest, Sha256};

pub(super) const FIXTURE_SHA: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub(super) fn fixture_input(vm_name: &str) -> SynthesisInput<'_> {
    SynthesisInput {
        mailbox: None,
        outputs: Vec::new(),
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        network_mode: Default::default(),
        ingress: Vec::new(),
        vm_name,
        tenant: None,
        backend_name: "firecracker",
        image_name: "img",
        image_sha256: FIXTURE_SHA,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        secret_release: SecretReleasePolicy::None,
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: 1,
        mem_mib: 256,
        disk_mib: 0,
        boot_timeout_secs: 30,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        assets: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        caller_commitment: None,
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
    }
}

/// The libc the shipped cdylib is built for. These tests assert attachment
/// *shape* — count, read-only, kind — so they hold the libc loadable and
/// let the dedicated libc tests vary it.
/// One libc for both sides of the admission fixtures: what the image
/// records and what the sidecar was filed under have to agree for the
/// attachment to be admissible, and these tests are about the other rules.
pub(super) const LOADABLE_LIBC: GuestLibc = GuestLibc::Musl;

/// A sidecar volume shaped the way the resolver actually hands one over:
/// filed under its libc, because that segment is where the gate reads the
/// variant from. A path without it is not a lesser fixture, it is a
/// different case — covered by
/// `a_sidecar_filed_under_no_libc_is_refused`.
pub(super) fn sdk_sidecar_volume() -> mvm_core::vm_backend::VmVolume {
    sdk_sidecar_volume_for(LOADABLE_LIBC)
}

/// The same volume filed under an arbitrary libc, so a test can state both
/// sides of the comparison instead of leaning on which one the shared
/// fixture happens to use.
pub(super) fn sdk_sidecar_volume_for(libc: GuestLibc) -> mvm_core::vm_backend::VmVolume {
    use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
    VmVolume {
        host: format!(
            "/cache/sdk-sidecar/1.2.3/aarch64/{}/sdk.ext4",
            libc.as_str()
        ),
        guest: mvm_core::plan::SDK_SIDECAR_GUEST_PATH.into(),
        read_only: true,
        kind: VmVolumeKind::Disk,
        ..Default::default()
    }
}

pub(super) fn plan_binding(services: &[&str]) -> ExecutionPlan {
    let mut input = fixture_input("vm-sdk");
    input.services = services
        .iter()
        .map(|s| mvm_contract::protocol::broker::ServiceId::parse(*s).expect("fixture service id"))
        .collect();
    synthesize_plan(&input).expect("fixture plan synthesizes")
}

pub(super) struct FixedClock(pub(super) UtcTimestamp);

impl Clock for FixedClock {
    fn now(&self) -> UtcTimestamp {
        self.0
    }
}

// ---- grants: the ceiling, and what the tier can actually enforce ----

/// Isolate `MVM_HOME` and write an operator config carrying `ceiling`.
///
/// Admission reads the ceiling from host config rather than from a
/// parameter, so a test that wants a bounded host has to *be* one. Every
/// test that reaches `admit_for_run` or `admit_and_start` must hold the
/// returned guard, including tests using the default ceiling; otherwise it
/// can observe another parallel test's process-wide `MVM_HOME`. The guard
/// and home dir must both outlive the admission call.
pub(super) fn host_with_ceiling(
    ceiling: mvm_contract::grants::ceiling::GrantCeiling,
) -> (mvm_core::util::test_env::TestEnv, tempfile::TempDir) {
    let home = tempfile::tempdir().expect("scratch mvm home");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let cfg = mvm_core::user_config::MvmConfig {
        max_cpu_millicores: ceiling.max_cpu_millicores,
        max_memory_mib: ceiling.max_memory_mib,
        max_wall_clock_secs: ceiling.max_wall_clock_secs,
        ..mvm_core::user_config::MvmConfig::default()
    };
    mvm_core::user_config::save(&cfg, None).expect("writing the host config");
    // Precondition, not a redundant assertion: if this fails the isolation
    // did not hold, and every ceiling assertion below would then be
    // measuring some other directory's config.
    assert_eq!(
        mvm_core::user_config::load(None).grant_ceiling(),
        ceiling,
        "the isolated host must read back the ceiling it was configured with"
    );
    (env, home)
}

pub(super) fn cpu_share(millicores: u32) -> mvm_contract::grants::Grants {
    mvm_contract::grants::Grants {
        cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores }),
        ..mvm_contract::grants::Grants::default()
    }
}

/// Admit a synthesized plan and boot it through the shared admitted-start
/// tail: the two calls a local launch makes, as one step.
pub(super) fn admit_and_start(
    backend: &mvm_runtime::AnyBackend,
    params: AdmitAndStartParams<'_>,
) -> Result<StartedMachine> {
    let verified =
        mvm_runtime::runtime_evidence::verify_selected_release_runtime_set(&params.config)?;
    let admitted = admit_synthesized_with_verified_release(backend, &params, verified.as_ref())?;
    start_admitted_with_verified_release(
        StartAdmittedParams {
            backend,
            admitted,
            config: params.config,
            emitter: params.emitter,
            assurance: params.assurance,
        },
        verified.as_ref(),
    )
}
