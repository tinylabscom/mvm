//! A profile and the same flags admit the same plan.
//!
//! Resolved all the way through: the profile is folded into launch flags,
//! the flags go through grant resolution, and both sides are admitted by the
//! real admission path — synthesized, signed, verified — before their plans
//! are compared.

use mvm_core::user_config::MvmConfig;
use mvm_hostd::plan_admission::InMemoryNonceLedger;

use super::*;
use crate::admission::entrypoint_resolve::ResolvedEntrypoint;
use crate::admission::run_grants::{GrantInputs, RunGrants, resolve_run_grants};
use crate::admission::{AdmitPlanForBootParams, admit_plan_for_boot};

fn grants_for(
    allow_host: &[String],
    cpu_limit: Option<u32>,
    timeout: Option<u64>,
    config: &MvmConfig,
) -> RunGrants {
    resolve_run_grants(GrantInputs {
        cpu_limit_millicores: cpu_limit,
        timeout_secs: timeout,
        allow_host,
        peer: &[],
        net: false,
        network_preset: None,
        grants_file: None,
        manifest: None,
        config,
        ai: None,
    })
    .expect("grants resolve")
}

/// Admit a plan carrying `grants` and return it.
fn admitted_plan(grants: &RunGrants, dir: &std::path::Path) -> mvm_core::plan::ExecutionPlan {
    let rootfs = dir.join("rootfs.ext4");
    std::fs::write(&rootfs, b"equivalence rootfs").unwrap();
    let keys = dir.join("keys");
    let audit = dir.join("audit");
    let ledger = InMemoryNonceLedger::new();
    let ctx = admit_plan_for_boot(AdmitPlanForBootParams {
        outputs: Vec::new(),
        network_mode: mvm_contract::plan::NetworkMode::default(),
        tenant: "local",
        vm_name: "vm-equivalence",
        backend_name: "firecracker",
        configured_images_dir: None,
        rootfs_path: &rootfs,
        kernel_path: None,
        precomputed_image_sha256: None,
        boot_artifact_identity: None,
        cpus: 2,
        mem_mib: 512,
        seccomp_tier: mvm_core::plan::PlanSeccompTier::Standard,
        secret_release: mvm_core::plan::SecretReleasePolicy::None,
        secrets: Vec::new(),
        caller_commitment: None,
        ledger: &ledger,
        keys_dir: Some(&keys),
        audit_dir: Some(&audit),
        policy_dir: None,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        network_policy: grants.network_policy.clone(),
        agent_verb_override: vec![],
        restrict_agent_verbs: false,
        services: Vec::new(),
        grants: grants.plan_grants.clone(),
        backend_kind: None,
        entrypoint: ResolvedEntrypoint::unresolved("this test does not resolve one"),
        assets: Vec::new(),
    })
    .expect("admission succeeds");
    ctx.admitted.plan().clone()
}

/// The fields of a plan that the policy decides.
fn policy_fields(
    plan: &mvm_core::plan::ExecutionPlan,
) -> (Option<mvm_contract::grants::Grants>, Vec<String>) {
    let policy_assets = plan
        .asset_identities
        .iter()
        .filter(|a| a.kind == mvm_core::plan::AssetKind::Policy)
        .map(|a| a.digest.clone())
        .collect();
    (plan.grants.clone(), policy_assets)
}

#[test]
fn a_profile_and_the_same_flags_admit_the_same_plan() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::at(store_dir.path());
    std::fs::create_dir_all(store.profiles_dir()).unwrap();
    std::fs::create_dir_all(store.groups_dir()).unwrap();
    // Loopback names only: admission resolves every allowed host while it
    // builds the signed network policy, and a test must not need DNS.
    std::fs::write(
        store.groups_dir().join("local-apis.toml"),
        "[network]\nallow = [\"localhost:8443\", \"localhost:9443\"]\n",
    )
    .unwrap();
    std::fs::write(
        store.groups_dir().join("dropped.toml"),
        "[network]\nallow = [\"localhost:7443\"]\n",
    )
    .unwrap();
    std::fs::write(
        store.profiles_dir().join("base.toml"),
        "extends = \"default\"\n[groups]\ninclude = [\"local-apis\", \"dropped\"]\n",
    )
    .unwrap();
    std::fs::write(
        store.profiles_dir().join("agent.toml"),
        "extends = \"base\"\n[groups]\nexclude = [\"dropped\"]\n\
         [overrides.network]\nallow = [\"localhost:6443\"]\ndeny = [\"localhost:9443\"]\n\
         [overrides.resources]\ncpu_millicores = 750\nwall_clock_secs = 120\n",
    )
    .unwrap();
    let resolved = resolve(
        &store,
        &PolicySelection::profile(PolicyRef::Name("agent".into())),
        Platform::default(),
    )
    .unwrap();
    let folded = fold(
        &resolved.policy,
        &LaunchFlags {
            cpus: 2,
            memory_mib: 512,
            ..LaunchFlags::default()
        },
    )
    .unwrap();

    let config = MvmConfig::default();
    let from_profile = grants_for(
        &folded.allow_host,
        folded.cpu_limit,
        folded.timeout,
        &config,
    );
    let by_hand: Vec<String> = ["localhost:8443", "localhost:6443"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let from_flags = grants_for(&by_hand, Some(750), Some(120), &config);
    assert_eq!(
        from_profile, from_flags,
        "the same grants and egress policy"
    );

    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    assert_eq!(
        policy_fields(&admitted_plan(&from_profile, a.path())),
        policy_fields(&admitted_plan(&from_flags, b.path())),
        "the signed plans carry the same grants and the same policy digest"
    );
}

#[test]
fn a_resolved_manifest_admits_the_same_plan_as_its_profile() {
    let store = PolicyStore::at(tempfile::tempdir().unwrap().path());
    let resolved = resolve(
        &store,
        &PolicySelection::profile(PolicyRef::Name("dev-network".into())),
        Platform::default(),
    )
    .unwrap();
    let json = serde_json::to_vec(&ResolvedManifest::from_resolved(&resolved)).unwrap();
    let manifest = ResolvedManifest::from_json(&json, "manifest", None).unwrap();

    let flags = LaunchFlags {
        cpus: 2,
        memory_mib: 512,
        ..LaunchFlags::default()
    };
    let config = MvmConfig::default();
    let direct = fold(&resolved.policy, &flags).unwrap();
    let replayed = fold(&manifest.policy, &flags).unwrap();
    assert_eq!(direct, replayed);
    assert_eq!(
        grants_for(
            &direct.allow_host,
            direct.cpu_limit,
            direct.timeout,
            &config
        ),
        grants_for(
            &replayed.allow_host,
            replayed.cpu_limit,
            replayed.timeout,
            &config
        )
    );
}
