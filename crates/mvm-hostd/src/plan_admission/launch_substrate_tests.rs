#![cfg(test)]

use super::test_support::*;
use super::*;

#[test]
fn thread_tenant_id_sets_only_tenant_label_not_the_bridge_plan() {
    use mvm_core::vm_backend::VmStartConfig;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let admitted = admit_for_run(
        &fixture_input("vm-tenant-only"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("happy admit");

    let mut cfg = VmStartConfig::default();
    thread_tenant_id(&mut cfg, &admitted);

    // The broker spawn keys off this label.
    assert_eq!(
        cfg.tenant_id.as_deref(),
        Some(admitted.plan().tenant.0.as_str())
    );
    // It must NOT thread the signed plan / policy bundle — that flips
    // libkrun/HVF onto the gateway-bridge supervisor (+ its ~/.mvm/keys
    // substrate validation), which is a separate opt-in concern.
    assert!(
        cfg.plan_json.is_none(),
        "thread_tenant_id must not set plan_json"
    );
    assert!(
        cfg.bundle_json.is_none(),
        "thread_tenant_id must not set bundle_json"
    );
}

#[test]
fn populate_audit_substrate_threads_tenant_and_signed_envelope() {
    use mvm_core::vm_backend::VmStartConfig;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemClock;
    let ledger = InMemoryNonceLedger::new();
    let admitted = admit_for_run(
        &fixture_input("vm-substrate"),
        &clock,
        &ledger,
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("happy admit");

    let mut cfg = VmStartConfig::default();
    populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
    assert_eq!(
        cfg.tenant_id.as_deref(),
        Some(admitted.plan().tenant.0.as_str())
    );
    let audit = cfg.audit_context.as_ref().expect("audit binding populated");
    assert_eq!(audit.plan(), Some(admitted.plan()));
    let plan_json = cfg.plan_json.expect("plan_json populated");
    let roundtrip: mvm_core::plan::SignedExecutionPlan =
        serde_json::from_str(&plan_json).expect("roundtrip");
    // Re-verify the envelope to get the inner ExecutionPlan and
    // confirm the plan_id matches what the producer admitted.
    let signer = crate::audit::host_keypair::load_or_init_at(dir.path()).unwrap();
    let trusted: [(&str, &ed25519_dalek::VerifyingKey); 1] =
        [(admitted.signer_id(), &signer.verifying)];
    let recovered =
        mvm_core::plan::verify_plan(&roundtrip, &trusted).expect("envelope re-verifies");
    assert_eq!(&recovered.plan_id, admitted.plan_id());
    // fixture has no bundle pin, so bundle_json stays None
    assert!(cfg.bundle_json.is_none());
}

#[test]
fn bundle_json_carries_a_policy_bundle_not_the_artifact_pin() {
    // De-conflation: bundle_json is the tenant PolicyBundle the
    // supervisor's L4 gate + observers consume — sourced from the
    // policy_bundle arg, NOT from `admitted.plan().bundle` (the .mvmpkg
    // PlanArtifact pin, a different bundle verified separately).
    use mvm_core::vm_backend::VmStartConfig;
    let (_env, _home) = host_with_ceiling(Default::default());
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemClock;
    let ledger = InMemoryNonceLedger::new();
    let admitted = admit_for_run(
        &fixture_input("vm-policy-bundle"),
        &clock,
        &ledger,
        Some(dir.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("happy admit");

    let bundle = mvm_core::policy::PolicyBundle {
        schema_version: mvm_core::policy::SCHEMA_VERSION,
        bundle_id: mvm_core::policy::PolicyId("test".into()),
        bundle_version: 1,
        network: Default::default(),
        egress: Default::default(),
        pii: Default::default(),
        artifact: Default::default(),
        keys: Default::default(),
        audit: Default::default(),
        wasi: Default::default(),
        tenant_overlays: std::collections::BTreeMap::new(),
    };

    let mut cfg = VmStartConfig::default();
    populate_audit_substrate(&mut cfg, &admitted, Some(&bundle)).expect("populate");
    let bj = cfg.bundle_json.expect("bundle_json populated");
    let roundtrip: mvm_core::policy::PolicyBundle =
        serde_json::from_str(&bj).expect("bundle_json deserializes as a PolicyBundle");
    assert_eq!(roundtrip, bundle);

    // No policy bundle → None (the de-conflated default; a pinned artifact
    // no longer leaks into this field).
    let mut cfg2 = VmStartConfig::default();
    populate_audit_substrate(&mut cfg2, &admitted, None).expect("populate none");
    assert!(cfg2.bundle_json.is_none());
}

// ───────────────────────────────────────────────────────────────
// write_secret_file + stash_plan_for_bridge

#[test]
fn shared_launch_preparation_persists_exact_admitted_envelope_and_guest_grant() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = mvm_core::config::mvm_keys_dir();
    let mut input = fixture_input("prepared-owned-actor");
    input.agent_verbs = Some(vec![mvm_core::plan::VerbId::new("run-entrypoint").unwrap()]);
    let admitted = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(&keys),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .unwrap();
    let expected = serde_json::to_vec(admitted.signed()).unwrap();
    let state = mvm_core::config::vm_state_dir(input.vm_name);
    assert!(!state.join("plan.json").exists());
    let config = VmStartConfig {
        name: input.vm_name.into(),
        rootfs_path: "/store/rootfs.ext4".into(),
        // Caller-supplied bytes must never replace the admitted envelope.
        plan_json: Some("untrusted caller bytes".into()),
        ..Default::default()
    };
    let (config, _) = super::final_gates::run_post_admission_gates(
        config,
        &admitted,
        mvm_core::vm_backend::BackendKind::Mock,
        None,
    )
    .unwrap();
    assert_eq!(std::fs::read(state.join("plan.json")).unwrap(), expected);
    assert_eq!(config.plan_json.unwrap().as_bytes(), expected);
    let grant: mvm_core::protocol::vm_backend::VerbGrantEnvelope =
        serde_json::from_slice(&std::fs::read(state.join("verb-grant.json")).unwrap()).unwrap();
    assert_eq!(grant.plan_nonce_hex, admitted.plan().nonce.as_hex());
    assert_eq!(config.audit_context.unwrap().plan(), Some(admitted.plan()));
}

#[test]
fn shared_launch_preparation_refuses_unwritable_plan_before_dispatch() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();
    let admitted = admit_for_run(
        &fixture_input("blocked-plan"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .unwrap();
    let state = mvm_core::config::vm_state_dir("blocked-plan");
    std::fs::create_dir_all(state.join("plan.json")).unwrap();
    let result = super::final_gates::run_post_admission_gates(
        VmStartConfig {
            name: "blocked-plan".into(),
            rootfs_path: "/store/rootfs.ext4".into(),
            ..Default::default()
        },
        &admitted,
        mvm_core::vm_backend::BackendKind::Mock,
        None,
    );
    let Err((stage, _)) = result else {
        panic!("plan persistence failure must refuse launch preparation");
    };
    assert_eq!(stage, "launch-substrate");
}
// ───────────────────────────────────────────────────────────────

#[test]
#[cfg(unix)]
fn write_secret_file_creates_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plan.json");
    write_secret_file(&path, b"{\"hello\":\"world\"}").expect("write");
    let meta = std::fs::metadata(&path).expect("stat");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "secret file must be mode 0600 (got {mode:o})");
    let body = std::fs::read(&path).expect("read");
    assert_eq!(body, b"{\"hello\":\"world\"}");
}

#[test]
#[cfg(unix)]
fn write_secret_file_atomic_via_rename() {
    // Two consecutive writes; the second must fully replace the
    // first and leave no `*.json.tmp` artifact behind. This proves
    // the tmp-and-rename happy path doesn't leak partial files.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plan.json");
    write_secret_file(&path, b"first body").expect("first write");
    write_secret_file(&path, b"second body wins").expect("second write");
    assert_eq!(std::fs::read(&path).unwrap(), b"second body wins");
    // The tmp file path is `plan.json.tmp`; it must not exist after
    // a clean write.
    assert!(
        !dir.path().join("plan.json.tmp").exists(),
        "tmp file should be renamed away"
    );
}

#[test]
#[cfg(unix)]
fn write_secret_file_never_writes_through_a_planted_link() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = dir.path().join("outside");
    std::fs::write(&outside, b"untouched").unwrap();
    let path = dir.path().join("plan.json");
    // A link at the old fixed temporary name and one at the destination:
    // neither may carry the write to the file they point at.
    std::os::unix::fs::symlink(&outside, path.with_extension("json.tmp")).unwrap();
    write_secret_file(&path, b"first").expect("write past a planted temporary");
    assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
    assert_eq!(std::fs::read(&path).unwrap(), b"first");

    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&outside, &path).unwrap();
    write_secret_file(&path, b"second").expect("write over a planted destination");
    assert_eq!(std::fs::read(&outside).unwrap(), b"untouched");
    assert!(
        !std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"second");
}

#[test]
#[cfg(unix)]
fn write_secret_file_creates_parent_dir() {
    // The bridge writes under `~/.mvm/vms/<vm>/`; that dir may not
    // exist on a first boot. The helper must create it (matching
    // the `stash_plan_for_bridge` callsite's invariant).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vms").join("foo").join("plan.json");
    write_secret_file(&path, b"body").expect("write with missing parent");
    assert!(path.exists());
}

#[test]
fn stash_plan_for_bridge_skips_when_plan_json_none() {
    use mvm_core::vm_backend::VmStartConfig;
    // Legacy / no-admission path: cfg.plan_json is None.
    // `stash_plan_for_bridge` must succeed without touching disk
    // because there's nothing to stash.
    let dir = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", dir.path());

    let cfg = VmStartConfig {
        name: "skip-me".into(),
        ..Default::default()
    };
    stash_plan_for_bridge(&cfg).expect("None plan_json is a no-op");
    assert!(
        !dir.path().join("vms/skip-me/plan.json").exists(),
        "no files when plan_json is None"
    );
}

#[test]
#[cfg(unix)]
fn stash_plan_for_bridge_writes_both_files_when_present() {
    use mvm_core::vm_backend::VmStartConfig;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", dir.path());

    let cfg = VmStartConfig {
        name: "with-plan".into(),
        plan_json: Some("{\"plan\":\"body\"}".into()),
        bundle_json: Some("{\"bundle\":\"pin\"}".into()),
        ..Default::default()
    };
    stash_plan_for_bridge(&cfg).expect("stash succeeds");

    let plan_path = dir.path().join("vms/with-plan/plan.json");
    let bundle_path = dir.path().join("vms/with-plan/bundle.json");
    assert!(plan_path.exists(), "plan.json must be written");
    assert!(bundle_path.exists(), "bundle.json must be written");
    assert_eq!(
        std::fs::metadata(&plan_path).unwrap().permissions().mode() & 0o777,
        0o600,
        "plan.json must be mode 0600"
    );
    assert_eq!(
        std::fs::metadata(&bundle_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "bundle.json must be mode 0600"
    );
}

// ───────────────────────────────────────────────────────────────
// verb-grant sidecar: stash_plan_for_bridge mint path
// ───────────────────────────────────────────────────────────────

#[test]
#[cfg(unix)]
fn stash_plan_for_bridge_writes_verb_grant_when_agent_verbs_present() {
    use ed25519_dalek::VerifyingKey;
    use mvm_core::plan::VerbId;
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
    use mvm_core::vm_backend::VmStartConfig;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", dir.path());
    let keys_dir = mvm_core::config::mvm_keys_dir();

    // Build an admitted plan that carries agent_verbs.
    let mut input = fixture_input("vm-verb-grant");
    input.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
    let admitted = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys_dir.as_path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("admit with agent_verbs");

    let mut cfg = VmStartConfig {
        name: "vm-verb-grant".into(),
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
    let issued = stash_plan_and_mint_verb_grant(&cfg)
        .expect("stash succeeds")
        .expect("agent verbs mint a grant");

    let grant_path = dir.path().join("vms/vm-verb-grant/verb-grant.json");
    assert!(grant_path.exists(), "verb-grant.json must be written");
    let mode = std::fs::metadata(&grant_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "verb-grant.json must be mode 0600");

    // Parse the envelope and verify the grant under the signer key.
    let raw = std::fs::read(&grant_path).unwrap();
    let envelope: VerbGrantEnvelope = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        serde_json::to_vec(&issued).unwrap(),
        serde_json::to_vec(&envelope).unwrap(),
        "the returned envelope is exactly the sidecar payload"
    );
    assert!(!envelope.pubkey_hex.is_empty(), "pubkey_hex must be set");
    assert_eq!(
        envelope.plan_nonce_hex,
        admitted.plan().nonce.as_hex(),
        "nonce hex must match plan"
    );
    assert_eq!(
        envelope.grant.not_after,
        admitted.plan().valid_until,
        "a verb grant must not outlive its admitted plan"
    );
    let pub_arr: [u8; 32] = hex::decode(&envelope.pubkey_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let vk = VerifyingKey::from_bytes(&pub_arr).unwrap();
    envelope
        .grant
        .verify(
            &vk,
            "vm-verb-grant",
            &admitted.plan().nonce,
            mvm_core::util::time::utc_timestamp_now(),
        )
        .expect("grant must verify under the signer key");
}

#[test]
fn stash_plan_for_bridge_no_verb_grant_when_agent_verbs_absent() {
    use mvm_core::vm_backend::VmStartConfig;

    let dir = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", dir.path());
    let keys_dir = mvm_core::config::mvm_keys_dir();

    // Plain plan with no agent_verbs — the fixture default.
    let admitted = admit_for_run(
        &fixture_input("vm-no-verbs"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys_dir.as_path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("admit without agent_verbs");

    let mut cfg = VmStartConfig {
        name: "vm-no-verbs".into(),
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg, &admitted, None).expect("populate");
    stash_plan_for_bridge(&cfg).expect("stash succeeds");

    assert!(
        !dir.path().join("vms/vm-no-verbs/verb-grant.json").exists(),
        "verb-grant.json must NOT be written when agent_verbs is None"
    );
}

#[test]
#[cfg(unix)]
fn stash_plan_for_bridge_removes_stale_verb_grant_on_grant_less_restash() {
    use mvm_core::plan::VerbId;
    use mvm_core::vm_backend::VmStartConfig;

    let dir = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", dir.path());
    let keys_dir = mvm_core::config::mvm_keys_dir();

    let vm_name = "vm-stale-grant";

    // First boot: plan with agent_verbs — sidecar must be written.
    let mut input_with = fixture_input(vm_name);
    input_with.agent_verbs = Some(vec![VerbId::new("run-entrypoint").unwrap()]);
    let admitted_with = admit_for_run(
        &input_with,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys_dir.as_path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("admit with agent_verbs");
    let mut cfg_with = VmStartConfig {
        name: vm_name.into(),
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg_with, &admitted_with, None).expect("populate");
    stash_plan_for_bridge(&cfg_with).expect("first stash succeeds");

    let grant_path = dir.path().join(format!("vms/{vm_name}/verb-grant.json"));
    assert!(
        grant_path.exists(),
        "verb-grant.json must be present after first stash"
    );

    // Second boot: same VM name, no agent_verbs — stale sidecar must be removed.
    let admitted_without = admit_for_run(
        &fixture_input(vm_name),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys_dir.as_path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("admit without agent_verbs");
    let mut cfg_without = VmStartConfig {
        name: vm_name.into(),
        ..Default::default()
    };
    populate_audit_substrate(&mut cfg_without, &admitted_without, None).expect("populate");
    stash_plan_for_bridge(&cfg_without).expect("second stash succeeds");

    assert!(
        !grant_path.exists(),
        "stale verb-grant.json must be removed on a grant-less re-stash of the same VM name"
    );
}

/// Three points around the cap. The `>` → `==` mutant admits
/// everything above the cap, which is the whole vector the cap closes;
/// `>` → `>=` refuses a payload exactly at it. Only a boundary test
/// separates the two, and only an extracted comparison makes a
/// boundary test cheap.
#[test]
fn the_size_cap_admits_up_to_the_cap_and_refuses_above_it() {
    assert!(enforce_size_cap("plan_json", 0, 16).is_ok());
    assert!(enforce_size_cap("plan_json", 15, 16).is_ok());
    assert!(
        enforce_size_cap("plan_json", 16, 16).is_ok(),
        "a payload exactly at the cap is within it"
    );
    assert!(
        enforce_size_cap("plan_json", 17, 16).is_err(),
        "a payload over the cap must be refused"
    );
    assert!(
        enforce_size_cap("plan_json", usize::MAX, 16).is_err(),
        "a cap that only refuses one exact size is not a cap"
    );
}

/// The stale-sidecar removal exists so a reused VM name cannot inherit
/// the previous boot's grant. Swallowing a real removal failure leaves
/// that grant in place while reporting success — the one outcome the
/// removal is there to prevent.
#[test]
fn a_failed_stale_grant_removal_is_not_reported_as_success() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("vm-state");
    std::fs::create_dir_all(&state_dir).unwrap();

    // A non-empty directory where the sidecar file belongs: remove_file
    // refuses it, and the refusal is not NotFound.
    let sidecar = state_dir.join("verb-grant.json");
    std::fs::create_dir_all(&sidecar).unwrap();
    std::fs::write(sidecar.join("occupant"), b"stale").unwrap();

    assert!(
        mint_verb_grant_sidecar("{}", "vm-reused", &state_dir).is_err(),
        "a stale grant that could not be removed must not read as removed"
    );

    // Absent is still the quiet, successful case.
    let clean = tmp.path().join("clean-state");
    std::fs::create_dir_all(&clean).unwrap();
    assert!(mint_verb_grant_sidecar("{}", "vm-fresh", &clean).is_ok());
}
