#![cfg(test)]

use super::test_support::*;
use super::*;

#[test]
fn local_retention_requires_a_configured_host_ceiling() {
    let mut grant = MailboxGrant {
        mailbox: MailboxId::from_bytes([1; 32]),
        authority_key: [2; 32],
        epoch: ExecutionEpoch::new(1).expect("epoch"),
        report: None,
        retention: None,
        service_blind: None,
    };
    assert!(enforce_mailbox_retention(Some(&grant), None).is_ok());
    grant.retention = Some(MailboxRetentionPolicy::new(10_000).expect("window"));
    assert!(enforce_mailbox_retention(Some(&grant), None).is_err());
    assert!(enforce_mailbox_retention(Some(&grant), Some(0)).is_err());
    assert!(enforce_mailbox_retention(Some(&grant), Some(u64::MAX)).is_err());
    assert!(enforce_mailbox_retention(Some(&grant), Some(9_999)).is_err());
    assert!(enforce_mailbox_retention(Some(&grant), Some(10_000)).is_ok());
    assert!(enforce_mailbox_retention(Some(&grant), Some(20_000)).is_ok());
}

/// Run `f` with a subscriber installed, returning its value and everything
/// that was logged.
///
/// A test that only asserts "admitted" cannot tell a warned admission from
/// a silent one, and the difference is the whole dev half of the rule.
fn capturing_warnings<T>(f: impl FnOnce() -> T) -> (T, String) {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("log sink poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let sink = Sink(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    // Another thread may have cached a callsite as uninteresting before
    // this per-thread subscriber existed; recompute before running `f`.
    let value = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        f()
    });
    let logged = String::from_utf8(sink.0.lock().expect("log sink poisoned").clone())
        .expect("log output is utf-8");
    (value, logged)
}

#[cfg(target_os = "macos")]
#[test]
fn host_cpu_mechanism_gap_honors_hvf_quota_range() {
    // On macOS the HVF tier serves CPU shares through its own scheduler.
    // A share outside the scheduler's range is a missing mechanism; a
    // share inside the range is enforceable.
    assert!(
        host_cpu_mechanism_gap(&cpu_share(1500), BackendKind::Hvf, None).is_some(),
        "1500 millicores is out of range and must be reported as unenforceable"
    );
    assert!(
        host_cpu_mechanism_gap(&cpu_share(500), BackendKind::Hvf, None).is_none(),
        "500 millicores is inside the scheduler range and is enforceable"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn prod_admits_a_valid_hvf_cpu_share() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();

    let mut input = fixture_input("vm-hvf-valid-share");
    input.backend_name = "hvf";
    input.grants = Some(cpu_share(500));

    admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
    )
    .expect("a 500 millicore share is enforceable on HVF");
}

/// The spawn-time memory and task ceilings are host protection nobody
/// requested, so a host that cannot attach them is no reason to refuse a
/// sealed run: without a CPU share there is no mechanism gap to report,
/// whichever half of the mechanism is missing.
#[test]
fn a_missing_scope_mechanism_refuses_nothing_that_did_not_ask_for_cpu() {
    use mvm_core::spawn_scope::MechanismGap;
    for kind in [
        BackendKind::Firecracker,
        BackendKind::Qemu,
        BackendKind::Libkrun,
    ] {
        for gap in [
            MechanismGap::SystemdRunMissing,
            MechanismGap::NoUserSessionBus,
        ] {
            assert_eq!(
                host_cpu_mechanism_gap(&mvm_contract::grants::Grants::default(), kind, Some(gap)),
                None,
                "{kind:?} with {gap:?}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn host_cpu_mechanism_gap_requires_a_share_capable_tier_and_a_reported_gap() {
    use mvm_core::spawn_scope::MechanismGap;

    let missing_bus = Some(MechanismGap::NoUserSessionBus);
    assert_eq!(
        host_cpu_mechanism_gap(
            &mvm_contract::grants::Grants::default(),
            BackendKind::Firecracker,
            missing_bus,
        ),
        None,
        "a plan with no CPU share has no CPU mechanism gap"
    );
    assert_eq!(
        host_cpu_mechanism_gap(&cpu_share(1000), BackendKind::Wasm, missing_bus),
        None,
        "a tier whose CPU control is not a cgroup share does not use the host mechanism"
    );
    assert_eq!(
        host_cpu_mechanism_gap(&cpu_share(1000), BackendKind::Firecracker, None),
        None,
        "an available host mechanism leaves no gap"
    );

    let detail = host_cpu_mechanism_gap(&cpu_share(1000), BackendKind::Firecracker, missing_bus)
        .expect("a missing mechanism must be reported for a share-capable tier");
    assert!(detail.contains("no user session bus"), "{detail}");
}

/// Admit the fixture under a home whose `host-interface/` files are
/// `files`; returns the admission result.
fn admit_with_host_interface_files(files: &[(&str, &str)]) -> Result<AdmittedPlan> {
    let (_env, home) = host_with_ceiling(Default::default());
    let hi = home.path().join("host-interface");
    std::fs::create_dir_all(&hi).unwrap();
    for (name, body) in files {
        std::fs::write(hi.join(name), body).unwrap();
    }
    let keys = tempfile::tempdir().unwrap();
    admit_for_run(
        &fixture_input("vm-host-interface"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
}

/// The launch budgets are 300 ms cold and 50 ms warm for everything the
/// preflight adds. This times only the host-interface gate (node record,
/// policy and ledger reads, and the concurrent checks), not synthesis,
/// signing or the boot. It asserts the median, which is stable on a loaded
/// runner, and prints the 99th percentile for the record; run with
/// `--nocapture` to read both.
#[test]
fn host_interface_preflight_stays_inside_the_launch_budgets() {
    use std::time::{Duration, Instant};
    let (_env, _home) = host_with_ceiling(Default::default());
    let plan = synthesize_plan(&fixture_input("vm-timing")).expect("fixture plan");

    let cold = Instant::now();
    host_gates::admit_host_interface(&plan).expect("the default node admits");
    let cold = cold.elapsed();

    let mut warm: Vec<Duration> = (0..300)
        .map(|_| {
            let t = Instant::now();
            host_gates::admit_host_interface(&plan).expect("admits");
            t.elapsed()
        })
        .collect();
    warm.sort();
    let (p50, p99) = (warm[warm.len() / 2], warm[warm.len() * 99 / 100]);
    println!("host-interface preflight: cold {cold:?}, warm p50 {p50:?}, p99 {p99:?}");

    assert!(
        cold < Duration::from_millis(300),
        "cold {cold:?} exceeds the 300 ms budget"
    );
    assert!(
        p50 < Duration::from_millis(50),
        "warm p50 {p50:?} exceeds the 50 ms budget"
    );
}

#[test]
fn host_interface_with_no_local_state_admits_unchanged() {
    admit_with_host_interface_files(&[]).expect("the permissive local default admits");
}

#[test]
fn host_interface_refuses_revoked_and_quarantined_nodes() {
    for state in ["revoked", "quarantined"] {
        let node = format!(r#"{{"node_id":"local","state":"{state}","epoch":1}}"#);
        let err = admit_with_host_interface_files(&[("node.json", &node)])
            .expect_err("a node that is not active must not boot a workload");
        assert!(err.to_string().contains(state), "{err}");
    }
}

#[test]
fn host_interface_refuses_only_the_quarantined_workload() {
    let name = "vm-host-interface";
    let ledger = format!(r#"{{"{name}":{{"epoch":1,"quarantined":true}}}}"#);
    let err = admit_with_host_interface_files(&[("workloads.json", &ledger)])
        .expect_err("a quarantined workload must not boot");
    assert!(err.to_string().contains("quarantined"), "{err}");
    let other = r#"{"some-other-workload":{"epoch":1,"quarantined":true}}"#;
    admit_with_host_interface_files(&[("workloads.json", other)])
        .expect("quarantining another workload must not block this one");
}

#[test]
fn host_interface_refuses_a_plan_from_before_a_replacement() {
    // The ledger says epoch 2; a plan synthesized before the replacement
    // (or issued by a control plane that never saw it) still carries 1.
    let (_env, home) = host_with_ceiling(Default::default());
    let hi = home.path().join("host-interface");
    std::fs::create_dir_all(&hi).unwrap();
    std::fs::write(
        hi.join("workloads.json"),
        r#"{"vm-epoch":{"epoch":2,"quarantined":false}}"#,
    )
    .unwrap();
    let mut stale = synthesize_plan(&fixture_input("vm-epoch")).unwrap();
    assert_eq!(
        stale.execution_epoch, 2,
        "synthesis reads the current epoch"
    );
    stale.execution_epoch = 1;
    let err = host_gates::admit_host_interface(&stale)
        .expect_err("a plan at an older epoch must not admit");
    assert!(err.to_string().contains("stale execution epoch"), "{err}");
    stale.execution_epoch = 2;
    host_gates::admit_host_interface(&stale).expect("the current epoch admits");
    stale.execution_epoch = 3;
    assert!(
        host_gates::admit_host_interface(&stale).is_err(),
        "an epoch the host never issued is refused too"
    );
}

#[test]
fn host_interface_refuses_expired_policy_and_unpinned_image() {
    let expired =
        admit_with_host_interface_files(&[("policy.json", r#"{"version":1,"not_after":1}"#)])
            .expect_err("an expired policy must not admit");
    assert!(expired.to_string().contains("expired"), "{expired}");
    let pinned = admit_with_host_interface_files(&[(
        "policy.json",
        r#"{"version":1,"not_after":null,"image_digests":["feedface"]}"#,
    )])
    .expect_err("an image outside the pinned list must not admit");
    assert!(pinned.to_string().contains("image"), "{pinned}");
}

#[test]
fn host_interface_refuses_a_malformed_or_hardware_requiring_policy() {
    let bad = admit_with_host_interface_files(&[("policy.json", "{nope")])
        .expect_err("a malformed policy must fail closed");
    assert!(bad.to_string().contains("unreadable"), "{bad}");
    let hw = admit_with_host_interface_files(&[(
        "policy.json",
        r#"{"version":1,"not_after":null,"attestation":{"required":true,"minimum":"hardware"}}"#,
    )])
    .expect_err("software evidence cannot satisfy a hardware requirement");
    assert!(hw.to_string().contains("attestation"), "{hw}");
}

#[test]
fn admission_refuses_a_grant_over_the_ceiling() {
    let (_env, _home) = host_with_ceiling(mvm_contract::grants::ceiling::GrantCeiling {
        max_cpu_millicores: Some(2000),
        ..Default::default()
    });
    let keys = tempfile::tempdir().unwrap();

    let mut input = fixture_input("vm-over-ceiling");
    input.grants = Some(cpu_share(64_000));

    let err = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("a grant above the host's ceiling must not be admitted");
    let msg = err.to_string();
    assert!(msg.contains("ceiling"), "{msg}");
    assert!(msg.contains("64000") && msg.contains("2000"), "{msg}");

    // Under the same ceiling, a request within it still admits — otherwise
    // this test would pass on a gate that refuses everything.
    let mut within = fixture_input("vm-under-ceiling");
    within.grants = Some(cpu_share(1500));
    admit_for_run(
        &within,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("a grant inside the ceiling admits");
}

#[test]
fn mailbox_retention_above_or_without_host_ceiling_refuses_before_signing() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().expect("keystore");
    let mut input = fixture_input("vm-retention");
    input.mailbox = Some(MailboxGrant {
        mailbox: MailboxId::from_bytes([1; 32]),
        authority_key: [2; 32],
        epoch: ExecutionEpoch::new(1).expect("epoch"),
        report: None,
        retention: Some(MailboxRetentionPolicy::new(10_000).expect("window")),
        service_blind: None,
    });
    let attempt = || {
        admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::without_backend(Variant::Dev),
        )
    };
    let missing = attempt().expect_err("missing operator ceiling must refuse");
    assert!(
        missing.to_string().contains("max_mailbox_retention_ms"),
        "{missing:#}"
    );
    assert!(
        !keys.path().join("host-signer.ed25519").exists(),
        "a refused grant must not reach the keystore"
    );
    let mut config = mvm_core::user_config::load(None);
    config.max_mailbox_retention_ms = Some(9_999);
    mvm_core::user_config::save(&config, None).expect("set host ceiling");
    let over = attempt().expect_err("request above host ceiling must refuse");
    assert!(over.to_string().contains("ceiling"), "{over:#}");
    assert!(
        !keys.path().join("host-signer.ed25519").exists(),
        "an over-ceiling grant must not be signed"
    );
}

#[test]
fn admission_refuses_before_signing() {
    // Not "an error came back" — no *signature* may exist for a run we
    // refuse. The host signer is generated lazily on first use, so an
    // untouched keys dir is proof the keystore was never reached and
    // therefore that nothing was signed.
    let (_env, _home) = host_with_ceiling(mvm_contract::grants::ceiling::GrantCeiling {
        max_cpu_millicores: Some(2000),
        ..Default::default()
    });
    let keys = tempfile::tempdir().unwrap();
    let key_file = keys
        .path()
        .join(crate::audit::host_keypair::SECRET_FILENAME);

    let mut input = fixture_input("vm-refused-unsigned");
    input.grants = Some(cpu_share(64_000));
    let refused = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    );
    assert!(refused.is_err(), "the ceiling must refuse this run");
    assert!(
        !key_file.exists(),
        "the refusal path reached the keystore; a plan we would not admit \
         must never acquire a signature"
    );

    // The control: an admitted run does reach the keystore, so the
    // assertion above is about the refusal and not about a keys dir that
    // is never written under any outcome.
    admit_for_run(
        &fixture_input("vm-admitted-signed"),
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect("an unbounded run admits");
    assert!(
        key_file.exists(),
        "an admitted run signs under the host key"
    );
}

#[test]
fn prod_refuses_a_cpu_grant_on_a_backend_that_cannot_bound_cpu() {
    // The hvf tier has no cgroup equivalent on any host, so a CPU share is
    // a bound nothing behind it implements. The tier comes from the
    // posture — the backend in hand — not from the plan's label.
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();

    let mut input = fixture_input("vm-prod-unenforceable");
    input.backend_name = "hvf";
    input.grants = Some(cpu_share(1500));

    let err = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
    )
    .expect_err("a sealed run must not boot with a bound nothing enforces");
    let msg = err.to_string();
    assert!(msg.contains("unenforceable"), "{msg}");
    assert!(msg.contains("cpu.share"), "{msg}");
}

#[test]
fn dev_warns_and_proceeds_on_the_same_input() {
    // Same tier, same grant, dev posture: admitted, because a laptop that
    // cannot bound CPU is where most development happens and refusing
    // there would only teach everyone to stop declaring grants.
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();

    let mut input = fixture_input("vm-dev-unenforceable");
    input.backend_name = "hvf";
    input.grants = Some(cpu_share(1500));

    let (result, logs) = capturing_warnings(|| {
        admit_for_run(
            &input,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
            RunPosture::on_backend(Variant::Dev, BackendKind::Hvf),
        )
    });
    let admitted = result.expect("a dev run proceeds with an unenforceable grant");
    assert_eq!(
        admitted.plan().grants.as_ref().map(|g| g.cpu),
        Some(Some(mvm_contract::grants::CpuGrant::Share {
            millicores: 1500
        })),
        "the declared grant rides in the signed plan even when unenforced"
    );

    // "Warns" is half of what this test's name promises, so it is asserted
    // rather than assumed: a silent admission would leave the operator with
    // a grant they believe is bounding something.
    assert!(
        logs.contains("WARN"),
        "the dev path must warn, not admit silently: {logs:?}"
    );
    assert!(
        logs.contains("cpu.share") && logs.contains("not enforced"),
        "the warning must name what went unenforced: {logs:?}"
    );

    // Posture is the only difference between this outcome and the refusal
    // above. Asserted against the gate directly as well, so a change that
    // makes the rule unconditional in either direction fails here and not
    // only in the prod witness.
    let plan = admitted.plan();
    let grants = cpu_share(1500);
    assert!(
        enforceability_gate(
            &grants,
            plan,
            RunPosture::on_backend(Variant::Prod, BackendKind::Hvf)
        )
        .is_err()
    );
    assert!(
        enforceability_gate(
            &grants,
            plan,
            RunPosture::on_backend(Variant::Dev, BackendKind::Hvf)
        )
        .is_ok()
    );
}

#[test]
fn a_mismatched_profile_label_cannot_select_the_wrong_tier() {
    // A fuel grant is enforceable on the wasm tier and on no other. A plan
    // labelled `wasm` that is actually booting on hvf must not be admitted
    // on the strength of that label — the label is the plan author's
    // string, the tier is what will run.
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();
    let fuel = mvm_contract::grants::Grants {
        cpu: Some(mvm_contract::grants::CpuGrant::Fuel {
            instructions: 1_000_000,
        }),
        ..mvm_contract::grants::Grants::default()
    };

    let mut mislabelled = fixture_input("vm-mislabelled");
    mislabelled.backend_name = "wasm";
    mislabelled.grants = Some(fuel.clone());
    let err = admit_for_run(
        &mislabelled,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
    )
    .expect_err("the label must not buy admission for a tier that is not booting");
    let msg = err.to_string();
    assert!(msg.contains("runtime profile"), "{msg}");
    assert!(msg.contains("wasm") && msg.contains("hvf"), "{msg}");

    // Honest label, honest tier, and the same grant: still refused, because
    // hvf meters no instructions. The refusal follows the tier either way.
    let mut honest = fixture_input("vm-honest-label");
    honest.backend_name = "hvf";
    honest.grants = Some(fuel.clone());
    let err = admit_for_run(
        &honest,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Prod, BackendKind::Hvf),
    )
    .expect_err("no microVM tier counts instructions");
    assert!(err.to_string().contains("cpu.fuel"), "{err}");

    // And on the tier that does meter them, the same grant admits — so the
    // two refusals above are about the mechanism, not about fuel grants
    // being refused everywhere.
    let mut on_wasm = fixture_input("vm-on-wasm");
    on_wasm.backend_name = "wasm";
    on_wasm.grants = Some(fuel);
    admit_for_run(
        &on_wasm,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Prod, BackendKind::Wasm),
    )
    .expect("the wasm tier meters instructions, so a fuel grant is enforceable there");
}

#[test]
fn a_run_admitted_without_a_backend_cannot_claim_its_grants_are_enforced() {
    // A caller with no backend object has nothing to measure against. That
    // must fail closed rather than fall back to the plan's own label, which
    // is how a mislabelled plan would pick its own controls.
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();

    // `firecracker` is a tier that *can* bound a share on Linux, so a gate
    // reading the label would admit this on a host where that is true.
    let mut input = fixture_input("vm-no-backend");
    input.backend_name = "firecracker";
    input.grants = Some(cpu_share(1500));

    let err = admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Prod),
    )
    .expect_err("an unmeasurable grant must not be admitted under a sealed posture");
    assert!(err.to_string().contains("without the backend"), "{err}");
}

#[test]
fn a_profile_that_names_no_tier_is_not_treated_as_a_disagreement() {
    // `mvmctl exec` labels its plans `transient-run`; the lineage path uses
    // the workload's name. Neither is a backend, so neither can contradict
    // the backend in hand — refusing them as a mismatch would break real
    // paths over a string that never claimed to be a tier.
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();

    let mut input = fixture_input("vm-transient");
    input.backend_name = "transient-run";
    input.grants = Some(mvm_contract::grants::Grants {
        cpu: Some(mvm_contract::grants::CpuGrant::Fuel {
            instructions: 1_000_000,
        }),
        ..mvm_contract::grants::Grants::default()
    });

    admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::on_backend(Variant::Prod, BackendKind::Wasm),
    )
    .expect("the tier that boots meters instructions, whatever the profile is called");
}

#[test]
fn a_run_that_grants_nothing_is_unaffected_by_the_tier_gate() {
    // The gate must stay silent for the overwhelmingly common case, or
    // every unbounded boot on a laptop becomes a warning.
    let (_env, _home) = host_with_ceiling(Default::default());
    let keys = tempfile::tempdir().unwrap();

    let mut input = fixture_input("vm-no-grants");
    input.backend_name = "hvf";
    admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Prod),
    )
    .expect("a run declaring no grant admits on any tier");
}

#[test]
fn the_ceiling_bounds_memory_even_though_no_one_granted_it() {
    // Memory is fixed at VM creation rather than requested, so a plan that
    // declares no grants at all can still reserve the whole host.
    let (_env, _home) = host_with_ceiling(mvm_contract::grants::ceiling::GrantCeiling {
        max_memory_mib: Some(128),
        ..Default::default()
    });
    let keys = tempfile::tempdir().unwrap();

    let err = admit_for_run(
        &fixture_input("vm-fat"), // fixture asks for 256 MiB
        &SystemClock,
        &InMemoryNonceLedger::new(),
        Some(keys.path()),
        None,
        RunPosture::without_backend(Variant::Dev),
    )
    .expect_err("memory above the ceiling must be refused");
    assert!(err.to_string().contains("memory_mib"), "{err}");
}
