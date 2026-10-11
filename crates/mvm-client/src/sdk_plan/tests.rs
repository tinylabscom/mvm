use super::*;

fn recording() -> LoadedRecording {
    load_recording_bytes(
        br#"{"workload_id":"shape","create":{"template":"minimal"},"ops":[{"kind":"command_start","argv":["true"],"env":{}}]}"#,
        None,
    )
    .unwrap()
}

#[test]
fn placeholder_image_sha_is_64_hex_chars() {
    let sha = placeholder_image_sha("wl-id", "app-1");
    assert_eq!(sha.len(), 64);
    assert!(sha.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
}

#[test]
fn placeholder_image_sha_is_stable() {
    let a = placeholder_image_sha("wl", "app");
    let b = placeholder_image_sha("wl", "app");
    assert_eq!(a, b, "same inputs must yield same SHA");
}

#[test]
fn placeholder_image_sha_differs_per_app() {
    let a = placeholder_image_sha("wl", "app1");
    let b = placeholder_image_sha("wl", "app2");
    assert_ne!(a, b, "different app names must yield different SHAs");
}

#[test]
fn byte_loader_checks_digest_before_parsing() {
    assert!(matches!(
        load_recording_bytes(b"invalid", Some(&"0".repeat(64))),
        Err(PlanError::Digest(_))
    ));
    assert!(matches!(
        load_recording_bytes(b"invalid", None),
        Err(PlanError::Parse(_))
    ));
    let bytes = br#"{"workload_id":"shape","create":{"template":"minimal"},"ops":[]}"#;
    assert!(matches!(
        load_recording_bytes(bytes, None),
        Err(PlanError::Lower(_))
    ));
}

#[test]
fn byte_loader_preserves_digest_and_divergence() {
    let bytes = br#"{"workload_id":"shape","create":{"template":"minimal"},"ops":[{"kind":"command_start","argv":["true"],"env":{}},{"kind":"kill"}]}"#;
    let digest = mvm_sdk::runtime::recording_sha256_hex(bytes);
    let loaded = load_recording_bytes(bytes, Some(&digest)).unwrap();
    assert_eq!(loaded.digest_hex, digest);
    assert_eq!(loaded.findings.len(), 1);
    assert_eq!(loaded.findings[0].kind_slug(), "kill-dropped");
    assert!(matches!(
        loaded.validate(&PlanOptions::default()),
        Err(PlanError::Unacknowledged { count: 1, .. })
    ));
    loaded
        .validate(&PlanOptions {
            acknowledged_divergences: vec!["kill-dropped".into()],
            ..Default::default()
        })
        .unwrap();
}

#[test]
fn recording_gates_run_before_any_admission() {
    let mut loaded = recording();
    loaded.secret_findings.push(SecretFinding {
        location: "create env[TOKEN]".into(),
        rules: vec!["test".into()],
    });
    loaded
        .findings
        .push(Divergence::KillDropped { op_index: 0 });
    let options = PlanOptions {
        acknowledged_divergences: vec!["kill-dropped".into()],
        ..Default::default()
    };
    let result = loaded.admit_with(&options, |_| panic!("must not reach host admission"));
    assert!(matches!(
        result,
        Err(PlanError::EmbeddedSecrets { count: 1 })
    ));
    loaded.secret_findings.clear();
    let result = loaded.admit_with(&PlanOptions::default(), |_| {
        panic!("must not reach host admission")
    });
    assert!(matches!(
        result,
        Err(PlanError::Unacknowledged { count: 1, .. })
    ));
    loaded.findings.clear();
    loaded.workload.apps.clear();
    let result = loaded.admit_with(&options, |_| panic!("must not reach host admission"));
    assert!(matches!(result, Err(PlanError::NoApps)));
}

#[test]
fn dry_orchestration_preserves_order_and_continues_after_refusal() {
    let mut loaded = recording();
    let mut second = loaded.workload.apps[0].clone();
    second.name = "second".into();
    loaded.workload.apps.push(second);
    let mut calls = Vec::new();
    let report = loaded
        .admit_with(&PlanOptions::default(), |input| {
            calls.push(input.vm_name.to_owned());
            assert_eq!(
                input.network_mode,
                crate::launch::persistent::preflight_network()
            );
            assert_eq!(input.backend_name, "firecracker");
            assert_eq!(input.image_sha256.len(), 64);
            assert!(input.bundle_pin.is_none());
            assert!(input.destroy_on_exit);
            if calls.len() == 1 {
                anyhow::bail!("policy refused");
            }
            Ok(AdmissionSummary {
                plan_id: "plan".into(),
                signer_id: "signer".into(),
                cpus: input.cpus,
                mem_mib: input.mem_mib,
                workload: input.vm_name.into(),
                tenant: "tenant".into(),
            })
        })
        .unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1], "second");
    assert_eq!(report.admitted_count(), 1);
    assert_eq!(report.rejected_count(), 1);
    assert_eq!(
        report.apps[0].result.as_ref().unwrap_err(),
        "policy refused"
    );
}

#[test]
fn synthesis_preserves_resource_floors_and_identity_hash() {
    let mut loaded = recording();
    let app = &mut loaded.workload.apps[0];
    app.resources.cpu_cores = 0;
    app.resources.memory_mb = 1;
    let hash = placeholder_image_sha(&loaded.workload.id, &app.name);
    let commitment = mvm_core::plan::CallerCommitment::from_bytes([7; 32]);
    let input = synthesis_input_for_app(app, &hash, Some(commitment.clone())).unwrap();
    assert_eq!(input.cpus, 1);
    assert_eq!(input.mem_mib, 64);
    assert_eq!(input.disk_mib, app.resources.rootfs_size_mb as u64);
    assert_eq!(input.image_sha256, hash);
    assert_eq!(input.caller_commitment, Some(commitment));
    assert!(input.ingress.is_empty());
}

#[test]
fn synthesis_failure_aborts_after_observing_completed_apps() {
    let mut loaded = recording();
    let mut invalid = loaded.workload.apps[0].clone();
    invalid.name = "invalid-ingress".into();
    invalid.network = Some(mvm_contract::ir::Network {
        mode: mvm_contract::ir::NetworkMode::Bridge,
        ports: vec![mvm_contract::ir::PortForward {
            mapping_id: 0,
            host_addr: "127.0.0.1".into(),
            host: 8080,
            guest_addr: "127.0.0.1".into(),
            guest: 80,
            proto: PortProto::Tcp,
            transform: PortTransform::Opaque,
            tls_secret: None,
        }],
        preset: None,
        egress: None,
        peers: Vec::new(),
        dns: None,
        ai: None,
    });
    loaded.workload.apps.push(invalid);
    loaded.workload.apps.push(loaded.workload.apps[0].clone());
    let mut calls = 0;
    let mut observed = Vec::new();
    let result = loaded.admit_with_observer(
        &PlanOptions::default(),
        |_| {
            calls += 1;
            anyhow::bail!("admission refusal")
        },
        |app| observed.push(app.app.clone()),
    );
    assert!(matches!(result, Err(PlanError::Synthesis { app, .. }) if app == "invalid-ingress"));
    assert_eq!(calls, 1);
    assert_eq!(observed, [loaded.workload.apps[0].name.clone()]);
}
