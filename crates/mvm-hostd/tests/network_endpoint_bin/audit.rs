use super::*;
use mvm_core::audit_sink::AuditContext;
use mvm_hostd::supervisor::endpoint::network_endpoint::FlowMuxIdentity;

fn flow_config(socket: &std::path::Path) -> (EndpointConfig, ed25519_dalek::SigningKey) {
    use base64::Engine as _;
    let host = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let guest = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut cfg = test_config(EndpointTransport::Uds {
        path: socket.to_owned(),
    });
    cfg.egress_mode = EgressMode::FlowMux;
    cfg.flowmux_identity = Some(FlowMuxIdentity {
        session_id: "audit-startup".into(),
        host_signing_key_base64: b64.encode(host.to_bytes()),
        guest_verifying_key_base64: b64.encode(guest.verifying_key().to_bytes()),
    });
    (cfg, guest)
}

fn refused_start(cfg: &EndpointConfig, home: &std::path::Path) -> std::process::Output {
    let mut child = Command::new(BIN)
        .env("MVM_HOME", home)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(cfg).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Record `workload` at `epoch` in the workload ledger under `home`, the way
/// the policy coordinator would have after advancing it.
fn ledger_at(home: &std::path::Path, workload: &str, epoch: u64) {
    let dir = mvm_core::host_interface::workload::canonical_dir_at(home);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(mvm_core::host_interface::workload::LEDGER_FILE),
        serde_json::json!({
            "sequence": 1,
            "workloads": { workload: { "epoch": epoch, "quarantined": false } },
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn a_plan_whose_epoch_the_ledger_does_not_admit_refuses_before_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    ledger_at(&home, "test", 2);
    let socket = dir.path().join("network.sock");
    let (mut cfg, _) = flow_config(&socket);
    let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
    plan.tenant = mvm_core::plan::TenantId("local".into());
    plan.workload = mvm_core::plan::WorkloadId("test".into());
    plan.execution_epoch = 1;
    cfg.audit = Some(AuditContext::Workload {
        plan: Box::new(plan),
    });
    let output = refused_start(&cfg, &home);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "no readiness for a stale epoch");
    assert!(UnixStream::connect(&socket).is_err());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("does not admit"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_missing_audit_binding_refuses_before_listener_or_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("network.sock");
    let (mut cfg, _) = flow_config(&socket);
    cfg.audit = None;
    let output = refused_start(&cfg, &dir.path().join("home"));
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "no readiness may precede audit binding"
    );
    assert!(
        !socket.exists(),
        "an unbound endpoint must not bind a listener"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("bound audit identity"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_missing_recorder_key_refuses_instead_of_starting_without_audit() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("network.sock");
    let (cfg, _) = flow_config(&socket);
    let output = refused_start(&cfg, &dir.path().join("home"));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(UnixStream::connect(&socket).is_err());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("required audit recorder"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn twenty_fresh_endpoint_sessions_record_each_plan_bound_denial_before_response() {
    for epoch in 1..=20 {
        let dir = tempfile::tempdir().unwrap();
        let _environment = audit_environment(dir.path());
        // Each session runs at the epoch the ledger names current for it.
        ledger_at(&dir.path().join("mvm-home"), "test", epoch);
        let socket = dir.path().join("network.sock");
        let (mut cfg, guest_key) = flow_config(&socket);
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.tenant = mvm_core::plan::TenantId("local".into());
        plan.workload = mvm_core::plan::WorkloadId("test".into());
        plan.plan_id = mvm_core::plan::PlanId(format!("endpoint-denial-{epoch}"));
        plan.execution_epoch = epoch;
        cfg.audit = Some(AuditContext::Workload {
            plan: Box::new(plan.clone()),
        });
        let mut child = Command::new(BIN)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&cfg).unwrap())
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let guard = Kill(child);
        let mut ready = String::new();
        stdout.read_line(&mut ready).unwrap();
        assert!(!ready.is_empty(), "endpoint {epoch} did not become ready");
        let mut guest = UnixStream::connect(&socket).unwrap();
        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let host = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        let (mut session, _) =
            mvm_core::net::session::Session::guest(&mut guest, guest_key, &host).unwrap();
        complete_flowmux_hello(&mut guest, &mut session);
        write_flowmux_frame(
            &mut guest,
            &mut session,
            Opcode::OpenTcp,
            1,
            b"denied.example:443",
        );
        let (opcode, _, _) = read_flowmux_frame(&mut guest, &mut session);
        assert_eq!(opcode, Opcode::Refused);
        let journal = mvm_core::config::mvm_audit_dir().join("local.jsonl");
        let audit_key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key();
        mvm_hostd::supervisor::audit::audit_file::verify_audit_chain(&journal, &audit_key).unwrap();
        let entries = std::fs::read_to_string(&journal).unwrap();
        let denied: Vec<serde_json::Value> = entries
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|value| value["entry"]["event"] == "host.flow.denied")
            .collect();
        assert_eq!(denied.len(), 1, "epoch {epoch}: {entries}");
        assert_eq!(denied[0]["entry"]["plan_id"], plan.plan_id.0);
        assert_eq!(
            denied[0]["entry"]["labels"]["execution_epoch"],
            epoch.to_string()
        );
        drop(guest);
        drop(guard);
    }
}
