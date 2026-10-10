use super::*;
use std::process::{Command, Stdio};

// These helpers are direct owned children. `exec` replaces the shell; no
// background grandchildren, VMs, runtime commands or credential resolution.
fn helper(script: &str) -> OwnedEndpoint {
    require_child_custody().unwrap();
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut endpoint = OwnedEndpoint::new(child);
    endpoint.arm().unwrap();
    endpoint
}

fn exited(endpoint: &mut OwnedEndpoint) {
    if endpoint.status.is_some() {
        return;
    }
    let event = endpoint
        .observer
        .as_ref()
        .unwrap()
        .wait_event(Instant::now() + Duration::from_secs(3))
        .unwrap();
    assert_eq!(event, ProcessExitWait::Exited);
    endpoint.exit_observed = true;
}

#[test]
fn valid_handshake_retains_child_until_explicit_idempotent_shutdown() {
    let mut endpoint =
        helper("cat >/dev/null; printf '{\"env\":[],\"input_fingerprints\":[]}\\n'; exec sleep 30");
    assert_eq!(
        exchange(&mut endpoint, b"{}", Duration::from_secs(3)).unwrap(),
        EndpointHandshake::default()
    );
    assert!(endpoint.exit_status().is_none());
    endpoint.shutdown().unwrap();
    assert_eq!(
        endpoint.exit_status().unwrap().signal(),
        Some(libc::SIGKILL)
    );
    endpoint.shutdown().unwrap();
    assert_eq!(endpoint.faults.signal_attempts, 1);
}

#[test]
fn invalid_handshake_does_not_echo_secret_or_release_ownership() {
    let mut endpoint =
        helper("cat >/dev/null; printf '{\"credential\":\"secret-canary\"}\\n'; exec sleep 30");
    let error = exchange(&mut endpoint, b"{}", Duration::from_secs(3)).unwrap_err();
    assert!(error.to_string().contains("invalid"));
    assert!(!format!("{error:?}").contains("secret-canary"));
    assert!(endpoint.collect().unwrap().is_none());
    endpoint.shutdown().unwrap();
}

#[test]
fn oversized_handshake_is_bounded() {
    let mut endpoint = helper("cat >/dev/null; printf '%01048577d' 0; exec sleep 30");
    let error = exchange(&mut endpoint, b"{}", Duration::from_secs(3)).unwrap_err();
    assert!(error.to_string().contains("byte limit"));
    endpoint.shutdown().unwrap();
}

#[test]
fn silent_handshake_and_unread_config_have_one_total_deadline() {
    let mut silent = helper("exec sleep 30");
    let start = Instant::now();
    assert!(
        exchange(&mut silent, b"{}", Duration::from_millis(25))
            .unwrap_err()
            .to_string()
            .contains("timed out")
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    silent.shutdown().unwrap();
    let mut blocked = helper("exec sleep 30");
    let start = Instant::now();
    assert!(
        exchange(
            &mut blocked,
            &vec![0; HANDSHAKE_LIMIT],
            Duration::from_millis(25)
        )
        .unwrap_err()
        .to_string()
        .contains("timed out")
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    blocked.shutdown().unwrap();
}

#[test]
fn eof_does_not_mean_exit_and_unrelated_child_is_not_signaled() {
    let mut sentinel = helper("exec sleep 30");
    let mut endpoint = helper("cat >/dev/null; exec 1>&-; exec sleep 30");
    assert!(
        exchange(&mut endpoint, b"{}", Duration::from_secs(3))
            .unwrap_err()
            .to_string()
            .contains("closed stdout")
    );
    assert!(endpoint.collect().unwrap().is_none());
    endpoint.shutdown().unwrap();
    assert!(sentinel.collect().unwrap().is_none());
    assert_eq!(sentinel.faults.signal_attempts, 0);
    sentinel.shutdown().unwrap();
}

#[test]
fn exit_status_is_preserved_and_nonzero_is_never_success() {
    for code in [0, 23] {
        let mut endpoint = helper(&format!("exit {code}"));
        exited(&mut endpoint);
        assert_eq!(endpoint.collect().unwrap().unwrap().code(), Some(code));
        assert_eq!(endpoint.shutdown().is_ok(), code == 0);
        assert_eq!(endpoint.shutdown().is_ok(), code == 0);
        assert_eq!(endpoint.exit_status().unwrap().code(), Some(code));
        assert_eq!(endpoint.faults.signal_attempts, 0);
    }
}

#[test]
fn child_exited_before_registration_keeps_exact_status() {
    let child = Command::new("/bin/sh")
        .args(["-c", "exit 37"])
        .spawn()
        .unwrap();
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let observer = ProcessExitObserver::arm(pid).unwrap();
    assert_eq!(
        observer
            .wait_event(Instant::now() + Duration::from_secs(3))
            .unwrap(),
        ProcessExitWait::Exited
    );
    let mut endpoint = OwnedEndpoint::new(child);
    endpoint.arm().unwrap();
    assert_eq!(endpoint.collect().unwrap().unwrap().code(), Some(37));
    assert!(endpoint.shutdown().is_err());
    assert_eq!(endpoint.faults.signal_attempts, 0);
}

#[test]
fn delayed_exit_event_is_not_reaped_by_observer() {
    let mut endpoint = helper("sleep 0.02; exit 19");
    exited(&mut endpoint);
    assert!(endpoint.status.is_none());
    assert_eq!(endpoint.collect().unwrap().unwrap().code(), Some(19));
    assert!(endpoint.shutdown().is_err());
}

#[test]
fn failed_kill_retains_child_and_evidence_for_retry() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = directory.path().join(SUBST_PID_FILE);
    let mut endpoint = helper("exec sleep 30");
    std::fs::write(&evidence, endpoint.id().to_string()).unwrap();
    endpoint.faults.kill_error = true;
    assert!(endpoint.shutdown().is_err());
    assert!(endpoint.collect().unwrap().is_none());
    assert!(evidence.exists());
    endpoint.faults.kill_error = false;
    endpoint.shutdown().unwrap();
    assert!(evidence.exists());
}

#[test]
fn failed_wait_forbids_signals_and_preserves_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = directory.path().join(SUBST_PID_FILE);
    let mut endpoint = helper("exec sleep 30");
    std::fs::write(&evidence, endpoint.id().to_string()).unwrap();
    endpoint.faults.wait_error = true;
    assert!(endpoint.shutdown().is_err());
    assert_eq!(endpoint.faults.signal_attempts, 0);
    assert!(evidence.exists());
    endpoint.faults.wait_error = false;
    assert!(endpoint.shutdown().is_err());
    assert_eq!(endpoint.faults.signal_attempts, 0);
    // Test owns the child and knows the injected error did not lose custody.
    endpoint.child.kill().unwrap();
    exited(&mut endpoint);
    assert!(endpoint.shutdown().is_err());
    assert!(endpoint.exit_status().is_some());
    assert!(evidence.exists());
}

#[test]
fn timeout_is_not_success_and_retry_does_not_signal_again() {
    let mut endpoint = helper("exec sleep 30");
    endpoint.faults.timeout = true;
    assert!(endpoint.shutdown().is_err());
    assert!(endpoint.exit_status().is_none());
    assert_eq!(endpoint.faults.signal_attempts, 1);
    endpoint.faults.timeout = false;
    exited(&mut endpoint);
    endpoint.shutdown().unwrap();
    assert_eq!(endpoint.faults.signal_attempts, 1);
}

#[test]
fn drop_is_bounded_and_never_deletes_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let evidence = directory.path().join(SUBST_PID_FILE);
    let endpoint = helper("exec sleep 30");
    std::fs::write(&evidence, endpoint.id().to_string()).unwrap();
    let start = Instant::now();
    drop(endpoint);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(evidence.exists());
}

#[test]
fn evidence_creation_refuses_existing_files_and_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let existing = directory.path().join("existing");
    std::fs::write(&existing, b"original").unwrap();
    assert!(create_evidence(&existing).is_err());
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&existing, &link).unwrap();
    assert!(create_evidence(&link).is_err());
    assert_eq!(std::fs::read(existing).unwrap(), b"original");
}

#[test]
fn startup_error_retains_child_and_redacted_reason() {
    let mut error = anyhow::Error::new(OwnedEndpointSpawnError {
        reason: anyhow!("invalid owned endpoint handshake"),
        endpoint: helper("exec sleep 30"),
    });
    let failure = error.downcast_mut::<OwnedEndpointSpawnError>().unwrap();
    failure.endpoint_mut().shutdown().unwrap();
    assert!(failure.endpoint_mut().exit_status().is_some());
}

#[test]
fn shared_command_preserves_lifetime_arguments_without_owned_detachment() {
    let log = tempfile::tempfile().unwrap();
    let state = Path::new("/test/endpoint-state");
    let command = endpoint_command(Path::new("/test/helper"), EndpointLifetime::Vm, state, log);
    assert_eq!(command.get_program(), "/test/helper");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [VM_LIFETIME_FLAG, "/test/endpoint-state"]
    );
}

fn params<'a>(
    state: &'a Path,
    redaction: &'a mvm_core::policy::RedactionPolicy,
) -> SubstitutionSpawnParams<'a> {
    SubstitutionSpawnParams::builder()
        .vm_name("owned-endpoint-fixture")
        .state_dir(state)
        .lifetime(EndpointLifetime::Launcher)
        .tenant("fixture")
        .secrets(&[])
        .redaction(redaction)
        .transport(EndpointTransport::Uds {
            path: state.join("endpoint.sock"),
        })
        .build()
        .unwrap()
}

fn script(directory: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join("endpoint.sh");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn prepared_spawn_uses_exact_shared_config_and_retains_all_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path();
    let config_path = state.join("received.json");
    let bin = script(
        state,
        &format!(
            "cat > '{}'; printf '{{\"env\":[]}}\\n'; exec sleep 30",
            config_path.display()
        ),
    );
    let env_path = state.join("environment.json");
    let redaction = mvm_core::policy::RedactionPolicy::default();
    let mut params = params(state, &redaction);
    params.session_marker = Some(state.join(SUBST_SESSION_FILE));
    let config = serde_json::to_vec(&build_endpoint_config_json(&params)).unwrap();
    let mut endpoint =
        spawn_prepared(params, &env_path, &bin, &config, Duration::from_secs(3)).unwrap();
    assert_eq!(std::fs::read(config_path).unwrap(), config);
    assert_eq!(std::fs::read(&env_path).unwrap(), b"[]");
    assert_eq!(
        std::fs::read_to_string(state.join(SUBST_PID_FILE)).unwrap(),
        endpoint.id().to_string()
    );
    endpoint.shutdown().unwrap();
    assert!(env_path.exists());
    assert!(state.join(SUBST_PID_FILE).exists());
}

#[test]
fn post_spawn_failure_retains_status_and_original_evidence_without_secret_echo() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path();
    let bin = script(
        state,
        "cat >/dev/null; printf '{\"secret\":\"must-not-echo\"}\\n'; exec sleep 30",
    );
    let env_path = state.join("environment.json");
    let redaction = mvm_core::policy::RedactionPolicy::default();
    let mut error = spawn_prepared(
        params(state, &redaction),
        &env_path,
        &bin,
        b"{}",
        Duration::from_secs(3),
    )
    .unwrap_err();
    assert!(!format!("{error:?}").contains("must-not-echo"));
    let failure = error.downcast_mut::<OwnedEndpointSpawnError>().unwrap();
    assert!(failure.endpoint_mut().exit_status().is_some());
    failure.endpoint_mut().shutdown().unwrap();
    assert!(state.join(SUBST_PID_FILE).exists());
    assert!(!env_path.exists());
}

#[test]
fn environment_write_failure_does_not_erase_existing_state() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path();
    let bin = script(
        state,
        "cat >/dev/null; printf '{\"env\":[]}\\n'; exec sleep 30",
    );
    let env_path = state.join("environment.json");
    std::fs::write(&env_path, b"other-owner").unwrap();
    let redaction = mvm_core::policy::RedactionPolicy::default();
    let mut error = spawn_prepared(
        params(state, &redaction),
        &env_path,
        &bin,
        b"{}",
        Duration::from_secs(3),
    )
    .unwrap_err();
    error
        .downcast_mut::<OwnedEndpointSpawnError>()
        .unwrap()
        .endpoint_mut()
        .shutdown()
        .unwrap();
    assert_eq!(std::fs::read(&env_path).unwrap(), b"other-owner");
    assert!(state.join(SUBST_PID_FILE).exists());
}

#[test]
fn stale_evidence_is_refused_without_touching_it() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path();
    let env_path = state.join("environment.json");
    let redaction = mvm_core::policy::RedactionPolicy::default();
    let params = params(state, &redaction);
    refuse_existing_evidence(&params, &env_path).unwrap();
    let pid_path = state.join(SUBST_PID_FILE);
    std::fs::write(&pid_path, b"12345").unwrap();
    assert!(refuse_existing_evidence(&params, &env_path).is_err());
    assert_eq!(std::fs::read(pid_path).unwrap(), b"12345");
}

#[test]
fn vm_keeper_is_rejected_before_any_side_effect() {
    let directory = tempfile::tempdir().unwrap();
    let redaction = mvm_core::policy::RedactionPolicy::default();
    let mut params = params(directory.path(), &redaction);
    params.lifetime = EndpointLifetime::Vm;
    assert!(
        spawn_network_endpoint_owned(params)
            .unwrap_err()
            .to_string()
            .contains("launcher lifetime")
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
