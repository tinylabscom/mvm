//! Plan 118 WS-1 1a — process-level integration for the prelaunched supervisor.
//!
//! Gated behind `libkrun-live` because spawning `mvm-libkrun-supervisor`
//! requires the `libkrun-sys` feature (FFI link to libkrun). Two scenarios:
//!
//! 1. `wrong_nonce_attach_is_refused_without_boot` — runnable anywhere libkrun
//!    links: the attach is refused at `verify_and_merge_attach` *before* any
//!    `start_enter`, so it exercises the full stdin-dispatch → control-UDS bind
//!    → accept → frame-read → refuse → exit(6) path with no VM.
//! 2. `valid_attach_boots_and_agent_reachable` — `#[ignore]`: needs a real
//!    kernel + rootfs + in-guest agent. Run manually on a libkrun-capable host;
//!    model the boot/agent-ping on `examples/agent_ping` + the core-demo e2e.
#![cfg(feature = "libkrun-live")]

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use libkrun_sys::{BridgeRestartPolicy, KrunContext, SupervisorAttachConfig, SupervisorBaseConfig};

/// The supervisor bin built for this test target (cargo sets this because the
/// bin's `required-features = ["libkrun-sys"]` are satisfied via libkrun-live).
const SUPERVISOR_BIN: &str = env!("CARGO_BIN_EXE_mvm-libkrun-supervisor");

fn base(dir: &Path, binding_nonce: &str) -> SupervisorBaseConfig {
    // Kernel/rootfs paths are bogus — the refusal path never boots, so they are
    // never read. `rootfs_path` is nulled (a standby carries no workload rootfs).
    let mut krun = KrunContext::new("test-standby", "/nonexistent/kernel", "/nonexistent/rootfs");
    krun.rootfs_path = None;
    SupervisorBaseConfig {
        krun,
        vm_state_dir: dir.join("state").to_string_lossy().into_owned(),
        pid_file_name: None,
        signing_key_path: dir.join("host-signer.ed25519"),
        signer_id: "host:test".into(),
        binding_nonce: binding_nonce.into(),
        control_socket_path: dir.join("control.sock"),
        bridge_restart_policy: BridgeRestartPolicy::HardFail,
    }
}

/// Poll-connect to the control UDS until the supervisor binds it (it binds only
/// after reading stdin), or the deadline elapses.
fn connect_with_retry(path: &Path, timeout: Duration) -> UnixStream {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(s) = UnixStream::connect(path) {
            return s;
        }
        if Instant::now() >= deadline {
            panic!("control socket {} never appeared", path.display());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Wait for `child` to exit within `timeout`, returning its exit code; kills it
/// and panics on timeout so a wedged supervisor fails the test fast.
fn wait_code(child: &mut std::process::Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("supervisor did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn wrong_nonce_attach_is_refused_without_boot() {
    let dir = tempfile::tempdir().unwrap();
    let base = base(dir.path(), "correct-binding-nonce");
    let control_path = base.control_socket_path.clone();

    let stdin_json = serde_json::to_string(&serde_json::json!({ "prelaunch_base": base })).unwrap();

    let mut child = Command::new(SUPERVISOR_BIN)
        // Skip the codesign re-exec (already signed in dev); keeps stdin piping
        // deterministic for the test.
        .env("MVM_SIGNED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mvm-libkrun-supervisor");

    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(stdin_json.as_bytes()).unwrap();
        // drop closes stdin → the bin's read_to_string returns.
    }

    let mut stream = connect_with_retry(&control_path, Duration::from_secs(5));

    // Echo the WRONG binding nonce — from_base_and_attach rejects before any
    // libkrun call, so the supervisor exits 6 without ever booting.
    let attach = SupervisorAttachConfig {
        binding_nonce: "totally-wrong-nonce".into(),
        rootfs_path: "/nonexistent/rootfs.ext4".into(),
        tenant_id: "tenant-a".into(),
        audit_dir: dir.path().join("audit"),
        gateway_audit_socket: dir.path().join("audit/g.sock"),
        gateway_events_socket: None,
        plan: serde_json::json!({ "ignored": "never-reached" }),
        bundle: None,
    };
    libkrun_sys::framing::write_json_frame_sync(&mut stream, &attach).unwrap();

    let code = wait_code(&mut child, Duration::from_secs(10));
    // ExitCode::from(6) — the prelaunch "attach refused" arm.
    assert_eq!(
        code,
        Some(6),
        "wrong-nonce attach must be refused with exit 6"
    );

    // No workload-exit control socket should ever have been bound (that only
    // happens in dispatch_config, which a refused attach never reaches).
    let workload_exit_sock = dir.path().join("state").join("vsock-5251.sock");
    assert!(
        !workload_exit_sock.exists(),
        "refused attach must not have reached the boot path"
    );
}

#[test]
#[ignore = "needs a real kernel+rootfs+agent; run manually on a libkrun-capable host (model on examples/agent_ping)"]
fn valid_attach_boots_and_agent_reachable() {
    // Build a BaseConfig with a real kernel + the agent port in host_listen_ports,
    // spawn the supervisor, connect to the control UDS, and write_json_frame_sync
    // a SupervisorAttachConfig whose `plan` is a freshly-signed admitted envelope
    // (sign with the same on-disk host key the base points at) + a real rootfs.
    // Assert the agent answers a ping. Left as an explicit manual harness — the
    // refusal path above + the Task 3 unit ladder cover the security logic.
    unimplemented!("manual live-boot harness — see module docs");
}
