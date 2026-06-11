//! Integration tests for the host-side vsock response listener in
//! `mvm_build::libkrun_builder`.
//!
//! These live in `tests/` (not inline in `libkrun_builder.rs::tests`)
//! because they need `UnixListener::bind` to simulate libkrun's
//! host-side Unix-socket proxy. The architecture invariant grep in
//! `.github/workflows/architecture.yml` scans `crates/*/src/` for
//! server-binding patterns and would flag the bind otherwise — the
//! grep deliberately excludes `**/tests/**` for exactly this case.

#![cfg(feature = "builder-vm")]

use std::os::unix::net::UnixListener;
use std::time::Duration;

use mvm_build::builder_protocol::{
    BootTimingsWire, HostVmResponse, HostVmResponseRead, JobId, JobTimings,
};
use mvm_build::libkrun_builder::spawn_vsock_response_listener;

fn socket_path_in(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(format!(
        "vsock-{}.sock",
        mvm_guest::builder_agent::BUILDER_DISPATCH_PORT
    ))
}

#[test]
fn spawn_vsock_response_listener_decodes_guest_response() {
    // Set up: tempdir simulates <vm_state_dir>. Bind a UnixListener
    // at the path libkrun would create — that's what the host-side
    // spawn_vsock_response_listener's retry loop connects to. From
    // a separate thread, accept the connection and write a framed
    // HostVmResponse. The listener helper's receiver should yield
    // Frame(...).
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket_path = socket_path_in(scratch.path());
    let listener = UnixListener::bind(&socket_path).expect("bind unix socket");

    let response = HostVmResponse::Result {
        job_id: JobId::default(),
        exit_code: 0,
        stderr_tail: "ok".to_string(),
        boot_timings: Some(Box::new(BootTimingsWire {
            init_start_ms: Some(0),
            pseudofs_ready_ms: Some(11),
            nix_device_ready_ms: Some(15),
            nix_seeded_ms: None,
            nix_mounted_ms: Some(180),
            nix_db_loaded_ms: Some(185),
            modules_ready_ms: Some(25),
            virtiofs_ready_ms: Some(35),
            network_ready_ms: Some(190),
            job_start_ms: Some(200),
            job_end_ms: Some(1200),
            poweroff_start_ms: Some(1210),
        })),
        job_timings: JobTimings {
            dispatch_ms: 0,
            build_ms: 1000,
            teardown_ms: 0,
        },
    };

    let expected = response.clone();
    let guest_thread = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        mvm_guest::vsock::write_frame(&mut conn, &response).expect("write_frame");
        // Drop closes the socket, signaling EOF.
    });

    let rx = spawn_vsock_response_listener(scratch.path());
    let received = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("response within 1s");
    guest_thread.join().expect("guest thread");

    match received {
        HostVmResponseRead::Frame(got) => assert_eq!(got, expected),
        other => panic!("expected Frame, got {other:?}"),
    }
}

#[test]
fn spawn_vsock_response_listener_yields_empty_eof_when_no_send() {
    // Guest opens the socket but writes nothing — simulates a cached
    // dev image from before the guest learned to send a response (or a
    // guest that hit a fault before reaching the send code). Listener
    // helper must classify as EmptyEof so the caller falls back to the
    // file path silently.
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket_path = socket_path_in(scratch.path());
    let listener = UnixListener::bind(&socket_path).expect("bind unix socket");

    let guest_thread = std::thread::spawn(move || {
        let (_conn, _) = listener.accept().expect("accept");
        // Drop immediately = clean EOF without bytes.
    });

    let rx = spawn_vsock_response_listener(scratch.path());
    let received = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("response within 1s");
    guest_thread.join().expect("guest thread");

    match received {
        HostVmResponseRead::EmptyEof => {}
        other => panic!("expected EmptyEof, got {other:?}"),
    }
}
