//! Integration tests for `PersistentBuilderSupervisor`.
//!
//! These live in `tests/` (not inline in `persistent_builder.rs::tests`)
//! because they need server-binding patterns to simulate the
//! guest's dispatch loop end of the libkrun-managed Unix socket.
//! The architecture invariant grep in
//! `.github/workflows/architecture.yml` scans `crates/*/src/`
//! for server-binding patterns and deliberately excludes
//! `**/tests/**` for mock scaffolding like this.

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

use mvm_build::builder_protocol::{
    BootTimingsWire, HostVmRequest, HostVmResponse, JobId, JobTimings, WorkloadId,
};
use mvm_build::builder_vm::BuilderJob;
use mvm_build::persistent_builder::{
    BuilderAuditSink, DispatchOutcome, PersistentBuilderError, PersistentBuilderSupervisor,
    WorkloadStartParams, dispatch_socket_path,
};

/// Spawn a fake guest dispatch loop on `socket_path`. The closure
/// is invoked with each accepted connection and is responsible for
/// reading any incoming `HostVmRequest`, writing responses, and
/// dropping the stream. Returns the listener thread handle —
/// callers `join` after asserting the supervisor outcome.
fn spawn_fake_guest<F>(socket_path: &Path, handler: F) -> std::thread::JoinHandle<()>
where
    F: FnOnce(std::os::unix::net::UnixStream) + Send + 'static,
{
    let listener = UnixListener::bind(socket_path).expect("bind unix socket");
    std::thread::spawn(move || {
        let (conn, _) = listener.accept().expect("accept");
        handler(conn);
    })
}

fn sample_boot_timings() -> BootTimingsWire {
    BootTimingsWire {
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
    }
}

#[test]
fn submit_round_trips_request_and_result_with_no_stderr_chunks() {
    // Happy path: supervisor sends Run, guest immediately sends
    // back Result with exit_code=0, no stderr stream.
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let request: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        let job_id = match &request {
            HostVmRequest::Run { job_id, .. } => *job_id,
            other => panic!("expected Run, got {other:?}"),
        };
        let response = HostVmResponse::Result {
            job_id,
            exit_code: 0,
            stderr_tail: String::new(),
            boot_timings: Some(Box::new(sample_boot_timings())),
            job_timings: JobTimings {
                dispatch_ms: 1,
                build_ms: 1000,
                teardown_ms: 5,
            },
        };
        mvm_guest::vsock::write_frame(&mut conn, &response).expect("write response");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));

    let outcome = supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            "00000000-0000-0000-0000-000000000000".to_string(),
        )
        .expect("submit");

    guest.join().expect("guest");
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.stderr_chunks.len(), 0);
    assert_eq!(outcome.job_timings.build_ms, 1000);
    assert!(outcome.boot_timings.is_some());
}

#[test]
fn submit_streams_stderr_chunks_then_collects_terminating_result() {
    // Realistic path: guest streams several StderrChunk frames
    // before the Result. Supervisor must accumulate them in
    // `outcome.stderr_chunks` in order.
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let request: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        let job_id = match &request {
            HostVmRequest::Run { job_id, .. } => *job_id,
            other => panic!("expected Run, got {other:?}"),
        };
        for line in ["building", "building 2/3", "building 3/3"] {
            mvm_guest::vsock::write_frame(
                &mut conn,
                &HostVmResponse::StderrChunk {
                    job_id,
                    line: line.to_string(),
                },
            )
            .expect("write chunk");
        }
        let result = HostVmResponse::Result {
            job_id,
            exit_code: 0,
            stderr_tail: "building 3/3".to_string(),
            boot_timings: None,
            job_timings: JobTimings {
                dispatch_ms: 0,
                build_ms: 50,
                teardown_ms: 0,
            },
        };
        mvm_guest::vsock::write_frame(&mut conn, &result).expect("write result");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));

    let outcome = supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            "abc".to_string(),
        )
        .expect("submit");

    guest.join().expect("guest");
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(
        outcome.stderr_chunks,
        vec![
            "building".to_string(),
            "building 2/3".to_string(),
            "building 3/3".to_string()
        ]
    );
    assert!(outcome.boot_timings.is_none());
}

#[test]
fn submit_returns_premature_eof_when_guest_closes_without_result() {
    // Guest accepts the connection, reads the Run, then closes
    // without sending Result. Common crash signature; supervisor
    // surfaces PrematureEof so the caller can decide whether to
    // retry or fall back.
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let _: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        // Drop conn -> EOF.
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));

    let err = supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            "abc".to_string(),
        )
        .expect_err("must error on premature EOF");

    guest.join().expect("guest");
    match err {
        PersistentBuilderError::PrematureEof { chunks } => assert_eq!(chunks, 0),
        other => panic!("expected PrematureEof, got {other:?}"),
    }
}

#[test]
fn submit_detects_job_id_mismatch_in_result() {
    // Guest dispatch loop bug: response carries a different job_id
    // than the request. Hard failure — supervisor must not silently
    // accept the misattributed result.
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let _: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        let bogus = HostVmResponse::Result {
            job_id: JobId::new(),
            exit_code: 0,
            stderr_tail: String::new(),
            boot_timings: None,
            job_timings: JobTimings::default(),
        };
        mvm_guest::vsock::write_frame(&mut conn, &bogus).expect("write bogus");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));

    let err = supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            "abc".to_string(),
        )
        .expect_err("must reject job_id mismatch");

    guest.join().expect("guest");
    assert!(matches!(err, PersistentBuilderError::JobIdMismatch { .. }));
}

#[test]
fn shutdown_writes_shutdown_request_and_consumes_bye() {
    // Lifecycle path: caller invokes shutdown(); supervisor sends
    // HostVmRequest::Shutdown; guest replies with Bye; supervisor
    // returns cleanly.
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let request: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        assert!(matches!(request, HostVmRequest::Shutdown {}));
        mvm_guest::vsock::write_frame(&mut conn, &HostVmResponse::Bye {}).expect("write bye");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));

    supervisor.shutdown().expect("shutdown");
    guest.join().expect("guest");
}

// Suppress the unused-import warning when running under feature
// gates that don't actually pull DispatchOutcome — keeps clippy
// silent without `#[allow]`.
#[allow(dead_code)]
fn _force_use(_: DispatchOutcome) {}

/// Recording fake for `BuilderAuditSink`.
/// Captures every emit (kind + job_id + payload digest) so tests
/// can assert on the exact pair the supervisor emitted around a
/// dispatch round.
#[derive(Debug, Default)]
struct RecordingAuditSink {
    events: std::sync::Mutex<Vec<RecordedAuditEvent>>,
}

#[derive(Debug, PartialEq, Eq)]
enum RecordedAuditEvent {
    Dispatched { job_id: JobId, relpath: String },
    Completed { job_id: JobId, exit_code: i32 },
    Failed { job_id: JobId, reason: String },
}

impl BuilderAuditSink for RecordingAuditSink {
    fn dispatched(&self, job_id: JobId, _job: &BuilderJob, job_dir_relpath: &str) {
        self.events
            .lock()
            .unwrap()
            .push(RecordedAuditEvent::Dispatched {
                job_id,
                relpath: job_dir_relpath.to_string(),
            });
    }

    fn completed(&self, job_id: JobId, exit_code: i32, _job_timings: JobTimings) {
        self.events
            .lock()
            .unwrap()
            .push(RecordedAuditEvent::Completed { job_id, exit_code });
    }

    fn failed(&self, job_id: JobId, reason: &str) {
        self.events
            .lock()
            .unwrap()
            .push(RecordedAuditEvent::Failed {
                job_id,
                reason: reason.to_string(),
            });
    }
}

#[test]
fn submit_with_audit_sink_emits_dispatched_then_completed_on_success() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let request: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        let job_id = match &request {
            HostVmRequest::Run { job_id, .. } => *job_id,
            other => panic!("expected Run, got {other:?}"),
        };
        let response = HostVmResponse::Result {
            job_id,
            exit_code: 0,
            stderr_tail: String::new(),
            boot_timings: None,
            job_timings: JobTimings {
                dispatch_ms: 2,
                build_ms: 500,
                teardown_ms: 3,
            },
        };
        mvm_guest::vsock::write_frame(&mut conn, &response).expect("write response");
    });

    let sink = std::sync::Arc::new(RecordingAuditSink::default());
    let supervisor = PersistentBuilderSupervisor::new(&socket)
        .with_frame_read_timeout(Duration::from_secs(1))
        .with_audit_sink(sink.clone());

    let outcome = supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            "abc123".to_string(),
        )
        .expect("submit");
    guest.join().expect("guest");

    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 2, "dispatched + completed; got {events:?}");
    match &events[0] {
        RecordedAuditEvent::Dispatched { job_id, relpath } => {
            assert_eq!(job_id, &outcome.job_id);
            assert_eq!(relpath, "abc123");
        }
        other => panic!("expected Dispatched first, got {other:?}"),
    }
    match &events[1] {
        RecordedAuditEvent::Completed { job_id, exit_code } => {
            assert_eq!(job_id, &outcome.job_id);
            assert_eq!(*exit_code, 0);
        }
        other => panic!("expected Completed second, got {other:?}"),
    }
}

#[test]
fn submit_with_audit_sink_emits_dispatched_then_failed_on_premature_eof() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    // Guest accepts and immediately closes — supervisor surfaces
    // PrematureEof, audit sink should see dispatched + failed.
    let guest = spawn_fake_guest(&socket, |mut conn| {
        let _request: HostVmRequest =
            mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        drop(conn);
    });

    let sink = std::sync::Arc::new(RecordingAuditSink::default());
    let supervisor = PersistentBuilderSupervisor::new(&socket)
        .with_frame_read_timeout(Duration::from_secs(2))
        .with_audit_sink(sink.clone());

    let err = supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "x".to_string(),
            },
            "deadbeef".to_string(),
        )
        .expect_err("submit should fail");
    guest.join().expect("guest");

    assert!(matches!(err, PersistentBuilderError::PrematureEof { .. }));
    let events = sink.events.lock().unwrap();
    assert_eq!(events.len(), 2, "dispatched + failed; got {events:?}");
    assert!(matches!(&events[0], RecordedAuditEvent::Dispatched { .. }));
    match &events[1] {
        RecordedAuditEvent::Failed { reason, .. } => {
            assert!(
                reason.contains("dispatch ended without Result") || reason.contains("PrematureEof"),
                "reason should mention premature EOF; got {reason}"
            );
        }
        other => panic!("expected Failed second, got {other:?}"),
    }
}

#[test]
fn submit_without_audit_sink_emits_nothing() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let request: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        let job_id = match &request {
            HostVmRequest::Run { job_id, .. } => *job_id,
            other => panic!("expected Run, got {other:?}"),
        };
        mvm_guest::vsock::write_frame(
            &mut conn,
            &HostVmResponse::Result {
                job_id,
                exit_code: 0,
                stderr_tail: String::new(),
                boot_timings: None,
                job_timings: JobTimings::default(),
            },
        )
        .expect("write response");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));
    supervisor
        .submit(
            BuilderJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "x".to_string(),
            },
            "no-sink".to_string(),
        )
        .expect("submit");
    guest.join().expect("guest");
    // No sink, no panic, no recorded events. The test passes if
    // we get here cleanly — the supervisor's `Option<sink>`
    // branches don't dereference None.
}

// ── workload lifecycle dispatch ─────────────────────────────────

fn sample_workload_params() -> WorkloadStartParams {
    WorkloadStartParams {
        kernel_path: "/job/workload/vmlinux".to_string(),
        rootfs_path: "/job/workload/rootfs.ext4".to_string(),
        vsock_socket_dir: "/var/lib/mvm/workloads".to_string(),
        vcpus: 2,
        memory_mib: 1024,
        kernel_cmdline_extras: "root=/dev/vda ro".to_string(),
    }
}

#[test]
fn submit_workload_start_round_trips_started() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let request: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        let workload_id = match &request {
            HostVmRequest::WorkloadStart {
                workload_id,
                vcpus,
                memory_mib,
                ..
            } => {
                assert_eq!(*vcpus, 2);
                assert_eq!(*memory_mib, 1024);
                *workload_id
            }
            other => panic!("expected WorkloadStart, got {other:?}"),
        };
        let response = HostVmResponse::WorkloadStarted {
            workload_id,
            pid: 4242,
        };
        mvm_guest::vsock::write_frame(&mut conn, &response).expect("write response");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));
    let outcome = supervisor
        .submit_workload_start(sample_workload_params())
        .expect("workload start");
    guest.join().expect("guest");
    assert_eq!(outcome.pid, 4242);
}

#[test]
fn submit_workload_start_surfaces_workload_failed() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let request: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        let workload_id = match &request {
            HostVmRequest::WorkloadStart { workload_id, .. } => *workload_id,
            other => panic!("expected WorkloadStart, got {other:?}"),
        };
        let response = HostVmResponse::WorkloadFailed {
            workload_id,
            error: "spawn /usr/bin/firecracker: ENOENT".to_string(),
        };
        mvm_guest::vsock::write_frame(&mut conn, &response).expect("write response");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));
    let err = supervisor
        .submit_workload_start(sample_workload_params())
        .expect_err("must surface WorkloadFailed");
    guest.join().expect("guest");
    match err {
        PersistentBuilderError::WorkloadFailed { error, .. } => {
            assert!(error.contains("ENOENT"), "error lost: {error}");
        }
        other => panic!("expected WorkloadFailed, got {other:?}"),
    }
}

#[test]
fn submit_workload_start_rejects_unexpected_response() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        let _req: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        // Wrong kind for a WorkloadStart.
        mvm_guest::vsock::write_frame(&mut conn, &HostVmResponse::Bye {}).expect("write response");
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));
    let err = supervisor
        .submit_workload_start(sample_workload_params())
        .expect_err("must reject wrong-kind response");
    guest.join().expect("guest");
    match err {
        PersistentBuilderError::UnexpectedResponse { expected, got } => {
            assert_eq!(expected, "workload_started");
            assert_eq!(got, "bye");
        }
        other => panic!("expected UnexpectedResponse, got {other:?}"),
    }
}

#[test]
fn submit_workload_start_premature_eof_when_guest_closes() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());

    let guest = spawn_fake_guest(&socket, |mut conn| {
        // Read the request, then close without replying (guest crash).
        let _req: HostVmRequest = mvm_guest::vsock::read_frame(&mut conn).expect("read request");
        drop(conn);
    });

    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));
    let err = supervisor
        .submit_workload_start(sample_workload_params())
        .expect_err("must surface PrematureEof");
    guest.join().expect("guest");
    assert!(matches!(err, PersistentBuilderError::PrematureEof { .. }));
}

#[test]
fn submit_workload_stop_and_status_round_trip() {
    // Stop → WorkloadStopped → Ok(())
    let scratch = tempfile::tempdir().expect("tempdir");
    let socket = dispatch_socket_path(scratch.path());
    let wid = WorkloadId::new();
    let guest =
        spawn_fake_guest(&socket, move |mut conn| {
            match mvm_guest::vsock::read_frame::<HostVmRequest>(&mut conn).expect("read") {
                HostVmRequest::WorkloadStop { workload_id } => {
                    mvm_guest::vsock::write_frame(
                        &mut conn,
                        &HostVmResponse::WorkloadStopped { workload_id },
                    )
                    .expect("write");
                }
                other => panic!("expected WorkloadStop, got {other:?}"),
            }
        });
    let supervisor =
        PersistentBuilderSupervisor::new(&socket).with_frame_read_timeout(Duration::from_secs(1));
    supervisor.submit_workload_stop(wid).expect("stop ok");
    guest.join().expect("guest");

    // Status → WorkloadStatusReport{status} → Ok(status)
    let scratch2 = tempfile::tempdir().expect("tempdir");
    let socket2 = dispatch_socket_path(scratch2.path());
    let guest2 = spawn_fake_guest(&socket2, |mut conn| {
        let workload_id =
            match mvm_guest::vsock::read_frame::<HostVmRequest>(&mut conn).expect("read") {
                HostVmRequest::WorkloadStatus { workload_id } => workload_id,
                other => panic!("expected WorkloadStatus, got {other:?}"),
            };
        mvm_guest::vsock::write_frame(
            &mut conn,
            &HostVmResponse::WorkloadStatusReport {
                workload_id,
                status: "running".to_string(),
            },
        )
        .expect("write");
    });
    let supervisor2 =
        PersistentBuilderSupervisor::new(&socket2).with_frame_read_timeout(Duration::from_secs(1));
    let status = supervisor2.submit_workload_status(wid).expect("status ok");
    guest2.join().expect("guest");
    assert_eq!(status, "running");
}
