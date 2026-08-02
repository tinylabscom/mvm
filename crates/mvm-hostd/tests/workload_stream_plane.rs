//! The output stream plane, reached the way a workload reaches it: nothing
//! here constructs a broker, a socket, or a transcript.
//!
//! The whole chain under test is `install_host_console_streamer` → the
//! runtime's process registration → `WorkloadRunner::new`'s default hook →
//! `start_workload`'s unconditional console call → a bound socket a reader
//! resolves by VM name. A test that stood a broker up itself would prove the
//! broker works and say nothing about whether anything runs it, which is
//! exactly the gap this exists to close.
//!
//! The workload is **unadmitted** — no tenant, so the host-services broker
//! registration defuses itself. That is deliberate: a local dev run is the
//! case with the fewest other ways to see a boot failure, so it is the case
//! the console hook most has to cover.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use anyhow::Result;
use mvm_core::config;
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::stream_client::{
    KindFilter, OutputRecord, OutputRequest, RecordOrigin, StreamAvailability, StreamOpts,
    open_vm_output,
};
use mvm_core::util::test_env::TestEnv;
use mvm_core::vm_backend::{VmBackend, VmId, VmStartConfig};
use mvm_protocol::stream::{StreamKind, StreamSource};
use mvm_runtime::driver::MockDriver;
use mvm_runtime::workload_runner::{
    EndpointSpawnRequest, EndpointSpawner, RealBrokerRegistrar, WorkloadLaunchInputs,
    WorkloadRunner, console_streamer_installed,
};

/// How long a record may take to cross the console follower's poll interval
/// and then the socket server's.
const DEADLINE: Duration = Duration::from_secs(10);

/// Long enough for the accept loop to take a queued connection and subscribe
/// its reader before the test produces bytes it expects that reader to see.
const ACCEPT_SETTLE: Duration = Duration::from_millis(250);

/// The one gating-endpoint stand-in: `RealEndpointSpawner` would fork the
/// substitution endpoint subprocess, which this test has no use for. Every
/// other collaborator on the start path is the production one.
struct StubEndpointSpawner;

impl EndpointSpawner for StubEndpointSpawner {
    fn spawn(&self, _req: &EndpointSpawnRequest<'_>) -> Result<PathBuf> {
        Ok(PathBuf::from("/run/mvm-test-endpoint.sock"))
    }
}

/// Point the whole mvm world at a tempdir: state dirs, sockets, and the host
/// transcript KEK all land under it.
fn isolated_home() -> (TestEnv, tempfile::TempDir) {
    let mut env = TestEnv::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    env.isolate_mvm_home(tmp.path());
    (env, tmp)
}

fn runner() -> WorkloadRunner<MockDriver, StubEndpointSpawner, RealBrokerRegistrar> {
    // No `with_console_streamer`: the hook has to arrive from the process
    // registration, or this test proves nothing about production.
    WorkloadRunner::new(
        MockDriver::default(),
        StubEndpointSpawner,
        RealBrokerRegistrar,
    )
}

fn launch(runner: &WorkloadRunner<MockDriver, StubEndpointSpawner, RealBrokerRegistrar>, vm: &str) {
    let config = VmStartConfig {
        name: vm.to_string(),
        rootfs_path: "/img/rootfs.ext4".into(),
        ..Default::default()
    };
    let policy = NetworkPolicy::deny_all();
    let redaction = RedactionPolicy::default();
    runner
        .start_workload(&WorkloadLaunchInputs {
            config: &config,
            tenant: "local",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: "root=/dev/vda".into(),
        })
        .expect("the workload starts against the mock driver");
}

/// Where the backend writes the guest console — the file the plane follows.
fn console_log(vm: &str) -> PathBuf {
    config::vm_console_log(vm)
}

/// A follower attached on its own thread, because `next_output` blocks on the
/// socket while following: reading it inline would hang the suite on a
/// regression instead of failing it.
struct Follower {
    availability: StreamAvailability,
    records: Receiver<OutputRecord>,
}

impl Follower {
    /// Attach through the same resolver `mvmctl logs -f` uses.
    fn attach(vm: &str) -> Self {
        Self::attach_kinds(vm, KindFilter::all())
    }

    /// Attach narrowed to `kinds`, the way `mvmctl logs --stream <channel>`
    /// does.
    fn attach_kinds(vm: &str, kinds: KindFilter) -> Self {
        let (ready_tx, ready_rx) = channel();
        let (record_tx, record_rx) = channel();
        let vm = vm.to_string();
        std::thread::spawn(move || {
            let request = OutputRequest {
                opts: StreamOpts::builder().follow(true).kinds(kinds).build(),
                history_tail: Some(0),
                console_tail_bytes: None,
            };
            let mut stream = open_vm_output(&vm, request).expect("open the output stream");
            if ready_tx.send(stream.availability()).is_err() {
                return;
            }
            while let Ok(Some(record)) = stream.next_output() {
                if record_tx.send(record).is_err() {
                    return;
                }
            }
        });
        let availability = ready_rx
            .recv_timeout(DEADLINE)
            .expect("the follower must resolve a source");
        std::thread::sleep(ACCEPT_SETTLE);
        Self {
            availability,
            records: record_rx,
        }
    }

    fn next(&self) -> OutputRecord {
        self.records
            .recv_timeout(DEADLINE)
            .expect("a record must reach the follower")
    }
}

/// Register the plane the way the CLI does at startup. Process-global and
/// once-only, so every test in this binary calls it and the first one wins.
fn register() {
    mvm_hostd::stream::install_host_console_streamer();
    assert!(
        console_streamer_installed(),
        "the runtime must have a console streamer after the host registers one"
    );
}

#[test]
fn starting_a_workload_stands_up_a_stream_socket_that_serves_records() {
    register();
    let (_env, _tmp) = isolated_home();
    let runner = runner();

    launch(&runner, "streamed-vm");

    let socket = config::vm_stream_socket("streamed-vm");
    assert!(
        socket.exists(),
        "starting a workload must bind its stream socket at {}",
        socket.display()
    );

    let follower = Follower::attach("streamed-vm");
    assert!(
        follower.availability.is_live(),
        "a running workload's output must come from the broker, not a console tail: {:?}",
        follower.availability
    );

    // The producer is the real one: the write-only console capture every
    // backend writes before the guest agent can say anything.
    std::fs::write(console_log("streamed-vm"), b"booting\n").expect("write the console capture");

    let record = follower.next();
    assert!(
        matches!(record.origin, RecordOrigin::Live { .. }),
        "the broker served this record, not the degraded console fallback: {:?}",
        record.origin
    );
    assert_eq!(record.payload, b"booting\n");

    runner.stop(&VmId("streamed-vm".to_string())).expect("stop");
}

#[test]
fn stopping_a_workload_releases_the_socket_and_seals_a_readable_transcript() {
    register();
    let (_env, _tmp) = isolated_home();
    let runner = runner();

    launch(&runner, "sealed-vm");
    std::fs::write(console_log("sealed-vm"), b"ran and exited\n")
        .expect("write the console capture");

    runner.stop(&VmId("sealed-vm".to_string())).expect("stop");

    assert!(
        !config::vm_stream_socket("sealed-vm").exists(),
        "stopping a workload must release its stream socket"
    );

    // What the operator reads after the VM is gone: the durable half, sealed
    // and verified, rather than the unchained console file beside it.
    let mut stream =
        open_vm_output("sealed-vm", OutputRequest::default()).expect("the sealed capture opens");
    assert_eq!(stream.availability(), StreamAvailability::HistoryOnly);
    let record = stream
        .next_output()
        .expect("read")
        .expect("the sealed capture holds the run's output");
    assert_eq!(record.origin, RecordOrigin::Durable);
    assert_eq!(record.payload, b"ran and exited\n");
}

/// The second source, reached the way the entrypoint dispatch reaches it:
/// through the plane the process registered, by VM name.
///
/// The console covers the windows the agent cannot and merges both channels
/// into stdout; only these frames can say which channel a byte came out of. If
/// they never reach the broker, `--stream stderr` matches nothing a workload
/// ever wrote — with a plane up and looking healthy.
#[test]
fn the_entrypoints_stderr_reaches_a_reader_asking_for_the_stderr_channel() {
    register();
    let (_env, _tmp) = isolated_home();
    let runner = runner();

    launch(&runner, "entrypoint-vm");
    let follower = Follower::attach_kinds("entrypoint-vm", KindFilter::only(StreamKind::Stderr));

    let plane = mvm_hostd::stream::host_stream_plane()
        .expect("registering the console streamer must publish its plane");
    let mut sink = plane.entrypoint_sink("entrypoint-vm");
    assert!(
        sink.is_recorded(),
        "a workload the runner started is attached to this process's plane"
    );
    sink.ingest(StreamKind::Stdout, b"the result\n");
    sink.ingest(StreamKind::Stderr, b"the warning\n");
    drop(sink);

    let record = follower.next();
    assert_eq!(
        record.payload, b"the warning\n",
        "a stderr read must skip the stdout frame, not return it"
    );
    assert!(
        matches!(
            record.origin,
            RecordOrigin::Live {
                source: StreamSource::Entrypoint,
                ..
            }
        ),
        "the frame must be attributed to the entrypoint, not the console: {:?}",
        record.origin
    );

    runner
        .stop(&VmId("entrypoint-vm".to_string()))
        .expect("stop");
}

#[test]
fn a_workload_never_started_here_has_no_socket_and_stopping_it_is_harmless() {
    // `stop` routinely runs in a different process invocation from the
    // `start` that opened the capture. It must not fail, and it must not
    // invent a socket.
    register();
    let (_env, _tmp) = isolated_home();
    let runner = runner();

    let _ = runner.stop(&VmId("never-started".to_string()));
    assert!(!config::vm_stream_socket("never-started").exists());
}

#[test]
fn the_console_hook_is_wired_for_an_unadmitted_workload() {
    // `BrokerRegistrar` no-ops without a tenant. Console capture must not
    // inherit that: an unadmitted local run has the fewest other ways to see
    // a boot failure.
    register();
    let (_env, _tmp) = isolated_home();
    let runner = runner();

    launch(&runner, "unadmitted-vm");

    assert!(
        config::vm_stream_socket("unadmitted-vm").exists(),
        "an unadmitted workload still gets its output captured"
    );
    assert!(
        !config::vm_vsock_port_socket("unadmitted-vm", mvm_agentd::vsock::BROKER_PORT).exists(),
        "the fixture must really be unadmitted: no host-services broker channel"
    );

    runner
        .stop(&VmId("unadmitted-vm".to_string()))
        .expect("stop");
}

/// The console capture is opened for reading and nothing else.
///
/// The sealed production console has no host input fd, and that absence is a
/// security property. A plane that opened the file read-write would leave a
/// writable handle on the one artifact the guest's output arrives through.
#[test]
fn following_the_console_never_writes_to_it() {
    register();
    let (_env, _tmp) = isolated_home();
    let runner = runner();

    launch(&runner, "readonly-vm");
    let console = console_log("readonly-vm");
    std::fs::write(&console, b"guest says hello\n").expect("write the console capture");

    let follower = Follower::attach("readonly-vm");
    assert!(follower.availability.is_live());

    // Give the follower several poll intervals against a file it must only
    // ever read, then confirm the bytes on disk are exactly what was written.
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        std::fs::read(&console).expect("read the console capture"),
        b"guest says hello\n",
        "the plane must not modify the console capture it follows"
    );

    runner.stop(&VmId("readonly-vm".to_string())).expect("stop");
}

/// Sanity: the helper resolves paths the same way the reader does, so a
/// failure above is a wiring failure and not two different opinions about
/// where a VM's console lives.
#[test]
fn the_console_path_the_test_writes_is_the_one_under_the_vm_state_dir() {
    let (_env, _tmp) = isolated_home();
    let path = console_log("path-vm");
    assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("console.log")));
    assert!(path.starts_with(config::vm_state_dir("path-vm")));
    assert!(Path::new(&path).parent().is_some());
}
