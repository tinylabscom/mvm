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
use std::sync::Arc;
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
use mvm_hostd::stream::StreamPlane;
use mvm_protocol::stream::{StreamKind, StreamSource};
use mvm_runtime::driver::MockDriver;
use mvm_runtime::workload_runner::{
    ConsoleStreamer, EndpointSpawnRequest, EndpointSpawner, RealBrokerRegistrar,
    WorkloadLaunchInputs, WorkloadRunner, console_streamer_installed,
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

/// A runner belonging to one host *process*, modelled by giving it its own
/// plane instead of the process-global one.
///
/// The process registration is a `OnceLock`, so a single test binary cannot
/// hold two of them — and two host processes is exactly the shape under test:
/// one starts a workload and exits, another stops it later. Everything else on
/// the path is the production collaborator, including the plane itself.
fn runner_in_process(
    plane: &Arc<StreamPlane>,
) -> WorkloadRunner<MockDriver, StubEndpointSpawner, RealBrokerRegistrar> {
    WorkloadRunner::new(
        MockDriver::default(),
        StubEndpointSpawner,
        RealBrokerRegistrar,
    )
    .with_console_streamer(Arc::clone(plane) as Arc<dyn ConsoleStreamer>)
}

/// Let the console follower take what is on disk before the process holding
/// it goes away. A real detached start runs for as long as the workload takes
/// to print; a race here would be the test's, not the plane's.
fn settle() {
    std::thread::sleep(ACCEPT_SETTLE);
}

/// The whole durable half of one VM's run, as an operator reads it after the
/// VM is gone.
fn sealed_run(vm: &str) -> (StreamAvailability, Vec<OutputRecord>) {
    let mut stream = open_vm_output(vm, OutputRequest::default()).expect("the capture opens");
    let availability = stream.availability();
    let mut records = Vec::new();
    while let Some(record) = stream.next_output().expect("read the capture") {
        records.push(record);
    }
    (availability, records)
}

fn payloads(records: &[OutputRecord]) -> Vec<Vec<u8>> {
    records.iter().map(|r| r.payload.clone()).collect()
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

#[test]
fn a_detached_start_is_sealed_by_the_later_stop_that_ends_the_vm() {
    // `mvmctl machine run -d`: the CLI boots the workload and exits, and a
    // separate `mvmctl machine stop` ends it minutes or days later. Until the
    // stop learned to seal, that whole shape wrote no manifest at all — so
    // `logs` resolved to the unchained console file and the verifiable half
    // of the capture was dead weight for every workload but a foreground one.
    register();
    let (_env, _tmp) = isolated_home();

    let starting = Arc::new(StreamPlane::new());
    launch(&runner_in_process(&starting), "detached-vm");
    std::fs::write(console_log("detached-vm"), b"started and left running\n")
        .expect("write the console capture");
    settle();
    // The starting process exits with the VM still up.
    drop(starting);

    let stopping = Arc::new(StreamPlane::new());
    runner_in_process(&stopping)
        .stop(&VmId("detached-vm".to_string()))
        .expect("stop");

    let (availability, records) = sealed_run("detached-vm");
    assert_eq!(
        availability,
        StreamAvailability::HistoryAndConsole,
        "the run is readable off the durable half, with the console covering what it could not"
    );
    let durable: Vec<Vec<u8>> = records
        .iter()
        .filter(|r| r.origin == RecordOrigin::Durable)
        .map(|r| r.payload.clone())
        .collect();
    assert_eq!(
        durable,
        [b"started and left running\n"],
        "the chained half holds what the departed process recorded"
    );
}

#[test]
fn a_detached_runs_output_after_its_recorder_exited_still_reaches_the_reader() {
    // The shape that matters and the one an adopted manifest cannot cover on
    // its own: the CLI exits two seconds in, the workload prints for another
    // half hour into the console the backend still owns, and the later `stop`
    // seals a transcript describing only those two seconds. If `logs` reports
    // that transcript and nothing else, the run's actual output is sitting on
    // disk and never shown — a partial artifact *displacing* a complete one.
    register();
    let (_env, _tmp) = isolated_home();

    let starting = Arc::new(StreamPlane::new());
    launch(&runner_in_process(&starting), "outlived-vm");
    std::fs::write(console_log("outlived-vm"), b"the first seconds\n")
        .expect("write the console capture");
    settle();
    // The starting process exits. Its console follower dies with it; the
    // backend's own write-only capture does not.
    drop(starting);

    std::fs::write(
        console_log("outlived-vm"),
        b"the first seconds\nTHIRTY MINUTES OF WORK\nfinished\n",
    )
    .expect("the workload keeps printing");

    runner_in_process(&Arc::new(StreamPlane::new()))
        .stop(&VmId("outlived-vm".to_string()))
        .expect("stop");

    let (availability, records) = sealed_run("outlived-vm");
    // The output first: what a user typing `mvmctl logs` gets back is the
    // whole point, and an availability label they never see is not.
    let whole = String::from_utf8(payloads(&records).concat()).expect("utf-8");
    assert!(
        whole.contains("THIRTY MINUTES OF WORK") && whole.contains("finished"),
        "everything the workload printed after its recorder exited must be returned: {whole:?}"
    );
    assert_eq!(availability, StreamAvailability::HistoryAndConsole);
    assert!(
        records.iter().any(|r| r.origin == RecordOrigin::Durable),
        "the chained half is still shown"
    );
    assert!(
        records.iter().any(|r| r.origin == RecordOrigin::Console),
        "and the remainder is labelled as the unchained source it is"
    );
}

#[test]
fn an_entrypoint_run_whose_caller_exits_is_sealed_by_the_stop_that_follows() {
    // `mvmctl up`: an admitted workload whose entrypoint output arrives over
    // the agent channel rather than the console. Same process boundary, and
    // the same requirement — except that these frames are the only ones that
    // carry which channel a byte came out of, so losing them costs the
    // transcript the one thing the console can never supply.
    register();
    let (_env, _tmp) = isolated_home();

    let starting = Arc::new(StreamPlane::new());
    launch(&runner_in_process(&starting), "up-vm");
    let mut sink = starting.entrypoint_sink("up-vm");
    assert!(sink.is_recorded(), "the workload is attached to this plane");
    sink.ingest(StreamKind::Stdout, b"the result\n");
    sink.ingest(StreamKind::Stderr, b"the warning\n");
    drop(sink);
    settle();
    drop(starting);

    let stopping = Arc::new(StreamPlane::new());
    runner_in_process(&stopping)
        .stop(&VmId("up-vm".to_string()))
        .expect("stop");

    let (availability, records) = sealed_run("up-vm");
    assert_eq!(availability, StreamAvailability::HistoryOnly);
    assert_eq!(
        records
            .iter()
            .map(|r| (r.kind, r.payload.clone()))
            .collect::<Vec<_>>(),
        vec![
            (StreamKind::Stdout, b"the result\n".to_vec()),
            (StreamKind::Stderr, b"the warning\n".to_vec()),
        ],
        "the sealed capture keeps the channel the entrypoint sent each frame on"
    );
}

#[test]
fn a_foreground_run_detached_part_way_through_still_seals_when_the_vm_stops() {
    // The documented Ctrl-C detach: the foreground caller goes away while the
    // workload keeps running, so the `stop` that eventually ends it belongs
    // to a process that saw none of the output.
    register();
    let (_env, _tmp) = isolated_home();

    let foreground = Arc::new(StreamPlane::new());
    launch(&runner_in_process(&foreground), "detached-later-vm");
    std::fs::write(
        console_log("detached-later-vm"),
        b"printed before the detach\n",
    )
    .expect("write the console capture");
    settle();
    drop(foreground);

    // Nothing seals on the way out, and nothing should: the VM is still
    // running and the manifest belongs to whoever ends it. Until then the
    // only readable source is the console file — the state this task exists
    // to make temporary rather than permanent.
    assert_eq!(
        sealed_run("detached-later-vm").0,
        StreamAvailability::ConsoleOnly
    );

    runner_in_process(&Arc::new(StreamPlane::new()))
        .stop(&VmId("detached-later-vm".to_string()))
        .expect("stop");

    let (availability, records) = sealed_run("detached-later-vm");
    assert_eq!(availability, StreamAvailability::HistoryAndConsole);
    let durable: Vec<Vec<u8>> = records
        .iter()
        .filter(|r| r.origin == RecordOrigin::Durable)
        .map(|r| r.payload.clone())
        .collect();
    assert_eq!(durable, [b"printed before the detach\n"]);
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
