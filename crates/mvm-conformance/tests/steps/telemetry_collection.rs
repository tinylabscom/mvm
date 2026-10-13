//! Guest telemetry from the guest agent's own capture subscriber to the
//! operator's `mvmctl machine telemetry`, hermetically: the real capture
//! session serves an authenticated host receiver over a socket pair, the
//! records pass the host collector's scrub and sealed sink into the isolated
//! home exactly where a VM's collector writes them, and the CLI reads them
//! back through the read seam. No VM boots; the live witnesses on Firecracker
//! and HVF are recorded in the telemetry certification record.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use cucumber::{given, then};
use ed25519_dalek::{Signer as _, SigningKey};
use mvm_agentd::telemetry_capture::session::{SessionDeadlines, serve_capture_session};
use mvm_agentd::telemetry_capture::{AgentSubscriber, CaptureState, offer_stdio_to};
use mvm_contract::stream::secret_fingerprint::{SecretCategory, SecretFingerprint};
use mvm_core::net::telemetry::outbox::Outbox;
use mvm_core::net::telemetry::{TelemetryReceiver, handshake_signing_bytes};
use mvm_core::protocol::telemetry::MAX_RECORD_BYTES;
use mvm_hostd::telemetry_collector::{
    CappedJsonlSink, CollectorStatusSnapshot, LossCounters, RecordSink as _, ScrubbingSink,
};
use mvm_vmm::host::telemetry_provisioning::{
    TELEMETRY_COLLECTOR_STATUS_FILE, TELEMETRY_RECORDS_FILE, provision_records_key,
    record_boot_provisioning,
};

use crate::world::CliWorld;

/// The synthetic secret the withholding scenario binds. Never a credential.
pub(crate) const SYNTHETIC_SECRET: &str = "bdd-telemetry-secret-5f2a9c71e0";

const BOUNDS: SessionDeadlines = SessionDeadlines {
    probe: Duration::from_millis(10),
    ..SessionDeadlines::AGENT
};

fn home(world: &CliWorld) -> PathBuf {
    world
        .isolated_home
        .as_ref()
        .expect("an isolated mvm home must be created first")
        .path()
        .to_path_buf()
}

/// Emit `diagnostics` through the guest agent's capture subscriber, carry
/// them over a real authenticated capture session, and persist what the
/// host collector keeps for `machine` in the isolated home.
fn collect(home: &Path, machine: &str, bound_secret: bool, diagnostics: impl FnOnce()) {
    collect_with(home, machine, bound_secret, diagnostics, |_| {});
}

/// The guest's capture queue, in records; the agent's own is 128.
const QUEUE_RECORDS: usize = 64;
/// How long the host waits for the next record before calling the session
/// done. Past the capture session's one-second loss-summary clock, so a
/// session that shed records always reports it before the host stops.
const QUIET_FOR: Duration = Duration::from_millis(1500);

/// [`collect`], with workload output offered to capture the way the agent's
/// pipe readers offer it.
fn collect_with(
    home: &Path,
    machine: &str,
    bound_secret: bool,
    diagnostics: impl FnOnce(),
    output: impl FnOnce(&CaptureState),
) {
    collect_into_queue(
        home,
        machine,
        bound_secret,
        QUEUE_RECORDS,
        diagnostics,
        output,
    );
}

fn collect_into_queue(
    home: &Path,
    machine: &str,
    bound_secret: bool,
    queue_records: usize,
    diagnostics: impl FnOnce(),
    output: impl FnOnce(&CaptureState),
) {
    let state_dir = mvm_core::config::vm_state_dir_at(home, machine);
    std::fs::create_dir_all(&state_dir).unwrap();
    record_boot_provisioning(&state_dir, true).unwrap();
    let key = provision_records_key(&state_dir, &mvm_core::config::mvm_keys_dir_at(home)).unwrap();

    let capture = Arc::new(
        CaptureState::new(Arc::new(
            Outbox::new(queue_records, queue_records * MAX_RECORD_BYTES).unwrap(),
        ))
        .unwrap(),
    );
    tracing::subscriber::with_default(AgentSubscriber::new(Arc::clone(&capture)), diagnostics);
    output(&capture);

    let guest_key = SigningKey::from_bytes(&[91; 32]);
    let anchor_key = SigningKey::from_bytes(&[92; 32]);
    let (mut guest, mut host) = UnixStream::pair().unwrap();
    let guest_identity = guest_key.verifying_key();
    let anchor = anchor_key.verifying_key();
    let serving = std::thread::spawn(move || {
        let stop = AtomicBool::new(false);
        serve_capture_session(&mut guest, guest_key, &anchor, &capture, &stop, BOUNDS)
    });

    let mut receiver = TelemetryReceiver::connect_authenticated(
        &mut host,
        &anchor_key.verifying_key(),
        &guest_identity,
        move |hello, ack| {
            let bytes =
                handshake_signing_bytes(hello, ack, &anchor_key.verifying_key()).map_err(|_| {
                    mvm_core::net::session::SessionError::InvalidHandshake("bad handshake".into())
                })?;
            Ok(anchor_key.sign(&bytes))
        },
    )
    .expect("the host authenticates the guest's capture session");

    let fingerprints = if bound_secret {
        vec![
            SecretFingerprint::of(SYNTHETIC_SECRET.as_bytes(), SecretCategory::HostSecret).unwrap(),
        ]
    } else {
        Vec::new()
    };
    let losses = Arc::new(LossCounters::default());
    let mut sink = ScrubbingSink::new(
        fingerprints,
        mvm_hostd::stream::redact::StreamRedaction::curated(
            &mvm_core::policy::RedactionPolicy::default(),
        ),
        CappedJsonlSink::create(&state_dir.join(TELEMETRY_RECORDS_FILE), 1 << 20, key).unwrap(),
        Arc::clone(&losses),
    );
    host.set_read_timeout(Some(QUIET_FOR)).unwrap();
    while let Ok(record) = receiver.receive(&mut host) {
        if let mvm_hostd::telemetry_collector::IngestOutcome::Shed(class) = sink.try_ingest(&record)
        {
            losses.record(class);
        }
    }
    sink.release_held();
    drop(host);
    let _ = serving.join();

    let snapshot = losses.snapshot();
    let status = CollectorStatusSnapshot {
        vm_name: machine.to_string(),
        status: "collecting".into(),
        generation: Some(1),
        shed: snapshot.total(),
        losses: snapshot,
    };
    std::fs::write(
        state_dir.join(TELEMETRY_COLLECTOR_STATUS_FILE),
        serde_json::to_vec(&status).unwrap(),
    )
    .unwrap();
}

#[given(expr = "a machine {string} whose guest agent emitted an event outside any span")]
async fn guest_emitted_a_standalone_event(world: &mut CliWorld, machine: String) {
    let home = home(world);
    tokio::task::spawn_blocking(move || {
        collect(&home, &machine, false, || {
            tracing::warn!(detail = "standalone", "bdd standalone event");
        });
    })
    .await
    .unwrap();
}

#[given(expr = "a machine {string} whose guest agent emitted boot diagnostics")]
async fn guest_emitted_boot_diagnostics(world: &mut CliWorld, machine: String) {
    let home = home(world);
    tokio::task::spawn_blocking(move || {
        collect(&home, &machine, false, || {
            tracing::info!(phase = "boot", "bdd agent boot diagnostic");
        });
    })
    .await
    .unwrap();
}

#[given(expr = "a machine {string} whose guest agent logged a secret bound to it")]
async fn guest_logged_a_bound_secret(world: &mut CliWorld, machine: String) {
    let home = home(world);
    tokio::task::spawn_blocking(move || {
        collect(&home, &machine, true, || {
            tracing::warn!(token = SYNTHETIC_SECRET, "bdd leaked credential");
            tracing::info!("bdd clean diagnostic");
        });
    })
    .await
    .unwrap();
}

#[given(expr = "a machine {string} whose detached workload wrote to stdout and stderr")]
async fn detached_workload_wrote_output(world: &mut CliWorld, machine: String) {
    use mvm_core::protocol::telemetry::StdioStream;
    let home = home(world);
    tokio::task::spawn_blocking(move || {
        collect_with(
            &home,
            &machine,
            false,
            || {},
            |capture| {
                offer_stdio_to(capture, StdioStream::Stdout, b"bdd-out-line\n");
                offer_stdio_to(capture, StdioStream::Stderr, b"bdd-err-line\n");
            },
        );
    })
    .await
    .unwrap();
}

#[given(expr = "a machine {string} whose guest flooded diagnostics while no host was reading")]
async fn guest_flooded_with_no_reader(world: &mut CliWorld, machine: String) {
    let home = home(world);
    tokio::task::spawn_blocking(move || {
        // Eight queue slots and a hundred events emitted before any host
        // session exists: every emission returns at once, and what did not
        // fit is counted for the session to report.
        collect_into_queue(
            &home,
            &machine,
            false,
            8,
            || {
                for n in 0..100 {
                    tracing::info!(n, "bdd flood");
                }
            },
            |_| {},
        );
    })
    .await
    .unwrap();
}

#[given(expr = "a machine {string} whose guest agent emitted an event inside a child span")]
async fn guest_emitted_nested_spans(world: &mut CliWorld, machine: String) {
    let home = home(world);
    tokio::task::spawn_blocking(move || {
        collect(&home, &machine, false, || {
            let parent = tracing::info_span!("bdd-parent", step = "outer");
            let _in_parent = parent.enter();
            let child = tracing::info_span!("bdd-child", step = "inner");
            let _in_child = child.enter();
            tracing::info!("bdd event in child");
        });
    })
    .await
    .unwrap();
}

fn stdout(world: &CliWorld) -> String {
    String::from_utf8_lossy(&world.last_output().stdout).into_owned()
}

/// The line `machine telemetry` printed for the span opened as `name`.
fn span_open_line<'a>(stdout: &'a str, name: &str) -> &'a str {
    let marker = format!("span open {name} ");
    stdout
        .lines()
        .find(|line| line.contains(&marker))
        .unwrap_or_else(|| panic!("no span open line for {name}; stdout:\n{stdout}"))
}

/// The (trace id, span id) of the traceparent printed after the span's name.
fn printed_ids(stdout: &str, name: &str) -> (String, String) {
    let marker = format!("span open {name} ");
    let line = span_open_line(stdout, name);
    let traceparent = line[line.find(&marker).unwrap_or_default() + marker.len()..]
        .split_whitespace()
        .next()
        .unwrap_or_default();
    let mut fields = traceparent.split('-').skip(1);
    match (fields.next(), fields.next()) {
        (Some(trace), Some(span)) => (trace.to_string(), span.to_string()),
        _ => panic!("no traceparent after {name}: {line}"),
    }
}

#[then(expr = "the span {string} is shown as the parent of span {string}")]
fn span_is_shown_as_parent(world: &mut CliWorld, parent: String, child: String) {
    let stdout = stdout(world);
    let (parent_trace, parent_span) = printed_ids(&stdout, &parent);
    let (child_trace, _) = printed_ids(&stdout, &child);
    let child_line = span_open_line(&stdout, &child);
    assert!(
        child_line.contains(&format!(" parent={parent_span}")),
        "{child} must name {parent} ({parent_span}) as its parent: {child_line}"
    );
    assert_eq!(
        parent_trace, child_trace,
        "{child} must share {parent}'s trace"
    );
}

#[then(expr = "the event {string} is shown inside span {string}")]
fn event_is_shown_inside_span(world: &mut CliWorld, message: String, span: String) {
    let stdout = stdout(world);
    let (_, span_id) = printed_ids(&stdout, &span);
    let event_line = stdout
        .lines()
        .find(|line| line.contains(" event ") && line.contains(&message))
        .unwrap_or_else(|| panic!("no event line for {message:?}; stdout:\n{stdout}"));
    assert!(
        event_line.contains(&format!(" span={span_id}")),
        "{message:?} must be correlated with {span} ({span_id}): {event_line}"
    );
}

#[then(expr = "the span {string} is shown closed")]
fn span_is_shown_closed(world: &mut CliWorld, span: String) {
    let stdout = stdout(world);
    let (_, span_id) = printed_ids(&stdout, &span);
    assert!(
        stdout
            .lines()
            .any(|line| line.contains(&format!("span close {span_id} "))),
        "{span} ({span_id}) must be shown closed; stdout:\n{stdout}"
    );
}
