//! One workload's output driven into another's stdin, through the real
//! broker, the real reader and the real input gate.
//!
//! Nothing here hand-builds a session or a reader. The point is the seam
//! between two pieces that each already work alone: whether the connector
//! preserves what the gate needs (acceptance order, a live lease, the withheld
//! tail delivered at close) once something actually drives it.

use mvm_contract::protocol::broker::ServiceId;
use mvm_contract::stream::edge::{EdgeBackpressure, EdgeRedaction, StreamEdge};
use mvm_contract::stream::input::INPUT_GRANT_SERVICE;
use mvm_contract::stream::input::{CloseInput, InputFrame};
use mvm_contract::stream::record::{StreamKind, StreamSource};
use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput};
use mvm_core::policy::RedactionPolicy;
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::plan_admission::{AdmittedPlan, InMemoryNonceLedger, SystemClock, admit_for_run};
use mvm_hostd::stream::{
    EdgeConnector, EdgeError, EdgeStep, InputAudit, InputBinding, InputGate, InputRefusal,
    InputRoute, InputTransport, StreamBroker, StreamRedaction, WireSequence,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

#[derive(Clone, Default)]
struct CapturedInput {
    bytes: Arc<Mutex<Vec<u8>>>,
    close: Arc<Mutex<Option<CloseInput>>>,
}

impl CapturedInput {
    fn bytes(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn close(&self) -> Option<CloseInput> {
        self.close
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl InputTransport for CapturedInput {
    fn deliver(&mut self, frame: &InputFrame) -> anyhow::Result<()> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(&frame.payload);
        Ok(())
    }

    fn close(&mut self, close: &CloseInput) -> anyhow::Result<()> {
        self.bytes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(&close.trailing);
        *self
            .close
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(close.clone());
        Ok(())
    }
}

fn input_route(vm: &str, admitted: &AdmittedPlan) -> (InputRoute, CapturedInput) {
    let capture = CapturedInput::default();
    let route = InputRoute::open(
        vm,
        admitted,
        Box::new(capture.clone()),
        WireSequence::default(),
    )
    .expect("the plan grants input");
    (route, capture)
}

fn unique_vm(prefix: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// A plan out of the real admission pipeline, carrying the input grant.
///
/// Signed, verified, window-checked and replay-checked — the gate takes
/// nothing less, so a fixture that hand-built one would be testing a path no
/// caller uses.
fn admitted_with_grant(vm: &str) -> AdmittedPlan {
    const FIXTURE_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let input = SynthesisInput {
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        vm_name: vm,
        tenant: None,
        backend_name: "firecracker",
        image_name: "img",
        image_sha256: FIXTURE_SHA,
        image_cosign_bundle: None,
        intent: None,
        seccomp_tier: PlanSeccompTier::Standard,
        network_policy_ref: None,
        fs_policy_ref: None,
        egress_policy_ref: None,
        tool_policy_ref: None,
        secret_release: SecretReleasePolicy::None,
        secrets: Vec::new(),
        audit_event_prefix: None,
        cpus: 1,
        mem_mib: 256,
        disk_mib: 0,
        boot_timeout_secs: 30,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        audit_labels: Default::default(),
        agent_verbs: None,
        services: vec![ServiceId::parse(INPUT_GRANT_SERVICE).expect("the grant token parses")],
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
        network_mode: mvm_contract::plan::NetworkMode::None,
        ingress: Vec::new(),
    };
    admit_for_run(
        &input,
        &SystemClock,
        &InMemoryNonceLedger::new(),
        None,
        None,
        mvm_hostd::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
    )
    .expect("the fixture input admits")
}

/// Serializes the tests in this file.
///
/// `MVM_HOME` is process-global and the gate's lease table is process-wide, so
/// two of these running at once are configuring each other's world. Held for
/// the body of each test rather than just the setup, because the gate reads
/// the environment again on every open.
static SERIAL: Mutex<()> = Mutex::new(());

/// An isolated `MVM_HOME`, so the gate's signer and chain land in a temp dir.
fn isolated_home() -> (MutexGuard<'static, ()>, TestEnv, tempfile::TempDir) {
    let guard = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut env = TestEnv::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    env.isolate_mvm_home(tmp.path());
    (guard, env, tmp)
}

/// Bind the consumer's gate to a chain of its own.
///
/// Without this the gate refuses every open as `Unauditable`: input that
/// leaves no signed trace is input it declines to have happened. The process
/// default chain is cached once per process, so each VM needs its own.
fn bind_chain(vm: &str) -> tempfile::TempDir {
    let chain_dir = tempfile::tempdir().expect("chain dir");
    let key = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
    InputGate::bind(
        vm,
        InputBinding::new().with_audit(InputAudit::new(
            AuditEmitter::with_dir(key, chain_dir.path()).expect("open the chain"),
        )),
    );
    chain_dir
}

/// A broker with no durable sink: this exercises fan-out, not retention.
fn broker(vm: &str) -> StreamBroker {
    StreamBroker::live_only(vm, StreamRedaction::curated(&RedactionPolicy::default()))
}

fn ingest(b: &mut StreamBroker, payload: &[u8]) {
    b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, payload);
}

/// The core of the slice: bytes a producer wrote reach a consumer's stdin, in
/// order, without either side naming the other.
#[test]
fn a_producers_output_reaches_a_consumers_stdin_in_order() {
    let (_serial, _env, _tmp) = isolated_home();
    let consumer = unique_vm("consumer");
    let plan = admitted_with_grant(&consumer);
    let _chain = bind_chain(&consumer);
    let (route, captured) = input_route(&consumer, &plan);

    let mut b = broker(&unique_vm("producer"));
    let reader = b.subscribe();
    ingest(&mut b, b"first\n");
    ingest(&mut b, b"second\n");

    let mut edge = EdgeConnector::new(&StreamEdge::new("upstream"), route, reader)
        .expect("a redacted edge is servable");
    match edge.step().expect("the pump runs") {
        EdgeStep::Delivered { records, bytes } => {
            assert_eq!(records, 2, "both records crossed");
            assert_eq!(bytes, b"first\nsecond\n".len(), "every byte crossed");
        }
        other => panic!("expected delivery, got {other:?}"),
    }
    assert_eq!(captured.bytes(), b"first\nsecond\n");

    edge.close().expect("close");
    let closed = captured.close().expect("the transport saw EOF");
    assert_eq!(
        closed.after_seq,
        Some(1),
        "the close names the last frame the gate accepted, so a re-run can reason about it"
    );
}

/// A lease these tests mean to step across or outwait, the gap between steps,
/// and a wait that outlives the lease.
///
/// The TTL doubles as the window each step has to land in, so it is sized from
/// measurement rather than taste: on a loaded host the gap between two adjacent
/// statements measured up to 298ms, so the previous 60ms lease lapsed between
/// two steps and handed the lease to the competitor the test expects to be
/// refused. See `input_gate::tests::LAPSING_LEASE_TTL` for the measurement.
const LAPSING_LEASE_TTL: Duration = Duration::from_secs(1);
const BETWEEN_STEPS: Duration = Duration::from_millis(300);
const PAST_THE_LEASE: Duration = Duration::from_millis(1300);

/// An edge whose producer is quiet must not lose the single-writer lease.
///
/// Observed the only way it can be: by a competing writer. A test that merely
/// stepped twice would pass whether or not the refresh happened, because the
/// default TTL outlives the test — which is the shape of a test that cannot
/// fail. Here the TTL is short, the edge is stepped across it, and the
/// competitor is refused because the lease is still held.
#[test]
fn stepping_across_the_ttl_keeps_the_lease_from_a_competitor() {
    let (_serial, _env, _tmp) = isolated_home();
    let consumer = unique_vm("consumer-idle");
    let plan = admitted_with_grant(&consumer);

    let chain_dir = tempfile::tempdir().expect("chain dir");
    let key = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
    InputGate::bind(
        &consumer,
        InputBinding::new()
            .with_lease_ttl(LAPSING_LEASE_TTL)
            .with_audit(InputAudit::new(
                AuditEmitter::with_dir(key, chain_dir.path()).expect("chain"),
            )),
    );
    let (route, _captured) = input_route(&consumer, &plan);

    let mut b = broker(&unique_vm("producer-idle"));
    let reader = b.subscribe();
    let mut edge = EdgeConnector::new(&StreamEdge::new("quiet"), route, reader).expect("servable");

    // Step across more than one whole TTL, with nothing to send. Six gaps of
    // this size outlast the TTL, while each one still leaves the next step room
    // to land inside it.
    for _ in 0..6 {
        assert_eq!(edge.step().expect("idle step"), EdgeStep::Idle);
        std::thread::sleep(BETWEEN_STEPS);
    }

    assert!(
        matches!(
            InputGate::open(&consumer, &plan),
            Err(InputRefusal::LeaseHeld { .. })
        ),
        "a stepped edge still holds the lease, so a competitor must be refused"
    );
}

/// The converse, so the test above is known to be observing something: an edge
/// that is *not* stepped lets the lease lapse and the competitor wins.
#[test]
fn an_unstepped_edge_lets_the_lease_lapse() {
    let (_serial, _env, _tmp) = isolated_home();
    let consumer = unique_vm("consumer-lapse");
    let plan = admitted_with_grant(&consumer);

    let chain_dir = tempfile::tempdir().expect("chain dir");
    let key = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
    InputGate::bind(
        &consumer,
        InputBinding::new()
            .with_lease_ttl(LAPSING_LEASE_TTL)
            .with_audit(InputAudit::new(
                AuditEmitter::with_dir(key, chain_dir.path()).expect("chain"),
            )),
    );
    let (route, _captured) = input_route(&consumer, &plan);

    let mut b = broker(&unique_vm("producer-lapse"));
    let reader = b.subscribe();
    let _edge = EdgeConnector::new(&StreamEdge::new("abandoned"), route, reader).expect("servable");

    std::thread::sleep(PAST_THE_LEASE);
    assert!(
        InputGate::open(&consumer, &plan).is_ok(),
        "an abandoned lease must lapse, or the two tests above prove nothing"
    );
}

/// Records ingested *before* the edge is built are already in the reader's
/// queue, and must not be skipped. A connector that only forwarded what
/// arrived after construction would silently drop a producer's head.
#[test]
fn records_buffered_before_the_edge_existed_are_delivered() {
    let (_serial, _env, _tmp) = isolated_home();
    let consumer = unique_vm("consumer-backlog");
    let plan = admitted_with_grant(&consumer);
    let _chain = bind_chain(&consumer);
    let (route, captured) = input_route(&consumer, &plan);

    let mut b = broker(&unique_vm("producer-backlog"));
    let reader = b.subscribe();
    for i in 0..5 {
        ingest(&mut b, format!("line-{i}\n").as_bytes());
    }

    let mut edge = EdgeConnector::new(&StreamEdge::new("backlog"), route, reader).expect("ok");
    match edge.step().expect("pump") {
        EdgeStep::Delivered { records, .. } => assert_eq!(records, 5, "the backlog crossed whole"),
        other => panic!("expected delivery, got {other:?}"),
    }
    assert_eq!(
        captured.bytes(),
        b"line-0\nline-1\nline-2\nline-3\nline-4\n"
    );
}

/// Frame sequence must advance across steps, not restart. The gate rejects a
/// repeat, so a connector that reset its counter per step would have its
/// second batch refused.
#[test]
fn frame_sequence_advances_across_steps() {
    let (_serial, _env, _tmp) = isolated_home();
    let consumer = unique_vm("consumer-seq");
    let plan = admitted_with_grant(&consumer);
    let _chain = bind_chain(&consumer);
    let (route, captured) = input_route(&consumer, &plan);

    let mut b = broker(&unique_vm("producer-seq"));
    let reader = b.subscribe();
    let mut edge = EdgeConnector::new(&StreamEdge::new("seq"), route, reader).expect("ok");

    ingest(&mut b, b"one\n");
    assert!(matches!(
        edge.step().expect("first"),
        EdgeStep::Delivered { records: 1, .. }
    ));
    ingest(&mut b, b"two\n");
    assert!(
        matches!(
            edge.step().expect("second"),
            EdgeStep::Delivered { records: 1, .. }
        ),
        "a restarted sequence would have been refused as a replay here"
    );

    edge.close().expect("close");
    let closed = captured.close().expect("the transport saw EOF");
    assert_eq!(closed.after_seq, Some(1), "two frames, seq 0 and 1");
}

/// A raw edge is refused rather than served masked bytes under a raw label.
#[test]
fn a_raw_edge_is_refused_at_construction() {
    let (_serial, _env, _tmp) = isolated_home();
    let consumer = unique_vm("consumer-raw");
    let plan = admitted_with_grant(&consumer);
    let _chain = bind_chain(&consumer);
    let (route, _captured) = input_route(&consumer, &plan);

    let mut b = broker(&unique_vm("producer-raw"));
    let reader = b.subscribe();
    let edge = StreamEdge {
        binding: "fidelity".into(),
        redaction: EdgeRedaction::Raw,
        backpressure: EdgeBackpressure::Lossy,
    };
    match EdgeConnector::new(&edge, route, reader) {
        Err(EdgeError::RawUnavailable { binding }) => assert_eq!(binding, "fidelity"),
        Ok(_) => panic!("a raw edge must not be served from a post-seam reader"),
        Err(other) => panic!("expected RawUnavailable, got {other}"),
    }
}

/// The two backpressure modes must differ on the same input. Both are built
/// over the same reader shape; only the reaction to a lost record differs.
#[test]
fn the_backpressure_modes_are_distinguishable() {
    let lossy = StreamEdge::new("l");
    let reliable = StreamEdge {
        binding: "r".into(),
        redaction: EdgeRedaction::Redacted,
        backpressure: EdgeBackpressure::Reliable,
    };
    assert_eq!(lossy.backpressure, EdgeBackpressure::Lossy);
    assert_eq!(reliable.backpressure, EdgeBackpressure::Reliable);
    assert!(
        !lossy.is_raw() && !reliable.is_raw(),
        "both default to the masked posture"
    );
}
