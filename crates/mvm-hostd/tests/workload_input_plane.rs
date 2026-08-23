//! The input plane end to end, reached the way a writer reaches it: a plan
//! that came out of the real admission pipeline, the real gate, the real
//! per-VM plane, and a workload process that either does or does not receive
//! the bytes.
//!
//! Nothing here constructs an `InputSession` or an `AdmittedPlan` by hand.
//! Those shortcuts exist inside the crate and they prove the pieces work; what
//! this file is for is the question the pieces cannot answer on their own —
//! whether anything connects them, and whether the two guarantees that survive
//! only by construction still hold once they do.
//!
//! The transport terminates in the guest's own `InputSink` over a real child
//! process, so "the workload sees it" is a `read` on a pipe rather than an
//! assertion about a buffer. The vsock hop between them is the one link a test
//! without a microVM cannot cross; `mvm_agentd::stream_input`'s own tests cover
//! the far side of it.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use mvm_agentd::stream_input::{InputDesk, InputSink};
use mvm_agentd::vsock::StreamInputResult;
use mvm_contract::protocol::broker::ServiceId;
use mvm_contract::stream::input::{CloseInput, INPUT_GRANT_SERVICE, InputFrame};
use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput};
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::emitter::{AuditEmitter, stream_audit};
use mvm_hostd::plan_admission::{AdmittedPlan, InMemoryNonceLedger, SystemClock, admit_for_run};
use mvm_hostd::stream::{
    CATEGORY_HOST_SECRET, InputAudit, InputBinding, InputGate, InputRefusal, InputRouteError,
    InputTransport, StreamPlane,
};
use mvm_hostd::supervisor::verify_audit_chain;

/// The guest half, standing in for the vsock hop: every frame the route hands
/// over goes straight into a real workload's stdin, in the order it arrives.
struct ToWorkload {
    /// `None` once the stream is closed — `InputSink::close` consumes the
    /// sink, and that consumption is what closes the fd.
    sink: Option<InputSink>,
}

impl ToWorkload {
    fn over(child: &mut Child) -> Self {
        Self {
            sink: Some(InputSink::new(child.stdin.take().expect("piped stdin"))),
        }
    }
}

impl InputTransport for ToWorkload {
    fn deliver(&mut self, frame: &InputFrame) -> Result<()> {
        let sink = self
            .sink
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("the workload's input stream is already closed"))?;
        sink.write_frame(frame.clone())?;
        Ok(())
    }

    fn close(&mut self, close: &CloseInput) -> Result<()> {
        let mut sink = self
            .sink
            .take()
            .ok_or_else(|| anyhow::anyhow!("the workload's input stream is already closed"))?;
        // The tail first, then EOF. The guest's types force this order —
        // `deliver_tail` borrows, `close` consumes — but nothing forces the
        // host to hand a tail over at all, which is the failure this covers.
        sink.deliver_tail(&close.trailing)?;
        sink.close();
        Ok(())
    }
}

/// The guest half again, but the *real* one: frames go through the agent's own
/// [`InputDesk`], which is precisely what the vsock hop delivers to and the
/// only thing that enforces the guest's end of the ordering contract.
///
/// It can be told to lose the answer to one call *after* the desk has already
/// taken the frame — a connection reset mid-answer, which is the failure that
/// makes a retry either exactly-once or a silent duplicate.
struct ToDesk {
    lose_answer_at: Option<u64>,
}

impl ToDesk {
    fn over(child: &mut Child) -> Self {
        InputDesk::open(child.stdin.take().expect("piped stdin"));
        Self::to_the_open_desk()
    }

    /// A second transport onto the desk a workload already has open — what a
    /// writer succeeding a lapsed one gets.
    fn to_the_open_desk() -> Self {
        Self {
            lose_answer_at: None,
        }
    }

    fn losing_the_answer_to(mut self, seq: u64) -> Self {
        self.lose_answer_at = Some(seq);
        self
    }
}

impl InputTransport for ToDesk {
    fn deliver(&mut self, frame: &InputFrame) -> Result<()> {
        let answered = InputDesk::write_frame(frame.clone());
        if self.lose_answer_at == Some(frame.seq) {
            self.lose_answer_at = None;
            anyhow::bail!("the connection reset before the guest's answer arrived");
        }
        match answered {
            StreamInputResult::Accepted { .. } => Ok(()),
            other => anyhow::bail!("the guest refused the frame: {other:?}"),
        }
    }

    fn close(&mut self, close: &CloseInput) -> Result<()> {
        match InputDesk::close(close.clone()) {
            StreamInputResult::Closed => Ok(()),
            other => anyhow::bail!("the guest refused the close: {other:?}"),
        }
    }
}

/// The desk is one per guest, so two tests driving it at once would be driving
/// each other's workload. Serialized rather than made per-test: "there is
/// exactly one" is the property under test.
fn desk_test() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A workload shaped like the ones this plane serves: reads stdin to EOF,
/// writes it back out.
fn cat() -> Child {
    Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the workload")
}

/// Everything the workload read, once its stdin has been closed and it has
/// exited.
fn workload_output(mut child: Child) -> Vec<u8> {
    let mut out = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut out)
        .expect("read the workload's output");
    child.wait().expect("the workload exits after EOF");
    out
}

/// Point the whole mvm world at a tempdir: the host signer, the audit chain
/// and every VM state dir land under it.
fn isolated_home() -> (TestEnv, tempfile::TempDir) {
    let mut env = TestEnv::new();
    let tmp = tempfile::tempdir().expect("tempdir");
    env.isolate_mvm_home(tmp.path());
    (env, tmp)
}

/// A VM name no other test uses: the gate's lease table is process-wide.
fn frame(seq: u64, payload: &[u8]) -> InputFrame {
    InputFrame {
        seq,
        payload: payload.to_vec(),
    }
}

fn unique_vm(prefix: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// A lease a test means to watch lapse, and a wait that outlives it.
///
/// The TTL doubles as the window every write before the lapse has to land in,
/// so it cannot be shortened to taste. On a loaded host the gap between two
/// adjacent statements measured up to 298ms, which is why the previous 20ms
/// lease expired mid-setup and refused a write the test required to succeed.
/// See `input_gate::tests::LAPSING_LEASE_TTL` for the measurement.
const LAPSING_LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(1);
const PAST_THE_LEASE: std::time::Duration = std::time::Duration::from_millis(1300);
/// For a lease nothing waits out, so jitter cannot reach it.
const LIVE_LEASE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// The input binding the fixtures share: a real chain, so the gate's
/// record-the-decision path is exercised rather than stubbed.
fn audit_binding(
    chain_key: &ed25519_dalek::SigningKey,
    chain_dir: &std::path::Path,
) -> InputBinding {
    InputBinding::new().with_audit(InputAudit::new(
        AuditEmitter::with_dir(chain_key.clone(), chain_dir).expect("open the chain"),
    ))
}

fn synthesis_input(vm_name: &str) -> SynthesisInput<'_> {
    const FIXTURE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    SynthesisInput {
        grants: None,
        stream_edges: Vec::new(),
        kernel_sha256: None,
        vm_name,
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
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        extensions: Vec::new(),
        stream_retention: Default::default(),
        attestation_mode: mvm_contract::plan::AttestationMode::Noop,
        // Closed transport: this fixture's workload reaches nothing.
        network_mode: mvm_contract::plan::NetworkMode::None,
        ingress: Vec::new(),
    }
}

/// One test's world: an isolated `MVM_HOME`, the host signer admission mints
/// under it, and a chain of its own for the gate to record into.
///
/// The chain is bound per VM rather than left to the process default because
/// the process default is cached once per process — a second test in the same
/// binary would append to the first one's directory, which by then no longer
/// exists. Binding it explicitly is also what lets a test verify the
/// signatures it is asserting about.
struct Fixture {
    vm: String,
    plane: StreamPlane,
    chain_dir: tempfile::TempDir,
    chain_key: ed25519_dalek::SigningKey,
    _env: TestEnv,
    _home: tempfile::TempDir,
}

impl Fixture {
    /// A VM bound to this fixture's chain, recognising `secret` on the way in
    /// when one is given.
    fn new(prefix: &str, secret: Option<&[u8]>) -> Self {
        Self::bound(prefix, secret, None)
    }

    /// Stand in for the substitution endpoint: fingerprint `secret` and record
    /// it exactly where the spawn path records what the endpoint reported.
    ///
    /// This is the whole point of routing it through the registry rather than
    /// binding the gate directly — the production path that installs a
    /// fingerprint set is `StreamPlane::open_input`, and a test that reached
    /// past it would pass whether or not that call existed.
    fn endpoint_reports(vm: &str, secret: &[u8]) {
        let fingerprint = mvm_contract::stream::secret_fingerprint::SecretFingerprint::of(
            secret,
            mvm_contract::stream::secret_fingerprint::SecretCategory::HostSecret,
        )
        .expect("a non-empty secret fingerprints");
        mvm_runtime::record_secret_fingerprints(vm, vec![fingerprint]);
    }

    /// The same, on a lease short enough for a test to outwait.
    fn with_lease_ttl(prefix: &str, lease_ttl: std::time::Duration) -> Self {
        Self::bound(prefix, None, Some(lease_ttl))
    }

    /// Re-bind this VM's lease TTL, keeping the chain it was bound with.
    ///
    /// For a test where one lease is meant to lapse and the next is not: the
    /// successor's TTL is not what the test is timing, so it should not be
    /// racing the clock alongside the one that is.
    fn rebind_lease(&self, lease_ttl: std::time::Duration) {
        InputGate::bind(
            &self.vm,
            audit_binding(&self.chain_key, self.chain_dir.path()).with_lease_ttl(lease_ttl),
        );
    }

    fn bound(prefix: &str, secret: Option<&[u8]>, lease_ttl: Option<std::time::Duration>) -> Self {
        let (env, home) = isolated_home();
        let vm = unique_vm(prefix);
        let chain_dir = tempfile::tempdir().expect("chain dir");
        let chain_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);

        let mut binding = audit_binding(&chain_key, chain_dir.path());
        if let Some(ttl) = lease_ttl {
            binding = binding.with_lease_ttl(ttl);
        }
        InputGate::bind(&vm, binding);
        if let Some(secret) = secret {
            Self::endpoint_reports(&vm, secret);
        }

        Self {
            vm,
            plane: StreamPlane::new(),
            chain_dir,
            chain_key,
            _env: env,
            _home: home,
        }
    }

    /// A plan minted by the real admission pipeline, granting the input plane
    /// or not. Signed, verified, window-checked and replay-checked — the gate
    /// takes nothing less.
    fn admit(&self, granting: bool) -> AdmittedPlan {
        let mut input = synthesis_input(&self.vm);
        if granting {
            input.services =
                vec![ServiceId::parse(INPUT_GRANT_SERVICE).expect("the grant token parses")];
        }
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

    fn chain_path(&self) -> std::path::PathBuf {
        self.chain_dir
            .path()
            .join(format!("{}.jsonl", mvm_core::plan::DEFAULT_TENANT))
    }

    /// The chain-signed entries about this VM, as `(event, labels)`.
    fn chain_entries(&self) -> Vec<(String, BTreeMap<String, String>)> {
        let Ok(content) = std::fs::read_to_string(self.chain_path()) else {
            return Vec::new();
        };
        content
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|envelope| {
                let entry = envelope.get("entry")?;
                let labels: BTreeMap<String, String> =
                    serde_json::from_value(entry.get("labels")?.clone()).ok()?;
                if labels.get(stream_audit::LABEL_VM_NAME).map(String::as_str) != Some(&self.vm) {
                    return None;
                }
                Some((entry.get("event")?.as_str()?.to_string(), labels))
            })
            .collect()
    }
}

#[test]
fn a_plan_granted_writer_reaches_a_running_workloads_stdin() {
    // The gap this whole task exists to close: before it, a granted writer had
    // a session, a lease and an audit entry, and no code path from any of that
    // to a workload's stdin.
    let fx = Fixture::new("input-granted", None);
    let mut child = cat();

    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToWorkload::over(&mut child)),
        )
        .expect("an admitted plan carrying the grant opens the route");
    assert!(fx.plane.input_is_open(&fx.vm));

    fx.plane
        .write_input(&fx.vm, frame(0, b"hello "))
        .expect("the gate cleared it");
    fx.plane
        .write_input(&fx.vm, frame(1, b"workload\n"))
        .expect("and this one");
    fx.plane.close_input(&fx.vm).expect("the lease is live");

    assert_eq!(workload_output(child), b"hello workload\n");
    assert!(
        !fx.plane.input_is_open(&fx.vm),
        "a closed stream is not open"
    );
    assert!(
        fx.chain_entries()
            .iter()
            .any(|(event, _)| event == stream_audit::INPUT_GRANTED_EVENT),
        "a writer that reached a sealed workload leaves a signed trace"
    );
}

#[test]
fn an_ungranted_writer_is_refused_and_the_refusal_is_in_the_chain() {
    // Default-deny, and the record of it. A refusal nobody can see is the same
    // defect one layer down, so the chain entry is part of the property rather
    // than a nicety beside it.
    let fx = Fixture::new("input-ungranted", None);
    let mut child = cat();

    let refusal = fx
        .plane
        .open_input(
            &fx.vm,
            &fx.admit(false),
            Box::new(ToWorkload::over(&mut child)),
        )
        .expect_err("a plan without the grant must not open a route");
    assert!(matches!(refusal, InputRefusal::NotGranted));
    assert!(!fx.plane.input_is_open(&fx.vm));
    assert!(
        matches!(
            fx.plane.write_input(&fx.vm, frame(0, b"anyway")),
            Err(InputRouteError::NoSession)
        ),
        "there is no session to write through, which is the whole of the deny"
    );

    let entries = fx.chain_entries();
    let refused = entries
        .iter()
        .find(|(event, _)| event == stream_audit::INPUT_REFUSED_EVENT)
        .expect("the refusal is a signed fact, not a log line");
    assert_eq!(
        refused
            .1
            .get(stream_audit::LABEL_REASON)
            .map(String::as_str),
        Some("not-granted")
    );
    assert!(
        !entries
            .iter()
            .any(|(event, _)| event == stream_audit::INPUT_GRANTED_EVENT),
        "nothing was granted, so nothing may say it was"
    );
    verify_audit_chain(&fx.chain_path(), &fx.chain_key.verifying_key())
        .expect("the refusal is chain-signed like any other entry");

    // Nothing was written to the workload; closing the sink's own handle is
    // what lets it exit.
    assert!(workload_output(child).is_empty());
}

#[test]
fn a_secret_split_across_two_frames_does_not_reassemble_in_the_workload() {
    // Guarantee one, stated as its failure: the gate scans in acceptance order
    // and does not reassemble by `seq`, so a route that re-batched or
    // reordered would hand the workload, contiguously, a secret the gate saw
    // as two harmless halves.
    const SECRET: &[u8] = b"AKIAIOSFODNN7EXAMPLE";
    let fx = Fixture::new("input-split-secret", Some(SECRET));
    let mut child = cat();
    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToWorkload::over(&mut child)),
        )
        .expect("the grant opens the route");

    fx.plane
        .write_input(&fx.vm, frame(0, b"echo AKIAIOSFODNN"))
        .expect("a prefix alone is not a match");
    assert!(
        matches!(
            fx.plane.write_input(&fx.vm, frame(1, b"7EXAMPLE")),
            Err(InputRouteError::Refused(InputRefusal::SecretMaterial {
                category: CATEGORY_HOST_SECRET
            }))
        ),
        "the second half must be refused"
    );

    // The session latched on that refusal, so its close is refused too and the
    // stream never ends cleanly. Teardown is what frees the workload.
    fx.plane.release(&fx.vm);
    let seen = workload_output(child);
    assert_eq!(
        seen, b"",
        "nothing may arrive: the whole first frame sat inside the carried window"
    );
    assert!(
        !seen.windows(SECRET.len()).any(|w| w == SECRET),
        "and certainly not the secret itself"
    );
}

#[test]
fn the_tail_the_gate_withheld_is_delivered_before_the_workload_sees_eof() {
    // Guarantee two. The gate holds back a live secret prefix rather than
    // shipping it and refusing afterwards, and releases it at close because
    // closing proves it was only ever a prefix. A route that dropped the tail
    // would lose the writer's last bytes with no error anywhere — and a `cat`
    // that echoes them is the only way to tell.
    let fx = Fixture::new("input-tail", Some(b"AKIAIOSFODNN7EXAMPLE"));
    let mut child = cat();
    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToWorkload::over(&mut child)),
        )
        .expect("the grant opens the route");

    fx.plane
        .write_input(&fx.vm, frame(0, b"echo AKIAIOSFODNN"))
        .expect("a prefix is not a match");
    fx.plane.close_input(&fx.vm).expect("the lease is live");

    assert_eq!(
        workload_output(child),
        b"echo AKIAIOSFODNN",
        "the withheld tail is the writer's last bytes and must arrive ahead of EOF"
    );
}

#[test]
fn stopping_a_workload_ends_its_input_stream() {
    // A route left behind would hold the VM's stdin lease past the VM, and a
    // workload waiting on a stdin nobody will ever close waits for its whole
    // deadline.
    let fx = Fixture::new("input-release", None);
    let mut child = cat();
    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToWorkload::over(&mut child)),
        )
        .expect("the grant opens the route");
    fx.plane
        .write_input(&fx.vm, frame(0, b"before teardown"))
        .expect("the gate cleared it");

    fx.plane.release(&fx.vm);

    assert!(!fx.plane.input_is_open(&fx.vm));
    assert_eq!(InputGate::lease_holder(&fx.vm), None, "the lease goes back");
    assert_eq!(
        workload_output(child),
        b"before teardown",
        "teardown ends the stream rather than abandoning it"
    );
}

#[test]
fn a_writer_that_let_its_lease_lapse_does_not_wedge_the_stream_for_its_successor() {
    // The gate hands a lapsed lease to whoever asks next, so displacement is
    // reachable in normal operation. The guest, meanwhile, refuses anything
    // that does not advance past what it already delivered — so a successor
    // that started numbering afresh would be refused for its predecessor's
    // sequence and the workload's stdin would be wedged for good.
    let _guard = desk_test();
    let fx = Fixture::with_lease_ttl("input-displaced", LAPSING_LEASE_TTL);
    let mut child = cat();
    fx.plane
        .open_input(&fx.vm, &fx.admit(true), Box::new(ToDesk::over(&mut child)))
        .expect("the first writer takes the lease");
    fx.plane
        .write_input(&fx.vm, frame(0, b"first "))
        .expect("the gate cleared it");

    // The first writer goes quiet for longer than its lease.
    std::thread::sleep(PAST_THE_LEASE);
    assert_eq!(
        InputGate::lease_holder(&fx.vm),
        None,
        "the lease is there to be taken"
    );
    // Only the first writer's lease is meant to lapse. The successor has to
    // survive its write and its close, neither of which this test is timing.
    fx.rebind_lease(LIVE_LEASE_TTL);

    // The successor points at the same guest — the desk is already open over
    // this workload — and starts its own numbering at zero.
    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToDesk::to_the_open_desk()),
        )
        .expect("a lapsed lease is takeable");
    fx.plane
        .write_input(&fx.vm, frame(0, b"second"))
        .expect("the successor must not be refused for its predecessor's sequence");
    fx.plane.close_input(&fx.vm).expect("the lease is live");

    assert_eq!(
        workload_output(child),
        b"first second",
        "both writers' bytes, in the order they were accepted"
    );
}

#[test]
fn an_idle_writer_can_keep_its_stream_alive_without_sending_anything() {
    // The lease exists to free a stdin whose writer died, not to punish one
    // that is thinking. Without a way to hold it, a writer that paused past
    // the TTL would find its close refused too — and a refused close drops the
    // tail the gate withheld, which is the writer's last bytes.
    let fx = Fixture::with_lease_ttl("input-refresh", LAPSING_LEASE_TTL);
    let mut child = cat();
    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToWorkload::over(&mut child)),
        )
        .expect("the grant opens the route");
    fx.plane
        .write_input(&fx.vm, frame(0, b"thinking"))
        .expect("the gate cleared it");

    // Five pauses of this length outlast the TTL, so reaching the close proves
    // the refreshes held the lease. Each pause still has to leave the refresh
    // room to land inside the TTL, hence a pause well under it.
    const THINKING_FOR: std::time::Duration = std::time::Duration::from_millis(300);
    for _ in 0..5 {
        std::thread::sleep(THINKING_FOR);
        fx.plane
            .refresh_input(&fx.vm)
            .expect("an idle holder keeps its lease");
    }

    fx.plane
        .close_input(&fx.vm)
        .expect("a lease held through the pause still closes cleanly");
    assert_eq!(workload_output(child), b"thinking");
}

#[test]
fn a_delivery_whose_answer_was_lost_is_not_written_to_the_workload_twice() {
    // The transport call can fail *after* the guest already took the bytes.
    // Retrying under a fresh number would put them into the workload's stdin
    // a second time, and neither end's ordering check would ever see it — a
    // silent duplication in place of a silent loss.
    let _guard = desk_test();
    let fx = Fixture::new("input-retry", None);
    let mut child = cat();
    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToDesk::over(&mut child).losing_the_answer_to(0)),
        )
        .expect("the grant opens the route");

    assert!(
        matches!(
            fx.plane.write_input(&fx.vm, frame(0, b"once")),
            Err(InputRouteError::Transport(_))
        ),
        "a lost answer is reported, not swallowed"
    );
    fx.plane
        .write_input(&fx.vm, frame(1, b" only"))
        .expect("the retry and the new frame both go out");
    fx.plane.close_input(&fx.vm).expect("the lease is live");

    assert_eq!(
        workload_output(child),
        b"once only",
        "the re-offered frame is recognised as the one the guest already took"
    );
}

#[test]
fn concurrent_writers_never_interleave_a_frame_into_another_frames_bytes() {
    // Two threads through one VM's route. Whichever frames the gate accepts,
    // the guest must see each one whole and in strictly increasing delivery
    // order: an accept that did not deliver under the same lock would let one
    // thread's bytes land inside another's.
    let _guard = desk_test();
    let fx = Fixture::new("input-concurrent", None);
    let mut child = cat();
    fx.plane
        .open_input(&fx.vm, &fx.admit(true), Box::new(ToDesk::over(&mut child)))
        .expect("the grant opens the route");

    const PER_THREAD: u64 = 40;
    let next_seq = AtomicU64::new(0);
    let accepted = std::sync::Mutex::new(Vec::<Vec<u8>>::new());

    std::thread::scope(|scope| {
        for tag in ["a", "b"] {
            let (fx, next_seq, accepted) = (&fx, &next_seq, &accepted);
            scope.spawn(move || {
                for i in 0..PER_THREAD {
                    let payload = format!("<{tag}{i}>").into_bytes();
                    let seq = next_seq.fetch_add(1, Ordering::SeqCst);
                    // Accepting under one lock and delivering under another is
                    // what this races against; the gate refuses whichever
                    // frame arrives out of turn, which is fine.
                    if fx
                        .plane
                        .write_input(
                            &fx.vm,
                            InputFrame {
                                seq,
                                payload: payload.clone(),
                            },
                        )
                        .is_ok()
                    {
                        accepted
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(payload);
                    }
                }
            });
        }
    });
    fx.plane.close_input(&fx.vm).expect("the lease is live");

    let seen = String::from_utf8(workload_output(child)).expect("the payloads are ascii");
    let accepted = accepted
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        !accepted.is_empty(),
        "at least one writer has to get through for this to mean anything"
    );
    // Every accepted payload arrived whole. A frame cut in half by another
    // thread's delivery would leave its marker text broken.
    for payload in accepted.iter() {
        let text = std::str::from_utf8(payload).expect("ascii");
        assert!(
            seen.matches(text).count() == 1,
            "{text} must appear exactly once in {seen}"
        );
    }
    assert_eq!(
        seen.len(),
        accepted.iter().map(Vec::len).sum::<usize>(),
        "nothing arrived that was not accepted, and nothing accepted went missing"
    );
}

#[test]
fn a_second_writer_is_refused_while_the_first_holds_the_stream() {
    // One byte stream, one writer. Two consumers interleaving would produce
    // input neither of them sent.
    let fx = Fixture::new("input-contested", None);
    let mut first = cat();
    let mut second = cat();
    fx.plane
        .open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToWorkload::over(&mut first)),
        )
        .expect("the first writer takes the lease");

    assert!(matches!(
        fx.plane.open_input(
            &fx.vm,
            &fx.admit(true),
            Box::new(ToWorkload::over(&mut second))
        ),
        Err(InputRefusal::LeaseHeld { .. })
    ));

    fx.plane.release(&fx.vm);
    assert!(workload_output(first).is_empty());
    let _ = second.kill();
    let _ = second.wait();
}
