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
use mvm_agentd::stream_input::InputSink;
use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput};
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::emitter::{AuditEmitter, stream_audit};
use mvm_hostd::plan_admission::{AdmittedPlan, InMemoryNonceLedger, SystemClock, admit_for_run};
use mvm_hostd::stream::{
    CATEGORY_HOST_SECRET, InputAudit, InputBinding, InputGate, InputRefusal, InputRouteError,
    InputTransport, KnownSecret, StreamPlane,
};
use mvm_hostd::supervisor::verify_audit_chain;
use mvm_protocol::protocol::broker::ServiceId;
use mvm_protocol::stream::input::{CloseInput, INPUT_GRANT_SERVICE, InputFrame};

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
    fn deliver(&mut self, frame: InputFrame) -> Result<()> {
        let sink = self
            .sink
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("the workload's input stream is already closed"))?;
        sink.write_frame(frame)?;
        Ok(())
    }

    fn close(&mut self, close: CloseInput) -> Result<()> {
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

fn synthesis_input(vm_name: &str) -> SynthesisInput<'_> {
    const FIXTURE_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    SynthesisInput {
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
        exec_timeout_secs: 0,
        destroy_on_exit: true,
        bundle_pin: None,
        deps_volume: None,
        shares: Vec::new(),
        redaction: mvm_core::policy::RedactionPolicy::default(),
        reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
        audit_labels: Default::default(),
        agent_verbs: None,
        services: Vec::new(),
        stream_retention: Default::default(),
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
        let (env, home) = isolated_home();
        let vm = unique_vm(prefix);
        let chain_dir = tempfile::tempdir().expect("chain dir");
        let chain_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);

        let mut binding = InputBinding::new().with_audit(InputAudit::new(
            AuditEmitter::with_dir(chain_key.clone(), chain_dir.path()).expect("open the chain"),
        ));
        if let Some(secret) = secret {
            binding = binding.with_secret(KnownSecret::host_material(secret));
        }
        InputGate::bind(&vm, binding);

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
        seen, b"echo ",
        "only the bytes that were never part of the secret may arrive"
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
