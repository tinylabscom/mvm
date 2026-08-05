//! The road between the gate and the guest: what carries bytes the
//! [`InputGate`] cleared to the workload that asked for them.
//!
//! The gate decides *whether* input may move and the guest's sink decides
//! *how* it reaches a child's stdin. Neither owns a transport, so until this
//! module existed an admitted frame had nowhere to go — a policy with no code
//! path behind it. What the route adds is exactly one thing, and it is the
//! thing that is easy to get silently wrong:
//!
//! - **Delivery order is acceptance order, and nothing may run in between.**
//!   The gate scans for secret material over the concatenation of what it
//!   accepted, in that order, and deliberately does not reassemble by `seq` —
//!   so a secret split across two frames is caught only if the guest receives
//!   them in the same order. [`InputRoute::write`] therefore accepts, drains
//!   and delivers one frame in a single `&mut self` call: there is no moment
//!   at which a second caller could accept a frame whose bytes overtake this
//!   one's. One route per VM, behind that VM's own lock in the plane, is what
//!   makes "one order" true across concurrent callers rather than merely
//!   intended — per VM rather than process-wide, so a wedged guest slows only
//!   its own writers.
//!
//!   A delivery the transport refuses is not dropped either. The gate has no
//!   un-accept — it scanned those bytes and advanced past their `seq`, so the
//!   writer cannot resend them — so the wire frame stays queued *verbatim* and
//!   is offered again, ahead of the next one. Same concatenation, same order,
//!   and the same wire number, which is what makes the retry safe (below).
//!
//! - **Delivery is exactly once, not at least once.** A transport call can
//!   fail after the guest already took the bytes: the answer is lost, not the
//!   frame. Retrying under a fresh number would write those bytes into the
//!   workload's stdin twice, and neither this end's ordering check nor the
//!   guest's would see it — a silent duplication traded for a silent loss.
//!   The retry therefore carries the frame's own identity, its wire `seq`, and
//!   the guest recognises a repeat of the number it last accepted as the
//!   re-offer it is, answering without enqueueing anything. Wire numbers are
//!   minted here, once per accepted frame, and never carry different bytes on
//!   a second showing, which is what makes the number an identity.
//!
//! - **The queue behind a wedged guest is bounded.** The guest caps what it
//!   will hold for a workload that stopped reading, and answers `QueueFull`
//!   rather than growing; this end mirrors that cap, refuses with
//!   [`InputRouteError::Backlogged`] *before* the gate sees the frame, and so
//!   costs a wedged workload a bounded amount of host memory rather than an
//!   unbounded one. Refusing ahead of the gate is what leaves the frame
//!   re-offerable: the gate never saw its `seq`, so the writer may try again.
//!
//! - **The withheld tail is handed over.** The gate holds back the tail of the
//!   stream that is still a live prefix of a known secret rather than shipping
//!   it and refusing afterwards, and releases it when closing proves it was
//!   only ever a prefix. [`InputRoute::close`] is what carries those bytes to
//!   the guest, ahead of EOF. Dropping them would lose the writer's last bytes
//!   with no error anywhere — the guest's own types force `deliver_tail`
//!   before `close`, but nothing forces this end to send a tail at all.
//!
//! Everything else the route does is pass-through, and that is deliberate: a
//! second place that decided whether bytes may move would be a second place to
//! get default-deny wrong. [`InputRoute::open`] is the only constructor and it
//! goes through [`InputGate::open`], so a route that exists is a route the
//! signed plan admitted.
//!
//! ## Why the wire numbers a frame travels under are not the writer's
//!
//! The gate's `seq` orders one *writer's* frames. [`WireSequence`] orders
//! everything one VM's stdin ever receives, and those stop being the same
//! sequence the moment a lease changes hands: a successor's first frame is
//! `seq` 0 in its own numbering, and the guest — which refuses anything that
//! does not advance past what it already delivered — would refuse it for its
//! predecessor's sequence. The counter is therefore per VM and outlives any
//! one route, so a handover is invisible to the guest while still being the
//! strictly increasing order the scan describes. One wire frame per accepted
//! caller frame either way, empty payloads included.
//!
//! ## Why one RPC per frame
//!
//! [`VsockInput`] opens a control connection, sends one frame, reads its
//! answer, and hangs up. That is not an oversight: the guest agent's
//! production control listener answers one operational request per connection,
//! and waiting for each answer before offering the next is what makes arrival
//! order at the guest the order the gate accepted. Pipelining would hand that
//! ordering to the transport, and the scan is defined over acceptance order.
//!
//! The guest never blocks on the workload, so "wait for the answer" costs a
//! round trip and never the workload's own read latency — a child that stopped
//! reading its stdin queues on the guest side and answers `QueueFull`, which
//! the writer can see, rather than parking the host.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use mvm_agentd::stream_input::MAX_PENDING_INPUT_BYTES;
use mvm_agentd::vsock::{StreamInputRefusal, StreamInputResult};
use mvm_contract::stream::input::{CloseInput, InputFrame};
use zeroize::Zeroize;

use crate::plan_admission::AdmittedPlan;
use crate::stream::input_gate::{InputGate, InputRefusal, InputSession};

/// How much cleared-but-undelivered input one route will hold before it starts
/// refusing.
///
/// The same number the guest holds for a workload that stopped reading, and
/// for the same reason: both bound how much input is kept alive on a wedged
/// workload's behalf, and a host mirror that grew without limit would make the
/// guest's cap pointless — the memory would simply pile up one hop earlier.
pub const MAX_UNDELIVERED_INPUT_BYTES: usize = MAX_PENDING_INPUT_BYTES;

/// The delivery-order counter for one VM's stdin.
///
/// Shared rather than owned by a route so it outlives any single writer — see
/// the module docs on why the wire numbers are not the writer's own.
#[derive(Clone, Default)]
pub struct WireSequence(Arc<AtomicU64>);

impl WireSequence {
    /// Mint the next delivery number.
    fn mint(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }

    /// The last number minted for this VM, or `None` before the first.
    fn last(&self) -> Option<u64> {
        self.0.load(Ordering::SeqCst).checked_sub(1)
    }
}

/// Where bytes the gate cleared actually go.
///
/// A trait because the production destination is a running microVM's agent and
/// a test's destination is a process it can look inside, and because the
/// route's ordering guarantee has to hold for both. Not a security seam: the
/// gate decides whether there are any bytes to carry, so the worst a wrong
/// implementation can do is fail to deliver them.
///
/// Both methods borrow rather than take ownership, so the route keeps the only
/// copy of the bytes and can zeroize it once the guest has them — and so it
/// can offer the very same frame again when a call fails without knowing
/// whether the guest took it.
pub trait InputTransport: Send {
    /// Carry one admitted frame to the workload.
    ///
    /// `frame.seq` is this VM's delivery number, not the writer's own, so the
    /// receiving end can check the order it was promised across a change of
    /// writer. A repeat of a number already delivered is a retry of that same
    /// frame and must not reach the workload twice.
    fn deliver(&mut self, frame: &InputFrame) -> Result<()>;

    /// Carry the withheld tail and the end of the stream.
    fn close(&mut self, close: &CloseInput) -> Result<()>;
}

/// How a write to a workload's stdin failed.
#[derive(Debug, thiserror::Error)]
pub enum InputRouteError {
    /// The gate refused. Nothing was delivered and the refusal is in the
    /// chain-signed audit log.
    #[error(transparent)]
    Refused(#[from] InputRefusal),
    /// No writer has an open input session for this workload.
    #[error("no input session is open for this workload")]
    NoSession,
    /// The route is already holding as much undelivered input as it will. The
    /// frame was never offered to the gate, so the writer may offer it again.
    #[error("the workload's input backlog is full ({queued} of {limit} bytes undelivered)")]
    Backlogged {
        /// Bytes already cleared and still waiting for the transport.
        queued: usize,
        /// The cap that stopped this frame.
        limit: usize,
    },
    /// The gate cleared the bytes; carrying them to the guest failed.
    #[error("the workload's input transport failed: {0:#}")]
    Transport(#[from] anyhow::Error),
}

/// Wire frames the transport has not taken yet, oldest first.
///
/// A type of its own for its `Drop`: these are bytes the gate cleared for a
/// workload, and a route that ends without delivering them should not leave
/// them on the host heap any more than [`InputSession`] leaves its own outbox
/// there.
#[derive(Default)]
struct Pending {
    frames: VecDeque<InputFrame>,
    bytes: usize,
}

impl Pending {
    /// Queue one wire frame — including an empty one, because the guest checks
    /// the sequence and a skipped number reads as a lost frame.
    fn push(&mut self, frame: InputFrame) {
        self.bytes = self.bytes.saturating_add(frame.payload.len());
        self.frames.push_back(frame);
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        for frame in &mut self.frames {
            frame.payload.zeroize();
        }
    }
}

/// What a displaced route could not hand over.
///
/// Returned rather than logged in here so the plane, which knows the VM this
/// happened on, is the one place that reports it.
pub struct DisplacedRoute {
    /// The lease holder that lost the stream.
    pub holder: String,
    /// Bytes the gate had cleared that now go nowhere.
    pub stranded_bytes: usize,
}

/// One admitted writer's road to a workload's stdin: the gate session that
/// clears bytes and the transport that carries them.
///
/// Not `Clone`. The gate leases a VM's stdin to one writer, and a second
/// handle onto the same session would put back the interleaving the lease
/// exists to prevent.
pub struct InputRoute {
    session: InputSession,
    transport: Box<dyn InputTransport>,
    pending: Pending,
    wire_seq: WireSequence,
}

impl InputRoute {
    /// Take the input lease on `vm` under `admitted`, point it at `transport`,
    /// and number its deliveries out of `wire_seq`.
    ///
    /// The only constructor, and it opens the gate first: a route that exists
    /// is one the signed plan admitted, the lease was free for, and the audit
    /// chain recorded. There is deliberately no way to build one that skips
    /// any of those.
    ///
    /// `wire_seq` belongs to the VM rather than to this route, so a route that
    /// succeeds a lapsed one carries on numbering where its predecessor
    /// stopped instead of restarting at a number the guest has already seen.
    pub fn open(
        vm: &str,
        admitted: &AdmittedPlan,
        transport: Box<dyn InputTransport>,
        wire_seq: WireSequence,
    ) -> Result<Self, InputRefusal> {
        Ok(Self {
            session: InputGate::open(vm, admitted)?,
            transport,
            pending: Pending::default(),
            wire_seq,
        })
    }

    /// The lease holder id the gate minted for this route's session.
    #[must_use]
    pub fn holder(&self) -> &str {
        self.session.holder()
    }

    /// Offer one frame, and deliver whatever it cleared.
    ///
    /// Accept, drain and deliver happen here and nowhere else, in that order,
    /// without yielding: that is what keeps the bytes the scan concatenated in
    /// one order from reaching the guest in another. One wire frame is minted
    /// per accepted caller frame — including one whose cleared payload is
    /// empty because the gate is still withholding a live secret prefix — so
    /// acceptance order, wire order and delivery order are one order.
    ///
    /// The backlog check comes first, ahead of the gate, so a refusal here
    /// leaves the frame re-offerable: the gate never saw its `seq`.
    pub fn write(&mut self, frame: InputFrame) -> Result<(), InputRouteError> {
        // Drain before measuring. The queue only ever moves when something
        // offers it to the transport, so a cap checked without a drain attempt
        // first would be a cap the route could never get back under: every
        // frame that might have emptied it would be refused for its fullness.
        // The outcome is not reported here — the flush at the end of this call
        // retries the very same frames and reports for both.
        let _ = flush_into(&mut *self.transport, &mut self.pending);
        self.reject_if_backlogged(frame.payload.len())?;
        self.session.write(frame)?;
        let cleared = self.session.take_admitted()?;
        self.pending.push(InputFrame {
            seq: self.wire_seq.mint(),
            payload: cleared,
        });
        flush_into(&mut *self.transport, &mut self.pending)
    }

    /// Extend the lease without writing, for a writer that is idle but alive.
    pub fn refresh(&mut self) -> Result<(), InputRouteError> {
        self.session.refresh().map_err(InputRouteError::Refused)
    }

    /// End the stream: hand the withheld tail to the guest, then EOF.
    ///
    /// A refusal from the gate here means the lease lapsed, and the tail goes
    /// nowhere — correct, because a stalled writer must not close a stdin its
    /// successor now owns.
    pub fn close(self) -> Result<(), InputRouteError> {
        let Self {
            session,
            mut transport,
            mut pending,
            wire_seq,
        } = self;
        let mut ending = session.close()?;
        let outcome = end_stream(&mut *transport, &mut pending, &wire_seq, &ending.trailing);
        ending.trailing.zeroize();
        outcome
    }

    /// Wind this route up because another writer took the VM's stdin.
    ///
    /// Deliberately not a [`close`](Self::close). The successor is about to
    /// write to the same stdin, so sending EOF here would end a stream that is
    /// not over and leave the successor writing into a closed pipe.
    ///
    /// Nothing is flushed, and that is not an oversight either. The gate has
    /// already taken this session's lease away, and every path that moves
    /// bytes out of a session is lease-gated precisely so a writer that
    /// stalled cannot deliver into a stdin somebody else now holds. The
    /// withheld tail is the sharper case: it is a live prefix of a known
    /// secret, and only *closing* proves it was only ever a prefix. Shipping
    /// it here would let the successor's first bytes complete it inside the
    /// guest, with neither writer's scanner having seen the whole of it.
    ///
    /// So those bytes are lost — zeroized on the way out — and the caller is
    /// told how many, because losing them in silence is the failure this
    /// returns a value to prevent.
    #[must_use]
    pub fn displace(self) -> DisplacedRoute {
        DisplacedRoute {
            holder: self.session.holder().to_string(),
            stranded_bytes: self
                .pending
                .bytes
                .saturating_add(self.session.stranded_len()),
        }
    }

    fn reject_if_backlogged(&self, incoming: usize) -> Result<(), InputRouteError> {
        let queued = self.pending.bytes;
        if queued.saturating_add(incoming) > MAX_UNDELIVERED_INPUT_BYTES {
            return Err(InputRouteError::Backlogged {
                queued,
                limit: MAX_UNDELIVERED_INPUT_BYTES,
            });
        }
        Ok(())
    }
}

/// Offer every queued wire frame, oldest first, stopping at the first one the
/// transport will not take.
///
/// A frame the transport refuses goes back on the front of the queue exactly
/// as it was — same number, same bytes — because the call may have failed
/// after the guest already took it, and only an unchanged re-offer lets the
/// guest recognise the retry instead of writing the bytes a second time.
fn flush_into(
    transport: &mut dyn InputTransport,
    pending: &mut Pending,
) -> Result<(), InputRouteError> {
    while let Some(mut frame) = pending.frames.pop_front() {
        if let Err(error) = transport.deliver(&frame) {
            pending.frames.push_front(frame);
            return Err(InputRouteError::Transport(error));
        }
        pending.bytes = pending.bytes.saturating_sub(frame.payload.len());
        // The guest has them now; the host copy has no further use.
        frame.payload.zeroize();
    }
    Ok(())
}

/// Hand over what is still queued, then the withheld tail and EOF.
fn end_stream(
    transport: &mut dyn InputTransport,
    pending: &mut Pending,
    wire_seq: &WireSequence,
    trailing: &[u8],
) -> Result<(), InputRouteError> {
    flush_into(transport, pending)?;
    let mut message = CloseInput {
        // EOF sits after the last number this VM's stdin actually saw, not
        // after the writer's own last frame: the two differ whenever a lease
        // changed hands, and the guest checks against what it received.
        after_seq: wire_seq.last(),
        trailing: trailing.to_vec(),
    };
    let sent = transport.close(&message);
    message.trailing.zeroize();
    sent.map_err(InputRouteError::Transport)
}

/// The production transport: the guest agent's vsock control channel, which is
/// the only channel a workload guest has. There is no NIC to reach it by and
/// this adds none.
pub struct VsockInput {
    vm: String,
}

impl VsockInput {
    /// Reach `vm`'s guest agent.
    #[must_use]
    pub fn new(vm: impl Into<String>) -> Self {
        Self { vm: vm.into() }
    }

    /// One request, one answer, one connection — see the module docs on why
    /// the route does not pipeline.
    fn call(
        &self,
        request: impl FnOnce(
            &mut std::os::unix::net::UnixStream,
        ) -> Result<StreamInputResult, mvm_agentd::vsock::RpcError>,
    ) -> Result<()> {
        let transport = mvm_runtime::vsock_transport::for_vm(&self.vm)
            .with_context(|| format!("pick a transport for the guest agent on {:?}", self.vm))?;
        let mut stream = transport
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .with_context(|| format!("connect to the guest agent on {:?}", self.vm))?;
        match request(&mut stream)? {
            StreamInputResult::Accepted { .. } | StreamInputResult::Closed => Ok(()),
            StreamInputResult::Refused { kind, message } => {
                bail!(
                    "the guest refused the input frame ({}): {message}",
                    refusal_word(kind)
                )
            }
        }
    }
}

impl InputTransport for VsockInput {
    fn deliver(&mut self, frame: &InputFrame) -> Result<()> {
        let frame = frame.clone();
        self.call(move |stream| mvm_agentd::vsock::send_stream_input(stream, frame))
    }

    fn close(&mut self, close: &CloseInput) -> Result<()> {
        let close = close.clone();
        self.call(move |stream| mvm_agentd::vsock::send_close_stream_input(stream, close))
    }
}

/// Wire-stable word for a guest-side refusal, so an operator greps for the
/// same token the guest named.
fn refusal_word(kind: StreamInputRefusal) -> &'static str {
    match kind {
        StreamInputRefusal::NoWorkload => "no-workload",
        StreamInputRefusal::OutOfOrder => "out-of-order",
        StreamInputRefusal::QueueFull => "queue-full",
        StreamInputRefusal::WorkloadGone => "workload-gone",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_contract::stream::input::INPUT_GRANT_SERVICE;
    use mvm_core::plan::sign_plan;
    use mvm_core::plan::test_support::PlanFixture;

    use super::*;
    use crate::stream::input_gate::{InputBinding, KnownSecret};

    /// What a transport was asked to carry, in the order it was asked.
    ///
    /// Recorded rather than delivered because the property under test is the
    /// order and content of the hand-over, which a real guest would then be
    /// obliged to honour — `mvm_agentd::stream_input`'s own tests cover the
    /// honouring.
    #[derive(Default)]
    struct Carried {
        frames: Vec<InputFrame>,
        closed: Option<CloseInput>,
    }

    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Carried>>);

    impl Recorder {
        fn carried(&self) -> std::sync::MutexGuard<'_, Carried> {
            self.0.lock().expect("no test panics under this lock")
        }

        /// The bytes the guest would have written to the workload's stdin,
        /// concatenated in delivery order — including the tail, if the stream
        /// was closed.
        fn stdin_bytes(&self) -> Vec<u8> {
            let carried = self.carried();
            let mut out: Vec<u8> = carried
                .frames
                .iter()
                .flat_map(|f| f.payload.clone())
                .collect();
            if let Some(close) = &carried.closed {
                out.extend_from_slice(&close.trailing);
            }
            out
        }

        fn seqs(&self) -> Vec<u64> {
            self.carried().frames.iter().map(|f| f.seq).collect()
        }
    }

    impl InputTransport for Recorder {
        fn deliver(&mut self, frame: &InputFrame) -> Result<()> {
            self.carried().frames.push(frame.clone());
            Ok(())
        }

        fn close(&mut self, close: &CloseInput) -> Result<()> {
            self.carried().closed = Some(close.clone());
            Ok(())
        }
    }

    /// A transport that cannot reach its guest. The gate has already cleared
    /// the bytes by the time this fires, so the route has to report it rather
    /// than pretend the write landed.
    struct Unreachable;

    impl InputTransport for Unreachable {
        fn deliver(&mut self, _frame: &InputFrame) -> Result<()> {
            bail!("the guest agent is not answering")
        }

        fn close(&mut self, _close: &CloseInput) -> Result<()> {
            bail!("the guest agent is not answering")
        }
    }

    /// A VM name no other test uses: the gate's lease table is process-wide.
    fn unique_vm(prefix: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
    }

    fn stream_service() -> ServiceId {
        ServiceId::parse(INPUT_GRANT_SERVICE).expect("the grant token is a valid service id")
    }

    fn admitted(services: Vec<ServiceId>) -> AdmittedPlan {
        let plan = PlanFixture::new().services(services).build();
        let signer_id = "host:test".to_string();
        let signed = sign_plan(&plan, &SigningKey::from_bytes(&[7u8; 32]), &signer_id);
        AdmittedPlan::for_test(plan, signer_id, signed)
    }

    fn frame(seq: u64, payload: &[u8]) -> InputFrame {
        InputFrame {
            seq,
            payload: payload.to_vec(),
        }
    }

    /// A route over a recording transport, on a VM bound to recognise
    /// `secret` when one is given.
    fn route_on(vm: &str, secret: Option<&str>) -> (InputRoute, Recorder) {
        let mut binding = InputBinding::new();
        if let Some(secret) = secret {
            binding = binding.with_secret(KnownSecret::host_material(secret.as_bytes()));
        }
        InputGate::bind(vm, binding);
        let recorder = Recorder::default();
        let route = InputRoute::open(
            vm,
            &admitted(vec![stream_service()]),
            Box::new(recorder.clone()),
            WireSequence::default(),
        )
        .expect("the plan grants input");
        (route, recorder)
    }

    #[test]
    fn a_granted_writers_bytes_reach_the_transport_and_the_stream_ends_with_an_eof() {
        let vm = unique_vm("route-grant");
        let (mut route, carried) = route_on(&vm, None);

        route.write(frame(0, b"ls ")).expect("the gate cleared it");
        route.write(frame(1, b"-la\n")).expect("and this one");
        route.close().expect("the lease is live");

        assert_eq!(carried.stdin_bytes(), b"ls -la\n");
        assert_eq!(
            carried.carried().closed.as_ref().map(|c| c.after_seq),
            Some(Some(1)),
            "the close names the last frame the gate accepted"
        );
    }

    #[test]
    fn an_ungranted_writer_gets_no_route_at_all() {
        // Default-deny is structural here: there is no route object to write
        // through, so there is no degraded mode to get wrong later.
        let vm = unique_vm("route-ungranted");
        InputGate::bind(&vm, InputBinding::new());
        assert!(matches!(
            InputRoute::open(
                &vm,
                &admitted(vec![]),
                Box::new(Recorder::default()),
                WireSequence::default()
            ),
            Err(InputRefusal::NotGranted)
        ));
        assert_eq!(InputGate::lease_holder(&vm), None);
    }

    #[test]
    fn delivery_order_is_acceptance_order_even_when_a_frame_clears_nothing() {
        // The guarantee this module exists for. The gate withholds
        // "AKIAIOSFODNN" as a live prefix, so frame 0 clears only "echo " —
        // and the wire still carries a frame at seq 0, so the sequence the
        // guest sees is the sequence the gate accepted, gaps and all.
        let vm = unique_vm("route-order");
        let (mut route, carried) = route_on(&vm, Some("AKIAIOSFODNN7EXAMPLE"));

        route
            .write(frame(0, b"echo AKIAIOSFODNN"))
            .expect("a prefix is not a match");
        route
            .write(frame(1, b"DEMO\n"))
            .expect("it was never a secret");

        assert_eq!(carried.seqs(), [0, 1], "one wire frame per accepted frame");
        assert_eq!(
            carried.carried().frames[0].payload,
            b"echo ",
            "the live prefix stays on the host until it is resolved"
        );
        assert_eq!(
            carried.stdin_bytes(),
            b"echo AKIAIOSFODNNDEMO\n",
            "and arrives, in order, once it resolves to nothing"
        );
    }

    #[test]
    fn a_secret_split_across_two_frames_never_reaches_the_transport() {
        // The other half of the same guarantee: refusing the second frame is
        // worthless if the first already handed the guest the first twelve
        // bytes. Nothing of the secret may be on the wire, in any order.
        let vm = unique_vm("route-split-secret");
        let (mut route, carried) = route_on(&vm, Some("AKIAIOSFODNN7EXAMPLE"));

        route
            .write(frame(0, b"AKIAIOSFODNN"))
            .expect("a prefix alone is not a match");
        assert!(matches!(
            route.write(frame(1, b"7EXAMPLE")),
            Err(InputRouteError::Refused(
                InputRefusal::SecretMaterial { .. }
            ))
        ));

        let delivered = carried.stdin_bytes();
        assert!(
            delivered.is_empty(),
            "no part of a split secret may cross the seam: {delivered:?}"
        );
    }

    #[test]
    fn closing_hands_the_withheld_tail_over_before_the_eof() {
        // The gate holds a live secret prefix back rather than shipping it and
        // refusing afterwards, and releases it at close because closing proves
        // it was only ever a prefix. A route that dropped it would lose the
        // writer's last bytes with no error anywhere.
        let vm = unique_vm("route-tail");
        let (mut route, carried) = route_on(&vm, Some("AKIAIOSFODNN7EXAMPLE"));

        route
            .write(frame(0, b"echo AKIAIOSFODNN"))
            .expect("a prefix is not a match");
        assert_eq!(
            carried.carried().frames[0].payload,
            b"echo ",
            "the tail is withheld while the stream is open"
        );

        route.close().expect("the lease is live");
        let closed = carried.carried().closed.clone().expect("the stream ended");
        assert_eq!(closed.trailing, b"AKIAIOSFODNN");
        assert_eq!(
            carried.stdin_bytes(),
            b"echo AKIAIOSFODNN",
            "the writer's own bytes, all of them, in the order they were sent"
        );
    }

    /// A transport that refuses the first `refusals` deliveries and takes
    /// everything after them.
    #[derive(Clone)]
    struct FlakyFor(Arc<Mutex<usize>>, Recorder);

    impl InputTransport for FlakyFor {
        fn deliver(&mut self, frame: &InputFrame) -> Result<()> {
            let mut left = self.0.lock().expect("no test panics under this lock");
            if *left > 0 {
                *left -= 1;
                bail!("the guest queue is full");
            }
            drop(left);
            self.1.deliver(frame)
        }

        fn close(&mut self, close: &CloseInput) -> Result<()> {
            self.1.close(close)
        }
    }

    #[test]
    fn bytes_a_failed_delivery_left_behind_go_out_in_front_of_the_next_frame() {
        // The gate has no un-accept: it scanned these bytes and advanced past
        // their `seq`, so the writer cannot resend them — offering the same
        // frame again is refused as out of order. Dropping them on a transport
        // failure would be a silent hole in the middle of the stream.
        let vm = unique_vm("route-retry");
        InputGate::bind(&vm, InputBinding::new());
        let carried = Recorder::default();
        let flaky = FlakyFor(Arc::new(Mutex::new(1)), carried.clone());
        let mut route = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(flaky),
            WireSequence::default(),
        )
        .expect("the plan grants input");

        assert!(matches!(
            route.write(frame(0, b"lost?")),
            Err(InputRouteError::Transport(_))
        ));
        route
            .write(frame(1, b" no"))
            .expect("the transport recovered");
        route.close().expect("the lease is live");

        assert_eq!(
            carried.stdin_bytes(),
            b"lost? no",
            "the undelivered bytes lead, in the order the gate cleared them"
        );
    }

    #[test]
    fn undelivered_bytes_still_ride_out_on_the_close() {
        let vm = unique_vm("route-retry-close");
        InputGate::bind(&vm, InputBinding::new());
        let carried = Recorder::default();
        let flaky = FlakyFor(Arc::new(Mutex::new(1)), carried.clone());
        let mut route = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(flaky),
            WireSequence::default(),
        )
        .expect("the plan grants input");

        assert!(route.write(frame(0, b"stranded")).is_err());
        route.close().expect("the lease is live");

        assert_eq!(
            carried.stdin_bytes(),
            b"stranded",
            "a writer that closes after a failed frame still loses nothing"
        );
    }

    #[test]
    fn a_transport_that_cannot_reach_the_guest_is_reported_not_swallowed() {
        let vm = unique_vm("route-unreachable");
        InputGate::bind(&vm, InputBinding::new());
        let mut route = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(Unreachable),
            WireSequence::default(),
        )
        .expect("the plan grants input");
        assert!(matches!(
            route.write(frame(0, b"hello")),
            Err(InputRouteError::Transport(_))
        ));
    }

    #[test]
    fn a_route_that_lost_its_lease_delivers_nothing_further() {
        let vm = unique_vm("route-lease");
        InputGate::bind(
            &vm,
            InputBinding::new().with_lease_ttl(std::time::Duration::from_millis(20)),
        );
        let carried = Recorder::default();
        let mut stalled = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(carried.clone()),
            WireSequence::default(),
        )
        .expect("the plan grants input");
        std::thread::sleep(std::time::Duration::from_millis(40));

        assert!(matches!(
            stalled.write(frame(0, b"too late")),
            Err(InputRouteError::Refused(InputRefusal::LeaseExpired))
        ));
        assert!(
            carried.carried().frames.is_empty(),
            "a lapsed writer must not deliver into a stdin its successor owns"
        );
        assert!(matches!(
            stalled.close(),
            Err(InputRouteError::Refused(InputRefusal::LeaseExpired))
        ));
        assert!(carried.carried().closed.is_none(), "nor close it");
    }

    #[test]
    fn a_route_holding_a_full_backlog_refuses_rather_than_growing() {
        // The guest caps what it will hold for a workload that stopped reading
        // and answers `QueueFull`. A host mirror with no cap would make that
        // pointless: the memory would pile up one hop earlier, on a host that
        // is serving every other VM too.
        let vm = unique_vm("route-backlog");
        InputGate::bind(&vm, InputBinding::new());
        let mut route = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(Unreachable),
            WireSequence::default(),
        )
        .expect("the plan grants input");

        let chunk = vec![b'x'; 64 * 1024];
        let mut refusal = None;
        for seq in 0..64 {
            match route.write(frame(seq, &chunk)) {
                Err(InputRouteError::Backlogged { queued, .. }) => {
                    refusal = Some(queued);
                    break;
                }
                // Every delivery fails; the bytes stay queued.
                Err(InputRouteError::Transport(_)) => {}
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        let queued = refusal.expect("an undeliverable backlog must stop growing at its budget");
        assert!(
            queued <= MAX_UNDELIVERED_INPUT_BYTES,
            "{queued} bytes is past the {MAX_UNDELIVERED_INPUT_BYTES} budget"
        );
    }

    #[test]
    fn a_backlog_refusal_leaves_the_frame_re_offerable() {
        // The refusal happens ahead of the gate, so the frame's `seq` was
        // never consumed. A writer that waited for the backlog to drain must
        // be able to offer the very same frame rather than having lost it.
        let vm = unique_vm("route-backlog-retry");
        InputGate::bind(&vm, InputBinding::new());
        let carried = Recorder::default();
        let stuck = Arc::new(Mutex::new(usize::MAX));
        let flaky = FlakyFor(Arc::clone(&stuck), carried.clone());
        let mut route = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(flaky),
            WireSequence::default(),
        )
        .expect("the plan grants input");

        let chunk = vec![b'x'; 256 * 1024];
        let mut refused_at = None;
        for seq in 0..64 {
            if let Err(InputRouteError::Backlogged { .. }) = route.write(frame(seq, &chunk)) {
                refused_at = Some(seq);
                break;
            }
        }
        let seq = refused_at.expect("the backlog fills");

        // The transport recovers and the backlog drains, so the frame the
        // backlog refused is welcome now.
        *stuck.lock().expect("no test panics under this lock") = 0;
        route
            .write(frame(seq, b"drained"))
            .expect("the refused frame was never consumed by the gate");
        assert!(
            carried.stdin_bytes().ends_with(b"drained"),
            "and it arrives behind everything that was already queued"
        );
    }

    #[test]
    fn a_displaced_route_reports_the_bytes_it_can_no_longer_deliver() {
        // A route whose lease lapsed cannot hand its bytes over: every
        // extraction path is lease-gated so a stalled writer cannot deliver
        // into a stdin its successor now owns, and the withheld tail is a live
        // secret prefix that only closing proves harmless. Those bytes are
        // therefore lost — and losing them in silence is the failure this
        // return value exists to prevent.
        let vm = unique_vm("route-displaced");
        InputGate::bind(
            &vm,
            InputBinding::new().with_secret(KnownSecret::host_material(b"AKIAIOSFODNN7EXAMPLE")),
        );
        let mut route = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(Unreachable),
            WireSequence::default(),
        )
        .expect("the plan grants input");
        let holder = route.holder().to_string();

        assert!(matches!(
            route.write(frame(0, b"echo AKIAIOSFODNN")),
            Err(InputRouteError::Transport(_))
        ));

        let displaced = route.displace();
        assert_eq!(displaced.holder, holder, "the report names who lost it");
        assert_eq!(
            displaced.stranded_bytes,
            b"echo ".len() + b"AKIAIOSFODNN".len(),
            "the undelivered frame and the withheld tail are both counted"
        );
    }

    #[test]
    fn a_successor_numbers_its_deliveries_where_its_predecessor_stopped() {
        // The guest refuses anything that does not advance past what it
        // already delivered, and it has no idea a lease changed hands. A
        // successor that restarted numbering would be refused for its
        // predecessor's sequence and the stdin would be wedged for good.
        let vm = unique_vm("route-resume");
        InputGate::bind(
            &vm,
            InputBinding::new().with_lease_ttl(std::time::Duration::from_millis(20)),
        );
        let wire_seq = WireSequence::default();
        let carried = Recorder::default();
        let mut first = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(carried.clone()),
            wire_seq.clone(),
        )
        .expect("the plan grants input");
        first
            .write(frame(0, b"first"))
            .expect("the gate cleared it");
        first.write(frame(1, b"more")).expect("and this one");
        std::thread::sleep(std::time::Duration::from_millis(40));
        let _ = first.displace();

        let mut second = InputRoute::open(
            &vm,
            &admitted(vec![stream_service()]),
            Box::new(carried.clone()),
            wire_seq,
        )
        .expect("a lapsed lease is takeable");
        // The successor's own numbering starts at zero, as any writer's does.
        second
            .write(frame(0, b"second"))
            .expect("the gate cleared it");
        second.close().expect("the lease is live");

        assert_eq!(
            carried.seqs(),
            [0, 1, 2],
            "one continuous delivery order across the handover"
        );
        assert_eq!(
            carried.carried().closed.as_ref().map(|c| c.after_seq),
            Some(Some(2)),
            "and EOF sits after the last number the guest actually saw"
        );
    }

    #[test]
    fn an_idle_writer_can_hold_its_lease_without_writing() {
        let vm = unique_vm("route-refresh");
        let (mut route, _carried) = route_on(&vm, None);
        route.refresh().expect("an idle holder keeps its lease");
        assert_eq!(
            InputGate::lease_holder(&vm).as_deref(),
            Some(route.holder())
        );
    }
}
