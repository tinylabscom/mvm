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
//!   writer cannot resend them — and they go out in front of the next frame's,
//!   which is the same concatenation in the same order the scan described.
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

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{StreamInputRefusal, StreamInputResult};
use mvm_protocol::stream::input::{CloseInput, InputFrame};

use crate::plan_admission::AdmittedPlan;
use crate::stream::input_gate::{InputGate, InputRefusal, InputSession};

/// Where bytes the gate cleared actually go.
///
/// A trait because the production destination is a running microVM's agent and
/// a test's destination is a process it can look inside, and because the
/// route's ordering guarantee has to hold for both. Not a security seam: the
/// gate decides whether there are any bytes to carry, so the worst a wrong
/// implementation can do is fail to deliver them.
pub trait InputTransport: Send {
    /// Carry one admitted frame to the workload.
    ///
    /// `frame.seq` is the sequence number the gate accepted, not one the
    /// transport minted, so the receiving end can check the order it was
    /// promised.
    fn deliver(&mut self, frame: InputFrame) -> Result<()>;

    /// Carry the withheld tail and the end of the stream.
    fn close(&mut self, close: CloseInput) -> Result<()>;
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
    /// The gate cleared the bytes; carrying them to the guest failed.
    #[error("the workload's input transport failed: {0:#}")]
    Transport(#[from] anyhow::Error),
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
    /// Bytes the gate cleared that the transport would not take.
    ///
    /// Held rather than dropped because the gate has no un-accept: it has
    /// already scanned these bytes and advanced past their `seq`, so a writer
    /// cannot resend them — offering the same frame again is refused as out of
    /// order. Losing them here would be a silent hole in the middle of a
    /// stream. They go out in front of the next frame's, which is the same
    /// concatenation in the same order the scan already described, so carrying
    /// them costs the ordering guarantee nothing.
    undelivered: Vec<u8>,
}

impl InputRoute {
    /// Take the input lease on `vm` under `admitted` and point it at
    /// `transport`.
    ///
    /// The only constructor, and it opens the gate first: a route that exists
    /// is one the signed plan admitted, the lease was free for, and the audit
    /// chain recorded. There is deliberately no way to build one that skips
    /// any of those.
    pub fn open(
        vm: &str,
        admitted: &AdmittedPlan,
        transport: Box<dyn InputTransport>,
    ) -> Result<Self, InputRefusal> {
        Ok(Self {
            session: InputGate::open(vm, admitted)?,
            transport,
            undelivered: Vec::new(),
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
    /// one order from reaching the guest in another. The wire frame carries
    /// the caller's own `seq`, so the guest sees the same sequence the gate
    /// accepted — including a frame whose cleared payload is empty because the
    /// gate is still withholding a live secret prefix.
    pub fn write(&mut self, frame: InputFrame) -> Result<(), InputRouteError> {
        let seq = frame.seq;
        self.session.write(frame)?;
        let cleared = self.session.take_admitted()?;
        self.undelivered.extend_from_slice(&cleared);
        let payload = std::mem::take(&mut self.undelivered);
        // Copied so a transport that refuses can hand the bytes back — see
        // `undelivered`. One small memcpy per frame buys "no byte the gate
        // cleared is dropped without an error".
        if let Err(error) = self.transport.deliver(InputFrame {
            seq,
            payload: payload.clone(),
        }) {
            self.undelivered = payload;
            return Err(InputRouteError::Transport(error));
        }
        Ok(())
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
            mut undelivered,
        } = self;
        let mut close = session.close()?;
        // Anything a failed delivery left behind is older than the tail and
        // goes back in front of it, so the last bytes on the wire are the last
        // bytes the writer sent.
        undelivered.extend_from_slice(&close.trailing);
        close.trailing = undelivered;
        transport.close(close)?;
        Ok(())
    }
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
    fn deliver(&mut self, frame: InputFrame) -> Result<()> {
        self.call(move |stream| mvm_agentd::vsock::send_stream_input(stream, frame))
    }

    fn close(&mut self, close: CloseInput) -> Result<()> {
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
    use mvm_core::plan::sign_plan;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_protocol::protocol::broker::ServiceId;
    use mvm_protocol::stream::input::INPUT_GRANT_SERVICE;

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
        fn deliver(&mut self, frame: InputFrame) -> Result<()> {
            self.carried().frames.push(frame);
            Ok(())
        }

        fn close(&mut self, close: CloseInput) -> Result<()> {
            self.carried().closed = Some(close);
            Ok(())
        }
    }

    /// A transport that cannot reach its guest. The gate has already cleared
    /// the bytes by the time this fires, so the route has to report it rather
    /// than pretend the write landed.
    struct Unreachable;

    impl InputTransport for Unreachable {
        fn deliver(&mut self, _frame: InputFrame) -> Result<()> {
            bail!("the guest agent is not answering")
        }

        fn close(&mut self, _close: CloseInput) -> Result<()> {
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
            InputRoute::open(&vm, &admitted(vec![]), Box::new(Recorder::default())),
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
        fn deliver(&mut self, frame: InputFrame) -> Result<()> {
            let mut left = self.0.lock().expect("no test panics under this lock");
            if *left > 0 {
                *left -= 1;
                bail!("the guest queue is full");
            }
            drop(left);
            self.1.deliver(frame)
        }

        fn close(&mut self, close: CloseInput) -> Result<()> {
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
        let mut route = InputRoute::open(&vm, &admitted(vec![stream_service()]), Box::new(flaky))
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
        let mut route = InputRoute::open(&vm, &admitted(vec![stream_service()]), Box::new(flaky))
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
