//! The gate that decides whether anyone may write to a running workload's
//! stdin — and the only way bytes reach it.
//!
//! Output capture is always on and needs no authorization. Input is the
//! opposite in every respect, because it is the direction that changes what a
//! workload *does*. Until this module existed, a sealed production microVM had
//! no host→guest byte path at all, and "nobody can drive it" held by absence.
//! It now holds by policy, which is a strictly weaker guarantee — so four
//! properties carry the weight the absence used to:
//!
//! - **Default-deny.** [`InputGate::open`] refuses unless the plan carries the
//!   input grant, and it takes an [`AdmittedPlan`] rather than a bare
//!   `ExecutionPlan` — "signed" is the whole basis of the grant, so the
//!   parameter is the type only the admission pipeline mints. That is enforced
//!   rather than asserted: `AdmittedPlan`'s fields are private, so no caller
//!   outside admission can write the struct literal, and no accessor hands back
//!   a `&mut`, so a caller holding a real one cannot push the grant token into
//!   it afterwards. Not a warning and not a degraded mode: no session object
//!   exists, so there is nothing to write through. The grant check reads the
//!   same token the plan DTOs define, so a plan cannot mean one thing here and
//!   another to the admission path.
//! - **One writer at a time.** Two consumers interleaving into one byte stream
//!   produce garbage that neither of them sent, so concurrency is arbitrated
//!   rather than merged: a lease, held by exactly one session per VM. The
//!   lease expires, and the holder refreshes it by writing — a consumer that
//!   takes the lease and dies must not wedge the VM's stdin forever. Every
//!   path that moves bytes out of a session is gated on it, extraction
//!   included: a writer that stalled past its TTL must not deliver into a
//!   stdin its successor now owns.
//! - **The secret scan spans frame boundaries.** A scanner that inspects one
//!   frame at a time is defeated by splitting a secret across two writes, so
//!   [`SecretScanner`] carries a sliding window and, more than that, *withholds*
//!   the tail of the stream that is still a live prefix of a known secret. A
//!   refusal that arrives after the first half already reached the guest would
//!   be theatre. See [`SecretScanner`] for what this cannot catch; it is a
//!   backstop against a confused caller, not a defence against a determined
//!   one. The real guarantee is upstream: the host has no reason to send a
//!   secret into a guest, because secrets are substituted on egress instead.
//! - **Every refusal is audited, payload-free.** Each refusal, and each grant,
//!   emits a chain-signed entry naming the binding and the reason. Never the
//!   frame bytes, and never the matched secret — writing the secret into the
//!   log to explain why it was refused would ship it anyway, through the one
//!   file an operator is most likely to read. A decision the gate cannot
//!   record is a decision it declines to make: that refusal has its own
//!   [`InputRefusal::Unauditable`] reason, so "you were not granted" never
//!   stands in for "we could not record that you were".
//!
//! ## Ordering: one order, not three
//!
//! The scan runs over the concatenation of what the gate cleared, in arrival
//! order, so arrival order has to *be* delivery order — otherwise a secret
//! split across two frames and sent out of order would scan as non-contiguous
//! here and reassemble contiguously inside the guest, defeated by the very
//! `seq` field the frames carry. The gate closes that by refusing any frame
//! whose `seq` does not advance past the last one it accepted
//! ([`InputRefusal::OutOfOrder`]) rather than buffering and re-sorting, which
//! would mean holding bytes it has already decided about. Arrival order, `seq`
//! order and delivery order are therefore one order, and
//! [`InputSession::take_admitted`] states the delivery half as the caller's
//! contract.
//!
//! ## Ordering: close against an in-flight frame
//!
//! A close carries no `seq` of its own, so the wire alone cannot say whether
//! one overtook a frame still in flight. Rather than assume the transport is
//! ordered, the gate makes the question unaskable: a close is *defined* to sit
//! after the highest `seq` this session accepted, and [`InputSession::close`]
//! takes `self` by value, so no frame can be written through a session that has
//! closed. One leaseholder owns the session, and the lease is what makes "the
//! writer cannot race itself" true. [`CloseInput::after_seq`] hands the
//! boundary to the delivery side, which needs to know which frame EOF follows —
//! and it is the same type that travels the wire, so the two ends cannot hold
//! different opinions about where the stream ended.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use mvm_core::plan::ExecutionPlan;
use mvm_protocol::stream::input::{CloseInput, InputFrame, grants_input};
use zeroize::Zeroize;

use crate::audit::emitter::AuditEmitter;
use crate::plan_admission::AdmittedPlan;

/// How long a writer keeps the input lease without touching it.
///
/// Long enough that an interactive human pausing to think does not lose their
/// place; short enough that a consumer which crashed mid-session frees the
/// VM's stdin inside a coffee break rather than at VM teardown.
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(30);

/// Category recorded for a secret value the host itself holds for a workload.
pub const CATEGORY_HOST_SECRET: &str = "host-secret";

/// Why the gate would not let bytes through.
///
/// Every variant is a refusal — there is no partial admission and no
/// "delivered with a warning". A caller that gets one of these delivered
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InputRefusal {
    /// The admitted plan carries no input grant.
    #[error("no admitted input grant for this workload")]
    NotGranted,
    /// The decision could not be written to the chain-signed log.
    ///
    /// Distinct from [`Self::NotGranted`] because the two are different facts
    /// and an operator debugging one must not be handed the other: input into
    /// a sealed workload that leaves no signed trace is input the gate
    /// declines to have happened, which is not the same as a plan that never
    /// asked for it.
    #[error("the input decision could not be recorded in the audit chain")]
    Unauditable,
    /// Another writer holds the single-writer lease and has not let it lapse.
    #[error("another writer holds the input lease ({holder})")]
    LeaseHeld {
        /// The lease holder that was there first.
        holder: String,
    },
    /// The bytes carry material the host recognises as one of its own secrets.
    #[error("input carries recognised secret material ({category})")]
    SecretMaterial {
        /// Which category matched. The category, never the value.
        category: &'static str,
    },
    /// This session's lease lapsed. Refreshing it is the holder's job; once it
    /// is gone another writer may take it, so the session does not silently
    /// reacquire.
    #[error("the input lease expired")]
    LeaseExpired,
    /// A frame arrived at or before the highest `seq` this session already
    /// accepted. The gate refuses rather than reorders, because the secret
    /// scan runs in arrival order and a stream the caller may re-sort is a
    /// stream the scan does not describe.
    #[error("input frame seq {seq} does not advance past the accepted {after}")]
    OutOfOrder {
        /// The `seq` the refused frame carried.
        seq: u64,
        /// The highest `seq` this session had already accepted.
        after: u64,
    },
}

impl InputRefusal {
    /// Wire-stable reason word for the audit chain. Stable because an operator
    /// greps for it and a later reader groups by it.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotGranted => "not-granted",
            Self::Unauditable => "unauditable",
            Self::LeaseHeld { .. } => "lease-held",
            Self::SecretMaterial { .. } => "secret-material",
            Self::LeaseExpired => "lease-expired",
            Self::OutOfOrder { .. } => "out-of-order",
        }
    }
}

/// One secret value the gate should recognise on its way *into* a guest.
///
/// Held in the clear because recognising a byte sequence requires having it;
/// the type earns that by rendering as its category and length only, and by
/// zeroing itself on drop. There is deliberately no accessor for the bytes.
pub struct KnownSecret {
    value: Vec<u8>,
    category: &'static str,
}

impl KnownSecret {
    /// A secret the host holds on the workload's behalf.
    #[must_use]
    pub fn host_material(value: impl Into<Vec<u8>>) -> Self {
        Self::categorized(value, CATEGORY_HOST_SECRET)
    }

    /// The same, under a caller-chosen category name. `&'static str` because a
    /// category is a fixed vocabulary word that reaches the audit chain, not a
    /// value derived from the secret.
    #[must_use]
    pub fn categorized(value: impl Into<Vec<u8>>, category: &'static str) -> Self {
        Self {
            value: value.into(),
            category,
        }
    }
}

impl fmt::Debug for KnownSecret {
    /// Shape only. A derived `Debug` would put the secret in every log line
    /// that ever formats a binding.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnownSecret")
            .field("category", &self.category)
            .field("len", &self.value.len())
            .finish()
    }
}

impl Drop for KnownSecret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Keeps [`InputAuditSink`] closed to outside implementations.
///
/// Not a namespacing device: a sink is the *only* record that a writer reached
/// a sealed workload, so an implementation that returns `Ok(())` without
/// writing anything would leave the gate believing every decision was
/// chain-recorded while the chain stayed empty. That is a strictly worse
/// failure than an unreachable chain, which the gate refuses on. Sealing means
/// no crate outside this one can write that impl at all.
mod sealed {
    pub trait Sealed {}
}

/// Where the gate records what it decided.
///
/// A trait rather than the one concrete chain emitter because "the chain is
/// unreachable" is a state the gate has to behave correctly in — it is the
/// difference between refusing and silently admitting an unrecorded writer —
/// and the only honest way to exercise that is to hand the gate a sink that
/// fails. Both methods report failure so the gate, not the sink, decides what
/// an unrecordable decision means.
///
/// Sealed: [`InputAudit`] is the only implementation outside this module's
/// tests, so "somewhere other than the host chain" is not a place a caller can
/// send these decisions.
pub trait InputAuditSink: sealed::Sealed + Send + Sync {
    /// Record an admitted writer.
    fn record_granted(&self, plan: &ExecutionPlan, vm: &str, holder: &str) -> anyhow::Result<()>;
    /// Record a refusal and why.
    fn record_refused(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        refusal: &InputRefusal,
    ) -> anyhow::Result<()>;
}

/// Binds the gate's decisions for one VM to the chain-signed audit log — the
/// production [`InputAuditSink`].
///
/// Separate from the plan, which arrives per call: one VM's audit binding
/// outlives any single writer's session.
pub struct InputAudit {
    emitter: AuditEmitter,
}

impl InputAudit {
    /// Record this VM's input decisions through `emitter`.
    #[must_use]
    pub fn new(emitter: AuditEmitter) -> Self {
        Self { emitter }
    }
}

impl sealed::Sealed for InputAudit {}

impl InputAuditSink for InputAudit {
    fn record_granted(&self, plan: &ExecutionPlan, vm: &str, holder: &str) -> anyhow::Result<()> {
        self.emitter.emit_stream_input_granted(plan, vm, holder)
    }

    fn record_refused(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        refusal: &InputRefusal,
    ) -> anyhow::Result<()> {
        self.emitter.emit_stream_input_refused(plan, vm, refusal)
    }
}

/// Record a refusal, best effort.
///
/// Failing to write it does not soften the refusal — the bytes are already not
/// going anywhere — so this reports rather than propagates. The inverse of the
/// grant path, where an unrecordable decision *is* the refusal.
fn audit_refused(
    sink: &dyn InputAuditSink,
    plan: &ExecutionPlan,
    vm: &str,
    refusal: &InputRefusal,
) {
    if let Err(err) = sink.record_refused(plan, vm, refusal) {
        tracing::warn!(
            vm = %vm,
            reason = refusal.reason(),
            error = %err,
            "workload input refusal not recorded in the audit chain"
        );
    }
}

/// Everything the host installs for one VM before a writer may reach its
/// stdin.
///
/// Optional in the sense that an unbound VM still gets default-deny, a lease,
/// and the process audit chain — what a binding adds is the secret set to
/// recognise, a VM-specific chain, and a lease lifetime.
pub struct InputBinding {
    secrets: Vec<KnownSecret>,
    audit: Option<Arc<dyn InputAuditSink>>,
    lease_ttl: Duration,
}

impl InputBinding {
    /// An empty binding: no known secrets, the process audit chain, the
    /// default lease lifetime.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
            audit: None,
            lease_ttl: DEFAULT_LEASE_TTL,
        }
    }

    /// Recognise one more secret value on the way into this VM.
    #[must_use]
    pub fn with_secret(mut self, secret: KnownSecret) -> Self {
        self.secrets.push(secret);
        self
    }

    /// Send this VM's input decisions to a specific chain.
    ///
    /// [`InputAudit`] and nothing else: the parameter is the concrete chain
    /// binding rather than `Arc<dyn InputAuditSink>` so that "record these
    /// somewhere else" is not an option a production caller has. A sink that
    /// answers `Ok(())` without writing would satisfy the gate's every check
    /// and leave no trace that a writer ever reached the workload.
    #[must_use]
    pub fn with_audit(mut self, audit: InputAudit) -> Self {
        self.audit = Some(Arc::new(audit));
        self
    }

    /// Send this VM's input decisions to an arbitrary [`InputAuditSink`] —
    /// **tests only**, and compiled out of every production build.
    ///
    /// The gate has to behave correctly when the chain is unreachable, and the
    /// only honest way to reach that state in a test is to install a sink that
    /// fails. Leaving the same door open at runtime would let a caller install
    /// one that *succeeds* without writing, which is the failure this whole
    /// module is built to prevent.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_audit_sink(mut self, sink: Arc<dyn InputAuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// How long this VM's lease survives without a write.
    #[must_use]
    pub fn with_lease_ttl(mut self, lease_ttl: Duration) -> Self {
        self.lease_ttl = lease_ttl;
        self
    }
}

impl Default for InputBinding {
    fn default() -> Self {
        Self::new()
    }
}

/// A binding as the gate stores it: the secret set shared rather than copied
/// into every session that opens.
struct Bound {
    secrets: Arc<Vec<KnownSecret>>,
    audit: Option<Arc<dyn InputAuditSink>>,
    lease_ttl: Duration,
}

/// The single-writer claim on one VM's stdin.
struct Lease {
    holder: String,
    expires_at: Instant,
}

impl Lease {
    fn is_live(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

/// Process-wide gate state. One arbiter per host process is the point: two
/// tables would be two writers.
#[derive(Default)]
struct GateState {
    bindings: HashMap<String, Bound>,
    leases: HashMap<String, Lease>,
    next_holder: u64,
}

static GATE: OnceLock<Mutex<GateState>> = OnceLock::new();

/// The gate's state, recovered rather than propagated on poison: a panicking
/// writer must not take every other VM's stdin down with it, and every field
/// here is a plain map that a partial update cannot leave inconsistent.
fn gate() -> MutexGuard<'static, GateState> {
    GATE.get_or_init(|| Mutex::new(GateState::default()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// What one VM's binding supplies, resolved once per open.
struct Resolved {
    audit: Option<Arc<dyn InputAuditSink>>,
    secrets: Arc<Vec<KnownSecret>>,
    lease_ttl: Duration,
}

/// The gate: process-wide, and reached by name rather than by handle so there
/// is exactly one of it.
pub struct InputGate;

impl InputGate {
    /// Install what the gate needs to police `vm`'s stdin. Replaces any
    /// previous binding; call it before the workload is reachable.
    ///
    /// A session snapshots the secret set at [`open`](Self::open) and holds it
    /// for its lifetime, so re-binding does not change what a *live* session
    /// recognises — a secret registered mid-session is recognised by the next
    /// writer, not the current one. Deliberate: the alternative is a scanner
    /// whose window can change under a partially-scanned stream.
    pub fn bind(vm: &str, binding: InputBinding) {
        let bound = Bound {
            secrets: Arc::new(binding.secrets),
            audit: binding.audit,
            lease_ttl: binding.lease_ttl,
        };
        gate().bindings.insert(vm.to_string(), bound);
    }

    /// Drop `vm`'s binding and any lease on it — the teardown half of
    /// [`bind`](Self::bind). Leaving the binding behind would keep a dead VM's
    /// secrets resident.
    pub fn unbind(vm: &str) {
        let mut state = gate();
        state.bindings.remove(vm);
        state.leases.remove(vm);
    }

    /// Take the input lease on `vm` under the authority of `admitted`.
    ///
    /// The parameter is an [`AdmittedPlan`] — what the admission pipeline
    /// mints — and not a bare `ExecutionPlan`, because a grant that any
    /// in-process caller can forge is not a grant. An `ExecutionPlan` carrying
    /// the input token is a value anyone can synthesize; only admission
    /// produces the plan that has been signed, verified, window-checked and
    /// replay-checked, and `AdmittedPlan`'s private fields are what keep the
    /// two from being the same thing — there is no literal to write and no
    /// mutable accessor to reach through. Taking the proof-carrying type is
    /// what makes the signature enforce what the docs assert.
    ///
    /// Refuses unless the plan grants input, unless the lease is free (or
    /// lapsed), and unless the grant itself can be chain-recorded.
    pub fn open(vm: &str, admitted: &AdmittedPlan) -> Result<InputSession, InputRefusal> {
        let plan = admitted.plan();
        let resolved = resolve(vm);

        // No chain, no decision. Checked ahead of the lease so a VM whose
        // audit is unreachable cannot hold a would-be writer out even briefly.
        let Some(audit) = resolved.audit else {
            tracing::warn!(vm = %vm, "workload input refused: no chain to record the decision in");
            return Err(InputRefusal::Unauditable);
        };

        if !grants_input(plan) {
            audit_refused(audit.as_ref(), plan, vm, &InputRefusal::NotGranted);
            return Err(InputRefusal::NotGranted);
        }

        let holder = match claim_lease(vm, plan, resolved.lease_ttl) {
            Ok(holder) => holder,
            Err(refusal) => {
                audit_refused(audit.as_ref(), plan, vm, &refusal);
                return Err(refusal);
            }
        };

        // An unauditable admission is the exact hole this gate exists to
        // close, so it fails closed and gives the lease straight back. The
        // refusal is recorded on the way out: the emit that just failed may
        // have failed transiently, and a refusal nobody can see is the same
        // defect one layer down.
        if let Err(err) = audit.record_granted(plan, vm, &holder) {
            release_lease(vm, &holder);
            tracing::warn!(vm = %vm, error = %err, "workload input refused: grant not recorded");
            audit_refused(audit.as_ref(), plan, vm, &InputRefusal::Unauditable);
            return Err(InputRefusal::Unauditable);
        }

        Ok(InputSession {
            vm: vm.to_string(),
            plan: plan.clone(),
            holder,
            audit,
            lease_ttl: resolved.lease_ttl,
            scanner: SecretScanner::new(resolved.secrets),
            outbox: Vec::new(),
            highest_accepted_seq: None,
            refused: None,
        })
    }

    /// Who holds `vm`'s input lease right now, if anyone. Read-only view for a
    /// caller reporting on the VM.
    #[must_use]
    pub fn lease_holder(vm: &str) -> Option<String> {
        let now = Instant::now();
        gate()
            .leases
            .get(vm)
            .filter(|lease| lease.is_live(now))
            .map(|lease| lease.holder.clone())
    }
}

/// One leased writer's channel into a workload's stdin.
///
/// Not `Clone` and not shareable: the lease means one of these exists per VM,
/// and handing out copies would put back the interleaving it prevents.
pub struct InputSession {
    vm: String,
    plan: ExecutionPlan,
    holder: String,
    audit: Arc<dyn InputAuditSink>,
    lease_ttl: Duration,
    scanner: SecretScanner,
    outbox: Vec<u8>,
    highest_accepted_seq: Option<u64>,
    /// Set by the first refusal a write hit. A session that refused once stays
    /// refused: the alternative lets a caller keep probing the secret scanner
    /// one byte at a time.
    refused: Option<InputRefusal>,
}

impl InputSession {
    /// The lease holder id the gate minted for this session.
    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    /// Offer one frame. On `Ok` the bytes cleared for the guest are in the
    /// outbox; anything still a live prefix of a known secret is held back
    /// until the next frame or [`close`](Self::close) resolves it.
    ///
    /// Frames must arrive in strictly increasing `seq`; one that does not
    /// advance is refused with [`InputRefusal::OutOfOrder`] and contributes
    /// nothing to the scan. See [`take_admitted`](Self::take_admitted) for why
    /// the gate refuses instead of reordering.
    pub fn write(&mut self, frame: InputFrame) -> Result<(), InputRefusal> {
        self.check_live()?;
        if let Some(after) = self.highest_accepted_seq
            && frame.seq <= after
        {
            // Audited but not latched: a frame that never reached the scanner
            // leaves the session's view of the stream intact, so a writer that
            // sent one out of turn can carry on in order.
            let refusal = InputRefusal::OutOfOrder {
                seq: frame.seq,
                after,
            };
            audit_refused(self.audit.as_ref(), &self.plan, &self.vm, &refusal);
            return Err(refusal);
        }
        match self.scanner.admit(&frame.payload) {
            Ok(cleared) => {
                self.outbox.extend_from_slice(&cleared);
                self.highest_accepted_seq = Some(frame.seq);
                Ok(())
            }
            Err(category) => Err(self.latch(InputRefusal::SecretMaterial { category })),
        }
    }

    /// Take the bytes cleared for delivery so far, in the order the guest must
    /// receive them.
    ///
    /// **Contract: the caller writes these bytes to the workload's stdin in
    /// exactly this order and never re-sorts them by frame `seq`.** The secret
    /// scan runs over this concatenation, so scan order has to be delivery
    /// order — a consumer that buffered and re-sorted could reassemble, inside
    /// the guest, a secret that was non-contiguous here. The gate holds up its
    /// end by refusing any frame whose `seq` does not advance, so following
    /// arrival order and following `seq` order are the same thing and neither
    /// can drift from what was scanned.
    ///
    /// Gated on the lease, because draining is a byte-extraction path: a
    /// writer whose lease lapsed while it stalled must not deliver into a
    /// stdin its successor now owns.
    ///
    /// The gate clears bytes; it does not own the transport that carries them.
    /// The single leaseholder drains this and delivers, which is also what
    /// bounds the buffer — nothing accumulates here that its own owner did not
    /// choose to leave.
    pub fn take_admitted(&mut self) -> Result<Vec<u8>, InputRefusal> {
        self.check_live()?;
        Ok(std::mem::take(&mut self.outbox))
    }

    /// Extend the lease without writing, for a holder that is idle but alive.
    pub fn refresh(&mut self) -> Result<(), InputRefusal> {
        self.check_live()
    }

    /// How many bytes this session is holding that it can no longer hand over:
    /// what it cleared but nobody drained, plus the tail it withheld.
    ///
    /// A count, never the bytes — and deliberately not gated on the lease,
    /// because the one caller is a lapsed session's undertaker and a number is
    /// not an extraction path. It exists so losing those bytes at a change of
    /// writer can be reported rather than happening in silence.
    #[must_use]
    pub fn stranded_len(&self) -> usize {
        self.outbox
            .len()
            .saturating_add(self.scanner.withheld_len())
    }

    /// End the session: flush what was held back, release the lease, and fix
    /// where EOF sits in the sequence.
    ///
    /// The withheld tail ships here because it is, by construction, a proper
    /// prefix of a secret and not a secret — dropping it would silently
    /// swallow the caller's last bytes.
    ///
    /// Gated on the lease like every other extraction path, and for a sharper
    /// reason: `close` decides where EOF sits, so a stalled writer closing
    /// after its lease lapsed would close a stdin its successor is still
    /// using. Taking `self` by value keeps a closed session from being written
    /// to, but that is a compile-time guard and expiry is a runtime condition.
    /// A lost lease yields nothing at all, EOF included.
    pub fn close(mut self) -> Result<CloseInput, InputRefusal> {
        self.check_live()?;
        let mut trailing = std::mem::take(&mut self.outbox);
        trailing.extend_from_slice(&self.scanner.flush());
        release_lease(&self.vm, &self.holder);
        Ok(CloseInput {
            after_seq: self.highest_accepted_seq,
            trailing,
        })
    }

    /// The two runtime conditions every byte-moving call shares: a session
    /// that refused once stays refused, and a session that lost its lease no
    /// longer speaks for the VM.
    fn check_live(&mut self) -> Result<(), InputRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        self.renew_lease()
    }

    /// Re-take our own lease, or find out we lost it.
    fn renew_lease(&mut self) -> Result<(), InputRefusal> {
        let now = Instant::now();
        let renewed = {
            let mut state = gate();
            match state.leases.get_mut(&self.vm) {
                Some(lease) if lease.holder == self.holder && lease.is_live(now) => {
                    lease.expires_at = now + self.lease_ttl;
                    true
                }
                // Lapsed and reaped, or lapsed and taken by somebody else:
                // either way this writer no longer speaks for the VM.
                _ => false,
            }
        };
        if renewed {
            Ok(())
        } else {
            Err(self.latch(InputRefusal::LeaseExpired))
        }
    }

    /// Record the refusal once, latch it, and hand it back. Latched refusals
    /// are the terminal ones — the session cannot recover from them, and a
    /// caller that keeps probing learns nothing new.
    fn latch(&mut self, refusal: InputRefusal) -> InputRefusal {
        audit_refused(self.audit.as_ref(), &self.plan, &self.vm, &refusal);
        self.refused = Some(refusal.clone());
        refusal
    }
}

impl Drop for InputSession {
    /// A dropped session frees the VM's stdin immediately rather than at
    /// lease expiry. `close` already released it; releasing keys on the holder
    /// id, so this cannot take a lease a later writer acquired.
    ///
    /// Anything cleared but not drained is discarded here, which is the right
    /// outcome rather than data loss: a session that ended without
    /// [`close`](InputSession::close) has no owner left to deliver those bytes
    /// and no boundary to deliver them before, so shipping them would be an
    /// unattributed write into a stdin somebody else may now hold. They are
    /// zeroized rather than merely freed so cleared input does not linger on
    /// the heap; the withheld tail is zeroized by the scanner's own `Drop`.
    fn drop(&mut self) {
        self.outbox.zeroize();
        release_lease(&self.vm, &self.holder);
    }
}

/// Look up what `vm`'s binding supplies, falling back to the process defaults.
///
/// The lock is released before the audit fallback runs: opening the host chain
/// is filesystem work, and holding the one gate lock across it would stall
/// every other VM's writer behind this VM's disk.
fn resolve(vm: &str) -> Resolved {
    let (audit, secrets, lease_ttl) = {
        let state = gate();
        match state.bindings.get(vm) {
            Some(bound) => (
                bound.audit.clone(),
                Arc::clone(&bound.secrets),
                bound.lease_ttl,
            ),
            None => (None, Arc::new(Vec::new()), DEFAULT_LEASE_TTL),
        }
    };
    Resolved {
        audit: audit.or_else(process_audit),
        secrets,
        lease_ttl,
    }
}

/// Take the lease on `vm`, or say who has it.
fn claim_lease(vm: &str, plan: &ExecutionPlan, ttl: Duration) -> Result<String, InputRefusal> {
    let now = Instant::now();
    let mut state = gate();
    if let Some(lease) = state.leases.get(vm)
        && lease.is_live(now)
    {
        return Err(InputRefusal::LeaseHeld {
            holder: lease.holder.clone(),
        });
    }
    // Attributable to the admitting plan, and unique per process so a stale
    // session's `Drop` can never release a successor's lease.
    let holder = format!("{}#{}", plan.plan_id.0, state.next_holder);
    state.next_holder = state.next_holder.saturating_add(1);
    state.leases.insert(
        vm.to_string(),
        Lease {
            holder: holder.clone(),
            expires_at: now + ttl,
        },
    );
    Ok(holder)
}

/// Give back the lease, but only if it is still ours.
fn release_lease(vm: &str, holder: &str) {
    let mut state = gate();
    if state
        .leases
        .get(vm)
        .is_some_and(|lease| lease.holder == holder)
    {
        state.leases.remove(vm);
    }
}

/// The chain a decision lands in when the VM's binding names none.
///
/// `None` when the host chain cannot be opened at all; the gate then refuses
/// every decision on that VM, because an input path nobody can audit is the
/// thing this module exists to prevent.
fn process_audit() -> Option<Arc<dyn InputAuditSink>> {
    static PROCESS_AUDIT: OnceLock<Mutex<Option<Arc<InputAudit>>>> = OnceLock::new();
    let slot = PROCESS_AUDIT.get_or_init(|| Mutex::new(None));
    let sink: Arc<dyn InputAuditSink> = cached_audit(slot, build_process_audit)?;
    Some(sink)
}

/// Return the cached chain, building one on first use — and caching it **only
/// on success**.
///
/// A failure is deliberately not remembered. Caching it would let a single
/// transient error at process start disable workload input for the entire
/// lifetime of the host process: a blip promoted to a permanent, silent policy
/// change nobody asked for. Retrying costs one filesystem open on a path that
/// is already refusing.
fn cached_audit(
    slot: &Mutex<Option<Arc<InputAudit>>>,
    build: impl FnOnce() -> anyhow::Result<InputAudit>,
) -> Option<Arc<InputAudit>> {
    let mut cached = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(audit) = cached.as_ref() {
        return Some(Arc::clone(audit));
    }
    match build() {
        Ok(audit) => {
            let audit = Arc::new(audit);
            *cached = Some(Arc::clone(&audit));
            Some(audit)
        }
        Err(err) => {
            tracing::warn!(error = %err, "workload input decisions cannot be chain-recorded");
            None
        }
    }
}

#[cfg(not(test))]
fn build_process_audit() -> anyhow::Result<InputAudit> {
    let signer = crate::audit::host_keypair::load_or_init()?;
    Ok(InputAudit::new(AuditEmitter::new(signer.signing)?))
}

/// Under test the process chain is a scratch directory, for the same reason
/// the transcript tests use one: a unit test must not append to the operator's
/// real audit log, and the entries still have to be genuinely chain-signed for
/// an assertion about them to mean anything.
#[cfg(test)]
fn build_process_audit() -> anyhow::Result<InputAudit> {
    let key = ed25519_dalek::SigningKey::from_bytes(&tests::TEST_CHAIN_SEED);
    Ok(InputAudit::new(AuditEmitter::with_dir(
        key,
        tests::test_chain_dir(),
    )?))
}

/// Recognises known secret material in a byte stream that arrives in
/// arbitrarily chopped frames.
///
/// Two things make it work across frames. It scans the concatenation of the
/// carried tail and the new payload, so a secret split down the middle is
/// still a contiguous match; and it *withholds* the longest suffix of the
/// stream that is still a proper prefix of some known secret, so the first
/// half of a split secret never reaches the guest ahead of the refusal. A
/// suffix that is not a prefix of anything ships immediately, which is what
/// keeps ordinary interactive input from being delayed.
///
/// **What it cannot catch**, and this is not a gap that more rules would
/// close: any encoding of the secret (base64, hex, URL-escaping), any
/// derivation of it (a hash, a signature, a substring used as a lookup key),
/// and any secret the host never registered. It is a backstop against a
/// caller that pasted the wrong thing, not a defence against a caller that
/// wants the secret in there. The property that actually holds is upstream —
/// the host substitutes secrets on egress and so has no reason to send one
/// into a guest at all.
struct SecretScanner {
    secrets: Arc<Vec<KnownSecret>>,
    /// Length of the longest registered secret; the window is one byte short
    /// of it, because a full-length suffix would be a match, not a prefix.
    longest: usize,
    /// The withheld tail: a proper prefix of at least one known secret.
    pending: Vec<u8>,
}

impl SecretScanner {
    fn new(secrets: Arc<Vec<KnownSecret>>) -> Self {
        // A zero-length "secret" matches everywhere and means nothing, so it
        // is not allowed to set the window.
        let longest = secrets.iter().map(|s| s.value.len()).max().unwrap_or(0);
        Self {
            secrets,
            longest,
            pending: Vec::new(),
        }
    }

    /// Clear `payload` for delivery, or name the category it matched.
    fn admit(&mut self, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.longest == 0 {
            return Ok(payload.to_vec());
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(payload);

        if let Some(category) = self.first_match(&buf) {
            // The buffer straddles a secret; it is not going anywhere, and it
            // does not linger in this process either.
            buf.zeroize();
            return Err(category);
        }

        let hold = self.unresolved_tail(&buf);
        self.pending = buf.split_off(buf.len() - hold);
        Ok(buf)
    }

    /// Release the withheld tail. Safe by construction: it is a proper prefix
    /// of a secret, which is not a secret.
    fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    /// How much is being withheld. A length, not the bytes.
    fn withheld_len(&self) -> usize {
        self.pending.len()
    }

    /// The category of the first known secret contained in `buf`.
    fn first_match(&self, buf: &[u8]) -> Option<&'static str> {
        self.secrets
            .iter()
            .filter(|secret| !secret.value.is_empty() && secret.value.len() <= buf.len())
            .find(|secret| {
                buf.windows(secret.value.len())
                    .any(|window| window == secret.value.as_slice())
            })
            .map(|secret| secret.category)
    }

    /// How many trailing bytes of `buf` must be held back: the longest suffix
    /// that is still a proper prefix of some known secret, and zero when the
    /// stream ends in nothing interesting.
    fn unresolved_tail(&self, buf: &[u8]) -> usize {
        let ceiling = self.longest.saturating_sub(1).min(buf.len());
        (1..=ceiling)
            .rev()
            .find(|&k| {
                let tail = &buf[buf.len() - k..];
                self.secrets
                    .iter()
                    .any(|secret| secret.value.len() > k && secret.value.starts_with(tail))
            })
            .unwrap_or(0)
    }
}

impl Drop for SecretScanner {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput, sign_plan};
    use mvm_protocol::protocol::broker::ServiceId;
    use mvm_protocol::stream::input::INPUT_GRANT_SERVICE;
    use tempfile::TempDir;

    use super::*;
    use crate::audit::emitter::stream_audit;
    use crate::plan_admission::{InMemoryNonceLedger, SystemClock, admit_for_run};
    use crate::supervisor::verify_audit_chain;

    /// Fixed so a test can verify the scratch chain's signatures.
    pub(super) const TEST_CHAIN_SEED: [u8; 32] = [9u8; 32];

    /// The scratch chain every test in this module shares, created once per
    /// test process.
    pub(super) fn test_chain_dir() -> &'static Path {
        static DIR: OnceLock<TempDir> = OnceLock::new();
        DIR.get_or_init(|| tempfile::tempdir().expect("scratch audit chain"))
            .path()
    }

    /// A VM name no other test uses, so the process-wide lease table cannot
    /// couple two tests together.
    fn unique_vm(prefix: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
    }

    /// The plan token that authorizes the input plane.
    fn stream_service() -> ServiceId {
        ServiceId::parse(INPUT_GRANT_SERVICE).expect("the grant token is a valid service id")
    }

    /// An `AdmittedPlan` over a fixture plan binding `services`, signed the way
    /// admission signs.
    ///
    /// The gate takes the proof-carrying type, so every test has to produce
    /// one. `a_plan_from_the_real_admission_pipeline_opens_the_gate` drives
    /// `admit_for_run` end to end so this shortcut cannot drift from what
    /// admission actually mints — and the shortcut itself is
    /// `AdmittedPlan::for_test`, a `#[cfg(test)]` constructor that does not
    /// exist in a production build.
    fn admitted_with(services: Vec<ServiceId>) -> AdmittedPlan {
        admitted_from(PlanFixture::new().services(services).build())
    }

    /// The same, over a caller-built fixture plan.
    fn admitted_from(plan: ExecutionPlan) -> AdmittedPlan {
        let signer_id = "host:test".to_string();
        let signed = sign_plan(&plan, &SigningKey::from_bytes(&[7u8; 32]), &signer_id);
        AdmittedPlan::for_test(plan, signer_id, signed)
    }

    /// A synthesis input the real admission pipeline accepts, for the one test
    /// that goes through it.
    fn synthesis_input(vm_name: &str) -> SynthesisInput<'_> {
        const FIXTURE_SHA: &str =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
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

    /// A sink that cannot write. The chain being unreachable is a state the
    /// gate has to behave correctly in, and handing it one that fails is the
    /// only honest way to get there.
    struct BrokenSink;

    impl sealed::Sealed for BrokenSink {}

    impl InputAuditSink for BrokenSink {
        fn record_granted(&self, _: &ExecutionPlan, _: &str, _: &str) -> anyhow::Result<()> {
            anyhow::bail!("the chain is unreachable")
        }

        fn record_refused(
            &self,
            _: &ExecutionPlan,
            _: &str,
            _: &InputRefusal,
        ) -> anyhow::Result<()> {
            anyhow::bail!("the chain is unreachable")
        }
    }

    /// One entry of the scratch chain, flattened to what these tests assert on.
    struct ChainEntry {
        kind: String,
        labels: BTreeMap<String, String>,
    }

    /// Every entry the process chain holds about `vm`.
    fn read_chain(vm: &str) -> Vec<ChainEntry> {
        let path = test_chain_dir().join("local.jsonl");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        content
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|envelope| {
                let entry = envelope.get("entry")?;
                let labels: BTreeMap<String, String> =
                    serde_json::from_value(entry.get("labels")?.clone()).ok()?;
                if labels.get(stream_audit::LABEL_VM_NAME).map(String::as_str) != Some(vm) {
                    return None;
                }
                Some(ChainEntry {
                    kind: entry.get("event")?.as_str()?.to_string(),
                    labels,
                })
            })
            .collect()
    }

    /// A session on a VM bound to recognise exactly one secret.
    fn granted_session_with_known_secret(secret: &str) -> InputSession {
        let vm = unique_vm("vm-secret");
        InputGate::bind(
            &vm,
            InputBinding::new().with_secret(KnownSecret::host_material(secret.as_bytes())),
        );
        let plan = admitted_with(vec![stream_service()]);
        InputGate::open(&vm, &plan).expect("the plan grants input")
    }

    // --- the four required properties -------------------------------------

    #[test]
    fn input_is_refused_without_a_plan_grant() {
        let plan = admitted_with(vec![]); // no host.stream.v1
        assert!(matches!(
            InputGate::open("vm-a", &plan),
            Err(InputRefusal::NotGranted)
        ));
    }

    #[test]
    fn a_second_writer_is_refused_while_the_lease_is_held() {
        let plan = admitted_with(vec![stream_service()]);
        let _first = InputGate::open("vm-a", &plan).expect("first session");
        assert!(matches!(
            InputGate::open("vm-a", &plan),
            Err(InputRefusal::LeaseHeld { .. })
        ));
    }

    #[test]
    fn secret_material_split_across_frames_is_still_refused() {
        // A scanner that inspects one frame at a time is trivially evaded by
        // splitting; the gate must carry a sliding window across frames.
        let mut s = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        s.write(InputFrame {
            seq: 0,
            payload: b"AKIAIOSFODNN".to_vec(),
        })
        .expect("prefix alone is not a match");
        assert!(matches!(
            s.write(InputFrame {
                seq: 1,
                payload: b"7EXAMPLE".to_vec()
            }),
            Err(InputRefusal::SecretMaterial { .. })
        ));
    }

    #[test]
    fn every_refusal_is_audited() {
        let plan = admitted_with(vec![]);
        let _ = InputGate::open("vm-a", &plan);
        let entries = read_chain("vm-a");
        assert!(
            entries
                .iter()
                .any(|e| e.kind == stream_audit::INPUT_REFUSED_EVENT)
        );
    }

    // --- what the chain may and may not carry ------------------------------

    /// The refusal entry names the binding and the reason, and nothing else —
    /// least of all the material it refused.
    ///
    /// The exhaustive key-set assertion is the part that matters: a substring
    /// check only refutes the leak a test thought of, while pinning the whole
    /// label set means a future label carrying frame bytes fails here whatever
    /// it is named.
    ///
    /// The plan carries an audit label of its own, because `AuditEntry` merges
    /// `plan.audit_labels` into every entry: against a plan with none, the key
    /// set would be the gate's labels alone and the assertion would prove less
    /// than it claims on any production plan.
    #[test]
    fn stream_input_audit_records_the_reason_and_none_of_the_refused_bytes() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let vm = unique_vm("vm-audit");
        InputGate::bind(
            &vm,
            InputBinding::new().with_secret(KnownSecret::host_material(secret.as_bytes())),
        );
        let plan = admitted_from(
            PlanFixture::new()
                .services(vec![stream_service()])
                .audit_labels(BTreeMap::from([(
                    "workload_owner".to_string(),
                    "team-a".to_string(),
                )]))
                .build(),
        );
        let mut session = InputGate::open(&vm, &plan).expect("the plan grants input");
        session
            .write(InputFrame {
                seq: 0,
                payload: secret.as_bytes().to_vec(),
            })
            .expect_err("the whole secret in one frame is refused");

        let entries = read_chain(&vm);
        let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                stream_audit::INPUT_GRANTED_EVENT,
                stream_audit::INPUT_REFUSED_EVENT
            ],
            "the admission and the refusal are both signed facts"
        );

        let refusal = entries.last().expect("the refusal entry");
        assert_eq!(
            refusal
                .labels
                .get(stream_audit::LABEL_REASON)
                .map(String::as_str),
            Some("secret-material")
        );
        assert_eq!(
            refusal
                .labels
                .get(stream_audit::LABEL_SECRET_CATEGORY)
                .map(String::as_str),
            Some(CATEGORY_HOST_SECRET)
        );
        let keys: Vec<&str> = refusal.labels.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                stream_audit::LABEL_REASON,
                stream_audit::LABEL_SECRET_CATEGORY,
                stream_audit::LABEL_VM_NAME,
                "workload_owner",
            ],
            "a refusal carries the binding, the reason, the plan's own labels, \
             and nothing else"
        );

        let path = test_chain_dir().join("local.jsonl");
        let raw = std::fs::read_to_string(&path).expect("the chain");
        assert!(
            !raw.contains(secret),
            "the refused secret must not appear in the log that explains the refusal"
        );
        assert!(!raw.contains("AKIAIOSFODNN"), "nor any part of it");
        verify_audit_chain(
            &path,
            &SigningKey::from_bytes(&TEST_CHAIN_SEED).verifying_key(),
        )
        .expect("the refusal is chain-signed like any other entry");
    }

    // --- the grant --------------------------------------------------------

    #[test]
    fn a_granting_plan_opens_a_session_and_a_lease() {
        let vm = unique_vm("vm-grant");
        let plan = admitted_with(vec![stream_service()]);
        let session = InputGate::open(&vm, &plan).expect("the plan grants input");
        assert_eq!(
            InputGate::lease_holder(&vm).as_deref(),
            Some(session.holder())
        );
        assert!(
            session.holder().starts_with(&plan.plan_id().0),
            "the holder names the plan that admitted it: {}",
            session.holder()
        );
    }

    #[test]
    fn an_unrelated_service_binding_does_not_grant_input() {
        let vm = unique_vm("vm-other-service");
        let other = ServiceId::parse("host.audit.v1").expect("valid service id");
        let plan = admitted_with(vec![other]);
        assert!(matches!(
            InputGate::open(&vm, &plan),
            Err(InputRefusal::NotGranted)
        ));
        assert_eq!(InputGate::lease_holder(&vm), None);
    }

    // --- the lease --------------------------------------------------------

    #[test]
    fn a_released_lease_lets_the_next_writer_in() {
        let vm = unique_vm("vm-lease-release");
        let plan = admitted_with(vec![stream_service()]);
        let first = InputGate::open(&vm, &plan).expect("first session");
        let held = first.holder().to_string();
        let closed = first.close().expect("the lease was live");
        assert!(closed.trailing.is_empty(), "nothing was written");
        assert_eq!(InputGate::lease_holder(&vm), None);

        let second = InputGate::open(&vm, &plan).expect("the lease was free");
        assert_ne!(second.holder(), held, "a fresh session is a fresh holder");
    }

    #[test]
    fn a_dropped_session_frees_the_lease() {
        let vm = unique_vm("vm-lease-drop");
        let plan = admitted_with(vec![stream_service()]);
        drop(InputGate::open(&vm, &plan).expect("first session"));
        assert_eq!(InputGate::lease_holder(&vm), None);
        InputGate::open(&vm, &plan).expect("a crashed writer must not wedge stdin");
    }

    #[test]
    fn a_holder_that_stops_refreshing_loses_the_lease() {
        // The reason the lease has an expiry at all: a consumer that took it
        // and died must not hold a VM's stdin until teardown.
        let vm = unique_vm("vm-lease-expiry");
        InputGate::bind(
            &vm,
            InputBinding::new().with_lease_ttl(Duration::from_millis(20)),
        );
        let plan = admitted_with(vec![stream_service()]);
        let mut stale = InputGate::open(&vm, &plan).expect("first session");
        std::thread::sleep(Duration::from_millis(40));

        assert_eq!(InputGate::lease_holder(&vm), None, "the lease lapsed");
        let mut fresh = InputGate::open(&vm, &plan).expect("a lapsed lease is takeable");
        assert!(matches!(
            stale.write(InputFrame {
                seq: 0,
                payload: b"too late".to_vec()
            }),
            Err(InputRefusal::LeaseExpired)
        ));
        fresh
            .write(InputFrame {
                seq: 0,
                payload: b"mine now".to_vec(),
            })
            .expect("the new holder writes");
        assert_eq!(
            fresh.take_admitted().expect("its lease is live"),
            b"mine now"
        );
    }

    #[test]
    fn a_write_refreshes_the_lease() {
        let vm = unique_vm("vm-lease-refresh");
        InputGate::bind(
            &vm,
            InputBinding::new().with_lease_ttl(Duration::from_millis(60)),
        );
        let plan = admitted_with(vec![stream_service()]);
        let mut session = InputGate::open(&vm, &plan).expect("first session");
        for seq in 0..4u64 {
            std::thread::sleep(Duration::from_millis(20));
            session
                .write(InputFrame {
                    seq,
                    payload: b".".to_vec(),
                })
                .expect("an active writer keeps its lease");
        }
        session.refresh().expect("an idle writer can hold it too");
    }

    #[test]
    fn a_writer_that_lost_the_lease_cannot_deliver_into_its_successors_stdin() {
        // The interleaving the lease exists to prevent, driven end to end: A
        // clears bytes, stalls past the TTL, B takes over — and A's owner then
        // tries to deliver. `close(self)` stops A writing *through* a closed
        // session at compile time, but expiry is a runtime condition, so both
        // of A's byte-extraction paths have to check it too.
        let vm = unique_vm("vm-interleave");
        InputGate::bind(
            &vm,
            InputBinding::new().with_lease_ttl(Duration::from_millis(20)),
        );
        let plan = admitted_with(vec![stream_service()]);
        let mut stalled = InputGate::open(&vm, &plan).expect("first session");
        stalled
            .write(InputFrame {
                seq: 0,
                payload: b"rm -rf /\n".to_vec(),
            })
            .expect("cleared while the lease was live");

        std::thread::sleep(Duration::from_millis(40));
        let mut successor = InputGate::open(&vm, &plan).expect("a lapsed lease is takeable");
        successor
            .write(InputFrame {
                seq: 0,
                payload: b"ls\n".to_vec(),
            })
            .expect("the new holder writes");

        assert!(
            matches!(stalled.take_admitted(), Err(InputRefusal::LeaseExpired)),
            "draining is a byte-extraction path and must be gated on the lease"
        );
        assert!(
            matches!(stalled.close(), Err(InputRefusal::LeaseExpired)),
            "so is close, which would otherwise close a stdin it no longer owns"
        );
        assert_eq!(
            successor.take_admitted().expect("its lease is live"),
            b"ls\n",
            "only the leaseholder's bytes reach the stream"
        );
    }

    // --- the secret scan ---------------------------------------------------

    #[test]
    fn a_live_secret_prefix_is_withheld_rather_than_delivered_early() {
        // The half of the split-secret defence that a refusal alone does not
        // give you: refusing the second frame is worthless if the first frame
        // already handed the guest the first twelve bytes.
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"echo AKIAIOSFODNN".to_vec(),
            })
            .expect("a prefix is not a match");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"echo ",
            "the live prefix stays on the host until it is resolved"
        );
    }

    #[test]
    fn a_tail_that_resolves_to_nothing_ships_on_the_next_frame() {
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"AKIA".to_vec(),
            })
            .expect("a prefix is not a match");
        assert!(
            session
                .take_admitted()
                .expect("the lease is live")
                .is_empty()
        );
        session
            .write(InputFrame {
                seq: 1,
                payload: b"DEMO\n".to_vec(),
            })
            .expect("it was never a secret");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"AKIADEMO\n"
        );
    }

    #[test]
    fn ordinary_input_is_not_delayed_by_the_scanner() {
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"ls -la\n".to_vec(),
            })
            .expect("nothing to match");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"ls -la\n",
            "a suffix that is not a prefix of any secret ships immediately"
        );
    }

    #[test]
    fn a_session_that_refused_once_stays_refused() {
        // Otherwise a caller walks the scanner one byte at a time and learns
        // the secret from which byte flips the answer.
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            })
            .expect_err("the whole secret is refused");
        assert!(matches!(
            session.write(InputFrame {
                seq: 1,
                payload: b"harmless".to_vec()
            }),
            Err(InputRefusal::SecretMaterial { .. })
        ));
    }

    #[test]
    fn a_secret_split_three_ways_is_still_refused() {
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        for (seq, chunk) in [b"AKIAIOS".as_slice(), b"FODNN7EX".as_slice()]
            .into_iter()
            .enumerate()
        {
            session
                .write(InputFrame {
                    seq: u64::try_from(seq).expect("fits"),
                    payload: chunk.to_vec(),
                })
                .expect("no complete secret yet");
        }
        assert!(matches!(
            session.write(InputFrame {
                seq: 2,
                payload: b"AMPLE".to_vec()
            }),
            Err(InputRefusal::SecretMaterial { .. })
        ));
    }

    #[test]
    fn a_secret_split_one_byte_at_a_time_is_still_refused() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let mut session = granted_session_with_known_secret(secret);
        let mut refused = None;
        for (seq, byte) in secret.bytes().enumerate() {
            let seq = u64::try_from(seq).expect("fits");
            if let Err(err) = session.write(InputFrame {
                seq,
                payload: vec![byte],
            }) {
                refused = Some(err);
                break;
            }
        }
        assert!(
            matches!(refused, Some(InputRefusal::SecretMaterial { .. })),
            "one byte per frame must not evade the window: {refused:?}"
        );
    }

    #[test]
    fn a_vm_with_no_registered_secrets_delivers_verbatim() {
        let vm = unique_vm("vm-no-secrets");
        let plan = admitted_with(vec![stream_service()]);
        let mut session = InputGate::open(&vm, &plan).expect("the plan grants input");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            })
            .expect("the gate recognises only what it was told about");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[test]
    fn a_known_secret_never_renders_its_value() {
        let rendered = format!("{:?}", KnownSecret::host_material(b"AKIAIOSFODNN7EXAMPLE"));
        assert!(!rendered.contains("AKIA"), "got {rendered}");
        assert!(rendered.contains(CATEGORY_HOST_SECRET), "got {rendered}");
    }

    // --- close ordering ----------------------------------------------------

    #[test]
    fn close_is_ordered_after_the_highest_accepted_seq() {
        let vm = unique_vm("vm-close");
        let plan = admitted_with(vec![stream_service()]);
        let mut session = InputGate::open(&vm, &plan).expect("the plan grants input");
        for seq in 0..3u64 {
            session
                .write(InputFrame {
                    seq,
                    payload: b"x".to_vec(),
                })
                .expect("accepted");
        }
        let closed = session.close().expect("the lease is live");
        assert_eq!(closed.after_seq, Some(2));
        assert_eq!(closed.trailing, b"xxx");
        assert_eq!(InputGate::lease_holder(&vm), None);
    }

    #[test]
    fn closing_a_session_that_wrote_nothing_has_no_boundary() {
        let vm = unique_vm("vm-close-empty");
        let plan = admitted_with(vec![stream_service()]);
        let closed = InputGate::open(&vm, &plan)
            .expect("the plan grants input")
            .close()
            .expect("the lease is live");
        assert_eq!(closed.after_seq, None);
        assert!(closed.trailing.is_empty());
    }

    #[test]
    fn close_flushes_the_withheld_tail() {
        // A prefix of a secret is not a secret; swallowing the caller's last
        // bytes at EOF would be silent data loss, not a defence.
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        session
            .write(InputFrame {
                seq: 7,
                payload: b"AKIA".to_vec(),
            })
            .expect("a prefix is not a match");
        let closed = session.close().expect("the lease is live");
        assert_eq!(closed.after_seq, Some(7));
        assert_eq!(closed.trailing, b"AKIA");
    }

    // --- binding lifecycle -------------------------------------------------

    #[test]
    fn unbinding_drops_the_lease_with_the_binding() {
        let vm = unique_vm("vm-unbind");
        InputGate::bind(&vm, InputBinding::new());
        let plan = admitted_with(vec![stream_service()]);
        let _session = InputGate::open(&vm, &plan).expect("the plan grants input");
        InputGate::unbind(&vm);
        assert_eq!(InputGate::lease_holder(&vm), None);
    }

    // --- ordering ----------------------------------------------------------

    #[test]
    fn a_frame_that_does_not_advance_the_sequence_is_refused_rather_than_reordered() {
        // Scan order is delivery order. If the gate accepted a frame that went
        // backwards, a secret split in two and sent out of order would scan as
        // non-contiguous here and reassemble contiguously inside the guest —
        // the scan defeated by the very `seq` field the frames carry.
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        session
            .write(InputFrame {
                seq: 1,
                payload: b"7EXAMPLE".to_vec(),
            })
            .expect("the first frame sets the boundary wherever it starts");
        assert!(
            matches!(
                session.write(InputFrame {
                    seq: 0,
                    payload: b"AKIAIOSFODNN".to_vec()
                }),
                Err(InputRefusal::OutOfOrder { seq: 0, after: 1 })
            ),
            "the other half of the secret must not be admitted behind the first"
        );
        assert!(
            matches!(
                session.write(InputFrame {
                    seq: 1,
                    payload: b"again".to_vec()
                }),
                Err(InputRefusal::OutOfOrder { seq: 1, after: 1 })
            ),
            "a repeat is not an advance"
        );
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"7EXAMPLE",
            "the reordered half never entered the stream"
        );
    }

    #[test]
    fn an_out_of_order_refusal_is_audited_and_leaves_the_session_usable() {
        let vm = unique_vm("vm-order-audit");
        let plan = admitted_with(vec![stream_service()]);
        let mut session = InputGate::open(&vm, &plan).expect("the plan grants input");
        for (seq, payload) in [(4u64, "a"), (2, "b"), (5, "c")] {
            let _ = session.write(InputFrame {
                seq,
                payload: payload.as_bytes().to_vec(),
            });
        }
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"ac",
            "the frame that went backwards contributed nothing, the next one did"
        );

        let refusals: Vec<ChainEntry> = read_chain(&vm)
            .into_iter()
            .filter(|e| e.kind == stream_audit::INPUT_REFUSED_EVENT)
            .collect();
        assert_eq!(refusals.len(), 1, "one refusal, one entry");
        assert_eq!(
            refusals[0]
                .labels
                .get(stream_audit::LABEL_REASON)
                .map(String::as_str),
            Some("out-of-order")
        );
        assert_eq!(
            refusals[0]
                .labels
                .get(stream_audit::LABEL_SEQ)
                .map(String::as_str),
            Some("2"),
            "a position, never a payload"
        );
    }

    // --- the plan the gate will accept -------------------------------------

    #[test]
    fn a_plan_from_the_real_admission_pipeline_opens_the_gate() {
        // The gate takes admission's own output, so a synthesized plan with
        // the grant token pasted into `services` is not a key that fits — it
        // is the wrong type. Driving `admit_for_run` here keeps the fixture
        // shortcut the other tests use from drifting away from what admission
        // actually mints, and shows default-deny surviving the real path.
        let keys = tempfile::tempdir().expect("scratch keys dir");
        let vm = unique_vm("vm-real-admission");

        let ungranted = admit_for_run(
            &synthesis_input(&vm),
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
        )
        .expect("the fixture input admits");
        assert!(matches!(
            InputGate::open(&vm, &ungranted),
            Err(InputRefusal::NotGranted)
        ));

        let mut granting = synthesis_input(&vm);
        granting.services = vec![stream_service()];
        let admitted = admit_for_run(
            &granting,
            &SystemClock,
            &InMemoryNonceLedger::new(),
            Some(keys.path()),
            None,
        )
        .expect("the granting input admits");
        let session =
            InputGate::open(&vm, &admitted).expect("an admitted plan carrying the grant opens");
        assert_eq!(
            InputGate::lease_holder(&vm).as_deref(),
            Some(session.holder())
        );
    }

    // --- the unauditable path ----------------------------------------------

    #[test]
    fn a_grant_that_cannot_be_recorded_is_refused_as_unauditable() {
        // Not `NotGranted`: an operator debugging this must not be told "you
        // were not granted" when the truth is "we could not record that you
        // were".
        let vm = unique_vm("vm-unauditable");
        InputGate::bind(
            &vm,
            InputBinding::new().with_audit_sink(Arc::new(BrokenSink)),
        );
        let plan = admitted_with(vec![stream_service()]);

        // `.err()` rather than `expect_err`: a session has no `Debug`, on
        // purpose — it carries the plan and the secret-scanner state.
        let refusal = InputGate::open(&vm, &plan)
            .err()
            .expect("an unauditable grant is not a grant");
        assert_eq!(refusal, InputRefusal::Unauditable);
        assert_eq!(refusal.reason(), "unauditable");
        assert_eq!(
            InputGate::lease_holder(&vm),
            None,
            "the lease goes straight back, so the VM is not wedged by a dead chain"
        );
    }

    #[test]
    fn a_production_build_cannot_swap_in_a_discarding_audit_sink() {
        // A sink that answers `Ok(())` without writing is worse than the
        // unreachable chain the test above covers: the gate believes every
        // decision was chain-recorded, admits the writer, and leaves no trace
        // that anyone reached the workload. Two absences stop it — the trait is
        // sealed, and the sink-injection point is compiled out of production —
        // and neither is observable at runtime, so the source is the assertion.
        let src = include_str!("input_gate.rs");

        assert!(
            src.contains("pub trait InputAuditSink: sealed::Sealed"),
            "the trait must stay sealed so no outside crate can implement it"
        );
        assert!(
            src.contains("mod sealed {"),
            "the sealing supertrait must live in a private module"
        );
        assert!(
            src.contains("#[cfg(test)]\n    #[must_use]\n    pub(crate) fn with_audit_sink("),
            "the arbitrary-sink injection point must stay `#[cfg(test)]` and crate-private"
        );
        assert!(
            src.contains("pub fn with_audit(mut self, audit: InputAudit)"),
            "the production binding must take the concrete chain, not `dyn InputAuditSink`"
        );

        // And inside this crate, the only implementations are the real chain
        // and the deliberately-failing test double — nothing that discards.
        let (production, tests) = src
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("this module keeps its tests at the end");
        let impls = |section: &str| -> Vec<String> {
            section
                .lines()
                .map(str::trim_start)
                .filter(|line| line.starts_with("impl") && line.contains("InputAuditSink for"))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(
            impls(production),
            ["impl InputAuditSink for InputAudit {"],
            "the chain binding is the only production sink"
        );
        assert_eq!(
            impls(tests),
            ["impl InputAuditSink for BrokenSink {"],
            "the only test sink fails loudly; a silently-succeeding one would \
             make every assertion about the chain vacuous"
        );
    }

    #[test]
    fn a_transient_chain_failure_does_not_disable_input_for_the_process() {
        // Caching the failure would let one blip at process start turn
        // workload input off for the lifetime of the host process — a silent
        // policy change nobody asked for.
        let slot = Mutex::new(None);
        assert!(
            cached_audit(&slot, || anyhow::bail!("the chain is briefly unreachable")).is_none(),
            "a build failure yields no chain"
        );
        assert!(
            cached_audit(&slot, build_process_audit).is_some(),
            "and a later attempt must still be able to succeed"
        );
    }

    #[test]
    fn the_session_crosses_thread_boundaries() {
        // The delivering consumer runs on its own thread in the daemon; a
        // non-`Send` field would only surface when that wiring lands.
        fn assert_send<T: Send>() {}
        assert_send::<InputSession>();
        assert_send::<InputGate>();
    }
}
