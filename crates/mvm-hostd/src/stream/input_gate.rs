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
//! - **The secret scan spans frame boundaries, and holds no secret.** A
//!   scanner that inspects one frame at a time is defeated by splitting a
//!   secret across two writes, so `stream::secret_scan`
//!   carries a sliding window and, more than that, *withholds* the tail of the
//!   stream it must still be able to see. A refusal that arrives after the
//!   first half already reached the guest would be theatre. What it slides
//!   that window against is a set of [`SecretFingerprint`]s — a length and a
//!   rolling hash each, computed by the process that legitimately holds the
//!   plaintext — because this gate runs in a process that must not hold one.
//!   A fingerprint match is a hash match and nothing stronger, which is why
//!   [`InputRefusal::SecretMaterial`] says so. Holding fingerprints rather than
//!   values also means the withheld tail is a blanket
//!   `longest_secret - 1` bytes rather than the exact live prefix, which is
//!   wider than a request line — so [`InputSession::refresh`] releases it after
//!   [`DEFAULT_IDLE_FLUSH_AFTER`] of writer silence, on elapsed time alone. See
//!   `stream::secret_scan` for what this cannot catch;
//!   it is a backstop against a confused caller, not a defence against a
//!   determined one. The real guarantee is upstream: the host has no reason to
//!   send a secret into a guest, because secrets are substituted on egress
//!   instead.
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
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use mvm_contract::stream::input::{CloseInput, InputFrame, grants_input};
use mvm_contract::stream::secret_fingerprint::SecretFingerprint;
use mvm_core::plan::ExecutionPlan;
use zeroize::Zeroize;

use crate::audit::emitter::AuditEmitter;
use crate::plan_admission::AdmittedPlan;
use crate::stream::secret_scan::SecretScanner;

/// Category recorded for a secret value the host itself holds for a workload.
pub use mvm_contract::stream::secret_fingerprint::CATEGORY_HOST_SECRET;

/// How long a writer keeps the input lease without touching it.
///
/// Long enough that an interactive human pausing to think does not lose their
/// place, and that a writer waiting between chunks — a pipe blocked on its
/// upstream, a keepalive tick that slipped — does not lose it to a timer;
/// short enough that a consumer which crashed mid-session frees the VM's stdin
/// inside a coffee break rather than at VM teardown.
///
/// The pause this describes is a real workflow again only because of
/// [`DEFAULT_IDLE_FLUSH_AFTER`]: a lease that outlives a pause is worth
/// nothing if the bytes the writer already typed are still sitting in the
/// scanner waiting for a write that the workload's silence guarantees will
/// never come.
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(30);

/// How quiet a writer must go before the gate hands over the tail its secret
/// scan is withholding.
///
/// On a VM with bound fingerprints the scanner withholds a blanket
/// `longest_secret - 1` bytes of every write, so a request line shorter than
/// that clears nothing at all. Without a release on silence that is a
/// deadlock, not latency: the workload never receives a line, so it never
/// answers, so the operator never sends the write that would push the first
/// one out. The release is what makes the request/response shape work.
///
/// 50ms, because the threshold has to sit between two gaps that differ by
/// orders of magnitude. Below it is the gap *inside* one writer's burst —
/// consecutive frames of a paste or of a chunked pipe are separated by a
/// buffer copy and one vsock round trip, microseconds to low milliseconds —
/// and the scan must stay exact across those, since that is the split a
/// confused caller actually produces. Above it is the gap a human or a
/// request/response peer leaves, which is at minimum the workload's own
/// think time. 50ms is roughly fifty times the first and half of the ~100ms
/// at which a person starts to perceive delay, so it neither fires inside a
/// burst nor is felt outside one.
///
/// **The decision is elapsed time and nothing else.** It never consults the
/// withheld bytes, and it must not: a release that depended on content would
/// be a prefix oracle — feed a byte, watch whether it was withheld, and walk
/// a secret out one byte at a time. The blanket carry is what denies an
/// observer that signal, and a content-blind release preserves it.
pub const DEFAULT_IDLE_FLUSH_AFTER: Duration = Duration::from_millis(50);

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
    /// The bytes match the fingerprint of one of the host's own secrets.
    ///
    /// Deliberately *not* "carries a secret". The gate holds fingerprints, not
    /// values, so a match says the bytes have the same length and the same
    /// rolling hash as a bound secret — which a collision also does. It
    /// refuses either way, because failing closed is the right direction; but
    /// an operator handed "this contained a secret" when it did not would lose
    /// hours proving the negative, so the sentence has to say what was
    /// actually checked.
    #[error(
        "input matches the fingerprint of known secret material ({category}); \
         a fingerprint match is a length and hash match, not proof these bytes are that secret"
    )]
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
/// and the process audit chain — what a binding adds is the fingerprint set to
/// recognise, a VM-specific chain, and a lease lifetime.
pub struct InputBinding {
    fingerprints: Vec<SecretFingerprint>,
    audit: Option<Arc<dyn InputAuditSink>>,
    lease_ttl: Duration,
    idle_flush_after: Duration,
}

impl InputBinding {
    /// An empty binding: no fingerprints, the process audit chain, the
    /// default lease lifetime and the default idle release.
    #[must_use]
    pub fn new() -> Self {
        Self {
            fingerprints: Vec::new(),
            audit: None,
            lease_ttl: DEFAULT_LEASE_TTL,
            idle_flush_after: DEFAULT_IDLE_FLUSH_AFTER,
        }
    }

    /// Recognise one more secret on the way into this VM.
    ///
    /// A [`SecretFingerprint`] and not a value: the process that binds this is
    /// not the process that holds the plaintext, and keeping it that way is
    /// the reason the parameter has this type. There is no overload taking
    /// bytes.
    #[must_use]
    pub fn with_fingerprint(mut self, fingerprint: SecretFingerprint) -> Self {
        self.fingerprints.push(fingerprint);
        self
    }

    /// The same for a whole set, which is how one arrives: the substitution
    /// endpoint fingerprints every secret it resolved for this VM at once.
    #[must_use]
    pub fn with_fingerprints(
        mut self,
        fingerprints: impl IntoIterator<Item = SecretFingerprint>,
    ) -> Self {
        self.fingerprints.extend(fingerprints);
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

    /// How quiet this VM's writer must go before the withheld tail is released.
    ///
    /// A knob rather than a constant so the boundary can be exercised from
    /// both sides without sleeping on a wall clock: zero releases on the first
    /// idle check, an hour releases on none of them, and both are decided by
    /// the same elapsed-time comparison production uses. See
    /// [`DEFAULT_IDLE_FLUSH_AFTER`] for what the value has to sit between.
    #[must_use]
    pub fn with_idle_flush_after(mut self, idle_flush_after: Duration) -> Self {
        self.idle_flush_after = idle_flush_after;
        self
    }
}

impl Default for InputBinding {
    fn default() -> Self {
        Self::new()
    }
}

/// A binding as the gate stores it: the fingerprint set shared rather than
/// copied into every session that opens.
struct Bound {
    fingerprints: Arc<Vec<SecretFingerprint>>,
    audit: Option<Arc<dyn InputAuditSink>>,
    lease_ttl: Duration,
    idle_flush_after: Duration,
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
    fingerprints: Arc<Vec<SecretFingerprint>>,
    lease_ttl: Duration,
    idle_flush_after: Duration,
}

/// The gate: process-wide, and reached by name rather than by handle so there
/// is exactly one of it.
pub struct InputGate;

impl InputGate {
    /// Install what the gate needs to police `vm`'s stdin. Replaces any
    /// previous binding; call it before the workload is reachable.
    ///
    /// A session snapshots the fingerprint set at [`open`](Self::open) and
    /// holds it for its lifetime, so re-binding does not change what a *live*
    /// session recognises — a secret registered mid-session is recognised by
    /// the next writer, not the current one. Deliberate: the alternative is a
    /// scanner whose window can change under a partially-scanned stream.
    pub fn bind(vm: &str, binding: InputBinding) {
        let bound = Bound {
            fingerprints: Arc::new(binding.fingerprints),
            audit: binding.audit,
            lease_ttl: binding.lease_ttl,
            idle_flush_after: binding.idle_flush_after,
        };
        gate().bindings.insert(vm.to_string(), bound);
    }

    /// Replace just the fingerprint set for `vm`, leaving its chain and its
    /// lease and idle timings alone.
    ///
    /// Two different owners, so two different calls. The fingerprints come
    /// from the substitution endpoint and change whenever a VM's secrets do;
    /// the audit chain and the timings are installed once by whoever stood the
    /// VM up. A caller refreshing one must not silently reset the other — most
    /// sharply for the chain, where reverting to the process default would
    /// move a VM's input decisions into a different log without saying so.
    ///
    /// Replaces rather than merges: a set that could only grow would let a
    /// previous boot's fingerprints outlive the secrets they stood for.
    pub fn bind_fingerprints(vm: &str, fingerprints: Vec<SecretFingerprint>) {
        let mut state = gate();
        match state.bindings.get_mut(vm) {
            Some(bound) => bound.fingerprints = Arc::new(fingerprints),
            None => {
                state.bindings.insert(
                    vm.to_string(),
                    Bound {
                        fingerprints: Arc::new(fingerprints),
                        audit: None,
                        lease_ttl: DEFAULT_LEASE_TTL,
                        idle_flush_after: DEFAULT_IDLE_FLUSH_AFTER,
                    },
                );
            }
        }
    }

    /// Drop `vm`'s binding and any lease on it — the teardown half of
    /// [`bind`](Self::bind). Leaving the binding behind would keep a dead VM's
    /// fingerprints resident.
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
            idle_flush_after: resolved.idle_flush_after,
            // The session opens "just written to", so a writer that opens and
            // sits there has nothing withheld to release and nothing to
            // measure against.
            last_admitted_at: Instant::now(),
            scanner: SecretScanner::new(resolved.fingerprints),
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
    /// How long this session's writer must be silent before the withheld tail
    /// is released. See [`DEFAULT_IDLE_FLUSH_AFTER`].
    idle_flush_after: Duration,
    /// When the scanner last took bytes. The one input to the idle release,
    /// and deliberately the only one — see [`Self::release_if_idle`].
    last_admitted_at: Instant,
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
                // Any accepted frame is activity, including one that cleared
                // nothing: the writer is mid-burst and the scan must stay
                // exact across the boundary it just created.
                self.last_admitted_at = Instant::now();
                Ok(())
            }
            Err(category) => Err(self.latch(InputRefusal::SecretMaterial {
                category: category.as_str(),
            })),
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

    /// Say "I am idle but alive": extend the lease, and release the tail the
    /// secret scan has been withholding if the writer has been quiet for
    /// [`DEFAULT_IDLE_FLUSH_AFTER`].
    ///
    /// Both halves answer the same fact, which is why they are one call. A
    /// lease that survives a pause is worth nothing on a secret-bearing VM if
    /// the bytes the writer already sent are still held: the scan withholds a
    /// blanket `longest_secret - 1` bytes, which is wider than a request line,
    /// so the workload receives nothing, answers nothing, and the writer never
    /// produces the next write that would push the first one out. Releasing on
    /// silence is what breaks that circle.
    ///
    /// Anything released lands in the outbox, so a caller drains with
    /// [`take_admitted`](Self::take_admitted) exactly as it would after a
    /// write.
    pub fn refresh(&mut self) -> Result<(), InputRefusal> {
        self.check_live()?;
        self.release_if_idle(Instant::now());
        Ok(())
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

    /// Hand the withheld tail to the outbox once the writer has been quiet for
    /// [`Self::idle_flush_after`].
    ///
    /// **Content-independent, and that is the whole design.** The two inputs
    /// are how long it has been since the scanner last took bytes and how many
    /// bytes it is holding. Neither is derived from what those bytes *are*, so
    /// an observer who watches whether a write came out learns only when it
    /// wrote — never anything about the secret. The alternative, releasing
    /// only the tails that cannot still become a secret, is what the plaintext
    /// scanner did and is a prefix oracle here: hold the input grant, feed one
    /// byte, see whether it was withheld, and a 40-byte credential falls in
    /// about 40·256 probes instead of 256^40. A blanket carry leaks nothing
    /// because it is blanket; a blanket release keeps it that way.
    ///
    /// Releasing cannot hand over a secret. The tail is what survived
    /// [`SecretScanner::admit`], which already refused the whole buffer if any
    /// window in it matched — so what is released is bytes already proven not
    /// to contain a bound fingerprint. What is lost is *context*: a secret
    /// split across the silence is no longer contiguous in the scanner and is
    /// missed. That needs the sender to pause mid-credential, which a confused
    /// caller does not do and a determined one does not need, since encoding
    /// the value defeats the scan outright.
    fn release_if_idle(&mut self, now: Instant) {
        if self.scanner.withheld_len() == 0 {
            return;
        }
        if now.duration_since(self.last_admitted_at) < self.idle_flush_after {
            return;
        }
        let mut released = self.scanner.flush();
        self.outbox.extend_from_slice(&released);
        released.zeroize();
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
    let (audit, fingerprints, lease_ttl, idle_flush_after) = {
        let state = gate();
        match state.bindings.get(vm) {
            Some(bound) => (
                bound.audit.clone(),
                Arc::clone(&bound.fingerprints),
                bound.lease_ttl,
                bound.idle_flush_after,
            ),
            None => (
                None,
                Arc::new(Vec::new()),
                DEFAULT_LEASE_TTL,
                DEFAULT_IDLE_FLUSH_AFTER,
            ),
        }
    };
    Resolved {
        audit: audit.or_else(process_audit),
        fingerprints,
        lease_ttl,
        idle_flush_after,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_contract::stream::input::INPUT_GRANT_SERVICE;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::plan::{PlanSeccompTier, SecretReleasePolicy, SynthesisInput, sign_plan};
    use tempfile::TempDir;

    use mvm_contract::stream::secret_fingerprint::SecretCategory;

    use super::*;
    use crate::audit::emitter::stream_audit;
    use crate::plan_admission::{InMemoryNonceLedger, SystemClock, admit_for_run};
    use crate::supervisor::verify_audit_chain;

    /// Fixed so a test can verify the scratch chain's signatures.
    pub(super) const TEST_CHAIN_SEED: [u8; 32] = [9u8; 32];

    /// A lease that has already lapsed when it is taken, so no test has to
    /// sleep to watch one expire.
    ///
    /// The degenerate TTL, and the one to reach for first: `is_live` is
    /// `now < expires_at`, so a zero TTL expires the instant it is claimed.
    /// Deterministic and free. Use it whenever nothing has to be written
    /// through the lease *before* it lapses — pair it with [`LIVE_LEASE_TTL`]
    /// re-bound before the successor opens, since `bind` replaces the binding
    /// and leaves the lease table alone.
    const ALREADY_LAPSED: Duration = Duration::ZERO;

    /// A lease that must be live for a write and lapse only afterwards, with
    /// the wait that outlives it.
    ///
    /// [`ALREADY_LAPSED`] cannot express this: the write has to be admitted
    /// first, so the lease has to be live first, so the test has to wait the
    /// TTL out. That makes the TTL the *window the write has to land in*, and
    /// it is therefore sized from measurement rather than taste. Sampling
    /// adjacent-statement stalls on a 16-core host while the `mvm-hostd` suite
    /// ran under 2x CPU oversubscription measured 27 stalls over 20ms in a
    /// single pass, the worst 298ms. At the previous 20ms a writer descheduled
    /// between `open` and its first `write` lost the lease mid-setup and the
    /// write was refused — the flake, 3-4 times per full-suite run.
    ///
    /// One second gives the write roughly 3x the worst stall seen under load
    /// harsher than CI.
    const LAPSING_LEASE_TTL: Duration = Duration::from_secs(1);

    /// A wait that outlives [`LAPSING_LEASE_TTL`] with room for the sleep
    /// itself to be scheduled late.
    const PAST_THE_LEASE: Duration = Duration::from_millis(1300);

    /// For a lease that must stay live to the end of the test. Nothing waits
    /// this out, so it is sized to be unreachable by scheduler jitter rather
    /// than merely unlikely.
    const LIVE_LEASE_TTL: Duration = Duration::from_secs(30);

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
            assets: Vec::new(),
            redaction: mvm_core::policy::RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            caller_commitment: None,
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

    /// The fingerprint of `secret`, as the substitution endpoint computes it.
    ///
    /// A test may hold a literal; the point of the type is that the *gate*
    /// never does, and this helper is where that transition happens.
    fn fingerprint(secret: &str) -> SecretFingerprint {
        SecretFingerprint::of(secret.as_bytes(), SecretCategory::HostSecret)
            .expect("a non-empty secret fingerprints")
    }

    /// A session on a VM bound to recognise exactly one secret's fingerprint.
    fn granted_session_with_known_secret(secret: &str) -> InputSession {
        session_bound_to(secret, DEFAULT_IDLE_FLUSH_AFTER)
    }

    /// The same, with the idle release set where the test needs it.
    ///
    /// The threshold is the seam these tests drive, not the clock: zero
    /// releases on the first idle check and an hour releases on none of them,
    /// so both sides of the boundary are decided by the same elapsed-time
    /// comparison production uses, with nothing sleeping and nothing to go
    /// flaky under a loaded machine.
    fn session_bound_to(secret: &str, idle_flush_after: Duration) -> InputSession {
        let vm = unique_vm("vm-secret");
        InputGate::bind(
            &vm,
            InputBinding::new()
                .with_fingerprint(fingerprint(secret))
                .with_idle_flush_after(idle_flush_after),
        );
        let plan = admitted_with(vec![stream_service()]);
        InputGate::open(&vm, &plan).expect("the plan grants input")
    }

    /// A 40-byte secret, so the carry is 39 — wider than any request line a
    /// person types, which is the shape the idle release exists for.
    const LONG_SECRET: &str = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI0K7MDE";

    /// Never elapses within a test process's lifetime, so the idle release is
    /// off and only a write or a close can move the withheld tail.
    const NEVER_IDLE: Duration = Duration::from_secs(3600);

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
    /// The plan carries an audit label of its own, because `PlanAuditEntry` merges
    /// `plan.audit_labels` into every entry: against a plan with none, the key
    /// set would be the gate's labels alone and the assertion would prove less
    /// than it claims on any production plan.
    #[test]
    fn stream_input_audit_records_the_reason_and_none_of_the_refused_bytes() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let vm = unique_vm("vm-audit");
        InputGate::bind(
            &vm,
            InputBinding::new().with_fingerprint(fingerprint(secret)),
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
        //
        // Decided by degenerate TTLs rather than by a wall clock, the same way
        // the idle-flush tests above are: a zero TTL has lapsed the moment it
        // is taken, an hour has not lapsed by the end of the test. Sleeping
        // past a short TTL makes the outcome depend on scheduler luck — this
        // test failed exactly that way on a loaded CI runner, at a 20ms TTL
        // with a 40ms sleep.
        let vm = unique_vm("vm-lease-expiry");
        InputGate::bind(&vm, InputBinding::new().with_lease_ttl(ALREADY_LAPSED));
        let plan = admitted_with(vec![stream_service()]);
        let mut stale = InputGate::open(&vm, &plan).expect("first session");

        assert_eq!(InputGate::lease_holder(&vm), None, "the lease lapsed");

        // Re-bind before the second open so the taker gets a live lease.
        // `bind` replaces the binding and leaves the lease table alone (only
        // `unbind` clears it), so the lapsed lease is still there to take over.
        InputGate::bind(&vm, InputBinding::new().with_lease_ttl(LIVE_LEASE_TTL));
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
    fn a_lease_is_not_live_at_its_exact_expiry() {
        let now = Instant::now();
        let lease = Lease {
            holder: "holder".into(),
            expires_at: now + Duration::from_secs(1),
        };

        assert!(lease.is_live(now));
        assert!(lease.is_live(now + Duration::from_millis(999)));
        assert!(!lease.is_live(lease.expires_at));
    }

    #[test]
    fn a_write_refreshes_the_lease() {
        let vm = unique_vm("vm-lease-refresh");
        InputGate::bind(&vm, InputBinding::new().with_lease_ttl(LAPSING_LEASE_TTL));
        let plan = admitted_with(vec![stream_service()]);
        let mut session = InputGate::open(&vm, &plan).expect("first session");
        // Four gaps of this size outlast the TTL, so reaching the end proves
        // the writes refreshed it. Each gap still has to leave a write room to
        // land inside the TTL, so the gap is the TTL less a wide margin for a
        // late wakeup — see `LAPSING_LEASE_TTL` for where the margin comes from.
        const BETWEEN_WRITES: Duration = Duration::from_millis(300);
        for seq in 0..4u64 {
            std::thread::sleep(BETWEEN_WRITES);
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
        InputGate::bind(&vm, InputBinding::new().with_lease_ttl(LAPSING_LEASE_TTL));
        let plan = admitted_with(vec![stream_service()]);
        let mut stalled = InputGate::open(&vm, &plan).expect("first session");
        stalled
            .write(InputFrame {
                seq: 0,
                payload: b"rm -rf /\n".to_vec(),
            })
            .expect("cleared while the lease was live");

        std::thread::sleep(PAST_THE_LEASE);
        // A's lease is the one under test; B's only has to still be there at
        // the end, so it is not left racing the clock too.
        InputGate::bind(&vm, InputBinding::new().with_lease_ttl(LIVE_LEASE_TTL));
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
        // already handed the guest the first twelve bytes of the key.
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"echo AKIAIOSFODNN".to_vec(),
            })
            .expect("a prefix is not a match");
        let cleared = session.take_admitted().expect("the lease is live");
        assert!(
            !cleared.ends_with(b"AKIAIOSFODNN"),
            "the live prefix must not reach the guest ahead of the refusal: {:?}",
            String::from_utf8_lossy(&cleared)
        );
        assert_eq!(
            cleared, b"",
            "the whole 17-byte frame sits inside the 19-byte carry"
        );
    }

    #[test]
    fn the_withheld_tail_is_bounded_and_ships_on_the_next_frame() {
        // The cost of matching fingerprints rather than values: the scanner
        // cannot tell a live prefix from an innocent tail, so it holds a fixed
        // `longest - 1` bytes. Bounded, and never lost — the previous tail
        // ships the moment the next frame proves nothing straddles.
        let mut session = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
        let first = b"the quick brown fox jumps over the lazy dog\n";
        session
            .write(InputFrame {
                seq: 0,
                payload: first.to_vec(),
            })
            .expect("nothing to match");
        let cleared = session.take_admitted().expect("the lease is live");
        assert_eq!(
            cleared.len(),
            first.len() - 19,
            "exactly one byte short of the longest secret stays behind"
        );
        assert_eq!(cleared, &first[..first.len() - 19]);

        session
            .write(InputFrame {
                seq: 1,
                payload: b"and again\n".to_vec(),
            })
            .expect("still nothing to match");
        assert_eq!(
            [cleared, session.take_admitted().expect("the lease is live")].concat(),
            [first.as_slice(), b"and again\n"].concat()[..first.len() + 10 - 19],
            "every earlier byte came out, in order"
        );
    }

    #[test]
    fn a_vm_that_bound_no_fingerprints_is_not_delayed_at_all() {
        // The carry is the price of scanning, so it must be charged only to
        // workloads that actually have a secret to leak.
        let vm = unique_vm("vm-undelayed");
        InputGate::bind(&vm, InputBinding::new());
        let plan = admitted_with(vec![stream_service()]);
        let mut session = InputGate::open(&vm, &plan).expect("the plan grants input");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"ls -la\n".to_vec(),
            })
            .expect("nothing bound");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"ls -la\n",
            "with no fingerprints there is nothing to slide a window against"
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
    fn the_gate_holds_no_secret_value_anywhere_a_binding_can_put_one() {
        // The type surface is the guarantee, not a comment: the only way a
        // secret enters this gate is `with_fingerprint`, whose parameter is a
        // length, a hash and a vocabulary word. There is no byte-taking
        // overload to reach for, so a caller that has no plaintext cannot be
        // tempted into acquiring some, and one that does cannot hand it over.
        let binding = InputBinding::new().with_fingerprint(fingerprint("AKIAIOSFODNN7EXAMPLE"));
        let rendered = format!("{:?}", binding.fingerprints);
        assert!(!rendered.contains("AKIA"), "got {rendered}");
        assert!(rendered.contains("len: 20"), "got {rendered}");
        assert_eq!(
            std::mem::size_of::<SecretFingerprint>(),
            std::mem::size_of::<u64>() * 2,
            "a fingerprint is fixed-width and inline: two words hold a length, a \
             hash and a category, and there is no room for a pointer to a value"
        );
        fn assert_copy<T: Copy>() {}
        assert_copy::<SecretFingerprint>();

        // And the source says the same thing: no constructor on the binding
        // takes bytes.
        let src = include_str!("input_gate.rs");
        let (production, _tests) = src
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("this module keeps its tests at the end");
        assert!(
            !production.contains("KnownSecret"),
            "the plaintext-carrying binding type must stay deleted, not deprecated"
        );
        assert!(
            production
                .contains("pub fn with_fingerprint(mut self, fingerprint: SecretFingerprint)"),
            "the one secret-facing setter must take a fingerprint"
        );
    }

    /// A test lease must be sized by a named constant, never by a magnitude
    /// picked in place.
    ///
    /// The magnitudes are how this went wrong: a lease TTL is not only how long
    /// the lease survives, it is the window every write before the lapse has to
    /// land in. Written as `from_millis(20)` that reads like "a short lease",
    /// not like "this test fails if the host stalls for 20ms" — and on a loaded
    /// host stalls over 20ms happened 27 times in one suite pass. Seven tests
    /// across four files flaked on it.
    ///
    /// `Duration::ZERO` is deliberately allowed: it is not a guess about how
    /// fast the host is, it is the exact statement "already lapsed", and it is
    /// the technique that removes the wait entirely. `from_millis` /
    /// `from_secs` are the ones that encode an assumption about scheduling,
    /// and those must come from a constant whose docs carry the measurement.
    /// This checks the test halves only: production has its own default, and
    /// the setter's own signature names `Duration`.
    #[test]
    fn a_test_lease_is_sized_by_a_named_constant_not_a_literal() {
        // Every file that binds a lease from a test, including the integration
        // tests, which are where three of the seven flakes lived.
        let sources: [(&str, &str); 4] = [
            ("input_gate.rs", include_str!("input_gate.rs")),
            ("input_route.rs", include_str!("input_route.rs")),
            (
                "tests/workload_input_plane.rs",
                include_str!("../../tests/workload_input_plane.rs"),
            ),
            (
                "tests/stream_edge_connector.rs",
                include_str!("../../tests/stream_edge_connector.rs"),
            ),
        ];

        let mut literals = Vec::new();
        for (name, src) in sources {
            // A `src/` module keeps its tests at the end; an integration test
            // file is tests all the way down.
            let tests = src
                .split_once("#[cfg(test)]\nmod tests {")
                .map_or(src, |(_production, tests)| tests);
            for (offset, _) in tests.match_indices(".with_lease_ttl(") {
                let argument = tests[offset + ".with_lease_ttl(".len()..].trim_start();
                let constructed = argument
                    .strip_prefix("std::time::")
                    .unwrap_or(argument)
                    .starts_with("Duration::from_");
                if constructed {
                    let line = tests[..offset].lines().count() + 1;
                    literals.push(format!(
                        "{name}: a lease sized in place (test-half line ~{line})"
                    ));
                }
            }
        }

        assert!(
            literals.is_empty(),
            "size these from LAPSING_LEASE_TTL / LIVE_LEASE_TTL, whose docs carry \
             the measured stall the value has to clear: {literals:#?}"
        );
    }

    #[test]
    fn a_fingerprint_refusal_does_not_claim_the_bytes_are_the_secret() {
        // A fingerprint match is a length-and-hash match; a collision produces
        // the same refusal from bytes that are nobody's secret. Refusing is
        // right — it fails closed — but an operator told "this contained a
        // secret" when it did not would spend hours proving the negative, so
        // the sentence has to say what was actually checked.
        let refusal = InputRefusal::SecretMaterial {
            category: CATEGORY_HOST_SECRET,
        };
        let said = refusal.to_string();
        assert!(
            said.contains("matches the fingerprint"),
            "the refusal must name what it compared: {said}"
        );
        assert!(
            said.contains("not proof"),
            "and must disclaim the certainty it does not have: {said}"
        );
        assert!(
            !said.contains("carries recognised secret material"),
            "the old wording asserted identity from a hash: {said}"
        );
        assert_eq!(
            refusal.reason(),
            "secret-material",
            "the wire-stable reason word an operator greps for does not move"
        );
    }

    // --- the idle release --------------------------------------------------

    #[test]
    fn an_idle_writer_gets_the_line_the_carry_swallowed() {
        // The deadlock, and its end. A 40-byte bound secret makes the carry
        // 39, so an 11-byte request line clears nothing: the workload receives
        // no line, answers nothing, and the operator has no reason to send the
        // write that would push the first one out. Releasing on silence is the
        // only thing that breaks the circle — before this, the line arrived at
        // EOF or never.
        let mut session = session_bound_to(LONG_SECRET, Duration::ZERO);
        let line = b"{\"q\":\"hi\"}\n";
        session
            .write(InputFrame {
                seq: 0,
                payload: line.to_vec(),
            })
            .expect("a JSON line is not a secret");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"",
            "the whole 11-byte line sits inside the 39-byte carry"
        );

        session.refresh().expect("the lease is live");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            line,
            "going quiet must hand the line over, not wait for a write that \
             the workload's own silence guarantees will never come"
        );
        session.refresh().expect("the lease is live");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"",
            "and there is nothing left to release twice"
        );
        assert_eq!(session.stranded_len(), 0);
    }

    #[test]
    fn idle_release_happens_at_the_exact_threshold() {
        let mut session = session_bound_to(LONG_SECRET, Duration::from_secs(1));
        let line = &LONG_SECRET.as_bytes()[..1];
        session
            .write(InputFrame {
                seq: 0,
                payload: line.to_vec(),
            })
            .expect("the prefix is not a complete secret");
        assert!(session.take_admitted().unwrap().is_empty());

        let exact_deadline = session.last_admitted_at + session.idle_flush_after;
        session.release_if_idle(exact_deadline);
        assert_eq!(session.outbox, line);
    }

    #[test]
    fn the_idle_release_does_not_depend_on_what_the_withheld_bytes_are() {
        // The property the whole design rests on. A release that fired only
        // for tails which could not still become a secret would be a prefix
        // oracle: hold the grant, feed a byte, watch whether it came out, and
        // walk a 40-byte credential out in about 40x256 probes. So two
        // payloads of the same length must be indistinguishable from outside —
        // and one of these is a genuine live prefix of the bound secret while
        // the other is nobody's.
        let live_prefix = &LONG_SECRET.as_bytes()[..11];
        let innocent = b"hello world";
        assert_eq!(
            live_prefix.len(),
            innocent.len(),
            "same length, or nothing \
                    below compares anything"
        );

        let observe = |payload: &[u8]| -> (Vec<u8>, usize, Vec<u8>) {
            let mut session = session_bound_to(LONG_SECRET, Duration::ZERO);
            session
                .write(InputFrame {
                    seq: 0,
                    payload: payload.to_vec(),
                })
                .expect("neither payload completes the secret");
            let before = session.take_admitted().expect("the lease is live");
            let withheld = session.stranded_len();
            session.refresh().expect("the lease is live");
            let after = session.take_admitted().expect("the lease is live");
            (before, withheld, after)
        };

        let (prefix_before, prefix_withheld, prefix_after) = observe(live_prefix);
        let (innocent_before, innocent_withheld, innocent_after) = observe(innocent);

        assert_eq!(
            (prefix_before, prefix_withheld),
            (innocent_before, innocent_withheld),
            "what is withheld must be a length, never a verdict about the bytes"
        );
        assert_eq!(
            prefix_after.len(),
            innocent_after.len(),
            "and so must what the idle release hands back"
        );
        assert_eq!(prefix_after, live_prefix);
        assert_eq!(innocent_after, innocent);
    }

    #[test]
    fn a_secret_split_across_two_writes_inside_the_threshold_is_still_refused() {
        // The coverage the release must not cost. Inside the threshold the
        // writer is mid-burst — consecutive frames of a paste, or of a chunked
        // pipe — and that is exactly the split a confused caller produces, so
        // the scan has to stay exact across it. A release that fired here
        // would hand the guest the first half and refuse the second, which is
        // the theatre the carry exists to prevent.
        let mut session = session_bound_to("AKIAIOSFODNN7EXAMPLE", NEVER_IDLE);
        session
            .write(InputFrame {
                seq: 0,
                payload: b"AKIAIOSFODNN".to_vec(),
            })
            .expect("a prefix alone is not a match");
        session.refresh().expect("the lease is live");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"",
            "a writer that has not been quiet long enough gets nothing back"
        );
        assert!(matches!(
            session.write(InputFrame {
                seq: 1,
                payload: b"7EXAMPLE".to_vec()
            }),
            Err(InputRefusal::SecretMaterial { .. })
        ));
    }

    #[test]
    fn a_secret_split_across_the_idle_gap_is_missed_and_that_is_the_price() {
        // The weakening, pinned rather than left in prose. Once the tail is
        // released the scanner has no context to straddle, so a secret split
        // across the silence goes through. It needs the *sender* to pause
        // mid-credential, which a confused caller does not do and a determined
        // one does not need — base64 already defeats the scan outright. This
        // sits inside "backstop, not a defence"; it does not move that line.
        let mut session = session_bound_to("AKIAIOSFODNN7EXAMPLE", Duration::ZERO);
        session
            .write(InputFrame {
                seq: 0,
                payload: b"AKIAIOSFODNN".to_vec(),
            })
            .expect("a prefix alone is not a match");
        session.refresh().expect("the lease is live");
        session
            .write(InputFrame {
                seq: 1,
                payload: b"7EXAMPLE".to_vec(),
            })
            .expect("the halves are no longer contiguous in the scanner");
        session.refresh().expect("the lease is live");
        assert_eq!(
            session.take_admitted().expect("the lease is live"),
            b"AKIAIOSFODNN7EXAMPLE",
            "the patient caller wins, and the ledger says so"
        );
    }

    #[test]
    fn an_idle_release_cannot_hand_over_a_bound_secret() {
        // What the release can never do, whatever the threshold. Anything the
        // scanner is holding already survived a scan of the whole buffer it
        // came from, so no window inside it matches — and a session that did
        // hit a match latches, so a caller cannot go quiet to collect what was
        // refused.
        let mut session = session_bound_to("AKIAIOSFODNN7EXAMPLE", Duration::ZERO);
        session
            .write(InputFrame {
                seq: 0,
                payload: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            })
            .expect_err("the whole secret in one frame is refused");
        assert!(matches!(
            session.refresh(),
            Err(InputRefusal::SecretMaterial { .. })
        ));
        assert!(matches!(
            session.take_admitted(),
            Err(InputRefusal::SecretMaterial { .. })
        ));
    }

    #[test]
    fn a_writer_that_lost_its_lease_gets_no_idle_release_either() {
        // Every path that moves bytes out of a session is lease-gated, and the
        // idle release is a new one. A stalled writer collecting its tail
        // after a successor took the stdin would deliver into somebody else's.
        let vm = unique_vm("vm-idle-lease");
        InputGate::bind(
            &vm,
            InputBinding::new()
                .with_fingerprint(fingerprint(LONG_SECRET))
                .with_idle_flush_after(Duration::ZERO)
                .with_lease_ttl(LAPSING_LEASE_TTL),
        );
        let plan = admitted_with(vec![stream_service()]);
        let mut stalled = InputGate::open(&vm, &plan).expect("the plan grants input");
        stalled
            .write(InputFrame {
                seq: 0,
                payload: b"hello\n".to_vec(),
            })
            .expect("cleared while the lease was live");
        std::thread::sleep(PAST_THE_LEASE);

        assert!(matches!(stalled.refresh(), Err(InputRefusal::LeaseExpired)));
        assert!(matches!(
            stalled.take_admitted(),
            Err(InputRefusal::LeaseExpired)
        ));
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
        assert!(
            session
                .take_admitted()
                .expect("the lease is live")
                .is_empty(),
            "eight bytes sit inside the carried window"
        );
        assert_eq!(
            session.close().expect("the lease is live").trailing,
            b"7EXAMPLE",
            "the accepted half comes out at close; the reordered one never \
             entered the stream at all"
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
            crate::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
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
            crate::plan_admission::RunPosture::without_backend(mvm_core::plan::Variant::Dev),
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
