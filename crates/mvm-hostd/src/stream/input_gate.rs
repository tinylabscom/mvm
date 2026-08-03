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
//! - **Default-deny.** [`InputGate::open`] refuses unless the *signed* plan
//!   carries the input grant. Not a warning and not a degraded mode: no
//!   session object exists, so there is nothing to write through. The grant
//!   check reads the same token the plan DTOs define, so a plan cannot mean
//!   one thing here and another to the admission path.
//! - **One writer at a time.** Two consumers interleaving into one byte stream
//!   produce garbage that neither of them sent, so concurrency is arbitrated
//!   rather than merged: a lease, held by exactly one session per VM. The
//!   lease expires, and the holder refreshes it by writing — a consumer that
//!   takes the lease and dies must not wedge the VM's stdin forever.
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
//!   file an operator is most likely to read.
//!
//! ## Ordering: close against an in-flight frame
//!
//! `CloseInput` carries no `seq`, so the wire alone cannot say whether a close
//! overtook a frame still in flight. Rather than assume the transport is
//! ordered, the gate makes the question unaskable: a close is *defined* to sit
//! after the highest `seq` this session accepted, and [`InputSession::close`]
//! takes `self` by value, so no frame can be written through a session that has
//! closed. One leaseholder owns the session, and the lease is what makes "the
//! writer cannot race itself" true. [`InputClose::after_seq`] hands the
//! boundary to the delivery side, which needs to know which frame EOF follows.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use mvm_core::plan::ExecutionPlan;
use mvm_protocol::stream::input::{InputFrame, grants_input};
use zeroize::Zeroize;

use crate::audit::emitter::AuditEmitter;

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
    /// The signed plan carries no input grant, or the grant could not be
    /// written to the chain-signed log.
    ///
    /// The two are the same answer on purpose: input into a sealed workload
    /// that leaves no signed trace is input the gate declines to have
    /// happened.
    #[error("no admitted input grant for this workload")]
    NotGranted,
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
}

impl InputRefusal {
    /// Wire-stable reason word for the audit chain. Stable because an operator
    /// greps for it and a later reader groups by it.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotGranted => "not-granted",
            Self::LeaseHeld { .. } => "lease-held",
            Self::SecretMaterial { .. } => "secret-material",
            Self::LeaseExpired => "lease-expired",
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

/// Binds the gate's refusals for one VM to the chain-signed audit log.
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

    /// Record an admitted writer. The caller treats a failure here as a
    /// refusal: an unauditable grant is not a grant.
    fn granted(&self, plan: &ExecutionPlan, vm: &str, holder: &str) -> anyhow::Result<()> {
        self.emitter.emit_stream_input_granted(plan, vm, holder)
    }

    /// Record a refusal. Failing to write it does not soften the refusal — the
    /// bytes are already not going anywhere — so this reports rather than
    /// propagates.
    fn refused(&self, plan: &ExecutionPlan, vm: &str, refusal: &InputRefusal) {
        if let Err(err) = self.emitter.emit_stream_input_refused(plan, vm, refusal) {
            tracing::warn!(
                vm = %vm,
                reason = refusal.reason(),
                error = %err,
                "workload input refusal not recorded in the audit chain"
            );
        }
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
    audit: Option<Arc<InputAudit>>,
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
    #[must_use]
    pub fn with_audit(mut self, audit: InputAudit) -> Self {
        self.audit = Some(Arc::new(audit));
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
    audit: Option<Arc<InputAudit>>,
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
    audit: Option<Arc<InputAudit>>,
    secrets: Arc<Vec<KnownSecret>>,
    lease_ttl: Duration,
}

/// The gate: process-wide, and reached by name rather than by handle so there
/// is exactly one of it.
pub struct InputGate;

impl InputGate {
    /// Install what the gate needs to police `vm`'s stdin. Replaces any
    /// previous binding; call it before the workload is reachable.
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

    /// Take the input lease on `vm` under the authority of `plan`.
    ///
    /// Refuses unless the plan grants input, unless the lease is free (or
    /// lapsed), and unless the grant itself can be chain-recorded.
    pub fn open(vm: &str, plan: &ExecutionPlan) -> Result<InputSession, InputRefusal> {
        let resolved = resolve(vm);

        if !grants_input(plan) {
            return Err(record_refusal(
                resolved.audit.as_deref(),
                plan,
                vm,
                InputRefusal::NotGranted,
            ));
        }

        let holder = match claim_lease(vm, plan, resolved.lease_ttl) {
            Ok(holder) => holder,
            Err(refusal) => {
                return Err(record_refusal(resolved.audit.as_deref(), plan, vm, refusal));
            }
        };

        // An unauditable admission is the exact hole this gate exists to
        // close, so it fails closed and gives the lease straight back.
        let Some(audit) = resolved.audit else {
            release_lease(vm, &holder);
            tracing::warn!(vm = %vm, "workload input refused: no chain to record the grant in");
            return Err(InputRefusal::NotGranted);
        };
        if let Err(err) = audit.granted(plan, vm, &holder) {
            release_lease(vm, &holder);
            tracing::warn!(vm = %vm, error = %err, "workload input refused: grant not recorded");
            return Err(InputRefusal::NotGranted);
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
    audit: Arc<InputAudit>,
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
    pub fn write(&mut self, frame: InputFrame) -> Result<(), InputRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        self.renew_lease()?;
        match self.scanner.admit(&frame.payload) {
            Ok(cleared) => {
                self.outbox.extend_from_slice(&cleared);
                self.highest_accepted_seq = Some(
                    self.highest_accepted_seq
                        .map_or(frame.seq, |seq| seq.max(frame.seq)),
                );
                Ok(())
            }
            Err(category) => Err(self.refuse(InputRefusal::SecretMaterial { category })),
        }
    }

    /// Take the bytes cleared for delivery so far.
    ///
    /// The gate clears bytes; it does not own the transport that carries them.
    /// The single leaseholder drains this and delivers, which is also what
    /// bounds the buffer — nothing accumulates here that its own owner did not
    /// choose to leave.
    pub fn take_admitted(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbox)
    }

    /// Extend the lease without writing, for a holder that is idle but alive.
    pub fn refresh(&mut self) -> Result<(), InputRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        self.renew_lease()
    }

    /// End the session: flush what was held back, release the lease, and fix
    /// where EOF sits in the sequence.
    ///
    /// The withheld tail ships here because it is, by construction, a proper
    /// prefix of a secret and not a secret — dropping it would silently
    /// swallow the caller's last bytes.
    #[must_use]
    pub fn close(mut self) -> InputClose {
        let mut trailing = std::mem::take(&mut self.outbox);
        trailing.extend_from_slice(&self.scanner.flush());
        release_lease(&self.vm, &self.holder);
        InputClose {
            after_seq: self.highest_accepted_seq,
            trailing,
        }
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
            Err(self.refuse(InputRefusal::LeaseExpired))
        }
    }

    /// Record the refusal once, latch it, and hand it back.
    fn refuse(&mut self, refusal: InputRefusal) -> InputRefusal {
        self.audit.refused(&self.plan, &self.vm, &refusal);
        self.refused = Some(refusal.clone());
        refusal
    }
}

impl Drop for InputSession {
    /// A dropped session frees the VM's stdin immediately rather than at
    /// lease expiry. `close` already released it; releasing keys on the holder
    /// id, so this cannot take a lease a later writer acquired.
    fn drop(&mut self) {
        release_lease(&self.vm, &self.holder);
    }
}

/// Where a closed session left the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputClose {
    /// The highest `seq` this session accepted, or `None` if it accepted
    /// nothing. EOF is ordered immediately after it.
    pub after_seq: Option<u64>,
    /// Bytes cleared for the guest that the owner had not yet drained, plus
    /// the tail the scanner was holding.
    pub trailing: Vec<u8>,
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

/// Emit the refusal and hand it back, so a caller writes one expression rather
/// than an emit-then-return pair it could get out of step.
fn record_refusal(
    audit: Option<&InputAudit>,
    plan: &ExecutionPlan,
    vm: &str,
    refusal: InputRefusal,
) -> InputRefusal {
    match audit {
        Some(audit) => audit.refused(plan, vm, &refusal),
        None => tracing::warn!(
            vm = %vm,
            reason = refusal.reason(),
            "workload input refused with no chain to record it in"
        ),
    }
    refusal
}

static PROCESS_AUDIT: OnceLock<Option<Arc<InputAudit>>> = OnceLock::new();

/// The chain a decision lands in when the VM's binding names none.
///
/// `None` when the host chain cannot be opened at all; the gate then refuses
/// every grant, because an input path nobody can audit is the thing this
/// module exists to prevent.
fn process_audit() -> Option<Arc<InputAudit>> {
    PROCESS_AUDIT
        .get_or_init(|| match build_process_audit() {
            Ok(audit) => Some(Arc::new(audit)),
            Err(err) => {
                tracing::warn!(error = %err, "workload input decisions cannot be chain-recorded");
                None
            }
        })
        .clone()
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
    use mvm_protocol::protocol::broker::ServiceId;
    use mvm_protocol::stream::input::INPUT_GRANT_SERVICE;
    use tempfile::TempDir;

    use super::*;
    use crate::audit::emitter::stream_audit;
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
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        InputGate::open(&vm, &plan).expect("the plan grants input")
    }

    // --- the four required properties -------------------------------------

    #[test]
    fn input_is_refused_without_a_plan_grant() {
        let plan = PlanFixture::new().build(); // no host.stream.v1
        assert!(matches!(
            InputGate::open("vm-a", &plan),
            Err(InputRefusal::NotGranted)
        ));
    }

    #[test]
    fn a_second_writer_is_refused_while_the_lease_is_held() {
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
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
        let plan = PlanFixture::new().build();
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
    #[test]
    fn stream_input_audit_records_the_reason_and_none_of_the_refused_bytes() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let vm = unique_vm("vm-audit");
        InputGate::bind(
            &vm,
            InputBinding::new().with_secret(KnownSecret::host_material(secret.as_bytes())),
        );
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
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
            ],
            "a refusal carries the binding and the reason and nothing else"
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
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        let session = InputGate::open(&vm, &plan).expect("the plan grants input");
        assert_eq!(
            InputGate::lease_holder(&vm).as_deref(),
            Some(session.holder())
        );
        assert!(
            session.holder().starts_with(&plan.plan_id.0),
            "the holder names the plan that admitted it: {}",
            session.holder()
        );
    }

    #[test]
    fn an_unrelated_service_binding_does_not_grant_input() {
        let vm = unique_vm("vm-other-service");
        let other = ServiceId::parse("host.audit.v1").expect("valid service id");
        let plan = PlanFixture::new().services(vec![other]).build();
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
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        let first = InputGate::open(&vm, &plan).expect("first session");
        let held = first.holder().to_string();
        let closed = first.close();
        assert!(closed.trailing.is_empty(), "nothing was written");
        assert_eq!(InputGate::lease_holder(&vm), None);

        let second = InputGate::open(&vm, &plan).expect("the lease was free");
        assert_ne!(second.holder(), held, "a fresh session is a fresh holder");
    }

    #[test]
    fn a_dropped_session_frees_the_lease() {
        let vm = unique_vm("vm-lease-drop");
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
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
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
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
        assert_eq!(fresh.take_admitted(), b"mine now");
    }

    #[test]
    fn a_write_refreshes_the_lease() {
        let vm = unique_vm("vm-lease-refresh");
        InputGate::bind(
            &vm,
            InputBinding::new().with_lease_ttl(Duration::from_millis(60)),
        );
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        let mut session = InputGate::open(&vm, &plan).expect("first session");
        for _ in 0..4 {
            std::thread::sleep(Duration::from_millis(20));
            session
                .write(InputFrame {
                    seq: 0,
                    payload: b".".to_vec(),
                })
                .expect("an active writer keeps its lease");
        }
        session.refresh().expect("an idle writer can hold it too");
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
            session.take_admitted(),
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
        assert!(session.take_admitted().is_empty());
        session
            .write(InputFrame {
                seq: 1,
                payload: b"DEMO\n".to_vec(),
            })
            .expect("it was never a secret");
        assert_eq!(session.take_admitted(), b"AKIADEMO\n");
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
            session.take_admitted(),
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
        for chunk in [b"AKIAIOS".as_slice(), b"FODNN7EX".as_slice()] {
            session
                .write(InputFrame {
                    seq: 0,
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
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        let mut session = InputGate::open(&vm, &plan).expect("the plan grants input");
        session
            .write(InputFrame {
                seq: 0,
                payload: b"AKIAIOSFODNN7EXAMPLE".to_vec(),
            })
            .expect("the gate recognises only what it was told about");
        assert_eq!(session.take_admitted(), b"AKIAIOSFODNN7EXAMPLE");
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
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        let mut session = InputGate::open(&vm, &plan).expect("the plan grants input");
        for seq in 0..3u64 {
            session
                .write(InputFrame {
                    seq,
                    payload: b"x".to_vec(),
                })
                .expect("accepted");
        }
        let closed = session.close();
        assert_eq!(closed.after_seq, Some(2));
        assert_eq!(closed.trailing, b"xxx");
        assert_eq!(InputGate::lease_holder(&vm), None);
    }

    #[test]
    fn closing_a_session_that_wrote_nothing_has_no_boundary() {
        let vm = unique_vm("vm-close-empty");
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        let closed = InputGate::open(&vm, &plan)
            .expect("the plan grants input")
            .close();
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
        let closed = session.close();
        assert_eq!(closed.after_seq, Some(7));
        assert_eq!(closed.trailing, b"AKIA");
    }

    // --- binding lifecycle -------------------------------------------------

    #[test]
    fn unbinding_drops_the_lease_with_the_binding() {
        let vm = unique_vm("vm-unbind");
        InputGate::bind(&vm, InputBinding::new());
        let plan = PlanFixture::new().services(vec![stream_service()]).build();
        let _session = InputGate::open(&vm, &plan).expect("the plan grants input");
        InputGate::unbind(&vm);
        assert_eq!(InputGate::lease_holder(&vm), None);
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
