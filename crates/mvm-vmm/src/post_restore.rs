//! Backend-agnostic post-restore signaling and warm-snapshot primed barrier.
//!
//! After a snapshot restore resumes vCPUs, the host must signal the guest to
//! finish re-establishing itself (`PostRestore`). Before sealing a warm
//! snapshot, the host may wait for the workload to report it is fully primed.
//! Both flows are guest-agent RPCs over the backend-agnostic vsock transport,
//! so they live in `mvm-vmm` alongside `vsock_transport`.

use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Re-exported so callers that judge a restore by its outcome describe a missing
/// reseed the same way, without depending on the guest-agent crate themselves.
pub use mvm_agentd::vsock::{ReseedShortfall, describe_missing_reseed};

/// Outcome of waiting for a workload's "primed" ready signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimedOutcome {
    /// The workload signalled it has finished warming (caches, JITs, model load).
    Primed,
    /// The wait window elapsed with no signal.
    TimedOut,
}

/// Source of a workload's "primed" ready signal. The production impl waits for
/// the guest to notify the host (over vsock — no new guest privilege, unlike a
/// host-delivered SIGUSR1); tests inject a deterministic source. Kept a trait
/// so the barrier *policy* is unit-testable without a live guest (mirrors
/// [`PostRestoreSignal`]).
pub trait PrimedSignalSource {
    /// Block up to `timeout` for the workload to signal it has finished
    /// warming. Returns whether the signal arrived.
    fn wait_for_primed(&self, timeout: Duration) -> PrimedOutcome;
}

/// Wait for the workload's "primed" ready barrier before sealing a warm
/// snapshot, so the snapshot captures a *deterministic, fully-warmed* base and
/// every resume starts past cold-start.
///
/// Fails closed: a workload that never signals primed must NOT produce a
/// half-warmed snapshot — that would defeat the barrier's purpose — so a
/// timeout is an error, never a "snapshot anyway".
pub fn await_primed_barrier<S: PrimedSignalSource + ?Sized>(
    source: &S,
    timeout: Duration,
) -> Result<()> {
    match source.wait_for_primed(timeout) {
        PrimedOutcome::Primed => Ok(()),
        PrimedOutcome::TimedOut => bail!(
            "workload did not signal 'primed' within {timeout:?} — refusing to seal a \
             half-warmed snapshot; give the workload longer to warm or check its readiness hook"
        ),
    }
}

/// Poll `probe` until it reports primed or `timeout` elapses, sleeping
/// `interval` between polls. Pure (the only impurity is the clock + sleep) so
/// the "stop at first primed, else fail closed on the deadline" policy is
/// unit-tested with a fake probe (the "mock guest").
pub fn wait_for_primed_polling<F: FnMut() -> bool>(
    timeout: Duration,
    interval: Duration,
    mut probe: F,
) -> PrimedOutcome {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if probe() {
            return PrimedOutcome::Primed;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return PrimedOutcome::TimedOut;
        }
        std::thread::sleep(interval.min(deadline - now));
    }
}

/// Production [`PrimedSignalSource`] — polls the guest agent's `PrimedStatus`
/// RPC over the backend-agnostic vsock transport until the workload signals
/// primed (it created `PRIMED_MARKER_PATH`) or the barrier times out. Mirrors
/// [`VsockPostRestoreSignal`]: the per-poll vsock I/O ([`probe_once`]) is the
/// thin shell (not unit-tested — needs a live guest), while the poll *policy*
/// ([`wait_for_primed_polling`]) is unit-tested.
pub struct VsockPrimedSignalSource {
    /// VM whose guest agent is polled for the primed signal.
    pub vm_name: String,
    /// Delay between primed-status polls.
    pub poll_interval: Duration,
}

impl VsockPrimedSignalSource {
    /// One primed-status probe. Any transport/agent error is treated as "not
    /// primed yet" (best-effort) so a transient blip doesn't abort the
    /// barrier; the deadline in [`wait_for_primed_polling`] bounds the wait.
    pub fn probe_once(&self) -> bool {
        use mvm_agentd::vsock::{
            GUEST_AGENT_PORT, GuestRequest, call_unary, interpret_primed_status,
        };
        let Ok(transport) = crate::vsock_transport::for_vm(&self.vm_name) else {
            return false;
        };
        let Ok(mut stream) = transport.connect(GUEST_AGENT_PORT) else {
            return false;
        };
        match call_unary(&mut stream, &GuestRequest::PrimedStatus) {
            Ok(resp) => interpret_primed_status(resp).unwrap_or(false),
            Err(_) => false,
        }
    }
}

impl PrimedSignalSource for VsockPrimedSignalSource {
    fn wait_for_primed(&self, timeout: Duration) -> PrimedOutcome {
        wait_for_primed_polling(timeout, self.poll_interval, || self.probe_once())
    }
}

/// Outcome of signaling `PostRestore` to a resumed guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostRestoreOutcome {
    /// The guest agent acknowledged the post-restore signal succeeded
    /// (its `PostRestoreAck.success`). `false` means the agent answered
    /// but reported a failure (e.g. its SIGUSR1 → PID 1 kill failed).
    pub acknowledged: bool,
    /// Free-form detail from the agent's ack (e.g. "post-restore signal
    /// sent to init"), surfaced to the operator.
    pub detail: Option<String>,
    /// `true` iff the delivered generation token changed (a fresh clone of the
    /// snapshot) and the guest rekeyed its kernel generator from it. `false`
    /// for a plain wake, a no-rotation (zero-token) restore, or a reseed that
    /// failed.
    pub reseeded: bool,
    /// `true` iff the guest applied the host wall-clock epoch before
    /// acknowledging the restore.
    pub clock_resynced: bool,
    /// Why a requested rotation did not happen, when it did not. Kept apart
    /// from `acknowledged`: a guest that could not reseed still remounted its
    /// drives and restarted its services.
    pub reseed_shortfall: Option<mvm_agentd::vsock::ReseedShortfall>,
    /// The workload seccomp tier the guest reports holding after this restore.
    /// `None` when the request named no tier, or when the guest refused the
    /// one it was handed.
    pub seccomp_tier: Option<mvm_core::crypto::seccomp::SeccompTier>,
    /// How many late volumes the guest reports mounting. `None` when the
    /// request named none, or when the guest refused them.
    pub volumes_mounted: Option<u32>,
}

/// Turn the guest's answer into an outcome. Split out so the mapping — which
/// fields survive to the host — is tested without a live guest.
fn outcome_from_response(response: mvm_agentd::vsock::GuestResponse) -> Result<PostRestoreOutcome> {
    match response {
        mvm_agentd::vsock::GuestResponse::PostRestoreAck {
            success,
            detail,
            reseeded,
            clock_resynced,
            reseed_shortfall,
            seccomp_tier,
            volumes_mounted,
        } => Ok(PostRestoreOutcome {
            acknowledged: success,
            detail,
            reseeded,
            clock_resynced,
            reseed_shortfall,
            seccomp_tier,
            volumes_mounted,
        }),
        other => bail!("unexpected response to PostRestore: {other:?}"),
    }
}

/// Sends the `PostRestore` signal to a resumed guest so it finishes coming
/// back: the agent maps `PostRestore` to `SIGUSR1 → PID 1`, which remounts
/// the config/secrets drives and restarts services. Backend-agnostic — the
/// production impl ([`VsockPostRestoreSignal`]) routes through the same
/// `vsock_transport::for_vm` dispatcher every other host→agent RPC uses;
/// tests inject a mock.
pub trait PostRestoreSignal {
    /// Probe whether the guest is ready to accept `PostRestore` without
    /// actually sending the signal. Transient failures must return `false`
    /// so the caller can poll up to its deadline; only a successful connect
    /// (or equivalent) returns `true`.
    fn probe_ready(&self, vm_name: &str) -> bool;
    /// Send the signal and return the guest's acknowledged outcome.
    fn post_restore(&self, vm_name: &str) -> Result<PostRestoreOutcome>;
}

/// Interval between guest-readiness probes before delivering the post-restore
/// signal.
pub const POST_RESTORE_PROBE_INTERVAL: Duration = Duration::from_millis(50);

/// How long a resumed guest gets to make its agent reachable before the
/// post-restore signal is declared undelivered on an operator-driven resume.
/// The sealed-snapshot resume admission pairs this with a ten-second exchange
/// budget and documents the fifteen-second sum as the longest a refused guest
/// can run, so this value is load-bearing for that bound; tests pass their
/// own.
pub const POST_RESTORE_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a restored child gets to make its agent reachable where the
/// post-restore handshake gates a launch — a warm-pool claim's identity
/// delivery or a `vm_full` fork — and a timeout refuses the launch rather
/// than a retryable operator resume. Sized to the standby-parent agent
/// readiness budget on the same host class: the child is restored out of
/// exactly such a parent, and under host contention its agent can
/// legitimately start answering only after the tighter resume budget has
/// elapsed.
pub const POST_RESTORE_CLAIM_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound one readiness probe's I/O so an accepted-but-unserved transport
/// fails its attempt instead of consuming the readiness budget in a blocking
/// read. Half a second is far beyond a healthy local handshake exchange, so
/// the budgets buy materially more attempts than the one-second bound this
/// replaced; a partial handshake still fails the attempt, and the next poll
/// retries on a fresh connection.
const POST_RESTORE_PROBE_IO_TIMEOUT: Duration = Duration::from_millis(500);

fn authenticated_agent_is_ready(stream: &mut std::os::unix::net::UnixStream) -> bool {
    if stream
        .set_read_timeout(Some(POST_RESTORE_PROBE_IO_TIMEOUT))
        .is_err()
        || stream
            .set_write_timeout(Some(POST_RESTORE_PROBE_IO_TIMEOUT))
            .is_err()
    {
        return false;
    }
    mvm_agentd::vsock::probe_agent_ready(stream).is_ok()
}

/// After a snapshot restore resumes vCPUs, wait for the guest agent to be
/// reachable (so a slow-to-reattach guest does not spuriously report
/// `Undelivered`), then signal the guest to finish re-establishing itself.
/// An *unacknowledged* signal is an error: the VM is running at the
/// hypervisor level but its drives may be unmounted, so the resume is not
/// actually complete — fail closed and let the operator retry (`PostRestore`
/// is safe to re-send; SIGUSR1 just re-runs the remount).
pub fn signal_post_restore<S: PostRestoreSignal + ?Sized>(
    vm_name: &str,
    signal: &S,
    ready_timeout: Duration,
) -> Result<PostRestoreOutcome> {
    match wait_for_primed_polling(ready_timeout, POST_RESTORE_PROBE_INTERVAL, || {
        signal.probe_ready(vm_name)
    }) {
        PrimedOutcome::TimedOut => {
            bail!(
                "VM {vm_name} guest agent did not become reachable within {ready_timeout:?} \
                 after resume; post-restore signal undelivered"
            );
        }
        PrimedOutcome::Primed => {}
    }

    let outcome = signal
        .post_restore(vm_name)
        .with_context(|| format!("signaling post-restore to {vm_name}"))?;
    if !outcome.acknowledged {
        let detail = outcome
            .detail
            .as_deref()
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        bail!(
            "VM {vm_name} resumed but the guest did not acknowledge post-restore{detail} \
             — config/secrets drives may be unmounted; re-run `mvmctl resume`"
        );
    }
    if !outcome.clock_resynced {
        bail!(
            "VM {vm_name} resumed but the guest did not resynchronize its wall clock — \
             refusing to report post-restore readiness"
        );
    }
    Ok(outcome)
}

/// What a restored child is handed before a claim on it commits: the fresh
/// generation token it must reseed from, the signed verb grant it pins (when
/// its plan carries one), and the seccomp tier its claiming plan admits.
#[derive(Debug, Clone)]
pub struct ChildIdentity {
    /// Fresh VMGenID token bound to the child's content-address.
    pub token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
    /// Signed agent authority for the child, when its plan grants any.
    pub grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
    /// The tier every workload process in the child must run under. A standby
    /// parent boots with no plan and holds no tier, so the child's has to
    /// arrive here.
    pub seccomp_tier: Option<mvm_core::crypto::seccomp::SeccompTier>,
    /// Read-only volumes the claim attached to the parent's late-volume
    /// slots, for the guest to mount before it acknowledges.
    pub volumes: Vec<mvm_agentd::vsock::VolumeConfig>,
}

impl ChildIdentity {
    /// The post-restore signal that delivers this identity.
    #[must_use]
    pub fn signal(self) -> VsockPostRestoreSignal {
        VsockPostRestoreSignal::for_resumed_child(self.token, self.grant_envelope)
            .with_seccomp_tier(self.seccomp_tier)
            .with_volumes(self.volumes)
    }
}

/// Production [`PostRestoreSignal`] — sends `GuestRequest::PostRestore` over
/// the backend-agnostic vsock transport (Firecracker / libkrun / Apple
/// Container, selected per VM by `vsock_transport::for_vm`). Not unit-tested
/// here (needs a live guest agent); the orchestration in
/// [`signal_post_restore`] is what the tests cover.
pub struct VsockPostRestoreSignal {
    /// Host-minted generation token delivered to the guest on this resume so
    /// it rotates its VMGenID. Random per resume; an all-zero token requests
    /// no rotation (template restore).
    pub token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
    /// Workload identity to install as the guest hostname. A factory parent
    /// carries no name because the child identity is unknown until claim time.
    pub hostname: Option<String>,
    /// Signed capability to pin while the restored guest adopts its fresh
    /// identity. Ordinary resume paths carry no new grant.
    pub grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
    /// Workload seccomp tier the restored guest must admit before it
    /// acknowledges. Set for a child restored out of a standby parent, which
    /// booted with no plan and so holds no tier of its own.
    pub seccomp_tier: Option<mvm_core::crypto::seccomp::SeccompTier>,
    /// Late volumes the restored guest must mount before it acknowledges.
    pub volumes: Vec<mvm_agentd::vsock::VolumeConfig>,
}

impl VsockPostRestoreSignal {
    /// Signal for a child brought up by resuming a captured parent.
    ///
    /// Carries no hostname. A resumed guest never boots, so `mvm.hostname=` —
    /// which PID 1 applies from the kernel cmdline while it is still
    /// privileged — cannot run a second time, and the unprivileged agent that
    /// survives into the child has no capability to rename the guest. Asking
    /// for one fails an otherwise good restore, so the child keeps the
    /// parent's name and takes its identity from its own admitted plan,
    /// nonce, and verb grant.
    pub fn for_resumed_child(
        token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
        grant_envelope: Option<mvm_core::protocol::vm_backend::VerbGrantEnvelope>,
    ) -> Self {
        Self {
            token,
            hostname: None,
            grant_envelope,
            seccomp_tier: None,
            volumes: Vec::new(),
        }
    }

    /// Hand the restored guest the late volumes its claim attached.
    #[must_use]
    pub fn with_volumes(mut self, volumes: Vec<mvm_agentd::vsock::VolumeConfig>) -> Self {
        self.volumes = volumes;
        self
    }

    /// Hand the restored guest the seccomp tier its claiming plan admits.
    #[must_use]
    pub fn with_seccomp_tier(
        mut self,
        seccomp_tier: Option<mvm_core::crypto::seccomp::SeccompTier>,
    ) -> Self {
        self.seccomp_tier = seccomp_tier;
        self
    }

    pub fn request(&self, host_epoch_secs: u64) -> mvm_agentd::vsock::GuestRequest {
        mvm_agentd::vsock::GuestRequest::PostRestore {
            token: self.token,
            hostname: self.hostname.clone(),
            host_epoch_secs: Some(host_epoch_secs),
            grant_envelope: self.grant_envelope.clone(),
            seccomp_tier: self.seccomp_tier,
            volumes: self.volumes.clone(),
        }
    }
}

impl PostRestoreSignal for VsockPostRestoreSignal {
    fn probe_ready(&self, vm_name: &str) -> bool {
        let Ok(transport) = crate::vsock_transport::for_vm(vm_name) else {
            return false;
        };
        let Ok(mut stream) = transport.connect(mvm_agentd::vsock::GUEST_AGENT_PORT) else {
            return false;
        };
        authenticated_agent_is_ready(&mut stream)
    }

    fn post_restore(&self, vm_name: &str) -> Result<PostRestoreOutcome> {
        use mvm_agentd::vsock::{GUEST_AGENT_PORT, call_unary};
        let transport = crate::vsock_transport::for_vm(vm_name)
            .with_context(|| format!("resolving vsock transport for {vm_name}"))?;
        let mut stream = transport
            .connect(GUEST_AGENT_PORT)
            .with_context(|| format!("connecting to guest agent on {vm_name}"))?;
        // `call_unary` enforces PostRestore's response contract — the agent
        // `Error` / off-contract cases surface as a typed `RpcError`, so the
        // only `Ok` variant here is the contracted `PostRestoreAck`.
        let host_epoch_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("reading host wall clock for post-restore")?
            .as_secs();
        outcome_from_response(call_unary(&mut stream, &self.request(host_epoch_secs))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::Rng;
    use std::os::unix::net::UnixStream;

    fn seeded_host_signer(home: &std::path::Path) -> SigningKey {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let keys = mvm_core::config::mvm_keys_dir();
        assert!(keys.starts_with(home));
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("host-signer.ed25519"), seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn post_restore_readiness_rejects_a_connected_but_silent_guest() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let _host_key = seeded_host_signer(home.path());
        let (mut host, guest) = UnixStream::pair().unwrap();
        drop(guest);

        assert!(!authenticated_agent_is_ready(&mut host));
    }

    #[test]
    fn post_restore_readiness_accepts_an_authenticated_guest_ping() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let host_key = seeded_host_signer(home.path());
        let anchor = host_key.verifying_key();
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let guest_thread = std::thread::spawn(move || {
            let mut guest_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut guest_seed);
            let mut session = mvm_agentd::vsock::AuthenticatedSession::guest(
                &mut guest,
                SigningKey::from_bytes(&guest_seed),
                &anchor,
            )
            .expect("guest handshake");
            let request: mvm_agentd::vsock::GuestRequest =
                session.read(&mut guest).expect("read readiness request");
            assert!(matches!(request, mvm_agentd::vsock::GuestRequest::Ping));
            session
                .write(&mut guest, &mvm_agentd::vsock::GuestResponse::Pong)
                .expect("write readiness response");
        });

        assert!(authenticated_agent_is_ready(&mut host));
        guest_thread.join().unwrap();
    }

    /// A mock signal source that becomes ready after a configurable number of
    /// probes so the "poll until ready, then send once" policy is testable
    /// without a live guest. `probe_delay` stands in for the I/O a real probe
    /// spends on its handshake exchange.
    struct MockSignalCount {
        calls: std::cell::RefCell<usize>,
        ready_after: usize,
        outcome: Result<PostRestoreOutcome>,
        probe_delay: Duration,
    }

    impl PostRestoreSignal for MockSignalCount {
        fn probe_ready(&self, _vm_name: &str) -> bool {
            std::thread::sleep(self.probe_delay);
            let mut c = self.calls.borrow_mut();
            *c += 1;
            *c > self.ready_after
        }
        fn post_restore(&self, _vm_name: &str) -> Result<PostRestoreOutcome> {
            match &self.outcome {
                Ok(o) => Ok(o.clone()),
                Err(e) => Err(anyhow::anyhow!(e.to_string())),
            }
        }
    }

    #[test]
    fn signal_post_restore_polls_until_ready_then_sends_once() {
        let signal = MockSignalCount {
            calls: std::cell::RefCell::new(0),
            ready_after: 2,
            outcome: Ok(PostRestoreOutcome {
                acknowledged: true,
                detail: None,
                reseeded: true,
                clock_resynced: true,
                reseed_shortfall: None,
                seccomp_tier: None,
                volumes_mounted: None,
            }),
            probe_delay: Duration::ZERO,
        };
        let outcome = signal_post_restore("vm-1", &signal, Duration::from_millis(500))
            .expect("should succeed once the guest is ready");
        assert!(outcome.acknowledged);
        assert!(
            *signal.calls.borrow() > 2,
            "probe_ready must have been polled at least three times"
        );
    }

    /// A guest that remounted and resynced but could not reseed is a completed
    /// resume, not an unacknowledged one: `signal_post_restore` must hand the
    /// reseed result and the guest's reason to the caller, rather than bail
    /// with advice about unmounted drives.
    #[test]
    fn signal_post_restore_carries_a_missing_reseed_to_the_caller() {
        let response = mvm_agentd::vsock::GuestResponse::PostRestoreAck {
            success: true,
            detail: Some(
                "post-restore signal sent to init; restore reseed unavailable: no helper".into(),
            ),
            reseeded: false,
            clock_resynced: true,
            reseed_shortfall: Some(mvm_agentd::vsock::ReseedShortfall::HelperMissing),
            seccomp_tier: None,
            volumes_mounted: None,
        };
        let signal = MockSignalCount {
            calls: std::cell::RefCell::new(0),
            ready_after: 0,
            outcome: outcome_from_response(response),
            probe_delay: Duration::ZERO,
        };
        let outcome = signal_post_restore("vm-1", &signal, Duration::from_millis(500))
            .expect("a resume whose only shortfall is the reseed completes");
        assert!(outcome.acknowledged && !outcome.reseeded);
        assert_eq!(
            outcome.reseed_shortfall,
            Some(mvm_agentd::vsock::ReseedShortfall::HelperMissing)
        );
        assert!(
            outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("no helper")),
            "{outcome:?}"
        );
    }

    #[test]
    fn an_off_contract_answer_is_not_an_outcome() {
        assert!(outcome_from_response(mvm_agentd::vsock::GuestResponse::Pong).is_err());
    }

    #[test]
    fn signal_post_restore_times_out_when_guest_never_ready() {
        let signal = MockSignalCount {
            calls: std::cell::RefCell::new(0),
            ready_after: usize::MAX,
            outcome: Ok(PostRestoreOutcome {
                acknowledged: true,
                detail: None,
                reseeded: true,
                clock_resynced: true,
                reseed_shortfall: None,
                seccomp_tier: None,
                volumes_mounted: None,
            }),
            probe_delay: Duration::ZERO,
        };
        let err = signal_post_restore("vm-1", &signal, Duration::from_millis(30)).unwrap_err();
        assert!(
            err.to_string().contains("did not become reachable"),
            "timeout must fail closed before post_restore: {err}"
        );
    }

    /// The claim-side budget is deliberately wider than the operator resume
    /// budget: the resume value is half of the documented fifteen-second bound
    /// on how long a refused guest may run, while a claim's handshake gates a
    /// launch and matches the ten seconds a standby parent's agent gets to
    /// start serving on the same host class.
    #[test]
    fn the_claim_readiness_budget_is_wider_than_the_resume_budget() {
        assert_eq!(POST_RESTORE_READY_TIMEOUT, Duration::from_secs(5));
        assert_eq!(POST_RESTORE_CLAIM_READY_TIMEOUT, Duration::from_secs(10));
    }

    /// One wedged probe costs at most its I/O bound per exchange, so the claim
    /// budget buys attempts rather than hangs.
    #[test]
    fn a_wedged_probe_is_bounded_so_the_budget_buys_many_attempts() {
        assert_eq!(POST_RESTORE_PROBE_IO_TIMEOUT, Duration::from_millis(500));
        let attempt_cost =
            (POST_RESTORE_PROBE_IO_TIMEOUT + POST_RESTORE_PROBE_INTERVAL).as_millis();
        let attempts = POST_RESTORE_CLAIM_READY_TIMEOUT.as_millis() / attempt_cost;
        assert!(attempts >= 12, "the claim budget buys {attempts} attempts");
    }

    /// A guest that accepts the connection and then says nothing fails the
    /// probe at its I/O bound instead of hanging: the poll gets its attempts
    /// back.
    #[test]
    fn post_restore_readiness_fails_a_connected_guest_that_stays_silent() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        let _host_key = seeded_host_signer(home.path());
        // Held open and never written to: the guest end is connected but silent.
        let (mut host, guest) = UnixStream::pair().unwrap();

        let started = std::time::Instant::now();
        assert!(!authenticated_agent_is_ready(&mut host));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a silent peer must fail at the probe I/O bound, not hang: {:?}",
            started.elapsed()
        );
        drop(guest);
    }

    /// The budget, not a faster guest, decides a slow restore: the same
    /// late-answering guest is refused inside a tight budget with the
    /// unreachable-agent error shape, and admitted within the claim budget.
    #[test]
    fn a_late_answering_guest_is_admitted_within_the_claim_budget() {
        let ok_outcome = || {
            Ok(PostRestoreOutcome {
                acknowledged: true,
                detail: None,
                reseeded: true,
                clock_resynced: true,
                reseed_shortfall: None,
                seccomp_tier: None,
                volumes_mounted: None,
            })
        };
        let refused = MockSignalCount {
            calls: std::cell::RefCell::new(0),
            ready_after: 3,
            outcome: ok_outcome(),
            probe_delay: Duration::from_millis(100),
        };
        let err = signal_post_restore("vm-1", &refused, Duration::from_millis(250))
            .expect_err("a tight budget refuses the late guest");
        assert!(
            err.to_string().contains("did not become reachable"),
            "the refusal keeps the unreachable-agent shape: {err}"
        );

        let admitted = MockSignalCount {
            calls: std::cell::RefCell::new(0),
            ready_after: 3,
            outcome: ok_outcome(),
            probe_delay: Duration::from_millis(100),
        };
        let outcome = signal_post_restore("vm-1", &admitted, POST_RESTORE_CLAIM_READY_TIMEOUT)
            .expect("the claim budget admits the same late guest");
        assert!(outcome.acknowledged);
        assert!(
            *admitted.calls.borrow() > 3,
            "the guest was reached on a late attempt"
        );
    }

    /// Canned [`PrimedSignalSource`] so the barrier policy is testable without
    /// a live guest (mirrors `MockSignal`).
    struct MockPrimed(PrimedOutcome);
    impl PrimedSignalSource for MockPrimed {
        fn wait_for_primed(&self, _timeout: Duration) -> PrimedOutcome {
            self.0.clone()
        }
    }

    #[test]
    fn primed_barrier_passes_when_workload_signals() {
        await_primed_barrier(&MockPrimed(PrimedOutcome::Primed), Duration::from_secs(5))
            .expect("a primed workload clears the barrier");
    }

    #[test]
    fn primed_barrier_fails_closed_on_timeout() {
        let err = await_primed_barrier(
            &MockPrimed(PrimedOutcome::TimedOut),
            Duration::from_millis(10),
        )
        .expect_err("a timed-out barrier must fail closed");
        assert!(
            err.to_string().contains("half-warmed"),
            "fail-closed message names the hazard: {err}"
        );
    }

    #[test]
    fn poll_returns_primed_as_soon_as_the_probe_succeeds() {
        use std::cell::Cell;
        // Probe succeeds on the 3rd poll → Primed, and we stop polling there.
        let calls = Cell::new(0u32);
        let outcome =
            wait_for_primed_polling(Duration::from_secs(5), Duration::from_millis(1), || {
                calls.set(calls.get() + 1);
                calls.get() >= 3
            });
        assert_eq!(outcome, PrimedOutcome::Primed);
        assert_eq!(calls.get(), 3, "stops polling at the first success");
    }

    #[test]
    fn poll_times_out_when_the_probe_never_succeeds() {
        let outcome =
            wait_for_primed_polling(Duration::from_millis(15), Duration::from_millis(1), || {
                false
            });
        assert_eq!(outcome, PrimedOutcome::TimedOut);
    }
    /// A resumed child is never asked to rename itself.
    ///
    /// The guest can only take a hostname from the kernel cmdline, applied by
    /// PID 1 before it drops to the unprivileged agent identity. A restore
    /// skips that boot entirely, so a hostname on this path can only fail —
    /// and it fails the whole restore, not just the rename. Pinned here
    /// because both the fork and the warm-claim path build their signal from
    /// this constructor.
    #[test]
    fn a_resumed_child_is_asked_to_adopt_no_hostname() {
        let signal = VsockPostRestoreSignal::for_resumed_child(
            [3u8; mvm_core::crypto::vmgenid::GENID_BYTES],
            None,
        );
        assert_eq!(signal.hostname, None);

        let mvm_agentd::vsock::GuestRequest::PostRestore { hostname, .. } = signal.request(1)
        else {
            panic!("expected a PostRestore request");
        };
        assert_eq!(
            hostname, None,
            "a restore must not carry a hostname the resumed guest cannot install"
        );
    }

    /// A resumed child carries the claiming plan's tier on the request, and
    /// the guest's report of what it admitted reaches the caller.
    #[test]
    fn a_resumed_child_is_handed_its_seccomp_tier_and_reports_it_back() {
        use mvm_core::crypto::seccomp::SeccompTier;

        let signal = VsockPostRestoreSignal::for_resumed_child(
            [4u8; mvm_core::crypto::vmgenid::GENID_BYTES],
            None,
        )
        .with_seccomp_tier(Some(SeccompTier::Standard));
        let mvm_agentd::vsock::GuestRequest::PostRestore { seccomp_tier, .. } = signal.request(1)
        else {
            panic!("expected a PostRestore request");
        };
        assert_eq!(seccomp_tier, Some(SeccompTier::Standard));

        let outcome = outcome_from_response(mvm_agentd::vsock::GuestResponse::PostRestoreAck {
            success: true,
            detail: None,
            reseeded: true,
            clock_resynced: true,
            reseed_shortfall: None,
            seccomp_tier: Some(SeccompTier::Standard),
            volumes_mounted: None,
        })
        .unwrap();
        assert_eq!(outcome.seccomp_tier, Some(SeccompTier::Standard));
    }

    /// Without a tier the request serializes exactly as before the field
    /// existed, so a plain resume still reaches an agent built without it.
    #[test]
    fn a_request_without_a_tier_omits_the_field_from_the_wire() {
        let signal = VsockPostRestoreSignal::for_resumed_child(
            [4u8; mvm_core::crypto::vmgenid::GENID_BYTES],
            None,
        );
        let json = serde_json::to_string(&signal.request(1)).unwrap();
        assert!(!json.contains("seccomp_tier"), "{json}");
    }

    #[test]
    fn post_restore_request_carries_the_child_grant_envelope() {
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};
        use mvm_core::protocol::vm_backend::VerbGrantEnvelope;

        let nonce = Nonce::from_bytes([5u8; 16]);
        let envelope = VerbGrantEnvelope {
            pubkey_hex: "ab".repeat(32),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: VerbGrant {
                session_id: "child-final".into(),
                plan_nonce: nonce,
                not_after: mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap(),
                verbs: vec![VerbId::new("run-entrypoint").unwrap()],
                drive: None,
                tool_mediation: None,
                application_terminal: None,
                sig: vec![7u8; 64],
            },
        };
        let signal = VsockPostRestoreSignal {
            token: [9u8; mvm_core::crypto::vmgenid::GENID_BYTES],
            hostname: Some("child-final".to_string()),
            grant_envelope: Some(envelope),
            seccomp_tier: None,
            volumes: Vec::new(),
        };

        let mvm_agentd::vsock::GuestRequest::PostRestore {
            token,
            hostname,
            host_epoch_secs,
            grant_envelope,
            ..
        } = signal.request(42)
        else {
            panic!("post-restore signal built the wrong request variant");
        };
        assert_eq!(token, [9u8; mvm_core::crypto::vmgenid::GENID_BYTES]);
        assert_eq!(hostname.as_deref(), Some("child-final"));
        assert_eq!(host_epoch_secs, Some(42));
        assert_eq!(
            grant_envelope.expect("grant is carried").grant.session_id,
            "child-final"
        );
    }
}
