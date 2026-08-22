//! Backend-agnostic post-restore signaling and warm-snapshot primed barrier.
//!
//! After a snapshot restore resumes vCPUs, the host must signal the guest to
//! finish re-establishing itself (`PostRestore`). Before sealing a warm
//! snapshot, the host may wait for the workload to report it is fully primed.
//! Both flows are guest-agent RPCs over the backend-agnostic vsock transport,
//! so they live in `mvm-vmm` alongside `vsock_transport`.

use std::time::Duration;

use anyhow::{Context, Result, bail};

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
    /// `true` iff the guest reseeded its CSPRNG because the delivered
    /// generation token changed (a fresh clone of the snapshot). `false` for a
    /// plain wake or a no-rotation (zero-token) restore.
    pub reseeded: bool,
    /// `true` iff the guest applied the host wall-clock epoch before
    /// acknowledging the restore.
    pub clock_resynced: bool,
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
/// post-restore signal is declared undelivered. Every production caller uses
/// this so one restore does not get a quietly more generous deadline than
/// another; tests pass their own.
pub const POST_RESTORE_READY_TIMEOUT: Duration = Duration::from_secs(5);

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
}

impl VsockPostRestoreSignal {
    pub fn request(&self, host_epoch_secs: u64) -> mvm_agentd::vsock::GuestRequest {
        mvm_agentd::vsock::GuestRequest::PostRestore {
            token: self.token,
            hostname: self.hostname.clone(),
            host_epoch_secs: Some(host_epoch_secs),
            grant_envelope: self.grant_envelope.clone(),
        }
    }
}

impl PostRestoreSignal for VsockPostRestoreSignal {
    fn probe_ready(&self, vm_name: &str) -> bool {
        let Ok(transport) = crate::vsock_transport::for_vm(vm_name) else {
            return false;
        };
        transport
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .is_ok()
    }

    fn post_restore(&self, vm_name: &str) -> Result<PostRestoreOutcome> {
        use mvm_agentd::vsock::{GUEST_AGENT_PORT, GuestResponse, call_unary};
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
        match call_unary(&mut stream, &self.request(host_epoch_secs))? {
            GuestResponse::PostRestoreAck {
                success,
                detail,
                reseeded,
                clock_resynced,
            } => Ok(PostRestoreOutcome {
                acknowledged: success,
                detail,
                reseeded,
                clock_resynced,
            }),
            other => bail!("unexpected response to PostRestore: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock signal source that becomes ready after a configurable number of
    /// probes so the "poll until ready, then send once" policy is testable
    /// without a live guest.
    struct MockSignalCount {
        calls: std::cell::RefCell<usize>,
        ready_after: usize,
        outcome: Result<PostRestoreOutcome>,
    }

    impl PostRestoreSignal for MockSignalCount {
        fn probe_ready(&self, _vm_name: &str) -> bool {
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
            }),
        };
        let outcome = signal_post_restore("vm-1", &signal, Duration::from_millis(500))
            .expect("should succeed once the guest is ready");
        assert!(outcome.acknowledged);
        assert!(
            *signal.calls.borrow() > 2,
            "probe_ready must have been polled at least three times"
        );
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
            }),
        };
        let err = signal_post_restore("vm-1", &signal, Duration::from_millis(30)).unwrap_err();
        assert!(
            err.to_string().contains("did not become reachable"),
            "timeout must fail closed before post_restore: {err}"
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
                sig: vec![7u8; 64],
            },
        };
        let signal = VsockPostRestoreSignal {
            token: [9u8; mvm_core::crypto::vmgenid::GENID_BYTES],
            hostname: Some("child-final".to_string()),
            grant_envelope: Some(envelope),
        };

        let mvm_agentd::vsock::GuestRequest::PostRestore {
            token,
            hostname,
            host_epoch_secs,
            grant_envelope,
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
