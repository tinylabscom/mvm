//! mvm-hostd — host-side daemon roles.
//!
//! Consolidates five former crates into one, each a module; the
//! broker / host-signer / audit-signer additionally ship as separate
//! `[[bin]]`s so each key subprocess stays its own process (the
//! process moat).
//!
//! - [`supervisor`] — the trusted host-side supervisor library (egress
//!   proxy, tool gate, key release, audit signing, plan execution state
//!   machine). Run in-process by this crate's per-VM supervisor bins
//!   (`mvm-libkrun-supervisor`, `mvm-hvf-supervisor`), not as a
//!   standalone process.
//! - [`broker`] — host services broker subprocess (vsock dispatch).
//! - [`host_signer`] — Ed25519 host-key signer subprocess.
//! - [`audit_signer`] — chain-signing audit subprocess.
//! - [`jailer`] — the `mvm-jailer-lite` seccomp + landlock confinement
//!   helper, applied in-process by each role before it touches keys or
//!   untrusted input.
//! - [`stream`] — the per-VM workload output broker: one redaction seam, one
//!   hash chain, one durable transcript, N followers.
//! - [`bridge`] / [`firecracker_bridge`] / [`prelaunch`] / [`exit_capture`] —
//!   the shared per-VM supervisor host-process substrate: bridge-sidecar
//!   config parsing, the prelaunched-standby attach-verify, and the
//!   workload-exit control listener.

pub mod admission_budget;
pub mod admitted_campaign_runner;
pub mod assurance_agent_adapter;
pub mod assurance_attestation;
pub mod assurance_provider;
pub mod assurance_session;
pub mod audit;
pub mod audit_signer;
pub mod broker;
pub mod exit_capture;
pub mod extension_controller;
/// Length-prefixed message framing (4-byte BE length + body,
/// cap-before-alloc) for the same-uid UDS control channels. Relocated
/// from `mvm_core::framing` so `mvm-core`'s default build pulls no
/// async runtime.
pub mod framing;
/// Host->guest healthcheck probe: run a workload's healthcheck command via
/// the guest agent's exec protocol and decide pass/fail.
pub mod health_probe;
/// Idle-registration self-termination logic for the `mvm-host-agent` worker.
pub mod host_agent_idle;
pub mod host_signer;
pub mod jailer;
/// Secret keyholder — the `SecretRef` → credential boundary: the
/// [`keyholder::SecretResolver`] trait + the single-host
/// [`keyholder::LocalResolver`].
pub mod keyholder;
pub mod operator_admitted_trial_booter;
/// Redacting panic hook for the daemon bins. A panic payload is the one
/// string the no-`Display`-on-secret-types gate cannot reach.
pub mod panic_hook;
/// Child-side parent-death watchdog: each subprocess-moat bin exits the
/// instant its supervisor dies, closing the macOS / abnormal-death gap the
/// spawn-side `PR_SET_PDEATHSIG` attach leaves open.
pub mod parent_death;
pub mod plan_admission;
/// The prelaunched-supervisor attach verify+merge. Pure (no VM, no
/// `start_enter`) so the rejection ladder is unit-testable.
pub mod prelaunch;
pub mod run;
/// Resume orchestration for durable agent sessions: turn a parked session
/// record back into an admitted `ExecutionPlan`.
pub mod session_resume;
pub mod stream;
pub mod supervisor;
